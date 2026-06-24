use std::time::Instant;

use alloy::hex;
use alloy::primitives::{Address, FixedBytes, U256};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy_rpc_types_eth::Log;
use broadcaster_core::transact::{
    compute_railgun_txid_parts, railgun_txid_leaf_hash_with_output_start,
};
use broadcaster_core::tree::TREE_LEAF_COUNT;
use clap::Parser;
use eyre::{Context, Result, bail, eyre};
use railgun_indexer_core::chain_logs::{
    IndexedPublicTransaction, fetch_chain_index_logs, hydrate_public_transactions,
    ingest_chain_logs,
};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use tracing_subscriber::EnvFilter;

const DEFAULT_PAGE_SIZE: u64 = 10_000;
const DEFAULT_RPC_BLOCK_CHUNK_SIZE: u64 = 10_000;

#[derive(Debug, Parser)]
#[command(about = "Verify RPC-derived public TXID rows against Squid for a block range")]
struct Args {
    /// Chain ID to verify.
    #[arg(long)]
    chain_id: u64,

    /// Inclusive start block.
    #[arg(long)]
    from_block: u64,

    /// Inclusive end block.
    #[arg(long)]
    to_block: u64,

    /// Archive RPC URL. Must support `eth_getLogs` and transaction/block lookups;
    /// `debug_traceTransaction` or `trace_transaction` is used for wrapped calls.
    #[arg(long, env = "RAILGUN_TXID_RANGE_RPC_URL")]
    rpc_url: Option<String>,

    /// Override Railgun contract address.
    #[arg(long)]
    railgun_contract: Option<Address>,

    /// Override v2 start block.
    #[arg(long)]
    v2_start_block: Option<u64>,

    /// Override legacy shield block.
    #[arg(long)]
    legacy_shield_block: Option<u64>,

    /// Squid GraphQL page size.
    #[arg(long, default_value_t = DEFAULT_PAGE_SIZE)]
    page_size: u64,

    /// Maximum inclusive block span per `eth_getLogs` request.
    #[arg(long, default_value_t = DEFAULT_RPC_BLOCK_CHUNK_SIZE)]
    rpc_block_chunk_size: u64,
}

#[derive(Debug, Clone)]
struct TxidRow {
    range_index: usize,
    id: String,
    block_number: u64,
    block_timestamp: u64,
    transaction_hash: [u8; 32],
    merkle_root: [u8; 32],
    nullifiers: Vec<[u8; 32]>,
    commitments: Vec<[u8; 32]>,
    bound_params_hash: [u8; 32],
    has_unshield: bool,
    utxo_tree_in: u64,
    utxo_tree_out: u64,
    utxo_batch_start_position_out: u64,
}

impl TxidRow {
    fn leaf_hash(&self) -> U256 {
        let nullifiers = self
            .nullifiers
            .iter()
            .map(|value| U256::from_be_bytes(*value))
            .collect::<Vec<_>>();
        let commitments = self
            .commitments
            .iter()
            .map(|value| U256::from_be_bytes(*value))
            .collect::<Vec<_>>();
        let railgun_txid = compute_railgun_txid_parts(
            &nullifiers,
            &commitments,
            U256::from_be_bytes(self.bound_params_hash),
        );
        railgun_txid_leaf_hash_with_output_start(
            railgun_txid,
            self.utxo_tree_in,
            U256::from(self.output_start_global()),
        )
    }

    fn output_start_global(&self) -> u128 {
        u128::from(self.utxo_tree_out)
            .saturating_mul(u128::from(TREE_LEAF_COUNT))
            .saturating_add(u128::from(self.utxo_batch_start_position_out))
    }

    fn short(&self) -> String {
        format!(
            "range_index={} block={} timestamp={} tx=0x{} id={} out_global={} nullifiers={} commitments={} unshield={}",
            self.range_index,
            self.block_number,
            self.block_timestamp,
            hex::encode(self.transaction_hash),
            self.id,
            self.output_start_global(),
            self.nullifiers.len(),
            self.commitments.len(),
            self.has_unshield,
        )
    }
}

#[derive(Debug, Deserialize)]
struct GraphqlResponse {
    data: Option<TransactionsData>,
    errors: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct TransactionsData {
    transactions: Vec<Value>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    if args.from_block > args.to_block {
        bail!("--from-block must be <= --to-block");
    }
    if args.page_size == 0 {
        bail!("--page-size must be non-zero");
    }
    if args.rpc_block_chunk_size == 0 {
        bail!("--rpc-block-chunk-size must be non-zero");
    }

    let defaults = chain_defaults(args.chain_id)?;
    let railgun_contract = args.railgun_contract.unwrap_or(defaults.railgun_contract);
    let v2_start_block = args.v2_start_block.unwrap_or(defaults.v2_start_block);
    let legacy_shield_block = args
        .legacy_shield_block
        .unwrap_or(defaults.legacy_shield_block);
    let rpc_url = args
        .rpc_url
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| eyre!("--rpc-url or RAILGUN_TXID_RANGE_RPC_URL is required"))?;
    let provider = build_provider(rpc_url)?;
    let client = Client::builder()
        .user_agent("railgun-indexer-txid-range/0.1")
        .build()?;

    eprintln!(
        "[txid-range] fetching RPC logs chain={} blocks={}..={} contract={}",
        args.chain_id, args.from_block, args.to_block, railgun_contract
    );
    let logs = fetch_chain_index_logs_chunked(
        &provider,
        railgun_contract,
        args.from_block,
        args.to_block,
        v2_start_block,
        legacy_shield_block,
        args.rpc_block_chunk_size,
    )
    .await?;
    eprintln!("[txid-range] fetched RPC logs count={}", logs.len());

    let mut batch = ingest_chain_logs(&logs)?;
    eprintln!(
        "[txid-range] ingested logs transact={} legacy_encrypted={} legacy_generated={} nullifiers={}",
        batch.transact_commitments.len(),
        batch.legacy_encrypted_commitments.len(),
        batch.legacy_generated_commitments.len(),
        batch.nullifiers.len(),
    );
    hydrate_public_transactions(&provider, railgun_contract, &mut batch).await?;
    let rpc_rows = rpc_rows_from_batch(&batch.public_transactions)?;
    eprintln!(
        "[txid-range] hydrated RPC public_txid rows={}",
        rpc_rows.len()
    );

    let squid_rows = squid_public_txid_rows(
        &client,
        defaults.squid_endpoint,
        args.chain_id,
        args.from_block,
        args.to_block,
        args.page_size,
    )
    .await?;
    eprintln!(
        "[txid-range] loaded Squid public_txid rows={}",
        squid_rows.len()
    );

    let failures = compare_rows(&rpc_rows, &squid_rows);
    println!(
        "chain {} block_range={}..{} rpc_rows={} squid_rows={} failures={}",
        args.chain_id,
        args.from_block,
        args.to_block,
        rpc_rows.len(),
        squid_rows.len(),
        failures
    );
    if failures > 0 {
        bail!("TXID range parity failed with {failures} mismatch(es)");
    }
    Ok(())
}

async fn fetch_chain_index_logs_chunked<P: Provider + ?Sized>(
    provider: &P,
    railgun_contract: Address,
    from_block: u64,
    to_block: u64,
    v2_start_block: u64,
    legacy_shield_block: u64,
    block_chunk_size: u64,
) -> Result<Vec<Log>> {
    let mut logs = Vec::new();
    let total_blocks = to_block
        .checked_sub(from_block)
        .and_then(|blocks| blocks.checked_add(1))
        .ok_or_else(|| eyre!("block range overflow"))?;
    let total_chunks = total_blocks.div_ceil(block_chunk_size);
    let mut chunk_start = from_block;
    let mut chunk_index = 0_u64;
    while chunk_start <= to_block {
        chunk_index = chunk_index.saturating_add(1);
        let chunk_end = chunk_start
            .saturating_add(block_chunk_size.saturating_sub(1))
            .min(to_block);
        eprintln!(
            "[txid-range] fetching RPC log chunk {}/{} blocks={}..{} loaded_logs={}",
            chunk_index,
            total_chunks,
            chunk_start,
            chunk_end,
            logs.len()
        );
        let mut chunk_logs = fetch_chain_index_logs(
            provider,
            railgun_contract,
            chunk_start,
            chunk_end,
            v2_start_block,
            legacy_shield_block,
        )
        .await?;
        eprintln!(
            "[txid-range] fetched RPC log chunk {}/{} blocks={}..{} logs={}",
            chunk_index,
            total_chunks,
            chunk_start,
            chunk_end,
            chunk_logs.len()
        );
        logs.append(&mut chunk_logs);
        if chunk_end == to_block {
            break;
        }
        chunk_start = chunk_end
            .checked_add(1)
            .ok_or_else(|| eyre!("next chunk start overflow"))?;
    }
    logs.sort_by_key(|log| {
        (
            log.block_number.unwrap_or_default(),
            log.log_index.unwrap_or_default(),
        )
    });
    Ok(logs)
}

fn rpc_rows_from_batch(rows: &[IndexedPublicTransaction]) -> Result<Vec<TxidRow>> {
    rows.iter()
        .enumerate()
        .map(|(range_index, row)| {
            Ok(TxidRow {
                range_index,
                id: row.id.clone(),
                block_number: row.source.block_number,
                block_timestamp: row.block_timestamp,
                transaction_hash: fixed_bytes(row.source.transaction_hash),
                merkle_root: fixed_bytes(row.merkle_root),
                nullifiers: row.nullifiers.iter().copied().map(fixed_bytes).collect(),
                commitments: row.commitments.iter().copied().map(fixed_bytes).collect(),
                bound_params_hash: fixed_bytes(row.bound_params_hash),
                has_unshield: row.has_unshield,
                utxo_tree_in: row.utxo_tree_in,
                utxo_tree_out: row.utxo_tree_out,
                utxo_batch_start_position_out: row.utxo_batch_start_position_out,
            })
        })
        .collect()
}

async fn squid_public_txid_rows(
    client: &Client,
    endpoint: &str,
    chain_id: u64,
    from_block: u64,
    to_block: u64,
    page_size: u64,
) -> Result<Vec<TxidRow>> {
    let mut offset = 0_u64;
    let mut rows = Vec::new();
    let started = Instant::now();
    eprintln!(
        "[txid-range] starting Squid fetch chain={chain_id} endpoint={endpoint} page_size={page_size} blocks={from_block}..{to_block}"
    );
    loop {
        let page_started = Instant::now();
        eprintln!(
            "[txid-range] fetching Squid page chain={} offset={} limit={} blocks={}..{} loaded={}",
            chain_id,
            offset,
            page_size,
            from_block,
            to_block,
            rows.len()
        );
        let page =
            fetch_squid_page(client, endpoint, offset, page_size, from_block, to_block).await?;
        if page.is_empty() {
            eprintln!(
                "[txid-range] Squid returned empty page chain={} offset={} loaded={} page_elapsed_ms={} total_elapsed_ms={}",
                chain_id,
                offset,
                rows.len(),
                elapsed_ms(page_started),
                elapsed_ms(started)
            );
            break;
        }
        let page_len = page.len();
        let tail = squid_page_tail(&page);
        for value in page {
            let range_index = rows.len();
            rows.push(parse_squid_transaction(range_index, &value)?);
        }
        eprintln!(
            "[txid-range] decoded Squid page chain={} offset={} rows={} cumulative_rows={} page_elapsed_ms={}{}",
            chain_id,
            offset,
            page_len,
            rows.len(),
            elapsed_ms(page_started),
            tail
        );
        if page_len < usize::try_from(page_size).wrap_err("Squid page size overflow")? {
            break;
        }
        offset = u64::try_from(rows.len()).wrap_err("Squid offset overflow")?;
    }
    eprintln!(
        "[txid-range] finished Squid fetch chain={} rows={} blocks={}..{} elapsed_ms={}",
        chain_id,
        rows.len(),
        from_block,
        to_block,
        elapsed_ms(started)
    );
    Ok(rows)
}

async fn fetch_squid_page(
    client: &Client,
    endpoint: &str,
    offset: u64,
    limit: u64,
    from_block: u64,
    to_block: u64,
) -> Result<Vec<Value>> {
    let query = r"
query PublicTxidRange($offset: Int!, $limit: Int!, $fromBlock: BigInt!, $toBlock: BigInt!) {
  transactions(
    orderBy: id_ASC,
    offset: $offset,
    limit: $limit,
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
  ) {
    id
    blockNumber
    blockTimestamp
    transactionHash
    merkleRoot
    nullifiers
    commitments
    boundParamsHash
    hasUnshield
    utxoTreeIn
    utxoTreeOut
    utxoBatchStartPositionOut
  }
}
";
    let body = serde_json::json!({
        "query": query,
        "variables": {
            "offset": i32::try_from(offset).wrap_err("Squid offset exceeds GraphQL Int")?,
            "limit": i32::try_from(limit).wrap_err("Squid limit exceeds GraphQL Int")?,
            "fromBlock": from_block.to_string(),
            "toBlock": to_block.to_string(),
        }
    });
    let response = client
        .post(endpoint)
        .json(&body)
        .send()
        .await
        .wrap_err_with(|| format!("post Squid range page offset {offset} to {endpoint}"))?
        .error_for_status()
        .wrap_err_with(|| format!("Squid range page offset {offset} returned error status"))?
        .json::<GraphqlResponse>()
        .await
        .wrap_err("decode Squid GraphQL response")?;
    if let Some(errors) = response.errors {
        bail!("Squid GraphQL errors: {errors}");
    }
    Ok(response
        .data
        .ok_or_else(|| eyre!("Squid response missing data"))?
        .transactions)
}

fn compare_rows(rpc_rows: &[TxidRow], squid_rows: &[TxidRow]) -> usize {
    let mut failures = usize::from(rpc_rows.len() != squid_rows.len());
    if rpc_rows.len() != squid_rows.len() {
        println!(
            "row count mismatch rpc_rows={} squid_rows={}",
            rpc_rows.len(),
            squid_rows.len()
        );
    }
    let max = rpc_rows.len().max(squid_rows.len());
    for index in 0..max {
        match (rpc_rows.get(index), squid_rows.get(index)) {
            (Some(rpc), Some(squid)) => {
                let rpc_leaf = rpc.leaf_hash().to_be_bytes::<32>();
                let squid_leaf = squid.leaf_hash().to_be_bytes::<32>();
                if !rows_match(rpc, squid) || rpc_leaf != squid_leaf {
                    failures = failures.saturating_add(1);
                    println!("mismatch range_index={index}");
                    println!("  rpc:   {}", rpc.short());
                    println!("  squid: {}", squid.short());
                    println!("  rpc_leaf={}", hex::encode_prefixed(rpc_leaf));
                    println!("  squid_leaf={}", hex::encode_prefixed(squid_leaf));
                    print_row_diffs(rpc, squid);
                    break;
                }
            }
            (Some(rpc), None) => {
                failures = failures.saturating_add(1);
                println!("extra RPC row: {}", rpc.short());
                break;
            }
            (None, Some(squid)) => {
                failures = failures.saturating_add(1);
                println!("missing RPC row: {}", squid.short());
                break;
            }
            (None, None) => break,
        }
    }
    failures
}

fn elapsed_ms(started: Instant) -> u128 {
    started.elapsed().as_millis()
}

fn squid_page_tail(page: &[Value]) -> String {
    page.last()
        .map(|value| {
            format!(
                " last_block={} last_id={}",
                json_field_summary(value, "blockNumber"),
                json_field_summary(value, "id")
            )
        })
        .unwrap_or_default()
}

fn json_field_summary(value: &Value, field: &'static str) -> String {
    match value.get(field) {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Bool(value)) => value.to_string(),
        Some(Value::Null) => "null".to_string(),
        Some(_) => "<complex>".to_string(),
        None => "<missing>".to_string(),
    }
}

fn rows_match(left: &TxidRow, right: &TxidRow) -> bool {
    left.block_number == right.block_number
        && left.block_timestamp == right.block_timestamp
        && left.transaction_hash == right.transaction_hash
        && left.merkle_root == right.merkle_root
        && left.nullifiers == right.nullifiers
        && left.commitments == right.commitments
        && left.bound_params_hash == right.bound_params_hash
        && left.has_unshield == right.has_unshield
        && left.utxo_tree_in == right.utxo_tree_in
        && left.output_start_global() == right.output_start_global()
}

fn print_row_diffs(rpc: &TxidRow, squid: &TxidRow) {
    let mut printed = false;
    macro_rules! diff_value {
        ($field:literal, $left:expr, $right:expr) => {
            if $left != $right {
                printed = true;
                println!("  field_diff {} rpc={} squid={}", $field, $left, $right);
            }
        };
    }
    macro_rules! diff_hex {
        ($field:literal, $left:expr, $right:expr) => {
            if $left != $right {
                printed = true;
                println!(
                    "  field_diff {} rpc=0x{} squid=0x{}",
                    $field,
                    hex::encode($left),
                    hex::encode($right)
                );
            }
        };
    }
    macro_rules! diff_hex_vec {
        ($field:literal, $left:expr, $right:expr) => {
            if $left != $right {
                printed = true;
                println!(
                    "  field_diff {} rpc=[{}] squid=[{}]",
                    $field,
                    hex_vec($left),
                    hex_vec($right)
                );
            }
        };
    }

    diff_value!("block_number", rpc.block_number, squid.block_number);
    diff_value!(
        "block_timestamp",
        rpc.block_timestamp,
        squid.block_timestamp
    );
    diff_hex!(
        "transaction_hash",
        rpc.transaction_hash,
        squid.transaction_hash
    );
    diff_hex!("merkle_root", rpc.merkle_root, squid.merkle_root);
    diff_hex_vec!("nullifiers", &rpc.nullifiers, &squid.nullifiers);
    diff_hex_vec!("commitments", &rpc.commitments, &squid.commitments);
    diff_hex!(
        "bound_params_hash",
        rpc.bound_params_hash,
        squid.bound_params_hash
    );
    diff_value!("has_unshield", rpc.has_unshield, squid.has_unshield);
    diff_value!("utxo_tree_in", rpc.utxo_tree_in, squid.utxo_tree_in);
    diff_value!("utxo_tree_out", rpc.utxo_tree_out, squid.utxo_tree_out);
    diff_value!(
        "utxo_batch_start_position_out",
        rpc.utxo_batch_start_position_out,
        squid.utxo_batch_start_position_out
    );
    diff_value!(
        "output_start_global",
        rpc.output_start_global(),
        squid.output_start_global()
    );

    if !printed {
        println!("  field_diff <none>; row fields match but leaf differs");
    }
}

fn hex_vec(values: &[[u8; 32]]) -> String {
    values
        .iter()
        .map(hex::encode_prefixed)
        .collect::<Vec<_>>()
        .join(", ")
}

fn parse_squid_transaction(range_index: usize, value: &Value) -> Result<TxidRow> {
    Ok(TxidRow {
        range_index,
        id: string_field(value, "id")?.to_string(),
        block_number: u64_field(value, "blockNumber")?,
        block_timestamp: u64_field(value, "blockTimestamp")?,
        transaction_hash: fixed_hex_field(value, "transactionHash")?,
        merkle_root: fixed_hex_field(value, "merkleRoot")?,
        nullifiers: fixed_u256_array_field(value, "nullifiers")?,
        commitments: fixed_u256_array_field(value, "commitments")?,
        bound_params_hash: fixed_u256_field(value, "boundParamsHash")?,
        has_unshield: bool_field(value, "hasUnshield")?,
        utxo_tree_in: u64_field(value, "utxoTreeIn")?,
        utxo_tree_out: u64_field(value, "utxoTreeOut")?,
        utxo_batch_start_position_out: u64_field(value, "utxoBatchStartPositionOut")?,
    })
}

fn build_provider(rpc_url: &str) -> Result<RootProvider> {
    let url = url::Url::parse(rpc_url).wrap_err("parse RPC URL")?;
    Ok(ProviderBuilder::new().connect_http(url).root().clone())
}

const fn fixed_bytes(value: FixedBytes<32>) -> [u8; 32] {
    value.0
}

fn string_field<'a>(value: &'a Value, field: &'static str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| eyre!("field {field} missing or not string"))
}

fn bool_field(value: &Value, field: &'static str) -> Result<bool> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| eyre!("field {field} missing or not bool"))
}

fn u64_field(value: &Value, field: &'static str) -> Result<u64> {
    let value = value
        .get(field)
        .ok_or_else(|| eyre!("field {field} missing"))?;
    match value {
        Value::String(value) => parse_u64_string(value),
        Value::Number(value) => value.as_u64().ok_or_else(|| eyre!("field {field} not u64")),
        _ => bail!("field {field} is not numeric"),
    }
}

fn fixed_hex_field(value: &Value, field: &'static str) -> Result<[u8; 32]> {
    let value = string_field(value, field)?;
    decode_fixed_hex(value).wrap_err_with(|| format!("decode field {field}"))
}

fn fixed_u256_field(value: &Value, field: &'static str) -> Result<[u8; 32]> {
    let value = value
        .get(field)
        .ok_or_else(|| eyre!("field {field} missing"))?;
    parse_u256_value(value).wrap_err_with(|| format!("parse field {field}"))
}

fn fixed_u256_array_field(value: &Value, field: &'static str) -> Result<Vec<[u8; 32]>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| eyre!("field {field} missing or not array"))?
        .iter()
        .map(parse_u256_value)
        .collect::<Result<Vec<_>>>()
}

fn parse_u64_string(value: &str) -> Result<u64> {
    if let Some(value) = value.strip_prefix("0x") {
        u64::from_str_radix(value, 16).wrap_err("parse hex u64")
    } else {
        value.parse::<u64>().wrap_err("parse decimal u64")
    }
}

fn parse_u256_value(value: &Value) -> Result<[u8; 32]> {
    match value {
        Value::String(value) => {
            let parsed = if let Some(hex) = value.strip_prefix("0x") {
                U256::from_str_radix(hex, 16).wrap_err("parse hex U256")?
            } else {
                U256::from_str_radix(value, 10).wrap_err("parse decimal U256")?
            };
            Ok(parsed.to_be_bytes::<32>())
        }
        Value::Number(value) => {
            let value = value.as_u64().ok_or_else(|| eyre!("number is not u64"))?;
            Ok(U256::from(value).to_be_bytes::<32>())
        }
        _ => bail!("value is not U256-compatible"),
    }
}

fn decode_fixed_hex(value: &str) -> Result<[u8; 32]> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    let value = if value.len().is_multiple_of(2) {
        value.to_string()
    } else {
        format!("0{value}")
    };
    let bytes = hex::decode(value)?;
    if bytes.len() > 32 {
        bail!("expected at most 32 bytes, got {}", bytes.len());
    }
    let mut padded = [0_u8; 32];
    let start = padded.len() - bytes.len();
    padded[start..].copy_from_slice(&bytes);
    Ok(padded)
}

struct ChainDefaults {
    railgun_contract: Address,
    v2_start_block: u64,
    legacy_shield_block: u64,
    squid_endpoint: &'static str,
}

fn chain_defaults(chain_id: u64) -> Result<ChainDefaults> {
    match chain_id {
        1 => Ok(ChainDefaults {
            railgun_contract: "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9".parse()?,
            v2_start_block: 16_076_750,
            legacy_shield_block: 16_790_263,
            squid_endpoint: "https://rail-squid.squids.live/squid-railgun-ethereum-v2/graphql",
        }),
        56 => Ok(ChainDefaults {
            railgun_contract: "0x590162bf4b50f6576a459b75309ee21d92178a10".parse()?,
            v2_start_block: 23_478_204,
            legacy_shield_block: 26_313_947,
            squid_endpoint: "https://rail-squid.squids.live/squid-railgun-bsc-v2/graphql",
        }),
        137 => Ok(ChainDefaults {
            railgun_contract: "0x19b620929f97b7b990801496c3b361ca5def8c71".parse()?,
            v2_start_block: 36_219_104,
            legacy_shield_block: 40_143_539,
            squid_endpoint: "https://rail-squid.squids.live/squid-railgun-polygon-v2/graphql",
        }),
        42161 => Ok(ChainDefaults {
            railgun_contract: "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9".parse()?,
            v2_start_block: 0,
            legacy_shield_block: 68_196_853,
            squid_endpoint: "https://rail-squid.squids.live/squid-railgun-arbitrum-v2/graphql",
        }),
        _ => bail!("unsupported chain id {chain_id}"),
    }
}
