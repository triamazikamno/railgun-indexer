use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use alloy::primitives::FixedBytes;
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use clap::{Parser, ValueEnum};
use eyre::{Context, Result, bail, eyre};
use railgun_indexer_core::chain_logs::block_timestamp_for_source;
use railgun_indexer_core::config::{ChainIndexedChainConfig, Config};
use railgun_indexer_core::store::{
    Store, StoredMissingWalletScanTimestampBlock, StoredWalletScanTimestampBackfill, run_migrations,
};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use tracing_subscriber::EnvFilter;

const EVM_CHAIN_TYPE: u8 = 0;
const DEFAULT_BLOCK_QUERY_LIMIT: u64 = 1_000;
const DEFAULT_SQUID_PAGE_SIZE: u64 = 10_000;
const MAX_SQL_BLOCK: u64 = i64::MAX as u64;
const SQUID_PAGE_RETRY_ATTEMPTS: usize = 4;
const SQUID_PAGE_RETRY_BASE_DELAY: Duration = Duration::from_secs(2);
const SQUID_BLOCK_NUMBER_FILTER_LIMIT: usize = 1_000;
const SQUID_TIMESTAMP_FIELDS: &[&str] = &[
    "transactCommitments",
    "shieldCommitments",
    "nullifiers",
    "legacyEncryptedCommitments",
    "legacyGeneratedCommitments",
];

macro_rules! progress {
    ($($arg:tt)*) => {{
        eprintln!("[indexed-log-timestamp-backfill] {}", format_args!($($arg)*));
        let _ = io::stderr().flush();
    }};
}

#[derive(Debug, Parser)]
#[command(about = "Backfill missing wallet-scan block timestamps from indexed block hashes")]
struct Args {
    #[arg(long, env = "RAILGUN_INDEXER_CONFIG")]
    config: PathBuf,

    /// Restrict backfill to specific chain IDs. May be repeated.
    #[arg(long = "chain-id")]
    chain_ids: Vec<u64>,

    /// Override start block. Defaults to the configured chain start block.
    #[arg(long)]
    from_block: Option<u64>,

    /// Override end block. Defaults to the largest Postgres BIGINT-compatible block.
    #[arg(long)]
    to_block: Option<u64>,

    /// Maximum distinct missing blocks to query and update per DB batch.
    #[arg(long, default_value_t = DEFAULT_BLOCK_QUERY_LIMIT)]
    block_query_limit: u64,

    /// Timestamp source for missing blocks. Squid uses GraphQL blockTimestamp in bulk and falls back to RPC unless --no-rpc-fallback is set.
    #[arg(long, value_enum, default_value_t = TimestampSource::Rpc)]
    timestamp_source: TimestampSource,

    /// Squid GraphQL page size when --timestamp-source=squid.
    #[arg(long, default_value_t = DEFAULT_SQUID_PAGE_SIZE)]
    squid_page_size: u64,

    /// Override Squid endpoint for a chain as `CHAIN_ID=URL`. May be repeated.
    #[arg(long = "squid-endpoint")]
    squid_endpoints: Vec<String>,

    /// Do not query archive RPC for blocks absent from Squid when --timestamp-source=squid.
    #[arg(long)]
    no_rpc_fallback: bool,

    /// Fetch and validate timestamps without writing rows.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum TimestampSource {
    Rpc,
    Squid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedTimestamp {
    block_number: u64,
    block_hash: [u8; 32],
    block_timestamp: u64,
    missing_rows: u64,
}

#[derive(Debug, Deserialize)]
struct GraphqlResponse {
    data: Option<Value>,
    errors: Option<Value>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    if args.block_query_limit == 0 {
        bail!("--block-query-limit must be non-zero");
    }
    if args.squid_page_size == 0 {
        bail!("--squid-page-size must be non-zero");
    }

    let config = load_config(&args.config).wrap_err("load config")?;
    let selected = selected_chains(&config, &args)?;
    let selected_count = selected.len();
    let squid_endpoints = parse_squid_endpoint_overrides(&args.squid_endpoints)?;
    let squid_client = Client::new();
    let pool = config
        .connect_postgres()
        .await
        .wrap_err("connect postgres")?;
    run_migrations(&pool).await.wrap_err("run migrations")?;
    let store = Store::new(pool);

    let started = Instant::now();
    let mut total_blocks = 0_u64;
    let mut total_rows = 0_u64;
    for chain in selected {
        let use_rpc = args.timestamp_source == TimestampSource::Rpc || !args.no_rpc_fallback;
        let provider = if use_rpc {
            Some(build_provider(&chain.archive_rpc_url).wrap_err_with(|| {
                format!("build archive RPC provider for chain {}", chain.chain_id)
            })?)
        } else {
            None
        };
        let squid_endpoint = if args.timestamp_source == TimestampSource::Squid {
            Some(squid_endpoint_for_chain(chain.chain_id, &squid_endpoints)?)
        } else {
            None
        };
        let from_block = args.from_block.unwrap_or(chain.start_block);
        let to_block = args.to_block.unwrap_or(MAX_SQL_BLOCK);
        if from_block > to_block {
            progress!(
                "chain {}: skipping empty range {}..{}",
                chain.chain_id,
                from_block,
                to_block
            );
            continue;
        }

        let (blocks, rows) = backfill_chain(
            &store,
            provider.as_ref(),
            &squid_client,
            chain,
            from_block,
            to_block,
            args.block_query_limit,
            args.timestamp_source,
            squid_endpoint.as_deref(),
            args.squid_page_size,
            !args.no_rpc_fallback,
            args.dry_run,
        )
        .await?;
        total_blocks = total_blocks.saturating_add(blocks);
        total_rows = total_rows.saturating_add(rows);
    }

    progress!(
        "complete chains={} blocks={} rows={} dry_run={} elapsed_ms={}",
        selected_count,
        total_blocks,
        total_rows,
        args.dry_run,
        started.elapsed().as_millis()
    );
    Ok(())
}

async fn backfill_chain(
    store: &Store,
    provider: Option<&RootProvider>,
    squid_client: &Client,
    chain: &ChainIndexedChainConfig,
    from_block: u64,
    to_block: u64,
    block_query_limit: u64,
    timestamp_source: TimestampSource,
    squid_endpoint: Option<&str>,
    squid_page_size: u64,
    rpc_fallback: bool,
    dry_run: bool,
) -> Result<(u64, u64)> {
    let started = Instant::now();
    let mut total_blocks = 0_u64;
    let mut total_rows = 0_u64;

    if !dry_run {
        let mut tx = store
            .begin()
            .await
            .wrap_err("begin local timestamp seed tx")?;
        let seeded = Store::backfill_wallet_scan_timestamps_from_local_sources(
            &mut tx,
            EVM_CHAIN_TYPE,
            chain.chain_id,
            chain.railgun_contract,
            from_block,
            to_block,
        )
        .await
        .wrap_err("seed wallet-scan timestamps from local indexed rows")?;
        tx.commit()
            .await
            .wrap_err("commit local timestamp seed tx")?;
        if seeded > 0 {
            total_rows = total_rows.saturating_add(seeded);
            progress!(
                "chain {}: seeded local timestamps rows={}",
                chain.chain_id,
                seeded
            );
        }
    }

    loop {
        let missing = store
            .missing_wallet_scan_timestamp_blocks(
                EVM_CHAIN_TYPE,
                chain.chain_id,
                chain.railgun_contract,
                from_block,
                to_block,
                block_query_limit,
            )
            .await
            .wrap_err("query missing wallet-scan timestamp blocks")?;
        if missing.is_empty() {
            break;
        }

        let mut resolved = Vec::new();
        if timestamp_source == TimestampSource::Squid {
            let endpoint = squid_endpoint.ok_or_else(|| {
                eyre!(
                    "missing Squid endpoint for chain {}; pass --squid-endpoint {}=URL",
                    chain.chain_id,
                    chain.chain_id
                )
            })?;
            let squid_resolved = resolve_missing_with_squid(
                squid_client,
                endpoint,
                chain.chain_id,
                &missing,
                squid_page_size,
            )
            .await?;
            progress!(
                "chain {}: Squid resolved blocks={} requested_blocks={}",
                chain.chain_id,
                squid_resolved.len(),
                missing.len()
            );
            resolved.extend(squid_resolved);
        }

        let unresolved = unresolved_missing_blocks(&missing, &resolved);
        if (timestamp_source == TimestampSource::Rpc || (rpc_fallback && !unresolved.is_empty()))
            && !unresolved.is_empty()
        {
            let provider = provider.ok_or_else(|| {
                eyre!(
                    "archive RPC provider is unavailable for chain {}; remove --no-rpc-fallback or use --timestamp-source=rpc",
                    chain.chain_id
                )
            })?;
            let rpc_resolved = resolve_missing_with_rpc(provider, chain.chain_id, &unresolved)
                .await
                .wrap_err("resolve missing timestamps from archive RPC")?;
            progress!(
                "chain {}: RPC resolved blocks={} requested_blocks={}",
                chain.chain_id,
                rpc_resolved.len(),
                unresolved.len()
            );
            resolved.extend(rpc_resolved);
        }

        if resolved.is_empty() {
            progress!(
                "chain {}: no timestamps resolved for current batch; remaining first_block={} blocks={} rpc_fallback={}",
                chain.chain_id,
                missing[0].block_number,
                missing.len(),
                rpc_fallback
            );
            break;
        }

        let updated = apply_resolved_timestamps(store, chain, &resolved, dry_run).await?;
        total_blocks = total_blocks.saturating_add(
            u64::try_from(resolved.len()).wrap_err("resolved block count overflow")?,
        );
        total_rows = total_rows.saturating_add(updated);
        progress!(
            "chain {}: updated timestamp batch blocks={} rows={} dry_run={}",
            chain.chain_id,
            resolved.len(),
            updated,
            dry_run
        );

        if dry_run {
            break;
        }
    }
    let remaining = store
        .count_missing_wallet_scan_timestamps(
            EVM_CHAIN_TYPE,
            chain.chain_id,
            chain.railgun_contract,
            from_block,
            to_block,
        )
        .await
        .wrap_err("count remaining missing wallet-scan timestamps")?;
    progress!(
        "chain {}: complete blocks={} rows={} remaining={} dry_run={} elapsed_ms={}",
        chain.chain_id,
        total_blocks,
        total_rows,
        remaining,
        dry_run,
        started.elapsed().as_millis()
    );
    Ok((total_blocks, total_rows))
}

async fn apply_resolved_timestamps(
    store: &Store,
    chain: &ChainIndexedChainConfig,
    resolved: &[ResolvedTimestamp],
    dry_run: bool,
) -> Result<u64> {
    if dry_run {
        return Ok(resolved.iter().map(|item| item.missing_rows).sum());
    }
    let updates = resolved
        .iter()
        .map(|item| StoredWalletScanTimestampBackfill {
            block_number: item.block_number,
            block_hash: item.block_hash,
            block_timestamp: item.block_timestamp,
        })
        .collect::<Vec<_>>();
    let mut tx = store
        .begin()
        .await
        .wrap_err("begin timestamp backfill tx")?;
    let updated = Store::backfill_wallet_scan_block_timestamps(
        &mut tx,
        EVM_CHAIN_TYPE,
        chain.chain_id,
        chain.railgun_contract,
        &updates,
    )
    .await
    .wrap_err("bulk update wallet-scan timestamp rows")?;
    tx.commit().await.wrap_err("commit timestamp backfill tx")?;
    Ok(updated)
}

async fn resolve_missing_with_rpc(
    provider: &RootProvider,
    chain_id: u64,
    missing: &[StoredMissingWalletScanTimestampBlock],
) -> Result<Vec<ResolvedTimestamp>> {
    let mut resolved = Vec::with_capacity(missing.len());
    for block in missing {
        let block_hash = FixedBytes::from(block.block_hash);
        let timestamp = block_timestamp_for_source(provider, block_hash, block.block_number)
            .await
            .wrap_err_with(|| {
                format!(
                    "fetch timestamp for chain {chain_id} block {}",
                    block.block_number
                )
            })?;
        resolved.push(ResolvedTimestamp {
            block_number: block.block_number,
            block_hash: block.block_hash,
            block_timestamp: timestamp,
            missing_rows: block.missing_rows,
        });
    }
    Ok(resolved)
}

async fn resolve_missing_with_squid(
    client: &Client,
    endpoint: &str,
    chain_id: u64,
    missing: &[StoredMissingWalletScanTimestampBlock],
    page_size: u64,
) -> Result<Vec<ResolvedTimestamp>> {
    let (block_numbers, ambiguous_blocks) = squid_eligible_block_numbers(missing);
    if !ambiguous_blocks.is_empty() {
        progress!(
            "chain {}: skipping Squid timestamps for {} block number(s) with multiple block hashes",
            chain_id,
            ambiguous_blocks.len()
        );
    }
    if block_numbers.is_empty() {
        return Ok(Vec::new());
    }
    let timestamps = fetch_squid_timestamps(client, endpoint, chain_id, &block_numbers, page_size)
        .await
        .wrap_err("fetch Squid block timestamps")?;
    let mut resolved = Vec::new();
    for block in missing {
        if ambiguous_blocks.contains(&block.block_number) {
            continue;
        }
        if let Some(timestamp) = timestamps.get(&block.block_number) {
            resolved.push(ResolvedTimestamp {
                block_number: block.block_number,
                block_hash: block.block_hash,
                block_timestamp: *timestamp,
                missing_rows: block.missing_rows,
            });
        }
    }
    Ok(resolved)
}

fn unresolved_missing_blocks(
    missing: &[StoredMissingWalletScanTimestampBlock],
    resolved: &[ResolvedTimestamp],
) -> Vec<StoredMissingWalletScanTimestampBlock> {
    let resolved_keys = resolved
        .iter()
        .map(|item| (item.block_number, item.block_hash))
        .collect::<HashSet<_>>();
    missing
        .iter()
        .filter(|block| !resolved_keys.contains(&(block.block_number, block.block_hash)))
        .cloned()
        .collect()
}

fn squid_eligible_block_numbers(
    missing: &[StoredMissingWalletScanTimestampBlock],
) -> (Vec<u64>, HashSet<u64>) {
    let mut block_hashes = HashMap::<u64, [u8; 32]>::new();
    let mut ambiguous_blocks = HashSet::new();
    for block in missing {
        if let Some(previous_hash) = block_hashes.insert(block.block_number, block.block_hash)
            && previous_hash != block.block_hash
        {
            ambiguous_blocks.insert(block.block_number);
        }
    }
    let mut block_numbers = block_hashes
        .keys()
        .copied()
        .filter(|block_number| !ambiguous_blocks.contains(block_number))
        .collect::<Vec<_>>();
    block_numbers.sort_unstable();
    (block_numbers, ambiguous_blocks)
}

async fn fetch_squid_timestamps(
    client: &Client,
    endpoint: &str,
    chain_id: u64,
    block_numbers: &[u64],
    page_size: u64,
) -> Result<HashMap<u64, u64>> {
    let mut timestamps = HashMap::new();
    let requested = block_numbers.iter().copied().collect::<HashSet<_>>();
    let block_list_result = fetch_squid_timestamps_with_mode(
        client,
        endpoint,
        chain_id,
        SquidTimestampFilter::BlockList { block_numbers },
        &requested,
        page_size,
        &mut timestamps,
    )
    .await;
    match block_list_result {
        Ok(()) => Ok(timestamps),
        Err(error) => {
            progress!(
                "chain {}: Squid blockNumber_in timestamp query failed; falling back to block range query: {}",
                chain_id,
                error
            );
            let min_block = *block_numbers
                .first()
                .ok_or_else(|| eyre!("Squid timestamp block list unexpectedly empty"))?;
            let max_block = *block_numbers
                .last()
                .ok_or_else(|| eyre!("Squid timestamp block list unexpectedly empty"))?;
            let mut range_timestamps = HashMap::new();
            fetch_squid_timestamps_with_mode(
                client,
                endpoint,
                chain_id,
                SquidTimestampFilter::BlockRange {
                    min_block,
                    max_block,
                },
                &requested,
                page_size,
                &mut range_timestamps,
            )
            .await?;
            Ok(range_timestamps)
        }
    }
}

async fn fetch_squid_timestamps_with_mode(
    client: &Client,
    endpoint: &str,
    chain_id: u64,
    filter: SquidTimestampFilter<'_>,
    requested: &HashSet<u64>,
    page_size: u64,
    timestamps: &mut HashMap<u64, u64>,
) -> Result<()> {
    match filter {
        SquidTimestampFilter::BlockList { block_numbers } => {
            for chunk in block_numbers.chunks(SQUID_BLOCK_NUMBER_FILTER_LIMIT) {
                for field in SQUID_TIMESTAMP_FIELDS {
                    fetch_squid_timestamp_pages(
                        client,
                        endpoint,
                        chain_id,
                        field,
                        SquidTimestampFilter::BlockList {
                            block_numbers: chunk,
                        },
                        requested,
                        page_size,
                        timestamps,
                    )
                    .await?;
                }
            }
        }
        SquidTimestampFilter::BlockRange {
            min_block,
            max_block,
        } => {
            for field in SQUID_TIMESTAMP_FIELDS {
                fetch_squid_timestamp_pages(
                    client,
                    endpoint,
                    chain_id,
                    field,
                    SquidTimestampFilter::BlockRange {
                        min_block,
                        max_block,
                    },
                    requested,
                    page_size,
                    timestamps,
                )
                .await?;
            }
        }
    }
    Ok(())
}

async fn fetch_squid_timestamp_pages(
    client: &Client,
    endpoint: &str,
    chain_id: u64,
    field: &str,
    filter: SquidTimestampFilter<'_>,
    requested: &HashSet<u64>,
    page_size: u64,
    timestamps: &mut HashMap<u64, u64>,
) -> Result<()> {
    let mut offset = 0_u64;
    loop {
        let page = fetch_squid_timestamp_page(client, endpoint, field, filter, offset, page_size)
            .await
            .wrap_err_with(|| format!("fetch Squid {field} timestamp page offset {offset}"))?;
        let page_len = page.len();
        for value in &page {
            record_squid_timestamp(chain_id, field, requested, timestamps, value)?;
        }
        if page_len < usize::try_from(page_size).wrap_err("Squid timestamp page size overflow")? {
            break;
        }
        offset = offset.saturating_add(page_size);
    }
    Ok(())
}

async fn fetch_squid_timestamp_page(
    client: &Client,
    endpoint: &str,
    field: &str,
    filter: SquidTimestampFilter<'_>,
    offset: u64,
    limit: u64,
) -> Result<Vec<Value>> {
    for attempt in 1..=SQUID_PAGE_RETRY_ATTEMPTS {
        match fetch_squid_timestamp_page_once(client, endpoint, field, filter, offset, limit).await
        {
            Ok(page) => return Ok(page),
            Err(error)
                if attempt < SQUID_PAGE_RETRY_ATTEMPTS && is_retriable_squid_page_error(&error) =>
            {
                let delay = SQUID_PAGE_RETRY_BASE_DELAY * u32::try_from(attempt).unwrap_or(1);
                progress!(
                    "Squid {} timestamp page offset {} attempt {}/{} failed with transient error; retrying in {}ms: {}",
                    field,
                    offset,
                    attempt,
                    SQUID_PAGE_RETRY_ATTEMPTS,
                    delay.as_millis(),
                    error
                );
                tokio::time::sleep(delay).await;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("Squid timestamp page retry loop must return")
}

async fn fetch_squid_timestamp_page_once(
    client: &Client,
    endpoint: &str,
    field: &str,
    filter: SquidTimestampFilter<'_>,
    offset: u64,
    limit: u64,
) -> Result<Vec<Value>> {
    let query = squid_timestamp_query(field, filter);
    let variables = squid_timestamp_variables(filter, offset, limit)?;
    let body = serde_json::json!({
        "query": query,
        "variables": variables,
    });
    let response = client
        .post(endpoint)
        .json(&body)
        .send()
        .await
        .wrap_err_with(|| {
            format!("post Squid {field} timestamp page offset {offset} to {endpoint}")
        })?
        .error_for_status()
        .wrap_err_with(|| {
            format!("Squid {field} timestamp page offset {offset} returned error status")
        })?
        .json::<GraphqlResponse>()
        .await
        .wrap_err("decode Squid GraphQL response")?;
    if let Some(errors) = response.errors {
        bail!("Squid GraphQL errors: {errors}");
    }
    let data = response
        .data
        .ok_or_else(|| eyre!("Squid response missing data"))?;
    Ok(data
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| eyre!("Squid response missing field {field}"))?
        .clone())
}

fn record_squid_timestamp(
    chain_id: u64,
    field: &str,
    requested: &HashSet<u64>,
    timestamps: &mut HashMap<u64, u64>,
    value: &Value,
) -> Result<()> {
    let block_number = u64_field(value, "blockNumber")?;
    if !requested.contains(&block_number) {
        return Ok(());
    }
    let block_timestamp = u64_field(value, "blockTimestamp")?;
    if let Some(previous) = timestamps.insert(block_number, block_timestamp)
        && previous != block_timestamp
    {
        bail!(
            "chain {chain_id}: conflicting Squid timestamps for block {block_number} from {field}: {previous} != {block_timestamp}"
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum SquidTimestampFilter<'a> {
    BlockList { block_numbers: &'a [u64] },
    BlockRange { min_block: u64, max_block: u64 },
}

fn squid_timestamp_query(field: &str, filter: SquidTimestampFilter<'_>) -> String {
    let (variables, predicate) = match filter {
        SquidTimestampFilter::BlockList { .. } => {
            ("$blockNumbers: [BigInt!]!", "blockNumber_in: $blockNumbers")
        }
        SquidTimestampFilter::BlockRange { .. } => (
            "$minBlock: BigInt!, $maxBlock: BigInt!",
            "blockNumber_gte: $minBlock, blockNumber_lte: $maxBlock",
        ),
    };
    format!(
        "query TimestampBackfill($offset: Int!, $limit: Int!, {variables}) {{ \
           {field}(orderBy: [blockNumber_ASC], offset: $offset, limit: $limit, where: {{{predicate}}}) {{ \
             blockNumber \
             blockTimestamp \
           }} \
         }}"
    )
}

fn squid_timestamp_variables(
    filter: SquidTimestampFilter<'_>,
    offset: u64,
    limit: u64,
) -> Result<Value> {
    let offset = i32::try_from(offset).wrap_err("Squid offset exceeds GraphQL Int")?;
    let limit = i32::try_from(limit).wrap_err("Squid limit exceeds GraphQL Int")?;
    let mut variables = serde_json::json!({
        "offset": offset,
        "limit": limit,
    });
    let object = variables
        .as_object_mut()
        .ok_or_else(|| eyre!("Squid variables object unexpectedly missing"))?;
    match filter {
        SquidTimestampFilter::BlockList { block_numbers } => {
            object.insert(
                "blockNumbers".to_owned(),
                Value::Array(
                    block_numbers
                        .iter()
                        .map(|block_number| Value::String(block_number.to_string()))
                        .collect(),
                ),
            );
        }
        SquidTimestampFilter::BlockRange {
            min_block,
            max_block,
        } => {
            object.insert("minBlock".to_owned(), Value::String(min_block.to_string()));
            object.insert("maxBlock".to_owned(), Value::String(max_block.to_string()));
        }
    }
    Ok(variables)
}

fn is_retriable_squid_page_error(error: &eyre::Report) -> bool {
    error.chain().any(|source| {
        source
            .downcast_ref::<reqwest::Error>()
            .is_some_and(|error| {
                error.is_timeout()
                    || error.is_connect()
                    || error.status().is_some_and(|status| {
                        status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS
                    })
            })
    })
}

fn u64_field(value: &Value, field: &'static str) -> Result<u64> {
    let value = value
        .get(field)
        .ok_or_else(|| eyre!("Squid row missing {field}"))?;
    if let Some(number) = value.as_u64() {
        return Ok(number);
    }
    value
        .as_str()
        .ok_or_else(|| eyre!("Squid field {field} is not a string or number"))?
        .parse()
        .wrap_err_with(|| format!("parse Squid field {field}"))
}

fn selected_chains<'a>(
    config: &'a Config,
    args: &Args,
) -> Result<Vec<&'a ChainIndexedChainConfig>> {
    let chains = config
        .chain_indexed
        .chains
        .iter()
        .filter(|chain| args.chain_ids.is_empty() || args.chain_ids.contains(&chain.chain_id))
        .collect::<Vec<_>>();
    if chains.is_empty() {
        bail!("no chain_indexed chains matched --chain-id filters");
    }
    Ok(chains)
}

fn load_config(path: &PathBuf) -> Result<Config> {
    let data = fs::read_to_string(path).wrap_err("read config file")?;
    serde_yaml::from_str(&data).wrap_err("parse yaml config")
}

fn parse_squid_endpoint_overrides(raw: &[String]) -> Result<HashMap<u64, String>> {
    let mut overrides = HashMap::new();
    for value in raw {
        let (chain_id, endpoint) = value
            .split_once('=')
            .ok_or_else(|| eyre!("--squid-endpoint must use CHAIN_ID=URL, got {value}"))?;
        let chain_id = chain_id
            .parse::<u64>()
            .wrap_err_with(|| format!("parse Squid endpoint chain id from {value}"))?;
        let endpoint = endpoint.trim();
        if endpoint.is_empty() {
            bail!("--squid-endpoint URL must be non-empty for chain {chain_id}");
        }
        url::Url::parse(endpoint)
            .wrap_err_with(|| format!("parse Squid endpoint URL for chain {chain_id}"))?;
        overrides.insert(chain_id, endpoint.to_owned());
    }
    Ok(overrides)
}

fn squid_endpoint_for_chain(chain_id: u64, overrides: &HashMap<u64, String>) -> Result<String> {
    if let Some(endpoint) = overrides.get(&chain_id) {
        return Ok(endpoint.clone());
    }
    Ok(default_squid_endpoint(chain_id)?.to_owned())
}

fn default_squid_endpoint(chain_id: u64) -> Result<&'static str> {
    match chain_id {
        1 => Ok("https://rail-squid.squids.live/squid-railgun-ethereum-v2/graphql"),
        56 => Ok("https://rail-squid.squids.live/squid-railgun-bsc-v2/graphql"),
        137 => Ok("https://rail-squid.squids.live/squid-railgun-polygon-v2/graphql"),
        42161 => Ok("https://rail-squid.squids.live/squid-railgun-arbitrum-v2/graphql"),
        _ => bail!(
            "unsupported default Squid endpoint for chain {chain_id}; pass --squid-endpoint {chain_id}=URL"
        ),
    }
}

fn build_provider(rpc_url: &str) -> Result<RootProvider> {
    let url = url::Url::parse(rpc_url).wrap_err("parse RPC URL")?;
    Ok(ProviderBuilder::new().connect_http(url).root().clone())
}
