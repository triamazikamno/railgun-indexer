use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use alloy::hex;
use alloy::primitives::U256;
use broadcaster_core::transact::{
    compute_railgun_txid_parts, railgun_txid_leaf_hash_with_output_start,
};
use broadcaster_core::tree::TREE_LEAF_COUNT;
use clap::Parser;
use eyre::{Context, Result, bail, eyre};
use merkletree::tree::DenseMerkleTree;
use railgun_indexer_core::chunk::{ChunkEnvelope, decode_chunk_bytes};
use railgun_indexer_core::manifest::{
    IndexedArtifactCatalog, IndexedArtifactDescriptor, IndexedArtifactManifest,
    IndexedArtifactRangeKind, IndexedDatasetKind,
};
use railgun_indexer_core::publish::ipfs::raw_block_cid;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing_subscriber::EnvFilter;

macro_rules! progress {
    ($($arg:tt)*) => {{
        eprintln!("[txid-parity] {}", format_args!($($arg)*));
        let _ = io::stderr().flush();
    }};
}

const DEFAULT_MANIFEST_CID: &str = "QmUasLbTLuc6f9mE1oLcu851CAmW3zFhkkurnSvDscoGZw";
const DEFAULT_PAGE_SIZE: u64 = 10_000;
const SQUID_CACHE_VERSION: u32 = 1;
const IPFS_GATEWAYS: &[&str] = &["https://ipfs.io/ipfs/", "https://dweb.link/ipfs/"];
const IPNS_GATEWAYS: &[&str] = &["https://ipfs.io/ipns/", "https://dweb.link/ipns/"];

#[derive(Debug, Parser)]
#[command(about = "Verify published public TXID artifacts against Squid offset semantics")]
struct Args {
    /// Published chain-indexed manifest CID to verify.
    #[arg(long, default_value = DEFAULT_MANIFEST_CID)]
    manifest_cid: String,

    /// Chain-indexed manifest IPNS name to resolve instead of --manifest-cid.
    #[arg(long)]
    manifest_ipns_name: Option<String>,

    /// Squid GraphQL page size.
    #[arg(long, default_value_t = DEFAULT_PAGE_SIZE)]
    page_size: u64,

    /// Restrict verification to specific chain IDs. May be repeated.
    #[arg(long = "chain-id")]
    chain_ids: Vec<u64>,

    /// Print leaf hashing progress after this many rows.
    #[arg(long, default_value_t = 1_000)]
    progress_every: usize,

    /// Directory for reusable raw Squid public TXID cache files.
    #[arg(long)]
    squid_cache_dir: Option<PathBuf>,

    /// Ignore any existing Squid cache and rewrite it from Squid.
    #[arg(long)]
    refresh_squid_cache: bool,
}

#[derive(Debug, Clone)]
struct TxidRow {
    txid_index: u64,
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
            "index={} block={} timestamp={} tx=0x{} id={} out_global={} nullifiers={} commitments={} unshield={}",
            self.txid_index,
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

#[derive(Debug)]
struct ArtifactTxidData {
    rows: Vec<TxidRow>,
    chunks: Vec<IndexedArtifactDescriptor>,
}

#[derive(Debug)]
struct ChainParity {
    chain_id: u64,
    artifact_count: usize,
    squid_count: usize,
    matching_leaf_prefix: usize,
    matching_row_prefix: usize,
    artifact_tree_roots: BTreeMap<u64, [u8; 32]>,
    squid_tree_roots: BTreeMap<u64, [u8; 32]>,
    descriptor_root_errors: usize,
    first_leaf_mismatch: Option<Mismatch>,
    first_row_mismatch: Option<Mismatch>,
}

#[derive(Debug)]
struct Mismatch {
    index: usize,
    artifact: Option<TxidRow>,
    squid: Option<TxidRow>,
    artifact_leaf: Option<[u8; 32]>,
    squid_leaf: Option<[u8; 32]>,
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

#[derive(Debug, Serialize, Deserialize)]
struct SquidCacheFile {
    version: u32,
    chain_id: u64,
    endpoint: String,
    max_block: u64,
    row_count: usize,
    fetched_at_unix: u64,
    transactions: Vec<Value>,
}

#[derive(Debug)]
struct ManifestFetch {
    bytes: Vec<u8>,
    cid: String,
    source: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    if args.page_size == 0 {
        bail!("--page-size must be non-zero");
    }
    if args.progress_every == 0 {
        bail!("--progress-every must be non-zero");
    }
    if args.refresh_squid_cache && args.squid_cache_dir.is_none() {
        bail!("--refresh-squid-cache requires --squid-cache-dir");
    }

    let client = Client::builder()
        .user_agent("railgun-indexer-txid-parity/0.1")
        .build()?;
    let manifest_fetch = fetch_manifest(&client, &args).await?;
    let manifest: IndexedArtifactManifest = serde_json::from_slice(&manifest_fetch.bytes)
        .wrap_err("decode published indexed artifact manifest")?;
    progress!("verifying manifest signature");
    manifest
        .verify_signature()
        .wrap_err("verify manifest signature")?;
    println!(
        "manifest source={} cid={} sequence={} chains={} signature=ok",
        manifest_fetch.source,
        manifest_fetch.cid,
        manifest.sequence,
        manifest.chains.len()
    );

    let mut failures = 0_usize;
    for chain in &manifest.chains {
        let chain_id = chain.scope.chain_id;
        if !args.chain_ids.is_empty() && !args.chain_ids.contains(&chain_id) {
            continue;
        }
        let Some(catalog) = chain
            .catalogs
            .iter()
            .find(|catalog| catalog.dataset_kind == IndexedDatasetKind::PublicTxid)
        else {
            println!("chain {chain_id}: no public_txid catalog");
            continue;
        };
        progress!(
            "chain {}: starting public_txid parity catalog_cid={} rows={} range={:?}",
            chain_id,
            catalog.cid,
            catalog.row_count,
            catalog.range
        );
        let artifact = artifact_public_txid_data(&client, chain_id, catalog).await?;
        progress!(
            "chain {}: artifact rows loaded rows={} chunks={}",
            chain_id,
            artifact.rows.len(),
            artifact.chunks.len()
        );
        let max_block = chain
            .latest_indexed
            .iter()
            .find(|height| height.dataset_kind == IndexedDatasetKind::PublicTxid)
            .map(|height| height.block_number)
            .ok_or_else(|| eyre!("chain {chain_id} missing public_txid latest indexed height"))?;
        let squid_rows = squid_public_txid_rows(
            &client,
            chain_id,
            args.page_size,
            max_block,
            args.squid_cache_dir.as_deref(),
            args.refresh_squid_cache,
        )
        .await?;
        progress!(
            "chain {}: Squid rows loaded rows={}",
            chain_id,
            squid_rows.len()
        );
        let parity = compare_chain(chain_id, &artifact, &squid_rows, args.progress_every)?;
        print_parity(&parity);
        if !parity.passed() {
            failures = failures.saturating_add(1);
        }
    }

    if failures > 0 {
        bail!("TXID parity failed for {failures} chain(s)");
    }
    Ok(())
}

impl ChainParity {
    fn passed(&self) -> bool {
        self.artifact_count == self.squid_count
            && self.artifact_tree_roots == self.squid_tree_roots
            && self.descriptor_root_errors == 0
            && self.first_leaf_mismatch.is_none()
            && self.first_row_mismatch.is_none()
    }
}

async fn artifact_public_txid_data(
    client: &Client,
    chain_id: u64,
    catalog: &IndexedArtifactDescriptor,
) -> Result<ArtifactTxidData> {
    progress!(
        "chain {}: fetching public_txid catalog cid={} byte_size={}",
        chain_id,
        catalog.cid,
        catalog.byte_size
    );
    let catalog_bytes = fetch_ipfs(client, &catalog.cid).await?;
    let decoded: IndexedArtifactCatalog = serde_json::from_slice(&catalog_bytes)
        .wrap_err_with(|| format!("decode public_txid catalog {}", catalog.cid))?;
    let mut chunks = decoded.chunks;
    chunks.sort_by_key(|chunk| chunk.range.start);
    progress!(
        "chain {}: public_txid catalog decoded chunks={}",
        chain_id,
        chunks.len()
    );

    let mut rows = Vec::new();
    for (index, chunk) in chunks.iter().enumerate() {
        progress!(
            "chain {}: fetching public_txid chunk {}/{} cid={} rows={} range={:?} byte_size={}",
            chain_id,
            index + 1,
            chunks.len(),
            chunk.cid,
            chunk.row_count,
            chunk.range,
            chunk.byte_size
        );
        let bytes = fetch_ipfs(client, &chunk.cid).await?;
        let envelope = decode_chunk_bytes(chunk, &bytes)
            .wrap_err_with(|| format!("decode public_txid chunk {}", chunk.cid))?;
        let mut chunk_rows = parse_public_txid_payload(&envelope, chunk)
            .wrap_err_with(|| format!("parse public_txid chunk {}", chunk.cid))?;
        progress!(
            "chain {}: decoded public_txid chunk {}/{} rows={} cumulative_rows={}",
            chain_id,
            index + 1,
            chunks.len(),
            chunk_rows.len(),
            rows.len().saturating_add(chunk_rows.len())
        );
        rows.append(&mut chunk_rows);
    }
    rows.sort_by_key(|row| row.txid_index);
    for (expected, row) in rows.iter().enumerate() {
        let expected = u64::try_from(expected).wrap_err("artifact row index overflow")?;
        if row.txid_index != expected {
            bail!(
                "artifact txid_index is non-contiguous: expected {expected}, got {}",
                row.txid_index
            );
        }
    }
    Ok(ArtifactTxidData { rows, chunks })
}

async fn squid_public_txid_rows(
    client: &Client,
    chain_id: u64,
    page_size: u64,
    max_block: u64,
    cache_dir: Option<&Path>,
    refresh_cache: bool,
) -> Result<Vec<TxidRow>> {
    let endpoint = squid_endpoint(chain_id)?;
    let started = Instant::now();
    let values = squid_public_txid_values(
        client,
        chain_id,
        endpoint,
        page_size,
        max_block,
        cache_dir,
        refresh_cache,
    )
    .await?;
    let rows = parse_squid_transactions(&values, max_block)?;
    progress!(
        "chain {}: Squid rows parsed rows={} raw_rows={} target_max_block={} elapsed_ms={}",
        chain_id,
        rows.len(),
        values.len(),
        max_block,
        elapsed_ms(started)
    );
    Ok(rows)
}

async fn squid_public_txid_values(
    client: &Client,
    chain_id: u64,
    endpoint: &str,
    page_size: u64,
    max_block: u64,
    cache_dir: Option<&Path>,
    refresh_cache: bool,
) -> Result<Vec<Value>> {
    let Some(cache_dir) = cache_dir else {
        progress!(
            "chain {}: Squid cache disabled endpoint={} page_size={} max_block={}",
            chain_id,
            endpoint,
            page_size,
            max_block
        );
        return fetch_squid_values(client, endpoint, chain_id, page_size, None, max_block).await;
    };

    let cache_path = squid_cache_path(cache_dir, chain_id);
    if refresh_cache {
        progress!(
            "chain {}: refreshing Squid cache path={} endpoint={} max_block={}",
            chain_id,
            cache_path.display(),
            endpoint,
            max_block
        );
        let transactions =
            fetch_squid_values(client, endpoint, chain_id, page_size, None, max_block).await?;
        write_squid_cache(
            &cache_path,
            chain_id,
            endpoint,
            max_block,
            transactions.clone(),
        )?;
        return Ok(transactions);
    }

    if !cache_path.exists() {
        progress!(
            "chain {}: Squid cache miss path={} endpoint={} max_block={}",
            chain_id,
            cache_path.display(),
            endpoint,
            max_block
        );
        let transactions =
            fetch_squid_values(client, endpoint, chain_id, page_size, None, max_block).await?;
        write_squid_cache(
            &cache_path,
            chain_id,
            endpoint,
            max_block,
            transactions.clone(),
        )?;
        return Ok(transactions);
    }

    let mut cache = read_squid_cache(&cache_path, chain_id, endpoint)?;
    let usable_rows = count_squid_rows_at_or_below(&cache.transactions, max_block)?;
    progress!(
        "chain {}: Squid cache hit path={} cache_max_block={} target_max_block={} cached_rows={} usable_rows={}",
        chain_id,
        cache_path.display(),
        cache.max_block,
        max_block,
        cache.transactions.len(),
        usable_rows
    );

    if cache.max_block < max_block {
        progress!(
            "chain {}: Squid cache behind by {} blocks; fetching delta block_gt={} block_lte={}",
            chain_id,
            max_block.saturating_sub(cache.max_block),
            cache.max_block,
            max_block
        );
        let mut delta = fetch_squid_values(
            client,
            endpoint,
            chain_id,
            page_size,
            Some(cache.max_block),
            max_block,
        )
        .await?;
        progress!(
            "chain {}: Squid delta loaded rows={} cached_rows={} new_cached_rows={}",
            chain_id,
            delta.len(),
            cache.transactions.len(),
            cache.transactions.len().saturating_add(delta.len())
        );
        cache.transactions.append(&mut delta);
        cache.max_block = max_block;
        cache.row_count = cache.transactions.len();
        cache.fetched_at_unix = unix_timestamp()?;
        write_squid_cache_file(&cache_path, &cache)?;
    } else if cache.max_block > max_block {
        progress!(
            "chain {}: Squid cache is ahead of target by {} blocks; filtering cached rows for verification",
            chain_id,
            cache.max_block.saturating_sub(max_block)
        );
    }

    Ok(cache.transactions)
}

async fn fetch_squid_values(
    client: &Client,
    endpoint: &str,
    chain_id: u64,
    page_size: u64,
    min_block_exclusive: Option<u64>,
    max_block: u64,
) -> Result<Vec<Value>> {
    let mut offset = 0_u64;
    let mut values = Vec::new();
    let started = Instant::now();
    let block_gt =
        min_block_exclusive.map_or_else(|| "<none>".to_string(), |block| block.to_string());
    progress!(
        "chain {}: starting Squid fetch endpoint={} block_gt={} block_lte={} page_size={}",
        chain_id,
        endpoint,
        block_gt,
        max_block,
        page_size
    );
    loop {
        let limit = page_size;
        let page_started = Instant::now();
        progress!(
            "chain {}: fetching Squid page offset={} limit={} block_gt={} block_lte={} loaded={}",
            chain_id,
            offset,
            limit,
            block_gt,
            max_block,
            values.len()
        );
        let page = fetch_squid_page(
            client,
            endpoint,
            offset,
            limit,
            min_block_exclusive,
            max_block,
        )
        .await?;
        if page.is_empty() {
            progress!(
                "chain {}: Squid returned empty page offset={} loaded={} page_elapsed_ms={} total_elapsed_ms={}",
                chain_id,
                offset,
                values.len(),
                elapsed_ms(page_started),
                elapsed_ms(started)
            );
            break;
        }
        let page_len = page.len();
        let tail = squid_page_tail(&page);
        values.extend(page);
        progress!(
            "chain {}: decoded Squid page offset={} rows={} cumulative_rows={} page_elapsed_ms={}{}",
            chain_id,
            offset,
            page_len,
            values.len(),
            elapsed_ms(page_started),
            tail
        );
        if page_len < usize::try_from(limit).wrap_err("Squid limit overflow")? {
            break;
        }
        offset = u64::try_from(values.len()).wrap_err("squid row count overflow")?;
    }
    progress!(
        "chain {}: finished Squid fetch rows={} block_gt={} block_lte={} elapsed_ms={}",
        chain_id,
        values.len(),
        block_gt,
        max_block,
        elapsed_ms(started)
    );
    Ok(values)
}

fn parse_squid_transactions(values: &[Value], max_block: u64) -> Result<Vec<TxidRow>> {
    let mut rows = Vec::new();
    for value in values {
        if u64_field(value, "blockNumber")? > max_block {
            continue;
        }
        let txid_index = u64::try_from(rows.len()).wrap_err("Squid txid index overflow")?;
        rows.push(parse_squid_transaction(txid_index, value)?);
    }
    Ok(rows)
}

fn count_squid_rows_at_or_below(values: &[Value], max_block: u64) -> Result<usize> {
    values.iter().try_fold(0_usize, |count, value| {
        let block_number = u64_field(value, "blockNumber")?;
        Ok(if block_number <= max_block {
            count.saturating_add(1)
        } else {
            count
        })
    })
}

fn read_squid_cache(path: &Path, chain_id: u64, endpoint: &str) -> Result<SquidCacheFile> {
    let bytes = fs::read(path).wrap_err_with(|| format!("read Squid cache {}", path.display()))?;
    let cache: SquidCacheFile = serde_json::from_slice(&bytes)
        .wrap_err_with(|| format!("decode Squid cache {}", path.display()))?;
    if cache.version != SQUID_CACHE_VERSION {
        bail!(
            "Squid cache {} has unsupported version {}; rerun with --refresh-squid-cache",
            path.display(),
            cache.version
        );
    }
    if cache.chain_id != chain_id {
        bail!(
            "Squid cache {} is for chain {}, expected {}; rerun with --refresh-squid-cache",
            path.display(),
            cache.chain_id,
            chain_id
        );
    }
    if cache.endpoint != endpoint {
        bail!(
            "Squid cache {} endpoint mismatch; cached={} expected={}; rerun with --refresh-squid-cache",
            path.display(),
            cache.endpoint,
            endpoint
        );
    }
    if cache.row_count != cache.transactions.len() {
        bail!(
            "Squid cache {} row_count mismatch metadata={} rows={}; rerun with --refresh-squid-cache",
            path.display(),
            cache.row_count,
            cache.transactions.len()
        );
    }
    let max_seen = max_squid_block(&cache.transactions)?;
    if max_seen > cache.max_block {
        bail!(
            "Squid cache {} contains block {} beyond cache max_block {}; rerun with --refresh-squid-cache",
            path.display(),
            max_seen,
            cache.max_block
        );
    }
    Ok(cache)
}

fn write_squid_cache(
    path: &Path,
    chain_id: u64,
    endpoint: &str,
    max_block: u64,
    transactions: Vec<Value>,
) -> Result<()> {
    let cache = SquidCacheFile {
        version: SQUID_CACHE_VERSION,
        chain_id,
        endpoint: endpoint.to_string(),
        max_block,
        row_count: transactions.len(),
        fetched_at_unix: unix_timestamp()?,
        transactions,
    };
    write_squid_cache_file(path, &cache)
}

fn write_squid_cache_file(path: &Path, cache: &SquidCacheFile) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .wrap_err_with(|| format!("create Squid cache dir {}", parent.display()))?;
    }
    let mut temp_path = path.to_path_buf();
    temp_path.set_extension(format!("json.tmp-{}", std::process::id()));
    let bytes = serde_json::to_vec(cache).wrap_err("encode Squid cache")?;
    fs::write(&temp_path, bytes)
        .wrap_err_with(|| format!("write Squid cache temp file {}", temp_path.display()))?;
    fs::rename(&temp_path, path).wrap_err_with(|| {
        format!(
            "rename Squid cache temp file {} to {}",
            temp_path.display(),
            path.display()
        )
    })?;
    progress!(
        "chain {}: wrote Squid cache path={} rows={} max_block={} fetched_at_unix={}",
        cache.chain_id,
        path.display(),
        cache.row_count,
        cache.max_block,
        cache.fetched_at_unix
    );
    Ok(())
}

fn squid_cache_path(cache_dir: &Path, chain_id: u64) -> PathBuf {
    cache_dir.join(format!("public-txid-squid-chain-{chain_id}.json"))
}

fn max_squid_block(values: &[Value]) -> Result<u64> {
    values.iter().try_fold(0_u64, |max_block, value| {
        Ok(max_block.max(u64_field(value, "blockNumber")?))
    })
}

fn unix_timestamp() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .wrap_err("system clock is before UNIX_EPOCH")?
        .as_secs())
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

fn compare_chain(
    chain_id: u64,
    artifact: &ArtifactTxidData,
    squid_rows: &[TxidRow],
    progress_every: usize,
) -> Result<ChainParity> {
    progress!(
        "chain {}: hashing artifact leaves rows={}",
        chain_id,
        artifact.rows.len()
    );
    let artifact_leaves = leaf_hashes(chain_id, "artifact", &artifact.rows, progress_every);
    progress!(
        "chain {}: hashing Squid leaves rows={}",
        chain_id,
        squid_rows.len()
    );
    let squid_leaves = leaf_hashes(chain_id, "Squid", squid_rows, progress_every);
    progress!("chain {}: comparing rows and leaves", chain_id);
    let matching_leaf_prefix = matching_leaf_prefix(&artifact_leaves, &squid_leaves);
    let matching_row_prefix = matching_row_prefix(&artifact.rows, squid_rows);
    let first_leaf_mismatch =
        first_leaf_mismatch(&artifact.rows, squid_rows, &artifact_leaves, &squid_leaves);
    let first_row_mismatch =
        first_row_mismatch(&artifact.rows, squid_rows, &artifact_leaves, &squid_leaves);
    let artifact_tree_roots = roots_by_tree(chain_id, "artifact", &artifact_leaves)?;
    let squid_tree_roots = roots_by_tree(chain_id, "Squid", &squid_leaves)?;
    let descriptor_root_errors =
        verify_artifact_descriptor_roots(chain_id, &artifact.chunks, &artifact_leaves)?;
    Ok(ChainParity {
        chain_id,
        artifact_count: artifact.rows.len(),
        squid_count: squid_rows.len(),
        matching_leaf_prefix,
        matching_row_prefix,
        artifact_tree_roots,
        squid_tree_roots,
        descriptor_root_errors,
        first_leaf_mismatch,
        first_row_mismatch,
    })
}

fn leaf_hashes(chain_id: u64, source: &str, rows: &[TxidRow], progress_every: usize) -> Vec<U256> {
    let mut leaves = Vec::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        leaves.push(row.leaf_hash());
        let count = index + 1;
        if count % progress_every == 0 || count == rows.len() {
            progress!(
                "chain {}: hashed {} leaves {}/{}",
                chain_id,
                source,
                count,
                rows.len()
            );
        }
    }
    leaves
}

fn matching_leaf_prefix(artifact_leaves: &[U256], squid_leaves: &[U256]) -> usize {
    artifact_leaves
        .iter()
        .zip(squid_leaves)
        .take_while(|(left, right)| left == right)
        .count()
}

fn matching_row_prefix(artifact_rows: &[TxidRow], squid_rows: &[TxidRow]) -> usize {
    artifact_rows
        .iter()
        .zip(squid_rows)
        .take_while(|(left, right)| rows_match(left, right))
        .count()
}

fn first_leaf_mismatch(
    artifact_rows: &[TxidRow],
    squid_rows: &[TxidRow],
    artifact_leaves: &[U256],
    squid_leaves: &[U256],
) -> Option<Mismatch> {
    let max = artifact_rows.len().max(squid_rows.len());
    for index in 0..max {
        let artifact_leaf = artifact_leaves.get(index).map(u256_to_be_bytes);
        let squid_leaf = squid_leaves.get(index).map(u256_to_be_bytes);
        if artifact_leaf != squid_leaf {
            return Some(Mismatch {
                index,
                artifact: artifact_rows.get(index).cloned(),
                squid: squid_rows.get(index).cloned(),
                artifact_leaf,
                squid_leaf,
            });
        }
    }
    None
}

fn first_row_mismatch(
    artifact_rows: &[TxidRow],
    squid_rows: &[TxidRow],
    artifact_leaves: &[U256],
    squid_leaves: &[U256],
) -> Option<Mismatch> {
    let max = artifact_rows.len().max(squid_rows.len());
    for index in 0..max {
        let artifact = artifact_rows.get(index);
        let squid = squid_rows.get(index);
        if !matches!((artifact, squid), (Some(left), Some(right)) if rows_match(left, right)) {
            return Some(Mismatch {
                index,
                artifact: artifact.cloned(),
                squid: squid.cloned(),
                artifact_leaf: artifact_leaves.get(index).map(u256_to_be_bytes),
                squid_leaf: squid_leaves.get(index).map(u256_to_be_bytes),
            });
        }
    }
    None
}

const fn u256_to_be_bytes(value: &U256) -> [u8; 32] {
    value.to_be_bytes::<32>()
}

fn rows_match(left: &TxidRow, right: &TxidRow) -> bool {
    left.txid_index == right.txid_index
        && left.block_number == right.block_number
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

fn roots_by_tree(chain_id: u64, source: &str, leaves: &[U256]) -> Result<BTreeMap<u64, [u8; 32]>> {
    let mut roots = BTreeMap::new();
    let tree_leaf_count = usize::try_from(TREE_LEAF_COUNT).wrap_err("tree leaf count overflow")?;
    for (tree, chunk) in leaves.chunks(tree_leaf_count).enumerate() {
        let tree = u64::try_from(tree).wrap_err("tree number overflow")?;
        let leaf_count = u64::try_from(chunk.len()).wrap_err("leaf count overflow")?;
        progress!(
            "chain {}: building {} tree root tree={} leaves={}",
            chain_id,
            source,
            tree,
            leaf_count
        );
        let root = DenseMerkleTree::from_ordered_leaves(chunk.to_vec(), leaf_count).root();
        progress!(
            "chain {}: built {} tree root tree={} root=0x{}",
            chain_id,
            source,
            tree,
            hex::encode(root.to_be_bytes::<32>())
        );
        roots.insert(tree, root.to_be_bytes::<32>());
    }
    Ok(roots)
}

fn verify_artifact_descriptor_roots(
    chain_id: u64,
    chunks: &[IndexedArtifactDescriptor],
    leaves: &[U256],
) -> Result<usize> {
    progress!(
        "chain {}: verifying descriptor roots chunks={}",
        chain_id,
        chunks.len()
    );
    let mut errors = 0_usize;
    for (index, chunk) in chunks.iter().enumerate() {
        let Some(root) = chunk.metadata.root.as_ref() else {
            println!("  chunk {} has no public_txid checkpoint root", chunk.cid);
            errors = errors.saturating_add(1);
            continue;
        };
        let tree_start = chunk.range.end / TREE_LEAF_COUNT * TREE_LEAF_COUNT;
        let leaf_count = chunk
            .range
            .end
            .checked_sub(tree_start)
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| eyre!("chunk range overflow"))?;
        let start = usize::try_from(tree_start).wrap_err("tree start overflow")?;
        let end = usize::try_from(chunk.range.end).wrap_err("chunk end overflow")?;
        let slice = leaves
            .get(start..=end)
            .ok_or_else(|| eyre!("chunk range is outside artifact rows"))?;
        progress!(
            "chain {}: verifying descriptor root chunk {}/{} cid={} range={:?} leaves={}",
            chain_id,
            index + 1,
            chunks.len(),
            chunk.cid,
            chunk.range,
            slice.len()
        );
        let computed = DenseMerkleTree::from_ordered_leaves(slice.to_vec(), leaf_count).root();
        let computed = computed.to_be_bytes::<32>();
        if computed.as_slice() != root.as_slice() {
            println!(
                "  chunk {} root mismatch descriptor=0x{} computed=0x{}",
                chunk.cid,
                hex::encode(root.as_slice()),
                hex::encode(computed)
            );
            errors = errors.saturating_add(1);
        }
    }
    progress!(
        "chain {}: descriptor root verification complete errors={}",
        chain_id,
        errors
    );
    Ok(errors)
}

fn parse_public_txid_payload(
    envelope: &ChunkEnvelope,
    descriptor: &IndexedArtifactDescriptor,
) -> Result<Vec<TxidRow>> {
    if descriptor.dataset_kind != IndexedDatasetKind::PublicTxid
        || descriptor.range.kind != IndexedArtifactRangeKind::TxidIndex
    {
        bail!("descriptor is not a public_txid txid_index chunk");
    }
    let mut cursor = Cursor::new(envelope.payload());
    let row_count = usize::try_from(descriptor.row_count).wrap_err("row count overflow")?;
    let mut rows = Vec::with_capacity(row_count);
    for _ in 0..row_count {
        let txid_index = cursor.read_u64()?;
        let id = cursor.read_string()?;
        let block_number = cursor.read_u64()?;
        let block_timestamp = cursor.read_u64()?;
        let _block_hash = cursor.read_fixed_32()?;
        rows.push(TxidRow {
            txid_index,
            id,
            block_number,
            block_timestamp,
            transaction_hash: cursor.read_fixed_32()?,
            // Log indexes are part of artifact provenance, but Squid's public
            // transaction query does not expose them. Consume them here and
            // compare the fields both sources can provide.
            merkle_root: {
                let _first_log_index = cursor.read_u64()?;
                let _last_log_index = cursor.read_u64()?;
                cursor.read_fixed_32()?
            },
            nullifiers: cursor.read_fixed_vec()?,
            commitments: cursor.read_fixed_vec()?,
            bound_params_hash: cursor.read_fixed_32()?,
            has_unshield: cursor.read_u8()? != 0,
            utxo_tree_in: cursor.read_u64()?,
            utxo_tree_out: cursor.read_u64()?,
            utxo_batch_start_position_out: cursor.read_u64()?,
        });
    }
    if cursor.remaining() != 0 {
        bail!(
            "public_txid payload has {} trailing bytes",
            cursor.remaining()
        );
    }
    Ok(rows)
}

async fn fetch_squid_page(
    client: &Client,
    endpoint: &str,
    offset: u64,
    limit: u64,
    min_block_exclusive: Option<u64>,
    max_block: u64,
) -> Result<Vec<Value>> {
    let full_query = r"
query PublicTxidPage($offset: Int!, $limit: Int!, $maxBlock: BigInt!) {
  transactions(orderBy: id_ASC, offset: $offset, limit: $limit, where: {blockNumber_lte: $maxBlock}) {
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
    let delta_query = r"
query PublicTxidPage($offset: Int!, $limit: Int!, $minBlock: BigInt!, $maxBlock: BigInt!) {
  transactions(orderBy: id_ASC, offset: $offset, limit: $limit, where: {blockNumber_gt: $minBlock, blockNumber_lte: $maxBlock}) {
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
    let variables = if let Some(min_block) = min_block_exclusive {
        serde_json::json!({
            "offset": i32::try_from(offset).wrap_err("Squid offset exceeds GraphQL Int")?,
            "limit": i32::try_from(limit).wrap_err("Squid limit exceeds GraphQL Int")?,
            "minBlock": min_block.to_string(),
            "maxBlock": max_block.to_string(),
        })
    } else {
        serde_json::json!({
            "offset": i32::try_from(offset).wrap_err("Squid offset exceeds GraphQL Int")?,
            "limit": i32::try_from(limit).wrap_err("Squid limit exceeds GraphQL Int")?,
            "maxBlock": max_block.to_string(),
        })
    };
    let body = serde_json::json!({
        "query": if min_block_exclusive.is_some() { delta_query } else { full_query },
        "variables": variables
    });
    let response = client
        .post(endpoint)
        .json(&body)
        .send()
        .await
        .wrap_err_with(|| format!("post Squid page offset {offset} to {endpoint}"))?
        .error_for_status()
        .wrap_err_with(|| format!("Squid page offset {offset} returned error status"))?
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

fn parse_squid_transaction(txid_index: u64, value: &Value) -> Result<TxidRow> {
    Ok(TxidRow {
        txid_index,
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

async fn fetch_ipfs(client: &Client, cid: &str) -> Result<Vec<u8>> {
    let mut errors = Vec::new();
    for gateway in IPFS_GATEWAYS {
        let url = format!("{gateway}{cid}");
        match client.get(&url).send().await {
            Ok(response) => match response.error_for_status() {
                Ok(response) => return Ok(response.bytes().await?.to_vec()),
                Err(error) => errors.push(format!("{url}: {error}")),
            },
            Err(error) => errors.push(format!("{url}: {error}")),
        }
    }
    bail!("failed to fetch IPFS CID {cid}: {}", errors.join("; "))
}

async fn fetch_manifest(client: &Client, args: &Args) -> Result<ManifestFetch> {
    if let Some(ipns_name) = args.manifest_ipns_name.as_deref() {
        let ipns_name = normalize_ipns_name(ipns_name)?;
        progress!("fetching manifest ipns_name={}", ipns_name);
        let bytes = fetch_ipns(client, ipns_name).await?;
        let cid = raw_block_cid(&bytes)
            .wrap_err("compute CID for IPNS-resolved manifest bytes")?
            .to_string();
        progress!(
            "resolved manifest ipns_name={} computed_cid={} byte_size={}",
            ipns_name,
            cid,
            bytes.len()
        );
        return Ok(ManifestFetch {
            bytes,
            cid,
            source: format!("ipns:{ipns_name}"),
        });
    }

    progress!("fetching manifest cid={}", args.manifest_cid);
    let bytes = fetch_ipfs(client, &args.manifest_cid).await?;
    Ok(ManifestFetch {
        bytes,
        cid: args.manifest_cid.clone(),
        source: format!("cid:{}", args.manifest_cid),
    })
}

async fn fetch_ipns(client: &Client, ipns_name: &str) -> Result<Vec<u8>> {
    let mut errors = Vec::new();
    for gateway in IPNS_GATEWAYS {
        let url = format!("{gateway}{ipns_name}");
        match client.get(&url).send().await {
            Ok(response) => match response.error_for_status() {
                Ok(response) => return Ok(response.bytes().await?.to_vec()),
                Err(error) => errors.push(format!("{url}: {error}")),
            },
            Err(error) => errors.push(format!("{url}: {error}")),
        }
    }
    bail!(
        "failed to resolve IPNS name {ipns_name}: {}",
        errors.join("; ")
    )
}

fn normalize_ipns_name(value: &str) -> Result<&str> {
    let value = value.trim();
    let value = value.strip_prefix("/ipns/").unwrap_or(value);
    if value.is_empty() {
        bail!("--manifest-ipns-name must be non-empty");
    }
    Ok(value)
}

fn squid_endpoint(chain_id: u64) -> Result<&'static str> {
    match chain_id {
        1 => Ok("https://rail-squid.squids.live/squid-railgun-ethereum-v2/graphql"),
        56 => Ok("https://rail-squid.squids.live/squid-railgun-bsc-v2/graphql"),
        137 => Ok("https://rail-squid.squids.live/squid-railgun-polygon-v2/graphql"),
        42161 => Ok("https://rail-squid.squids.live/squid-railgun-arbitrum-v2/graphql"),
        _ => bail!("unsupported chain id {chain_id}"),
    }
}

fn print_parity(parity: &ChainParity) {
    println!(
        "chain {}: artifact_rows={} squid_rows={} matching_leaf_prefix={} matching_row_prefix={} descriptor_root_errors={}",
        parity.chain_id,
        parity.artifact_count,
        parity.squid_count,
        parity.matching_leaf_prefix,
        parity.matching_row_prefix,
        parity.descriptor_root_errors
    );
    for (tree, artifact_root) in &parity.artifact_tree_roots {
        let squid_root = parity.squid_tree_roots.get(tree);
        println!(
            "  tree {} artifact_root=0x{} squid_root={} match={}",
            tree,
            hex::encode(artifact_root),
            squid_root.map_or_else(|| "<missing>".to_string(), hex::encode_prefixed,),
            squid_root.is_some_and(|root| root == artifact_root)
        );
    }
    if let Some(mismatch) = &parity.first_leaf_mismatch {
        print_mismatch("first_leaf_mismatch", mismatch);
    }
    if let Some(mismatch) = &parity.first_row_mismatch
        && parity
            .first_leaf_mismatch
            .as_ref()
            .is_none_or(|leaf_mismatch| leaf_mismatch.index != mismatch.index)
    {
        print_mismatch("first_row_mismatch", mismatch);
    }
}

fn print_mismatch(label: &str, mismatch: &Mismatch) {
    println!("  {label}_index={}", mismatch.index);
    if let Some(artifact) = &mismatch.artifact {
        println!("    artifact: {}", artifact.short());
    } else {
        println!("    artifact: <missing>");
    }
    if let Some(squid) = &mismatch.squid {
        println!("    squid:    {}", squid.short());
    } else {
        println!("    squid:    <missing>");
    }
    println!(
        "    artifact_leaf={}",
        mismatch
            .artifact_leaf
            .map_or_else(|| "<missing>".to_string(), hex::encode_prefixed,)
    );
    println!(
        "    squid_leaf={}",
        mismatch
            .squid_leaf
            .map_or_else(|| "<missing>".to_string(), hex::encode_prefixed,)
    );
    if let (Some(artifact), Some(squid)) = (&mismatch.artifact, &mismatch.squid) {
        print_row_diffs(artifact, squid);
    }
}

fn print_row_diffs(artifact: &TxidRow, squid: &TxidRow) {
    let mut printed = false;
    macro_rules! diff_value {
        ($field:literal, $left:expr, $right:expr) => {
            if $left != $right {
                printed = true;
                println!(
                    "    field_diff {} artifact={} squid={}",
                    $field, $left, $right
                );
            }
        };
    }
    macro_rules! diff_hex {
        ($field:literal, $left:expr, $right:expr) => {
            if $left != $right {
                printed = true;
                println!(
                    "    field_diff {} artifact=0x{} squid=0x{}",
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
                    "    field_diff {} artifact=[{}] squid=[{}]",
                    $field,
                    hex_vec($left),
                    hex_vec($right)
                );
            }
        };
    }

    diff_value!("txid_index", artifact.txid_index, squid.txid_index);
    diff_value!("block_number", artifact.block_number, squid.block_number);
    diff_value!(
        "block_timestamp",
        artifact.block_timestamp,
        squid.block_timestamp
    );
    diff_hex!(
        "transaction_hash",
        artifact.transaction_hash,
        squid.transaction_hash
    );
    diff_hex!("merkle_root", artifact.merkle_root, squid.merkle_root);
    diff_hex_vec!("nullifiers", &artifact.nullifiers, &squid.nullifiers);
    diff_hex_vec!("commitments", &artifact.commitments, &squid.commitments);
    diff_hex!(
        "bound_params_hash",
        artifact.bound_params_hash,
        squid.bound_params_hash
    );
    diff_value!("has_unshield", artifact.has_unshield, squid.has_unshield);
    diff_value!("utxo_tree_in", artifact.utxo_tree_in, squid.utxo_tree_in);
    diff_value!("utxo_tree_out", artifact.utxo_tree_out, squid.utxo_tree_out);
    diff_value!(
        "utxo_batch_start_position_out",
        artifact.utxo_batch_start_position_out,
        squid.utxo_batch_start_position_out
    );
    diff_value!(
        "output_start_global",
        artifact.output_start_global(),
        squid.output_start_global()
    );

    if !printed {
        println!("    field_diff <none>; row fields match but leaf differs");
    }
}

fn hex_vec(values: &[[u8; 32]]) -> String {
    values
        .iter()
        .map(hex::encode_prefixed)
        .collect::<Vec<_>>()
        .join(", ")
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

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| eyre!("cursor overflow"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| eyre!("unexpected end of payload"))?;
        self.position = end;
        Ok(value)
    }

    fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16> {
        let bytes = self.read_exact(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.read_exact(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self) -> Result<u64> {
        let bytes = self.read_exact(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_string(&mut self) -> Result<String> {
        let length = usize::from(self.read_u16()?);
        let bytes = self.read_exact(length)?;
        Ok(std::str::from_utf8(bytes)?.to_string())
    }

    fn read_fixed_32(&mut self) -> Result<[u8; 32]> {
        Ok(self
            .read_exact(32)?
            .try_into()
            .expect("read_exact returned 32 bytes"))
    }

    fn read_fixed_vec(&mut self) -> Result<Vec<[u8; 32]>> {
        let count = usize::try_from(self.read_u32()?).wrap_err("fixed vec count overflow")?;
        (0..count).map(|_| self.read_fixed_32()).collect()
    }
}
