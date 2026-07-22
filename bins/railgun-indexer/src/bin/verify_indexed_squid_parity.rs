use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use alloy::hex;
use alloy::primitives::{Address, FixedBytes, U256, Uint};
use alloy::sol_types::SolValue;
use broadcaster_core::contracts::railgun::{
    CommitmentCiphertext, CommitmentPreimage, LegacyCommitmentCiphertext, LegacyCommitmentPreimage,
    ShieldCiphertext, TokenData,
};
use broadcaster_core::crypto::poseidon::poseidon;
use broadcaster_core::transact::MERKLE_ZERO_VALUE;
use broadcaster_core::tree::{TREE_DEPTH, TREE_LEAF_COUNT, normalize_tree_position};
use clap::Parser;
use eyre::{Context, Result, bail, eyre};
use railgun_indexer_core::chunk::{ChunkEnvelope, decode_chunk_bytes};
use railgun_indexer_core::manifest::{
    IndexedArtifactCatalog, IndexedArtifactDescriptor, IndexedArtifactManifest,
    IndexedArtifactRange, IndexedDatasetKind,
};
use railgun_indexer_core::publish::ipfs::raw_block_cid;
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing_subscriber::EnvFilter;

macro_rules! progress {
    ($($arg:tt)*) => {{
        eprintln!("[indexed-squid-parity] {}", format_args!($($arg)*));
        let _ = io::stderr().flush();
    }};
}

const DEFAULT_PAGE_SIZE: u64 = 10_000;
const DEFAULT_MANIFEST_CID: &str = "QmUasLbTLuc6f9mE1oLcu851CAmW3zFhkkurnSvDscoGZw";
const IPFS_GATEWAYS: &[&str] = &["https://ipfs.io/ipfs/", "https://dweb.link/ipfs/"];
const IPNS_GATEWAYS: &[&str] = &["https://ipfs.io/ipns/", "https://dweb.link/ipns/"];
const SQUID_PAGE_RETRY_ATTEMPTS: usize = 4;
const SQUID_PAGE_RETRY_BASE_DELAY: Duration = Duration::from_secs(2);

const WALLET_TRANSACT_SECTION_ID: u16 = 1;
const WALLET_SHIELD_SECTION_ID: u16 = 2;
const WALLET_NULLIFIER_SECTION_ID: u16 = 3;
const WALLET_LEGACY_ENCRYPTED_SECTION_ID: u16 = 4;
const WALLET_LEGACY_GENERATED_SECTION_ID: u16 = 5;

#[derive(Debug, Parser)]
#[command(about = "Verify indexed artifacts against Squid data where Squid exposes parity data")]
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

    /// Retained for CLI symmetry with other verifiers; currently unused.
    #[arg(long)]
    squid_cache_dir: Option<PathBuf>,
}

#[derive(Debug)]
struct ManifestFetch {
    bytes: Vec<u8>,
    cid: String,
    source: String,
}

#[derive(Debug, Deserialize)]
struct GraphqlResponse {
    data: Option<Value>,
    errors: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommitmentRow {
    global_position: u64,
    block_number: u64,
    tree_number: u32,
    tree_position: u64,
    hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct WalletKey {
    block_number: u64,
    transaction_hash: [u8; 32],
    tree_number: u32,
    tree_position: Option<u64>,
    value: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TransactWalletRow {
    key: WalletKey,
    block_timestamp: Option<u64>,
    ciphertext: Option<TransactCiphertextOverlap>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ShieldWalletRow {
    key: WalletKey,
    block_timestamp: Option<u64>,
    preimage: Vec<u8>,
    shield_ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NullifierWalletRow {
    key: WalletKey,
    block_timestamp: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LegacyEncryptedWalletRow {
    key: WalletKey,
    block_timestamp: Option<u64>,
    ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LegacyGeneratedWalletRow {
    key: WalletKey,
    block_timestamp: Option<u64>,
    preimage: Vec<u8>,
    encrypted_random: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TransactCiphertextOverlap {
    ciphertext: [[u8; 32]; 4],
    blinded_sender_viewing_key: [u8; 32],
    memo: Vec<u8>,
}

#[derive(Default)]
struct ChainArtifacts {
    commitments: Vec<CommitmentRow>,
    commitment_ranges: Vec<IndexedArtifactRange>,
    merkle_checkpoints: Vec<MerkleCheckpointArtifact>,
    wallet: WalletArtifacts,
    wallet_ranges: Vec<IndexedArtifactRange>,
}

#[derive(Default)]
struct WalletArtifacts {
    transact: Vec<TransactWalletRow>,
    shield: Vec<ShieldWalletRow>,
    nullifiers: Vec<NullifierWalletRow>,
    legacy_encrypted: Vec<LegacyEncryptedWalletRow>,
    legacy_generated: Vec<LegacyGeneratedWalletRow>,
}

struct MerkleCheckpointArtifact {
    descriptor: IndexedArtifactDescriptor,
    tree_number: u32,
    leaf_count: u64,
    root: [u8; 32],
    last_indexed_block: u64,
    leaves: Vec<[u8; 32]>,
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
    if args.squid_cache_dir.is_some() {
        progress!("--squid-cache-dir is accepted for CLI compatibility but not used yet");
    }

    let client = Client::builder()
        .user_agent("railgun-indexer-indexed-squid-parity/0.1")
        .build()?;
    let manifest_fetch = fetch_manifest(&client, &args).await?;
    let manifest: IndexedArtifactManifest = serde_json::from_slice(&manifest_fetch.bytes)
        .wrap_err("decode published indexed artifact manifest")?;
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
        let endpoint = squid_endpoint(chain_id)?;
        progress!("chain {}: loading indexed artifacts", chain_id);
        let artifacts = load_chain_artifacts(&client, chain).await?;
        let commitment_latest_block = latest_indexed_block(chain, IndexedDatasetKind::Commitments)?;
        let commitment_max_block = artifacts
            .commitments
            .iter()
            .map(|row| row.block_number)
            .max()
            .map_or(commitment_latest_block, |block| {
                block.max(commitment_latest_block)
            });
        let wallet_max_block = latest_indexed_block(chain, IndexedDatasetKind::WalletScan)?;
        progress!(
            "chain {}: fetching Squid commitments max_block={} endpoint={}",
            chain_id,
            commitment_max_block,
            endpoint
        );
        let squid_commitments = fetch_squid_commitments(
            &client,
            endpoint,
            chain_id,
            args.page_size,
            commitment_max_block,
        )
        .await?;
        let ranged_squid_commitments =
            squid_commitments_in_ranges(&artifacts.commitment_ranges, &squid_commitments);
        let commitment_failures =
            compare_commitments(chain_id, &artifacts.commitments, &ranged_squid_commitments);
        let checkpoint_failures =
            compare_merkle_checkpoints(chain_id, &artifacts.merkle_checkpoints, &squid_commitments);
        progress!(
            "chain {}: fetching Squid wallet streams max_block={} endpoint={}",
            chain_id,
            wallet_max_block,
            endpoint
        );
        let squid_wallet = fetch_squid_wallet(
            &client,
            endpoint,
            chain_id,
            args.page_size,
            wallet_max_block,
        )
        .await?;
        let ranged_squid_wallet = squid_wallet_in_ranges(&artifacts.wallet_ranges, &squid_wallet);
        let wallet_failures = compare_wallet(chain_id, &artifacts.wallet, &squid_wallet);
        let chain_failures = commitment_failures
            .saturating_add(checkpoint_failures)
            .saturating_add(wallet_failures);
        println!(
            "chain {}: commitments={} squid_commitments={} squid_commitments_in_artifact_ranges={} checkpoints={} wallet_rows={} squid_wallet_rows={} squid_wallet_rows_in_artifact_ranges={} failures={}",
            chain_id,
            artifacts.commitments.len(),
            squid_commitments.len(),
            ranged_squid_commitments.len(),
            artifacts.merkle_checkpoints.len(),
            wallet_row_count(&artifacts.wallet),
            wallet_row_count(&squid_wallet),
            wallet_row_count(&ranged_squid_wallet),
            chain_failures
        );
        failures = failures.saturating_add(chain_failures);
    }

    if failures > 0 {
        bail!("indexed Squid parity failed with {failures} mismatch(es)");
    }
    Ok(())
}

async fn load_chain_artifacts(
    client: &Client,
    chain: &railgun_indexer_core::manifest::IndexedArtifactChainEntry,
) -> Result<ChainArtifacts> {
    let mut artifacts = ChainArtifacts::default();
    for catalog_descriptor in &chain.catalogs {
        match catalog_descriptor.dataset_kind {
            IndexedDatasetKind::Commitments
            | IndexedDatasetKind::MerkleCheckpoint
            | IndexedDatasetKind::WalletScan => {
                let catalog = fetch_catalog(client, catalog_descriptor).await?;
                for chunk in catalog.chunks {
                    let bytes = fetch_ipfs(client, &chunk.cid).await?;
                    verify_bytes(&bytes, &chunk.cid, &chunk.sha256, chunk.byte_size)
                        .wrap_err_with(|| format!("verify chunk {}", chunk.cid))?;
                    let envelope = decode_chunk_bytes(&chunk, &bytes)
                        .wrap_err_with(|| format!("decode chunk {}", chunk.cid))?;
                    match chunk.dataset_kind {
                        IndexedDatasetKind::Commitments => {
                            artifacts.commitment_ranges.push(chunk.range.clone());
                            artifacts
                                .commitments
                                .extend(parse_commitment_payload(&envelope)?);
                        }
                        IndexedDatasetKind::MerkleCheckpoint => artifacts
                            .merkle_checkpoints
                            .push(parse_merkle_checkpoint_payload(&chunk, &envelope)?),
                        IndexedDatasetKind::WalletScan => {
                            artifacts.wallet_ranges.push(chunk.range.clone());
                            let wallet = parse_wallet_payload(&envelope)?;
                            artifacts.wallet.transact.extend(wallet.transact);
                            artifacts.wallet.shield.extend(wallet.shield);
                            artifacts.wallet.nullifiers.extend(wallet.nullifiers);
                            artifacts
                                .wallet
                                .legacy_encrypted
                                .extend(wallet.legacy_encrypted);
                            artifacts
                                .wallet
                                .legacy_generated
                                .extend(wallet.legacy_generated);
                        }
                        IndexedDatasetKind::PublicTxid => {}
                    }
                }
            }
            IndexedDatasetKind::PublicTxid => {}
        }
    }
    artifacts.commitments.sort_by_key(|row| row.global_position);
    sort_wallet(&mut artifacts.wallet);
    Ok(artifacts)
}

async fn fetch_catalog(
    client: &Client,
    descriptor: &IndexedArtifactDescriptor,
) -> Result<IndexedArtifactCatalog> {
    progress!(
        "chain {}: fetching catalog dataset={:?} cid={} rows={} range={:?}",
        descriptor.scope.chain_id,
        descriptor.dataset_kind,
        descriptor.cid,
        descriptor.row_count,
        descriptor.range
    );
    let bytes = fetch_ipfs(client, &descriptor.cid).await?;
    verify_bytes(
        &bytes,
        &descriptor.cid,
        &descriptor.sha256,
        descriptor.byte_size,
    )
    .wrap_err_with(|| format!("verify catalog {}", descriptor.cid))?;
    let catalog: IndexedArtifactCatalog = serde_json::from_slice(&bytes)
        .wrap_err_with(|| format!("decode catalog {}", descriptor.cid))?;
    if catalog.dataset_kind != descriptor.dataset_kind || catalog.scope != descriptor.scope {
        bail!(
            "catalog {} does not match descriptor scope/kind",
            descriptor.cid
        );
    }
    Ok(catalog)
}

fn verify_bytes(bytes: &[u8], cid: &str, sha256: &FixedBytes<32>, byte_size: u64) -> Result<()> {
    let actual_size = u64::try_from(bytes.len()).wrap_err("byte size overflow")?;
    if actual_size != byte_size {
        bail!("byte size mismatch for {cid}: expected {byte_size}, got {actual_size}");
    }
    // Filebase may return a service CID that does not equal raw_block_cid(bytes),
    // so byte-level integrity is verified with manifest SHA-256 and byte size.
    let actual_sha = Sha256::digest(bytes);
    if actual_sha.as_slice() != sha256.as_slice() {
        bail!(
            "sha256 mismatch for {cid}: expected 0x{}, got 0x{}",
            hex::encode(sha256.as_slice()),
            hex::encode(actual_sha)
        );
    }
    Ok(())
}

fn parse_commitment_payload(envelope: &ChunkEnvelope) -> Result<Vec<CommitmentRow>> {
    let mut cursor = Cursor::new(envelope.payload());
    let count = cursor.read_u64()?;
    let count_usize = usize::try_from(count).wrap_err("commitment row count overflow")?;
    let mut rows = Vec::with_capacity(count_usize);
    for _ in 0..count_usize {
        let global_position = cursor.read_u64()?;
        let block_number = cursor.read_u64()?;
        let _family = cursor.read_u8()?;
        let tree_number = cursor.read_u32()?;
        let tree_position = cursor.read_u64()?;
        let hash = cursor.read_fixed_32()?;
        rows.push(CommitmentRow {
            global_position,
            block_number,
            tree_number,
            tree_position,
            hash,
        });
    }
    cursor.expect_end("commitment payload")?;
    if u64::try_from(rows.len()).wrap_err("commitment len overflow")? != envelope.header.row_count {
        bail!("commitment row count does not match chunk header");
    }
    Ok(rows)
}

fn parse_merkle_checkpoint_payload(
    descriptor: &IndexedArtifactDescriptor,
    envelope: &ChunkEnvelope,
) -> Result<MerkleCheckpointArtifact> {
    let mut cursor = Cursor::new(envelope.payload());
    let tree_number = cursor.read_u32()?;
    let leaf_count = cursor.read_u64()?;
    let root = cursor.read_fixed_32()?;
    let last_indexed_block = cursor.read_u64()?;
    let leaf_count_usize =
        usize::try_from(leaf_count).wrap_err("checkpoint leaf count overflow")?;
    let mut leaves = Vec::with_capacity(leaf_count_usize);
    for _ in 0..leaf_count_usize {
        leaves.push(cursor.read_fixed_32()?);
    }
    cursor.expect_end("merkle checkpoint payload")?;
    let computed = merkle_root(&leaves)?;
    if computed != root {
        bail!(
            "checkpoint payload root mismatch for chunk {}",
            descriptor.cid
        );
    }
    Ok(MerkleCheckpointArtifact {
        descriptor: descriptor.clone(),
        tree_number,
        leaf_count,
        root,
        last_indexed_block,
        leaves,
    })
}

fn parse_wallet_payload(envelope: &ChunkEnvelope) -> Result<WalletArtifacts> {
    let mut wallet = WalletArtifacts::default();
    for section in &envelope.header.sections {
        let start = usize::try_from(section.offset).wrap_err("wallet section offset overflow")?;
        let len =
            usize::try_from(section.byte_length).wrap_err("wallet section length overflow")?;
        let end = start
            .checked_add(len)
            .ok_or_else(|| eyre!("wallet section range overflow"))?;
        let bytes = envelope
            .payload()
            .get(start..end)
            .ok_or_else(|| eyre!("wallet section outside payload"))?;
        let mut cursor = Cursor::new(bytes);
        match section.section_id {
            WALLET_TRANSACT_SECTION_ID => wallet.transact = parse_wallet_transact(&mut cursor)?,
            WALLET_SHIELD_SECTION_ID => wallet.shield = parse_wallet_shield(&mut cursor)?,
            WALLET_NULLIFIER_SECTION_ID => {
                wallet.nullifiers = parse_wallet_nullifiers(&mut cursor)?;
            }
            WALLET_LEGACY_ENCRYPTED_SECTION_ID => {
                wallet.legacy_encrypted = parse_wallet_legacy_encrypted(&mut cursor)?;
            }
            WALLET_LEGACY_GENERATED_SECTION_ID => {
                wallet.legacy_generated = parse_wallet_legacy_generated(&mut cursor)?;
            }
            other => bail!("unknown wallet scan section id {other}"),
        }
        cursor.expect_end("wallet section")?;
    }
    Ok(wallet)
}

fn parse_wallet_transact(cursor: &mut Cursor<'_>) -> Result<Vec<TransactWalletRow>> {
    let count = usize::try_from(cursor.read_u64()?).wrap_err("transact count overflow")?;
    let mut rows = Vec::with_capacity(count);
    for _ in 0..count {
        let source = SourceSubset::read(cursor)?;
        let tree_number = cursor.read_u32()?;
        let tree_position = cursor.read_u64()?;
        let hash = cursor.read_fixed_32()?;
        let ciphertext_bytes = cursor.read_bytes()?;
        rows.push(TransactWalletRow {
            key: WalletKey {
                block_number: source.block_number,
                transaction_hash: source.transaction_hash,
                tree_number,
                tree_position: Some(tree_position),
                value: hash,
            },
            block_timestamp: source.block_timestamp,
            ciphertext: Some(parse_transact_ciphertext_overlap(&ciphertext_bytes)?),
        });
    }
    Ok(rows)
}

fn parse_wallet_shield(cursor: &mut Cursor<'_>) -> Result<Vec<ShieldWalletRow>> {
    let count = usize::try_from(cursor.read_u64()?).wrap_err("shield count overflow")?;
    let mut rows = Vec::with_capacity(count);
    for _ in 0..count {
        let source = SourceSubset::read(cursor)?;
        let tree_number = cursor.read_u32()?;
        let tree_position = cursor.read_u64()?;
        let hash = cursor.read_fixed_32()?;
        let preimage = cursor.read_bytes()?;
        let shield_ciphertext = cursor.read_bytes()?;
        rows.push(ShieldWalletRow {
            key: WalletKey {
                block_number: source.block_number,
                transaction_hash: source.transaction_hash,
                tree_number,
                tree_position: Some(tree_position),
                value: hash,
            },
            block_timestamp: source.block_timestamp,
            preimage,
            shield_ciphertext,
        });
    }
    Ok(rows)
}

fn parse_wallet_nullifiers(cursor: &mut Cursor<'_>) -> Result<Vec<NullifierWalletRow>> {
    let count = usize::try_from(cursor.read_u64()?).wrap_err("nullifier count overflow")?;
    let mut rows = Vec::with_capacity(count);
    for _ in 0..count {
        let source = SourceSubset::read(cursor)?;
        let tree_number = cursor.read_u32()?;
        let nullifier = cursor.read_fixed_32()?;
        rows.push(NullifierWalletRow {
            key: WalletKey {
                block_number: source.block_number,
                transaction_hash: source.transaction_hash,
                tree_number,
                tree_position: None,
                value: nullifier,
            },
            block_timestamp: source.block_timestamp,
        });
    }
    Ok(rows)
}

fn parse_wallet_legacy_encrypted(cursor: &mut Cursor<'_>) -> Result<Vec<LegacyEncryptedWalletRow>> {
    let count = usize::try_from(cursor.read_u64()?).wrap_err("legacy encrypted count overflow")?;
    let mut rows = Vec::with_capacity(count);
    for _ in 0..count {
        let source = SourceSubset::read(cursor)?;
        let tree_number = cursor.read_u32()?;
        let tree_position = cursor.read_u64()?;
        let hash = cursor.read_fixed_32()?;
        let ciphertext = cursor.read_bytes()?;
        rows.push(LegacyEncryptedWalletRow {
            key: WalletKey {
                block_number: source.block_number,
                transaction_hash: source.transaction_hash,
                tree_number,
                tree_position: Some(tree_position),
                value: hash,
            },
            block_timestamp: source.block_timestamp,
            ciphertext,
        });
    }
    Ok(rows)
}

fn parse_wallet_legacy_generated(cursor: &mut Cursor<'_>) -> Result<Vec<LegacyGeneratedWalletRow>> {
    let count = usize::try_from(cursor.read_u64()?).wrap_err("legacy generated count overflow")?;
    let mut rows = Vec::with_capacity(count);
    for _ in 0..count {
        let source = SourceSubset::read(cursor)?;
        let tree_number = cursor.read_u32()?;
        let tree_position = cursor.read_u64()?;
        let hash = cursor.read_fixed_32()?;
        let preimage = cursor.read_bytes()?;
        let encrypted_random = cursor.read_fixed_64()?;
        rows.push(LegacyGeneratedWalletRow {
            key: WalletKey {
                block_number: source.block_number,
                transaction_hash: source.transaction_hash,
                tree_number,
                tree_position: Some(tree_position),
                value: hash,
            },
            block_timestamp: source.block_timestamp,
            preimage,
            encrypted_random,
        });
    }
    Ok(rows)
}

async fn fetch_squid_commitments(
    client: &Client,
    endpoint: &str,
    chain_id: u64,
    page_size: u64,
    max_block: u64,
) -> Result<Vec<CommitmentRow>> {
    let query = r"
query Commitments($offset: Int!, $limit: Int!, $maxBlock: BigInt!) {
  commitments(
    orderBy: [treeNumber_ASC, treePosition_ASC]
    offset: $offset
    limit: $limit
    where: {blockNumber_lte: $maxBlock}
  ) {
    id
    treeNumber
    treePosition
    blockNumber
    hash
  }
}
";
    let values = fetch_squid_pages(
        client,
        endpoint,
        chain_id,
        query,
        "commitments",
        page_size,
        max_block,
    )
    .await?;
    let mut rows = values
        .iter()
        .map(parse_squid_commitment)
        .collect::<Result<Vec<_>>>()?;
    rows.sort_by_key(|row| row.global_position);
    Ok(rows)
}

async fn fetch_squid_wallet(
    client: &Client,
    endpoint: &str,
    chain_id: u64,
    page_size: u64,
    max_block: u64,
) -> Result<WalletArtifacts> {
    let transact = fetch_squid_pages(
        client,
        endpoint,
        chain_id,
        TRANSACT_QUERY,
        "transactCommitments",
        page_size,
        max_block,
    )
    .await?
    .into_iter()
    .filter(|value| {
        value
            .get("ciphertext")
            .is_some_and(|value| !value.is_null())
    })
    .map(|value| parse_squid_transact(&value))
    .collect::<Result<Vec<_>>>()?;
    let shield = fetch_squid_pages(
        client,
        endpoint,
        chain_id,
        SHIELD_QUERY,
        "shieldCommitments",
        page_size,
        max_block,
    )
    .await?
    .iter()
    .map(parse_squid_shield)
    .collect::<Result<Vec<_>>>()?;
    let nullifiers = fetch_squid_pages(
        client,
        endpoint,
        chain_id,
        NULLIFIER_QUERY,
        "nullifiers",
        page_size,
        max_block,
    )
    .await?
    .iter()
    .map(parse_squid_nullifier)
    .collect::<Result<Vec<_>>>()?;
    let legacy_encrypted = fetch_squid_pages(
        client,
        endpoint,
        chain_id,
        LEGACY_ENCRYPTED_QUERY,
        "legacyEncryptedCommitments",
        page_size,
        max_block,
    )
    .await?
    .iter()
    .map(parse_squid_legacy_encrypted)
    .collect::<Result<Vec<_>>>()?;
    let legacy_generated = fetch_squid_pages(
        client,
        endpoint,
        chain_id,
        LEGACY_GENERATED_QUERY,
        "legacyGeneratedCommitments",
        page_size,
        max_block,
    )
    .await?
    .iter()
    .map(parse_squid_legacy_generated)
    .collect::<Result<Vec<_>>>()?;
    let mut wallet = WalletArtifacts {
        transact,
        shield,
        nullifiers,
        legacy_encrypted,
        legacy_generated,
    };
    sort_wallet(&mut wallet);
    Ok(wallet)
}

async fn fetch_squid_pages(
    client: &Client,
    endpoint: &str,
    chain_id: u64,
    query: &str,
    field: &'static str,
    page_size: u64,
    max_block: u64,
) -> Result<Vec<Value>> {
    let started = Instant::now();
    let mut offset = 0_u64;
    let mut rows = Vec::new();
    loop {
        let page_started = Instant::now();
        progress!(
            "chain {}: fetching Squid {} offset={} limit={} max_block={} loaded={}",
            chain_id,
            field,
            offset,
            page_size,
            max_block,
            rows.len()
        );
        let page =
            fetch_squid_page(client, endpoint, query, field, offset, page_size, max_block).await?;
        if page.is_empty() {
            progress!(
                "chain {}: Squid {} empty offset={} loaded={} page_elapsed_ms={} total_elapsed_ms={}",
                chain_id,
                field,
                offset,
                rows.len(),
                elapsed_ms(page_started),
                elapsed_ms(started)
            );
            break;
        }
        let page_len = page.len();
        let tail = squid_page_tail(&page);
        rows.extend(page);
        progress!(
            "chain {}: decoded Squid {} offset={} rows={} cumulative_rows={} page_elapsed_ms={}{}",
            chain_id,
            field,
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
    progress!(
        "chain {}: finished Squid {} rows={} elapsed_ms={}",
        chain_id,
        field,
        rows.len(),
        elapsed_ms(started)
    );
    Ok(rows)
}

async fn fetch_squid_page(
    client: &Client,
    endpoint: &str,
    query: &str,
    field: &'static str,
    offset: u64,
    limit: u64,
    max_block: u64,
) -> Result<Vec<Value>> {
    for attempt in 1..=SQUID_PAGE_RETRY_ATTEMPTS {
        match fetch_squid_page_once(client, endpoint, query, field, offset, limit, max_block).await
        {
            Ok(page) => return Ok(page),
            Err(error)
                if attempt < SQUID_PAGE_RETRY_ATTEMPTS && is_retriable_squid_page_error(&error) =>
            {
                let delay = SQUID_PAGE_RETRY_BASE_DELAY * u32::try_from(attempt).unwrap_or(1);
                progress!(
                    "Squid {} page offset {} attempt {}/{} failed with transient error; retrying in {}ms: {}",
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

    unreachable!("Squid page retry loop must return")
}

async fn fetch_squid_page_once(
    client: &Client,
    endpoint: &str,
    query: &str,
    field: &'static str,
    offset: u64,
    limit: u64,
    max_block: u64,
) -> Result<Vec<Value>> {
    let body = serde_json::json!({
        "query": query,
        "variables": {
            "offset": i32::try_from(offset).wrap_err("Squid offset exceeds GraphQL Int")?,
            "limit": i32::try_from(limit).wrap_err("Squid limit exceeds GraphQL Int")?,
            "maxBlock": max_block.to_string(),
        }
    });
    let response = client
        .post(endpoint)
        .json(&body)
        .send()
        .await
        .wrap_err_with(|| format!("post Squid {field} page offset {offset} to {endpoint}"))?
        .error_for_status()
        .wrap_err_with(|| format!("Squid {field} page offset {offset} returned error status"))?
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

const TRANSACT_QUERY: &str = r"
query TransactCommitments($offset: Int!, $limit: Int!, $maxBlock: BigInt!) {
  transactCommitments(orderBy: [blockNumber_ASC, treePosition_ASC], offset: $offset, limit: $limit, where: {blockNumber_lte: $maxBlock}) {
    transactionHash
    blockNumber
    blockTimestamp
    treeNumber
    treePosition
    hash
    ciphertext {
      ciphertext { iv tag data }
      blindedSenderViewingKey
      memo
    }
  }
}
";

const SHIELD_QUERY: &str = r"
query ShieldCommitments($offset: Int!, $limit: Int!, $maxBlock: BigInt!) {
  shieldCommitments(orderBy: [blockNumber_ASC, treePosition_ASC], offset: $offset, limit: $limit, where: {blockNumber_lte: $maxBlock}) {
    transactionHash
    blockNumber
    blockTimestamp
    treeNumber
    treePosition
    preimage { npk token { tokenType tokenAddress tokenSubID } value }
    shieldKey
    encryptedBundle
  }
}
";

const NULLIFIER_QUERY: &str = r"
query IndexedNullifiers($offset: Int!, $limit: Int!, $maxBlock: BigInt!) {
  nullifiers(orderBy: [blockNumber_ASC, nullifier_DESC], offset: $offset, limit: $limit, where: {blockNumber_lte: $maxBlock}) {
    transactionHash
    blockNumber
    blockTimestamp
    treeNumber
    nullifier
  }
}
";

const LEGACY_ENCRYPTED_QUERY: &str = r"
query LegacyEncryptedCommitments($offset: Int!, $limit: Int!, $maxBlock: BigInt!) {
  legacyEncryptedCommitments(orderBy: [blockNumber_ASC, treePosition_ASC], offset: $offset, limit: $limit, where: {blockNumber_lte: $maxBlock}) {
    transactionHash
    blockNumber
    blockTimestamp
    treeNumber
    treePosition
    hash
    ciphertext { ciphertext { iv tag data } ephemeralKeys memo }
  }
}
";

const LEGACY_GENERATED_QUERY: &str = r"
query LegacyGeneratedCommitments($offset: Int!, $limit: Int!, $maxBlock: BigInt!) {
  legacyGeneratedCommitments(orderBy: [blockNumber_ASC, treePosition_ASC], offset: $offset, limit: $limit, where: {blockNumber_lte: $maxBlock}) {
    transactionHash
    blockNumber
    blockTimestamp
    treeNumber
    treePosition
    hash
    preimage { npk token { tokenType tokenAddress tokenSubID } value }
    encryptedRandom
  }
}
";

fn parse_squid_commitment(value: &Value) -> Result<CommitmentRow> {
    let (tree_number, tree_position) = normalized_squid_tree_position(value)?;
    Ok(CommitmentRow {
        global_position: global_tree_position(tree_number, tree_position)?,
        block_number: u64_field(value, "blockNumber")?,
        tree_number,
        tree_position,
        hash: u256_field(value, "hash")?,
    })
}

fn parse_squid_transact(value: &Value) -> Result<TransactWalletRow> {
    let (tree_number, tree_position) = normalized_squid_tree_position(value)?;
    let hash = u256_field(value, "hash")?;
    let ciphertext = value
        .get("ciphertext")
        .filter(|value| !value.is_null())
        .map(parse_squid_transact_ciphertext)
        .transpose()?;
    Ok(TransactWalletRow {
        key: wallet_key(value, tree_number, Some(tree_position), hash)?,
        block_timestamp: Some(u64_field(value, "blockTimestamp")?),
        ciphertext,
    })
}

fn parse_squid_shield(value: &Value) -> Result<ShieldWalletRow> {
    let (tree_number, tree_position) = normalized_squid_tree_position(value)?;
    let preimage = commitment_preimage(value_field(value, "preimage")?)?;
    let hash = preimage.hash().to_be_bytes::<32>();
    let shield_ciphertext = ShieldCiphertext {
        encryptedBundle: fixed_array_32::<3>(value_field(value, "encryptedBundle")?)?,
        shieldKey: fixed_hex_field(value, "shieldKey")?.into(),
    };
    Ok(ShieldWalletRow {
        key: wallet_key(value, tree_number, Some(tree_position), hash)?,
        block_timestamp: Some(u64_field(value, "blockTimestamp")?),
        preimage: preimage.abi_encode(),
        shield_ciphertext: shield_ciphertext.abi_encode(),
    })
}

fn parse_squid_nullifier(value: &Value) -> Result<NullifierWalletRow> {
    let tree_number = u32_field(value, "treeNumber")?;
    let nullifier = u256_field(value, "nullifier")?;
    Ok(NullifierWalletRow {
        key: wallet_key(value, tree_number, None, nullifier)?,
        block_timestamp: Some(u64_field(value, "blockTimestamp")?),
    })
}

fn parse_squid_legacy_encrypted(value: &Value) -> Result<LegacyEncryptedWalletRow> {
    let (tree_number, tree_position) = normalized_squid_tree_position(value)?;
    let hash = u256_field(value, "hash")?;
    let ciphertext = legacy_ciphertext(value_field(value, "ciphertext")?)?;
    Ok(LegacyEncryptedWalletRow {
        key: wallet_key(value, tree_number, Some(tree_position), hash)?,
        block_timestamp: Some(u64_field(value, "blockTimestamp")?),
        ciphertext: ciphertext.abi_encode(),
    })
}

fn parse_squid_legacy_generated(value: &Value) -> Result<LegacyGeneratedWalletRow> {
    let (tree_number, tree_position) = normalized_squid_tree_position(value)?;
    let preimage = legacy_preimage(value_field(value, "preimage")?)?;
    let hash = preimage.hash().to_be_bytes::<32>();
    Ok(LegacyGeneratedWalletRow {
        key: wallet_key(value, tree_number, Some(tree_position), hash)?,
        block_timestamp: Some(u64_field(value, "blockTimestamp")?),
        preimage: preimage.abi_encode(),
        encrypted_random: encrypted_random(value_field(value, "encryptedRandom")?)?,
    })
}

fn normalized_squid_tree_position(value: &Value) -> Result<(u32, u64)> {
    let tree_number = u32_field(value, "treeNumber")?;
    let tree_position = u64_field(value, "treePosition")?;
    Ok(normalize_tree_position(tree_number, tree_position))
}

fn wallet_key(
    value: &Value,
    tree_number: u32,
    tree_position: Option<u64>,
    row_value: [u8; 32],
) -> Result<WalletKey> {
    Ok(WalletKey {
        block_number: u64_field(value, "blockNumber")?,
        transaction_hash: fixed_hex_field(value, "transactionHash")?,
        tree_number,
        tree_position,
        value: row_value,
    })
}

fn parse_squid_transact_ciphertext(value: &Value) -> Result<TransactCiphertextOverlap> {
    let payload = value_field(value, "ciphertext")?;
    let iv = fixed_hex_sized::<16>(string_field(payload, "iv")?)?;
    let tag = fixed_hex_sized::<16>(string_field(payload, "tag")?)?;
    let data = fixed_array_32::<3>(value_field(payload, "data")?)?;
    let mut first = [0_u8; 32];
    first[..16].copy_from_slice(&iv);
    first[16..].copy_from_slice(&tag);
    Ok(TransactCiphertextOverlap {
        ciphertext: [first, data[0].0, data[1].0, data[2].0],
        blinded_sender_viewing_key: fixed_hex_field(value, "blindedSenderViewingKey")?,
        memo: bytes_field(value, "memo")?,
    })
}

fn parse_transact_ciphertext_overlap(bytes: &[u8]) -> Result<TransactCiphertextOverlap> {
    let decoded = CommitmentCiphertext::abi_decode(bytes)
        .wrap_err("decode artifact CommitmentCiphertext ABI")?;
    Ok(TransactCiphertextOverlap {
        ciphertext: decoded.ciphertext.map(|value| value.0),
        blinded_sender_viewing_key: decoded.blindedSenderViewingKey.0,
        memo: decoded.memo.to_vec(),
    })
}

fn commitment_preimage(value: &Value) -> Result<CommitmentPreimage> {
    Ok(CommitmentPreimage {
        npk: fixed_hex_field(value, "npk")?.into(),
        token: token_data(value_field(value, "token")?)?,
        value: uint120_field(value, "value")?,
    })
}

fn legacy_preimage(value: &Value) -> Result<LegacyCommitmentPreimage> {
    Ok(LegacyCommitmentPreimage {
        npk: U256::from_be_bytes(u256_field(value, "npk")?),
        token: token_data(value_field(value, "token")?)?,
        value: uint120_field(value, "value")?,
    })
}

fn token_data(value: &Value) -> Result<TokenData> {
    Ok(TokenData {
        tokenType: token_type(value_field(value, "tokenType")?)?,
        tokenAddress: string_field(value, "tokenAddress")?.parse::<Address>()?,
        tokenSubID: U256::from_be_bytes(u256_field(value, "tokenSubID")?),
    })
}

fn legacy_ciphertext(value: &Value) -> Result<LegacyCommitmentCiphertext> {
    let payload = value_field(value, "ciphertext")?;
    let iv = fixed_hex_sized::<16>(string_field(payload, "iv")?)?;
    let tag = fixed_hex_sized::<16>(string_field(payload, "tag")?)?;
    let data = fixed_array_32::<3>(value_field(payload, "data")?)?;
    let mut first = [0_u8; 32];
    first[..16].copy_from_slice(&iv);
    first[16..].copy_from_slice(&tag);
    Ok(LegacyCommitmentCiphertext {
        ciphertext: [
            U256::from_be_bytes(first),
            U256::from_be_bytes(data[0].0),
            U256::from_be_bytes(data[1].0),
            U256::from_be_bytes(data[2].0),
        ],
        ephemeralKeys: fixed_array_32::<2>(value_field(value, "ephemeralKeys")?)?
            .map(|value| U256::from_be_bytes(value.0)),
        memo: fixed_vec_32(value_field(value, "memo")?)?
            .into_iter()
            .map(|value| U256::from_be_bytes(value))
            .collect(),
    })
}

fn encrypted_random(value: &Value) -> Result<[u8; 64]> {
    let values = value
        .as_array()
        .ok_or_else(|| eyre!("encryptedRandom is not an array"))?;
    if values.len() != 2 {
        bail!("encryptedRandom expected 2 values, got {}", values.len());
    }
    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(&parse_u256_value(&values[0])?);
    bytes[32..].copy_from_slice(&parse_u256_value(&values[1])?);
    Ok(bytes)
}

fn compare_commitments(
    chain_id: u64,
    artifact: &[CommitmentRow],
    squid: &[CommitmentRow],
) -> usize {
    let mut failures = usize::from(artifact.len() != squid.len());
    if artifact.len() != squid.len() {
        println!(
            "chain {} commitments count mismatch artifact={} squid={}",
            chain_id,
            artifact.len(),
            squid.len()
        );
        if let Some(row) = artifact.get(squid.len()) {
            println!("chain {chain_id} first extra artifact commitment={row:?}");
        }
        if let Some(row) = squid.get(artifact.len()) {
            println!("chain {chain_id} first extra squid commitment={row:?}");
        }
    }
    for (index, (left, right)) in artifact.iter().zip(squid).enumerate() {
        if left != right {
            println!(
                "chain {chain_id} commitments mismatch index={index} artifact={left:?} squid={right:?}"
            );
            failures = failures.saturating_add(1);
            break;
        }
    }
    failures
}

fn compare_merkle_checkpoints(
    chain_id: u64,
    checkpoints: &[MerkleCheckpointArtifact],
    squid_commitments: &[CommitmentRow],
) -> usize {
    let by_tree = squid_commitments_by_tree(squid_commitments);
    let mut failures = 0_usize;
    for checkpoint in checkpoints {
        let expected = by_tree
            .get(&checkpoint.tree_number)
            .into_iter()
            .flat_map(|rows| rows.iter())
            .filter(|row| row.tree_position < checkpoint.leaf_count)
            .cloned()
            .collect::<Vec<_>>();
        let expected_leaf_count = expected
            .iter()
            .map(|row| row.tree_position)
            .max()
            .map_or(0, |position| position.saturating_add(1));
        if checkpoint.leaf_count != expected_leaf_count {
            println!(
                "chain {} checkpoint leaf_count mismatch tree={} artifact={} squid={}",
                chain_id, checkpoint.tree_number, checkpoint.leaf_count, expected_leaf_count
            );
            failures = failures.saturating_add(1);
            continue;
        }
        let leaves = dense_leaves(&expected, checkpoint.leaf_count);
        let Ok(root) = merkle_root(&leaves) else {
            println!(
                "chain {} checkpoint root compute failed tree={}",
                chain_id, checkpoint.tree_number
            );
            failures = failures.saturating_add(1);
            continue;
        };
        if checkpoint.leaves != leaves || checkpoint.root != root {
            println!(
                "chain {} checkpoint mismatch tree={} artifact_root=0x{} squid_root=0x{} leaves={}",
                chain_id,
                checkpoint.tree_number,
                hex::encode(checkpoint.root),
                hex::encode(root),
                checkpoint.leaves.len()
            );
            failures = failures.saturating_add(1);
        }
        if checkpoint.descriptor.metadata.root.as_ref() != Some(&FixedBytes::from(root)) {
            println!(
                "chain {} checkpoint descriptor root mismatch tree={}",
                chain_id, checkpoint.tree_number
            );
            failures = failures.saturating_add(1);
        }
        if checkpoint.descriptor.metadata.leaf_count != Some(checkpoint.leaf_count)
            || checkpoint.descriptor.metadata.tree_number
                != u16::try_from(checkpoint.tree_number).ok()
            || checkpoint.descriptor.metadata.last_indexed_block
                != Some(checkpoint.last_indexed_block)
        {
            println!(
                "chain {} checkpoint metadata mismatch tree={}",
                chain_id, checkpoint.tree_number
            );
            failures = failures.saturating_add(1);
        }
    }
    failures
}

fn compare_wallet(chain_id: u64, artifact: &WalletArtifacts, squid: &WalletArtifacts) -> usize {
    let mut failures = 0_usize;
    failures = failures.saturating_add(compare_wallet_vec(
        chain_id,
        "wallet transact",
        &artifact.transact,
        &squid.transact,
        transact_wallet_rows_match,
    ));
    failures = failures.saturating_add(compare_shield_wallet_vec(
        chain_id,
        &artifact.shield,
        &squid.shield,
    ));
    failures = failures.saturating_add(compare_wallet_vec(
        chain_id,
        "wallet nullifiers",
        &artifact.nullifiers,
        &squid.nullifiers,
        nullifier_wallet_rows_match,
    ));
    failures = failures.saturating_add(compare_wallet_vec(
        chain_id,
        "wallet legacy_encrypted",
        &artifact.legacy_encrypted,
        &squid.legacy_encrypted,
        legacy_encrypted_wallet_rows_match,
    ));
    failures = failures.saturating_add(compare_wallet_vec(
        chain_id,
        "wallet legacy_generated",
        &artifact.legacy_generated,
        &squid.legacy_generated,
        legacy_generated_wallet_rows_match,
    ));
    failures
}

fn compare_wallet_vec<T: std::fmt::Debug>(
    chain_id: u64,
    label: &'static str,
    artifact: &[T],
    squid: &[T],
    matches: impl Fn(&T, &T) -> bool,
) -> usize {
    let mut failures = usize::from(artifact.len() != squid.len());
    if artifact.len() != squid.len() {
        println!(
            "chain {} {} count mismatch artifact={} squid={}",
            chain_id,
            label,
            artifact.len(),
            squid.len()
        );
    }
    for (index, (left, right)) in artifact.iter().zip(squid).enumerate() {
        if !matches(left, right) {
            println!(
                "chain {chain_id} {label} mismatch index={index} artifact={left:?} squid={right:?}"
            );
            failures = failures.saturating_add(1);
            break;
        }
    }
    failures
}

fn compare_shield_wallet_vec(
    chain_id: u64,
    artifact: &[ShieldWalletRow],
    squid: &[ShieldWalletRow],
) -> usize {
    let mut failures = usize::from(artifact.len() != squid.len());
    if artifact.len() != squid.len() {
        println!(
            "chain {} wallet shield count mismatch artifact={} squid={}",
            chain_id,
            artifact.len(),
            squid.len()
        );
    }
    for (index, (left, right)) in artifact.iter().zip(squid).enumerate() {
        if !shield_wallet_rows_match(left, right) {
            println!(
                "chain {chain_id} wallet shield mismatch index={index} artifact={left:?} squid={right:?}"
            );
            print_shield_wallet_mismatch(chain_id, index, left, right);
            failures = failures.saturating_add(1);
            break;
        }
    }
    failures
}

fn print_shield_wallet_mismatch(
    chain_id: u64,
    index: usize,
    artifact: &ShieldWalletRow,
    squid: &ShieldWalletRow,
) {
    if artifact.key != squid.key {
        println!(
            "chain {} wallet shield key mismatch index={} artifact={:?} squid={:?}",
            chain_id, index, artifact.key, squid.key
        );
    }
    if !optional_timestamp_matches(artifact.block_timestamp, squid.block_timestamp) {
        println!(
            "chain {} wallet shield timestamp mismatch index={} artifact={:?} squid={:?}",
            chain_id, index, artifact.block_timestamp, squid.block_timestamp
        );
    }
    if artifact.preimage != squid.preimage {
        print_shield_preimage_mismatch(chain_id, index, &artifact.preimage, &squid.preimage);
    }
    if artifact.shield_ciphertext != squid.shield_ciphertext {
        println!(
            "chain {} wallet shield ciphertext mismatch index={} artifact_len={} squid_len={} first_diff={:?}",
            chain_id,
            index,
            artifact.shield_ciphertext.len(),
            squid.shield_ciphertext.len(),
            first_byte_diff(&artifact.shield_ciphertext, &squid.shield_ciphertext)
        );
    }
}

fn print_shield_preimage_mismatch(
    chain_id: u64,
    index: usize,
    artifact_bytes: &[u8],
    squid_bytes: &[u8],
) {
    println!(
        "chain {} wallet shield preimage byte mismatch index={} artifact_len={} squid_len={} first_diff={:?}",
        chain_id,
        index,
        artifact_bytes.len(),
        squid_bytes.len(),
        first_byte_diff(artifact_bytes, squid_bytes)
    );
    match (
        CommitmentPreimage::abi_decode(artifact_bytes),
        CommitmentPreimage::abi_decode(squid_bytes),
    ) {
        (Ok(artifact), Ok(squid)) => {
            println!(
                "chain {} wallet shield preimage fields index={} npk_match={} token_type artifact={} squid={} token_address artifact={:?} squid={:?} token_sub_id artifact=0x{} squid=0x{} value artifact={} squid={} hash_match={}",
                chain_id,
                index,
                artifact.npk == squid.npk,
                artifact.token.tokenType,
                squid.token.tokenType,
                artifact.token.tokenAddress,
                squid.token.tokenAddress,
                hex_u256(artifact.token.tokenSubID),
                hex_u256(squid.token.tokenSubID),
                artifact.value.to::<u128>(),
                squid.value.to::<u128>(),
                artifact.hash() == squid.hash()
            );
        }
        (artifact_result, squid_result) => {
            println!(
                "chain {} wallet shield preimage decode mismatch index={} artifact_ok={} squid_ok={}",
                chain_id,
                index,
                artifact_result.is_ok(),
                squid_result.is_ok()
            );
        }
    }
}

fn first_byte_diff(left: &[u8], right: &[u8]) -> Option<usize> {
    left.iter()
        .zip(right)
        .position(|(left, right)| left != right)
        .or_else(|| (left.len() != right.len()).then_some(left.len().min(right.len())))
}

fn hex_u256(value: U256) -> String {
    hex::encode(value.to_be_bytes::<32>())
}

fn transact_wallet_rows_match(left: &TransactWalletRow, right: &TransactWalletRow) -> bool {
    left.key == right.key
        && optional_timestamp_matches(left.block_timestamp, right.block_timestamp)
        && left.ciphertext == right.ciphertext
}

fn shield_wallet_rows_match(left: &ShieldWalletRow, right: &ShieldWalletRow) -> bool {
    left.key == right.key
        && optional_timestamp_matches(left.block_timestamp, right.block_timestamp)
        && commitment_preimage_bytes_match(&left.preimage, &right.preimage)
        && left.shield_ciphertext == right.shield_ciphertext
}

fn nullifier_wallet_rows_match(left: &NullifierWalletRow, right: &NullifierWalletRow) -> bool {
    left.key == right.key && optional_timestamp_matches(left.block_timestamp, right.block_timestamp)
}

fn legacy_encrypted_wallet_rows_match(
    left: &LegacyEncryptedWalletRow,
    right: &LegacyEncryptedWalletRow,
) -> bool {
    left.key == right.key
        && optional_timestamp_matches(left.block_timestamp, right.block_timestamp)
        && left.ciphertext == right.ciphertext
}

fn legacy_generated_wallet_rows_match(
    left: &LegacyGeneratedWalletRow,
    right: &LegacyGeneratedWalletRow,
) -> bool {
    left.key == right.key
        && optional_timestamp_matches(left.block_timestamp, right.block_timestamp)
        && legacy_preimage_bytes_match(&left.preimage, &right.preimage)
        && left.encrypted_random == right.encrypted_random
}

fn optional_timestamp_matches(artifact: Option<u64>, squid: Option<u64>) -> bool {
    match artifact {
        Some(artifact) => squid == Some(artifact),
        None => true,
    }
}

fn commitment_preimage_bytes_match(left: &[u8], right: &[u8]) -> bool {
    if left == right {
        return true;
    }
    let Ok(left) = CommitmentPreimage::abi_decode(left) else {
        return false;
    };
    let Ok(right) = CommitmentPreimage::abi_decode(right) else {
        return false;
    };
    commitment_preimages_wallet_equivalent(&left, &right)
}

fn legacy_preimage_bytes_match(left: &[u8], right: &[u8]) -> bool {
    if left == right {
        return true;
    }
    let Ok(left) = LegacyCommitmentPreimage::abi_decode(left) else {
        return false;
    };
    let Ok(right) = LegacyCommitmentPreimage::abi_decode(right) else {
        return false;
    };
    legacy_preimages_wallet_equivalent(&left, &right)
}

fn commitment_preimages_wallet_equivalent(
    left: &CommitmentPreimage,
    right: &CommitmentPreimage,
) -> bool {
    left.npk == right.npk
        && token_data_wallet_equivalent(&left.token, &right.token)
        && left.value == right.value
        && left.hash() == right.hash()
}

fn legacy_preimages_wallet_equivalent(
    left: &LegacyCommitmentPreimage,
    right: &LegacyCommitmentPreimage,
) -> bool {
    left.npk == right.npk
        && token_data_wallet_equivalent(&left.token, &right.token)
        && left.value == right.value
        && left.hash() == right.hash()
}

fn token_data_wallet_equivalent(left: &TokenData, right: &TokenData) -> bool {
    left.tokenType == right.tokenType
        && left.tokenAddress == right.tokenAddress
        && (left.tokenSubID == right.tokenSubID || left.tokenType == 0)
}

fn squid_commitments_in_ranges(
    ranges: &[IndexedArtifactRange],
    squid: &[CommitmentRow],
) -> Vec<CommitmentRow> {
    if ranges.is_empty() {
        return Vec::new();
    }
    squid
        .iter()
        .filter(|row| {
            ranges
                .iter()
                .any(|range| row.global_position >= range.start && row.global_position <= range.end)
        })
        .cloned()
        .collect()
}

fn squid_wallet_in_ranges(
    ranges: &[IndexedArtifactRange],
    squid: &WalletArtifacts,
) -> WalletArtifacts {
    if ranges.is_empty() {
        return WalletArtifacts::default();
    }
    WalletArtifacts {
        transact: squid
            .transact
            .iter()
            .filter(|row| block_in_ranges(row.key.block_number, ranges))
            .cloned()
            .collect(),
        shield: squid
            .shield
            .iter()
            .filter(|row| block_in_ranges(row.key.block_number, ranges))
            .cloned()
            .collect(),
        nullifiers: squid
            .nullifiers
            .iter()
            .filter(|row| block_in_ranges(row.key.block_number, ranges))
            .cloned()
            .collect(),
        legacy_encrypted: squid
            .legacy_encrypted
            .iter()
            .filter(|row| block_in_ranges(row.key.block_number, ranges))
            .cloned()
            .collect(),
        legacy_generated: squid
            .legacy_generated
            .iter()
            .filter(|row| block_in_ranges(row.key.block_number, ranges))
            .cloned()
            .collect(),
    }
}

fn block_in_ranges(block_number: u64, ranges: &[IndexedArtifactRange]) -> bool {
    ranges
        .iter()
        .any(|range| block_number >= range.start && block_number <= range.end)
}

fn squid_commitments_by_tree(rows: &[CommitmentRow]) -> BTreeMap<u32, Vec<CommitmentRow>> {
    let mut by_tree: BTreeMap<u32, Vec<CommitmentRow>> = BTreeMap::new();
    for row in rows {
        by_tree
            .entry(row.tree_number)
            .or_default()
            .push(row.clone());
    }
    by_tree
}

fn dense_leaves(rows: &[CommitmentRow], leaf_count: u64) -> Vec<[u8; 32]> {
    let zero = MERKLE_ZERO_VALUE.to_be_bytes::<32>();
    let Ok(len) = usize::try_from(leaf_count) else {
        return Vec::new();
    };
    let mut leaves = vec![zero; len];
    for row in rows {
        if let Ok(index) = usize::try_from(row.tree_position)
            && let Some(leaf) = leaves.get_mut(index)
        {
            *leaf = row.hash;
        }
    }
    leaves
}

fn merkle_root(leaves: &[[u8; 32]]) -> Result<[u8; 32]> {
    let leaf_count = usize::try_from(TREE_LEAF_COUNT).wrap_err("tree leaf count overflow")?;
    let mut layer = vec![MERKLE_ZERO_VALUE; leaf_count];
    for (index, leaf) in leaves.iter().enumerate() {
        if index >= layer.len() {
            bail!("leaf count exceeds tree size");
        }
        layer[index] = U256::from_be_bytes(*leaf);
    }
    for _ in 0..TREE_DEPTH {
        let mut parents = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks_exact(2) {
            parents.push(poseidon(vec![pair[0], pair[1]]));
        }
        layer = parents;
    }
    Ok(layer
        .first()
        .copied()
        .unwrap_or(MERKLE_ZERO_VALUE)
        .to_be_bytes::<32>())
}

fn latest_indexed_block(
    chain: &railgun_indexer_core::manifest::IndexedArtifactChainEntry,
    dataset_kind: IndexedDatasetKind,
) -> Result<u64> {
    chain
        .latest_indexed
        .iter()
        .find(|height| height.dataset_kind == dataset_kind)
        .map(|height| height.block_number)
        .ok_or_else(|| {
            eyre!(
                "chain {} missing latest indexed height for {:?}",
                chain.scope.chain_id,
                dataset_kind
            )
        })
}

const fn wallet_row_count(wallet: &WalletArtifacts) -> usize {
    wallet.transact.len()
        + wallet.shield.len()
        + wallet.nullifiers.len()
        + wallet.legacy_encrypted.len()
        + wallet.legacy_generated.len()
}

fn sort_wallet(wallet: &mut WalletArtifacts) {
    wallet
        .transact
        .sort_by(|left, right| left.key.cmp(&right.key));
    wallet
        .shield
        .sort_by(|left, right| left.key.cmp(&right.key));
    wallet
        .nullifiers
        .sort_by(|left, right| left.key.cmp(&right.key));
    wallet
        .legacy_encrypted
        .sort_by(|left, right| left.key.cmp(&right.key));
    wallet
        .legacy_generated
        .sort_by(|left, right| left.key.cmp(&right.key));
}

fn global_tree_position(tree_number: u32, tree_position: u64) -> Result<u64> {
    u64::from(tree_number)
        .checked_mul(TREE_LEAF_COUNT)
        .and_then(|tree_start| tree_start.checked_add(tree_position))
        .ok_or_else(|| eyre!("global tree position overflow"))
}

async fn fetch_manifest(client: &Client, args: &Args) -> Result<ManifestFetch> {
    if let Some(ipns_name) = args.manifest_ipns_name.as_deref() {
        let ipns_name = normalize_ipns_name(ipns_name)?;
        progress!("fetching manifest ipns_name={}", ipns_name);
        let bytes = fetch_ipns(client, ipns_name).await?;
        let cid = raw_block_cid(&bytes)
            .wrap_err("compute CID for IPNS-resolved manifest bytes")?
            .to_string();
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

#[derive(Debug, Clone)]
struct SourceSubset {
    block_number: u64,
    block_timestamp: Option<u64>,
    transaction_hash: [u8; 32],
}

impl SourceSubset {
    fn read(cursor: &mut Cursor<'_>) -> Result<Self> {
        let block_number = cursor.read_u64()?;
        let block_timestamp = Some(cursor.read_u64()?);
        let transaction_hash = cursor.read_fixed_32()?;
        Ok(Self {
            block_number,
            block_timestamp,
            transaction_hash,
        })
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_u8(&mut self) -> Result<u8> {
        let byte = *self
            .bytes
            .get(self.position)
            .ok_or_else(|| eyre!("unexpected EOF"))?;
        self.position += 1;
        Ok(byte)
    }

    fn read_u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    fn read_fixed_32(&mut self) -> Result<[u8; 32]> {
        self.read_array()
    }

    fn read_fixed_64(&mut self) -> Result<[u8; 64]> {
        self.read_array()
    }

    fn read_bytes(&mut self) -> Result<Vec<u8>> {
        let len = usize::try_from(self.read_u32()?).wrap_err("byte vector length overflow")?;
        let bytes = self.read_exact(len)?;
        Ok(bytes.to_vec())
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.read_exact(N)?;
        let mut out = [0_u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(len)
            .ok_or_else(|| eyre!("cursor overflow"))?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| eyre!("unexpected EOF"))?;
        self.position = end;
        Ok(bytes)
    }

    fn expect_end(&self, label: &'static str) -> Result<()> {
        if self.position != self.bytes.len() {
            bail!(
                "{label} has {} trailing bytes",
                self.bytes.len() - self.position
            );
        }
        Ok(())
    }
}

fn value_field<'a>(value: &'a Value, field: &'static str) -> Result<&'a Value> {
    value
        .get(field)
        .ok_or_else(|| eyre!("field {field} missing"))
}

fn string_field<'a>(value: &'a Value, field: &'static str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| eyre!("field {field} missing or not string"))
}

fn u32_field(value: &Value, field: &'static str) -> Result<u32> {
    u32::try_from(u64_field(value, field)?).wrap_err_with(|| format!("field {field} exceeds u32"))
}

fn u64_field(value: &Value, field: &'static str) -> Result<u64> {
    let value = value_field(value, field)?;
    match value {
        Value::String(value) => parse_u64_string(value),
        Value::Number(value) => value.as_u64().ok_or_else(|| eyre!("field {field} not u64")),
        _ => bail!("field {field} is not numeric"),
    }
}

fn uint120_field(value: &Value, field: &'static str) -> Result<Uint<120, 2>> {
    let parsed = U256::from_be_bytes(u256_field(value, field)?);
    Ok(Uint::<120, 2>::from(parsed.to::<u128>()))
}

fn fixed_hex_field(value: &Value, field: &'static str) -> Result<[u8; 32]> {
    fixed_hex_sized::<32>(string_field(value, field)?)
}

fn u256_field(value: &Value, field: &'static str) -> Result<[u8; 32]> {
    parse_u256_value(value_field(value, field)?)
}

fn bytes_field(value: &Value, field: &'static str) -> Result<Vec<u8>> {
    let value = string_field(value, field)?;
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(value).wrap_err_with(|| format!("decode field {field}"))
}

fn fixed_array_32<const N: usize>(value: &Value) -> Result<[FixedBytes<32>; N]> {
    let values = value.as_array().ok_or_else(|| eyre!("expected array"))?;
    if values.len() != N {
        bail!("expected {N} fixed values, got {}", values.len());
    }
    let vec = values
        .iter()
        .map(parse_u256_value)
        .map(|result| result.map(FixedBytes::from))
        .collect::<Result<Vec<_>>>()?;
    vec.try_into()
        .map_err(|values: Vec<_>| eyre!("expected {N} values, got {}", values.len()))
}

fn fixed_vec_32(value: &Value) -> Result<Vec<[u8; 32]>> {
    value
        .as_array()
        .ok_or_else(|| eyre!("expected array"))?
        .iter()
        .map(parse_u256_value)
        .collect()
}

fn token_type(value: &Value) -> Result<u8> {
    match value {
        Value::String(value) => match value.as_str() {
            "ERC20" => Ok(0),
            "ERC721" => Ok(1),
            "ERC1155" => Ok(2),
            other => other.parse::<u8>().wrap_err("parse token type"),
        },
        Value::Number(value) => value
            .as_u64()
            .and_then(|value| u8::try_from(value).ok())
            .ok_or_else(|| eyre!("token type out of range")),
        _ => bail!("unsupported token type"),
    }
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

fn fixed_hex_sized<const N: usize>(value: &str) -> Result<[u8; N]> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    let value = if value.len().is_multiple_of(2) {
        value.to_string()
    } else {
        format!("0{value}")
    };
    let bytes = hex::decode(value)?;
    if bytes.len() > N {
        bail!("expected at most {N} bytes, got {}", bytes.len());
    }
    let mut padded = [0_u8; N];
    let start = padded.len() - bytes.len();
    padded[start..].copy_from_slice(&bytes);
    Ok(padded)
}

fn elapsed_ms(started: Instant) -> u128 {
    started.elapsed().as_millis()
}

fn squid_page_tail(page: &[Value]) -> String {
    page.last()
        .map(|value| {
            format!(
                " last_block={} last_tx={}",
                json_field_summary(value, "blockNumber"),
                json_field_summary(value, "transactionHash")
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
