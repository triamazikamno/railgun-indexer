use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::eips::BlockNumberOrTag;
use alloy::hex;
use alloy::primitives::FixedBytes;
use alloy::providers::{Provider, ProviderBuilder, RootProvider, WsConnect};
use alloy::sol_types::SolEvent;
use alloy::transports::TransportError;
use alloy_rpc_types_eth::Filter;
use broadcaster_core::contracts::railgun::{
    CommitmentBatch, GeneratedCommitmentBatch, Nullified, Nullifiers, RailgunLegacyShieldEvents,
    Shield, Transact,
};
use broadcaster_core::tree::TREE_LEAF_COUNT;
use ed25519_dalek::SigningKey;
use eyre::{Result, WrapErr, eyre};
use futures_util::{StreamExt, future::join_all};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use railgun_indexer_core::audit::{Audit, IndexedArtifactPublicationKind};
use railgun_indexer_core::chain_indexer::{
    ChainIndexedBlockHeader, ChainLogIndexingOutcome, ChainLogIndexingRange, index_chain_log_range,
};
use railgun_indexer_core::chunk::{ChunkPlanItem, ChunkPlanningConfig, plan_chunks};
use railgun_indexer_core::commitments::{commitment_chunk_plan_item, prepare_commitment_chunk};
use railgun_indexer_core::config::{ChainIndexedChainConfig, Config};
use railgun_indexer_core::manifest::{
    ChainScope, ChainType, CompressionAlgorithm, DatasetDescriptorMetadata,
    INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION, INDEXED_ARTIFACT_MANIFEST_FORMAT_VERSION,
    IndexedArtifactCatalog, IndexedArtifactChainEntry, IndexedArtifactDescriptor,
    IndexedArtifactRange, IndexedDatasetKind, LatestIndexedHeight, PublisherIdentity, content_hash,
};
use railgun_indexer_core::merkle_checkpoint::{
    MerkleCheckpointArtifact, prepare_merkle_checkpoint_artifact,
};
use railgun_indexer_core::public_txid::{
    prepare_public_txid_chunk, public_txid_checkpoint_root, public_txid_chunk_plan_item,
};
use railgun_indexer_core::publish::ipfs::{IpfsClient, pin_indexed_chunk, pin_manifest};
use railgun_indexer_core::publish::ipns::IpnsPublisher;
use railgun_indexer_core::store::{
    IndexedDatasetKind as StoreDatasetKind, Store, StoredPublicTxidRow,
};
use railgun_indexer_core::wallet_scan::{prepare_wallet_scan_chunk, wallet_scan_chunk_plan_item};

const EVM_CHAIN_TYPE: u8 = 0;
const PUBLIC_TXID_PLANNING_ROW_UNIT: usize = 1_000;
const COMMITMENT_PLANNING_ROW_UNIT: usize = 1_000;
const WALLET_SCAN_PLANNING_BLOCK_SPAN: u64 = 100;
const MIN_INDEXING_BATCH_BLOCKS: u64 = 1_000;

struct ChainRuntime {
    chain: ChainIndexedChainConfig,
    provider: RootProvider,
    archive_provider: RootProvider,
}

impl ChainRuntime {
    fn new(chain: ChainIndexedChainConfig) -> Result<Self> {
        let provider = build_provider(&chain.rpc_url).wrap_err_with(|| {
            format!(
                "build chain-indexed RPC provider for chain {}",
                chain.chain_id
            )
        })?;
        let archive_provider = build_provider(&chain.archive_rpc_url).wrap_err_with(|| {
            format!(
                "build chain-indexed archive RPC provider for chain {}",
                chain.chain_id
            )
        })?;

        Ok(Self {
            chain,
            provider,
            archive_provider,
        })
    }
}

pub(crate) async fn run_indexing_loop(
    config: Config,
    store: Store,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let chains = config
        .chain_indexed
        .chains
        .clone()
        .into_iter()
        .map(ChainRuntime::new)
        .collect::<Result<Vec<_>>>()?;
    let mut tasks = JoinSet::new();
    for chain in chains {
        let config = config.clone();
        let store = store.clone();
        let shutdown = shutdown.clone();
        tasks.spawn(async move { run_chain_indexing_loop(config, store, chain, shutdown).await });
    }

    loop {
        tokio::select! {
            shutdown = shutdown_changed_or_requested(&mut shutdown) => {
                if shutdown {
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    return Ok(());
                }
            }
            result = tasks.join_next() => {
                match result {
                    Some(Ok(Ok(()))) if shutdown_requested(&shutdown) => return Ok(()),
                    Some(Ok(Ok(()))) => return Err(eyre!("chain-indexed RPC indexing worker exited unexpectedly")),
                    Some(Ok(Err(error))) => return Err(error),
                    Some(Err(error)) => {
                        return Err(eyre!(error).wrap_err("chain-indexed RPC indexing worker failed"));
                    }
                    None => return Ok(()),
                }
            }
        }
    }
}

async fn run_chain_indexing_loop(
    config: Config,
    store: Store,
    runtime: ChainRuntime,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let idle_interval = checked_interval(
        *config.chain_indexed.index_interval,
        "chain_indexed.index_interval",
    )?;
    let tail_safety_interval = checked_interval(
        *config.chain_indexed.tail_safety_interval,
        "chain_indexed.tail_safety_interval",
    )?;
    let configured_batch_span = config.chain_indexed.max_blocks_per_batch;
    let tail_batch_span = config.chain_indexed.tail_safety_block_span;
    let min_batch_span = configured_batch_span.clamp(1, MIN_INDEXING_BATCH_BLOCKS);
    let mut max_batch_span = configured_batch_span;
    let mut batch_span = configured_batch_span;
    let mut historical_catch_up_complete = false;

    loop {
        if shutdown_requested(&shutdown) {
            return Ok(());
        }

        let provider_mode = if historical_catch_up_complete {
            ChainIndexProviderMode::NormalWithArchiveFallback
        } else {
            ChainIndexProviderMode::Archive
        };
        let requested_batch_span = if historical_catch_up_complete {
            tail_batch_span
        } else {
            batch_span
        };

        match index_chain_once(
            &store,
            &config,
            &runtime,
            requested_batch_span,
            provider_mode,
        )
        .await
        {
            Ok(ChainIndexStep::Indexed {
                fetched_log_count,
                indexing_lag_blocks,
            }) => {
                if !historical_catch_up_complete
                    && fetched_log_count == 0
                    && batch_span < max_batch_span
                {
                    batch_span = batch_span.saturating_mul(2).min(max_batch_span);
                }
                if indexing_lag_blocks == 0 {
                    historical_catch_up_complete = true;
                    batch_span = max_batch_span;
                    if wait_for_tail_wakeup(
                        &config,
                        &runtime,
                        tail_safety_interval,
                        idle_interval,
                        &mut shutdown,
                    )
                    .await
                    {
                        return Ok(());
                    }
                }
            }
            Ok(ChainIndexStep::CaughtUp) => {
                historical_catch_up_complete = true;
                batch_span = max_batch_span;
                if wait_for_tail_wakeup(
                    &config,
                    &runtime,
                    tail_safety_interval,
                    idle_interval,
                    &mut shutdown,
                )
                .await
                {
                    return Ok(());
                }
            }
            Err(error) => {
                let next_batch_span = if historical_catch_up_complete {
                    tail_batch_span
                } else {
                    (batch_span / 2).max(min_batch_span)
                };
                let block_range_too_large = is_block_range_too_large(&error);
                if !historical_catch_up_complete && block_range_too_large {
                    max_batch_span = max_batch_span.min(next_batch_span);
                }
                let next_batch_span = if historical_catch_up_complete {
                    next_batch_span
                } else {
                    next_batch_span.min(max_batch_span)
                };
                warn!(
                    chain_id = runtime.chain.chain_id,
                    railgun_contract = %runtime.chain.railgun_contract,
                    batch_span = requested_batch_span,
                    next_batch_span,
                    max_batch_span,
                    historical_catch_up_complete,
                    block_range_too_large,
                    error = %format_report_chain(&error),
                    "chain-indexed RPC indexing cycle failed for chain"
                );
                if !historical_catch_up_complete {
                    batch_span = next_batch_span;
                }
                if sleep_or_shutdown(idle_interval, &mut shutdown).await {
                    return Ok(());
                }
            }
        }
    }
}

async fn wait_for_tail_wakeup(
    config: &Config,
    runtime: &ChainRuntime,
    tail_safety_interval: Duration,
    finality_poll_interval: Duration,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    let Some(ws_url) = runtime.chain.ws_url.as_deref() else {
        return sleep_or_shutdown(tail_safety_interval, shutdown).await;
    };

    match wait_for_ws_log_or_safety_interval(
        config,
        runtime,
        ws_url,
        tail_safety_interval,
        finality_poll_interval,
        shutdown,
    )
    .await
    {
        Ok(shutdown) => shutdown,
        Err(error) => {
            warn!(
                chain_id = runtime.chain.chain_id,
                railgun_contract = %runtime.chain.railgun_contract,
                ws_url,
                error = %format_report_chain(&error),
                "chain-indexed websocket subscription failed; using safety interval fallback"
            );
            sleep_or_shutdown(tail_safety_interval, shutdown).await
        }
    }
}

async fn wait_for_ws_log_or_safety_interval(
    config: &Config,
    runtime: &ChainRuntime,
    ws_url: &str,
    tail_safety_interval: Duration,
    finality_poll_interval: Duration,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<bool> {
    let ws = WsConnect::new(ws_url.to_string());
    let provider = ProviderBuilder::new()
        .connect_ws(ws)
        .await
        .wrap_err("connect chain-indexed websocket provider")?;
    let filter = chain_index_subscription_filter(runtime);
    let subscription = provider
        .subscribe_logs(&filter)
        .await
        .wrap_err("subscribe to chain-indexed Railgun logs")?;
    let mut stream = Box::pin(subscription.into_stream());
    debug!(
        chain_id = runtime.chain.chain_id,
        railgun_contract = %runtime.chain.railgun_contract,
        ws_url,
        tail_safety_interval_ms = tail_safety_interval.as_millis(),
        "waiting for chain-indexed websocket log or safety interval"
    );

    tokio::select! {
        () = tokio::time::sleep(tail_safety_interval) => Ok(shutdown_requested(shutdown)),
        shutdown = shutdown_changed_or_requested(shutdown) => Ok(shutdown),
        maybe_log = stream.next() => {
            let log = maybe_log.ok_or_else(|| eyre!("chain-indexed websocket log stream ended"))?;
            let block_number = log.block_number;
            debug!(
                chain_id = runtime.chain.chain_id,
                railgun_contract = %runtime.chain.railgun_contract,
                ws_url,
                block_number,
                transaction_hash = ?log.transaction_hash,
                "chain-indexed websocket log wakeup"
            );
            if let Some(block_number) = block_number {
                wait_for_ws_log_finality(
                    config,
                    runtime,
                    block_number,
                    finality_poll_interval,
                    shutdown,
                )
                .await
            } else {
                Ok(false)
            }
        }
    }
}

async fn wait_for_ws_log_finality(
    config: &Config,
    runtime: &ChainRuntime,
    log_block: u64,
    poll_interval: Duration,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<bool> {
    loop {
        let safe_head = runtime
            .provider
            .get_block_number()
            .await
            .wrap_err("fetch chain head while waiting for websocket log finality")?
            .saturating_sub(config.chain_indexed.safe_confirmations);
        if safe_head >= log_block {
            return Ok(false);
        }
        if sleep_or_shutdown(poll_interval, shutdown).await {
            return Ok(true);
        }
    }
}

fn chain_index_subscription_filter(runtime: &ChainRuntime) -> Filter {
    Filter::new()
        .address(runtime.chain.railgun_contract)
        .event_signature(chain_index_subscription_event_signatures())
}

fn chain_index_subscription_event_signatures() -> Vec<alloy::primitives::FixedBytes<32>> {
    vec![
        CommitmentBatch::SIGNATURE_HASH,
        GeneratedCommitmentBatch::SIGNATURE_HASH,
        Transact::SIGNATURE_HASH,
        RailgunLegacyShieldEvents::Shield::SIGNATURE_HASH,
        Shield::SIGNATURE_HASH,
        Nullifiers::SIGNATURE_HASH,
        Nullified::SIGNATURE_HASH,
    ]
}

pub(crate) async fn run_publication_loop(
    config: Config,
    store: Store,
    ipfs_client: Arc<dyn IpfsClient>,
    signing_key: SigningKey,
    ipns_publisher: IpnsPublisher,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let interval = checked_interval(
        *config.chain_indexed.publish_interval,
        "chain_indexed.publish_interval",
    )?;
    let mut scheduler = ChainIndexedPublicationScheduler {
        config,
        store,
        ipfs_client,
        signing_key,
        ipns_publisher,
        last_ipns_sequence: None,
        ipns_sequence_loaded: false,
    };
    if sleep_or_shutdown(interval, &mut shutdown).await {
        return Ok(());
    }

    loop {
        if let Err(error) = scheduler.publish_cycle(SystemTime::now()).await {
            warn!(
                error = %format_report_chain(&error),
                "chain-indexed artifact publication cycle failed"
            );
        }

        if sleep_or_shutdown(interval, &mut shutdown).await {
            return Ok(());
        }
    }
}

enum ChainIndexStep {
    Indexed {
        fetched_log_count: usize,
        indexing_lag_blocks: u64,
    },
    CaughtUp,
}

#[derive(Clone, Copy)]
enum ChainIndexProviderMode {
    Archive,
    NormalWithArchiveFallback,
}

async fn index_chain_once(
    store: &Store,
    config: &Config,
    runtime: &ChainRuntime,
    batch_span: u64,
    provider_mode: ChainIndexProviderMode,
) -> Result<ChainIndexStep> {
    let safe_head = runtime
        .provider
        .get_block_number()
        .await
        .wrap_err("fetch chain head")?
        .saturating_sub(config.chain_indexed.safe_confirmations);
    let from_block = resume_block_after_reorg(store, config, runtime).await?;
    if from_block > safe_head {
        return Ok(ChainIndexStep::CaughtUp);
    }
    let to_block = from_block
        .saturating_add(batch_span.saturating_sub(1))
        .min(safe_head);

    match provider_mode {
        ChainIndexProviderMode::Archive => {
            index_chain_range_with_provider(
                store,
                config,
                runtime,
                &runtime.archive_provider,
                "archive",
                safe_head,
                from_block,
                to_block,
            )
            .await
        }
        ChainIndexProviderMode::NormalWithArchiveFallback => match index_chain_range_with_provider(
            store,
            config,
            runtime,
            &runtime.provider,
            "rpc",
            safe_head,
            from_block,
            to_block,
        )
        .await
        {
            Ok(step) => Ok(step),
            Err(error) => {
                warn!(
                    chain_id = runtime.chain.chain_id,
                    railgun_contract = %runtime.chain.railgun_contract,
                    from_block,
                    to_block,
                    error = %format_report_chain(&error),
                    "chain-indexed normal RPC tail scan failed; retrying archive RPC"
                );
                index_chain_range_with_provider(
                    store,
                    config,
                    runtime,
                    &runtime.archive_provider,
                    "archive-fallback",
                    safe_head,
                    from_block,
                    to_block,
                )
                .await
            }
        },
    }
}

async fn index_chain_range_with_provider(
    store: &Store,
    config: &Config,
    runtime: &ChainRuntime,
    provider: &RootProvider,
    rpc_source: &'static str,
    safe_head: u64,
    from_block: u64,
    to_block: u64,
) -> Result<ChainIndexStep> {
    let indexed_through_header = fetch_block_header(provider, to_block).await?;
    let indexed_through_block_hash = indexed_through_header.block_hash;

    let outcome = index_chain_log_range(
        store,
        provider,
        ChainLogIndexingRange {
            chain_type: EVM_CHAIN_TYPE,
            chain_id: runtime.chain.chain_id,
            railgun_contract: runtime.chain.railgun_contract,
            from_block,
            to_block,
            indexed_through_block_hash,
            indexed_block_headers: vec![indexed_through_header],
            v2_start_block: runtime.chain.v2_start_block,
            legacy_shield_block: runtime.chain.legacy_shield_block,
        },
    )
    .await
    .wrap_err("index chain log range")?;
    let indexing_lag_blocks = safe_head.saturating_sub(outcome.to_block);
    let batch_block_span = outcome
        .to_block
        .saturating_sub(outcome.from_block)
        .saturating_add(1);

    log_indexed_range(
        runtime,
        config,
        rpc_source,
        safe_head,
        indexing_lag_blocks,
        batch_block_span,
        &outcome,
    );
    Ok(ChainIndexStep::Indexed {
        fetched_log_count: outcome.fetched_log_count,
        indexing_lag_blocks,
    })
}

fn log_indexed_range(
    runtime: &ChainRuntime,
    config: &Config,
    rpc_source: &'static str,
    safe_head: u64,
    indexing_lag_blocks: u64,
    batch_block_span: u64,
    outcome: &ChainLogIndexingOutcome,
) {
    if indexing_lag_blocks == 0
        && outcome.fetched_log_count == 0
        && outcome.persisted_row_count == 0
    {
        debug!(
            chain_id = runtime.chain.chain_id,
            railgun_contract = %runtime.chain.railgun_contract,
            rpc_source,
            safe_head,
            indexing_lag_blocks,
            batch_block_span,
            configured_batch_span = config.chain_indexed.max_blocks_per_batch,
            from_block = outcome.from_block,
            to_block = outcome.to_block,
            fetched_log_count = outcome.fetched_log_count,
            persisted_row_count = outcome.persisted_row_count,
            "indexed empty chain tail range"
        );
        return;
    }

    info!(
        chain_id = runtime.chain.chain_id,
        railgun_contract = %runtime.chain.railgun_contract,
        rpc_source,
        safe_head,
        indexing_lag_blocks,
        batch_block_span,
        configured_batch_span = config.chain_indexed.max_blocks_per_batch,
        from_block = outcome.from_block,
        to_block = outcome.to_block,
        fetched_log_count = outcome.fetched_log_count,
        persisted_row_count = outcome.persisted_row_count,
        "indexed chain log range"
    );
}

async fn resume_block_after_reorg(
    store: &Store,
    config: &Config,
    runtime: &ChainRuntime,
) -> Result<u64> {
    loop {
        let Some(progress) = store
            .chain_indexing_progress(
                EVM_CHAIN_TYPE,
                runtime.chain.chain_id,
                runtime.chain.railgun_contract,
                StoreDatasetKind::WalletScan,
            )
            .await
            .wrap_err("read chain-indexed progress")?
        else {
            return Ok(runtime.chain.start_block);
        };

        let remote_header =
            fetch_block_header(&runtime.archive_provider, progress.indexed_through_block).await?;
        if remote_header.block_hash.as_slice() == progress.indexed_through_block_hash {
            return Ok(progress.indexed_through_block.saturating_add(1));
        }

        let replay_from_block = progress
            .indexed_through_block
            .saturating_sub(config.chain_indexed.max_blocks_per_batch.saturating_sub(1))
            .max(runtime.chain.start_block);
        warn!(
            chain_id = runtime.chain.chain_id,
            railgun_contract = %runtime.chain.railgun_contract,
            replay_from_block,
            local_hash = %hex::encode_prefixed(progress.indexed_through_block_hash),
            remote_hash = %hex::encode_prefixed(remote_header.block_hash.as_slice()),
            "detected chain-indexed reorg; rewinding indexed rows"
        );
        let mut tx = store.begin().await.wrap_err("begin reorg rewind")?;
        if replay_from_block > runtime.chain.start_block {
            let previous_header = fetch_block_header(
                &runtime.archive_provider,
                replay_from_block.saturating_sub(1),
            )
            .await
            .wrap_err("fetch reorg rewind previous block header")?;
            Store::record_indexed_block_header(
                &mut tx,
                EVM_CHAIN_TYPE,
                runtime.chain.chain_id,
                previous_header.block_number,
                previous_header.block_hash.as_slice(),
                previous_header.parent_hash.as_slice(),
            )
            .await
            .wrap_err("record reorg rewind previous block header")?;
        }
        let rewind = Store::rewind_chain_indexing_to_replay_block(
            &mut tx,
            EVM_CHAIN_TYPE,
            runtime.chain.chain_id,
            runtime.chain.railgun_contract,
            replay_from_block,
        )
        .await
        .wrap_err("rewind indexed rows after reorg")?;
        tx.commit().await.wrap_err("commit reorg rewind")?;
        info!(
            chain_id = runtime.chain.chain_id,
            railgun_contract = %runtime.chain.railgun_contract,
            replay_from_block,
            deleted_indexed_rows = rewind.deleted_indexed_rows,
            deleted_public_transactions = rewind.deleted_public_transactions,
            deleted_block_headers = rewind.deleted_block_headers,
            rewound_progress_rows = rewind.rewound_progress_rows,
            deleted_progress_rows = rewind.deleted_progress_rows,
            "rewound chain-indexed rows after reorg"
        );
    }
}

async fn fetch_block_header(
    provider: &RootProvider,
    block_number: u64,
) -> Result<ChainIndexedBlockHeader> {
    let block = provider
        .get_block_by_number(BlockNumberOrTag::Number(block_number))
        .await
        .map_err(provider_error)?
        .ok_or_else(|| eyre!("block {block_number} is unavailable from RPC provider"))?;
    Ok(ChainIndexedBlockHeader {
        block_number,
        block_hash: block.header.hash,
        parent_hash: block.header.parent_hash,
    })
}

struct ChainIndexedPublicationScheduler {
    config: Config,
    store: Store,
    ipfs_client: Arc<dyn IpfsClient>,
    signing_key: SigningKey,
    ipns_publisher: IpnsPublisher,
    last_ipns_sequence: Option<u64>,
    ipns_sequence_loaded: bool,
}

impl ChainIndexedPublicationScheduler {
    async fn publish_cycle(&mut self, now: SystemTime) -> Result<()> {
        let configured_chains = self.config.chain_indexed.chains.clone();
        let published_chains = join_all(
            configured_chains
                .iter()
                .map(|chain| self.publish_chain_entry(chain)),
        )
        .await;

        let mut chains = Vec::new();
        for (chain, result) in configured_chains.iter().zip(published_chains) {
            match result {
                Ok(Some(entry)) => chains.push(entry),
                Ok(None) => {}
                Err(error) => {
                    return Err(error).wrap_err_with(|| {
                        format!(
                            "publish chain-indexed artifacts for chain {} ({})",
                            chain.chain_id, chain.railgun_contract
                        )
                    });
                }
            }
        }
        if chains.is_empty() {
            return Ok(());
        }

        let sequence = self.next_ipns_sequence(now).await?;
        let mut manifest = railgun_indexer_core::manifest::IndexedArtifactManifest::new(
            unix_millis(now)?,
            sequence,
            PublisherIdentity::ed25519(FixedBytes::ZERO),
            chains,
        );
        let chain_count = manifest.chains.len();
        let catalog_count = manifest
            .chains
            .iter()
            .map(|chain| chain.catalogs.len())
            .sum::<usize>();
        manifest
            .sign_manifest(&self.signing_key)
            .wrap_err("sign chain-indexed manifest")?;
        let manifest_bytes =
            serde_json::to_vec(&manifest).wrap_err("serialize chain-indexed manifest")?;
        let byte_size = u64::try_from(manifest_bytes.len())
            .wrap_err("chain-indexed manifest byte size overflow")?;
        let manifest_hash = content_hash(&manifest_bytes);
        let manifest_cid = pin_manifest(self.ipfs_client.as_ref(), &manifest_bytes)
            .await
            .wrap_err("pin chain-indexed manifest")?;

        let mut tx = self
            .store
            .begin()
            .await
            .wrap_err("begin chain-indexed manifest audit transaction")?;
        Audit::record_indexed_manifest_pin(
            &mut tx,
            &manifest_cid,
            sequence,
            byte_size,
            &manifest_hash,
            INDEXED_ARTIFACT_MANIFEST_FORMAT_VERSION,
        )
        .await
        .wrap_err("record chain-indexed manifest pin")?;
        tx.commit()
            .await
            .wrap_err("commit chain-indexed manifest pin audit")?;

        let manifest_cid_string = manifest_cid.to_string();
        self.ipns_publisher
            .publish_manifest_cid(&manifest_cid_string, sequence)
            .await
            .wrap_err("publish chain-indexed manifest CID to IPNS")?;
        let mut tx = self
            .store
            .begin()
            .await
            .wrap_err("begin chain-indexed manifest IPNS audit transaction")?;
        Audit::record_indexed_manifest_ipns_publication(&mut tx, &manifest_cid)
            .await
            .wrap_err("record chain-indexed manifest IPNS publication")?;
        tx.commit()
            .await
            .wrap_err("commit chain-indexed manifest IPNS audit")?;

        info!(
            manifest_cid = %manifest_cid_string,
            sequence,
            ipns_published = true,
            chain_count,
            catalog_count,
            byte_size,
            sha256 = %hex::encode_prefixed(manifest_hash),
            "published chain-indexed manifest"
        );
        Ok(())
    }

    async fn publish_chain_entry(
        &self,
        chain: &ChainIndexedChainConfig,
    ) -> Result<Option<IndexedArtifactChainEntry>> {
        let scope = ChainScope {
            chain_type: ChainType::Evm,
            chain_id: chain.chain_id,
            railgun_contract: chain.railgun_contract,
        };
        let latest_indexed = self.latest_indexed_heights(chain).await?;
        let mut catalogs = Vec::new();
        for dataset in &chain.datasets {
            match dataset {
                IndexedDatasetKind::PublicTxid => {
                    if let Some(max_block) = latest_indexed_block(&latest_indexed, *dataset) {
                        catalogs.extend(
                            self.publish_public_txid_catalog(chain, &scope, max_block)
                                .await?,
                        );
                    }
                }
                IndexedDatasetKind::WalletScan => {
                    if let Some(max_block) = latest_indexed_block(&latest_indexed, *dataset) {
                        catalogs.extend(
                            self.publish_wallet_scan_catalog(chain, &scope, max_block)
                                .await?,
                        );
                    }
                }
                IndexedDatasetKind::Commitments => {
                    catalogs.extend(self.publish_commitment_catalog(chain, &scope).await?);
                }
                IndexedDatasetKind::MerkleCheckpoint => {
                    catalogs.extend(
                        self.publish_merkle_checkpoint_catalog(chain, &scope)
                            .await?,
                    );
                }
            }
        }
        if catalogs.is_empty() {
            return Ok(None);
        }
        Ok(Some(IndexedArtifactChainEntry {
            scope,
            latest_indexed,
            catalogs,
        }))
    }

    async fn publish_public_txid_catalog(
        &self,
        chain: &ChainIndexedChainConfig,
        scope: &ChainScope,
        max_block: u64,
    ) -> Result<Vec<IndexedArtifactDescriptor>> {
        let mut offset = 0_u64;
        let mut chunks = Vec::new();
        loop {
            let row_limit = public_txid_chunk_row_limit(
                offset,
                self.config.chain_indexed.public_txid_chunk_row_limit,
            );
            let rows = self
                .store
                .public_txid_rows_through_block(
                    EVM_CHAIN_TYPE,
                    chain.chain_id,
                    chain.railgun_contract,
                    offset,
                    row_limit,
                    max_block,
                )
                .await
                .wrap_err("read public TXID rows for artifact publication")?;
            if rows.is_empty() {
                break;
            }
            let plan_items = public_txid_plan_items(scope, &rows)?;
            let planned_chunks = plan_chunks(&plan_items, ChunkPlanningConfig::default())
                .wrap_err("plan public TXID artifact chunks")?;
            for planned in planned_chunks {
                let chunk_rows = self
                    .store
                    .public_txid_rows_through_block(
                        EVM_CHAIN_TYPE,
                        chain.chain_id,
                        chain.railgun_contract,
                        planned.range.start,
                        planned.row_count,
                        max_block,
                    )
                    .await
                    .wrap_err("read planned public TXID rows for artifact publication")?;
                let checkpoint_root = self
                    .public_txid_checkpoint_root(chain, &chunk_rows, max_block)
                    .await
                    .wrap_err("compute public TXID checkpoint root")?;
                let mut published = prepare_public_txid_chunk(
                    scope.clone(),
                    &chunk_rows,
                    checkpoint_root,
                    CompressionAlgorithm::Zstd,
                )
                .wrap_err("publish public TXID chunk")?;
                published.descriptor = self
                    .reuse_or_pin_chunk(published.descriptor, &published.compressed_bytes)
                    .await?;
                self.record_chunk_descriptor(&published.descriptor).await?;
                offset = published.descriptor.range.end.saturating_add(1);
                chunks.push(published.descriptor);
            }
            if rows.len() < row_limit as usize {
                break;
            }
        }
        self.publish_catalogs(scope, IndexedDatasetKind::PublicTxid, chunks)
            .await
    }

    async fn public_txid_checkpoint_root(
        &self,
        chain: &ChainIndexedChainConfig,
        rows: &[StoredPublicTxidRow],
        max_block: u64,
    ) -> Result<[u8; 32]> {
        let last = rows
            .last()
            .ok_or_else(|| eyre!("public TXID checkpoint root requires rows"))?;
        let tree_start = last.txid_index / TREE_LEAF_COUNT * TREE_LEAF_COUNT;
        let row_count = last
            .txid_index
            .checked_sub(tree_start)
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| eyre!("public TXID checkpoint range overflow"))?;
        let checkpoint_rows = self
            .store
            .public_txid_rows_through_block(
                EVM_CHAIN_TYPE,
                chain.chain_id,
                chain.railgun_contract,
                tree_start,
                row_count,
                max_block,
            )
            .await
            .wrap_err("read public TXID checkpoint rows")?;
        public_txid_checkpoint_root(&checkpoint_rows).wrap_err("derive public TXID checkpoint root")
    }

    async fn wallet_scan_plan_items(
        &self,
        chain: &ChainIndexedChainConfig,
        scope: &ChainScope,
        start_block: u64,
        end_block: u64,
    ) -> Result<Vec<ChunkPlanItem>> {
        let mut items = Vec::new();
        let ranges = self
            .store
            .wallet_scan_populated_block_ranges(
                EVM_CHAIN_TYPE,
                chain.chain_id,
                chain.railgun_contract,
                start_block,
                end_block,
                WALLET_SCAN_PLANNING_BLOCK_SPAN,
            )
            .await
            .wrap_err("read populated wallet-scan block ranges")?;
        for range in ranges {
            let rows = self
                .store
                .wallet_scan_rows(
                    EVM_CHAIN_TYPE,
                    chain.chain_id,
                    chain.railgun_contract,
                    range.start_block,
                    range.end_block,
                )
                .await
                .wrap_err("read wallet scan rows for artifact planning")?;
            if rows.is_empty() {
                continue;
            }
            items.push(
                wallet_scan_chunk_plan_item(
                    scope,
                    range.start_block,
                    range.end_block,
                    &rows,
                    CompressionAlgorithm::Zstd,
                )
                .wrap_err("plan wallet-scan artifact chunk unit")?,
            );
        }
        Ok(items)
    }

    async fn publish_wallet_scan_catalog(
        &self,
        chain: &ChainIndexedChainConfig,
        scope: &ChainScope,
        max_block: u64,
    ) -> Result<Vec<IndexedArtifactDescriptor>> {
        if max_block < chain.start_block {
            return Ok(Vec::new());
        }

        let plan_items = self
            .wallet_scan_plan_items(chain, scope, chain.start_block, max_block)
            .await?;
        let planned_chunks = plan_chunks(&plan_items, ChunkPlanningConfig::default())
            .wrap_err("plan wallet-scan artifact chunks")?;
        let mut chunks = Vec::new();
        for planned in planned_chunks {
            let rows = self
                .store
                .wallet_scan_rows(
                    EVM_CHAIN_TYPE,
                    chain.chain_id,
                    chain.railgun_contract,
                    planned.range.start,
                    planned.range.end,
                )
                .await
                .wrap_err("read planned wallet scan rows for artifact publication")?;
            if rows.is_empty() {
                continue;
            }
            let mut published = prepare_wallet_scan_chunk(
                scope.clone(),
                planned.range.start,
                planned.range.end,
                &rows,
                CompressionAlgorithm::Zstd,
            )
            .wrap_err("publish wallet-scan chunk")?;
            published.descriptor = self
                .reuse_or_pin_chunk(published.descriptor, &published.compressed_bytes)
                .await?;
            self.record_chunk_descriptor(&published.descriptor).await?;
            chunks.push(published.descriptor);
        }
        self.publish_catalogs(scope, IndexedDatasetKind::WalletScan, chunks)
            .await
    }

    async fn publish_commitment_catalog(
        &self,
        chain: &ChainIndexedChainConfig,
        scope: &ChainScope,
    ) -> Result<Vec<IndexedArtifactDescriptor>> {
        let summaries = self
            .store
            .commitment_tree_summaries(EVM_CHAIN_TYPE, chain.chain_id, chain.railgun_contract)
            .await
            .wrap_err("read commitment tree summaries for commitment publication")?;
        let mut max_position = None;
        for summary in summaries {
            let last_position = summary
                .leaf_count
                .checked_sub(1)
                .ok_or_else(|| eyre!("commitment tree summary has zero leaves"))?;
            let tree_start = u64::from(summary.tree_number)
                .checked_mul(TREE_LEAF_COUNT)
                .ok_or_else(|| eyre!("commitment tree global position overflow"))?;
            let global_position = tree_start
                .checked_add(last_position)
                .ok_or_else(|| eyre!("commitment tree global position overflow"))?;
            max_position =
                Some(max_position.map_or(global_position, |value: u64| value.max(global_position)));
        }
        let Some(max_position) = max_position else {
            return Ok(Vec::new());
        };

        let mut start_position = 0_u64;
        let mut chunks = Vec::new();
        while start_position <= max_position {
            let end_position = start_position
                .saturating_add(
                    self.config
                        .chain_indexed
                        .commitment_chunk_row_limit
                        .saturating_sub(1),
                )
                .min(max_position);
            let rows = self
                .store
                .commitment_rows(
                    EVM_CHAIN_TYPE,
                    chain.chain_id,
                    chain.railgun_contract,
                    start_position,
                    end_position,
                )
                .await
                .wrap_err("read commitment rows for artifact publication")?;
            if rows.is_empty() {
                start_position = end_position.saturating_add(1);
                continue;
            }
            let plan_items = commitment_plan_items(scope, &rows)?;
            let planned_chunks = plan_chunks(&plan_items, ChunkPlanningConfig::default())
                .wrap_err("plan commitment artifact chunks")?;
            for planned in planned_chunks {
                let chunk_rows = self
                    .store
                    .commitment_rows(
                        EVM_CHAIN_TYPE,
                        chain.chain_id,
                        chain.railgun_contract,
                        planned.range.start,
                        planned.range.end,
                    )
                    .await
                    .wrap_err("read planned commitment rows for artifact publication")?;
                let mut published = prepare_commitment_chunk(
                    scope.clone(),
                    &chunk_rows,
                    CompressionAlgorithm::Zstd,
                )
                .wrap_err("publish commitment chunk")?;
                published.descriptor = self
                    .reuse_or_pin_chunk(published.descriptor, &published.compressed_bytes)
                    .await?;
                self.record_chunk_descriptor(&published.descriptor).await?;
                start_position = published.descriptor.range.end.saturating_add(1);
                chunks.push(published.descriptor);
            }
        }
        self.publish_catalogs(scope, IndexedDatasetKind::Commitments, chunks)
            .await
    }

    async fn publish_merkle_checkpoint_catalog(
        &self,
        chain: &ChainIndexedChainConfig,
        scope: &ChainScope,
    ) -> Result<Vec<IndexedArtifactDescriptor>> {
        let summaries = self
            .store
            .commitment_tree_summaries(EVM_CHAIN_TYPE, chain.chain_id, chain.railgun_contract)
            .await
            .wrap_err("read commitment tree summaries for checkpoint publication")?;
        let mut chunks = Vec::new();
        for summary in summaries {
            let checkpoint = self
                .store
                .commitment_tree_checkpoint(
                    EVM_CHAIN_TYPE,
                    chain.chain_id,
                    chain.railgun_contract,
                    &summary,
                )
                .await
                .wrap_err("read commitment tree checkpoint leaves")?;
            let artifact = MerkleCheckpointArtifact {
                tree_number: checkpoint.tree_number,
                leaf_count: checkpoint.leaf_count,
                last_indexed_block: checkpoint.last_indexed_block,
                leaves: checkpoint.leaves,
            };
            let mut published = prepare_merkle_checkpoint_artifact(
                scope.clone(),
                &artifact,
                CompressionAlgorithm::Zstd,
            )
            .wrap_err("publish Merkle checkpoint artifact")?;
            published.descriptor = self
                .reuse_or_pin_chunk(published.descriptor, &published.compressed_bytes)
                .await?;
            self.record_chunk_descriptor(&published.descriptor).await?;
            chunks.push(published.descriptor);
        }
        self.publish_catalogs(scope, IndexedDatasetKind::MerkleCheckpoint, chunks)
            .await
    }

    async fn publish_catalogs(
        &self,
        scope: &ChainScope,
        dataset_kind: IndexedDatasetKind,
        chunks: Vec<IndexedArtifactDescriptor>,
    ) -> Result<Vec<IndexedArtifactDescriptor>> {
        if chunks.is_empty() {
            return Ok(Vec::new());
        }
        let catalog = IndexedArtifactCatalog::new(dataset_kind, scope.clone(), chunks);
        let chunk_count = catalog.chunks.len();
        let total_chunk_byte_size = catalog.chunks.iter().try_fold(0_u64, |total, chunk| {
            total
                .checked_add(chunk.byte_size)
                .ok_or_else(|| eyre!("indexed artifact chunk byte size overflow"))
        })?;
        let max_chunk_byte_size = catalog
            .chunks
            .iter()
            .map(|chunk| chunk.byte_size)
            .max()
            .unwrap_or(0);
        let catalog_bytes = catalog
            .deterministic_body_bytes()
            .wrap_err("serialize indexed artifact catalog")?;
        let byte_size = u64::try_from(catalog_bytes.len())
            .wrap_err("indexed artifact catalog byte size overflow")?;
        let catalog_hash = content_hash(&catalog_bytes);
        let mut descriptor = catalog_descriptor(&catalog, "", byte_size, &catalog_hash)?;
        let catalog_cid = self
            .reuse_or_pin_indexed_artifact(
                IndexedArtifactPublicationKind::Catalog,
                descriptor.dataset_kind,
                &descriptor.scope,
                &descriptor.range,
                descriptor.byte_size,
                &catalog_hash,
                descriptor.encoding_version,
                &catalog_bytes,
            )
            .await
            .wrap_err("pin indexed artifact catalog")?;
        descriptor.cid = catalog_cid;
        let catalog_cid = descriptor
            .cid
            .parse::<cid::Cid>()
            .wrap_err_with(|| format!("parse indexed catalog CID {}", descriptor.cid))?;
        let mut tx = self
            .store
            .begin()
            .await
            .wrap_err("begin indexed catalog audit transaction")?;
        Audit::record_indexed_artifact_pin(
            &mut tx,
            IndexedArtifactPublicationKind::Catalog,
            descriptor.dataset_kind,
            &descriptor.scope,
            &descriptor.range,
            &catalog_cid,
            descriptor.byte_size,
            &catalog_hash,
            descriptor.encoding_version,
        )
        .await
        .wrap_err("record indexed catalog pin")?;
        tx.commit().await.wrap_err("commit indexed catalog audit")?;

        info!(
            chain_id = scope.chain_id,
            railgun_contract = %scope.railgun_contract,
            dataset = ?dataset_kind,
            cid = %descriptor.cid,
            chunk_count,
            total_chunk_byte_size,
            max_chunk_byte_size,
            byte_size,
            sha256 = %descriptor.sha256,
            "published indexed artifact catalog"
        );
        Ok(vec![descriptor])
    }

    async fn reuse_or_pin_chunk(
        &self,
        mut descriptor: IndexedArtifactDescriptor,
        compressed_bytes: &[u8],
    ) -> Result<IndexedArtifactDescriptor> {
        let hash = fixed_bytes(&descriptor.sha256);
        let cid = self
            .reuse_or_pin_indexed_artifact(
                IndexedArtifactPublicationKind::Chunk,
                descriptor.dataset_kind,
                &descriptor.scope,
                &descriptor.range,
                descriptor.byte_size,
                &hash,
                descriptor.encoding_version,
                compressed_bytes,
            )
            .await?;
        descriptor.cid = cid;
        Ok(descriptor)
    }

    async fn reuse_or_pin_indexed_artifact(
        &self,
        artifact_kind: IndexedArtifactPublicationKind,
        dataset_kind: IndexedDatasetKind,
        scope: &ChainScope,
        range: &IndexedArtifactRange,
        byte_size: u64,
        content_hash: &[u8; 32],
        format_version: u16,
        bytes: &[u8],
    ) -> Result<String> {
        if let Some(cid) = Audit::live_indexed_artifact_cid(
            self.store.pool(),
            artifact_kind,
            dataset_kind,
            scope,
            range,
            byte_size,
            content_hash,
            format_version,
        )
        .await
        .wrap_err("lookup reusable indexed artifact CID")?
        {
            return Ok(cid.to_string());
        }

        let cid = match artifact_kind {
            IndexedArtifactPublicationKind::Chunk => {
                pin_indexed_chunk(self.ipfs_client.as_ref(), bytes)
                    .await
                    .wrap_err("pin indexed artifact chunk")
            }
            IndexedArtifactPublicationKind::Catalog => {
                pin_manifest(self.ipfs_client.as_ref(), bytes)
                    .await
                    .wrap_err("pin indexed artifact catalog")
            }
        }?;
        Ok(cid.to_string())
    }

    async fn record_chunk_descriptor(&self, descriptor: &IndexedArtifactDescriptor) -> Result<()> {
        let cid = descriptor
            .cid
            .parse()
            .wrap_err_with(|| format!("parse indexed chunk CID {}", descriptor.cid))?;
        let hash = fixed_bytes(&descriptor.sha256);
        let mut tx = self
            .store
            .begin()
            .await
            .wrap_err("begin indexed chunk audit transaction")?;
        Audit::record_indexed_artifact_pin(
            &mut tx,
            IndexedArtifactPublicationKind::Chunk,
            descriptor.dataset_kind,
            &descriptor.scope,
            &descriptor.range,
            &cid,
            descriptor.byte_size,
            &hash,
            descriptor.encoding_version,
        )
        .await
        .wrap_err("record indexed chunk pin")?;
        tx.commit().await.wrap_err("commit indexed chunk audit")?;
        Ok(())
    }

    async fn latest_indexed_heights(
        &self,
        chain: &ChainIndexedChainConfig,
    ) -> Result<Vec<LatestIndexedHeight>> {
        let mut latest = Vec::new();
        for dataset in &chain.datasets {
            let Some(progress) = self
                .store
                .chain_indexing_progress(
                    EVM_CHAIN_TYPE,
                    chain.chain_id,
                    chain.railgun_contract,
                    store_dataset_kind(*dataset),
                )
                .await
                .wrap_err("read latest indexed height")?
            else {
                continue;
            };
            latest.push(LatestIndexedHeight {
                dataset_kind: *dataset,
                block_number: progress.indexed_through_block,
                block_hash: FixedBytes::from(progress.indexed_through_block_hash),
            });
        }
        Ok(latest)
    }

    async fn next_ipns_sequence(&mut self, now: SystemTime) -> Result<u64> {
        if !self.ipns_sequence_loaded {
            self.last_ipns_sequence = self
                .store
                .last_chain_indexed_ipns_sequence()
                .await
                .wrap_err("load persisted chain-indexed IPNS sequence")?;
            self.ipns_sequence_loaded = true;
        }
        let sequence = unix_millis(now)?;
        let sequence = self.last_ipns_sequence.map_or(sequence, |last_sequence| {
            sequence.max(last_sequence.saturating_add(1))
        });
        self.store
            .record_chain_indexed_ipns_sequence(sequence)
            .await
            .wrap_err("persist chain-indexed IPNS sequence")?;
        self.last_ipns_sequence = Some(sequence);
        Ok(sequence)
    }
}

fn build_provider(rpc_url: &str) -> Result<RootProvider> {
    let url = url::Url::parse(rpc_url).wrap_err("parse RPC URL")?;
    Ok(ProviderBuilder::new().connect_http(url).root().clone())
}

fn catalog_descriptor(
    catalog: &IndexedArtifactCatalog,
    cid: &str,
    byte_size: u64,
    content_hash: &[u8; 32],
) -> Result<IndexedArtifactDescriptor> {
    let mut chunks = catalog.chunks.clone();
    chunks.sort_by(|left, right| {
        left.range
            .start
            .cmp(&right.range.start)
            .then_with(|| left.range.end.cmp(&right.range.end))
            .then_with(|| left.cid.cmp(&right.cid))
    });
    let first = chunks
        .first()
        .ok_or_else(|| eyre!("indexed artifact catalog cannot be empty"))?;
    let last = chunks.last().expect("non-empty chunks checked above");
    if chunks
        .iter()
        .any(|chunk| chunk.range.kind != first.range.kind || chunk.scope != catalog.scope)
    {
        return Err(eyre!(
            "indexed artifact catalog chunks have mixed scope or range kind"
        ));
    }
    let row_count = chunks.iter().try_fold(0_u64, |total, chunk| {
        total
            .checked_add(chunk.row_count)
            .ok_or_else(|| eyre!("indexed catalog row count overflow"))
    })?;
    let last_indexed_block = chunks
        .iter()
        .filter_map(|chunk| chunk.metadata.last_indexed_block)
        .max();
    let start_block = chunks
        .iter()
        .filter_map(|chunk| chunk.metadata.start_block)
        .min();
    let end_block = chunks
        .iter()
        .filter_map(|chunk| chunk.metadata.end_block)
        .max();

    Ok(IndexedArtifactDescriptor {
        dataset_kind: catalog.dataset_kind,
        scope: catalog.scope.clone(),
        range: IndexedArtifactRange {
            kind: first.range.kind,
            start: first.range.start,
            end: last.range.end,
        },
        row_count,
        cid: cid.to_string(),
        sha256: FixedBytes::from(*content_hash),
        byte_size,
        encoding_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
        compression: CompressionAlgorithm::None,
        metadata: DatasetDescriptorMetadata {
            start_block,
            end_block,
            last_indexed_block,
            checkpoint_block: last_indexed_block,
            ..Default::default()
        },
    })
}

fn public_txid_chunk_row_limit(offset: u64, configured_limit: u64) -> u64 {
    let remaining_in_tree = TREE_LEAF_COUNT - (offset % TREE_LEAF_COUNT);
    configured_limit.min(remaining_in_tree)
}

fn latest_indexed_block(
    latest_indexed: &[LatestIndexedHeight],
    dataset_kind: IndexedDatasetKind,
) -> Option<u64> {
    latest_indexed
        .iter()
        .find(|height| height.dataset_kind == dataset_kind)
        .map(|height| height.block_number)
}

fn public_txid_plan_items(
    scope: &ChainScope,
    rows: &[StoredPublicTxidRow],
) -> Result<Vec<ChunkPlanItem>> {
    rows.chunks(PUBLIC_TXID_PLANNING_ROW_UNIT)
        .map(|rows| {
            public_txid_chunk_plan_item(scope, rows, CompressionAlgorithm::Zstd)
                .wrap_err("plan public TXID artifact chunk unit")
        })
        .collect()
}

fn commitment_plan_items(
    scope: &ChainScope,
    rows: &[railgun_indexer_core::store::StoredCommitmentRow],
) -> Result<Vec<ChunkPlanItem>> {
    rows.chunks(COMMITMENT_PLANNING_ROW_UNIT)
        .map(|rows| {
            commitment_chunk_plan_item(scope, rows, CompressionAlgorithm::Zstd)
                .wrap_err("plan commitment artifact chunk unit")
        })
        .collect()
}

const fn store_dataset_kind(dataset: IndexedDatasetKind) -> StoreDatasetKind {
    match dataset {
        IndexedDatasetKind::WalletScan => StoreDatasetKind::WalletScan,
        IndexedDatasetKind::Commitments => StoreDatasetKind::Commitments,
        IndexedDatasetKind::MerkleCheckpoint => StoreDatasetKind::MerkleCheckpoint,
        IndexedDatasetKind::PublicTxid => StoreDatasetKind::PublicTxid,
    }
}

fn fixed_bytes(value: &FixedBytes<32>) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(value.as_slice());
    bytes
}

fn unix_millis(now: SystemTime) -> Result<u64> {
    let duration = now
        .duration_since(UNIX_EPOCH)
        .wrap_err("system clock is before unix epoch")?;
    duration
        .as_millis()
        .try_into()
        .wrap_err("unix millisecond timestamp overflow")
}

fn checked_interval(duration: Duration, field: &'static str) -> Result<Duration> {
    if duration.is_zero() {
        Err(eyre!("{field} must be greater than zero"))
    } else {
        Ok(duration)
    }
}

fn shutdown_requested(shutdown: &watch::Receiver<bool>) -> bool {
    *shutdown.borrow()
}

async fn shutdown_changed_or_requested(shutdown: &mut watch::Receiver<bool>) -> bool {
    shutdown.changed().await.is_err() || shutdown_requested(shutdown)
}

async fn sleep_or_shutdown(duration: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    if duration.is_zero() {
        return shutdown_requested(shutdown);
    }
    tokio::select! {
        () = tokio::time::sleep(duration) => shutdown_requested(shutdown),
        shutdown = shutdown_changed_or_requested(shutdown) => shutdown,
    }
}

fn format_report_chain(error: &eyre::Report) -> String {
    error
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

fn is_block_range_too_large(error: &eyre::Report) -> bool {
    error.chain().any(|source| {
        source
            .to_string()
            .to_ascii_lowercase()
            .contains("block range is too large")
    })
}

fn provider_error(source: TransportError) -> eyre::Report {
    eyre!(source).wrap_err("RPC provider request failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::Address;

    #[test]
    fn catalog_descriptor_summarizes_chunk_ranges_and_counts() -> Result<()> {
        let scope = ChainScope {
            chain_type: ChainType::Evm,
            chain_id: 1,
            railgun_contract: Address::from([0xbb; 20]),
        };
        let chunks = vec![
            chunk_descriptor(scope.clone(), 10, 19, 10, 110),
            chunk_descriptor(scope.clone(), 0, 9, 10, 100),
        ];
        let catalog = IndexedArtifactCatalog::new(IndexedDatasetKind::PublicTxid, scope, chunks);

        let descriptor = catalog_descriptor(&catalog, "bafytestcatalog", 512, &[7_u8; 32])?;

        assert_eq!(descriptor.dataset_kind, IndexedDatasetKind::PublicTxid);
        assert_eq!(descriptor.range.start, 0);
        assert_eq!(descriptor.range.end, 19);
        assert_eq!(descriptor.row_count, 20);
        assert_eq!(descriptor.byte_size, 512);
        assert_eq!(descriptor.sha256, FixedBytes::from([7_u8; 32]));
        assert_eq!(descriptor.metadata.start_block, Some(100));
        assert_eq!(descriptor.metadata.end_block, Some(110));
        assert_eq!(descriptor.metadata.last_indexed_block, Some(110));
        Ok(())
    }

    #[test]
    fn latest_indexed_block_returns_dataset_watermark() {
        let latest_indexed = vec![
            LatestIndexedHeight {
                dataset_kind: IndexedDatasetKind::WalletScan,
                block_number: 100,
                block_hash: FixedBytes::from([1_u8; 32]),
            },
            LatestIndexedHeight {
                dataset_kind: IndexedDatasetKind::PublicTxid,
                block_number: 200,
                block_hash: FixedBytes::from([2_u8; 32]),
            },
        ];

        assert_eq!(
            latest_indexed_block(&latest_indexed, IndexedDatasetKind::PublicTxid),
            Some(200)
        );
        assert_eq!(
            latest_indexed_block(&latest_indexed, IndexedDatasetKind::Commitments),
            None
        );
    }

    fn chunk_descriptor(
        scope: ChainScope,
        start: u64,
        end: u64,
        row_count: u64,
        block: u64,
    ) -> IndexedArtifactDescriptor {
        IndexedArtifactDescriptor {
            dataset_kind: IndexedDatasetKind::PublicTxid,
            scope,
            range: IndexedArtifactRange {
                kind: railgun_indexer_core::manifest::IndexedArtifactRangeKind::TxidIndex,
                start,
                end,
            },
            row_count,
            cid: format!("bafychunk{start}"),
            sha256: FixedBytes::from([1_u8; 32]),
            byte_size: 128,
            encoding_version: 1,
            compression: CompressionAlgorithm::Zstd,
            metadata: DatasetDescriptorMetadata {
                start_block: Some(block),
                end_block: Some(block),
                last_indexed_block: Some(block),
                ..Default::default()
            },
        }
    }
}
