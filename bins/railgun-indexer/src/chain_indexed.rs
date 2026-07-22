use std::collections::BTreeSet;
use std::future::Future;
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

use railgun_indexer_core::audit::{
    Audit, ChainCanonicalityCoordinator, ChainCanonicalityLease, IndexedArtifactPublicationKind,
    PinLifecycleCoordinator, PinOwnershipLease,
};
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
    IndexedArtifactRange, IndexedArtifactRangeKind, IndexedDatasetKind, LatestIndexedHeight,
    PublisherIdentity, content_hash,
};
use railgun_indexer_core::merkle_checkpoint::{
    MerkleCheckpointArtifact, prepare_merkle_checkpoint_artifact,
};
use railgun_indexer_core::public_txid::{
    prepare_public_txid_chunk, public_txid_checkpoint_root, public_txid_chunk_plan_item,
};
use railgun_indexer_core::publish::ipfs::{IpfsClient, IpfsError, pin_indexed_chunk, pin_manifest};
use railgun_indexer_core::publish::ipns::IpnsPublisher;
use railgun_indexer_core::store::{
    IndexedDatasetKind as StoreDatasetKind, Store, StoredIndexedBlockHeader, StoredPublicTxidRow,
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
    canonicality: ChainCanonicalityCoordinator,
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
        let canonicality = canonicality.clone();
        tasks.spawn(async move {
            run_chain_indexing_loop(config, store, chain, canonicality, shutdown).await
        });
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
    canonicality: ChainCanonicalityCoordinator,
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
            &canonicality,
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
    pin_lifecycle: PinLifecycleCoordinator,
    canonicality: ChainCanonicalityCoordinator,
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
        pin_lifecycle,
        canonicality,
        last_ipns_sequence: None,
        ipns_sequence_loaded: false,
        shutdown: shutdown.clone(),
    };
    match scheduler.reconcile_pending_manifest().await {
        Ok(_) => {}
        Err(error) => {
            warn!(
                error = %format_report_chain(&error),
                "chain-indexed pending publication reconciliation failed"
            );
        }
    }
    if shutdown_requested(&shutdown) {
        return Ok(());
    }
    if sleep_or_shutdown(interval, &mut shutdown).await {
        return Ok(());
    }

    loop {
        match scheduler.publish_cycle(SystemTime::now()).await {
            Ok(()) => {}
            Err(error) => {
                warn!(
                    error = %format_report_chain(&error),
                    "chain-indexed artifact publication cycle failed"
                );
            }
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
    canonicality: &ChainCanonicalityCoordinator,
    batch_span: u64,
    provider_mode: ChainIndexProviderMode,
) -> Result<ChainIndexStep> {
    let safe_head = runtime
        .provider
        .get_block_number()
        .await
        .wrap_err("fetch chain head")?
        .saturating_sub(config.chain_indexed.safe_confirmations);
    let from_block = resume_block_after_reorg(store, config, runtime, canonicality).await?;
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
    canonicality: &ChainCanonicalityCoordinator,
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

        let _canonicality = canonicality.reorg_lease().await;
        let Some(progress) = store
            .chain_indexing_progress(
                EVM_CHAIN_TYPE,
                runtime.chain.chain_id,
                runtime.chain.railgun_contract,
                StoreDatasetKind::WalletScan,
            )
            .await
            .wrap_err("re-read chain-indexed progress before reorg rewind")?
        else {
            continue;
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
    pin_lifecycle: PinLifecycleCoordinator,
    canonicality: ChainCanonicalityCoordinator,
    last_ipns_sequence: Option<u64>,
    ipns_sequence_loaded: bool,
    shutdown: watch::Receiver<bool>,
}

struct PublishedCatalog {
    descriptor: IndexedArtifactDescriptor,
    artifact_cids: Vec<String>,
}

struct PublishedChainEntry {
    entry: IndexedArtifactChainEntry,
    artifact_cids: Vec<String>,
}

fn extend_published_catalogs(
    descriptors: &mut Vec<IndexedArtifactDescriptor>,
    artifact_cids: &mut BTreeSet<String>,
    published: Vec<PublishedCatalog>,
) {
    for catalog in published {
        descriptors.push(catalog.descriptor);
        artifact_cids.extend(catalog.artifact_cids);
    }
}

impl ChainIndexedPublicationScheduler {
    fn ensure_publication_running(&self) -> Result<()> {
        if shutdown_requested(&self.shutdown) {
            Err(eyre!(
                "publication stopped at a cooperative shutdown boundary"
            ))
        } else {
            Ok(())
        }
    }

    fn acquire_pin_ownership(&self) -> Result<PinOwnershipLease> {
        self.ensure_publication_running()?;
        self.pin_lifecycle
            .try_acquire_pin_ownership()
            .ok_or_else(|| eyre!("pin ownership admission is closed for shutdown"))
    }

    async fn publish_cycle(&mut self, now: SystemTime) -> Result<()> {
        self.ensure_publication_running()?;
        if self.reconcile_pending_manifest().await? {
            return Ok(());
        }
        let configured_chains = self.config.chain_indexed.chains.clone();
        let published_chains = join_all(
            configured_chains
                .iter()
                .map(|chain| self.publish_chain_entry(chain)),
        )
        .await;

        let mut chains = Vec::new();
        let mut artifact_cids = BTreeSet::new();
        for (chain, result) in configured_chains.iter().zip(published_chains) {
            self.ensure_publication_running()?;
            match result {
                Ok(Some(published)) => {
                    chains.push(published.entry);
                    artifact_cids.extend(published.artifact_cids);
                }
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

        let canonicality_guard = self.canonicality.publication_lease().await;
        self.validate_combined_manifest_snapshot(&configured_chains, &chains)
            .await?;

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
        let manifest_json =
            serde_json::to_string(&manifest).wrap_err("serialize chain-indexed manifest")?;
        let manifest_bytes = manifest_json.as_bytes();
        let byte_size = u64::try_from(manifest_bytes.len())
            .wrap_err("chain-indexed manifest byte size overflow")?;
        let manifest_hash = content_hash(manifest_bytes);
        let artifact_cids = artifact_cids.into_iter().collect::<Vec<_>>();
        let pin_lifecycle_guard = self.pin_lifecycle.lock().await;
        self.ensure_indexed_artifacts_available(&artifact_cids)
            .await?;
        let ownership = self.acquire_pin_ownership()?;
        let manifest_cid = match pin_manifest(self.ipfs_client.as_ref(), manifest_bytes).await {
            Ok(cid) => cid,
            Err(error) => {
                ownership.settle();
                return Err(error).wrap_err("pin chain-indexed manifest");
            }
        };

        let audit_result = async {
            let mut tx = self
                .store
                .begin()
                .await
                .wrap_err("begin chain-indexed manifest audit transaction")?;
            Audit::record_indexed_manifest_pin(
                &mut tx,
                &manifest_cid,
                &artifact_cids,
                sequence,
                byte_size,
                &manifest_hash,
                INDEXED_ARTIFACT_MANIFEST_FORMAT_VERSION,
                &manifest_json,
            )
            .await
            .wrap_err("record chain-indexed manifest pin")?;
            tx.commit()
                .await
                .wrap_err("commit chain-indexed manifest pin audit")
        }
        .await;
        if let Err(error) = audit_result {
            self.cleanup_uncommitted_pin_while_locked(
                &manifest_cid,
                "chain-indexed manifest",
                ownership,
            )
            .await;
            return Err(error);
        }
        ownership.settle();
        drop(pin_lifecycle_guard);
        self.ensure_publication_running()?;

        let manifest_cid_string = manifest_cid.to_string();
        self.ipns_publisher
            .publish_manifest_cid_with_lease(
                &manifest_cid_string,
                sequence,
                canonicality_guard.clone(),
            )
            .await
            .wrap_err("publish chain-indexed manifest CID to IPNS")?;
        self.ensure_publication_running()?;
        let mut tx = self
            .store
            .begin()
            .await
            .wrap_err("begin chain-indexed manifest IPNS audit transaction")?;
        Audit::record_indexed_manifest_ipns_publication(&mut tx, &manifest_cid, sequence)
            .await
            .wrap_err("record chain-indexed manifest IPNS publication")?;
        tx.commit()
            .await
            .wrap_err("commit chain-indexed manifest IPNS audit")?;
        drop(canonicality_guard);

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

    async fn reconcile_pending_manifest(&mut self) -> Result<bool> {
        let ipns_publisher = self.ipns_publisher.clone();
        self.reconcile_pending_manifest_with(move |cid, sequence, canonicality_lease| async move {
            ipns_publisher
                .publish_manifest_cid_with_lease(&cid, sequence, canonicality_lease)
                .await
                .wrap_err("reconcile pending chain-indexed manifest IPNS publication")?;
            Ok(())
        })
        .await
    }

    async fn reconcile_pending_manifest_with<PublishIpns, PublishFuture>(
        &mut self,
        publish_ipns: PublishIpns,
    ) -> Result<bool>
    where
        PublishIpns: FnOnce(String, u64, ChainCanonicalityLease) -> PublishFuture,
        PublishFuture: Future<Output = Result<()>>,
    {
        self.ensure_publication_running()?;
        let Some(pending) = Audit::pending_indexed_manifest_publication(
            self.store.pool(),
            &self.signing_key.verifying_key().to_bytes(),
        )
        .await
        .wrap_err("load pending chain-indexed manifest")?
        else {
            return Ok(false);
        };
        let configured_chains = self.config.chain_indexed.chains.clone();
        let canonicality_guard = self.canonicality.publication_lease().await;
        self.validate_combined_manifest_snapshot(&configured_chains, &pending.manifest.chains)
            .await
            .wrap_err("revalidate pending chain-indexed manifest watermarks")?;
        let pin_lifecycle_guard = self.pin_lifecycle.lock().await;
        self.ensure_indexed_artifacts_available(&pending.artifact_cids)
            .await?;
        let manifest_cid = pending
            .cid
            .parse::<cid::Cid>()
            .wrap_err("parse pending chain-indexed manifest CID")?;
        let ownership = self.acquire_pin_ownership()?;
        let returned_cid =
            match pin_manifest(self.ipfs_client.as_ref(), pending.manifest_json.as_bytes()).await {
                Ok(cid) => cid,
                Err(error) => {
                    ownership.settle();
                    return Err(error).wrap_err("re-pin pending chain-indexed manifest");
                }
            };
        if returned_cid != manifest_cid {
            self.cleanup_uncommitted_pin_while_locked(
                &returned_cid,
                "mismatched chain-indexed reconciliation manifest",
                ownership,
            )
            .await;
            return Err(IpfsError::CidMismatch {
                service: self.ipfs_client.service_name().to_string(),
                expected: Box::new(manifest_cid),
                returned: Box::new(returned_cid),
            }
            .into());
        }
        ownership.settle();
        drop(pin_lifecycle_guard);
        self.ensure_publication_running()?;
        publish_ipns(
            pending.cid.clone(),
            pending.sequence,
            canonicality_guard.clone(),
        )
        .await?;
        self.ensure_publication_running()?;
        let mut tx = self
            .store
            .begin()
            .await
            .wrap_err("begin pending chain-indexed manifest activation")?;
        Audit::record_indexed_manifest_ipns_publication(&mut tx, &manifest_cid, pending.sequence)
            .await
            .wrap_err("activate reconciled chain-indexed manifest")?;
        tx.commit()
            .await
            .wrap_err("commit reconciled chain-indexed manifest activation")?;
        drop(canonicality_guard);
        self.last_ipns_sequence = Some(pending.sequence);
        self.ipns_sequence_loaded = true;
        Ok(true)
    }

    async fn validate_combined_manifest_snapshot(
        &self,
        configured_chains: &[ChainIndexedChainConfig],
        entries: &[IndexedArtifactChainEntry],
    ) -> Result<()> {
        for entry in entries {
            let chain = configured_chains
                .iter()
                .find(|chain| {
                    chain.chain_id == entry.scope.chain_id
                        && chain.railgun_contract == entry.scope.railgun_contract
                })
                .ok_or_else(|| {
                    eyre!(
                        "combined indexed manifest contains unconfigured chain {} ({})",
                        entry.scope.chain_id,
                        entry.scope.railgun_contract
                    )
                })?;
            self.validate_chain_snapshot(chain, &entry.latest_indexed)
                .await?;
        }
        Ok(())
    }

    async fn publish_chain_entry(
        &self,
        chain: &ChainIndexedChainConfig,
    ) -> Result<Option<PublishedChainEntry>> {
        let scope = ChainScope {
            chain_type: ChainType::Evm,
            chain_id: chain.chain_id,
            railgun_contract: chain.railgun_contract,
        };
        let latest_indexed = self.latest_indexed_heights(chain).await?;
        let mut catalogs = Vec::new();
        let mut artifact_cids = BTreeSet::new();
        for dataset in &chain.datasets {
            match dataset {
                IndexedDatasetKind::PublicTxid => {
                    if let Some(max_block) = latest_indexed_block(&latest_indexed, *dataset) {
                        let published = self
                            .publish_public_txid_catalog(chain, &scope, max_block)
                            .await?;
                        extend_published_catalogs(&mut catalogs, &mut artifact_cids, published);
                    }
                }
                IndexedDatasetKind::WalletScan => {
                    if let Some(max_block) = latest_indexed_block(&latest_indexed, *dataset) {
                        let published = self
                            .publish_wallet_scan_catalog(chain, &scope, max_block)
                            .await?;
                        extend_published_catalogs(&mut catalogs, &mut artifact_cids, published);
                    }
                }
                IndexedDatasetKind::Commitments => {
                    if let Some(max_block) = latest_indexed_block(&latest_indexed, *dataset) {
                        let published = self
                            .publish_commitment_catalog(chain, &scope, max_block)
                            .await?;
                        extend_published_catalogs(&mut catalogs, &mut artifact_cids, published);
                    }
                }
                IndexedDatasetKind::MerkleCheckpoint => {
                    if let Some(max_block) = latest_indexed_block(&latest_indexed, *dataset) {
                        let published = self
                            .publish_merkle_checkpoint_catalog(chain, &scope, max_block)
                            .await?;
                        extend_published_catalogs(&mut catalogs, &mut artifact_cids, published);
                    }
                }
            }
        }
        self.validate_chain_snapshot(chain, &latest_indexed).await?;
        if catalogs.is_empty() {
            return Ok(None);
        }
        Ok(Some(PublishedChainEntry {
            entry: IndexedArtifactChainEntry {
                scope,
                latest_indexed,
                catalogs,
            },
            artifact_cids: artifact_cids.into_iter().collect(),
        }))
    }

    async fn ensure_indexed_artifacts_available(&self, artifact_cids: &[String]) -> Result<()> {
        for cid in artifact_cids {
            let parsed = cid
                .parse::<cid::Cid>()
                .wrap_err_with(|| format!("parse indexed manifest artifact CID {cid}"))?;
            if !self
                .ipfs_client
                .contains(&parsed)
                .await
                .wrap_err_with(|| format!("check indexed manifest artifact CID {cid}"))?
            {
                return Err(eyre!(
                    "indexed manifest artifact CID {cid} is unavailable before manifest publication"
                ));
            }
        }
        Ok(())
    }

    async fn validate_chain_snapshot(
        &self,
        chain: &ChainIndexedChainConfig,
        latest_indexed: &[LatestIndexedHeight],
    ) -> Result<()> {
        for height in latest_indexed {
            let header = self
                .store
                .indexed_block_header(EVM_CHAIN_TYPE, chain.chain_id, height.block_number)
                .await
                .wrap_err("revalidate chain-indexed publication watermark")?;
            validate_publication_watermark(height, header.as_ref())?;
        }
        Ok(())
    }

    async fn publish_public_txid_catalog(
        &self,
        chain: &ChainIndexedChainConfig,
        scope: &ChainScope,
        max_block: u64,
    ) -> Result<Vec<PublishedCatalog>> {
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
                offset = published.descriptor.range.end.saturating_add(1);
                chunks.push(published.descriptor);
            }
            if rows.len() < row_limit as usize {
                break;
            }
        }
        self.publish_catalogs(
            scope,
            IndexedDatasetKind::PublicTxid,
            chunks,
            CatalogCoverage::DerivedFromChunks,
        )
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
    ) -> Result<Vec<PublishedCatalog>> {
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
            chunks.push(published.descriptor);
        }
        self.publish_catalogs(
            scope,
            IndexedDatasetKind::WalletScan,
            chunks,
            CatalogCoverage::ExplicitBlockRange {
                start_block: chain.start_block,
                indexed_through_block: max_block,
            },
        )
        .await
    }

    async fn publish_commitment_catalog(
        &self,
        chain: &ChainIndexedChainConfig,
        scope: &ChainScope,
        max_block: u64,
    ) -> Result<Vec<PublishedCatalog>> {
        let summaries = self
            .store
            .commitment_tree_summaries(
                EVM_CHAIN_TYPE,
                chain.chain_id,
                chain.railgun_contract,
                Some(max_block),
            )
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
                    Some(max_block),
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
                        Some(max_block),
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
                start_position = published.descriptor.range.end.saturating_add(1);
                chunks.push(published.descriptor);
            }
        }
        self.publish_catalogs(
            scope,
            IndexedDatasetKind::Commitments,
            chunks,
            CatalogCoverage::DerivedFromChunks,
        )
        .await
    }

    async fn publish_merkle_checkpoint_catalog(
        &self,
        chain: &ChainIndexedChainConfig,
        scope: &ChainScope,
        max_block: u64,
    ) -> Result<Vec<PublishedCatalog>> {
        let summaries = self
            .store
            .commitment_tree_summaries(
                EVM_CHAIN_TYPE,
                chain.chain_id,
                chain.railgun_contract,
                Some(max_block),
            )
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
                    Some(max_block),
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
            chunks.push(published.descriptor);
        }
        self.publish_catalogs(
            scope,
            IndexedDatasetKind::MerkleCheckpoint,
            chunks,
            CatalogCoverage::DerivedFromChunks,
        )
        .await
    }

    async fn publish_catalogs(
        &self,
        scope: &ChainScope,
        dataset_kind: IndexedDatasetKind,
        chunks: Vec<IndexedArtifactDescriptor>,
        coverage: CatalogCoverage,
    ) -> Result<Vec<PublishedCatalog>> {
        if chunks.is_empty() && matches!(coverage, CatalogCoverage::DerivedFromChunks) {
            return Ok(Vec::new());
        }
        let (catalog, catalog_bytes, catalog_hash, mut descriptor) =
            prepare_catalog_artifact(scope, dataset_kind, chunks, coverage)?;
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
        info!(
            chain_id = scope.chain_id,
            railgun_contract = %scope.railgun_contract,
            dataset = ?dataset_kind,
            cid = %descriptor.cid,
            chunk_count,
            total_chunk_byte_size,
            max_chunk_byte_size,
            byte_size = descriptor.byte_size,
            sha256 = %descriptor.sha256,
            "published indexed artifact catalog"
        );
        let mut artifact_cids = catalog
            .chunks
            .iter()
            .map(|chunk| chunk.cid.clone())
            .collect::<Vec<_>>();
        artifact_cids.push(descriptor.cid.clone());
        Ok(vec![PublishedCatalog {
            descriptor,
            artifact_cids,
        }])
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
        self.ensure_publication_running()?;
        let _pin_lifecycle = self.pin_lifecycle.lock().await;
        let reusable = Audit::live_indexed_artifact_cid(
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
        .wrap_err("lookup reusable indexed artifact CID")?;
        let (cid, ownership) = if let Some(cid) = reusable {
            if self
                .ipfs_client
                .contains(&cid)
                .await
                .wrap_err("check reusable indexed artifact availability")?
            {
                (cid, None)
            } else {
                warn!(%cid, "reusable indexed artifact CID is missing; repinning");
                let ownership = self.acquire_pin_ownership()?;
                match self.pin_indexed_artifact(artifact_kind, bytes).await {
                    Ok(returned) => (returned, Some(ownership)),
                    Err(error) => {
                        ownership.settle();
                        return Err(error);
                    }
                }
            }
        } else {
            let ownership = self.acquire_pin_ownership()?;
            match self.pin_indexed_artifact(artifact_kind, bytes).await {
                Ok(returned) => (returned, Some(ownership)),
                Err(error) => {
                    ownership.settle();
                    return Err(error);
                }
            }
        };
        let audit_result = async {
            let mut tx = self
                .store
                .begin()
                .await
                .wrap_err("begin indexed artifact audit transaction")?;
            Audit::record_indexed_artifact_pin(
                &mut tx,
                artifact_kind,
                dataset_kind,
                scope,
                range,
                &cid,
                byte_size,
                content_hash,
                format_version,
            )
            .await
            .wrap_err("record indexed artifact pin")?;
            tx.commit().await.wrap_err("commit indexed artifact audit")
        }
        .await;
        if let Err(error) = audit_result {
            if let Some(ownership) = ownership {
                self.cleanup_uncommitted_pin_while_locked(&cid, "indexed artifact", ownership)
                    .await;
            }
            return Err(error);
        }
        if let Some(ownership) = ownership {
            ownership.settle();
        }
        self.ensure_publication_running()?;
        Ok(cid.to_string())
    }

    async fn pin_indexed_artifact(
        &self,
        artifact_kind: IndexedArtifactPublicationKind,
        bytes: &[u8],
    ) -> Result<cid::Cid> {
        match artifact_kind {
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
        }
    }

    async fn cleanup_uncommitted_pin_while_locked(
        &self,
        cid: &cid::Cid,
        label: &'static str,
        ownership: PinOwnershipLease,
    ) {
        match Audit::publication_cid_is_referenced(self.store.pool(), cid).await {
            Ok(true) => {
                warn!(%cid, label, "preserving uncommitted pin because it is already referenced");
                ownership.settle();
            }
            Ok(false) => match self.ipfs_client.unpin(cid).await {
                Ok(()) => ownership.settle(),
                Err(error) => {
                    warn!(%cid, label, %error, "failed to clean up uncommitted provider pin");
                    if Audit::record_pin_cleanup_debt(
                        self.store.pool(),
                        cid,
                        self.ipfs_client.service_name(),
                        &error.to_string(),
                    )
                    .await
                    .is_ok()
                    {
                        ownership.settle();
                    }
                }
            },
            Err(error) => {
                warn!(%cid, label, %error, "preserving uncommitted pin because reference recheck failed");
                if Audit::record_pin_cleanup_debt(
                    self.store.pool(),
                    cid,
                    self.ipfs_client.service_name(),
                    &error.to_string(),
                )
                .await
                .is_ok()
                {
                    ownership.settle();
                }
            }
        }
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

fn validate_publication_watermark(
    height: &LatestIndexedHeight,
    header: Option<&StoredIndexedBlockHeader>,
) -> Result<()> {
    let header = header.ok_or_else(|| {
        eyre!(
            "chain-indexed publication watermark {} for {:?} was rewound during publication",
            height.block_number,
            height.dataset_kind
        )
    })?;
    if header.block_hash.as_slice() != height.block_hash.as_slice() {
        return Err(eyre!(
            "chain-indexed publication watermark {} for {:?} changed during publication",
            height.block_number,
            height.dataset_kind
        ));
    }
    Ok(())
}

fn build_provider(rpc_url: &str) -> Result<RootProvider> {
    let url = url::Url::parse(rpc_url).wrap_err("parse RPC URL")?;
    Ok(ProviderBuilder::new().connect_http(url).root().clone())
}

#[derive(Debug, Clone, Copy)]
enum CatalogCoverage {
    DerivedFromChunks,
    ExplicitBlockRange {
        start_block: u64,
        indexed_through_block: u64,
    },
}

fn prepare_catalog_artifact(
    scope: &ChainScope,
    dataset_kind: IndexedDatasetKind,
    chunks: Vec<IndexedArtifactDescriptor>,
    coverage: CatalogCoverage,
) -> Result<(
    IndexedArtifactCatalog,
    Vec<u8>,
    [u8; 32],
    IndexedArtifactDescriptor,
)> {
    let catalog = IndexedArtifactCatalog::new(dataset_kind, scope.clone(), chunks);
    let catalog_bytes = catalog
        .deterministic_body_bytes()
        .wrap_err("serialize indexed artifact catalog")?;
    let byte_size = u64::try_from(catalog_bytes.len())
        .wrap_err("indexed artifact catalog byte size overflow")?;
    let catalog_hash = content_hash(&catalog_bytes);
    let descriptor = catalog_descriptor(&catalog, "", byte_size, &catalog_hash, coverage)?;
    Ok((catalog, catalog_bytes, catalog_hash, descriptor))
}

fn catalog_descriptor(
    catalog: &IndexedArtifactCatalog,
    cid: &str,
    byte_size: u64,
    content_hash: &[u8; 32],
    coverage: CatalogCoverage,
) -> Result<IndexedArtifactDescriptor> {
    let mut chunks = catalog.chunks.clone();
    chunks.sort_by(|left, right| {
        left.range
            .start
            .cmp(&right.range.start)
            .then_with(|| left.range.end.cmp(&right.range.end))
            .then_with(|| left.cid.cmp(&right.cid))
    });
    if chunks
        .iter()
        .any(|chunk| chunk.dataset_kind != catalog.dataset_kind || chunk.scope != catalog.scope)
    {
        return Err(eyre!(
            "indexed artifact catalog chunks have mixed dataset or scope"
        ));
    }
    let range = match coverage {
        CatalogCoverage::DerivedFromChunks => {
            let first = chunks
                .first()
                .ok_or_else(|| eyre!("indexed artifact catalog cannot be empty"))?;
            let last = chunks.last().expect("non-empty chunks checked above");
            if chunks
                .iter()
                .any(|chunk| chunk.range.kind != first.range.kind)
            {
                return Err(eyre!(
                    "indexed artifact catalog chunks have mixed range kind"
                ));
            }
            IndexedArtifactRange {
                kind: first.range.kind,
                start: first.range.start,
                end: last.range.end,
            }
        }
        CatalogCoverage::ExplicitBlockRange {
            start_block,
            indexed_through_block,
        } => {
            if catalog.dataset_kind != IndexedDatasetKind::WalletScan {
                return Err(eyre!(
                    "explicit block coverage is only supported for wallet-scan catalogs"
                ));
            }
            if start_block > indexed_through_block {
                return Err(eyre!(
                    "indexed artifact catalog coverage start {start_block} exceeds indexed-through block {indexed_through_block}"
                ));
            }
            if chunks.iter().any(|chunk| {
                chunk.range.kind != IndexedArtifactRangeKind::Block
                    || chunk.range.start < start_block
                    || chunk.range.end > indexed_through_block
            }) {
                return Err(eyre!(
                    "indexed artifact catalog chunk is outside explicit block coverage {start_block}-{indexed_through_block}"
                ));
            }
            IndexedArtifactRange {
                kind: IndexedArtifactRangeKind::Block,
                start: start_block,
                end: indexed_through_block,
            }
        }
    };
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
    let (start_block, end_block, last_indexed_block, checkpoint_block) = match coverage {
        CatalogCoverage::DerivedFromChunks => (
            start_block,
            end_block,
            last_indexed_block,
            last_indexed_block,
        ),
        CatalogCoverage::ExplicitBlockRange {
            start_block,
            indexed_through_block,
        } => (
            Some(start_block),
            Some(indexed_through_block),
            Some(indexed_through_block),
            Some(indexed_through_block),
        ),
    };

    Ok(IndexedArtifactDescriptor {
        dataset_kind: catalog.dataset_kind,
        scope: catalog.scope.clone(),
        range,
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
            checkpoint_block,
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

const fn fixed_bytes(value: &FixedBytes<32>) -> [u8; 32] {
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
    use async_trait::async_trait;
    use cid::Cid;
    use railgun_indexer_core::publish::ipfs::raw_block_cid;
    use railgun_indexer_core::publish::ipns::IpnsPublisherConfig;
    use railgun_indexer_core::store::run_migrations;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use testcontainers_modules::postgres::Postgres;
    use testcontainers_modules::testcontainers::ContainerAsync;
    use testcontainers_modules::testcontainers::runners::AsyncRunner;

    #[tokio::test]
    #[ignore = "requires Docker PostgreSQL"]
    async fn pending_reconciliation_rejects_rotated_signer_before_provider_or_ipns() -> Result<()> {
        let (_postgres, store) = reconciliation_store().await?;
        let old_signing_key = SigningKey::from_bytes(&[71; 32]);
        let current_signing_key = SigningKey::from_bytes(&[72; 32]);
        let (manifest_cid, _) =
            record_pending_indexed_manifest(&store, &old_signing_key, 11, None).await?;
        let ipfs = Arc::new(ReconciliationIpfs::default());
        let mut scheduler =
            reconciliation_scheduler(store.clone(), ipfs.clone(), current_signing_key)?;
        let ipns_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&ipns_calls);

        let error = scheduler
            .reconcile_pending_manifest_with(move |_, _, _| async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await
            .expect_err("current signer must reject a pending manifest signed by the old key");

        assert!(
            format_report_chain(&error).contains("publisher public key mismatch"),
            "unexpected reconciliation error: {error:?}"
        );
        assert_eq!(ipfs.pin_count(), 0);
        assert_eq!(ipfs.unpin_count(), 0);
        assert_eq!(ipns_calls.load(Ordering::SeqCst), 0);
        assert!(indexed_manifest_is_pending(store.pool(), &manifest_cid, 11).await?);
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires Docker PostgreSQL"]
    async fn pending_reconciliation_cleans_unreferenced_provider_cid_mismatch_without_ipns()
    -> Result<()> {
        let (_postgres, store) = reconciliation_store().await?;
        let signing_key = SigningKey::from_bytes(&[73; 32]);
        let (manifest_cid, manifest_json) =
            record_pending_indexed_manifest(&store, &signing_key, 12, None).await?;
        let returned_cid = raw_block_cid(b"provider returned a different packaged CID")?;
        let ipfs = Arc::new(ReconciliationIpfs::returning(returned_cid));
        let mut scheduler = reconciliation_scheduler(store.clone(), ipfs.clone(), signing_key)?;
        let ipns_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&ipns_calls);

        let error = scheduler
            .reconcile_pending_manifest_with(move |_, _, _| async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await
            .expect_err("provider CID mismatch must fail closed");

        assert!(matches!(
            error.downcast_ref::<IpfsError>(),
            Some(IpfsError::CidMismatch {
                expected,
                returned,
                ..
            }) if expected.as_ref() == &manifest_cid && returned.as_ref() == &returned_cid
        ));
        assert_eq!(ipfs.pinned_bytes(), vec![manifest_json.into_bytes()]);
        assert_eq!(ipfs.unpin_count(), 1);
        assert_eq!(ipns_calls.load(Ordering::SeqCst), 0);
        assert!(indexed_manifest_is_pending(store.pool(), &manifest_cid, 12).await?);
        assert_eq!(scheduler.pin_lifecycle.active_pin_owners(), 0);
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires Docker PostgreSQL"]
    async fn pending_reconciliation_preserves_referenced_mismatching_provider_cid() -> Result<()> {
        let (_postgres, store) = reconciliation_store().await?;
        let signing_key = SigningKey::from_bytes(&[77; 32]);
        let (manifest_cid, _) =
            record_pending_indexed_manifest(&store, &signing_key, 15, None).await?;
        let returned_cid = raw_block_cid(b"independently referenced returned CID")?;
        let scope = ChainScope {
            chain_type: ChainType::Evm,
            chain_id: 1,
            railgun_contract: Address::from([0xcc; 20]),
        };
        let range = IndexedArtifactRange {
            kind: IndexedArtifactRangeKind::Block,
            start: 1,
            end: 1,
        };
        let mut tx = store.begin().await?;
        Audit::record_indexed_artifact_pin(
            &mut tx,
            IndexedArtifactPublicationKind::Chunk,
            IndexedDatasetKind::WalletScan,
            &scope,
            &range,
            &returned_cid,
            1,
            &[1; 32],
            1,
        )
        .await?;
        tx.commit().await?;
        let ipfs = Arc::new(ReconciliationIpfs::returning(returned_cid));
        let mut scheduler = reconciliation_scheduler(store.clone(), ipfs.clone(), signing_key)?;
        let ipns_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&ipns_calls);

        let _error = scheduler
            .reconcile_pending_manifest_with(move |_, _, _| async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await
            .expect_err("provider CID mismatch must fail closed");

        assert_eq!(ipfs.unpin_count(), 0);
        assert_eq!(ipns_calls.load(Ordering::SeqCst), 0);
        assert!(indexed_manifest_is_pending(store.pool(), &manifest_cid, 15).await?);
        assert_eq!(scheduler.pin_lifecycle.active_pin_owners(), 0);
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires Docker PostgreSQL"]
    async fn pending_reconciliation_records_cleanup_debt_when_mismatch_unpin_fails() -> Result<()> {
        let (_postgres, store) = reconciliation_store().await?;
        let signing_key = SigningKey::from_bytes(&[78; 32]);
        let (manifest_cid, _) =
            record_pending_indexed_manifest(&store, &signing_key, 16, None).await?;
        let returned_cid = raw_block_cid(b"returned CID whose cleanup fails")?;
        let ipfs = Arc::new(ReconciliationIpfs::returning(returned_cid));
        ipfs.fail_unpin.store(true, Ordering::SeqCst);
        let mut scheduler = reconciliation_scheduler(store.clone(), ipfs.clone(), signing_key)?;
        let ipns_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&ipns_calls);

        let _error = scheduler
            .reconcile_pending_manifest_with(move |_, _, _| async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await
            .expect_err("provider CID mismatch must fail closed");

        let debt: Option<String> =
            sqlx::query_scalar("SELECT cid FROM pin_cleanup_debt WHERE cid = $1")
                .bind(returned_cid.to_string())
                .fetch_optional(store.pool())
                .await?;
        assert_eq!(debt, Some(returned_cid.to_string()));
        assert_eq!(ipns_calls.load(Ordering::SeqCst), 0);
        assert!(indexed_manifest_is_pending(store.pool(), &manifest_cid, 16).await?);
        assert_eq!(scheduler.pin_lifecycle.active_pin_owners(), 0);
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires Docker PostgreSQL"]
    async fn pending_reconciliation_repins_exact_body_before_ipns_and_activates() -> Result<()> {
        let (_postgres, store) = reconciliation_store().await?;
        let signing_key = SigningKey::from_bytes(&[74; 32]);
        let trusted_publisher_pubkey = signing_key.verifying_key().to_bytes();
        let provider_packaged_cid = raw_block_cid(b"provider-packaged manifest CID")?;
        let (manifest_cid, manifest_json) =
            record_pending_indexed_manifest(&store, &signing_key, 13, Some(provider_packaged_cid))
                .await?;
        assert_ne!(manifest_cid, raw_block_cid(manifest_json.as_bytes())?);
        let ipfs = Arc::new(ReconciliationIpfs::returning(provider_packaged_cid));
        let mut scheduler = reconciliation_scheduler(store.clone(), ipfs.clone(), signing_key)?;
        let ipns_calls = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::clone(&ipns_calls);

        assert!(
            scheduler
                .reconcile_pending_manifest_with(move |cid, sequence, _lease| async move {
                    calls.lock().expect("IPNS calls lock").push((cid, sequence));
                    Ok(())
                })
                .await?
        );

        assert_eq!(ipfs.pinned_bytes(), vec![manifest_json.into_bytes()]);
        assert_eq!(ipfs.unpin_count(), 0);
        assert_eq!(
            *ipns_calls.lock().expect("IPNS calls lock"),
            vec![(manifest_cid.to_string(), 13)]
        );
        assert!(!indexed_manifest_is_pending(store.pool(), &manifest_cid, 13).await?);
        assert!(
            Audit::pending_indexed_manifest_publication(store.pool(), &trusted_publisher_pubkey,)
                .await?
                .is_none()
        );
        assert_eq!(scheduler.last_ipns_sequence, Some(13));
        assert!(scheduler.ipns_sequence_loaded);
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires Docker PostgreSQL"]
    async fn pending_reconciliation_shutdown_after_ipns_leaves_durable_pending_unactivated()
    -> Result<()> {
        let (_postgres, store) = reconciliation_store().await?;
        let signing_key = SigningKey::from_bytes(&[75; 32]);
        let (manifest_cid, _) =
            record_pending_indexed_manifest(&store, &signing_key, 14, None).await?;
        let ipfs = Arc::new(ReconciliationIpfs::default());
        let mut scheduler = reconciliation_scheduler(store.clone(), ipfs, signing_key)?;
        let (shutdown_tx, shutdown) = watch::channel(false);
        scheduler.shutdown = shutdown;

        let error = scheduler
            .reconcile_pending_manifest_with(move |_, _, _lease| async move {
                shutdown_tx.send(true).expect("request shutdown after IPNS");
                Ok(())
            })
            .await
            .expect_err("shutdown must stop before activation");

        assert!(error.to_string().contains("cooperative shutdown boundary"));
        assert!(indexed_manifest_is_pending(store.pool(), &manifest_cid, 14).await?);
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires Docker PostgreSQL"]
    async fn fresh_indexed_artifact_pin_is_cleaned_when_audit_commit_fails() -> Result<()> {
        let (_postgres, store) = reconciliation_store().await?;
        sqlx::query(
            r"
            CREATE FUNCTION reject_indexed_artifact_audit() RETURNS trigger AS $$
            BEGIN RAISE EXCEPTION 'forced indexed artifact audit failure'; END;
            $$ LANGUAGE plpgsql
            ",
        )
        .execute(store.pool())
        .await?;
        sqlx::query(
            "CREATE TRIGGER reject_indexed_artifact_audit \
             BEFORE INSERT ON published_indexed_artifacts \
             FOR EACH ROW EXECUTE FUNCTION reject_indexed_artifact_audit()",
        )
        .execute(store.pool())
        .await?;
        let signing_key = SigningKey::from_bytes(&[76; 32]);
        let ipfs = Arc::new(ReconciliationIpfs::default());
        let scheduler = reconciliation_scheduler(store.clone(), ipfs.clone(), signing_key)?;
        let scope = ChainScope {
            chain_type: ChainType::Evm,
            chain_id: 1,
            railgun_contract: Address::from([0xbb; 20]),
        };
        let range = IndexedArtifactRange {
            kind: IndexedArtifactRangeKind::Block,
            start: 1,
            end: 1,
        };
        let bytes = b"fresh indexed artifact";

        let _error = scheduler
            .reuse_or_pin_indexed_artifact(
                IndexedArtifactPublicationKind::Chunk,
                IndexedDatasetKind::WalletScan,
                &scope,
                &range,
                u64::try_from(bytes.len())?,
                &content_hash(bytes),
                1,
                bytes,
            )
            .await
            .expect_err("forced audit failure must fail publication");

        assert_eq!(ipfs.pin_count(), 1);
        assert_eq!(ipfs.unpin_count(), 1);
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM published_indexed_artifacts")
            .fetch_one(store.pool())
            .await?;
        assert_eq!(rows, 0);
        Ok(())
    }

    #[tokio::test]
    async fn replacement_watermark_is_rejected_inside_publication_lease() {
        let coordinator = ChainCanonicalityCoordinator::default();
        let height = LatestIndexedHeight {
            dataset_kind: IndexedDatasetKind::WalletScan,
            block_number: 200,
            block_hash: FixedBytes::from([3_u8; 32]),
        };
        let replacement = StoredIndexedBlockHeader {
            block_number: 200,
            block_hash: [4_u8; 32],
            parent_hash: [2_u8; 32],
        };
        let ipns_called = AtomicBool::new(false);

        let _publication = coordinator.publication_lease().await;
        let validation = validate_publication_watermark(&height, Some(&replacement));
        if validation.is_ok() {
            ipns_called.store(true, Ordering::SeqCst);
        }

        assert!(validation.is_err());
        assert!(!ipns_called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn publication_lease_blocks_reorg_until_release() {
        let coordinator = ChainCanonicalityCoordinator::default();
        let publication = coordinator.publication_lease().await;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (acquired_tx, mut acquired_rx) = tokio::sync::oneshot::channel();
        let reorg_coordinator = coordinator.clone();
        let reorg = tokio::spawn(async move {
            let _ = started_tx.send(());
            let _reorg = reorg_coordinator.reorg_lease().await;
            let _ = acquired_tx.send(());
        });

        started_rx.await.expect("reorg task started");
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut acquired_rx)
                .await
                .is_err(),
            "reorg must wait for publication lease"
        );
        let background_publication = publication.clone();
        drop(publication);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut acquired_rx)
                .await
                .is_err(),
            "cloned publication lease must not reacquire behind queued writer"
        );
        drop(background_publication);
        tokio::time::timeout(Duration::from_secs(1), acquired_rx)
            .await
            .expect("reorg acquisition timeout")
            .expect("reorg acquired notification");
        reorg.await.expect("reorg task");
    }

    #[tokio::test]
    async fn cancelled_publication_releases_canonicality_lease() {
        let coordinator = ChainCanonicalityCoordinator::default();
        let (acquired_tx, acquired_rx) = tokio::sync::oneshot::channel();
        let publication_coordinator = coordinator.clone();
        let publication = tokio::spawn(async move {
            let _publication = publication_coordinator.publication_lease().await;
            let _ = acquired_tx.send(());
            std::future::pending::<()>().await;
        });
        acquired_rx.await.expect("publication acquired lease");

        publication.abort();
        let _ = publication.await;
        tokio::time::timeout(Duration::from_secs(1), coordinator.reorg_lease())
            .await
            .expect("cancelled publication retained lease");
    }

    #[tokio::test]
    async fn append_only_work_does_not_wait_for_publication_lease() {
        let coordinator = ChainCanonicalityCoordinator::default();
        let _publication = coordinator.publication_lease().await;
        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::task::yield_now().await;
        })
        .await
        .expect("append-only work was unexpectedly blocked");
    }

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

        let descriptor = catalog_descriptor(
            &catalog,
            "bafytestcatalog",
            512,
            &[7_u8; 32],
            CatalogCoverage::DerivedFromChunks,
        )?;

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
    fn wallet_catalog_descriptor_attests_sparse_deployment_to_checkpoint_coverage() -> Result<()> {
        let scope = ChainScope {
            chain_type: ChainType::Evm,
            chain_id: 1,
            railgun_contract: Address::from([0xbb; 20]),
        };
        let chunks = vec![
            wallet_chunk_descriptor(scope.clone(), 14_751_290, 18_551_881, 40_574),
            wallet_chunk_descriptor(scope.clone(), 18_551_907, 20_246_689, 40_496),
        ];
        let catalog =
            IndexedArtifactCatalog::new(IndexedDatasetKind::WalletScan, scope, chunks.clone());

        let descriptor = catalog_descriptor(
            &catalog,
            "bafywalletcatalog",
            512,
            &[8_u8; 32],
            CatalogCoverage::ExplicitBlockRange {
                start_block: 14_737_691,
                indexed_through_block: 20_300_000,
            },
        )?;

        assert_eq!(descriptor.range.kind, IndexedArtifactRangeKind::Block);
        assert_eq!(descriptor.range.start, 14_737_691);
        assert_eq!(descriptor.range.end, 20_300_000);
        assert_eq!(descriptor.row_count, 81_070);
        assert_eq!(descriptor.metadata.start_block, Some(14_737_691));
        assert_eq!(descriptor.metadata.end_block, Some(20_300_000));
        assert_eq!(descriptor.metadata.checkpoint_block, Some(20_300_000));
        assert_eq!(descriptor.metadata.last_indexed_block, Some(20_300_000));
        assert_eq!(catalog.chunks, chunks);
        Ok(())
    }

    #[test]
    fn wallet_catalog_descriptor_attests_zero_row_coverage() -> Result<()> {
        let scope = ChainScope {
            chain_type: ChainType::Evm,
            chain_id: 1,
            railgun_contract: Address::from([0xbb; 20]),
        };
        let catalog =
            IndexedArtifactCatalog::new(IndexedDatasetKind::WalletScan, scope, Vec::new());

        let (prepared_catalog, catalog_bytes, catalog_hash, descriptor) = prepare_catalog_artifact(
            &catalog.scope,
            IndexedDatasetKind::WalletScan,
            Vec::new(),
            CatalogCoverage::ExplicitBlockRange {
                start_block: 14_737_691,
                indexed_through_block: 14_751_289,
            },
        )?;

        assert_eq!(prepared_catalog, catalog);
        assert_eq!(content_hash(&catalog_bytes), catalog_hash);
        assert_eq!(
            u64::try_from(catalog_bytes.len()).expect("catalog byte size"),
            descriptor.byte_size
        );
        let decoded: IndexedArtifactCatalog =
            serde_json::from_slice(&catalog_bytes).expect("decode empty catalog");
        assert!(decoded.chunks.is_empty());
        assert_eq!(descriptor.range.start, 14_737_691);
        assert_eq!(descriptor.range.end, 14_751_289);
        assert_eq!(descriptor.row_count, 0);
        assert_eq!(descriptor.metadata.checkpoint_block, Some(14_751_289));
        Ok(())
    }

    #[test]
    fn wallet_catalog_descriptor_rejects_invalid_or_out_of_range_coverage() {
        let scope = ChainScope {
            chain_type: ChainType::Evm,
            chain_id: 1,
            railgun_contract: Address::from([0xbb; 20]),
        };
        let catalog = IndexedArtifactCatalog::new(
            IndexedDatasetKind::WalletScan,
            scope.clone(),
            vec![wallet_chunk_descriptor(scope, 150, 180, 1)],
        );

        let invalid = catalog_descriptor(
            &catalog,
            "bafywalletcatalog",
            64,
            &[9_u8; 32],
            CatalogCoverage::ExplicitBlockRange {
                start_block: 200,
                indexed_through_block: 100,
            },
        )
        .expect_err("invalid coverage rejected");
        assert!(invalid.to_string().contains("coverage start"));

        let outside = catalog_descriptor(
            &catalog,
            "bafywalletcatalog",
            64,
            &[9_u8; 32],
            CatalogCoverage::ExplicitBlockRange {
                start_block: 151,
                indexed_through_block: 200,
            },
        )
        .expect_err("out-of-range chunk rejected");
        assert!(
            outside
                .to_string()
                .contains("outside explicit block coverage")
        );
    }

    #[test]
    fn publication_watermark_rejects_rewind_or_replacement_hash() -> Result<()> {
        let height = LatestIndexedHeight {
            dataset_kind: IndexedDatasetKind::WalletScan,
            block_number: 200,
            block_hash: FixedBytes::from([3_u8; 32]),
        };
        let matching = StoredIndexedBlockHeader {
            block_number: 200,
            block_hash: [3_u8; 32],
            parent_hash: [2_u8; 32],
        };
        validate_publication_watermark(&height, Some(&matching))?;

        let rewound =
            validate_publication_watermark(&height, None).expect_err("rewound watermark rejected");
        assert!(rewound.to_string().contains("was rewound"));

        let replacement = StoredIndexedBlockHeader {
            block_hash: [4_u8; 32],
            ..matching
        };
        let changed = validate_publication_watermark(&height, Some(&replacement))
            .expect_err("replacement watermark rejected");
        assert!(changed.to_string().contains("changed during publication"));
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

    async fn reconciliation_store() -> Result<(ContainerAsync<Postgres>, Store)> {
        let node = Postgres::default()
            .start()
            .await
            .wrap_err("start Docker PostgreSQL; this ignored test requires Docker")?;
        let connection_string = format!(
            "postgres://postgres:postgres@127.0.0.1:{}/postgres",
            node.get_host_port_ipv4(5432).await?
        );
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&connection_string)
            .await?;
        run_migrations(&pool).await?;
        Ok((node, Store::new(pool)))
    }

    fn reconciliation_scheduler(
        store: Store,
        ipfs_client: Arc<ReconciliationIpfs>,
        signing_key: SigningKey,
    ) -> Result<ChainIndexedPublicationScheduler> {
        let mut config: Config =
            serde_yaml::from_str(include_str!("../../../config.railgun-indexer.example.yaml"))
                .wrap_err("parse example config for reconciliation test")?;
        config.chain_indexed.chains.clear();
        let (ipns_publisher, _ipns_task) = IpnsPublisher::new(
            &signing_key,
            IpnsPublisherConfig {
                bootstrap_peers: Vec::new(),
                record_lifetime: Duration::from_mins(1),
                record_ttl: Duration::from_secs(30),
                publish_timeout: Duration::from_secs(1),
            },
        )?;
        let (_shutdown_tx, shutdown) = watch::channel(false);
        Ok(ChainIndexedPublicationScheduler {
            config,
            store,
            ipfs_client,
            signing_key,
            ipns_publisher,
            pin_lifecycle: PinLifecycleCoordinator::default(),
            canonicality: ChainCanonicalityCoordinator::default(),
            last_ipns_sequence: None,
            ipns_sequence_loaded: false,
            shutdown,
        })
    }

    async fn record_pending_indexed_manifest(
        store: &Store,
        signing_key: &SigningKey,
        sequence: u64,
        audited_cid: Option<Cid>,
    ) -> Result<(Cid, String)> {
        let mut manifest = railgun_indexer_core::manifest::IndexedArtifactManifest::new(
            1_700_000_000_000,
            sequence,
            PublisherIdentity::ed25519(FixedBytes::ZERO),
            Vec::new(),
        );
        manifest.sign_manifest(signing_key)?;
        let manifest_json = serde_json::to_string(&manifest)?;
        let manifest_cid = match audited_cid {
            Some(cid) => cid,
            None => raw_block_cid(manifest_json.as_bytes())?,
        };
        let mut tx = store.begin().await?;
        Audit::record_indexed_manifest_pin(
            &mut tx,
            &manifest_cid,
            &[],
            sequence,
            u64::try_from(manifest_json.len())?,
            &content_hash(manifest_json.as_bytes()),
            INDEXED_ARTIFACT_MANIFEST_FORMAT_VERSION,
            &manifest_json,
        )
        .await?;
        tx.commit().await?;
        Ok((manifest_cid, manifest_json))
    }

    async fn indexed_manifest_is_pending(
        pool: &sqlx::PgPool,
        cid: &Cid,
        sequence: u64,
    ) -> Result<bool> {
        Ok(sqlx::query_scalar(
            r"
            SELECT ipns_published_at IS NULL
               AND superseded_at IS NULL
               AND unpinned_at IS NULL
               AND reconciliation_invalidated_at IS NULL
            FROM published_indexed_manifests
            WHERE cid = $1 AND ipns_sequence = $2
            ",
        )
        .bind(cid.to_string())
        .bind(i64::try_from(sequence)?)
        .fetch_one(pool)
        .await?)
    }

    #[derive(Debug, Default)]
    struct ReconciliationIpfs {
        returned_cid: Option<Cid>,
        pinned: Mutex<Vec<Vec<u8>>>,
        unpin_count: AtomicUsize,
        fail_unpin: AtomicBool,
    }

    impl ReconciliationIpfs {
        fn returning(returned_cid: Cid) -> Self {
            Self {
                returned_cid: Some(returned_cid),
                pinned: Mutex::new(Vec::new()),
                unpin_count: AtomicUsize::new(0),
                fail_unpin: AtomicBool::new(false),
            }
        }

        fn pinned_bytes(&self) -> Vec<Vec<u8>> {
            self.pinned.lock().expect("pinned bytes lock").clone()
        }

        fn pin_count(&self) -> usize {
            self.pinned.lock().expect("pinned bytes lock").len()
        }

        fn unpin_count(&self) -> usize {
            self.unpin_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl IpfsClient for ReconciliationIpfs {
        fn service_name(&self) -> &'static str {
            "reconciliation-test"
        }

        async fn pin_bytes(&self, bytes: &[u8]) -> Result<Cid, IpfsError> {
            self.pinned
                .lock()
                .expect("pinned bytes lock")
                .push(bytes.to_vec());
            match self.returned_cid {
                Some(cid) => Ok(cid),
                None => raw_block_cid(bytes),
            }
        }

        async fn unpin(&self, _cid: &Cid) -> Result<(), IpfsError> {
            self.unpin_count.fetch_add(1, Ordering::SeqCst);
            if self.fail_unpin.load(Ordering::SeqCst) {
                Err(IpfsError::UnpinFailed {
                    service: self.service_name().to_string(),
                    cid: Box::new(*_cid),
                    source: Box::new(std::io::Error::other("forced unpin failure")),
                })
            } else {
                Ok(())
            }
        }

        async fn contains(&self, _cid: &Cid) -> Result<bool, IpfsError> {
            Ok(true)
        }
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

    fn wallet_chunk_descriptor(
        scope: ChainScope,
        start: u64,
        end: u64,
        row_count: u64,
    ) -> IndexedArtifactDescriptor {
        IndexedArtifactDescriptor {
            dataset_kind: IndexedDatasetKind::WalletScan,
            scope,
            range: IndexedArtifactRange {
                kind: IndexedArtifactRangeKind::Block,
                start,
                end,
            },
            row_count,
            cid: format!("bafywalletchunk{start}"),
            sha256: FixedBytes::from([2_u8; 32]),
            byte_size: 128,
            encoding_version: 1,
            compression: CompressionAlgorithm::Zstd,
            metadata: DatasetDescriptorMetadata {
                checkpoint_block: Some(end),
                last_indexed_block: Some(end),
                ..Default::default()
            },
        }
    }
}
