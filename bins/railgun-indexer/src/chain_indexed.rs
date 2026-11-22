use std::collections::BTreeSet;
use std::future::Future;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use alloy::eips::BlockNumberOrTag;
use alloy::hex;
use alloy::primitives::FixedBytes;
use alloy::providers::{Provider, ProviderBuilder, RootProvider, WsConnect};
use alloy::pubsub::SubscriptionStream;
use alloy::sol_types::SolEvent;
use alloy::transports::TransportError;
use alloy_rpc_types_eth::{Filter, Log};
use broadcaster_core::contracts::railgun::{
    CommitmentBatch, GeneratedCommitmentBatch, Nullified, Nullifiers, RailgunLegacyShieldEvents,
    Shield, Transact,
};
use broadcaster_core::tree::TREE_LEAF_COUNT;
use ed25519_dalek::SigningKey;
use eyre::{Result, WrapErr, eyre};
use futures_util::{FutureExt, StreamExt, future::join_all};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use railgun_indexer_core::amount_statistics::derive_amount_statistics;
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
    AMOUNT_STATISTICS_MANIFEST_FORMAT_VERSION, AmountStatisticsChainEntry,
    AmountStatisticsManifest, AmountStatisticsManifestEnvelope, AmountStatisticsSnapshotDescriptor,
    ChainScope, ChainType, CompressionAlgorithm, DatasetDescriptorMetadata,
    INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION, INDEXED_ARTIFACT_MANIFEST_FORMAT_VERSION,
    IndexedArtifactCatalog, IndexedArtifactChainEntry, IndexedArtifactDescriptor,
    IndexedArtifactRange, IndexedArtifactRangeKind, IndexedDatasetKind, LatestIndexedHeight,
    PublisherIdentity, content_hash, encode_amount_statistics_snapshot,
};
use railgun_indexer_core::merkle_checkpoint::{
    MerkleCheckpointArtifact, prepare_merkle_checkpoint_artifact,
};
use railgun_indexer_core::public_txid::{
    prepare_public_txid_chunk, public_txid_checkpoint_root, public_txid_chunk_plan_item,
};
use railgun_indexer_core::publish::ipfs::{IpfsClient, IpfsError, pin_indexed_chunk, pin_manifest};
use railgun_indexer_core::publish::ipns::IpnsPublisher;
use railgun_indexer_core::status::{AmountStatisticsChainFailure, SharedStatus};
use railgun_indexer_core::store::{
    IndexedDatasetKind as StoreDatasetKind, Store, StoredIndexedBlockHeader, StoredPublicTxidRow,
};
use railgun_indexer_core::wallet_scan::{prepare_wallet_scan_chunk, wallet_scan_chunk_plan_item};

use crate::{
    checked_interval, format_report_chain, shutdown_changed_or_requested, shutdown_requested,
    sleep_or_shutdown, unix_millis,
};

mod amount_statistics;
mod catalog_descriptors;
mod catalogs;
mod publication;

use amount_statistics::AmountStatisticsPublication;
#[cfg(test)]
use amount_statistics::next_manifest_chains;
#[cfg(test)]
use catalog_descriptors::catalog_descriptor;
use catalog_descriptors::{
    CatalogCoverage, commitment_plan_items, fixed_bytes, latest_indexed_block,
    prepare_catalog_artifact, public_txid_chunk_row_limit, public_txid_plan_items,
    store_dataset_kind,
};
#[cfg(test)]
use publication::validate_publication_watermark;

/// Keeps the tracing target of the moved methods at this module's path.
const LOG_TARGET: &str = module_path!();

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
    let mut tail_subscription = None;
    let mut known_safe_head = None;

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
            known_safe_head.take(),
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
                    match wait_for_tail_wakeup(
                        &config,
                        &runtime,
                        &mut tail_subscription,
                        tail_safety_interval,
                        idle_interval,
                        &mut shutdown,
                    )
                    .await
                    {
                        ControlFlow::Break(()) => return Ok(()),
                        ControlFlow::Continue(safe_head) => known_safe_head = safe_head,
                    }
                }
            }
            Ok(ChainIndexStep::CaughtUp) => {
                historical_catch_up_complete = true;
                batch_span = max_batch_span;
                match wait_for_tail_wakeup(
                    &config,
                    &runtime,
                    &mut tail_subscription,
                    tail_safety_interval,
                    idle_interval,
                    &mut shutdown,
                )
                .await
                {
                    ControlFlow::Break(()) => return Ok(()),
                    ControlFlow::Continue(safe_head) => known_safe_head = safe_head,
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

/// Websocket provider kept alive alongside its log stream and reused across waits. The next
/// wait recreates it after the stream ends or an idle safety timeout, because Alloy's reconnect
/// does not retry a failed resubscribe and can leave the stream open with no subscription.
type TailLogSubscription = (RootProvider, SubscriptionStream<Log>);

/// `Break` on shutdown; otherwise `Continue` with the safe head when one was
/// already fetched while waiting.
type TailWakeup = ControlFlow<(), Option<u64>>;

const fn tail_wakeup_after_sleep(shutdown: bool) -> TailWakeup {
    if shutdown {
        ControlFlow::Break(())
    } else {
        ControlFlow::Continue(None)
    }
}

async fn wait_for_tail_wakeup(
    config: &Config,
    runtime: &ChainRuntime,
    subscription: &mut Option<TailLogSubscription>,
    tail_safety_interval: Duration,
    finality_poll_interval: Duration,
    shutdown: &mut watch::Receiver<bool>,
) -> TailWakeup {
    let Some(ws_url) = runtime.chain.ws_url.as_deref() else {
        return tail_wakeup_after_sleep(sleep_or_shutdown(tail_safety_interval, shutdown).await);
    };

    match wait_for_ws_log_or_safety_interval(
        config,
        runtime,
        ws_url,
        subscription,
        tail_safety_interval,
        finality_poll_interval,
        shutdown,
    )
    .await
    {
        Ok(wakeup) => wakeup,
        Err(error) => {
            warn!(
                chain_id = runtime.chain.chain_id,
                railgun_contract = %runtime.chain.railgun_contract,
                ws_url,
                error = %format_report_chain(&error),
                "chain-indexed websocket subscription failed; using safety interval fallback"
            );
            tail_wakeup_after_sleep(sleep_or_shutdown(tail_safety_interval, shutdown).await)
        }
    }
}

async fn subscribe_tail_logs(runtime: &ChainRuntime, ws_url: &str) -> Result<TailLogSubscription> {
    let ws = WsConnect::new(ws_url.to_string());
    let provider = ProviderBuilder::new()
        .connect_ws(ws)
        .await
        .wrap_err("connect chain-indexed websocket provider")?
        .root()
        .clone();
    let filter = chain_index_subscription_filter(runtime);
    let subscription = provider
        .subscribe_logs(&filter)
        .await
        .wrap_err("subscribe to chain-indexed Railgun logs")?;
    debug!(
        chain_id = runtime.chain.chain_id,
        railgun_contract = %runtime.chain.railgun_contract,
        ws_url,
        "subscribed to chain-indexed websocket logs"
    );
    Ok((provider, subscription.into_stream()))
}

async fn wait_for_ws_log_or_safety_interval(
    config: &Config,
    runtime: &ChainRuntime,
    ws_url: &str,
    subscription: &mut Option<TailLogSubscription>,
    tail_safety_interval: Duration,
    finality_poll_interval: Duration,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<TailWakeup> {
    let (_, stream) = match subscription {
        Some(subscription) => subscription,
        None => subscription.insert(subscribe_tail_logs(runtime, ws_url).await?),
    };

    // Collapse logs that arrived while indexing into one wakeup for the newest block.
    let mut queued_log_block = None;
    while let Some(Some(log)) = stream.next().now_or_never() {
        queued_log_block = queued_log_block.max(log.block_number);
    }

    let log_block = if queued_log_block.is_some() {
        queued_log_block
    } else {
        debug!(
            chain_id = runtime.chain.chain_id,
            railgun_contract = %runtime.chain.railgun_contract,
            ws_url,
            tail_safety_interval_ms = tail_safety_interval.as_millis(),
            "waiting for chain-indexed websocket log or safety interval"
        );
        let maybe_log = tokio::select! {
            () = tokio::time::sleep(tail_safety_interval) => {
                *subscription = None;
                return Ok(tail_wakeup_after_sleep(shutdown_requested(shutdown)));
            }
            shutdown = shutdown_changed_or_requested(shutdown) => {
                return Ok(tail_wakeup_after_sleep(shutdown));
            }
            maybe_log = stream.next() => maybe_log,
        };
        let Some(log) = maybe_log else {
            *subscription = None;
            return Err(eyre!("chain-indexed websocket log stream ended"));
        };
        debug!(
            chain_id = runtime.chain.chain_id,
            railgun_contract = %runtime.chain.railgun_contract,
            ws_url,
            block_number = log.block_number,
            transaction_hash = ?log.transaction_hash,
            "chain-indexed websocket log wakeup"
        );
        log.block_number
    };

    match log_block {
        Some(log_block) => {
            wait_for_ws_log_finality(config, runtime, log_block, finality_poll_interval, shutdown)
                .await
        }
        None => Ok(ControlFlow::Continue(None)),
    }
}

async fn wait_for_ws_log_finality(
    config: &Config,
    runtime: &ChainRuntime,
    log_block: u64,
    poll_interval: Duration,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<TailWakeup> {
    loop {
        let safe_head = runtime
            .provider
            .get_block_number()
            .await
            .wrap_err("fetch chain head while waiting for websocket log finality")?
            .saturating_sub(config.chain_indexed.safe_confirmations);
        if safe_head >= log_block {
            return Ok(ControlFlow::Continue(Some(safe_head)));
        }
        if sleep_or_shutdown(poll_interval, shutdown).await {
            return Ok(ControlFlow::Break(()));
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

/// The key that signs chain-indexed publications and the IPNS publisher that announces them.
pub(crate) struct ChainIndexedPublisher {
    pub(crate) signing_key: SigningKey,
    pub(crate) ipns_publisher: IpnsPublisher,
}

/// `amount_statistics` holds the amount-statistics IPNS publisher and the status it reports to,
/// and is `Some` only when amount-statistics publication is enabled.
pub(crate) async fn run_publication_loop(
    config: Config,
    store: Store,
    ipfs_client: Arc<dyn IpfsClient>,
    publisher: ChainIndexedPublisher,
    amount_statistics: Option<(IpnsPublisher, SharedStatus)>,
    pin_lifecycle: PinLifecycleCoordinator,
    canonicality: ChainCanonicalityCoordinator,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let interval = checked_interval(
        *config.chain_indexed.publish_interval,
        "chain_indexed.publish_interval",
    )?;
    let amount_statistics = amount_statistics
        .map(|(ipns_publisher, status)| {
            AmountStatisticsPublication::new(&config, ipns_publisher, status)
        })
        .transpose()?;
    let mut scheduler = ChainIndexedPublicationScheduler {
        config,
        store,
        ipfs_client,
        signing_key: publisher.signing_key,
        ipns_publisher: publisher.ipns_publisher,
        amount_statistics,
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
        match scheduler.publish_cycles(SystemTime::now()).await {
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
    known_safe_head: Option<u64>,
) -> Result<ChainIndexStep> {
    let safe_head = match known_safe_head {
        Some(safe_head) => safe_head,
        None => runtime
            .provider
            .get_block_number()
            .await
            .wrap_err("fetch chain head")?
            .saturating_sub(config.chain_indexed.safe_confirmations),
    };
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
            action_start_block: runtime.chain.action_start_block,
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
        unshield_log_derivations = outcome.unshield_log_derivations,
        unshield_log_divergences = outcome.unshield_log_divergences,
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
    amount_statistics: Option<AmountStatisticsPublication>,
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

fn build_provider(rpc_url: &str) -> Result<RootProvider> {
    let url = url::Url::parse(rpc_url).wrap_err("parse RPC URL")?;
    Ok(ProviderBuilder::new().connect_http(url).root().clone())
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
mod tests;
