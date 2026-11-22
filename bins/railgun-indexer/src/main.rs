use alloy_primitives::{FixedBytes, hex};
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use cid::Cid;
use clap::{Parser, ValueEnum};
use ed25519_dalek::SigningKey;
use eyre::{Result, WrapErr, eyre};
use poi::artifacts::v4::{
    ArtifactEncoding, BlockedShieldsDescriptor, CheckpointCatalog, CheckpointCatalogDescriptor,
    Compression, Error as PoiArtifactError, EventArtifactDescriptor, EventArtifactKind,
    FORMAT_VERSION as POI_ARTIFACT_FORMAT_VERSION, MAX_RETAINED_BRIDGES,
    Manifest as PoiArtifactManifest, ManifestEntry as PoiArtifactManifestEntry, Scope,
};
use poi::poi::PoiRpcClient;
use railgun_indexer_core::audit::{
    ActivePoiGraph, Audit, ChainCanonicalityCoordinator, PinLifecycleCoordinator,
    PinOwnershipLease, PoiArtifactPublicationKind, PoiManifestChannel, Retention,
};
use railgun_indexer_core::blocked::content_hash;
use railgun_indexer_core::config::Config;
use railgun_indexer_core::manifest::load_publisher_signing_key;
use railgun_indexer_core::poi_v4::{
    PreparedEventArtifact, PublicationError, ValidatedCorpus,
    artifact_descriptor as poi_artifact_descriptor, checkpoint_catalog,
};
use railgun_indexer_core::publication_sequence::{
    PoiPublicationSequenceAllocator, PoiPublicationSequenceLease,
};
use railgun_indexer_core::publish::ipfs::{
    FilebaseIpfsClient, IpfsClient, MultiPinner, pin_manifest,
};
use railgun_indexer_core::publish::ipns::{
    IpnsPublisher, IpnsPublisherConfig, IpnsPublisherTask, ManifestIpnsPublisher,
    PublisherIdentities, amount_statistics_public_identity, signing_key_peer_id,
    v4_poi_public_identity, validate_publisher_identities,
};
use railgun_indexer_core::publisher_lock::{
    PUBLISHER_ADVISORY_LOCK_NAME, try_acquire_publisher_lock,
};
use railgun_indexer_core::scrape::Orchestrator;
use railgun_indexer_core::snapshot::Lifecycle;
use railgun_indexer_core::status::{SharedStatus, Status};
use railgun_indexer_core::store::{Store, run_migrations};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgAdvisoryLock;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

mod chain_indexed;
mod poi_artifacts;
mod publication;

/// Keeps the tracing target of the moved methods at this module's path.
const LOG_TARGET: &str = module_path!();

const FILEBASE_ACCESS_KEY_ENV: &str = "RAILGUN_INDEXER_FILEBASE_ACCESS_KEY";
const FILEBASE_SECRET_KEY_ENV: &str = "RAILGUN_INDEXER_FILEBASE_SECRET_KEY";
const FILEBASE_BUCKET_ENV: &str = "RAILGUN_INDEXER_FILEBASE_BUCKET";
const FILEBASE_REGION: &str = "us-east-1";
const FILEBASE_KEY_PREFIX: &str = "railgun-indexer";
const EVM_CHAIN_TYPE: u8 = 0;
const RETENTION_SWEEP_INTERVAL_CAP: Duration = Duration::from_mins(10);
const V4_BRIDGE_RETENTION_TARGET: Duration = Duration::from_hours(168);
const BACKGROUND_TASK_FINAL_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Parser)]
#[command(name = "railgun-indexer")]
struct Options {
    #[arg(
        long,
        env = "RAILGUN_INDEXER_CONFIG",
        required_unless_present = "print_v4_poi_public_identity",
        conflicts_with = "print_v4_poi_public_identity"
    )]
    config: Option<PathBuf>,
    #[arg(
        long,
        requires = "publisher_signing_key_path",
        conflicts_with = "invalidate_pending_poi_manifest"
    )]
    print_v4_poi_public_identity: bool,
    #[arg(long, value_name = "PATH", requires = "print_v4_poi_public_identity")]
    publisher_signing_key_path: Option<PathBuf>,
    #[arg(
        long,
        requires_all = ["config", "channel", "manifest_cid", "manifest_sequence"],
        conflicts_with = "adopt_poi_txid_version"
    )]
    invalidate_pending_poi_manifest: bool,
    #[arg(long, value_enum, requires = "invalidate_pending_poi_manifest")]
    channel: Option<RecoveryChannel>,
    #[arg(long, requires = "invalidate_pending_poi_manifest")]
    manifest_cid: Option<Cid>,
    #[arg(long, requires = "invalidate_pending_poi_manifest")]
    manifest_sequence: Option<u64>,
    #[arg(
        long,
        requires_all = ["config", "authorized_txid_version"],
        conflicts_with_all = ["invalidate_pending_poi_manifest", "print_v4_poi_public_identity"]
    )]
    adopt_poi_txid_version: bool,
    #[arg(long, value_name = "TXID_VERSION", requires = "adopt_poi_txid_version")]
    authorized_txid_version: Option<String>,
    #[arg(
        long,
        env = "RAILGUN_INDEXER_STATUS_BIND_ADDR",
        default_value = "127.0.0.1:8080"
    )]
    status_bind_addr: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum RecoveryChannel {
    V4,
}

impl From<RecoveryChannel> for PoiManifestChannel {
    fn from(value: RecoveryChannel) -> Self {
        match value {
            RecoveryChannel::V4 => Self::V4,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let options = Options::parse();
    if options.print_v4_poi_public_identity {
        let key_path = options
            .publisher_signing_key_path
            .as_ref()
            .expect("clap requires the publisher signing key path in offline mode");
        print_v4_poi_public_identity(key_path)?;
        return Ok(());
    }

    let config_path = options
        .config
        .as_ref()
        .expect("clap requires config in normal mode");
    let config = load_config(config_path).wrap_err("load config")?;
    let pool = config
        .connect_postgres()
        .await
        .wrap_err("validate config")?;
    let publisher_lock = PgAdvisoryLock::new(PUBLISHER_ADVISORY_LOCK_NAME);
    let _publisher_lock_guard = try_acquire_publisher_lock(&publisher_lock, &pool).await?;
    run_migrations(&pool)
        .await
        .wrap_err("run database migrations")?;
    let store = Store::new(pool.clone());
    if options.invalidate_pending_poi_manifest {
        let channel = options.channel.expect("clap requires the recovery channel");
        let cid = options
            .manifest_cid
            .as_ref()
            .expect("clap requires the recovery manifest CID");
        let sequence = options
            .manifest_sequence
            .expect("clap requires the recovery manifest sequence");
        let mut tx = pool
            .begin()
            .await
            .wrap_err("begin pending POI manifest recovery transaction")?;
        Audit::invalidate_pending_poi_manifest_reconciliation(
            &mut tx,
            channel.into(),
            cid,
            sequence,
        )
        .await
        .wrap_err("invalidate exact pending POI manifest reconciliation")?;
        tx.commit()
            .await
            .wrap_err("commit pending POI manifest recovery")?;
        println!(
            "invalidated pending {} POI manifest cid={} sequence={}",
            channel
                .to_possible_value()
                .expect("recovery channel value")
                .get_name(),
            cid,
            sequence
        );
        return Ok(());
    }
    if options.adopt_poi_txid_version {
        let authorized = options
            .authorized_txid_version
            .as_deref()
            .expect("clap requires exact TXID-version authorization");
        validate_poi_txid_adoption_authorization(&config.txid_version, authorized)?;
        store
            .adopt_poi_txid_version(&config.txid_version)
            .await
            .wrap_err("adopt exact POI TXID-version identity")?;
        println!(
            "POI database TXID-version identity is {}",
            config.txid_version
        );
        return Ok(());
    }
    store
        .admit_poi_txid_version(&config.txid_version)
        .await
        .wrap_err("admit configured POI TXID-version identity")?;

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let status =
        Status::for_pairs(&config.list_keys, &config.chain_ids, config.page_size_max).shared();
    let orchestrator = Orchestrator::from_config(&config, store.clone())
        .wrap_err("initialize scraper orchestrator")?
        .with_status(status.clone());
    let publisher_key = load_publisher_signing_key(&config.publisher_signing_key_path)
        .wrap_err("load publisher signing key")?;
    let chain_indexed_publisher_key =
        load_publisher_signing_key(&config.chain_indexed_publisher_signing_key_path)
            .wrap_err("load chain-indexed publisher signing key")?;
    let ipfs_pinner = init_ipfs_pinner(&config).wrap_err("initialize IPFS pinner")?;
    let ipns_config =
        IpnsPublisherConfig::from_indexer_config(&config).wrap_err("initialize IPNS config")?;
    let [
        (v4_poi_ipns_publisher, v4_poi_ipns_task),
        (chain_indexed_ipns_publisher, chain_indexed_ipns_task),
        amount_statistics_ipns,
    ] = init_ipns_publishers(&publisher_key, &chain_indexed_publisher_key, ipns_config)?;
    let poi_v4_ipns_name = v4_poi_ipns_publisher
        .ipns_name()
        .wrap_err("derive v4 POI IPNS name")?;
    let chain_indexed_ipns_name = chain_indexed_ipns_publisher
        .ipns_name()
        .wrap_err("derive chain-indexed IPNS name")?;
    let poi_v4_peer_id = v4_poi_ipns_publisher.peer_id().to_string();
    let chain_indexed_peer_id = chain_indexed_ipns_publisher.peer_id().to_string();
    status.write().await.set_ipns_identities(
        poi_v4_ipns_name.clone(),
        chain_indexed_ipns_name.clone(),
        poi_v4_peer_id.clone(),
        chain_indexed_peer_id.clone(),
    );
    let status_listener = TcpListener::bind(options.status_bind_addr)
        .await
        .wrap_err("bind status HTTP listener")?;
    info!(
        upstream_endpoint_hash = %hex::encode_prefixed(upstream_endpoint_hash(&config.upstream_url)),
        chain_count = config.chain_ids.len(),
        list_count = config.list_keys.len(),
        poi_v4_ipns_name,
        chain_indexed_ipns_name,
        poi_v4_peer_id,
        chain_indexed_peer_id,
        "loaded railgun indexer config"
    );

    run_background_tasks(
        config,
        store,
        orchestrator,
        publisher_key,
        ipfs_pinner,
        v4_poi_ipns_publisher,
        v4_poi_ipns_task,
        chain_indexed::ChainIndexedPublisher {
            signing_key: chain_indexed_publisher_key,
            ipns_publisher: chain_indexed_ipns_publisher,
        },
        chain_indexed_ipns_task,
        amount_statistics_ipns,
        status_listener,
        status,
    )
    .await
}

/// Builds the v4 POI, chain-indexed and amount-statistics IPNS publishers, in that order, and
/// refuses to start on a publication identity collision that `validate_publisher_identities`
/// rejects.
fn init_ipns_publishers(
    publisher_key: &SigningKey,
    chain_indexed_publisher_key: &SigningKey,
    ipns_config: IpnsPublisherConfig,
) -> Result<[(IpnsPublisher, IpnsPublisherTask); 3]> {
    let v4_poi = IpnsPublisher::new_v4_poi(publisher_key, ipns_config.clone())
        .wrap_err("initialize v4 POI IPNS publisher")?;
    let chain_indexed = IpnsPublisher::new(chain_indexed_publisher_key, ipns_config.clone())
        .wrap_err("initialize chain-indexed IPNS publisher")?;
    let amount_statistics =
        IpnsPublisher::new_amount_statistics(chain_indexed_publisher_key, ipns_config)
            .wrap_err("initialize amount-statistics IPNS publisher")?;
    let legacy_poi =
        signing_key_peer_id(publisher_key).wrap_err("derive legacy POI IPNS identity")?;
    validate_publisher_identities(&PublisherIdentities {
        v4_poi: v4_poi.0.peer_id(),
        chain_indexed: chain_indexed.0.peer_id(),
        legacy_poi,
        amount_statistics: amount_statistics.0.peer_id(),
    })
    .wrap_err("validate publisher identities")?;
    Ok([v4_poi, chain_indexed, amount_statistics])
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct V4PoiPublicIdentityOutput {
    manifest_signing_public_key: String,
    amount_statistics_ipns_name: String,
    v4_ipns_public_key: String,
    v4_ipns_peer_id: String,
    v4_ipns_name: String,
}

fn print_v4_poi_public_identity(key_path: &PathBuf) -> Result<()> {
    let signing_key =
        load_publisher_signing_key(key_path).wrap_err("load publisher signing key")?;
    println!("{}", v4_poi_public_identity_json(&signing_key)?);
    Ok(())
}

fn v4_poi_public_identity_json(signing_key: &SigningKey) -> Result<String> {
    let identity = v4_poi_public_identity(signing_key).wrap_err("derive v4 POI public identity")?;
    let amount_statistics = amount_statistics_public_identity(signing_key)
        .wrap_err("derive amount-statistics public identity")?;
    let output = V4PoiPublicIdentityOutput {
        manifest_signing_public_key: hex::encode_prefixed(signing_key.verifying_key().to_bytes()),
        amount_statistics_ipns_name: amount_statistics.ipns_name,
        v4_ipns_public_key: hex::encode_prefixed(identity.ed25519_public_key),
        v4_ipns_peer_id: identity.peer_id.to_string(),
        v4_ipns_name: identity.ipns_name,
    };
    serde_json::to_string(&output).wrap_err("encode v4 POI public identity")
}

fn load_config(path: &PathBuf) -> Result<Config> {
    let data = fs::read_to_string(path).wrap_err("read config file")?;
    serde_yaml::from_str(&data).wrap_err("parse yaml config")
}

fn validate_poi_txid_adoption_authorization(configured: &str, authorized: &str) -> Result<()> {
    if authorized == configured {
        Ok(())
    } else {
        Err(eyre!(
            "authorized TXID version {authorized} does not exactly match configured poi.txid_version {configured}; no database state was changed"
        ))
    }
}

fn init_ipfs_pinner(config: &Config) -> Result<Arc<dyn IpfsClient>> {
    let access_key = required_env(FILEBASE_ACCESS_KEY_ENV)?;
    let secret_key = required_env(FILEBASE_SECRET_KEY_ENV)?;
    let bucket = required_env(FILEBASE_BUCKET_ENV)?;
    let client: Arc<dyn IpfsClient> = Arc::new(
        FilebaseIpfsClient::with_endpoint(
            access_key,
            secret_key,
            bucket,
            config.ipfs_endpoint.clone(),
            FILEBASE_REGION,
            FILEBASE_KEY_PREFIX,
        )
        .wrap_err("build Filebase IPFS client")?,
    );
    let pinner = MultiPinner::new(vec![client], 1).wrap_err("build quorum pinner")?;

    Ok(Arc::new(pinner))
}

fn required_env(name: &str) -> Result<String> {
    env::var(name).wrap_err_with(|| format!("read {name}"))
}

async fn run_background_tasks(
    config: Config,
    store: Store,
    orchestrator: Orchestrator,
    publisher_key: SigningKey,
    ipfs_pinner: Arc<dyn IpfsClient>,
    v4_poi_ipns_publisher: IpnsPublisher,
    v4_poi_ipns_task: IpnsPublisherTask,
    chain_indexed_publisher: chain_indexed::ChainIndexedPublisher,
    chain_indexed_ipns_task: IpnsPublisherTask,
    amount_statistics_ipns: (IpnsPublisher, IpnsPublisherTask),
    status_listener: TcpListener,
    status: SharedStatus,
) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut tasks = JoinSet::new();
    let pin_lifecycle = PinLifecycleCoordinator::default();
    let chain_canonicality = ChainCanonicalityCoordinator::default();

    spawn_ipns_task(
        &mut tasks,
        v4_poi_ipns_task,
        &shutdown_rx,
        "v4 POI IPNS publisher task",
    );
    spawn_ipns_task(
        &mut tasks,
        chain_indexed_ipns_task,
        &shutdown_rx,
        "chain-indexed IPNS publisher task",
    );
    tasks.spawn({
        let orchestrator = orchestrator.clone();
        let shutdown = shutdown_rx.clone();
        let idle_interval = *config.polite_interval;
        async move {
            run_scraper_loop(orchestrator, idle_interval, shutdown)
                .await
                .wrap_err("scraper orchestrator task")
        }
    });
    tasks.spawn({
        let orchestrator = orchestrator.clone();
        let shutdown = shutdown_rx.clone();
        async move {
            orchestrator
                .run_blocked_shield_resync_loop_or_shutdown(shutdown)
                .await
                .wrap_err("blocked-shield resync task")
        }
    });
    tasks.spawn({
        let poi_rpc_client = PoiRpcClient::new(
            url::Url::parse(&config.upstream_url).wrap_err("parse POI publication upstream URL")?,
        );
        let shutdown = shutdown_rx.clone();
        let scheduler = PublicationScheduler::new(
            config.clone(),
            store.clone(),
            ipfs_pinner.clone(),
            publisher_key,
            poi_rpc_client,
            Arc::new(v4_poi_ipns_publisher),
            status.clone(),
            pin_lifecycle.clone(),
        );
        async move {
            run_publication_scheduler(scheduler, shutdown)
                .await
                .wrap_err("publication scheduler task")
        }
    });
    if config.chain_indexed.enabled {
        tasks.spawn({
            let config = config.clone();
            let store = store.clone();
            let shutdown = shutdown_rx.clone();
            let chain_canonicality = chain_canonicality.clone();
            async move {
                chain_indexed::run_indexing_loop(config, store, chain_canonicality, shutdown)
                    .await
                    .wrap_err("chain-indexed RPC indexing task")
            }
        });
        let amount_statistics_ipns_publisher =
            spawn_amount_statistics_ipns(&mut tasks, &config, amount_statistics_ipns, &shutdown_rx);
        tasks.spawn({
            let config = config.clone();
            let store = store.clone();
            let ipfs_pinner = ipfs_pinner.clone();
            let shutdown = shutdown_rx.clone();
            let pin_lifecycle = pin_lifecycle.clone();
            let chain_canonicality = chain_canonicality.clone();
            let status = status.clone();
            async move {
                chain_indexed::run_publication_loop(
                    config,
                    store,
                    ipfs_pinner,
                    chain_indexed_publisher,
                    amount_statistics_ipns_publisher,
                    pin_lifecycle,
                    chain_canonicality,
                    status,
                    shutdown,
                )
                .await
                .wrap_err("chain-indexed artifact publication task")
            }
        });
    }
    tasks.spawn({
        let store = store.clone();
        let ipfs_pinner = ipfs_pinner.clone();
        let retention_interval =
            checked_interval(*config.retention_interval, "retention_interval")?;
        let shutdown = shutdown_rx.clone();
        let pin_lifecycle = pin_lifecycle.clone();
        let retention_status = status.clone();
        async move {
            run_retention_sweeper(
                store,
                ipfs_pinner,
                retention_interval,
                pin_lifecycle,
                retention_status,
                shutdown,
            )
            .await
            .wrap_err("retention sweeper task")
        }
    });
    tasks.spawn({
        let status = status.clone();
        let shutdown = shutdown_rx.clone();
        async move {
            serve_status(status_listener, status, shutdown)
                .await
                .wrap_err("status HTTP task")
        }
    });

    let first_exit = tokio::select! {
        result = wait_for_shutdown() => result.wrap_err("wait for shutdown signal"),
        result = next_task_result(&mut tasks) => result,
    };

    pin_lifecycle.stop_new_pin_ownership();
    if shutdown_tx.send(true).is_err() {
        info!("shutdown signal had no receivers");
    }

    let drain_result = drain_background_tasks(&mut tasks, &pin_lifecycle).await;
    match (first_exit, drain_result) {
        (Err(error), _) | (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

/// Starts the amount-statistics IPNS publisher task and returns its publisher when
/// amount-statistics publication is enabled.
fn spawn_amount_statistics_ipns(
    tasks: &mut JoinSet<Result<()>>,
    config: &Config,
    amount_statistics_ipns: (IpnsPublisher, IpnsPublisherTask),
    shutdown_rx: &watch::Receiver<bool>,
) -> Option<IpnsPublisher> {
    if config.chain_indexed.amount_statistics.enabled {
        let (publisher, task) = amount_statistics_ipns;
        spawn_ipns_task(
            tasks,
            task,
            shutdown_rx,
            "amount-statistics IPNS publisher task",
        );
        Some(publisher)
    } else {
        None
    }
}

/// Runs an IPNS publisher task as a background task until shutdown.
fn spawn_ipns_task(
    tasks: &mut JoinSet<Result<()>>,
    task: IpnsPublisherTask,
    shutdown_rx: &watch::Receiver<bool>,
    name: &'static str,
) {
    let shutdown = shutdown_rx.clone();
    tasks.spawn(async move { task.run(shutdown).await.wrap_err(name) });
}

async fn run_scraper_loop(
    orchestrator: Orchestrator,
    idle_interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        if shutdown_requested(&shutdown) {
            return Ok(());
        }

        if let Err(error) = orchestrator
            .run_until_caught_up_or_shutdown(shutdown.clone())
            .await
            .wrap_err("run scraper until caught up")
        {
            warn!(
                error = %format_report_chain(&error),
                "POI scraper cycle failed; backing off before retry"
            );
        }

        if sleep_or_shutdown(idle_interval, &mut shutdown).await {
            return Ok(());
        }
    }
}

async fn run_publication_scheduler(
    mut scheduler: PublicationScheduler,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    scheduler.shutdown = Some(shutdown.clone());
    let publish_interval = checked_interval(
        *scheduler.config.delta_publish_interval,
        "delta_publish_interval",
    )?;
    let mut interval = tokio::time::interval(publish_interval);

    loop {
        if interval_tick_or_shutdown(&mut interval, &mut shutdown).await {
            return Ok(());
        }

        match scheduler.publish_cycle(SystemTime::now()).await {
            Ok(()) => {}
            Err(error) => {
                scheduler.set_ipfs_reachable(false).await;
                info!(?error, "POI publication cycle failed");
            }
        }
        if shutdown_requested(&shutdown) {
            return Ok(());
        }
    }
}

async fn run_retention_sweeper(
    store: Store,
    ipfs_client: Arc<dyn IpfsClient>,
    retention_interval: Duration,
    pin_lifecycle: PinLifecycleCoordinator,
    status: SharedStatus,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let sweep_interval = retention_interval.min(RETENTION_SWEEP_INTERVAL_CAP);
    let mut interval = tokio::time::interval(sweep_interval);
    loop {
        if interval_tick_or_shutdown(&mut interval, &mut shutdown).await {
            return Ok(());
        }

        match Retention::sweep_with_coordinator(
            store.pool(),
            ipfs_client.as_ref(),
            SystemTime::now(),
            retention_interval,
            &pin_lifecycle,
        )
        .await
        {
            Ok(sweep) => {
                status
                    .write()
                    .await
                    .record_retention_sweep(sweep.unpinned_cids.len(), sweep.failed_cids.len());
                info!(
                    retention_interval_seconds = retention_interval.as_secs(),
                    unpinned_count = sweep.unpinned_cids.len(),
                    failed_count = sweep.failed_cids.len(),
                    "completed railgun-indexer retention sweep"
                );
            }
            Err(error) => info!(error = %error, "railgun-indexer retention sweep failed"),
        }
    }
}

struct PublicationScheduler {
    config: Config,
    store: Store,
    lifecycle: Lifecycle,
    ipfs_client: Arc<dyn IpfsClient>,
    signing_key: SigningKey,
    poi_rpc_client: PoiRpcClient,
    v4_ipns_publisher: Arc<dyn ManifestIpnsPublisher>,
    status: SharedStatus,
    pin_lifecycle: PinLifecycleCoordinator,
    sequence_allocator: PoiPublicationSequenceAllocator,
    last_poi_artifact_manifest_cid: Option<String>,
    last_poi_artifact_graph_hash: Option<[u8; 32]>,
    manifest_needs_publish: bool,
    last_ipns_publish_at: Option<SystemTime>,
    publication_state_loaded: bool,
    shutdown: Option<watch::Receiver<bool>>,
}

struct PublishedManifest {
    cid: String,
    sequence: u64,
}

struct PublishedPoiManifests {
    v4: PublishedManifest,
    poi_artifact_graph_cids: Vec<String>,
}

#[derive(Debug)]
struct PublishedPoiGraph {
    entries: Vec<PoiArtifactManifestEntry>,
    artifact_cids: Vec<String>,
    graph_hash: [u8; 32],
    checkpoint_chunks: usize,
    checkpoint_bytes: u64,
    tail_bytes: u64,
    bridge_count: usize,
    reused_cids: usize,
}

struct PublishedPoiEntry {
    entry: PoiArtifactManifestEntry,
    checkpoint_chunk_cids: Vec<String>,
    graph_cids: Vec<String>,
    checkpoint_bytes: u64,
    tail_bytes: u64,
    reused_cids: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingPoiPublicationReconciliation {
    None,
    Activated,
    Abandoned,
}

fn retain_recent_bridges(
    bridges: Vec<EventArtifactDescriptor>,
    active: &ActivePoiGraph,
    now: SystemTime,
) -> Result<Vec<EventArtifactDescriptor>> {
    let active_cids = active
        .entry
        .retained_bridges
        .iter()
        .map(|bridge| bridge.artifact.cid.as_str())
        .collect::<BTreeSet<_>>();
    let mut retained = Vec::new();
    for bridge in bridges {
        let published_at = match active.bridge_published_at.get(&bridge.artifact.cid) {
            Some(published_at) => *published_at,
            None if active_cids.contains(bridge.artifact.cid.as_str()) => {
                return Err(eyre!(
                    "active POI artifact bridge is missing durable publication time"
                ));
            }
            None => now,
        };
        if now
            .duration_since(published_at)
            .is_ok_and(|age| age <= V4_BRIDGE_RETENTION_TARGET)
        {
            retained.push(bridge);
        }
    }
    if retained.len() > MAX_RETAINED_BRIDGES {
        retained.drain(..retained.len() - MAX_RETAINED_BRIDGES);
    }
    Ok(retained)
}

fn poi_artifact_rotation_required(
    has_active_tail: bool,
    checkpoint_age: Option<Duration>,
    rotation_interval: Duration,
    current_tail_fits: bool,
) -> bool {
    (has_active_tail && checkpoint_age.is_some_and(|age| age >= rotation_interval))
        || !current_tail_fits
}

async fn cid_is_available(
    ipfs_client: &dyn IpfsClient,
    cid: &str,
    label: &'static str,
) -> Result<bool> {
    let parsed_cid = cid
        .parse()
        .wrap_err_with(|| format!("parse published {label} CID {cid}"))?;
    ipfs_client
        .contains(&parsed_cid)
        .await
        .wrap_err_with(|| format!("check published {label} CID availability {cid}"))
}

fn upstream_endpoint_hash(upstream_url: &str) -> [u8; 32] {
    Sha256::digest(upstream_url.as_bytes()).into()
}

fn list_key_hex(list_key: &FixedBytes<32>) -> String {
    hex::encode_prefixed(list_key.as_slice())
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

fn format_report_chain(error: &eyre::Report) -> String {
    error
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

fn status_router(status: SharedStatus) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/status", get(status_response))
        .with_state(status)
}

async fn health() -> &'static str {
    "ok"
}

async fn status_response(State(status): State<SharedStatus>) -> Json<Status> {
    Json(status.read().await.snapshot_at(SystemTime::now()))
}

async fn serve_status(
    listener: TcpListener,
    status: SharedStatus,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    axum::serve(listener, status_router(status))
        .with_graceful_shutdown(async move {
            wait_for_shutdown_rx(&mut shutdown).await;
        })
        .await
        .wrap_err("serve status HTTP")
}

async fn wait_for_shutdown_rx(shutdown: &mut watch::Receiver<bool>) {
    if shutdown_requested(shutdown) {
        return;
    }
    let _ = shutdown.changed().await;
}

async fn next_task_result(tasks: &mut JoinSet<Result<()>>) -> Result<()> {
    match tasks.join_next().await {
        Some(Ok(Ok(()))) => Err(eyre!("background task exited unexpectedly")),
        Some(Ok(Err(error))) => Err(error),
        Some(Err(error)) => Err(error).wrap_err("background task panicked"),
        None => Ok(()),
    }
}

async fn drain_background_tasks(
    tasks: &mut JoinSet<Result<()>>,
    pin_lifecycle: &PinLifecycleCoordinator,
) -> Result<()> {
    drain_background_tasks_with_timeout(tasks, BACKGROUND_TASK_FINAL_DRAIN_TIMEOUT, pin_lifecycle)
        .await
}

async fn drain_background_tasks_with_timeout(
    tasks: &mut JoinSet<Result<()>>,
    timeout: Duration,
    pin_lifecycle: &PinLifecycleCoordinator,
) -> Result<()> {
    let mut first_error = None;
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match tokio::time::timeout_at(deadline, tasks.join_next()).await {
            Ok(Some(result)) => record_background_task_result(result, &mut first_error, false),
            Ok(None) => return first_error.map_or(Ok(()), Err),
            Err(_) => break,
        }
    }

    if pin_lifecycle.active_pin_owners() > 0 {
        warn!(
            timeout_seconds = timeout.as_secs(),
            remaining_tasks = tasks.len(),
            active_pin_owners = pin_lifecycle.active_pin_owners(),
            "background task final drain deadline expired with active pin ownership; waiting for ownership to settle"
        );
        pin_lifecycle.wait_for_no_pin_owners().await;
    }
    warn!(
        timeout_seconds = timeout.as_secs(),
        remaining_tasks = tasks.len(),
        "aborting remaining non-owning background tasks after final drain"
    );
    tasks.abort_all();
    while let Some(result) = tasks.join_next().await {
        record_background_task_result(result, &mut first_error, true);
    }

    first_error.map_or(Ok(()), Err)
}

fn record_background_task_result(
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
    first_error: &mut Option<eyre::Report>,
    abort_expected: bool,
) {
    let error = match result {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(error),
        Err(error) if abort_expected && error.is_cancelled() => None,
        Err(error) => Some(eyre!(error).wrap_err("background task panicked")),
    };
    if first_error.is_none() {
        *first_error = error;
    }
}

fn shutdown_requested(shutdown: &watch::Receiver<bool>) -> bool {
    *shutdown.borrow()
}

async fn shutdown_changed_or_requested(shutdown: &mut watch::Receiver<bool>) -> bool {
    shutdown.changed().await.is_err() || shutdown_requested(shutdown)
}

async fn interval_tick_or_shutdown(
    interval: &mut tokio::time::Interval,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        _ = interval.tick() => shutdown_requested(shutdown),
        shutdown = shutdown_changed_or_requested(shutdown) => shutdown,
    }
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

#[cfg(unix)]
async fn wait_for_shutdown() -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate()).wrap_err("install SIGTERM handler")?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.wrap_err("listen for SIGINT")?;
        }
        _ = sigterm.recv() => {}
    }
    info!("shutdown signal received");
    Ok(())
}

#[cfg(not(unix))]
async fn wait_for_shutdown() -> Result<()> {
    tokio::signal::ctrl_c()
        .await
        .wrap_err("listen for shutdown signal")?;
    info!("shutdown signal received");
    Ok(())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod scheduler_tests;
