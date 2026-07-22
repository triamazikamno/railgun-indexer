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
use railgun_indexer_core::manifest::{
    ArtifactDescriptor, Manifest, ManifestEntry, RetainedDeltaDescriptor,
    load_publisher_signing_key,
};
use railgun_indexer_core::poi_v4::{
    PreparedEventArtifact, PublicationError, ValidatedCorpus,
    artifact_descriptor as poi_artifact_descriptor, checkpoint_catalog,
};
use railgun_indexer_core::publication_sequence::{
    PoiPublicationSequenceAllocator, PoiPublicationSequenceLease, run_dual_poi_publication_cycle,
};
use railgun_indexer_core::publish::ipfs::{
    FilebaseIpfsClient, IpfsClient, MultiPinner, pin_blocked_shields, pin_manifest,
    pin_snapshot_file,
};
use railgun_indexer_core::publish::ipns::{
    IpnsPublisher, IpnsPublisherConfig, IpnsPublisherTask, ManifestIpnsPublisher,
    v4_poi_public_identity, validate_publisher_identities,
};
use railgun_indexer_core::scrape::Orchestrator;
use railgun_indexer_core::snapshot::format::FORMAT_VERSION as SNAPSHOT_FORMAT_VERSION;
use railgun_indexer_core::snapshot::{Lifecycle, SnapshotKind};
use railgun_indexer_core::status::{SharedStatus, Status};
use railgun_indexer_core::store::{Store, StoredPublication, run_migrations};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::pool::PoolConnection;
use sqlx::postgres::{PgAdvisoryLock, PgAdvisoryLockGuard};
use sqlx::{Either, Postgres};
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

const FILEBASE_ACCESS_KEY_ENV: &str = "RAILGUN_INDEXER_FILEBASE_ACCESS_KEY";
const FILEBASE_SECRET_KEY_ENV: &str = "RAILGUN_INDEXER_FILEBASE_SECRET_KEY";
const FILEBASE_BUCKET_ENV: &str = "RAILGUN_INDEXER_FILEBASE_BUCKET";
const FILEBASE_REGION: &str = "us-east-1";
const FILEBASE_KEY_PREFIX: &str = "railgun-indexer";
const EVM_CHAIN_TYPE: u8 = 0;
const RETENTION_SWEEP_INTERVAL_CAP: Duration = Duration::from_mins(10);
const V4_BRIDGE_RETENTION_TARGET: Duration = Duration::from_hours(168);
const BACKGROUND_TASK_FINAL_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
const PUBLISHER_ADVISORY_LOCK_NAME: &str = "railgun-indexer/publication-owner/v1";

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
    Legacy,
    V4,
}

impl From<RecoveryChannel> for PoiManifestChannel {
    fn from(value: RecoveryChannel) -> Self {
        match value {
            RecoveryChannel::Legacy => Self::Legacy,
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
    let (ipns_publisher, ipns_task) = IpnsPublisher::new(&publisher_key, ipns_config.clone())
        .wrap_err("initialize legacy POI IPNS publisher")?;
    let (v4_poi_ipns_publisher, v4_poi_ipns_task) =
        IpnsPublisher::new_v4_poi(&publisher_key, ipns_config.clone())
            .wrap_err("initialize v4 POI IPNS publisher")?;
    let (chain_indexed_ipns_publisher, chain_indexed_ipns_task) =
        IpnsPublisher::new(&chain_indexed_publisher_key, ipns_config)
            .wrap_err("initialize chain-indexed IPNS publisher")?;
    validate_publisher_identities(
        &ipns_publisher,
        &v4_poi_ipns_publisher,
        &chain_indexed_ipns_publisher,
    )
    .wrap_err("validate publisher identities")?;
    let poi_ipns_name = ipns_publisher
        .ipns_name()
        .wrap_err("derive legacy POI IPNS name")?;
    let poi_v4_ipns_name = v4_poi_ipns_publisher
        .ipns_name()
        .wrap_err("derive v4 POI IPNS name")?;
    let chain_indexed_ipns_name = chain_indexed_ipns_publisher
        .ipns_name()
        .wrap_err("derive chain-indexed IPNS name")?;
    let poi_peer_id = ipns_publisher.peer_id().to_string();
    let poi_v4_peer_id = v4_poi_ipns_publisher.peer_id().to_string();
    let chain_indexed_peer_id = chain_indexed_ipns_publisher.peer_id().to_string();
    status.write().await.set_ipns_identities(
        poi_ipns_name.clone(),
        poi_v4_ipns_name.clone(),
        chain_indexed_ipns_name.clone(),
        poi_peer_id.clone(),
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
        poi_ipns_name,
        poi_v4_ipns_name,
        chain_indexed_ipns_name,
        poi_peer_id,
        poi_v4_peer_id,
        chain_indexed_peer_id,
        "loaded railgun indexer config"
    );

    run_background_tasks(
        config,
        store,
        orchestrator,
        publisher_key,
        chain_indexed_publisher_key,
        ipfs_pinner,
        ipns_publisher,
        ipns_task,
        v4_poi_ipns_publisher,
        v4_poi_ipns_task,
        chain_indexed_ipns_publisher,
        chain_indexed_ipns_task,
        status_listener,
        status,
    )
    .await
}

type PublisherLockGuard<'lock> = PgAdvisoryLockGuard<'lock, PoolConnection<Postgres>>;

async fn try_acquire_publisher_lock<'lock>(
    lock: &'lock PgAdvisoryLock,
    pool: &sqlx::PgPool,
) -> Result<PublisherLockGuard<'lock>> {
    match lock
        .try_acquire(
            pool.acquire()
                .await
                .wrap_err("acquire publisher lock connection")?,
        )
        .await
        .wrap_err("try publisher advisory lock")?
    {
        Either::Left(guard) => Ok(guard),
        Either::Right(_) => Err(eyre!(
            "publisher advisory lock is held; stop the publisher before running this process"
        )),
    }
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct V4PoiPublicIdentityOutput {
    manifest_signing_public_key: String,
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
    let output = V4PoiPublicIdentityOutput {
        manifest_signing_public_key: hex::encode_prefixed(signing_key.verifying_key().to_bytes()),
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
    chain_indexed_publisher_key: SigningKey,
    ipfs_pinner: Arc<dyn IpfsClient>,
    ipns_publisher: IpnsPublisher,
    ipns_task: IpnsPublisherTask,
    v4_poi_ipns_publisher: IpnsPublisher,
    v4_poi_ipns_task: IpnsPublisherTask,
    chain_indexed_ipns_publisher: IpnsPublisher,
    chain_indexed_ipns_task: IpnsPublisherTask,
    status_listener: TcpListener,
    status: SharedStatus,
) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut tasks = JoinSet::new();
    let pin_lifecycle = PinLifecycleCoordinator::default();
    let chain_canonicality = ChainCanonicalityCoordinator::default();

    tasks.spawn({
        let shutdown = shutdown_rx.clone();
        async move {
            ipns_task
                .run(shutdown)
                .await
                .wrap_err("POI IPNS publisher task")
        }
    });
    tasks.spawn({
        let shutdown = shutdown_rx.clone();
        async move {
            v4_poi_ipns_task
                .run(shutdown)
                .await
                .wrap_err("v4 POI IPNS publisher task")
        }
    });
    tasks.spawn({
        let shutdown = shutdown_rx.clone();
        async move {
            chain_indexed_ipns_task
                .run(shutdown)
                .await
                .wrap_err("chain-indexed IPNS publisher task")
        }
    });
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
            Arc::new(ipns_publisher),
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
        tasks.spawn({
            let config = config.clone();
            let store = store.clone();
            let ipfs_pinner = ipfs_pinner.clone();
            let shutdown = shutdown_rx.clone();
            let pin_lifecycle = pin_lifecycle.clone();
            let chain_canonicality = chain_canonicality.clone();
            async move {
                chain_indexed::run_publication_loop(
                    config,
                    store,
                    ipfs_pinner,
                    chain_indexed_publisher_key,
                    chain_indexed_ipns_publisher,
                    pin_lifecycle,
                    chain_canonicality,
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
    ipns_publisher: Arc<dyn ManifestIpnsPublisher>,
    v4_ipns_publisher: Arc<dyn ManifestIpnsPublisher>,
    status: SharedStatus,
    pin_lifecycle: PinLifecycleCoordinator,
    sequence_allocator: PoiPublicationSequenceAllocator,
    last_manifest_cid: Option<String>,
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
    legacy: Option<PublishedManifest>,
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

impl PublicationScheduler {
    fn new(
        config: Config,
        store: Store,
        ipfs_client: Arc<dyn IpfsClient>,
        signing_key: SigningKey,
        poi_rpc_client: PoiRpcClient,
        ipns_publisher: Arc<dyn ManifestIpnsPublisher>,
        v4_ipns_publisher: Arc<dyn ManifestIpnsPublisher>,
        status: SharedStatus,
        pin_lifecycle: PinLifecycleCoordinator,
    ) -> Self {
        let lifecycle = Lifecycle::new(
            store.clone(),
            config.upstream_url.clone(),
            EVM_CHAIN_TYPE,
            upstream_endpoint_hash(&config.upstream_url),
        );
        let sequence_allocator = PoiPublicationSequenceAllocator::new(store.clone());

        Self {
            config,
            store,
            lifecycle,
            ipfs_client,
            signing_key,
            poi_rpc_client,
            ipns_publisher,
            v4_ipns_publisher,
            status,
            pin_lifecycle,
            sequence_allocator,
            last_manifest_cid: None,
            last_poi_artifact_manifest_cid: None,
            last_poi_artifact_graph_hash: None,
            manifest_needs_publish: true,
            last_ipns_publish_at: None,
            publication_state_loaded: false,
            shutdown: None,
        }
    }

    fn ensure_publication_running(&self) -> Result<()> {
        if self.shutdown.as_ref().is_some_and(shutdown_requested) {
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
        let reconciled = self.reconcile_pending_poi_publications().await?;
        if !self.publication_state_loaded || reconciled {
            self.load_durable_publication_state().await?;
            self.publication_state_loaded = true;
        }
        if reconciled {
            return Ok(());
        }

        let mut published_snapshot = false;
        for list_key in &self.config.list_keys {
            for chain_id in &self.config.chain_ids {
                self.ensure_publication_running()?;
                match self.publish_pair(list_key, *chain_id, now).await {
                    Ok(pair_published) => {
                        if pair_published {
                            published_snapshot = true;
                            self.manifest_needs_publish = true;
                        }
                    }
                    Err(error) => {
                        self.set_ipfs_reachable(false).await;
                        warn!(
                            list_key = %list_key_hex(list_key),
                            chain_id,
                            error = %error,
                            "POI snapshot publication failed for pair; continuing cycle"
                        );
                    }
                }
            }
        }

        self.ensure_publication_running()?;
        let poi_artifact_started = std::time::Instant::now();
        let poi_graph = self.publish_poi_artifact_graph(now).await?;
        self.ensure_publication_running()?;
        let legacy_entries = self.manifest_entries().await?;
        let graph_changed = self
            .last_poi_artifact_graph_hash
            .is_none_or(|hash| hash != poi_graph.graph_hash);
        let legacy_missing = !legacy_entries.is_empty() && self.last_manifest_cid.is_none();
        let mut needs_publication = published_snapshot
            || self.manifest_needs_publish
            || legacy_missing
            || self.last_poi_artifact_manifest_cid.is_none()
            || graph_changed
            || self.should_republish_ipns(now);
        if !needs_publication {
            let mut current_manifests = vec![
                self.last_poi_artifact_manifest_cid
                    .as_ref()
                    .expect("POI artifact manifest CID checked above")
                    .as_str(),
            ];
            if let Some(legacy) = self.last_manifest_cid.as_deref() {
                current_manifests.push(legacy);
            }
            for cid in current_manifests {
                if !self.cid_is_available(cid, "manifest").await? {
                    needs_publication = true;
                    break;
                }
            }
        }
        if !needs_publication {
            return Ok(());
        }

        let lease = self
            .sequence_allocator
            .reserve_cycle(unix_millis(now)?)
            .await
            .wrap_err("reserve dual POI publication sequence")?;
        let manifests = self
            .publish_poi_manifests(now, lease, legacy_entries, &poi_graph)
            .await?;
        self.ensure_publication_running()?;
        self.publish_poi_ipns(lease, &manifests).await?;
        self.last_manifest_cid = manifests
            .legacy
            .as_ref()
            .map(|manifest| manifest.cid.clone());
        self.last_poi_artifact_manifest_cid = Some(manifests.v4.cid.clone());
        self.last_poi_artifact_graph_hash = Some(poi_graph.graph_hash);
        self.manifest_needs_publish = false;
        self.last_ipns_publish_at = Some(now);
        self.status.write().await.record_poi_artifact_publication(
            manifests.v4.cid.clone(),
            manifests.v4.sequence,
            &poi_graph.entries,
            poi_graph.checkpoint_chunks,
            poi_graph.checkpoint_bytes,
            poi_graph.tail_bytes,
            poi_graph.bridge_count,
            poi_graph.reused_cids,
            u64::try_from(poi_artifact_started.elapsed().as_millis()).unwrap_or(u64::MAX),
        );
        info!(
            sequence = lease.sequence(),
            checkpoint_chunks = poi_graph.checkpoint_chunks,
            checkpoint_bytes = poi_graph.checkpoint_bytes,
            tail_bytes = poi_graph.tail_bytes,
            bridges = poi_graph.bridge_count,
            reused_cids = poi_graph.reused_cids,
            elapsed_ms = poi_artifact_started.elapsed().as_millis(),
            "published dual POI cycle"
        );
        Ok(())
    }

    async fn publish_pair(
        &self,
        list_key: &alloy_primitives::FixedBytes<32>,
        chain_id: u64,
        now: SystemTime,
    ) -> Result<bool> {
        let Some(tip) = self
            .store
            .chain_tip(list_key, chain_id, &self.config.upstream_url)
            .await
            .wrap_err("read chain tip for publication")?
        else {
            return Ok(false);
        };
        let Some(tip_merkleroot) = tip.last_tip_merkleroot else {
            return Ok(false);
        };
        let publications = self
            .store
            .active_publications(list_key, chain_id, &self.config.upstream_url)
            .await
            .wrap_err("read active snapshot publications")?;
        let active_base = active_base(&publications);
        let current_publications = current_manifest_publications(&publications);
        let last_published_tip = published_tip(&current_publications);

        if last_published_tip.is_some_and(|published_tip| tip.last_event_index < published_tip) {
            info!(
                list_key = %list_key_hex(list_key),
                chain_id,
                chain_tip = tip.last_event_index,
                published_tip = last_published_tip,
                "skipping publication because active snapshots are ahead of chain tip"
            );
            return Ok(false);
        }

        let published_snapshot = if let Some(missing_cid) = first_missing_publication_cid(
            self.ipfs_client.as_ref(),
            &publications,
            list_key,
            chain_id,
        )
        .await?
        {
            warn!(
                list_key = %list_key_hex(list_key),
                chain_id,
                missing_cid,
                "active POI snapshot CID is missing from IPFS service; rebuilding base snapshot"
            );
            self.publish_snapshot(
                list_key,
                chain_id,
                SnapshotKind::Base,
                0,
                tip.last_event_index,
                &tip_merkleroot,
            )
            .await?;
            true
        } else {
            let should_rebuild_base = active_base.is_none_or(|base| {
                Lifecycle::should_rebuild_base(
                    Some(base.published_at),
                    now,
                    *self.config.base_rebuild_interval,
                )
            });
            if should_rebuild_base {
                self.publish_snapshot(
                    list_key,
                    chain_id,
                    SnapshotKind::Base,
                    0,
                    tip.last_event_index,
                    &tip_merkleroot,
                )
                .await?;
                true
            } else if let Some(published_tip) = last_published_tip
                && tip.last_event_index > published_tip
            {
                self.publish_snapshot(
                    list_key,
                    chain_id,
                    SnapshotKind::Delta,
                    published_tip + 1,
                    tip.last_event_index,
                    &tip_merkleroot,
                )
                .await?;
                true
            } else {
                false
            }
        };

        let published_blocked_shields = self
            .publish_blocked_shields_artifact(list_key, chain_id)
            .await?;

        Ok(published_snapshot || published_blocked_shields)
    }

    async fn publish_snapshot(
        &self,
        list_key: &alloy_primitives::FixedBytes<32>,
        chain_id: u64,
        kind: SnapshotKind,
        start_index: u64,
        end_index: u64,
        tip_merkleroot: &[u8; 32],
    ) -> Result<()> {
        self.ensure_publication_running()?;
        let bytes = match kind {
            SnapshotKind::Base => self
                .lifecycle
                .build_base(list_key, chain_id, end_index)
                .await
                .wrap_err("build base snapshot")?,
            SnapshotKind::Delta => self
                .lifecycle
                .build_delta(list_key, chain_id, start_index, end_index)
                .await
                .wrap_err("build delta snapshot")?,
        };
        self.ensure_publication_running()?;
        let pin_lifecycle_guard = self.pin_lifecycle.lock().await;
        let ownership = self.acquire_pin_ownership()?;
        let cid = match pin_snapshot_file(self.ipfs_client.as_ref(), &bytes).await {
            Ok(cid) => cid,
            Err(error) => {
                ownership.settle();
                return Err(error).wrap_err("pin snapshot to IPFS");
            }
        };
        let audit_result = async {
            let byte_size = u64::try_from(bytes.len()).wrap_err("snapshot byte size overflow")?;
            let artifact_hash = content_hash(&bytes);
            let mut tx = self
                .store
                .begin()
                .await
                .wrap_err("begin audit transaction")?;
            Audit::record_publication(
                &mut tx,
                list_key,
                chain_id,
                &self.config.upstream_url,
                kind,
                start_index,
                end_index,
                &cid,
                byte_size,
                &artifact_hash,
                SNAPSHOT_FORMAT_VERSION,
                tip_merkleroot,
            )
            .await
            .wrap_err("record snapshot publication")?;
            tx.commit()
                .await
                .wrap_err("commit snapshot publication audit")?;
            Ok::<_, eyre::Report>((byte_size, artifact_hash))
        }
        .await;
        let (byte_size, artifact_hash) = match audit_result {
            Ok(result) => result,
            Err(error) => {
                self.cleanup_uncommitted_pin_while_locked(&cid, "snapshot", ownership)
                    .await;
                return Err(error);
            }
        };
        ownership.settle();
        drop(pin_lifecycle_guard);
        self.ensure_publication_running()?;

        info!(
            list_key = %list_key_hex(list_key),
            chain_id,
            kind = snapshot_kind_label(kind),
            start_index,
            end_index,
            byte_size,
            sha256 = %hex::encode_prefixed(artifact_hash),
            cid = %cid,
            "published POI snapshot"
        );
        Ok(())
    }

    async fn publish_blocked_shields_artifact(
        &self,
        list_key: &alloy_primitives::FixedBytes<32>,
        chain_id: u64,
    ) -> Result<bool> {
        self.ensure_publication_running()?;
        let artifact = self
            .lifecycle
            .build_blocked_shields_artifact(list_key, chain_id)
            .await
            .wrap_err("build blocked-shields artifact")?;
        let bytes = artifact.bytes;
        let artifact_hash = content_hash(&bytes);
        let active = self
            .store
            .active_blocked_shields_publication(list_key, chain_id, &self.config.upstream_url)
            .await
            .wrap_err("read active blocked-shields publication")?;

        if let Some(active) = &active
            && active.content_hash == artifact_hash
        {
            if self
                .cid_is_available(&active.cid, "blocked-shields")
                .await?
            {
                return Ok(false);
            }
            warn!(
                list_key = %list_key_hex(list_key),
                chain_id,
                cid = %active.cid,
                "active blocked-shields artifact CID is missing from IPFS service; repinning"
            );
        }

        self.ensure_publication_running()?;
        let pin_lifecycle_guard = self.pin_lifecycle.lock().await;
        let ownership = self.acquire_pin_ownership()?;
        let cid = match pin_blocked_shields(self.ipfs_client.as_ref(), &bytes).await {
            Ok(cid) => cid,
            Err(error) => {
                ownership.settle();
                return Err(error).wrap_err("pin blocked-shields artifact to IPFS");
            }
        };
        let audit_result = async {
            let byte_size = u64::try_from(bytes.len())
                .wrap_err("blocked-shields artifact byte size overflow")?;
            let mut tx = self
                .store
                .begin()
                .await
                .wrap_err("begin blocked-shields audit transaction")?;
            Audit::record_blocked_shields_publication(
                &mut tx,
                list_key,
                chain_id,
                &self.config.upstream_url,
                &cid,
                byte_size,
                SNAPSHOT_FORMAT_VERSION,
                &artifact_hash,
            )
            .await
            .wrap_err("record blocked-shields publication")?;
            tx.commit()
                .await
                .wrap_err("commit blocked-shields publication audit")?;
            Ok::<_, eyre::Report>(byte_size)
        }
        .await;
        let byte_size = match audit_result {
            Ok(byte_size) => byte_size,
            Err(error) => {
                self.cleanup_uncommitted_pin_while_locked(&cid, "blocked-shields", ownership)
                    .await;
                return Err(error);
            }
        };
        ownership.settle();
        drop(pin_lifecycle_guard);
        self.ensure_publication_running()?;

        info!(
            list_key = %list_key_hex(list_key),
            chain_id,
            byte_size,
            blocked_shield_count = artifact.row_count,
            cid = %cid,
            "published blocked-shields artifact"
        );
        Ok(true)
    }

    async fn publish_poi_artifact_graph(&self, now: SystemTime) -> Result<PublishedPoiGraph> {
        let mut corpora = Vec::new();
        for list_key in &self.config.list_keys {
            for chain_id in &self.config.chain_ids {
                let scope = Scope::new(
                    *list_key,
                    EVM_CHAIN_TYPE,
                    *chain_id,
                    self.config.txid_version.clone(),
                );
                let tip = self
                    .store
                    .chain_tip(list_key, *chain_id, &self.config.upstream_url)
                    .await
                    .wrap_err("read POI tip for v4 publication")?;
                let (stored_events, expected_root) = if let Some(tip) = tip {
                    let root = tip
                        .last_tip_merkleroot
                        .ok_or_else(|| eyre!("nonempty POI tip is missing upstream root"))?;
                    (
                        self.store
                            .page_event_range(list_key, *chain_id, 0, tip.last_event_index)
                            .await
                            .wrap_err("read stored POI events for v4 replay")?,
                        Some(FixedBytes::from(root)),
                    )
                } else {
                    (Vec::new(), None)
                };
                corpora.push(
                    ValidatedCorpus::replay(scope, &stored_events, expected_root)
                        .wrap_err("validate stored POI event corpus")?,
                );
            }
        }

        for corpus in &mut corpora {
            if corpus.event_count() == 0 {
                continue;
            }
            let roots = corpus.current_roots();
            let root_hexes = roots.values().map(hex::encode).collect::<Vec<_>>();
            let scope = corpus.scope();
            let accepted = self
                .poi_rpc_client
                .validate_poi_merkleroots(
                    &scope.txid_version,
                    scope.chain_type,
                    scope.chain_id,
                    &scope.list_key,
                    &root_hexes,
                )
                .await
                .wrap_err("revalidate replayed POI roots before v4 publication")?;
            if !accepted {
                return Err(eyre!(
                    "upstream rejected replayed POI roots for list_key={} chain_id={}",
                    list_key_hex(&scope.list_key),
                    scope.chain_id
                ));
            }
        }

        let mut entries = Vec::new();
        let mut artifact_cids = BTreeSet::new();
        let mut checkpoint_chunks = 0usize;
        let mut checkpoint_bytes = 0_u64;
        let mut tail_bytes = 0_u64;
        let mut bridge_count = 0usize;
        let mut reused_cids = 0usize;

        for corpus in &corpora {
            self.ensure_publication_running()?;
            let active = Audit::active_poi_graph(self.store.pool(), corpus.scope())
                .await
                .wrap_err("load active POI v4 graph")?;
            let published = self
                .publish_poi_artifact_entry(now, corpus, active.as_ref())
                .await?;
            checkpoint_chunks += published.checkpoint_chunk_cids.len();
            checkpoint_bytes = checkpoint_bytes
                .checked_add(published.checkpoint_bytes)
                .ok_or_else(|| eyre!("POI checkpoint byte total overflow"))?;
            tail_bytes = tail_bytes
                .checked_add(published.tail_bytes)
                .ok_or_else(|| eyre!("POI tail byte total overflow"))?;
            bridge_count += published.entry.retained_bridges.len();
            reused_cids += published.reused_cids;
            artifact_cids.extend(published.checkpoint_chunk_cids);
            artifact_cids.extend(published.graph_cids);
            entries.push(published.entry);
        }
        entries.sort_by(|left, right| left.scope.cmp(&right.scope));
        let graph_bytes =
            serde_json::to_vec(&entries).wrap_err("serialize POI artifact graph identity")?;
        Ok(PublishedPoiGraph {
            entries,
            artifact_cids: artifact_cids.into_iter().collect(),
            graph_hash: content_hash(&graph_bytes),
            checkpoint_chunks,
            checkpoint_bytes,
            tail_bytes,
            bridge_count,
            reused_cids,
        })
    }

    async fn publish_poi_artifact_entry(
        &self,
        now: SystemTime,
        corpus: &ValidatedCorpus,
        active: Option<&ActivePoiGraph>,
    ) -> Result<PublishedPoiEntry> {
        let event_count = corpus.event_count();
        if let Some(active) = active {
            active
                .entry
                .validate()
                .wrap_err("validate active POI artifact entry")?;
            if active.entry.event_count > event_count {
                return Err(eyre!(
                    "stored POI event count {event_count} regresses active POI artifact count {}",
                    active.entry.event_count
                ));
            }
            if active.entry.event_count > 0 {
                let active_tip = active.entry.event_count - 1;
                let replayed = corpus.root_at(active_tip)?;
                if active.entry.current_root != Some(replayed) {
                    return Err(eyre!(
                        "stored POI prefix conflicts with active POI artifact root"
                    ));
                }
            }
        }

        let mut checkpoint_event_count = active.map_or(event_count, |graph| {
            graph.entry.checkpoint_catalog.row_count
        });
        let mut retained_bridges = active
            .map(|graph| graph.entry.retained_bridges.clone())
            .unwrap_or_default();
        let current_tail_fits = if checkpoint_event_count < event_count {
            match corpus.prepare_event_artifact(
                EventArtifactKind::CurrentTail,
                checkpoint_event_count,
                event_count - 1,
            ) {
                Ok(_) => true,
                Err(PublicationError::Contract(
                    PoiArtifactError::EventArtifactByteLimitExceeded { .. },
                )) => false,
                Err(error) => return Err(error.into()),
            }
        } else {
            true
        };
        let rotate = active.is_some_and(|graph| {
            poi_artifact_rotation_required(
                graph.entry.current_tail.is_some(),
                now.duration_since(graph.checkpoint_published_at).ok(),
                *self.config.base_rebuild_interval,
                current_tail_fits,
            )
        });
        let mut reused_cids = 0usize;

        if rotate {
            let graph =
                active.ok_or_else(|| eyre!("POI artifact rotation requires an active graph"))?;
            let prior_checkpoint_count = graph.entry.checkpoint_catalog.row_count;
            let prior_event_count = graph.entry.event_count;
            // Only the previously published current tail may become a bridge. Advancing the
            // checkpoint past prior_event_count or splitting the unseen suffix into synthetic
            // bridges would violate the v4 graph contract, so an oversized new suffix fails closed.
            if prior_event_count > prior_checkpoint_count {
                let bridge = corpus.prepare_event_artifact(
                    EventArtifactKind::Bridge,
                    prior_checkpoint_count,
                    prior_event_count - 1,
                )?;
                let (bridge, reused) = self
                    .publish_poi_event_artifact(PoiArtifactPublicationKind::Bridge, &bridge)
                    .await?;
                reused_cids += usize::from(reused);
                retained_bridges.push(bridge);
            }
            checkpoint_event_count = prior_event_count;
            retained_bridges = retain_recent_bridges(retained_bridges, graph, now)?;
        }

        let prepared_chunks = corpus.prepare_checkpoint(checkpoint_event_count)?;
        let mut checkpoint_descriptors = Vec::with_capacity(prepared_chunks.len());
        let mut checkpoint_chunk_cids = Vec::with_capacity(prepared_chunks.len());
        let mut checkpoint_bytes = 0_u64;
        for chunk in &prepared_chunks {
            let (descriptor, reused) = self
                .publish_poi_event_artifact(PoiArtifactPublicationKind::CheckpointChunk, chunk)
                .await?;
            checkpoint_bytes = checkpoint_bytes
                .checked_add(descriptor.artifact.byte_size)
                .ok_or_else(|| eyre!("POI checkpoint byte total overflow"))?;
            reused_cids += usize::from(reused);
            checkpoint_chunk_cids.push(descriptor.artifact.cid.clone());
            checkpoint_descriptors.push(descriptor);
        }
        let (catalog, catalog_bytes) =
            checkpoint_catalog(corpus.scope().clone(), checkpoint_descriptors)?;
        let scope = catalog.scope.clone();
        let (checkpoint_catalog, catalog_reused) = self
            .publish_poi_checkpoint_catalog(&catalog, &catalog_bytes)
            .await?;
        reused_cids += usize::from(catalog_reused);

        let current_tail = if checkpoint_event_count < event_count {
            let prepared = corpus.prepare_event_artifact(
                EventArtifactKind::CurrentTail,
                checkpoint_event_count,
                event_count - 1,
            )?;
            let (descriptor, reused) = self
                .publish_poi_event_artifact(PoiArtifactPublicationKind::CurrentTail, &prepared)
                .await?;
            reused_cids += usize::from(reused);
            Some(descriptor)
        } else {
            None
        };
        let tail_bytes = current_tail
            .as_ref()
            .map_or(0, |tail| tail.artifact.byte_size);
        let (blocked_shields, blocked_reused) = self.publish_poi_blocked_shields(&scope).await?;
        reused_cids += usize::from(blocked_reused);
        let current_tip_index = event_count.checked_sub(1);
        let current_root = current_tip_index
            .map(|index| corpus.root_at(index))
            .transpose()?;
        let entry = PoiArtifactManifestEntry {
            scope,
            event_count,
            current_tip_index,
            current_root,
            checkpoint_catalog,
            current_tail,
            retained_bridges,
            blocked_shields,
        };
        entry
            .validate()
            .wrap_err("validate prepared POI artifact entry")?;
        let mut graph_cids = vec![
            entry.checkpoint_catalog.artifact.cid.clone(),
            entry.blocked_shields.artifact.cid.clone(),
        ];
        graph_cids.extend(
            entry
                .retained_bridges
                .iter()
                .map(|bridge| bridge.artifact.cid.clone()),
        );
        if let Some(tail) = &entry.current_tail {
            graph_cids.push(tail.artifact.cid.clone());
        }
        Ok(PublishedPoiEntry {
            entry,
            checkpoint_chunk_cids,
            graph_cids,
            checkpoint_bytes,
            tail_bytes,
            reused_cids,
        })
    }

    async fn publish_poi_event_artifact(
        &self,
        kind: PoiArtifactPublicationKind,
        prepared: &PreparedEventArtifact,
    ) -> Result<(EventArtifactDescriptor, bool)> {
        self.ensure_publication_running()?;
        let byte_size = u64::try_from(prepared.bytes.len())
            .wrap_err("POI event artifact byte size overflow")?;
        let _pin_lifecycle = self.pin_lifecycle.lock().await;
        let reusable = Audit::live_poi_artifact_cid(
            self.store.pool(),
            kind,
            &prepared.artifact.scope,
            Some(prepared.artifact.range),
            byte_size,
            &prepared.sha256,
            Some(&prepared.artifact.end_root),
        )
        .await?;
        let (cid, reused, ownership) = if let Some(cid) = reusable {
            if self.ipfs_client.contains(&cid).await? {
                (cid, true, None)
            } else {
                let ownership = self.acquire_pin_ownership()?;
                match self.ipfs_client.pin_bytes(&prepared.bytes).await {
                    Ok(returned) => (returned, false, Some(ownership)),
                    Err(error) => {
                        ownership.settle();
                        return Err(error.into());
                    }
                }
            }
        } else {
            let ownership = self.acquire_pin_ownership()?;
            match self.ipfs_client.pin_bytes(&prepared.bytes).await {
                Ok(returned) => (returned, false, Some(ownership)),
                Err(error) => {
                    ownership.settle();
                    return Err(error.into());
                }
            }
        };
        let audit_result = async {
            let descriptor = prepared.descriptor(cid.to_string())?;
            let mut tx = self.store.begin().await?;
            Audit::record_poi_artifact_pin(
                &mut tx,
                kind,
                &descriptor.scope,
                Some(descriptor.range),
                &cid,
                descriptor.artifact.byte_size,
                &prepared.sha256,
                Some(&descriptor.end_root),
                &serde_json::to_string(&descriptor)?,
            )
            .await?;
            tx.commit().await?;
            Ok::<_, eyre::Report>(descriptor)
        }
        .await;
        let descriptor = match audit_result {
            Ok(descriptor) => descriptor,
            Err(error) => {
                if let Some(ownership) = ownership {
                    self.cleanup_uncommitted_pin_while_locked(
                        &cid,
                        "POI event artifact",
                        ownership,
                    )
                    .await;
                }
                return Err(error);
            }
        };
        if let Some(ownership) = ownership {
            ownership.settle();
        }
        self.ensure_publication_running()?;
        Ok((descriptor, reused))
    }

    async fn publish_poi_checkpoint_catalog(
        &self,
        catalog: &CheckpointCatalog,
        bytes: &[u8],
    ) -> Result<(CheckpointCatalogDescriptor, bool)> {
        self.ensure_publication_running()?;
        let byte_size =
            u64::try_from(bytes.len()).wrap_err("POI checkpoint catalog byte size overflow")?;
        let hash = content_hash(bytes);
        let _pin_lifecycle = self.pin_lifecycle.lock().await;
        let reusable = Audit::live_poi_artifact_cid(
            self.store.pool(),
            PoiArtifactPublicationKind::CheckpointCatalog,
            &catalog.scope,
            catalog.range,
            byte_size,
            &hash,
            catalog.checkpoint_root.as_ref(),
        )
        .await?;
        let (cid, reused, ownership) = if let Some(cid) = reusable {
            if self.ipfs_client.contains(&cid).await? {
                (cid, true, None)
            } else {
                let ownership = self.acquire_pin_ownership()?;
                match self.ipfs_client.pin_bytes(bytes).await {
                    Ok(returned) => (returned, false, Some(ownership)),
                    Err(error) => {
                        ownership.settle();
                        return Err(error.into());
                    }
                }
            }
        } else {
            let ownership = self.acquire_pin_ownership()?;
            match self.ipfs_client.pin_bytes(bytes).await {
                Ok(returned) => (returned, false, Some(ownership)),
                Err(error) => {
                    ownership.settle();
                    return Err(error.into());
                }
            }
        };
        let audit_result = async {
            let descriptor = catalog.descriptor(cid.to_string())?;
            let mut tx = self.store.begin().await?;
            Audit::record_poi_artifact_pin(
                &mut tx,
                PoiArtifactPublicationKind::CheckpointCatalog,
                &catalog.scope,
                catalog.range,
                &cid,
                byte_size,
                &hash,
                catalog.checkpoint_root.as_ref(),
                &serde_json::to_string(&descriptor)?,
            )
            .await?;
            tx.commit().await?;
            Ok::<_, eyre::Report>(descriptor)
        }
        .await;
        let descriptor = match audit_result {
            Ok(descriptor) => descriptor,
            Err(error) => {
                if let Some(ownership) = ownership {
                    self.cleanup_uncommitted_pin_while_locked(
                        &cid,
                        "POI checkpoint catalog",
                        ownership,
                    )
                    .await;
                }
                return Err(error);
            }
        };
        if let Some(ownership) = ownership {
            ownership.settle();
        }
        self.ensure_publication_running()?;
        Ok((descriptor, reused))
    }

    async fn publish_poi_blocked_shields(
        &self,
        scope: &Scope,
    ) -> Result<(BlockedShieldsDescriptor, bool)> {
        self.ensure_publication_running()?;
        let artifact = self
            .lifecycle
            .build_poi_blocked_shields_artifact(scope)
            .await?;
        let bytes = artifact.bytes;
        let byte_size = u64::try_from(bytes.len())
            .wrap_err("POI blocked-shields artifact byte size overflow")?;
        let hash = content_hash(&bytes);
        let row_count = u64::try_from(artifact.row_count)
            .wrap_err("POI blocked-shields artifact row count overflow")?;
        let _pin_lifecycle = self.pin_lifecycle.lock().await;
        let reusable = Audit::live_poi_artifact_cid(
            self.store.pool(),
            PoiArtifactPublicationKind::BlockedShields,
            scope,
            None,
            byte_size,
            &hash,
            None,
        )
        .await?;
        let (cid, reused, ownership) = if let Some(cid) = reusable {
            if self.ipfs_client.contains(&cid).await? {
                (cid, true, None)
            } else {
                let ownership = self.acquire_pin_ownership()?;
                match self.ipfs_client.pin_bytes(&bytes).await {
                    Ok(returned) => (returned, false, Some(ownership)),
                    Err(error) => {
                        ownership.settle();
                        return Err(error.into());
                    }
                }
            }
        } else {
            let ownership = self.acquire_pin_ownership()?;
            match self.ipfs_client.pin_bytes(&bytes).await {
                Ok(returned) => (returned, false, Some(ownership)),
                Err(error) => {
                    ownership.settle();
                    return Err(error.into());
                }
            }
        };
        let audit_result = async {
            let descriptor = BlockedShieldsDescriptor {
                artifact: poi_artifact_descriptor(cid.to_string(), &bytes),
                format_version: POI_ARTIFACT_FORMAT_VERSION,
                scope: scope.clone(),
                row_count,
                encoding: ArtifactEncoding::CanonicalJson,
                compression: Compression::Identity,
            };
            descriptor.validate()?;
            let mut tx = self.store.begin().await?;
            Audit::record_poi_artifact_pin(
                &mut tx,
                PoiArtifactPublicationKind::BlockedShields,
                scope,
                None,
                &cid,
                byte_size,
                &hash,
                None,
                &serde_json::to_string(&descriptor)?,
            )
            .await?;
            tx.commit().await?;
            Ok::<_, eyre::Report>(descriptor)
        }
        .await;
        let descriptor = match audit_result {
            Ok(descriptor) => descriptor,
            Err(error) => {
                if let Some(ownership) = ownership {
                    self.cleanup_uncommitted_pin_while_locked(
                        &cid,
                        "POI blocked-shields artifact",
                        ownership,
                    )
                    .await;
                }
                return Err(error);
            }
        };
        if let Some(ownership) = ownership {
            ownership.settle();
        }
        self.ensure_publication_running()?;
        Ok((descriptor, reused))
    }

    async fn publish_poi_manifests(
        &self,
        now: SystemTime,
        lease: PoiPublicationSequenceLease,
        legacy_entries: Vec<ManifestEntry>,
        poi_graph: &PublishedPoiGraph,
    ) -> Result<PublishedPoiManifests> {
        self.ensure_publication_running()?;
        let issued_at_ms = unix_millis(now)?;
        let legacy = if legacy_entries.is_empty() {
            None
        } else {
            let mut manifest = Manifest::new(
                SNAPSHOT_FORMAT_VERSION,
                issued_at_ms,
                lease.legacy_manifest_sequence(),
                FixedBytes::ZERO,
                legacy_entries,
            );
            manifest
                .sign_manifest(&self.signing_key)
                .wrap_err("sign unchanged legacy POI manifest")?;
            Some(serde_json::to_vec(&manifest).wrap_err("serialize legacy POI manifest")?)
        };
        let mut poi_manifest = PoiArtifactManifest::new(
            issued_at_ms,
            lease.v4_manifest_sequence(),
            FixedBytes::ZERO,
            poi_graph.entries.clone(),
        );
        poi_manifest
            .sign_manifest(&self.signing_key)
            .wrap_err("sign POI v4 manifest")?;
        let poi_manifest_bytes = poi_manifest
            .to_bytes()
            .wrap_err("serialize POI v4 manifest")?;

        let _pin_lifecycle = self.pin_lifecycle.lock().await;
        let (legacy_pin, mut legacy_ownership) = if let Some(bytes) = legacy.as_deref() {
            let ownership = self.acquire_pin_ownership()?;
            match pin_manifest(self.ipfs_client.as_ref(), bytes).await {
                Ok(cid) => (Some(cid), Some(ownership)),
                Err(error) => {
                    ownership.settle();
                    return Err(error).wrap_err("pin legacy POI manifest");
                }
            }
        } else {
            (None, None)
        };
        if let Err(error) = self.ensure_publication_running() {
            if let (Some(cid), Some(ownership)) = (&legacy_pin, legacy_ownership.take()) {
                self.cleanup_uncommitted_pin_while_locked(cid, "legacy POI manifest", ownership)
                    .await;
            }
            return Err(error);
        }
        let poi_artifact_ownership = match self.acquire_pin_ownership() {
            Ok(ownership) => ownership,
            Err(error) => {
                if let (Some(cid), Some(ownership)) = (&legacy_pin, legacy_ownership.take()) {
                    self.cleanup_uncommitted_pin_while_locked(
                        cid,
                        "legacy POI manifest",
                        ownership,
                    )
                    .await;
                }
                return Err(error);
            }
        };
        let poi_artifact_pin =
            match pin_manifest(self.ipfs_client.as_ref(), &poi_manifest_bytes).await {
                Ok(cid) => cid,
                Err(error) => {
                    poi_artifact_ownership.settle();
                    if let (Some(cid), Some(ownership)) = (&legacy_pin, legacy_ownership.take()) {
                        self.cleanup_uncommitted_pin_while_locked(
                            cid,
                            "legacy POI manifest",
                            ownership,
                        )
                        .await;
                    }
                    return Err(error).wrap_err("pin POI v4 manifest");
                }
            };
        if let Err(error) = self.ensure_publication_running() {
            if let (Some(cid), Some(ownership)) = (&legacy_pin, legacy_ownership.take()) {
                self.cleanup_uncommitted_pin_while_locked(cid, "legacy POI manifest", ownership)
                    .await;
            }
            self.cleanup_uncommitted_pin_while_locked(
                &poi_artifact_pin,
                "POI artifact manifest",
                poi_artifact_ownership,
            )
            .await;
            return Err(error);
        }
        let audit_result = async {
            let mut tx = self
                .store
                .begin()
                .await
                .wrap_err("begin dual POI manifest audit transaction")?;
            if let (Some(cid), Some(bytes)) = (legacy_pin.as_ref(), legacy.as_deref()) {
                Audit::record_manifest_pin(
                    &mut tx,
                    cid,
                    lease.legacy_manifest_sequence(),
                    u64::try_from(bytes.len()).wrap_err("legacy manifest byte size overflow")?,
                    &content_hash(bytes),
                    SNAPSHOT_FORMAT_VERSION,
                )
                .await
                .wrap_err("record legacy manifest pin")?;
            }
            Audit::record_poi_artifact_manifest_pin(
                &mut tx,
                &poi_artifact_pin,
                &poi_graph.entries,
                &poi_graph.artifact_cids,
                lease.v4_manifest_sequence(),
                u64::try_from(poi_manifest_bytes.len())
                    .wrap_err("POI artifact manifest byte size overflow")?,
                &content_hash(&poi_manifest_bytes),
            )
            .await
            .wrap_err("record POI v4 manifest graph")?;
            tx.commit().await.wrap_err("commit dual POI manifest audit")
        }
        .await;
        if let Err(error) = audit_result {
            if let (Some(cid), Some(ownership)) = (&legacy_pin, legacy_ownership.take()) {
                self.cleanup_uncommitted_pin_while_locked(cid, "legacy POI manifest", ownership)
                    .await;
            }
            self.cleanup_uncommitted_pin_while_locked(
                &poi_artifact_pin,
                "POI artifact manifest",
                poi_artifact_ownership,
            )
            .await;
            return Err(error);
        }
        if let Some(ownership) = legacy_ownership.take() {
            ownership.settle();
        }
        poi_artifact_ownership.settle();

        let legacy = legacy_pin.map(|cid| PublishedManifest {
            cid: cid.to_string(),
            sequence: lease.legacy_manifest_sequence(),
        });
        let v4 = PublishedManifest {
            cid: poi_artifact_pin.to_string(),
            sequence: lease.v4_manifest_sequence(),
        };
        if let Some(legacy) = &legacy {
            self.status
                .write()
                .await
                .record_manifest_publication(legacy.cid.clone());
        }
        self.ensure_publication_running()?;
        Ok(PublishedPoiManifests {
            legacy,
            v4,
            poi_artifact_graph_cids: poi_graph.artifact_cids.clone(),
        })
    }

    async fn manifest_entries(&self) -> Result<Vec<ManifestEntry>> {
        let mut entries = Vec::new();
        for list_key in &self.config.list_keys {
            for chain_id in &self.config.chain_ids {
                let publications = self
                    .store
                    .active_publications(list_key, *chain_id, &self.config.upstream_url)
                    .await
                    .wrap_err("read active publications for manifest")?;
                let Some(base) = active_base(&publications) else {
                    continue;
                };
                let Some(blocked_shields) = self
                    .store
                    .active_blocked_shields_publication(
                        list_key,
                        *chain_id,
                        &self.config.upstream_url,
                    )
                    .await
                    .wrap_err("read active blocked-shields publication for manifest")?
                else {
                    continue;
                };
                let deltas = manifest_deltas(&publications, base);
                let retained_deltas = active_deltas(&publications)
                    .into_iter()
                    .map(retained_delta_descriptor)
                    .collect::<Result<Vec<_>>>()?;
                let current = deltas.last().copied().unwrap_or(base);
                let tip_merkleroot = current
                    .tip_merkleroot
                    .ok_or_else(|| eyre!("published snapshot is missing tip merkleroot"))?;

                entries.push(ManifestEntry {
                    list_key: *list_key,
                    chain_id: *chain_id,
                    base: artifact_descriptor(base),
                    deltas: deltas
                        .iter()
                        .map(|publication| artifact_descriptor(publication))
                        .collect(),
                    retained_deltas,
                    blocked_shields: blocked_shields_descriptor(&blocked_shields),
                    current_tip_index: current.end_index,
                    current_tip_merkleroot: FixedBytes::from(tip_merkleroot),
                });
            }
        }

        entries.sort_by(|left, right| {
            left.list_key
                .cmp(&right.list_key)
                .then_with(|| left.chain_id.cmp(&right.chain_id))
        });
        Ok(entries)
    }

    async fn publish_poi_ipns(
        &self,
        lease: PoiPublicationSequenceLease,
        manifests: &PublishedPoiManifests,
    ) -> Result<()> {
        self.ensure_publication_running()?;
        let mut required_poi_artifacts = manifests.poi_artifact_graph_cids.clone();
        required_poi_artifacts.push(manifests.v4.cid.clone());
        let mut failures = Vec::new();
        if let Some(legacy) = &manifests.legacy {
            let outcome = run_dual_poi_publication_cycle(
                lease,
                |sequence| async move {
                    if !self
                        .cid_is_available(&legacy.cid, "legacy manifest")
                        .await?
                    {
                        return Err(eyre!("legacy manifest CID is externally unavailable"));
                    }
                    self.ipns_publisher
                        .publish_manifest_cid(&legacy.cid, sequence)
                        .await
                        .map_err(eyre::Report::new)
                },
                |sequence| async move {
                    for cid in &required_poi_artifacts {
                        if !self.cid_is_available(cid, "POI v4 graph").await? {
                            return Err(eyre!(
                                "required POI v4 graph CID {cid} is externally unavailable"
                            ));
                        }
                    }
                    self.v4_ipns_publisher
                        .publish_manifest_cid(&manifests.v4.cid, sequence)
                        .await
                        .map_err(eyre::Report::new)
                },
            )
            .await;
            match outcome.legacy {
                Ok(_) => {
                    if let Err(error) = self.ensure_publication_running() {
                        failures.push(format!("legacy activation: {error}"));
                    } else if let Err(error) =
                        self.record_legacy_ipns(&legacy.cid, legacy.sequence).await
                    {
                        failures.push(format!("legacy audit: {error}"));
                    }
                }
                Err(error) => failures.push(format!("legacy: {error}")),
            }
            match outcome.v4 {
                Ok(_) => {
                    if let Err(error) = self.ensure_publication_running() {
                        failures.push(format!("v4 activation: {error}"));
                    } else if let Err(error) = self
                        .record_v4_ipns(&manifests.v4.cid, manifests.v4.sequence)
                        .await
                    {
                        failures.push(format!("POI artifact audit: {error}"));
                    }
                }
                Err(error) => failures.push(format!("v4: {error}")),
            }
        } else {
            let publication = async {
                for cid in &required_poi_artifacts {
                    if !self.cid_is_available(cid, "POI v4 graph").await? {
                        return Err(eyre!(
                            "required POI v4 graph CID {cid} is externally unavailable"
                        ));
                    }
                }
                self.v4_ipns_publisher
                    .publish_manifest_cid(&manifests.v4.cid, lease.v4_manifest_sequence())
                    .await
                    .map_err(eyre::Report::new)
            }
            .await;
            match publication {
                Ok(_) => {
                    if let Err(error) = self.ensure_publication_running() {
                        failures.push(format!("v4 activation: {error}"));
                    } else if let Err(error) = self
                        .record_v4_ipns(&manifests.v4.cid, manifests.v4.sequence)
                        .await
                    {
                        failures.push(format!("POI artifact audit: {error}"));
                    }
                }
                Err(error) => failures.push(format!("v4: {error}")),
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(eyre!(
                "POI IPNS publication failed: {}",
                failures.join(", ")
            ))
        }
    }

    async fn record_legacy_ipns(&self, manifest_cid: &str, sequence: u64) -> Result<()> {
        let parsed_cid = manifest_cid.parse().wrap_err("parse legacy manifest CID")?;
        let mut tx = self
            .store
            .begin()
            .await
            .wrap_err("begin legacy manifest IPNS audit transaction")?;
        Audit::record_manifest_ipns_publication(&mut tx, &parsed_cid, sequence)
            .await
            .wrap_err("record legacy manifest IPNS publication")?;
        tx.commit()
            .await
            .wrap_err("commit legacy manifest IPNS audit")?;
        Ok(())
    }

    async fn record_v4_ipns(&self, manifest_cid: &str, sequence: u64) -> Result<()> {
        let parsed_cid = manifest_cid.parse().wrap_err("parse POI v4 manifest CID")?;
        let mut tx = self.store.begin().await?;
        Audit::record_poi_artifact_manifest_ipns_publication(&mut tx, &parsed_cid, sequence)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn reconcile_pending_poi_publications(&self) -> Result<bool> {
        self.ensure_publication_running()?;
        let legacy = Audit::pending_manifest_publication(self.store.pool())
            .await
            .wrap_err("load pending legacy POI manifest")?;
        let v4 = Audit::pending_poi_artifact_manifest_publication(self.store.pool())
            .await
            .wrap_err("load pending v4 POI manifest")?;
        if legacy.is_none() && v4.is_none() {
            return Ok(false);
        }

        let legacy_reconciliation = async {
            let Some(pending) = legacy else {
                return Ok::<(), eyre::Report>(());
            };
            if !self
                .cid_is_available(&pending.cid, "pending legacy manifest")
                .await?
            {
                return Err(eyre!(
                    "pending legacy manifest CID {} is externally unavailable",
                    pending.cid
                ));
            }
            self.ipns_publisher
                .publish_manifest_cid(&pending.cid, pending.sequence)
                .await
                .map_err(eyre::Report::new)?;
            self.ensure_publication_running()?;
            self.record_legacy_ipns(&pending.cid, pending.sequence)
                .await
                .wrap_err("activate reconciled legacy POI manifest")
        };
        let v4_reconciliation = async {
            let Some(pending) = v4 else {
                return Ok::<(), eyre::Report>(());
            };
            for cid in pending
                .artifact_cids
                .iter()
                .chain(std::iter::once(&pending.cid))
            {
                if !self.cid_is_available(cid, "pending v4 graph").await? {
                    return Err(eyre!(
                        "pending v4 graph CID {cid} is externally unavailable"
                    ));
                }
            }
            self.v4_ipns_publisher
                .publish_manifest_cid(&pending.cid, pending.sequence)
                .await
                .map_err(eyre::Report::new)?;
            self.ensure_publication_running()?;
            self.record_v4_ipns(&pending.cid, pending.sequence)
                .await
                .wrap_err("activate reconciled v4 POI manifest")
        };
        let (legacy_result, v4_result) =
            futures_util::future::join(legacy_reconciliation, v4_reconciliation).await;
        let mut failures = Vec::new();
        if let Err(error) = legacy_result {
            failures.push(format!("legacy: {error}"));
        }
        if let Err(error) = v4_result {
            failures.push(format!("v4: {error}"));
        }
        if failures.is_empty() {
            Ok(true)
        } else {
            Err(eyre!(
                "pending POI publication reconciliation failed: {}",
                failures.join(", ")
            ))
        }
    }

    async fn load_durable_publication_state(&mut self) -> Result<()> {
        let legacy = Audit::active_manifest_publication(self.store.pool())
            .await
            .wrap_err("load active legacy POI manifest state")?;
        let v4 = Audit::active_poi_artifact_manifest_publication(self.store.pool())
            .await
            .wrap_err("load active v4 POI manifest state")?;
        self.last_manifest_cid = legacy.as_ref().map(|manifest| manifest.cid.clone());
        self.last_poi_artifact_manifest_cid = v4.as_ref().map(|manifest| manifest.cid.clone());
        self.last_poi_artifact_graph_hash = v4
            .as_ref()
            .map(|manifest| serde_json::to_vec(&manifest.entries))
            .transpose()
            .wrap_err("serialize active POI artifact graph identity")?
            .map(|bytes| content_hash(&bytes));
        self.last_ipns_publish_at = legacy
            .as_ref()
            .map(|manifest| manifest.ipns_published_at)
            .into_iter()
            .chain(v4.as_ref().map(|manifest| manifest.ipns_published_at))
            .max();
        self.manifest_needs_publish = v4.is_none();
        let mut status = self.status.write().await;
        if let Some(v4) = v4 {
            status.restore_poi_artifact_publication(v4.cid, v4.sequence, &v4.entries);
        } else {
            status.clear_poi_artifact_publication();
        }
        Ok(())
    }

    async fn cid_is_available(&self, cid: &str, label: &'static str) -> Result<bool> {
        cid_is_available(self.ipfs_client.as_ref(), cid, label).await
    }

    async fn cleanup_uncommitted_pin_while_locked(
        &self,
        cid: &Cid,
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

    fn should_republish_ipns(&self, now: SystemTime) -> bool {
        self.last_poi_artifact_manifest_cid.is_some()
            && self.last_ipns_publish_at.is_none_or(|last_published_at| {
                now.duration_since(last_published_at)
                    .is_ok_and(|elapsed| elapsed >= *self.config.ipns_republish_interval)
            })
    }

    async fn set_ipfs_reachable(&self, reachable: bool) {
        self.status.write().await.set_ipfs_reachable(reachable);
    }
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

fn active_base(publications: &[StoredPublication]) -> Option<&StoredPublication> {
    publications
        .iter()
        .rfind(|publication| matches!(publication.kind, SnapshotKind::Base))
}

fn active_deltas(publications: &[StoredPublication]) -> Vec<&StoredPublication> {
    let mut deltas = publications
        .iter()
        .filter(|publication| matches!(publication.kind, SnapshotKind::Delta))
        .collect::<Vec<_>>();
    deltas.sort_by_key(|publication| publication.start_index);
    deltas
}

fn manifest_deltas<'a>(
    publications: &'a [StoredPublication],
    base: &StoredPublication,
) -> Vec<&'a StoredPublication> {
    active_deltas(publications)
        .into_iter()
        .filter(|publication| publication.start_index > base.end_index)
        .collect()
}

fn current_manifest_publications(publications: &[StoredPublication]) -> Vec<&StoredPublication> {
    let Some(base) = active_base(publications) else {
        return Vec::new();
    };
    let mut current = Vec::with_capacity(publications.len());
    current.push(base);
    current.extend(manifest_deltas(publications, base));
    current
}

fn published_tip(publications: &[&StoredPublication]) -> Option<u64> {
    publications
        .iter()
        .map(|publication| publication.end_index)
        .max()
}

async fn first_missing_publication_cid(
    ipfs_client: &dyn IpfsClient,
    publications: &[StoredPublication],
    list_key: &alloy_primitives::FixedBytes<32>,
    chain_id: u64,
) -> Result<Option<String>> {
    for publication in current_manifest_publications(publications) {
        if !cid_is_available(ipfs_client, &publication.cid, "snapshot")
            .await
            .wrap_err_with(|| {
                format!(
                    "check published snapshot availability for list_key={} chain_id={chain_id} cid={}",
                    list_key_hex(list_key),
                    publication.cid
                )
            })?
        {
            return Ok(Some(publication.cid.clone()));
        }
    }

    Ok(None)
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

fn artifact_descriptor(publication: &StoredPublication) -> ArtifactDescriptor {
    ArtifactDescriptor {
        cid: publication.cid.clone(),
        sha256: FixedBytes::from(publication.content_hash),
        byte_size: publication.byte_size,
    }
}

fn retained_delta_descriptor(publication: &StoredPublication) -> Result<RetainedDeltaDescriptor> {
    let tip_merkleroot = publication
        .tip_merkleroot
        .ok_or_else(|| eyre!("published delta snapshot is missing tip merkleroot"))?;
    Ok(RetainedDeltaDescriptor::new(
        artifact_descriptor(publication),
        publication.start_index,
        publication.end_index,
        FixedBytes::from(tip_merkleroot),
    ))
}

fn blocked_shields_descriptor(
    publication: &railgun_indexer_core::store::StoredBlockedShieldsPublication,
) -> ArtifactDescriptor {
    ArtifactDescriptor {
        cid: publication.cid.clone(),
        sha256: FixedBytes::from(publication.content_hash),
        byte_size: publication.byte_size,
    }
}

fn list_key_hex(list_key: &FixedBytes<32>) -> String {
    hex::encode_prefixed(list_key.as_slice())
}

const fn snapshot_kind_label(kind: SnapshotKind) -> &'static str {
    match kind {
        SnapshotKind::Base => "base",
        SnapshotKind::Delta => "delta",
    }
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
mod tests {
    use super::*;
    use alloy_primitives::FixedBytes;
    use async_trait::async_trait;
    use cid::Cid;
    use clap::error::ErrorKind;
    use railgun_indexer_core::publish::ipfs::{IpfsError, raw_block_cid};
    use std::collections::{BTreeMap, HashSet};
    use std::sync::Mutex;

    #[test]
    fn offline_identity_mode_does_not_require_config() {
        let options = Options::try_parse_from([
            "railgun-indexer",
            "--print-v4-poi-public-identity",
            "--publisher-signing-key-path",
            "/secure/production-publisher.key",
        ])
        .expect("offline identity options");

        assert!(options.config.is_none());
        assert!(options.print_v4_poi_public_identity);
        assert_eq!(
            options.publisher_signing_key_path,
            Some(PathBuf::from("/secure/production-publisher.key"))
        );
    }

    #[test]
    fn normal_mode_still_requires_config() {
        let error = Options::try_parse_from(["railgun-indexer"])
            .expect_err("a startup mode must be selected");

        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn offline_and_normal_modes_are_mutually_exclusive() {
        let error = Options::try_parse_from([
            "railgun-indexer",
            "--config",
            "config.yaml",
            "--print-v4-poi-public-identity",
            "--publisher-signing-key-path",
            "/secure/production-publisher.key",
        ])
        .expect_err("offline and normal modes must conflict");

        assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn pending_manifest_recovery_requires_exact_authorization() {
        let cid = raw_block_cid(b"pending recovery CLI").expect("test CID");
        let cid_text = cid.to_string();
        let options = Options::try_parse_from([
            "railgun-indexer",
            "--config",
            "config.yaml",
            "--invalidate-pending-poi-manifest",
            "--channel",
            "v4",
            "--manifest-cid",
            &cid_text,
            "--manifest-sequence",
            "42",
        ])
        .expect("exact recovery options");

        assert!(options.invalidate_pending_poi_manifest);
        assert_eq!(options.channel, Some(RecoveryChannel::V4));
        assert_eq!(options.manifest_cid, Some(cid));
        assert_eq!(options.manifest_sequence, Some(42));
    }

    #[test]
    fn pending_manifest_recovery_rejects_partial_authorization() {
        let error = Options::try_parse_from([
            "railgun-indexer",
            "--config",
            "config.yaml",
            "--invalidate-pending-poi-manifest",
            "--channel",
            "legacy",
        ])
        .expect_err("CID and sequence are mandatory");

        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn poi_txid_identity_adoption_requires_complete_exact_authorization() {
        let options = Options::try_parse_from([
            "railgun-indexer",
            "--config",
            "config.yaml",
            "--adopt-poi-txid-version",
            "--authorized-txid-version",
            "V2_PoseidonMerkle",
        ])
        .expect("complete POI identity adoption options");
        assert!(options.adopt_poi_txid_version);
        assert_eq!(
            options.authorized_txid_version.as_deref(),
            Some("V2_PoseidonMerkle")
        );

        let partial = Options::try_parse_from([
            "railgun-indexer",
            "--config",
            "config.yaml",
            "--adopt-poi-txid-version",
        ])
        .expect_err("TXID-version authorization is mandatory");
        assert_eq!(partial.kind(), ErrorKind::MissingRequiredArgument);

        let _error = validate_poi_txid_adoption_authorization("V2_PoseidonMerkle", "OtherVersion")
            .expect_err("authorization must exactly match config");
    }

    #[tokio::test]
    async fn final_drain_deadline_aborts_and_drains_remaining_joins() -> Result<()> {
        struct DropSignal(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for DropSignal {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut tasks = JoinSet::new();
        let signal = DropSignal(dropped.clone());
        tasks.spawn(async move {
            let _signal = signal;
            std::future::pending::<()>().await;
            Ok(())
        });

        drain_background_tasks_with_timeout(
            &mut tasks,
            Duration::from_millis(10),
            &PinLifecycleCoordinator::default(),
        )
        .await?;

        assert!(tasks.is_empty());
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
        Ok(())
    }

    #[tokio::test]
    async fn final_drain_waits_for_pin_owner_before_aborting_nonowning_work() -> Result<()> {
        let coordinator = PinLifecycleCoordinator::default();
        let ownership = coordinator
            .try_acquire_pin_ownership()
            .expect("pin owner admitted");
        coordinator.stop_new_pin_ownership();
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dropped_by_task = dropped.clone();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            struct DropSignal(Arc<std::sync::atomic::AtomicBool>);
            impl Drop for DropSignal {
                fn drop(&mut self) {
                    self.0.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            }
            let _signal = DropSignal(dropped_by_task);
            std::future::pending::<()>().await;
            Ok(())
        });
        let drain_coordinator = coordinator.clone();
        let drain = tokio::spawn(async move {
            drain_background_tasks_with_timeout(
                &mut tasks,
                Duration::from_millis(10),
                &drain_coordinator,
            )
            .await
        });

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!drain.is_finished());
        assert!(!dropped.load(std::sync::atomic::Ordering::SeqCst));
        ownership.settle();
        drain.await.expect("join final drain")?;
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
        Ok(())
    }

    #[test]
    fn offline_identity_output_matches_vector_and_contains_only_public_values() -> Result<()> {
        let seed = std::array::from_fn(|index| u8::try_from(index).expect("seed byte"));
        let output = v4_poi_public_identity_json(&SigningKey::from_bytes(&seed))?;

        assert_eq!(
            output,
            r#"{"manifest_signing_public_key":"0x03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8","v4_ipns_public_key":"0x56f6df3102df0467da6a5adc7ef6ff577fabf2944fd1bd606f6a47464f22abc9","v4_ipns_peer_id":"12D3KooWFfqZkgZyH41hEVExsTkwAEVk9bTmHdLTP99uD1uwWo52","v4_ipns_name":"k51qzi5uqu5dicmabkge4lkunc4bkd198u9xicp5espmw5zdzbafkez7hyh5ft"}"#
        );
        assert!(!output.contains(&hex::encode(seed)));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&output)?
                .as_object()
                .expect("identity JSON object")
                .len(),
            4
        );
        Ok(())
    }

    #[tokio::test]
    async fn status_server_returns_health_and_status() -> Result<()> {
        let list_key = FixedBytes::from([1_u8; 32]);
        let status = Status::for_pairs(&[list_key], &[1], 100).shared();
        {
            let mut status = status.write().await;
            status.set_ipns_identities(
                "k51qzi5uqu5dlpoi",
                "k51qzi5uqu5dlv4poi",
                "k51qzi5uqu5dlindexed",
                "12D3KooWLegacy",
                "12D3KooWV4Poi",
                "12D3KooWIndexed",
            );
            status.record_poi_artifact_publication(
                "bafy-v4-manifest".to_string(),
                42,
                &[v4_test_entry()],
                0,
                0,
                0,
                0,
                2,
                3,
            );
            status.record_retention_sweep(4, 1);
        }
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .wrap_err("bind test status listener")?;
        let addr = listener.local_addr().wrap_err("read test listener addr")?;
        let server_status = status.clone();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server =
            tokio::spawn(async move { serve_status(listener, server_status, shutdown_rx).await });

        let health = reqwest::get(format!("http://{addr}/health"))
            .await
            .wrap_err("GET /health")?;
        assert!(health.status().is_success());

        let status = reqwest::get(format!("http://{addr}/status"))
            .await
            .wrap_err("GET /status")?
            .json::<Status>()
            .await
            .wrap_err("decode /status")?;
        assert_eq!(status.pairs.len(), 1);
        assert_eq!(status.pairs[0].chain_id, 1);
        assert_eq!(status.pairs[0].current_page_size, 100);
        assert_eq!(status.poi_ipns_name.as_deref(), Some("k51qzi5uqu5dlpoi"));
        assert_eq!(
            status.poi_v4_ipns_name.as_deref(),
            Some("k51qzi5uqu5dlv4poi")
        );
        assert_eq!(
            status.chain_indexed_ipns_name.as_deref(),
            Some("k51qzi5uqu5dlindexed")
        );
        assert_eq!(status.poi_peer_id.as_deref(), Some("12D3KooWLegacy"));
        assert_eq!(status.poi_v4_peer_id.as_deref(), Some("12D3KooWV4Poi"));
        assert_eq!(
            status.chain_indexed_peer_id.as_deref(),
            Some("12D3KooWIndexed")
        );
        let v4 = status
            .poi_artifact_publication
            .expect("POI artifact publication status");
        assert_eq!(v4.sequence, 42);
        assert_eq!(v4.reused_cids, Some(2));
        assert_eq!(v4.scopes.len(), 1);
        let retention = status.last_retention_sweep.expect("retention status");
        assert_eq!(retention.unpinned_count, 4);
        assert_eq!(retention.failed_count, 1);

        shutdown_tx.send(true).wrap_err("send shutdown")?;
        server.await.wrap_err("join status server")??;
        Ok(())
    }

    #[test]
    fn restored_v4_status_preserves_active_identity_without_claiming_runtime_metrics() {
        let mut status = Status::for_pairs(&[], &[], 100);
        let entry = v4_test_entry();

        status.restore_poi_artifact_publication("bafy-active".to_string(), 42, &[entry]);

        let publication = status
            .poi_artifact_publication
            .as_ref()
            .expect("restored POI artifact publication");
        assert_eq!(publication.manifest_cid, "bafy-active");
        assert_eq!(publication.sequence, 42);
        assert_eq!(publication.checkpoint_chunks, 0);
        assert_eq!(publication.checkpoint_bytes, None);
        assert_eq!(publication.reused_cids, None);
        assert_eq!(publication.elapsed_ms, None);
        assert_eq!(publication.scopes.len(), 1);
        assert!(!status.ipfs_reachable);

        status.clear_poi_artifact_publication();
        assert!(status.poi_artifact_publication.is_none());
    }

    #[tokio::test]
    async fn missing_publication_cid_detects_deleted_delta() -> Result<()> {
        let list_key = FixedBytes::from([2_u8; 32]);
        let base_cid = raw_block_cid(b"base")?;
        let delta_cid = raw_block_cid(b"delta")?;
        let client = AvailabilityClient::new([base_cid]);
        let publications = vec![
            stored_publication(SnapshotKind::Base, 0, 3, base_cid),
            stored_publication(SnapshotKind::Delta, 4, 4, delta_cid),
        ];

        let missing = first_missing_publication_cid(&client, &publications, &list_key, 1).await?;

        assert_eq!(missing, Some(delta_cid.to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn missing_publication_cid_accepts_all_present() -> Result<()> {
        let list_key = FixedBytes::from([3_u8; 32]);
        let base_cid = raw_block_cid(b"base")?;
        let delta_cid = raw_block_cid(b"delta")?;
        let client = AvailabilityClient::new([base_cid, delta_cid]);
        let publications = vec![
            stored_publication(SnapshotKind::Base, 0, 3, base_cid),
            stored_publication(SnapshotKind::Delta, 4, 4, delta_cid),
        ];

        let missing = first_missing_publication_cid(&client, &publications, &list_key, 1).await?;

        assert_eq!(missing, None);
        Ok(())
    }

    #[tokio::test]
    async fn missing_publication_cid_ignores_delta_covered_by_base() -> Result<()> {
        let list_key = FixedBytes::from([4_u8; 32]);
        let base_cid = raw_block_cid(b"base")?;
        let retained_delta_cid = raw_block_cid(b"retained delta")?;
        let current_delta_cid = raw_block_cid(b"current delta")?;
        let client = AvailabilityClient::new([base_cid, current_delta_cid]);
        let publications = vec![
            stored_publication(SnapshotKind::Base, 0, 10, base_cid),
            stored_publication(SnapshotKind::Delta, 8, 10, retained_delta_cid),
            stored_publication(SnapshotKind::Delta, 11, 12, current_delta_cid),
        ];

        let missing = first_missing_publication_cid(&client, &publications, &list_key, 1).await?;

        assert_eq!(missing, None);
        Ok(())
    }

    #[test]
    fn retained_delta_descriptor_includes_range_and_tip_root() -> Result<()> {
        let delta_cid = raw_block_cid(b"retained delta")?;
        let publication = stored_publication(SnapshotKind::Delta, 8, 10, delta_cid);

        let descriptor = retained_delta_descriptor(&publication)?;

        assert_eq!(descriptor.artifact.cid, delta_cid.to_string());
        assert_eq!(descriptor.start_index, 8);
        assert_eq!(descriptor.end_index, 10);
        assert_eq!(descriptor.tip_merkleroot, FixedBytes::from([9_u8; 32]));
        Ok(())
    }

    #[test]
    fn manifest_deltas_exclude_retained_deltas_covered_by_base() -> Result<()> {
        let base_cid = raw_block_cid(b"base")?;
        let retained_delta_cid = raw_block_cid(b"retained delta")?;
        let current_delta_cid = raw_block_cid(b"current delta")?;
        let publications = vec![
            stored_publication(SnapshotKind::Base, 0, 10, base_cid),
            stored_publication(SnapshotKind::Delta, 8, 10, retained_delta_cid),
            stored_publication(SnapshotKind::Delta, 11, 12, current_delta_cid),
        ];
        let base = active_base(&publications).expect("active base");

        let deltas = manifest_deltas(&publications, base);

        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].cid, current_delta_cid.to_string());
        Ok(())
    }

    #[test]
    fn released_alpha_legacy_manifest_fixture_still_verifies_and_decodes() -> Result<()> {
        const RELEASED_ALPHA_PUBLISHER: [u8; 32] = [
            0x19, 0x7f, 0x6b, 0x23, 0xe1, 0x6c, 0x85, 0x32, 0xc6, 0xab, 0xc8, 0x38, 0xfa, 0xcd,
            0x5e, 0xa7, 0x89, 0xbe, 0x0c, 0x76, 0xb2, 0x92, 0x03, 0x34, 0x03, 0x9b, 0xfa, 0x8b,
            0x3d, 0x36, 0x8d, 0x61,
        ];
        let bytes = include_bytes!("../tests/fixtures/released-alpha-poi-manifest-v1.json");
        let manifest: Manifest = serde_json::from_slice(bytes)?;

        manifest.verify_trusted_signature(&RELEASED_ALPHA_PUBLISHER)?;
        assert_eq!(
            serde_json::to_vec(&manifest)?,
            bytes.strip_suffix(b"\n").unwrap_or(bytes)
        );
        assert_eq!(manifest.format_version, 1);
        assert_eq!(manifest.entries.len(), 1);
        assert_eq!(manifest.entries[0].current_tip_index, 9);
        assert_eq!(manifest.entries[0].deltas.len(), 1);
        assert_eq!(manifest.entries[0].base.cid, "bafy-alpha-1");
        assert_eq!(manifest.entries[0].deltas[0].cid, "bafy-alpha-2");
        assert_eq!(manifest.entries[0].blocked_shields.cid, "bafy-alpha-3");
        Ok(())
    }

    #[test]
    fn bridge_retention_trims_expired_and_oldest_descriptors() -> Result<()> {
        let now = UNIX_EPOCH + Duration::from_hours(10 * 24);
        let mut entry = v4_test_entry();
        entry.retained_bridges = (0..8).map(|index| v4_test_bridge(index, index)).collect();
        let bridge_published_at = entry
            .retained_bridges
            .iter()
            .enumerate()
            .map(|(index, bridge)| {
                (
                    bridge.artifact.cid.clone(),
                    UNIX_EPOCH
                        + Duration::from_secs(
                            u64::try_from(index + 2).expect("day") * 24 * 60 * 60,
                        ),
                )
            })
            .collect();
        let active = ActivePoiGraph {
            entry: entry.clone(),
            checkpoint_published_at: now,
            bridge_published_at,
        };
        let new_bridge = v4_test_bridge(8, 8);
        let mut bridges = entry.retained_bridges;
        bridges.push(new_bridge.clone());

        let retained = retain_recent_bridges(bridges, &active, now)?;

        assert_eq!(retained.len(), MAX_RETAINED_BRIDGES);
        assert_eq!(retained.last(), Some(&new_bridge));
        assert_eq!(
            retained.first().map(|bridge| bridge.range.start_index),
            Some(2)
        );
        Ok(())
    }

    #[test]
    fn v4_rotates_before_tail_limit_and_on_checkpoint_cadence() {
        let interval = Duration::from_hours(24);
        assert!(poi_artifact_rotation_required(
            true,
            Some(Duration::from_hours(1)),
            interval,
            false,
        ));
        assert!(poi_artifact_rotation_required(
            true,
            Some(interval),
            interval,
            true,
        ));
        assert!(poi_artifact_rotation_required(
            false,
            Some(interval),
            interval,
            false,
        ));
        assert!(!poi_artifact_rotation_required(
            true,
            Some(Duration::from_hours(1)),
            interval,
            true,
        ));
    }

    #[test]
    fn example_config_chain_indexed_defaults_match_canonical_values() -> Result<()> {
        let config: Config =
            serde_yaml::from_str(include_str!("../../../config.railgun-indexer.example.yaml"))
                .wrap_err("parse example config")?;
        let chains = config
            .chain_indexed
            .chains
            .iter()
            .map(|chain| (chain.chain_id, chain))
            .collect::<BTreeMap<_, _>>();

        assert_eq!(chains.len(), 4);
        for expected in CANONICAL_CHAIN_INDEXED_DEFAULTS {
            let chain = chains.get(&expected.chain_id).unwrap_or_else(|| {
                panic!(
                    "missing chain-indexed config for chain {}",
                    expected.chain_id
                )
            });

            assert_eq!(
                chain.railgun_contract.to_string().to_ascii_lowercase(),
                expected.railgun_contract
            );
            assert_eq!(chain.start_block, expected.start_block);
            assert_eq!(chain.v2_start_block, expected.v2_start_block);
            assert_eq!(chain.legacy_shield_block, expected.legacy_shield_block);
        }

        let scopes = config
            .list_keys
            .iter()
            .flat_map(|list_key| {
                config.chain_ids.iter().map(|chain_id| {
                    Scope::new(
                        *list_key,
                        EVM_CHAIN_TYPE,
                        *chain_id,
                        config.txid_version.clone(),
                    )
                })
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(scopes.len(), 4);
        assert!(
            scopes
                .iter()
                .all(|scope| scope.txid_version == "V2_PoseidonMerkle")
        );

        Ok(())
    }

    // Mirrors sync_service::ChainConfigDefaults::for_chain for deployment fields.
    const CANONICAL_CHAIN_INDEXED_DEFAULTS: &[ExpectedChainIndexedDefault] = &[
        ExpectedChainIndexedDefault {
            chain_id: 1,
            railgun_contract: "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9",
            start_block: 14_737_691,
            v2_start_block: 16_076_750,
            legacy_shield_block: 16_790_263,
        },
        ExpectedChainIndexedDefault {
            chain_id: 56,
            railgun_contract: "0x590162bf4b50f6576a459b75309ee21d92178a10",
            start_block: 17_633_701,
            v2_start_block: 23_478_204,
            legacy_shield_block: 26_313_947,
        },
        ExpectedChainIndexedDefault {
            chain_id: 137,
            railgun_contract: "0x19b620929f97b7b990801496c3b361ca5def8c71",
            start_block: 28_083_766,
            v2_start_block: 36_219_104,
            legacy_shield_block: 40_143_539,
        },
        ExpectedChainIndexedDefault {
            chain_id: 42161,
            railgun_contract: "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9",
            start_block: 56_109_834,
            v2_start_block: 0,
            legacy_shield_block: 68_196_853,
        },
    ];

    struct ExpectedChainIndexedDefault {
        chain_id: u64,
        railgun_contract: &'static str,
        start_block: u64,
        v2_start_block: u64,
        legacy_shield_block: u64,
    }

    fn v4_test_entry() -> PoiArtifactManifestEntry {
        let scope = Scope::new(FixedBytes::from([1; 32]), 0, 1, "V2_PoseidonMerkle");
        PoiArtifactManifestEntry {
            scope: scope.clone(),
            event_count: 0,
            current_tip_index: None,
            current_root: None,
            checkpoint_catalog: CheckpointCatalogDescriptor {
                artifact: ArtifactDescriptor {
                    cid: "bafy-catalog".to_string(),
                    sha256: FixedBytes::from([2; 32]),
                    byte_size: 2,
                },
                format_version: POI_ARTIFACT_FORMAT_VERSION,
                scope: scope.clone(),
                range: None,
                row_count: 0,
                chunk_count: 0,
                encoding: ArtifactEncoding::CanonicalJson,
                compression: Compression::Identity,
                checkpoint_root: None,
            },
            current_tail: None,
            retained_bridges: Vec::new(),
            blocked_shields: BlockedShieldsDescriptor {
                artifact: ArtifactDescriptor {
                    cid: "bafy-blocked".to_string(),
                    sha256: FixedBytes::from([3; 32]),
                    byte_size: 3,
                },
                format_version: POI_ARTIFACT_FORMAT_VERSION,
                scope,
                row_count: 0,
                encoding: ArtifactEncoding::CanonicalJson,
                compression: Compression::Identity,
            },
        }
    }

    fn v4_test_bridge(start: u64, end: u64) -> EventArtifactDescriptor {
        let scope = Scope::new(FixedBytes::from([1; 32]), 0, 1, "V2_PoseidonMerkle");
        EventArtifactDescriptor {
            artifact: ArtifactDescriptor {
                cid: format!("bafy-bridge-{start}"),
                sha256: FixedBytes::from([u8::try_from(start).expect("test range"); 32]),
                byte_size: 244,
            },
            format_version: POI_ARTIFACT_FORMAT_VERSION,
            scope,
            kind: EventArtifactKind::Bridge,
            range: poi::artifacts::v4::EventRange {
                start_index: start,
                end_index: end,
            },
            row_count: end - start + 1,
            encoding: ArtifactEncoding::PoiEventBinary,
            compression: Compression::Identity,
            start_root: (start > 0).then_some(FixedBytes::from([4; 32])),
            end_root: FixedBytes::from([5; 32]),
        }
    }

    fn stored_publication(
        kind: SnapshotKind,
        start_index: u64,
        end_index: u64,
        cid: Cid,
    ) -> StoredPublication {
        StoredPublication {
            kind,
            start_index,
            end_index,
            cid: cid.to_string(),
            byte_size: 1,
            content_hash: [8_u8; 32],
            tip_merkleroot: Some([9_u8; 32]),
            published_at: UNIX_EPOCH,
        }
    }

    #[derive(Debug)]
    struct AvailabilityClient {
        present: Mutex<HashSet<String>>,
    }

    impl AvailabilityClient {
        fn new(cids: impl IntoIterator<Item = Cid>) -> Self {
            Self {
                present: Mutex::new(cids.into_iter().map(|cid| cid.to_string()).collect()),
            }
        }
    }

    #[async_trait]
    impl IpfsClient for AvailabilityClient {
        fn service_name(&self) -> &'static str {
            "availability"
        }

        async fn pin_bytes(&self, bytes: &[u8]) -> std::result::Result<Cid, IpfsError> {
            raw_block_cid(bytes)
        }

        async fn unpin(&self, _cid: &Cid) -> std::result::Result<(), IpfsError> {
            Ok(())
        }

        async fn contains(&self, cid: &Cid) -> std::result::Result<bool, IpfsError> {
            Ok(self
                .present
                .lock()
                .expect("present CID lock")
                .contains(&cid.to_string()))
        }
    }
}

#[cfg(test)]
mod scheduler_tests;
