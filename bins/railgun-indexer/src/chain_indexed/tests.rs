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
    let mut scheduler = reconciliation_scheduler(store.clone(), ipfs.clone(), current_signing_key)?;
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
    let (manifest_cid, _) = record_pending_indexed_manifest(&store, &signing_key, 15, None).await?;
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
    let (manifest_cid, _) = record_pending_indexed_manifest(&store, &signing_key, 16, None).await?;
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
    let (manifest_cid, _) = record_pending_indexed_manifest(&store, &signing_key, 14, None).await?;
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
    let catalog = IndexedArtifactCatalog::new(IndexedDatasetKind::WalletScan, scope, Vec::new());

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
    assert_eq!(decoded.chunks, [] as [IndexedArtifactDescriptor; 0]);
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
    let mut config: Config = serde_yaml::from_str(include_str!(
        "../../../../config.railgun-indexer.example.yaml"
    ))
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
