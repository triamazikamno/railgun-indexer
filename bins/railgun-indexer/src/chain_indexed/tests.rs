use super::*;
use alloy::primitives::{Address, U256, Uint};
use alloy::transports::mock::Asserter;
use async_trait::async_trait;
use broadcaster_core::contracts::railgun::{CommitmentPreimage, ShieldCiphertext, TokenData};
use cid::Cid;
use railgun_indexer_core::chain_logs::{
    IndexedLogBatch, IndexedLogSource, IndexedPublicTransaction, IndexedShieldCommitment,
};
use railgun_indexer_core::manifest::{AmountStatisticsCoveredBlock, AmountStatisticsError};
use railgun_indexer_core::publish::ipfs::raw_block_cid;
use railgun_indexer_core::publish::ipns::{IpnsPublisherConfig, IpnsPublisherTask};
use railgun_indexer_core::status::Status;
use railgun_indexer_core::store::run_migrations;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::UNIX_EPOCH;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ContainerAsync;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tokio::io::AsyncReadExt;

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

    let mut writer = coordinator.reorg_lease().await;
    let snapshot_coordinator = coordinator.clone();
    let snapshot = tokio::spawn(async move {
        snapshot_coordinator
            .publication_lease()
            .await
            .rewind_generation()
    });
    *writer += 1;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !snapshot.is_finished(),
        "a generation snapshot must wait for the active writer"
    );
    drop(writer);
    let generation = tokio::time::timeout(Duration::from_secs(1), snapshot)
        .await
        .expect("generation snapshot timeout")
        .expect("generation snapshot task");
    assert_eq!(generation, 1);
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
fn chunk_reuse_requires_the_remembered_header() {
    let height = |block_number: u64, hash: u8| LatestIndexedHeight {
        dataset_kind: IndexedDatasetKind::PublicTxid,
        block_number,
        block_hash: FixedBytes::from([hash; 32]),
    };
    let remembered = RememberedDataset::new(
        &height(100, 1),
        Vec::new(),
        0,
        PublicTxidCheckpoint::default(),
    );
    let decide = |remembered: Option<&RememberedDataset>,
                  current: LatestIndexedHeight,
                  stored: Option<[u8; 32]>| {
        match chunk_reuse(remembered, &current, stored) {
            ChunkReuse::DeriveAll => "derive all",
            ChunkReuse::ReuseAll(_) => "reuse all",
            ChunkReuse::ReuseAllButLast(_) => "reuse all but last",
        }
    };

    assert_eq!(decide(None, height(100, 1), Some([1; 32])), "derive all");
    assert_eq!(
        decide(Some(&remembered), height(100, 1), Some([1; 32])),
        "reuse all"
    );
    assert_eq!(
        decide(Some(&remembered), height(120, 2), Some([1; 32])),
        "reuse all but last"
    );
    assert_eq!(
        decide(Some(&remembered), height(120, 2), None),
        "derive all"
    );
    assert_eq!(
        decide(Some(&remembered), height(120, 2), Some([3; 32])),
        "derive all"
    );
    assert_eq!(
        decide(Some(&remembered), height(90, 2), Some([1; 32])),
        "derive all"
    );
}

#[test]
fn full_derivation_is_due_daily_and_after_a_clock_rewind() {
    let last = UNIX_EPOCH + Duration::from_hours(48);

    assert!(full_derivation_due(None, last));
    assert!(!full_derivation_due(
        Some(last),
        last + FULL_DERIVATION_INTERVAL - Duration::from_secs(1)
    ));
    assert!(full_derivation_due(
        Some(last),
        last + FULL_DERIVATION_INTERVAL
    ));
    assert!(full_derivation_due(
        Some(last),
        last - Duration::from_secs(1)
    ));
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn statistics_failure_keeps_chain_indexed_outcome_and_unchanged_block_publishes_nothing()
-> Result<()> {
    let (_postgres, store) = reconciliation_store().await?;
    seed_statistics_chain(&store).await?;
    let ipfs = Arc::new(ReconciliationIpfs::default());
    let mut scheduler = reconciliation_scheduler(
        store.clone(),
        ipfs.clone(),
        SigningKey::from_bytes(&[79; 32]),
    )?;
    let (status, asserter, _statistics_ipns_task) = enable_statistics(&mut scheduler)?;
    let now = UNIX_EPOCH + Duration::from_secs(STATISTICS_BLOCK_TIMESTAMP);

    // The amount-statistics IPNS task is held but never run, so its publication times out and the
    // first manifest stays pending. The chain-indexed task is dropped, so a request sent through
    // that publisher would fail as not running instead.
    asserter.push_success(&statistics_block_json());
    scheduler
        .publish_cycles(now)
        .await
        .wrap_err("a statistics failure must not fail chain-indexed publication")?;
    let first_error = status
        .read()
        .await
        .amount_statistics
        .clone()
        .and_then(|statistics| statistics.last_error)
        .unwrap_or_default();
    assert!(
        first_error.contains("timed out"),
        "statistics manifest must use the amount-statistics IPNS publisher: {first_error}"
    );
    let (manifest_cid, sequence): (String, i64) =
        sqlx::query_as("SELECT cid, ipns_sequence FROM published_amount_statistics_manifests")
            .fetch_one(store.pool())
            .await?;
    // Checked as a wallet would: the envelope against the chain-indexed key, then the entry
    // against the pinned compressed snapshot. Finding bytes by raw CID checks the CID.
    let pinned = ipfs.pinned_bytes();
    let pinned_at = |cid: &str| {
        pinned
            .iter()
            .find(|bytes| {
                raw_block_cid(bytes).is_ok_and(|pinned_cid| pinned_cid.to_string() == cid)
            })
            .unwrap_or_else(|| panic!("nothing pinned under {cid}"))
    };
    let manifest = AmountStatisticsManifestEnvelope::from_json_slice(pinned_at(&manifest_cid))?
        .verify_trusted(&scheduler.signing_key.verifying_key().to_bytes())?;
    assert_eq!(manifest.chains.len(), 1);
    let entry = &manifest.chains[0].snapshot;
    let snapshot_bytes = pinned_at(&entry.cid);
    assert_eq!(entry.sha256, FixedBytes::from(content_hash(snapshot_bytes)));
    assert_eq!(entry.byte_size, u64::try_from(snapshot_bytes.len())?);
    let mut tx = store.begin().await?;
    Audit::record_amount_statistics_manifest_ipns_publication(
        &mut tx,
        &manifest_cid.parse::<Cid>()?,
        u64::try_from(sequence)?,
    )
    .await?;
    tx.commit().await?;
    let pins_after_first_cycle = ipfs.pin_count();
    // Activation records PostgreSQL's clock, so the later cycles run relative to it.
    let published_at = Audit::active_amount_statistics_manifest(store.pool())
        .await?
        .expect("active amount-statistics manifest")
        .ipns_published_at;
    let republish_interval = *scheduler.config.ipns_republish_interval;

    asserter.push_success(&statistics_block_json());
    scheduler
        .publish_cycles(published_at + Duration::from_mins(10))
        .await?;

    assert_eq!(ipfs.pin_count(), pins_after_first_cycle);
    let manifests: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM published_amount_statistics_manifests")
            .fetch_one(store.pool())
            .await?;
    assert_eq!(manifests, 1);
    let statistics = status
        .read()
        .await
        .amount_statistics
        .clone()
        .expect("amount-statistics status");
    assert_eq!(statistics.last_error, None);
    assert_eq!(statistics.manifest_cid, Some(manifest_cid.clone()));
    assert_eq!(
        statistics.chain_failures.len(),
        0,
        "{:?}",
        statistics.chain_failures
    );

    // Once the IPNS record is due for renewal, the same snapshot goes out under a new manifest.
    asserter.push_success(&statistics_block_json());
    scheduler
        .publish_cycles(published_at + republish_interval)
        .await?;

    assert_eq!(
        ipfs.pin_count(),
        pins_after_first_cycle + 1,
        "a renewal pins its manifest and no snapshot"
    );
    let renewal_snapshot_cids: Vec<String> = sqlx::query_scalar(
        r"
        SELECT snapshot.snapshot_cid
        FROM published_amount_statistics_manifest_snapshots AS snapshot
        JOIN published_amount_statistics_manifests AS manifest
            ON manifest.id = snapshot.manifest_id
        WHERE manifest.cid <> $1
        ",
    )
    .bind(&manifest_cid)
    .fetch_all(store.pool())
    .await?;
    assert_eq!(renewal_snapshot_cids, vec![entry.cid.clone()]);
    let renewal_error = status
        .read()
        .await
        .amount_statistics
        .clone()
        .and_then(|statistics| statistics.last_error)
        .unwrap_or_default();
    assert!(
        renewal_error.contains("publish amount-statistics manifest CID to IPNS"),
        "the renewal must reach IPNS publication: {renewal_error}"
    );
    let active = Audit::active_amount_statistics_manifest(store.pool())
        .await?
        .expect("active amount-statistics manifest");
    assert_eq!(
        (active.cid, active.ipns_published_at),
        (manifest_cid, published_at),
        "a failed renewal keeps the active manifest and its publication time"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn stalled_statistics_rpc_times_out_and_releases_the_canonicality_lease() -> Result<()> {
    let (_postgres, store) = reconciliation_store().await?;
    seed_statistics_chain(&store).await?;
    let mut scheduler = reconciliation_scheduler(
        store,
        Arc::new(ReconciliationIpfs::default()),
        SigningKey::from_bytes(&[83; 32]),
    )?;
    let (status, _asserter, _statistics_ipns_task) = enable_statistics(&mut scheduler)?;
    // An RPC endpoint that reads the request and never replies, keeping the connection open.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let rpc_url = format!("http://{}", listener.local_addr()?);
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();
    let _rpc = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept statistics RPC");
        let mut request = vec![0_u8; 4096];
        let read = socket
            .read(&mut request)
            .await
            .expect("read statistics RPC request");
        request.truncate(read);
        let _ = request_tx.send(request);
        std::future::pending::<()>().await;
    });
    let statistics = scheduler
        .amount_statistics
        .as_mut()
        .expect("statistics enabled");
    statistics.chains = vec![(statistics_scope(), build_provider(&rpc_url)?)];
    statistics.chain_timeout = Duration::from_millis(200);

    tokio::time::timeout(
        Duration::from_secs(10),
        scheduler.publish_cycles(UNIX_EPOCH + Duration::from_secs(STATISTICS_BLOCK_TIMESTAMP)),
    )
    .await
    .wrap_err("publication must not wait on a stalled statistics RPC")??;

    let request = tokio::time::timeout(Duration::from_secs(1), request_rx).await??;
    assert!(
        request.starts_with(b"POST "),
        "{}",
        String::from_utf8_lossy(&request)
    );
    let statistics = status
        .read()
        .await
        .amount_statistics
        .clone()
        .expect("amount-statistics status");
    assert_eq!(
        statistics.chain_failures.len(),
        1,
        "{:?}",
        statistics.chain_failures
    );
    let failure = &statistics.chain_failures[0];
    assert_eq!(failure.chain_id, 1);
    assert!(failure.reason.contains("timed out"), "{}", failure.reason);
    tokio::time::timeout(Duration::from_secs(1), scheduler.canonicality.reorg_lease())
        .await
        .wrap_err("the statistics step must release the canonicality lease")?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn chain_indexed_manifest_bytes_are_identical_with_statistics_enabled_and_disabled()
-> Result<()> {
    let disabled = chain_indexed_manifest_json(false).await?;
    let enabled = chain_indexed_manifest_json(true).await?;

    assert_eq!(enabled, disabled);
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn incremental_publication_equals_full_derivation() -> Result<()> {
    let (_postgres, store) = reconciliation_store().await?;
    index_reuse_blocks(
        &store,
        &[(100, 0), (200, 1), (300, 2), (400, 3), (500, 4)],
        1,
    )
    .await?;
    let ipfs = Arc::new(ReconciliationIpfs::default());
    let mut scheduler = reuse_scheduler(&store, ipfs.clone())?;
    let chain = scheduler.config.chain_indexed.chains[0].clone();
    let published = scheduler
        .publish_chain_entry(&chain, true)
        .await?
        .expect("published chain entry");
    for dataset in &published.remembered {
        assert!(
            dataset.dataset_kind == IndexedDatasetKind::MerkleCheckpoint
                || dataset.chunks.len() > 1,
            "{:?} needs several chunks",
            dataset.dataset_kind
        );
    }
    scheduler.remember_published_chains(vec![(
        (chain.chain_id, chain.railgun_contract),
        published.remembered,
    )]);

    // Block 550 grows the last public TXID page, commitment window and wallet-scan bucket.
    index_reuse_blocks(&store, &[(550, 5), (800, 6)], 1).await?;
    let (incremental_checks, full_checks) =
        assert_incremental_equals_full(&mut scheduler, &ipfs, &store, &chain).await?;
    assert!(
        incremental_checks < full_checks,
        "an append must reuse chunks: {incremental_checks} checks against {full_checks}"
    );

    let mut tx = store.begin().await?;
    Store::rewind_chain_indexing_to_replay_block(&mut tx, EVM_CHAIN_TYPE, 1, REUSE_RAILGUN, 700)
        .await?;
    tx.commit().await?;
    index_reuse_blocks(&store, &[(750, 6), (850, 7)], 2).await?;
    assert_incremental_equals_full(&mut scheduler, &ipfs, &store, &chain).await?;

    assert_incremental_equals_full(&mut scheduler, &ipfs, &store, &chain).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn failed_cycle_forgets_remembered_chunks() -> Result<()> {
    let (_postgres, store) = reconciliation_store().await?;
    index_reuse_blocks(&store, &[(100, 0), (200, 1), (300, 2)], 1).await?;
    let ipfs = Arc::new(ReconciliationIpfs::default());
    let mut scheduler = reuse_scheduler(&store, ipfs.clone())?;
    let chain = scheduler.config.chain_indexed.chains[0].clone();
    let published = scheduler
        .publish_chain_entry(&chain, true)
        .await?
        .expect("published chain entry");
    scheduler.remember_published_chains(vec![(
        (chain.chain_id, chain.railgun_contract),
        published.remembered,
    )]);

    // The IPNS task is not running, so the cycle fails after recording its manifest.
    let _ = scheduler
        .publish_cycle(UNIX_EPOCH + Duration::from_secs(STATISTICS_BLOCK_TIMESTAMP))
        .await
        .expect_err("chain-indexed IPNS publication is unavailable");

    assert!(scheduler.remembered_chains.is_empty());
    assert_incremental_equals_full(&mut scheduler, &ipfs, &store, &chain).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn cycle_rejects_derivation_that_overlapped_a_reorg_rewind() -> Result<()> {
    let (_postgres, store) = reconciliation_store().await?;
    let blocks = [(100, 0), (200, 1), (300, 2)];
    index_reuse_blocks(&store, &blocks, 1).await?;
    let ipfs = Arc::new(ReconciliationIpfs::default());
    let mut scheduler = reuse_scheduler(&store, ipfs.clone())?;
    let chain = scheduler.config.chain_indexed.chains[0].clone();
    let mut published = scheduler
        .publish_chain_entry(&chain, true)
        .await?
        .expect("published chain entry");
    // A stale remembered chunk gives the full derivation a mismatch that rejection must discard.
    published
        .remembered
        .iter_mut()
        .find(|dataset| dataset.dataset_kind == IndexedDatasetKind::PublicTxid)
        .expect("public TXID dataset")
        .chunks[0]
        .sha256 = FixedBytes::ZERO;
    scheduler.remember_published_chains(vec![(
        (chain.chain_id, chain.railgun_contract),
        published.remembered,
    )]);
    let (parked_tx, parked_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    *ipfs.park.lock().expect("park lock") = Some((parked_tx, release_rx));

    // Block 300 has another hash on both reads, before and after taking the reorg lease.
    let asserter = Asserter::new();
    asserter.push_success(&statistics_block_json());
    asserter.push_success(&statistics_block_json());
    let provider = ProviderBuilder::new()
        .connect_mocked_client(asserter)
        .root()
        .clone();
    let runtime = ChainRuntime {
        chain: chain.clone(),
        provider: provider.clone(),
        archive_provider: provider,
    };
    let mut reorg_config = scheduler.config.clone();
    // Replay then starts at the chain's start block, so no earlier header is fetched.
    reorg_config.chain_indexed.max_blocks_per_batch = 1_000;
    let canonicality = scheduler.canonicality.clone();
    let rewind_and_replay = async {
        parked_rx.await?;
        let resume_block =
            resume_block_after_reorg(&store, &reorg_config, &runtime, &canonicality).await?;
        assert_eq!(resume_block, chain.start_block);
        // Replay restores the cycle's watermark heights and block hashes.
        index_reuse_blocks(&store, &blocks, 1).await?;
        let _ = release_tx.send(());
        Ok::<_, eyre::Report>(())
    };

    let (cycle, rewind) = tokio::join!(
        scheduler.publish_cycle(UNIX_EPOCH + Duration::from_secs(STATISTICS_BLOCK_TIMESTAMP)),
        rewind_and_replay
    );

    rewind?;
    let error = cycle.expect_err("a cycle that derived across a rewind must not publish");
    assert!(
        format_report_chain(&error)
            .contains("reorg rewind committed during chain-indexed artifact derivation"),
        "unexpected cycle error: {error:?}"
    );
    let manifests: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM published_indexed_manifests")
        .fetch_one(store.pool())
        .await?;
    assert_eq!(manifests, 0);
    assert!(scheduler.remembered_chains.is_empty());
    let mismatches = scheduler
        .status
        .read()
        .await
        .chain_indexed_reuse_mismatches
        .clone();
    assert!(mismatches.is_empty(), "{mismatches:?}");
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn periodic_full_derivation_reports_a_stale_remembered_chunk() -> Result<()> {
    let (_postgres, store) = reconciliation_store().await?;
    index_reuse_blocks(&store, &[(100, 0), (200, 1), (300, 2)], 1).await?;
    let ipfs = Arc::new(ReconciliationIpfs::default());
    let mut scheduler = reuse_scheduler(&store, ipfs)?;
    let chain = scheduler.config.chain_indexed.chains[0].clone();
    let mut published = scheduler
        .publish_chain_entry(&chain, true)
        .await?
        .expect("published chain entry");
    let public_txid = published
        .remembered
        .iter_mut()
        .find(|dataset| dataset.dataset_kind == IndexedDatasetKind::PublicTxid)
        .expect("public TXID dataset");
    let stale_range = public_txid.chunks[0].range.clone();
    public_txid.chunks[0].sha256 = FixedBytes::ZERO;
    scheduler.remember_published_chains(vec![(
        (chain.chain_id, chain.railgun_contract),
        published.remembered,
    )]);

    // No full derivation has been recorded, so the cycle derives every chunk. The IPNS task is
    // not running, so the cycle fails after recording its manifest.
    let _ = scheduler
        .publish_cycle(UNIX_EPOCH + Duration::from_secs(STATISTICS_BLOCK_TIMESTAMP))
        .await
        .expect_err("chain-indexed IPNS publication is unavailable");

    let pending = Audit::pending_indexed_manifest_publication(
        store.pool(),
        &scheduler.signing_key.verifying_key().to_bytes(),
    )
    .await?
    .expect("pending chain-indexed manifest");
    let fresh = reuse_scheduler(&store, Arc::new(ReconciliationIpfs::default()))?
        .publish_chain_entry(&chain, true)
        .await?
        .expect("fresh chain entry");
    assert_eq!(pending.manifest.chains, vec![fresh.entry]);
    let mismatches = scheduler
        .status
        .read()
        .await
        .chain_indexed_reuse_mismatches
        .clone();
    assert_eq!(mismatches.len(), 1, "{mismatches:?}");
    assert_eq!(mismatches[0].chain_id, chain.chain_id);
    assert_eq!(
        mismatches[0].railgun_contract,
        chain.railgun_contract.to_string()
    );
    assert_eq!(mismatches[0].dataset, IndexedDatasetKind::PublicTxid);
    assert_eq!(
        (mismatches[0].range_start, mismatches[0].range_end),
        (stale_range.start, stale_range.end)
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn full_derivation_without_catalogs_reports_mismatches_and_forgets_remembered_chunks()
-> Result<()> {
    let (_postgres, store) = reconciliation_store().await?;
    index_reuse_blocks(&store, &[(100, 0), (200, 1), (300, 2)], 1).await?;
    let mut scheduler = reuse_scheduler(&store, Arc::new(ReconciliationIpfs::default()))?;
    scheduler.config.chain_indexed.chains[0].datasets = vec![IndexedDatasetKind::PublicTxid];
    let chain = scheduler.config.chain_indexed.chains[0].clone();
    let published = scheduler
        .publish_chain_entry(&chain, true)
        .await?
        .expect("published chain entry");
    let remembered_ranges = published
        .remembered
        .iter()
        .find(|dataset| dataset.dataset_kind == IndexedDatasetKind::PublicTxid)
        .expect("public TXID dataset")
        .chunks
        .iter()
        .map(|chunk| (chunk.range.start, chunk.range.end))
        .collect::<Vec<_>>();
    assert_eq!(remembered_ranges.len(), 2);
    scheduler.remember_published_chains(vec![(
        (chain.chain_id, chain.railgun_contract),
        published.remembered,
    )]);
    // An outside edit removes this chain's rows (the only chain); progress and headers stay.
    let _ = sqlx::query("DELETE FROM indexed_public_txid_rows")
        .execute(store.pool())
        .await?;

    let now = UNIX_EPOCH + Duration::from_secs(STATISTICS_BLOCK_TIMESTAMP);
    scheduler.publish_cycle(now).await?;

    let status = scheduler.status.clone();
    let reported = || async {
        status
            .read()
            .await
            .chain_indexed_reuse_mismatches
            .iter()
            .map(|mismatch| {
                (
                    mismatch.chain_id,
                    mismatch.railgun_contract.clone(),
                    mismatch.dataset,
                    mismatch.range_start,
                    mismatch.range_end,
                )
            })
            .collect::<Vec<_>>()
    };
    let expected = remembered_ranges
        .iter()
        .map(|&(start, end)| {
            (
                chain.chain_id,
                chain.railgun_contract.to_string(),
                IndexedDatasetKind::PublicTxid,
                start,
                end,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(reported().await, expected);
    assert!(scheduler.remembered_chains.is_empty());
    let manifests: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM published_indexed_manifests")
        .fetch_one(store.pool())
        .await?;
    assert_eq!(manifests, 0);
    assert_eq!(store.last_chain_indexed_ipns_sequence().await?, None);

    scheduler.publish_cycle(now).await?;
    assert_eq!(reported().await, expected);
    Ok(())
}

#[test]
fn oversized_snapshot_keeps_the_chains_last_snapshot_and_reports_why() {
    let kept = statistics_entry(1, "bafykept");
    let refreshed = statistics_entry(2, "bafyrefreshed");
    let oversized = eyre::Report::new(AmountStatisticsError::CompressedTooLarge {
        actual: 5 * 1024 * 1024,
        maximum: 4 * 1024 * 1024,
    })
    .wrap_err("encode amount-statistics snapshot");

    let (chains, failures) = next_manifest_chains(
        &[kept.clone(), statistics_entry(2, "bafystale")],
        vec![
            (kept.scope.clone(), Err(oversized)),
            (refreshed.scope.clone(), Ok(refreshed.clone())),
        ],
    );

    assert_eq!(chains, vec![kept, refreshed]);
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].chain_id, 1);
    assert!(
        failures[0].reason.contains("compressed size"),
        "{}",
        failures[0].reason
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
        amount_statistics: None,
        pin_lifecycle: PinLifecycleCoordinator::default(),
        canonicality: ChainCanonicalityCoordinator::default(),
        last_ipns_sequence: None,
        ipns_sequence_loaded: false,
        shutdown,
        chunk_planning: ChunkPlanningConfig::default(),
        remembered_chains: HashMap::new(),
        last_full_derivation: None,
        status: Status::default().shared(),
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
    contains_count: AtomicUsize,
    /// When set, the first pin or availability check signals the sender and waits on the receiver.
    park: Mutex<Option<ParkFirstCall>>,
}

type ParkFirstCall = (
    tokio::sync::oneshot::Sender<()>,
    tokio::sync::oneshot::Receiver<()>,
);

impl ReconciliationIpfs {
    async fn park_first_call(&self) {
        let park = self.park.lock().expect("park lock").take();
        if let Some((parked, release)) = park {
            let _ = parked.send(());
            let _ = release.await;
        }
    }

    fn returning(returned_cid: Cid) -> Self {
        Self {
            returned_cid: Some(returned_cid),
            ..Self::default()
        }
    }

    fn contains_count(&self) -> usize {
        self.contains_count.load(Ordering::SeqCst)
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
        self.park_first_call().await;
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
        self.park_first_call().await;
        self.contains_count.fetch_add(1, Ordering::SeqCst);
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

const STATISTICS_RAILGUN: Address = Address::repeat_byte(0xdd);
const STATISTICS_BLOCK: u64 = 100;
const STATISTICS_BLOCK_HASH: FixedBytes<32> = FixedBytes::repeat_byte(0x64);
const STATISTICS_BLOCK_TIMESTAMP: u64 = 1_700_000_000;

const fn statistics_scope() -> ChainScope {
    ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: STATISTICS_RAILGUN,
    }
}

/// Publishes one cycle on a fresh database and returns the chain-indexed manifest body.
async fn chain_indexed_manifest_json(statistics_enabled: bool) -> Result<String> {
    let (_postgres, store) = reconciliation_store().await?;
    seed_statistics_chain(&store).await?;
    let ipfs = Arc::new(ReconciliationIpfs::default());
    let mut scheduler =
        reconciliation_scheduler(store.clone(), ipfs, SigningKey::from_bytes(&[81; 32]))?;
    scheduler
        .config
        .chain_indexed
        .chains
        .push(ChainIndexedChainConfig {
            chain_id: 1,
            railgun_contract: STATISTICS_RAILGUN,
            rpc_url: "http://127.0.0.1:9".to_string(),
            ws_url: None,
            archive_rpc_url: "http://127.0.0.1:9".to_string(),
            start_block: 0,
            v2_start_block: 0,
            legacy_shield_block: 0,
            action_start_block: None,
            datasets: vec![
                IndexedDatasetKind::WalletScan,
                IndexedDatasetKind::PublicTxid,
            ],
            public_txid_compatibility_omissions: Vec::new(),
        });
    if statistics_enabled {
        let (_status, asserter, _) = enable_statistics(&mut scheduler)?;
        asserter.push_success(&statistics_block_json());
    }

    // Neither IPNS task runs, so the chain-indexed step fails after recording its manifest.
    let _ = scheduler
        .publish_cycles(UNIX_EPOCH + Duration::from_secs(STATISTICS_BLOCK_TIMESTAMP))
        .await
        .expect_err("chain-indexed IPNS publication is unavailable");

    let snapshots: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM published_amount_statistics_snapshots")
            .fetch_one(store.pool())
            .await?;
    assert_eq!(snapshots, i64::from(statistics_enabled));
    Ok(
        sqlx::query_scalar("SELECT manifest_json FROM published_indexed_manifests")
            .fetch_one(store.pool())
            .await?,
    )
}

/// Enables statistics for `statistics_scope` with a mocked RPC provider. The returned status is
/// the one statistics report to. The IPNS task is returned unrun, so every statistics IPNS
/// publication fails: at once when the caller drops the task, by timeout while it holds it.
fn enable_statistics(
    scheduler: &mut ChainIndexedPublicationScheduler,
) -> Result<(SharedStatus, Asserter, IpnsPublisherTask)> {
    let asserter = Asserter::new();
    let provider = ProviderBuilder::new()
        .connect_mocked_client(asserter.clone())
        .root()
        .clone();
    let (ipns_publisher, ipns_task) = IpnsPublisher::new_amount_statistics(
        &scheduler.signing_key,
        IpnsPublisherConfig {
            bootstrap_peers: Vec::new(),
            record_lifetime: Duration::from_mins(1),
            record_ttl: Duration::from_secs(30),
            publish_timeout: Duration::from_secs(1),
        },
    )?;
    let status = Status::default().shared();
    scheduler.amount_statistics = Some(AmountStatisticsPublication {
        ipns_publisher,
        chains: vec![(statistics_scope(), provider)],
        status: status.clone(),
        chain_timeout: Duration::from_secs(30),
    });
    Ok((status, asserter, ipns_task))
}

/// Indexes one USDC shield at `STATISTICS_BLOCK` with both datasets indexed through it.
async fn seed_statistics_chain(store: &Store) -> Result<()> {
    let shield = IndexedShieldCommitment {
        tree_number: 0,
        tree_position: 0,
        preimage: CommitmentPreimage {
            npk: FixedBytes::repeat_byte(0x01),
            token: TokenData {
                tokenType: 0,
                tokenAddress: Address::repeat_byte(0x11),
                tokenSubID: U256::ZERO,
            },
            value: Uint::<120, 2>::from(997_500_000_u64),
        },
        shield_ciphertext: ShieldCiphertext {
            encryptedBundle: [FixedBytes::repeat_byte(0x02); 3],
            shieldKey: FixedBytes::repeat_byte(0x03),
        },
        source: IndexedLogSource {
            block_number: STATISTICS_BLOCK,
            block_timestamp: Some(STATISTICS_BLOCK_TIMESTAMP),
            block_hash: STATISTICS_BLOCK_HASH,
            transaction_hash: FixedBytes::repeat_byte(0x10),
            log_index: 0,
        },
    };
    let batch = IndexedLogBatch {
        shield_commitments: vec![shield],
        ..Default::default()
    };
    let mut tx = store.begin().await?;
    Store::persist_indexed_log_batch(&mut tx, EVM_CHAIN_TYPE, 1, STATISTICS_RAILGUN, &batch)
        .await?;
    Store::record_indexed_block_header(
        &mut tx,
        EVM_CHAIN_TYPE,
        1,
        STATISTICS_BLOCK,
        STATISTICS_BLOCK_HASH.as_slice(),
        &[0; 32],
    )
    .await?;
    for dataset_kind in [StoreDatasetKind::WalletScan, StoreDatasetKind::PublicTxid] {
        Store::record_chain_indexing_progress(
            &mut tx,
            EVM_CHAIN_TYPE,
            1,
            STATISTICS_RAILGUN,
            dataset_kind,
            STATISTICS_BLOCK,
            STATISTICS_BLOCK_HASH.as_slice(),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// The `eth_getBlockByHash` response for the covered block.
fn statistics_block_json() -> serde_json::Value {
    let zero_hash = format!("0x{}", "00".repeat(32));
    serde_json::json!({
        "hash": STATISTICS_BLOCK_HASH,
        "parentHash": zero_hash,
        "sha3Uncles": zero_hash,
        "miner": Address::ZERO,
        "stateRoot": zero_hash,
        "transactionsRoot": zero_hash,
        "receiptsRoot": zero_hash,
        "logsBloom": format!("0x{}", "00".repeat(256)),
        "difficulty": "0x0",
        "number": format!("0x{STATISTICS_BLOCK:x}"),
        "gasLimit": "0x1c9c380",
        "gasUsed": "0x0",
        "timestamp": format!("0x{STATISTICS_BLOCK_TIMESTAMP:x}"),
        "extraData": "0x",
        "mixHash": zero_hash,
        "nonce": "0x0000000000000000",
        "uncles": [],
        "transactions": [],
    })
}

const REUSE_RAILGUN: Address = Address::repeat_byte(0xee);

/// A scheduler for chain 1 at `REUSE_RAILGUN` with all four datasets and limits low enough that a
/// few rows give several chunks.
fn reuse_scheduler(
    store: &Store,
    ipfs: Arc<ReconciliationIpfs>,
) -> Result<ChainIndexedPublicationScheduler> {
    let mut scheduler =
        reconciliation_scheduler(store.clone(), ipfs, SigningKey::from_bytes(&[85; 32]))?;
    scheduler.config.chain_indexed.public_txid_chunk_row_limit = 2;
    scheduler.config.chain_indexed.commitment_chunk_row_limit = 2;
    scheduler.chunk_planning = ChunkPlanningConfig {
        target_compressed_bytes: 1,
        soft_min_compressed_bytes: 1,
        soft_max_compressed_bytes: 1,
        ..ChunkPlanningConfig::default()
    };
    scheduler
        .config
        .chain_indexed
        .chains
        .push(ChainIndexedChainConfig {
            chain_id: 1,
            railgun_contract: REUSE_RAILGUN,
            rpc_url: "http://127.0.0.1:9".to_string(),
            ws_url: None,
            archive_rpc_url: "http://127.0.0.1:9".to_string(),
            start_block: 0,
            v2_start_block: 0,
            legacy_shield_block: 0,
            action_start_block: None,
            datasets: vec![
                IndexedDatasetKind::WalletScan,
                IndexedDatasetKind::Commitments,
                IndexedDatasetKind::MerkleCheckpoint,
                IndexedDatasetKind::PublicTxid,
            ],
            public_txid_compatibility_omissions: Vec::new(),
        });
    Ok(scheduler)
}

/// Publishes `chain` on `scheduler` and on a fresh scheduler, asserts both entries are equal,
/// remembers the incremental result as a published manifest would, and returns how many provider
/// calls the incremental and the full derivation made. Every derived chunk and catalog costs one
/// availability check or one pin; a reused chunk costs none.
async fn assert_incremental_equals_full(
    scheduler: &mut ChainIndexedPublicationScheduler,
    ipfs: &ReconciliationIpfs,
    store: &Store,
    chain: &ChainIndexedChainConfig,
) -> Result<(usize, usize)> {
    let provider_calls = |ipfs: &ReconciliationIpfs| ipfs.contains_count() + ipfs.pin_count();
    let calls_before = provider_calls(ipfs);
    let incremental = scheduler
        .publish_chain_entry(chain, false)
        .await?
        .expect("incremental chain entry");
    let incremental_checks = provider_calls(ipfs) - calls_before;
    let full_ipfs = Arc::new(ReconciliationIpfs::default());
    let full = reuse_scheduler(store, full_ipfs.clone())?
        .publish_chain_entry(chain, true)
        .await?
        .expect("full chain entry");

    assert_eq!(incremental.entry, full.entry);
    scheduler.remember_published_chains(vec![(
        (chain.chain_id, chain.railgun_contract),
        incremental.remembered,
    )]);
    Ok((incremental_checks, provider_calls(&full_ipfs)))
}

fn reuse_hash(block_number: u64, variant: u8) -> FixedBytes<32> {
    let mut hash = [variant; 32];
    hash[..8].copy_from_slice(&block_number.to_be_bytes());
    FixedBytes::from(hash)
}

/// One shield and one public transaction at `block_number` and `tree_position`.
fn reuse_block_batch(block_number: u64, tree_position: u64, variant: u8) -> IndexedLogBatch {
    let source = IndexedLogSource {
        block_number,
        block_timestamp: Some(STATISTICS_BLOCK_TIMESTAMP + block_number),
        block_hash: reuse_hash(block_number, variant),
        transaction_hash: reuse_hash(block_number, !variant),
        log_index: 0,
    };
    IndexedLogBatch {
        shield_commitments: vec![IndexedShieldCommitment {
            tree_number: 0,
            tree_position,
            preimage: CommitmentPreimage {
                npk: FixedBytes::repeat_byte(variant),
                token: TokenData {
                    tokenType: 0,
                    tokenAddress: Address::repeat_byte(0x11),
                    tokenSubID: U256::ZERO,
                },
                value: Uint::<120, 2>::from(tree_position + 1),
            },
            shield_ciphertext: ShieldCiphertext {
                encryptedBundle: [FixedBytes::repeat_byte(0x02); 3],
                shieldKey: FixedBytes::repeat_byte(0x03),
            },
            source: source.clone(),
        }],
        public_transactions: vec![IndexedPublicTransaction {
            source,
            first_log_index: 0,
            last_log_index: 0,
            railgun_transaction_index: 0,
            id: format!("0x{block_number:x}:{variant}"),
            block_timestamp: STATISTICS_BLOCK_TIMESTAMP + block_number,
            nullifiers: vec![FixedBytes::repeat_byte(variant)],
            commitments: vec![FixedBytes::repeat_byte(0x22)],
            bound_params_hash: FixedBytes::repeat_byte(0x23),
            has_unshield: false,
            unshield_preimage: None,
            utxo_tree_in: 0,
            utxo_tree_out: 0,
            utxo_batch_start_position_out: tree_position,
            railgun_txid: U256::from(block_number),
        }],
        ..Default::default()
    }
}

/// Indexes one shield and one public transaction per `(block, tree position)` and advances every
/// dataset to the last block. `variant` changes every row and block hash.
async fn index_reuse_blocks(store: &Store, blocks: &[(u64, u64)], variant: u8) -> Result<()> {
    let mut tx = store.begin().await?;
    for &(block_number, tree_position) in blocks {
        let batch = reuse_block_batch(block_number, tree_position, variant);
        Store::persist_indexed_log_batch(&mut tx, EVM_CHAIN_TYPE, 1, REUSE_RAILGUN, &batch).await?;
        Store::record_indexed_block_header(
            &mut tx,
            EVM_CHAIN_TYPE,
            1,
            block_number,
            reuse_hash(block_number, variant).as_slice(),
            &[0; 32],
        )
        .await?;
    }
    let &(last_block, _) = blocks.last().expect("at least one block");
    for dataset_kind in [
        StoreDatasetKind::WalletScan,
        StoreDatasetKind::Commitments,
        StoreDatasetKind::MerkleCheckpoint,
        StoreDatasetKind::PublicTxid,
    ] {
        Store::record_chain_indexing_progress(
            &mut tx,
            EVM_CHAIN_TYPE,
            1,
            REUSE_RAILGUN,
            dataset_kind,
            last_block,
            reuse_hash(last_block, variant).as_slice(),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

fn statistics_entry(chain_id: u64, cid: &str) -> AmountStatisticsChainEntry {
    AmountStatisticsChainEntry {
        scope: ChainScope {
            chain_id,
            ..statistics_scope()
        },
        covered_block: AmountStatisticsCoveredBlock {
            number: STATISTICS_BLOCK,
            hash: STATISTICS_BLOCK_HASH,
            timestamp: STATISTICS_BLOCK_TIMESTAMP,
        },
        snapshot: AmountStatisticsSnapshotDescriptor {
            cid: cid.to_string(),
            sha256: FixedBytes::ZERO,
            byte_size: 1,
            encoding_version: 1,
            compression: CompressionAlgorithm::Zstd,
        },
    }
}
