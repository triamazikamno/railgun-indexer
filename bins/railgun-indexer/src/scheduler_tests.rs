use super::*;
use async_trait::async_trait;
use cid::Cid;
use ed25519_dalek::{Signer, SigningKey};
use libp2p::PeerId;
use poi::artifacts::SnapshotEvent;
use poi::artifacts::v4::Manifest;
use poi::artifacts::verify::canonical_poi_event_message;
use poi::cache::{PoiCache, PoiCacheIdentity};
use poi::poi::{PoiEventType, SignedBlockedShield, SignedPoiEvent};
use railgun_indexer_core::audit::Retention;
use railgun_indexer_core::publish::ipfs::{IpfsError, raw_block_cid};
use railgun_indexer_core::publish::ipns::{IpnsError, IpnsPublication};
use railgun_indexer_core::store::{StoredEvent, run_migrations};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ContainerAsync;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tokio::sync::Notify;

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn scheduler_revalidates_unchanged_tip_and_rejects_before_v4_pins() -> Result<()> {
    let (_postgres, store) = postgres_store().await?;
    let signing_key = SigningKey::from_bytes(&[31; 32]);
    let root = seed_events(&store, &signing_key, 1, "http://unused.invalid").await?;
    let root_server = RootServer::start(true).await?;
    let mut config = test_config(root_server.url.clone(), &signing_key, vec![1]);
    replace_tip_upstream(
        &store,
        &signing_key,
        "http://unused.invalid",
        &root_server.url,
    )
    .await?;
    config.upstream_url.clone_from(&root_server.url);
    let ipfs = Arc::new(MemoryIpfs::default());
    let publisher = Arc::new(MockPublisher::default());
    let scheduler = scheduler(
        &config,
        store,
        ipfs.clone(),
        signing_key,
        publisher.clone(),
        publisher,
    );

    let first = scheduler
        .publish_poi_artifact_graph(SystemTime::now())
        .await?;
    assert_eq!(first.entries[0].current_root, Some(root));
    assert_eq!(root_server.calls(), 1);
    let pinned_after_accept = ipfs.pin_count();
    root_server.accept.store(false, Ordering::SeqCst);
    ipfs.clear_bytes();
    ipfs.block_pin.store(true, Ordering::SeqCst);

    let error = tokio::time::timeout(
        Duration::from_secs(1),
        scheduler.publish_poi_artifact_graph(SystemTime::now()),
    )
    .await
    .expect("root rejection must happen before an unavailable pin can block")
    .expect_err("rejected unchanged root must fail publication preparation");
    assert!(
        error
            .to_string()
            .contains("upstream rejected replayed POI roots")
    );
    assert_eq!(root_server.calls(), 2);
    assert_eq!(ipfs.pin_count(), pinned_after_accept);
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn scheduler_publishes_four_empty_scopes_and_reuses_graph_after_restart() -> Result<()> {
    let (_postgres, store) = postgres_store().await?;
    let signing_key = SigningKey::from_bytes(&[32; 32]);
    let root_server = RootServer::start(true).await?;
    let config = test_config(
        root_server.url.clone(),
        &signing_key,
        vec![1, 56, 137, 42161],
    );
    let ipfs = Arc::new(MemoryIpfs::default());
    let legacy = Arc::new(MockPublisher::default());
    let v4 = Arc::new(MockPublisher::default());
    let now = SystemTime::now();
    let mut first = scheduler(
        &config,
        store.clone(),
        ipfs.clone(),
        signing_key.clone(),
        legacy.clone(),
        v4.clone(),
    );
    first.publish_cycle(now).await?;

    assert!(legacy.calls().is_empty());
    let poi_artifact_calls = v4.calls();
    assert_eq!(poi_artifact_calls.len(), 1);
    let manifest = Manifest::read(&ipfs.bytes(&poi_artifact_calls[0].0)?)?;
    assert_eq!(manifest.entries.len(), 4);
    assert!(manifest.entries.iter().all(|entry| {
        entry.event_count == 0
            && entry.current_tip_index.is_none()
            && entry.current_root.is_none()
            && entry.current_tail.is_none()
    }));
    let pins = ipfs.pin_count();

    let mut restarted = scheduler(
        &config,
        store,
        ipfs.clone(),
        signing_key,
        legacy,
        v4.clone(),
    );
    restarted
        .publish_cycle(now + Duration::from_secs(1))
        .await?;
    assert_eq!(v4.calls(), poi_artifact_calls);
    assert_eq!(ipfs.pin_count(), pins);
    let restored_status = restarted.status.read().await;
    let publication = restored_status
        .poi_artifact_publication
        .as_ref()
        .expect("active POI artifact status restored without republishing");
    assert_eq!(publication.manifest_cid, poi_artifact_calls[0].0);
    assert_eq!(publication.sequence, poi_artifact_calls[0].1);
    assert_eq!(publication.scopes.len(), 4);
    assert_eq!(publication.checkpoint_bytes, None);
    assert_eq!(publication.reused_cids, None);
    assert_eq!(publication.elapsed_ms, None);
    assert!(!restored_status.ipfs_reachable);
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn scheduler_processes_v4_when_legacy_activation_fails_and_reconciles_restart() -> Result<()>
{
    let (_postgres, store) = postgres_store().await?;
    let signing_key = SigningKey::from_bytes(&[33; 32]);
    let root_server = RootServer::start(true).await?;
    seed_events(&store, &signing_key, 1, &root_server.url).await?;
    let config = test_config(root_server.url.clone(), &signing_key, vec![1]);
    let ipfs = Arc::new(MemoryIpfs::default());
    let legacy = Arc::new(MockPublisher::default());
    let v4 = Arc::new(MockPublisher::default());
    install_legacy_activation_failure(store.pool()).await?;
    let now = SystemTime::now();
    let mut first = scheduler(
        &config,
        store.clone(),
        ipfs.clone(),
        signing_key.clone(),
        legacy.clone(),
        v4.clone(),
    );
    let _error = first
        .publish_cycle(now)
        .await
        .expect_err("legacy activation failure must fail the combined cycle");

    assert_eq!(legacy.calls().len(), 1);
    assert_eq!(v4.calls().len(), 1);
    let pending = Audit::pending_manifest_publication(store.pool())
        .await?
        .expect("legacy manifest remains pending");
    assert!(
        Audit::pending_poi_artifact_manifest_publication(store.pool())
            .await?
            .is_none()
    );
    assert!(
        Audit::active_poi_artifact_manifest_publication(store.pool())
            .await?
            .is_some()
    );

    drop_legacy_activation_failure(store.pool()).await?;
    let mut restarted = scheduler(
        &config,
        store.clone(),
        ipfs,
        signing_key,
        legacy.clone(),
        v4.clone(),
    );
    restarted
        .publish_cycle(now + Duration::from_secs(1))
        .await?;
    assert_eq!(
        legacy.calls().last(),
        Some(&(pending.cid, pending.sequence))
    );
    assert_eq!(
        v4.calls().len(),
        1,
        "active v4 channel must not be replayed"
    );
    assert!(
        Audit::pending_manifest_publication(store.pool())
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn early_rotation_bridges_prior_tail_and_reuses_exact_cids() -> Result<()> {
    let (_postgres, store) = postgres_store().await?;
    let signing_key = SigningKey::from_bytes(&[34; 32]);
    let root_server = RootServer::start(true).await?;
    let config = test_config(root_server.url.clone(), &signing_key, vec![1]);
    let ipfs = Arc::new(MemoryIpfs::default());
    let publisher = Arc::new(MockPublisher::default());
    let scheduler = scheduler(
        &config,
        store,
        ipfs.clone(),
        signing_key.clone(),
        publisher.clone(),
        publisher,
    );
    let empty = corpus(&signing_key, 0)?;
    let now = SystemTime::now();
    let empty_entry = scheduler
        .publish_poi_artifact_entry(now, &empty, None)
        .await?;
    let empty_active = active_graph(empty_entry.entry, now);
    let prior = corpus(&signing_key, 32_768)?;
    let prior_entry = scheduler
        .publish_poi_artifact_entry(now, &prior, Some(&empty_active))
        .await?;
    assert_eq!(
        prior_entry
            .entry
            .current_tail
            .as_ref()
            .map(|tail| tail.range.start_index),
        Some(0)
    );
    let prior_active = active_graph(prior_entry.entry, now);
    let current = corpus(&signing_key, 44_000)?;

    let rotated = scheduler
        .publish_poi_artifact_entry(now, &current, Some(&prior_active))
        .await?;
    assert_eq!(rotated.entry.checkpoint_catalog.row_count, 32_768);
    let bridge = rotated
        .entry
        .retained_bridges
        .last()
        .expect("promoted bridge");
    assert_eq!(
        (bridge.range.start_index, bridge.range.end_index),
        (0, 32_767)
    );
    let tail = rotated
        .entry
        .current_tail
        .as_ref()
        .expect("post-rotation tail");
    assert_eq!(
        (tail.range.start_index, tail.range.end_index),
        (32_768, 43_999)
    );
    assert_eq!(
        bridge.end_root,
        prior_active.entry.current_root.expect("prior root")
    );
    assert_eq!(
        tail.end_root,
        rotated.entry.current_root.expect("current root")
    );
    let pins = ipfs.pin_count();

    let repeated = scheduler
        .publish_poi_artifact_entry(now, &current, Some(&prior_active))
        .await?;
    assert_eq!(repeated.entry, rotated.entry);
    assert_eq!(ipfs.pin_count(), pins);
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn oversized_suffix_after_active_graph_without_tail_keeps_prior_graph_active() -> Result<()> {
    assert_oversized_suffix_cycle_fails_closed(false, [38; 32]).await
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn oversized_newer_suffix_after_active_tail_keeps_prior_graph_active() -> Result<()> {
    assert_oversized_suffix_cycle_fails_closed(true, [39; 32]).await
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn pending_v4_survives_activation_failure_retention_and_restart() -> Result<()> {
    let (_postgres, store) = postgres_store().await?;
    let signing_key = SigningKey::from_bytes(&[35; 32]);
    let list_key = FixedBytes::from(signing_key.verifying_key().to_bytes());
    let root_server = RootServer::start(true).await?;
    let config = test_config(root_server.url.clone(), &signing_key, vec![1]);
    let ipfs = Arc::new(MemoryIpfs::default());
    let legacy = Arc::new(MockPublisher::default());
    let v4 = Arc::new(MockPublisher::default());
    install_v4_activation_failure(store.pool()).await?;
    let now = SystemTime::now();
    let mut first = scheduler(
        &config,
        store.clone(),
        ipfs.clone(),
        signing_key.clone(),
        legacy.clone(),
        v4.clone(),
    );
    let _error = first
        .publish_cycle(now)
        .await
        .expect_err("activation trigger must fail after IPNS dispatch");
    let pending = Audit::pending_poi_artifact_manifest_publication(store.pool())
        .await?
        .expect("POI artifact graph remains pending");
    assert_eq!(v4.calls(), vec![(pending.cid.clone(), pending.sequence)]);

    age_v4_rows(store.pool(), 100).await?;
    let sweep = Retention::sweep_with_coordinator(
        store.pool(),
        ipfs.as_ref(),
        UNIX_EPOCH + Duration::from_secs(200),
        Duration::from_secs(50),
        &PinLifecycleCoordinator::default(),
    )
    .await?;
    assert!(sweep.unpinned_cids.is_empty());
    drop_v4_activation_failure(store.pool()).await?;

    let mut restarted = scheduler(
        &config,
        store.clone(),
        ipfs.clone(),
        signing_key,
        legacy,
        v4.clone(),
    );
    restarted
        .publish_cycle(now + Duration::from_secs(1))
        .await?;
    assert_eq!(
        v4.calls(),
        vec![
            (pending.cid.clone(), pending.sequence),
            (pending.cid.clone(), pending.sequence)
        ]
    );
    assert!(
        Audit::pending_poi_artifact_manifest_publication(store.pool())
            .await?
            .is_none()
    );
    assert_eq!(
        Audit::active_poi_artifact_manifest_publication(store.pool())
            .await?
            .expect("reconciled active POI artifact manifest")
            .cid,
        pending.cid
    );

    let old_active = Audit::active_poi_artifact_manifest_publication(store.pool())
        .await?
        .expect("old active POI artifact graph");
    let old_graph_cids = graph_cids(&old_active.entries[0]);
    let mut tx = store.begin().await?;
    Store::upsert_blocked_shields(
        &mut tx,
        &list_key,
        1,
        &[SignedBlockedShield {
            commitment_hash: hex::encode_prefixed([41; 32]),
            blinded_commitment: hex::encode_prefixed([42; 32]),
            block_reason: Some("new graph".to_string()),
            signature: hex::encode_prefixed([43; 64]),
        }],
    )
    .await?;
    tx.commit().await?;
    restarted
        .publish_cycle(now + Duration::from_mins(1))
        .await?;
    let new_active = Audit::active_poi_artifact_manifest_publication(store.pool())
        .await?
        .expect("new active POI artifact graph");
    let new_graph_cids = graph_cids(&new_active.entries[0]);
    let shared = old_graph_cids
        .intersection(&new_graph_cids)
        .cloned()
        .collect::<BTreeSet<_>>();
    let old_only = old_graph_cids
        .difference(&new_graph_cids)
        .cloned()
        .collect::<BTreeSet<_>>();
    assert!(!shared.is_empty());
    assert!(!old_only.is_empty());
    age_v4_rows(store.pool(), 100).await?;
    let sweep = Retention::sweep_with_coordinator(
        store.pool(),
        ipfs.as_ref(),
        UNIX_EPOCH + Duration::from_secs(200),
        Duration::from_secs(50),
        &PinLifecycleCoordinator::default(),
    )
    .await?;
    let unpinned = sweep
        .unpinned_cids
        .into_iter()
        .map(|cid| cid.to_string())
        .collect::<BTreeSet<_>>();
    assert!(unpinned.contains(&old_active.cid));
    assert!(old_only.is_subset(&unpinned));
    assert!(shared.is_disjoint(&unpinned));
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn pending_graph_is_retention_protected_while_ipns_is_blocked() -> Result<()> {
    let (_postgres, store) = postgres_store().await?;
    let signing_key = SigningKey::from_bytes(&[36; 32]);
    let root_server = RootServer::start(true).await?;
    let config = test_config(root_server.url.clone(), &signing_key, vec![1]);
    let ipfs = Arc::new(MemoryIpfs::default());
    let legacy = Arc::new(MockPublisher::default());
    let v4 = Arc::new(MockPublisher::default());
    v4.blocking.store(true, Ordering::SeqCst);
    let now = SystemTime::now();
    let mut publisher_scheduler = scheduler(
        &config,
        store.clone(),
        ipfs.clone(),
        signing_key,
        legacy,
        v4.clone(),
    );
    let publication = tokio::spawn(async move { publisher_scheduler.publish_cycle(now).await });
    v4.entered.notified().await;
    assert!(
        Audit::pending_poi_artifact_manifest_publication(store.pool())
            .await?
            .is_some()
    );
    age_v4_rows(store.pool(), 100).await?;
    let sweep = Retention::sweep_with_coordinator(
        store.pool(),
        ipfs.as_ref(),
        UNIX_EPOCH + Duration::from_secs(200),
        Duration::from_secs(50),
        &PinLifecycleCoordinator::default(),
    )
    .await?;
    assert!(sweep.unpinned_cids.is_empty());
    v4.release.notify_waiters();
    publication.await??;
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn shutdown_during_ipns_preserves_pending_graph_for_restart_reconciliation() -> Result<()> {
    let (_postgres, store) = postgres_store().await?;
    let signing_key = SigningKey::from_bytes(&[44; 32]);
    let root_server = RootServer::start(true).await?;
    let config = test_config(root_server.url.clone(), &signing_key, vec![1]);
    let ipfs = Arc::new(MemoryIpfs::default());
    let legacy = Arc::new(MockPublisher::default());
    let v4 = Arc::new(MockPublisher::default());
    v4.blocking.store(true, Ordering::SeqCst);
    let publication_scheduler = scheduler(
        &config,
        store.clone(),
        ipfs.clone(),
        signing_key.clone(),
        legacy.clone(),
        v4.clone(),
    );
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let publication = tokio::spawn(run_publication_scheduler(
        publication_scheduler,
        shutdown_rx,
    ));
    v4.entered.notified().await;
    let pending = Audit::pending_poi_artifact_manifest_publication(store.pool())
        .await?
        .expect("POI artifact graph is pending before uncertain IPNS completion");

    shutdown_tx.send(true)?;
    v4.release.notify_waiters();
    tokio::time::timeout(Duration::from_secs(1), publication)
        .await
        .expect("publication scheduler must honor shutdown")??;
    assert!(
        Audit::active_poi_artifact_manifest_publication(store.pool())
            .await?
            .is_none()
    );
    assert_eq!(
        Audit::pending_poi_artifact_manifest_publication(store.pool())
            .await?
            .expect("pending POI artifact graph survives shutdown"),
        pending
    );

    v4.blocking.store(false, Ordering::SeqCst);
    let mut restarted = scheduler(
        &config,
        store.clone(),
        ipfs,
        signing_key,
        legacy,
        v4.clone(),
    );
    restarted.publish_cycle(SystemTime::now()).await?;
    assert_eq!(
        v4.calls().last(),
        Some(&(pending.cid.clone(), pending.sequence))
    );
    assert!(
        Audit::pending_poi_artifact_manifest_publication(store.pool())
            .await?
            .is_none()
    );
    assert_eq!(
        Audit::active_poi_artifact_manifest_publication(store.pool())
            .await?
            .expect("restart reconciled POI artifact graph")
            .cid,
        pending.cid
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn publisher_advisory_lock_excludes_offline_recovery_process() -> Result<()> {
    let (_postgres, store) = postgres_store().await?;
    let lock = PgAdvisoryLock::new(PUBLISHER_ADVISORY_LOCK_NAME);
    let guard = try_acquire_publisher_lock(&lock, store.pool()).await?;

    let Err(error) = try_acquire_publisher_lock(&lock, store.pool()).await else {
        return Err(eyre!(
            "a second publisher or recovery process acquired the lock"
        ));
    };
    assert!(
        error
            .to_string()
            .contains("publisher advisory lock is held")
    );

    guard.release_now().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn scheduler_pin_and_audit_exclude_concurrent_retention_recheck() -> Result<()> {
    let (_postgres, store) = postgres_store().await?;
    let signing_key = SigningKey::from_bytes(&[37; 32]);
    let root_server = RootServer::start(true).await?;
    let config = test_config(root_server.url.clone(), &signing_key, vec![1]);
    let ipfs = Arc::new(MemoryIpfs::default());
    let stale_bytes = b"stale scheduler retention candidate";
    let stale_cid = ipfs.insert_untracked(stale_bytes)?;
    let stale_scope = Scope::new(
        FixedBytes::from(signing_key.verifying_key().to_bytes()),
        0,
        1,
        "V2_PoseidonMerkle",
    );
    let mut tx = store.begin().await?;
    Audit::record_poi_artifact_pin(
        &mut tx,
        PoiArtifactPublicationKind::CheckpointCatalog,
        &stale_scope,
        None,
        &stale_cid,
        u64::try_from(stale_bytes.len())?,
        &content_hash(stale_bytes),
        None,
        "{}",
    )
    .await?;
    tx.commit().await?;
    age_v4_rows(store.pool(), 100).await?;
    ipfs.block_pin.store(true, Ordering::SeqCst);
    let coordinator = PinLifecycleCoordinator::default();
    let mut publisher_scheduler = scheduler_with_coordinator(
        &config,
        store.clone(),
        ipfs.clone(),
        signing_key,
        Arc::new(MockPublisher::default()),
        Arc::new(MockPublisher::default()),
        coordinator.clone(),
    );
    let now = SystemTime::now();
    let publication = tokio::spawn(async move { publisher_scheduler.publish_cycle(now).await });
    ipfs.pin_entered.notified().await;

    let retention_store = store.clone();
    let retention_ipfs = ipfs.clone();
    let retention_coordinator = coordinator.clone();
    let mut retention = tokio::spawn(async move {
        Retention::sweep_with_coordinator(
            retention_store.pool(),
            retention_ipfs.as_ref(),
            UNIX_EPOCH + Duration::from_secs(200),
            Duration::from_secs(50),
            &retention_coordinator,
        )
        .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut retention)
            .await
            .is_err(),
        "retention must wait while the scheduler owns pin/audit lifecycle"
    );
    ipfs.block_pin.store(false, Ordering::SeqCst);
    ipfs.pin_release.notify_waiters();
    publication.await??;
    assert_eq!(retention.await??.unpinned_cids, vec![stale_cid]);
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn snapshot_audit_failure_cleans_fresh_pin_after_reference_recheck() -> Result<()> {
    let (_postgres, store) = postgres_store().await?;
    let signing_key = SigningKey::from_bytes(&[47; 32]);
    let root_server = RootServer::start(true).await?;
    let root = seed_events(&store, &signing_key, 1, &root_server.url).await?;
    sqlx::query(
        "CREATE FUNCTION reject_snapshot_audit() RETURNS trigger AS $$ \
         BEGIN RAISE EXCEPTION 'forced snapshot audit failure'; END; \
         $$ LANGUAGE plpgsql",
    )
    .execute(store.pool())
    .await?;
    sqlx::query(
        "CREATE TRIGGER reject_snapshot_audit BEFORE INSERT ON published_snapshots \
         FOR EACH ROW EXECUTE FUNCTION reject_snapshot_audit()",
    )
    .execute(store.pool())
    .await?;
    let config = test_config(root_server.url.clone(), &signing_key, vec![1]);
    let ipfs = Arc::new(MemoryIpfs::default());
    let publisher = Arc::new(MockPublisher::default());
    let scheduler = scheduler(
        &config,
        store.clone(),
        ipfs.clone(),
        signing_key,
        publisher.clone(),
        publisher,
    );

    let _error = scheduler
        .publish_snapshot(&config.list_keys[0], 1, SnapshotKind::Base, 0, 0, &root.0)
        .await
        .expect_err("forced snapshot audit failure must fail publication");

    assert_eq!(ipfs.pin_count(), 1);
    assert_eq!(ipfs.unpinned_count(), 1);
    assert_eq!(row_count(store.pool(), "published_snapshots").await?, 0);
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn shutdown_after_snapshot_pin_finishes_audit_then_stops_before_new_work() -> Result<()> {
    let (_postgres, store) = postgres_store().await?;
    let signing_key = SigningKey::from_bytes(&[48; 32]);
    let root_server = RootServer::start(true).await?;
    seed_events(&store, &signing_key, 1, &root_server.url).await?;
    let config = test_config(root_server.url.clone(), &signing_key, vec![1]);
    let ipfs = Arc::new(MemoryIpfs::default());
    ipfs.block_pin.store(true, Ordering::SeqCst);
    let publisher = Arc::new(MockPublisher::default());
    let mut scheduler = scheduler(
        &config,
        store.clone(),
        ipfs.clone(),
        signing_key,
        publisher.clone(),
        publisher,
    );
    let (shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
    scheduler.shutdown = Some(shutdown);
    let list_key = config.list_keys[0];
    let publication = tokio::spawn(async move {
        scheduler
            .publish_pair(&list_key, 1, SystemTime::now())
            .await
    });
    ipfs.pin_entered.notified().await;
    shutdown_tx.send(true).expect("request shutdown");
    ipfs.pin_release.notify_waiters();

    let error = publication
        .await
        .expect("join cooperative snapshot publication")
        .expect_err("shutdown boundary must stop after durable audit");
    assert!(error.to_string().contains("cooperative shutdown boundary"));
    assert_eq!(row_count(store.pool(), "published_snapshots").await?, 1);
    assert_eq!(
        row_count(store.pool(), "published_blocked_shields").await?,
        0
    );
    assert_eq!(ipfs.pin_count(), 1);
    assert_eq!(ipfs.unpinned_count(), 0);
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn second_dual_manifest_pin_failure_cleans_first_uncommitted_manifest_pin() -> Result<()> {
    let (_postgres, store) = postgres_store().await?;
    let signing_key = SigningKey::from_bytes(&[49; 32]);
    let root_server = RootServer::start(true).await?;
    seed_events(&store, &signing_key, 1, &root_server.url).await?;
    let config = test_config(root_server.url.clone(), &signing_key, vec![1]);
    let ipfs = Arc::new(MemoryIpfs::default());
    let publisher = Arc::new(MockPublisher::default());
    let scheduler = scheduler(
        &config,
        store.clone(),
        ipfs.clone(),
        signing_key,
        publisher.clone(),
        publisher,
    );
    let now = SystemTime::now();
    scheduler.publish_pair(&config.list_keys[0], 1, now).await?;
    let poi_graph = scheduler.publish_poi_artifact_graph(now).await?;
    let legacy_entries = scheduler.manifest_entries().await?;
    assert!(!legacy_entries.is_empty());
    let lease = scheduler
        .sequence_allocator
        .reserve_cycle(unix_millis(now)?)
        .await?;
    ipfs.fail_pin_at
        .store(ipfs.pin_attempts() + 2, Ordering::SeqCst);
    let unpinned_before = ipfs.unpinned_count();

    let _error = scheduler
        .publish_poi_manifests(now, lease, legacy_entries, &poi_graph)
        .await
        .err()
        .expect("second manifest pin must fail");

    assert_eq!(ipfs.unpinned_count(), unpinned_before + 1);
    assert_eq!(row_count(store.pool(), "published_manifests").await?, 0);
    assert_eq!(
        row_count(store.pool(), "published_poi_v4_manifests").await?,
        0
    );
    Ok(())
}

fn scheduler(
    config: &Config,
    store: Store,
    ipfs: Arc<MemoryIpfs>,
    signing_key: SigningKey,
    legacy: Arc<MockPublisher>,
    v4: Arc<MockPublisher>,
) -> PublicationScheduler {
    scheduler_with_coordinator(
        config,
        store,
        ipfs,
        signing_key,
        legacy,
        v4,
        PinLifecycleCoordinator::default(),
    )
}

async fn assert_oversized_suffix_cycle_fails_closed(
    with_prior_tail: bool,
    signing_seed: [u8; 32],
) -> Result<()> {
    let (_postgres, store) = postgres_store().await?;
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let root_server = RootServer::start(true).await?;
    seed_events(&store, &signing_key, 1, &root_server.url).await?;
    let config = test_config(root_server.url.clone(), &signing_key, vec![1]);
    let ipfs = Arc::new(MemoryIpfs::default());
    let legacy = Arc::new(MockPublisher::default());
    let v4 = Arc::new(MockPublisher::default());
    let now = SystemTime::now();
    let mut scheduler = scheduler(
        &config,
        store.clone(),
        ipfs.clone(),
        signing_key.clone(),
        legacy,
        v4.clone(),
    );
    scheduler.publish_cycle(now).await?;
    if with_prior_tail {
        seed_events(&store, &signing_key, 2, &root_server.url).await?;
        scheduler
            .publish_cycle(now + Duration::from_secs(1))
            .await?;
    }

    let prior = Audit::active_poi_artifact_manifest_publication(store.pool())
        .await?
        .expect("prior POI artifact graph is active");
    assert_eq!(prior.entries[0].current_tail.is_some(), with_prior_tail);
    let protected = active_v4_cids(store.pool(), &prior.cid).await?;
    let prior_calls = v4.calls();
    let prior_manifest_count = v4_manifest_count(store.pool()).await?;
    let event_count = if with_prior_tail { 44_002 } else { 44_001 };
    seed_events(&store, &signing_key, event_count, &root_server.url).await?;

    for attempt in 0..2 {
        let _error = scheduler
            .publish_cycle(now + Duration::from_secs(2 + attempt))
            .await
            .expect_err("oversized post-publication suffix must fail closed");
        let active = Audit::active_poi_artifact_manifest_publication(store.pool())
            .await?
            .expect("prior POI artifact graph remains active");
        assert_eq!(active.cid, prior.cid);
        assert_eq!(active.entries, prior.entries);
        assert_eq!(v4.calls(), prior_calls);
        assert_eq!(v4_manifest_count(store.pool()).await?, prior_manifest_count);
        assert!(
            Audit::pending_poi_artifact_manifest_publication(store.pool())
                .await?
                .is_none()
        );
    }

    age_v4_rows(store.pool(), 100).await?;
    let sweep = Retention::sweep_with_coordinator(
        store.pool(),
        ipfs.as_ref(),
        UNIX_EPOCH + Duration::from_secs(200),
        Duration::from_secs(50),
        &PinLifecycleCoordinator::default(),
    )
    .await?;
    let unpinned = sweep
        .unpinned_cids
        .into_iter()
        .map(|cid| cid.to_string())
        .collect::<BTreeSet<_>>();
    assert!(protected.is_disjoint(&unpinned));
    for cid in protected {
        let cid = cid.parse::<Cid>()?;
        assert!(ipfs.contains(&cid).await?);
    }
    let active_after_sweep = Audit::active_poi_artifact_manifest_publication(store.pool())
        .await?
        .expect("prior POI artifact graph remains active after retention");
    assert_eq!(active_after_sweep.cid, prior.cid);
    assert_eq!(active_after_sweep.entries, prior.entries);
    Ok(())
}

async fn active_v4_cids(pool: &sqlx::PgPool, manifest_cid: &str) -> Result<BTreeSet<String>> {
    let mut cids = sqlx::query_scalar::<_, String>(
        r"
        SELECT reference.artifact_cid
        FROM published_poi_v4_manifest_artifacts AS reference
        JOIN published_poi_v4_manifests AS manifest ON manifest.id = reference.manifest_id
        WHERE manifest.cid = $1
        ",
    )
    .bind(manifest_cid)
    .fetch_all(pool)
    .await?
    .into_iter()
    .collect::<BTreeSet<_>>();
    cids.insert(manifest_cid.to_string());
    Ok(cids)
}

async fn v4_manifest_count(pool: &sqlx::PgPool) -> Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT COUNT(*) FROM published_poi_v4_manifests")
            .fetch_one(pool)
            .await?,
    )
}

fn scheduler_with_coordinator(
    config: &Config,
    store: Store,
    ipfs: Arc<MemoryIpfs>,
    signing_key: SigningKey,
    legacy: Arc<MockPublisher>,
    v4: Arc<MockPublisher>,
    pin_lifecycle: PinLifecycleCoordinator,
) -> PublicationScheduler {
    PublicationScheduler::new(
        config.clone(),
        store,
        ipfs,
        signing_key,
        PoiRpcClient::new(url::Url::parse(&config.upstream_url).expect("test upstream URL")),
        legacy,
        v4,
        Status::for_pairs(&config.list_keys, &config.chain_ids, config.page_size_max).shared(),
        pin_lifecycle,
    )
}

fn test_config(upstream_url: String, signing_key: &SigningKey, chain_ids: Vec<u64>) -> Config {
    let mut config: Config =
        serde_yaml::from_str(include_str!("../../../config.railgun-indexer.example.yaml"))
            .expect("example config");
    config.upstream_url = upstream_url;
    config.list_keys = vec![FixedBytes::from(signing_key.verifying_key().to_bytes())];
    config.chain_ids = chain_ids;
    config.txid_version = "V2_PoseidonMerkle".to_string();
    config.base_rebuild_interval = Duration::from_hours(24).into();
    config.delta_publish_interval = Duration::from_mins(10).into();
    config.ipns_republish_interval = Duration::from_hours(1).into();
    config.chain_indexed.enabled = false;
    config
}

async fn postgres_store() -> Result<(ContainerAsync<Postgres>, Store)> {
    let node = Postgres::default()
        .start()
        .await
        .wrap_err("start Docker PostgreSQL; this ignored test requires Docker")?;
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&connection_string)
        .await?;
    run_migrations(&pool).await?;
    Ok((node, Store::new(pool)))
}

async fn row_count(pool: &sqlx::PgPool, table: &str) -> Result<i64> {
    let query = format!("SELECT COUNT(*) FROM {table}");
    Ok(sqlx::query_scalar(&query).fetch_one(pool).await?)
}

async fn seed_events(
    store: &Store,
    signing_key: &SigningKey,
    count: u64,
    upstream_url: &str,
) -> Result<FixedBytes<32>> {
    let signed = signed_events(signing_key, count);
    let stored = stored_events(&signed)?;
    let replayed = ValidatedCorpus::replay(
        Scope::new(
            FixedBytes::from(signing_key.verifying_key().to_bytes()),
            0,
            1,
            "V2_PoseidonMerkle",
        ),
        &stored,
        Some(replay_root(signing_key, &stored)?),
    )?;
    let root = replayed.root_at(count - 1)?;
    let mut tx = store.begin().await?;
    Store::insert_events(
        &mut tx,
        &FixedBytes::from(signing_key.verifying_key().to_bytes()),
        1,
        &signed,
    )
    .await?;
    Store::advance_chain_tip(
        &mut tx,
        &FixedBytes::from(signing_key.verifying_key().to_bytes()),
        1,
        upstream_url,
        count - 1,
        Some(&hex::encode_prefixed(root)),
    )
    .await?;
    tx.commit().await?;
    Ok(root)
}

async fn replace_tip_upstream(
    store: &Store,
    signing_key: &SigningKey,
    old: &str,
    new: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE chain_tips SET upstream_url = $1 WHERE list_key = $2 AND upstream_url = $3",
    )
    .bind(new)
    .bind(signing_key.verifying_key().as_bytes().as_slice())
    .bind(old)
    .execute(store.pool())
    .await?;
    Ok(())
}

fn corpus(signing_key: &SigningKey, count: u64) -> Result<ValidatedCorpus> {
    let signed = signed_events(signing_key, count);
    let stored = stored_events(&signed)?;
    let root = if stored.is_empty() {
        None
    } else {
        Some(replay_root(signing_key, &stored)?)
    };
    Ok(ValidatedCorpus::replay(
        Scope::new(
            FixedBytes::from(signing_key.verifying_key().to_bytes()),
            0,
            1,
            "V2_PoseidonMerkle",
        ),
        &stored,
        root,
    )?)
}

fn signed_events(signing_key: &SigningKey, count: u64) -> Vec<SignedPoiEvent> {
    (0..count)
        .map(|index| {
            let mut event = SignedPoiEvent {
                index,
                blinded_commitment: FixedBytes::from(index_bytes(index)),
                signature: String::new(),
                event_type: PoiEventType::Shield,
            };
            event.signature = hex::encode(
                signing_key
                    .sign(&canonical_poi_event_message(&event))
                    .to_bytes(),
            );
            event
        })
        .collect()
}

fn stored_events(events: &[SignedPoiEvent]) -> Result<Vec<StoredEvent>> {
    events
        .iter()
        .map(|event| {
            Ok(StoredEvent {
                event_index: event.index,
                blinded_commitment: event.blinded_commitment.0,
                signature: hex::decode(&event.signature)?
                    .try_into()
                    .map_err(|_| eyre!("test signature length"))?,
                event_type: event.event_type,
            })
        })
        .collect()
}

fn replay_root(signing_key: &SigningKey, events: &[StoredEvent]) -> Result<FixedBytes<32>> {
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        0,
        1,
        "V2_PoseidonMerkle",
        FixedBytes::from(signing_key.verifying_key().to_bytes()),
    ));
    let events = events
        .iter()
        .map(|event| SnapshotEvent {
            event_index: event.event_index,
            blinded_commitment: event.blinded_commitment,
            signature: event.signature,
            event_type: event.event_type,
        })
        .collect::<Vec<_>>();
    cache.apply_verified_artifact_events(&events)?;
    cache
        .root_at_global_index(
            events
                .last()
                .ok_or_else(|| eyre!("test events are empty"))?
                .event_index,
        )
        .ok_or_else(|| eyre!("test root unavailable"))
}

fn active_graph(entry: PoiArtifactManifestEntry, now: SystemTime) -> ActivePoiGraph {
    ActivePoiGraph {
        entry,
        checkpoint_published_at: now,
        bridge_published_at: BTreeMap::new(),
    }
}

fn graph_cids(entry: &PoiArtifactManifestEntry) -> BTreeSet<String> {
    let mut cids = BTreeSet::from([
        entry.checkpoint_catalog.artifact.cid.clone(),
        entry.blocked_shields.artifact.cid.clone(),
    ]);
    cids.extend(
        entry
            .retained_bridges
            .iter()
            .map(|bridge| bridge.artifact.cid.clone()),
    );
    if let Some(tail) = &entry.current_tail {
        cids.insert(tail.artifact.cid.clone());
    }
    cids
}

fn index_bytes(index: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&index.to_be_bytes());
    bytes
}

#[derive(Default)]
struct MemoryIpfs {
    bytes: Mutex<HashMap<String, Vec<u8>>>,
    pins: AtomicUsize,
    unpinned: Mutex<Vec<String>>,
    block_pin: AtomicBool,
    pin_entered: Notify,
    pin_release: Notify,
    pin_attempts: AtomicUsize,
    fail_pin_at: AtomicUsize,
}

impl MemoryIpfs {
    fn pin_count(&self) -> usize {
        self.pins.load(Ordering::SeqCst)
    }

    fn bytes(&self, cid: &str) -> Result<Vec<u8>> {
        self.bytes
            .lock()
            .expect("IPFS bytes lock")
            .get(cid)
            .cloned()
            .ok_or_else(|| eyre!("missing test CID {cid}"))
    }

    fn insert_untracked(&self, bytes: &[u8]) -> Result<Cid> {
        let cid = raw_block_cid(bytes)?;
        self.bytes
            .lock()
            .expect("IPFS bytes lock")
            .insert(cid.to_string(), bytes.to_vec());
        Ok(cid)
    }

    fn clear_bytes(&self) {
        self.bytes.lock().expect("IPFS bytes lock").clear();
    }

    fn unpinned_count(&self) -> usize {
        self.unpinned.lock().expect("IPFS unpinned lock").len()
    }

    fn pin_attempts(&self) -> usize {
        self.pin_attempts.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl IpfsClient for MemoryIpfs {
    fn service_name(&self) -> &'static str {
        "memory"
    }

    async fn pin_bytes(&self, bytes: &[u8]) -> std::result::Result<Cid, IpfsError> {
        let attempt = self.pin_attempts.fetch_add(1, Ordering::SeqCst) + 1;
        self.pin_entered.notify_one();
        if self.block_pin.load(Ordering::SeqCst) {
            self.pin_release.notified().await;
        }
        if self.fail_pin_at.load(Ordering::SeqCst) == attempt {
            return Err(IpfsError::PinFailed {
                service: "memory".to_string(),
                source: Box::new(std::io::Error::other("forced pin failure")),
            });
        }
        let cid = raw_block_cid(bytes)?;
        self.bytes
            .lock()
            .expect("IPFS bytes lock")
            .insert(cid.to_string(), bytes.to_vec());
        self.pins.fetch_add(1, Ordering::SeqCst);
        Ok(cid)
    }

    async fn unpin(&self, cid: &Cid) -> std::result::Result<(), IpfsError> {
        self.bytes
            .lock()
            .expect("IPFS bytes lock")
            .remove(&cid.to_string());
        self.unpinned
            .lock()
            .expect("IPFS unpinned lock")
            .push(cid.to_string());
        Ok(())
    }

    async fn contains(&self, cid: &Cid) -> std::result::Result<bool, IpfsError> {
        Ok(self
            .bytes
            .lock()
            .expect("IPFS bytes lock")
            .contains_key(&cid.to_string()))
    }
}

#[derive(Default)]
struct MockPublisher {
    calls: Mutex<Vec<(String, u64)>>,
    fail: AtomicBool,
    entered: Notify,
    release: Notify,
    blocking: AtomicBool,
}

impl MockPublisher {
    fn calls(&self) -> Vec<(String, u64)> {
        self.calls.lock().expect("publisher calls lock").clone()
    }
}

#[async_trait]
impl ManifestIpnsPublisher for MockPublisher {
    async fn publish_manifest_cid(
        &self,
        manifest_cid: &str,
        sequence: u64,
    ) -> std::result::Result<IpnsPublication, IpnsError> {
        self.calls
            .lock()
            .expect("publisher calls lock")
            .push((manifest_cid.to_string(), sequence));
        self.entered.notify_one();
        if self.blocking.load(Ordering::SeqCst) {
            self.release.notified().await;
        }
        if self.fail.load(Ordering::SeqCst) {
            return Err(IpnsError::PublisherUnavailable);
        }
        Ok(IpnsPublication {
            peer_id: PeerId::random(),
            ipns_name: "k51qzi5uqu5dtest".to_string(),
            value: format!("/ipfs/{manifest_cid}"),
            sequence,
        })
    }
}

struct RootServer {
    url: String,
    accept: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl RootServer {
    async fn start(accept: bool) -> Result<Self> {
        use axum::routing::post;
        let accept = Arc::new(AtomicBool::new(accept));
        let calls = Arc::new(AtomicUsize::new(0));
        let state = (accept.clone(), calls.clone());
        let app = Router::new().route(
            "/",
            post(|State((accept, calls)): State<(Arc<AtomicBool>, Arc<AtomicUsize>)>| async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": accept.load(Ordering::SeqCst)
                }))
            }),
        ).with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("root mock server");
        });
        Ok(Self {
            url,
            accept,
            calls,
            task,
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Drop for RootServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn install_v4_activation_failure(pool: &sqlx::PgPool) -> Result<()> {
    sqlx::query(
        r"
        CREATE OR REPLACE FUNCTION fail_test_v4_activation() RETURNS trigger AS $$
        BEGIN
            IF OLD.ipns_published_at IS NULL AND NEW.ipns_published_at IS NOT NULL THEN
                RAISE EXCEPTION 'test v4 activation failure';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        ",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        CREATE TRIGGER fail_test_v4_activation
        BEFORE UPDATE ON published_poi_v4_manifests
        FOR EACH ROW EXECUTE FUNCTION fail_test_v4_activation()
        ",
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn install_legacy_activation_failure(pool: &sqlx::PgPool) -> Result<()> {
    sqlx::query(
        r"
        CREATE OR REPLACE FUNCTION fail_test_legacy_activation() RETURNS trigger AS $$
        BEGIN
            IF OLD.ipns_published_at IS NULL AND NEW.ipns_published_at IS NOT NULL THEN
                RAISE EXCEPTION 'test legacy activation failure';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        ",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        CREATE TRIGGER fail_test_legacy_activation
        BEFORE UPDATE ON published_manifests
        FOR EACH ROW EXECUTE FUNCTION fail_test_legacy_activation()
        ",
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn drop_v4_activation_failure(pool: &sqlx::PgPool) -> Result<()> {
    sqlx::query("DROP TRIGGER IF EXISTS fail_test_v4_activation ON published_poi_v4_manifests")
        .execute(pool)
        .await?;
    sqlx::query("DROP FUNCTION IF EXISTS fail_test_v4_activation()")
        .execute(pool)
        .await?;
    Ok(())
}

async fn drop_legacy_activation_failure(pool: &sqlx::PgPool) -> Result<()> {
    sqlx::query("DROP TRIGGER IF EXISTS fail_test_legacy_activation ON published_manifests")
        .execute(pool)
        .await?;
    sqlx::query("DROP FUNCTION IF EXISTS fail_test_legacy_activation()")
        .execute(pool)
        .await?;
    Ok(())
}

async fn age_v4_rows(pool: &sqlx::PgPool, seconds: i64) -> Result<()> {
    sqlx::query(
        "UPDATE published_poi_v4_manifests \
         SET published_at = to_timestamp($1), \
             superseded_at = CASE WHEN superseded_at IS NULL THEN NULL ELSE to_timestamp($1) END",
    )
    .bind(seconds)
    .execute(pool)
    .await?;
    sqlx::query("UPDATE published_poi_v4_artifacts SET published_at = to_timestamp($1), last_referenced_at = to_timestamp($1)")
        .bind(seconds)
        .execute(pool)
        .await?;
    Ok(())
}
