use super::*;
use alloy_primitives::FixedBytes;
use clap::error::ErrorKind;
use railgun_indexer_core::manifest::ArtifactDescriptor;
use railgun_indexer_core::publish::ipfs::raw_block_cid;
use std::collections::BTreeMap;

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
    let error =
        Options::try_parse_from(["railgun-indexer"]).expect_err("a startup mode must be selected");

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
        "v4",
    ])
    .expect_err("CID and sequence are mandatory");

    assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
}

#[test]
fn pending_manifest_recovery_rejects_retired_legacy_channel() {
    let cid_text = raw_block_cid(b"pending recovery CLI")
        .expect("test CID")
        .to_string();
    let error = Options::try_parse_from([
        "railgun-indexer",
        "--config",
        "config.yaml",
        "--invalidate-pending-poi-manifest",
        "--channel",
        "legacy",
        "--manifest-cid",
        &cid_text,
        "--manifest-sequence",
        "42",
    ])
    .expect_err("legacy recovery channel is retired");

    assert_eq!(error.kind(), ErrorKind::InvalidValue);
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
            "k51qzi5uqu5dlv4poi",
            "k51qzi5uqu5dlindexed",
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
    assert_eq!(
        status.poi_v4_ipns_name.as_deref(),
        Some("k51qzi5uqu5dlv4poi")
    );
    assert_eq!(
        status.chain_indexed_ipns_name.as_deref(),
        Some("k51qzi5uqu5dlindexed")
    );
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
                    + Duration::from_secs(u64::try_from(index + 2).expect("day") * 24 * 60 * 60),
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
    config.validate().wrap_err("validate example config")?;
    let chains = config
        .chain_indexed
        .chains
        .iter()
        .map(|chain| (chain.chain_id, chain))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(chains.len(), 6);
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
        assert_eq!(chain.action_start_block, expected.action_start_block);
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
    assert_eq!(scopes.len(), 6);
    assert!(
        scopes
            .iter()
            .all(|scope| scope.txid_version == "V2_PoseidonMerkle")
    );

    Ok(())
}

// Mainnet deployment fields mirror sync_service::ChainConfigDefaults::for_chain.
// Sepolia and Base use their verified contract deployments and have no legacy event era.
const CANONICAL_CHAIN_INDEXED_DEFAULTS: &[ExpectedChainIndexedDefault] = &[
    ExpectedChainIndexedDefault {
        chain_id: 1,
        railgun_contract: "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9",
        start_block: 14_737_691,
        v2_start_block: 16_076_750,
        legacy_shield_block: 16_790_263,
        action_start_block: Some(25_753_685),
    },
    ExpectedChainIndexedDefault {
        chain_id: 56,
        railgun_contract: "0x590162bf4b50f6576a459b75309ee21d92178a10",
        start_block: 17_633_701,
        v2_start_block: 23_478_204,
        legacy_shield_block: 26_313_947,
        action_start_block: Some(115_899_634),
    },
    ExpectedChainIndexedDefault {
        chain_id: 137,
        railgun_contract: "0x19b620929f97b7b990801496c3b361ca5def8c71",
        start_block: 28_083_766,
        v2_start_block: 36_219_104,
        legacy_shield_block: 40_143_539,
        action_start_block: Some(92_007_080),
    },
    ExpectedChainIndexedDefault {
        chain_id: 8453,
        railgun_contract: "0x0047d1f97674614189e80566575fb615788acf25",
        start_block: 50_224_711,
        v2_start_block: 0,
        legacy_shield_block: 0,
        action_start_block: Some(50_224_711),
    },
    ExpectedChainIndexedDefault {
        chain_id: 42161,
        railgun_contract: "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9",
        start_block: 56_109_834,
        v2_start_block: 0,
        legacy_shield_block: 68_196_853,
        action_start_block: Some(494_497_454),
    },
    ExpectedChainIndexedDefault {
        chain_id: 11_155_111,
        railgun_contract: "0xecfcf3b4ec647c4ca6d49108b311b7a7c9543fea",
        start_block: 5_784_774,
        v2_start_block: 0,
        legacy_shield_block: 0,
        action_start_block: None,
    },
];

struct ExpectedChainIndexedDefault {
    chain_id: u64,
    railgun_contract: &'static str,
    start_block: u64,
    v2_start_block: u64,
    legacy_shield_block: u64,
    action_start_block: Option<u64>,
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
