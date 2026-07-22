use alloy_primitives::{FixedBytes, U256, hex};
use poi::poi::{PoiEventType, SignedBlockedShield, SignedPoiEvent};
use railgun_indexer_core::blocked::BlockedShieldsArtifact;
use railgun_indexer_core::manifest::{ArtifactDescriptor, Manifest, ManifestEntry};
use railgun_indexer_core::snapshot::{Lifecycle, LifecycleError, SnapshotKind, SnapshotReader};
use railgun_indexer_core::store::{Store, StoreError, run_migrations};
use sqlx::postgres::PgPoolOptions;
use std::collections::BTreeMap;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn lifecycle_manifest_base_and_deltas_replay_full_event_set()
-> Result<(), Box<dyn std::error::Error>> {
    let node = Postgres::default().start().await?;
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await?;
    run_migrations(&pool).await?;

    let store = Store::new(pool);
    let list_key = FixedBytes::from([9_u8; 32]);
    let upstream_url = "https://ppoi.example.invalid";
    let events = (0..5)
        .map(|index| signed_event(index, index as u8 + 1))
        .collect::<Vec<_>>();
    let blocked_shield = signed_blocked_shield();

    let mut tx = store.begin().await?;
    Store::insert_events(&mut tx, &list_key, 1, &events).await?;
    Store::upsert_blocked_shields(&mut tx, &list_key, 1, &[blocked_shield]).await?;
    Store::advance_chain_tip(
        &mut tx,
        &list_key,
        1,
        upstream_url,
        4,
        Some(&hex_bytes(99, 32)),
    )
    .await?;
    tx.commit().await?;

    let lifecycle = Lifecycle::new(store, upstream_url.to_string(), 0, [7; 32]);
    let base_bytes = lifecycle.build_base(&list_key, 1, 1).await?;
    let delta_1_bytes = lifecycle.build_delta(&list_key, 1, 2, 3).await?;
    let delta_2_bytes = lifecycle.build_delta(&list_key, 1, 4, 4).await?;
    let base = SnapshotReader::read(&base_bytes)?;
    let delta_1 = SnapshotReader::read(&delta_1_bytes)?;
    let delta_2 = SnapshotReader::read(&delta_2_bytes)?;
    let rebuilt_base = SnapshotReader::read(&lifecycle.build_base(&list_key, 1, 4).await?)?;
    let blocked_artifact = lifecycle
        .build_blocked_shields_artifact(&list_key, 1)
        .await?;
    let blocked_artifact = BlockedShieldsArtifact::read(&blocked_artifact.bytes)?;

    let replayed = base
        .events
        .iter()
        .chain(delta_1.events.iter())
        .chain(delta_2.events.iter())
        .map(|event| event.event_index)
        .collect::<Vec<_>>();
    assert_eq!(replayed, vec![0, 1, 2, 3, 4]);
    assert_eq!(base.header.kind, SnapshotKind::Base);
    assert_eq!(base.header.start_index, 0);
    assert_eq!(base.header.end_index, 1);
    assert_eq!(base.blocked_shields.len(), 0);
    assert_eq!(delta_1.header.kind, SnapshotKind::Delta);
    assert_eq!(delta_1.header.start_index, base.header.end_index + 1);
    assert_eq!(delta_1.header.end_index, 3);
    assert_eq!(delta_1.blocked_shields.len(), 0);
    assert_eq!(delta_2.header.start_index, delta_1.header.end_index + 1);
    assert_eq!(delta_2.header.end_index, 4);
    assert_eq!(rebuilt_base.header.kind, SnapshotKind::Base);
    assert_eq!(rebuilt_base.header.start_index, 0);
    assert_eq!(rebuilt_base.header.end_index, 4);
    assert_eq!(rebuilt_base.events.len(), 5);
    assert_eq!(blocked_artifact.blocked_shields.len(), 1);

    let manifest = manifest_for_snapshots(&list_key, FixedBytes::from([99; 32]));
    let files = BTreeMap::from([
        ("bafybase".to_string(), base_bytes),
        ("bafydelta1".to_string(), delta_1_bytes),
        ("bafydelta2".to_string(), delta_2_bytes),
    ]);
    let entry = &manifest.entries[0];
    let replayed_from_manifest = std::iter::once(&entry.base)
        .chain(entry.deltas.iter())
        .flat_map(|descriptor| {
            SnapshotReader::read(files.get(&descriptor.cid).expect("manifest CID exists"))
                .expect("snapshot decodes")
                .events
                .into_iter()
                .map(|event| event.event_index)
        })
        .collect::<Vec<_>>();
    assert_eq!(entry.current_tip_index, 4);
    assert_eq!(entry.current_tip_merkleroot, FixedBytes::from([99; 32]));
    assert_eq!(replayed_from_manifest, vec![0, 1, 2, 3, 4]);

    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn incomplete_event_data_fails_shared_reads_and_snapshot_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let node = Postgres::default().start().await?;
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await?;
    run_migrations(&pool).await?;

    let store = Store::new(pool);
    let list_key = FixedBytes::from([9_u8; 32]);
    let upstream_url = "https://ppoi.example.invalid";
    let mut tx = store.begin().await?;
    Store::insert_events(&mut tx, &list_key, 1, &[signed_event(0, 1)]).await?;
    Store::insert_event_leaves(
        &mut tx,
        &list_key,
        1,
        1,
        &[U256::from(2_u8), U256::from(3_u8)],
    )
    .await?;
    Store::advance_chain_tip(
        &mut tx,
        &list_key,
        1,
        upstream_url,
        2,
        Some(&hex_bytes(99, 32)),
    )
    .await?;
    tx.commit().await?;

    let page_error = store
        .page_event_range(&list_key, 1, 0, 2)
        .await
        .expect_err("incomplete rows must fail rather than filter or truncate");
    assert!(matches!(
        page_error,
        StoreError::IncompletePoiEvent {
            chain_id: 1,
            event_index: 1
        }
    ));

    let lifecycle = Lifecycle::new(store, upstream_url.to_string(), 0, [7; 32]);
    let publication_error = lifecycle
        .build_base(&list_key, 1, 2)
        .await
        .expect_err("snapshot publication must fail on incomplete event data");
    assert!(matches!(
        publication_error,
        LifecycleError::Store(StoreError::IncompletePoiEvent {
            chain_id: 1,
            event_index: 1
        })
    ));

    Ok(())
}

fn manifest_for_snapshots(list_key: &FixedBytes<32>, tip_merkleroot: FixedBytes<32>) -> Manifest {
    Manifest::new(
        1,
        1_767_225_600_000,
        1_767_225_600_000,
        FixedBytes::ZERO,
        vec![ManifestEntry {
            list_key: *list_key,
            chain_id: 1,
            base: descriptor("bafybase"),
            deltas: vec![descriptor("bafydelta1"), descriptor("bafydelta2")],
            retained_deltas: Vec::new(),
            blocked_shields: descriptor("bafyblocked"),
            current_tip_index: 4,
            current_tip_merkleroot: tip_merkleroot,
        }],
    )
}

fn descriptor(cid: &str) -> ArtifactDescriptor {
    ArtifactDescriptor {
        cid: cid.to_string(),
        sha256: FixedBytes::from([1; 32]),
        byte_size: 1,
    }
}

fn signed_event(index: u64, byte: u8) -> SignedPoiEvent {
    SignedPoiEvent {
        index,
        blinded_commitment: FixedBytes::from([byte; 32]),
        signature: hex_bytes(byte + 10, 64),
        event_type: match index % 4 {
            0 => PoiEventType::Shield,
            1 => PoiEventType::Transact,
            2 => PoiEventType::Unshield,
            _ => PoiEventType::LegacyTransact,
        },
    }
}

fn signed_blocked_shield() -> SignedBlockedShield {
    SignedBlockedShield {
        commitment_hash: hex_bytes(31, 32),
        blinded_commitment: hex_bytes(32, 32),
        block_reason: Some("blocked fixture".to_string()),
        signature: hex_bytes(33, 64),
    }
}

fn hex_bytes(byte: u8, len: usize) -> String {
    hex::encode_prefixed(vec![byte; len])
}
