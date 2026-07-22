use alloy::primitives::{Address, Bytes, FixedBytes as AlloyFixedBytes, U256, Uint};
use alloy_primitives::{FixedBytes, hex};
use async_trait::async_trait;
use broadcaster_core::contracts::railgun::{
    CommitmentCiphertext, CommitmentPreimage, LegacyCommitmentCiphertext, LegacyCommitmentPreimage,
    ShieldCiphertext, TokenData,
};
use broadcaster_core::transact::MERKLE_ZERO_VALUE;
use cid::Cid;
use ed25519_dalek::SigningKey;
use poi::artifacts::ArtifactDescriptor;
use poi::artifacts::v4::{
    ArtifactEncoding, BlockedShieldsDescriptor, CheckpointCatalogDescriptor, Compression,
    FORMAT_VERSION, ManifestEntry, Scope,
};
use poi::poi::{PoiEventType, SignedBlockedShield, SignedPoiEvent};
use railgun_indexer_core::audit::{
    Audit, IndexedArtifactPublicationKind, PinLifecycleCoordinator, PoiArtifactPublicationKind,
    PoiManifestChannel, Retention,
};
use railgun_indexer_core::chain_logs::{
    IndexedLegacyEncryptedCommitment, IndexedLegacyGeneratedCommitment, IndexedLogBatch,
    IndexedLogSource, IndexedNullifier, IndexedPublicTransaction, IndexedShieldCommitment,
    IndexedTransactCommitment,
};
use railgun_indexer_core::manifest::{
    ChainScope, ChainType, IndexedArtifactManifest, IndexedArtifactRange, IndexedArtifactRangeKind,
    IndexedDatasetKind as ManifestIndexedDatasetKind, PublisherIdentity, content_hash,
};
use railgun_indexer_core::publish::ipfs::{IpfsClient, IpfsError, raw_block_cid};
use railgun_indexer_core::snapshot::SnapshotKind;
use railgun_indexer_core::store::{
    IndexedDatasetKind, Store, StoreError, StoredCommitmentFamily,
    StoredWalletScanTimestampBackfill, run_migrations,
};
use sqlx::postgres::PgPoolOptions;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tokio::sync::Notify;

#[tokio::test]
async fn migrations_apply_and_tables_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping Postgres migration smoke test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await?;

    run_migrations(&pool).await?;

    let list_key = vec![1_u8; 32];
    let blinded_commitment = vec![2_u8; 32];
    let signature = vec![3_u8; 64];
    let commitment_hash = vec![4_u8; 32];
    let tip_merkleroot = vec![5_u8; 32];

    sqlx::query(
        "INSERT INTO poi_events \
         (list_key, chain_id, event_index, blinded_commitment, signature, event_type, event_data_complete) \
         VALUES ($1, $2, $3, $4, $5, $6, TRUE)",
    )
    .bind(&list_key)
    .bind(1_i64)
    .bind(0_i64)
    .bind(&blinded_commitment)
    .bind(&signature)
    .bind(0_i16)
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO blocked_shields \
         (list_key, chain_id, blinded_commitment, commitment_hash, signature, block_reason) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&list_key)
    .bind(1_i64)
    .bind(&blinded_commitment)
    .bind(&commitment_hash)
    .bind(&signature)
    .bind("fixture")
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO chain_tips \
         (list_key, chain_id, upstream_url, last_event_index, last_tip_merkleroot) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&list_key)
    .bind(1_i64)
    .bind("https://ppoi.example.invalid")
    .bind(0_i64)
    .bind(&tip_merkleroot)
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO published_snapshots \
         (list_key, chain_id, upstream_url, kind, start_index, end_index, cid, byte_size, format_version, tip_merkleroot) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(&list_key)
    .bind(1_i64)
    .bind("https://ppoi.example.invalid")
    .bind("base")
    .bind(0_i64)
    .bind(0_i64)
    .bind("bafyfixture")
    .bind(128_i64)
    .bind(2_i32)
    .bind(&tip_merkleroot)
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO published_blocked_shields \
         (list_key, chain_id, upstream_url, cid, byte_size, format_version, content_hash) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&list_key)
    .bind(1_i64)
    .bind("https://ppoi.example.invalid")
    .bind("bafyblockedfixture")
    .bind(64_i64)
    .bind(2_i32)
    .bind(vec![6_u8; 32])
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO published_manifests \
         (cid, ipns_sequence, byte_size, content_hash, format_version, ipns_published_at) \
         VALUES ($1, $2, $3, $4, $5, now())",
    )
    .bind("bafymanifestfixture")
    .bind(1_i64)
    .bind(96_i64)
    .bind(vec![7_u8; 32])
    .bind(2_i32)
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO published_indexed_artifacts \
         (artifact_kind, dataset_kind, chain_type, chain_id, railgun_contract, range_kind, range_start, range_end, cid, byte_size, content_hash, format_version) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind("chunk")
    .bind("wallet_scan")
    .bind(0_i16)
    .bind(1_i64)
    .bind("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    .bind("block")
    .bind(0_i64)
    .bind(100_i64)
    .bind("bafyindexedartifactfixture")
    .bind(128_i64)
    .bind(vec![23_u8; 32])
    .bind(1_i32)
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO published_indexed_manifests \
         (cid, ipns_sequence, byte_size, content_hash, format_version, ipns_published_at) \
         VALUES ($1, $2, $3, $4, $5, now())",
    )
    .bind("bafyindexedmanifestfixture")
    .bind(2_i64)
    .bind(96_i64)
    .bind(vec![24_u8; 32])
    .bind(1_i32)
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO chain_indexing_progress \
         (chain_type, chain_id, railgun_contract, dataset_kind, indexed_through_block, indexed_through_block_hash) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(0_i16)
    .bind(1_i64)
    .bind("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    .bind("public_txid")
    .bind(100_i64)
    .bind(vec![8_u8; 32])
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO indexed_block_checkpoints \
         (chain_type, chain_id, railgun_contract, checkpoint_kind, block_number, block_hash, parent_hash) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(0_i16)
    .bind(1_i64)
    .bind("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    .bind("public_txid")
    .bind(100_i64)
    .bind(vec![9_u8; 32])
    .bind(vec![10_u8; 32])
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO indexed_block_headers \
         (chain_type, chain_id, block_number, block_hash, parent_hash) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(0_i16)
    .bind(1_i64)
    .bind(100_i64)
    .bind(vec![9_u8; 32])
    .bind(vec![10_u8; 32])
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO indexed_public_transactions \
         (chain_type, chain_id, railgun_contract, block_number, block_hash, transaction_hash, first_log_index, last_log_index) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(0_i16)
    .bind(1_i64)
    .bind("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    .bind(100_i64)
    .bind(vec![9_u8; 32])
    .bind(vec![11_u8; 32])
    .bind(1_i64)
    .bind(2_i64)
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO indexed_transact_commitments \
         (chain_type, chain_id, railgun_contract, block_number, block_hash, transaction_hash, log_index, tree_number, tree_position, commitment_hash, ciphertext) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(0_i16)
    .bind(1_i64)
    .bind("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    .bind(100_i64)
    .bind(vec![9_u8; 32])
    .bind(vec![11_u8; 32])
    .bind(1_i64)
    .bind(0_i64)
    .bind(0_i64)
    .bind(vec![12_u8; 32])
    .bind(vec![13_u8; 32])
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO indexed_shield_commitments \
         (chain_type, chain_id, railgun_contract, block_number, block_hash, transaction_hash, log_index, tree_number, tree_position, commitment_hash, preimage, shield_ciphertext) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(0_i16)
    .bind(1_i64)
    .bind("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    .bind(100_i64)
    .bind(vec![9_u8; 32])
    .bind(vec![11_u8; 32])
    .bind(1_i64)
    .bind(0_i64)
    .bind(1_i64)
    .bind(vec![14_u8; 32])
    .bind(vec![15_u8; 32])
    .bind(vec![16_u8; 32])
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO indexed_nullifiers \
         (chain_type, chain_id, railgun_contract, block_number, block_hash, transaction_hash, log_index, tree_number, nullifier) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(0_i16)
    .bind(1_i64)
    .bind("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    .bind(100_i64)
    .bind(vec![9_u8; 32])
    .bind(vec![11_u8; 32])
    .bind(1_i64)
    .bind(0_i64)
    .bind(vec![17_u8; 32])
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO indexed_legacy_encrypted_commitments \
         (chain_type, chain_id, railgun_contract, block_number, block_hash, transaction_hash, log_index, tree_number, tree_position, commitment_hash, ciphertext) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(0_i16)
    .bind(1_i64)
    .bind("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    .bind(100_i64)
    .bind(vec![9_u8; 32])
    .bind(vec![11_u8; 32])
    .bind(1_i64)
    .bind(0_i64)
    .bind(2_i64)
    .bind(vec![18_u8; 32])
    .bind(vec![19_u8; 32])
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO indexed_legacy_generated_commitments \
         (chain_type, chain_id, railgun_contract, block_number, block_hash, transaction_hash, log_index, tree_number, tree_position, commitment_hash, preimage, encrypted_random) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(0_i16)
    .bind(1_i64)
    .bind("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    .bind(100_i64)
    .bind(vec![9_u8; 32])
    .bind(vec![11_u8; 32])
    .bind(1_i64)
    .bind(0_i64)
    .bind(3_i64)
    .bind(vec![20_u8; 32])
    .bind(vec![21_u8; 32])
    .bind(vec![22_u8; 64])
    .execute(&pool)
    .await?;

    assert_eq!(row_count(&pool, "poi_events").await?, 1);
    assert_eq!(row_count(&pool, "blocked_shields").await?, 1);
    assert_eq!(row_count(&pool, "chain_tips").await?, 1);
    assert_eq!(row_count(&pool, "published_snapshots").await?, 1);
    assert_eq!(row_count(&pool, "published_blocked_shields").await?, 1);
    assert_eq!(row_count(&pool, "published_manifests").await?, 1);
    assert_eq!(row_count(&pool, "published_indexed_artifacts").await?, 1);
    assert_eq!(row_count(&pool, "published_indexed_manifests").await?, 1);
    assert_eq!(row_count(&pool, "chain_indexing_progress").await?, 1);
    assert_eq!(row_count(&pool, "indexed_block_checkpoints").await?, 1);
    assert_eq!(row_count(&pool, "indexed_block_headers").await?, 1);
    assert_eq!(row_count(&pool, "indexed_public_transactions").await?, 1);
    assert_eq!(row_count(&pool, "indexed_transact_commitments").await?, 1);
    assert_eq!(row_count(&pool, "indexed_shield_commitments").await?, 1);
    assert_eq!(row_count(&pool, "indexed_nullifiers").await?, 1);
    assert_eq!(
        row_count(&pool, "indexed_legacy_encrypted_commitments").await?,
        1
    );
    assert_eq!(
        row_count(&pool, "indexed_legacy_generated_commitments").await?,
        1
    );

    Ok(())
}

#[tokio::test]
async fn migrations_skip_when_schema_version_is_current() -> Result<(), Box<dyn std::error::Error>>
{
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping Postgres migration version test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await?;

    sqlx::query(
        r"
        CREATE TABLE poi_indexer_schema_version (
            id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
            version INTEGER NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        ",
    )
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO poi_indexer_schema_version (id, version, applied_at) VALUES (TRUE, 19, now())",
    )
    .execute(&pool)
    .await?;

    run_migrations(&pool).await?;

    assert!(!table_exists(&pool, "poi_events").await?);
    assert_eq!(schema_version(&pool).await?, 19);

    Ok(())
}

#[tokio::test]
async fn v18_empty_and_chain_indexed_only_databases_admit_one_exact_txid_identity_concurrently()
-> Result<(), Box<dyn std::error::Error>> {
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping V18 POI identity concurrency test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&connection_string)
        .await?;
    run_migrations(&pool).await?;
    sqlx::query(
        "INSERT INTO indexer_state (key, value) VALUES ('chain_indexed_ipns_last_sequence', 9)",
    )
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO chain_indexing_progress (chain_type, chain_id, railgun_contract, \
         dataset_kind, indexed_through_block, indexed_through_block_hash) \
         VALUES (0, 1, '0x0000000000000000000000000000000000000001', \
         'wallet_scan', 10, $1)",
    )
    .bind([9_u8; 32].as_slice())
    .execute(&pool)
    .await?;
    let first = Store::new(pool.clone());
    let second = Store::new(pool.clone());
    let (first_result, second_result) = tokio::join!(
        first.admit_poi_txid_version("V2_PoseidonMerkle"),
        second.admit_poi_txid_version("V2_PoseidonMerkle")
    );
    first_result?;
    second_result?;
    let identities: Vec<String> =
        sqlx::query_scalar("SELECT txid_version FROM poi_dataset_identity")
            .fetch_all(&pool)
            .await?;
    assert_eq!(identities, vec!["V2_PoseidonMerkle".to_string()]);
    Ok(())
}

#[tokio::test]
async fn v18_populated_legacy_poi_requires_explicit_exact_adoption_without_corpus_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping V18 populated POI identity test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&connection_string)
        .await?;
    run_migrations(&pool).await?;
    sqlx::query(
        "INSERT INTO chain_tips (list_key, chain_id, upstream_url, last_event_index) \
         VALUES ($1, 1, 'https://legacy.example.invalid', 7)",
    )
    .bind([7_u8; 32].as_slice())
    .execute(&pool)
    .await?;
    let store = Store::new(pool.clone());
    assert!(matches!(
        store
            .admit_poi_txid_version("V2_PoseidonMerkle")
            .await
            .expect_err("populated fence-less database must fail closed"),
        StoreError::PoiTxidVersionAdoptionRequired { .. }
    ));
    assert_eq!(row_count(&pool, "poi_dataset_identity").await?, 0);
    store.adopt_poi_txid_version("V2_PoseidonMerkle").await?;
    store.adopt_poi_txid_version("V2_PoseidonMerkle").await?;
    assert_eq!(row_count(&pool, "chain_tips").await?, 1);
    assert!(matches!(
        store
            .adopt_poi_txid_version("OtherVersion")
            .await
            .expect_err("identity overwrite must fail"),
        StoreError::PoiTxidVersionMismatch { .. }
    ));
    assert!(matches!(
        store
            .admit_poi_txid_version("OtherVersion")
            .await
            .expect_err("later config mismatch must fail"),
        StoreError::PoiTxidVersionMismatch { .. }
    ));
    assert_eq!(row_count(&pool, "chain_tips").await?, 1);
    Ok(())
}

#[tokio::test]
async fn v19_cleanup_debt_is_persisted_and_retried_by_retention()
-> Result<(), Box<dyn std::error::Error>> {
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping V19 cleanup-debt retry test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&connection_string)
        .await?;
    run_migrations(&pool).await?;
    let cid = raw_block_cid(b"cleanup debt")?;
    Audit::record_pin_cleanup_debt(&pool, &cid, "recording", "forced unpin failure").await?;
    assert_eq!(row_count(&pool, "pin_cleanup_debt").await?, 1);

    let ipfs = RecordingIpfsClient::default();
    let sweep = Retention::sweep(
        &pool,
        &ipfs,
        UNIX_EPOCH + Duration::from_secs(1),
        Duration::ZERO,
    )
    .await?;

    assert!(sweep.unpinned_cids.contains(&cid));
    assert_eq!(row_count(&pool, "pin_cleanup_debt").await?, 0);
    Ok(())
}

#[tokio::test]
async fn v15_invalidates_preexisting_pending_reconciliation_until_newer_channel_activation()
-> Result<(), Box<dyn std::error::Error>> {
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping V15 pending reconciliation migration test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await?;
    run_migrations(&pool).await?;
    sqlx::query("DROP INDEX published_manifests_one_pending")
        .execute(&pool)
        .await?;
    sqlx::query("DROP INDEX published_poi_v4_manifests_one_pending")
        .execute(&pool)
        .await?;
    sqlx::query("ALTER TABLE published_manifests DROP COLUMN reconciliation_invalidated_at")
        .execute(&pool)
        .await?;
    sqlx::query("ALTER TABLE published_poi_v4_manifests DROP COLUMN reconciliation_invalidated_at")
        .execute(&pool)
        .await?;
    sqlx::query(
        "CREATE UNIQUE INDEX published_manifests_one_pending \
         ON published_manifests ((TRUE)) \
         WHERE ipns_published_at IS NULL AND superseded_at IS NULL AND unpinned_at IS NULL",
    )
    .execute(&pool)
    .await?;
    sqlx::query(
        "CREATE UNIQUE INDEX published_poi_v4_manifests_one_pending \
         ON published_poi_v4_manifests ((TRUE)) \
         WHERE ipns_published_at IS NULL AND superseded_at IS NULL AND unpinned_at IS NULL",
    )
    .execute(&pool)
    .await?;
    sqlx::query("UPDATE poi_indexer_schema_version SET version = 14 WHERE id = TRUE")
        .execute(&pool)
        .await?;

    let old_legacy = raw_block_cid(b"pre-v15 pending legacy")?;
    let old_v4 = raw_block_cid(b"pre-v15 pending v4")?;
    sqlx::query(
        "INSERT INTO published_manifests \
         (cid, ipns_sequence, byte_size, content_hash, format_version) \
         VALUES ($1, 40, 64, $2, 2)",
    )
    .bind(old_legacy.to_string())
    .bind([1_u8; 32].as_slice())
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO published_poi_v4_manifests \
         (cid, ipns_sequence, byte_size, content_hash, format_version) \
         VALUES ($1, 40, 64, $2, 4)",
    )
    .bind(old_v4.to_string())
    .bind([2_u8; 32].as_slice())
    .execute(&pool)
    .await?;
    let store = Store::new(pool.clone());
    store.record_ipns_sequence(40).await?;

    run_migrations(&pool).await?;

    assert_eq!(schema_version(&pool).await?, 19);
    let legacy_invalidated: Option<i64> = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM reconciliation_invalidated_at)::BIGINT \
         FROM published_manifests WHERE cid = $1",
    )
    .bind(old_legacy.to_string())
    .fetch_one(&pool)
    .await?;
    let v4_invalidated: Option<i64> = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM reconciliation_invalidated_at)::BIGINT \
         FROM published_poi_v4_manifests WHERE cid = $1",
    )
    .bind(old_v4.to_string())
    .fetch_one(&pool)
    .await?;
    assert!(legacy_invalidated.is_some());
    assert!(v4_invalidated.is_some());
    assert!(Audit::pending_manifest_publication(&pool).await?.is_none());
    assert!(
        Audit::pending_poi_artifact_manifest_publication(&pool)
            .await?
            .is_none()
    );

    let equal_legacy = raw_block_cid(b"post-v15 equal-sequence legacy")?;
    let lower_v4 = raw_block_cid(b"post-v15 lower-sequence v4")?;
    let mut tx = store.begin().await?;
    Audit::record_manifest_pin(&mut tx, &equal_legacy, 40, 64, &[3; 32], 2).await?;
    Audit::record_poi_artifact_manifest_pin(&mut tx, &lower_v4, &[], &[], 39, 64, &[4; 32]).await?;
    tx.commit().await?;
    assert_eq!(
        Audit::pending_manifest_publication(&pool)
            .await?
            .expect("new legacy pending remains reconcilable")
            .cid,
        equal_legacy.to_string()
    );
    assert_eq!(
        Audit::pending_poi_artifact_manifest_publication(&pool)
            .await?
            .expect("new POI artifact pending remains reconcilable")
            .cid,
        lower_v4.to_string()
    );

    let mut tx = store.begin().await?;
    let equal_error = Audit::record_manifest_ipns_publication(&mut tx, &equal_legacy, 40)
        .await
        .expect_err("equal sequence must not replace invalidated legacy pending");
    assert!(matches!(
        equal_error,
        railgun_indexer_core::audit::AuditError::ReconciliationSequenceNotNewer {
            channel: "legacy",
            sequence: 40,
            invalidated_sequence: 40,
            ..
        }
    ));
    tx.rollback().await?;
    let mut tx = store.begin().await?;
    let lower_error = Audit::record_poi_artifact_manifest_ipns_publication(&mut tx, &lower_v4, 39)
        .await
        .expect_err("lower sequence must not replace invalidated POI artifact pending");
    assert!(matches!(
        lower_error,
        railgun_indexer_core::audit::AuditError::ReconciliationSequenceNotNewer {
            channel: "v4",
            sequence: 39,
            invalidated_sequence: 40,
            ..
        }
    ));
    tx.rollback().await?;

    sqlx::query("UPDATE published_manifests SET superseded_at = now() WHERE cid = $1")
        .bind(equal_legacy.to_string())
        .execute(&pool)
        .await?;
    sqlx::query("UPDATE published_poi_v4_manifests SET superseded_at = now() WHERE cid = $1")
        .bind(lower_v4.to_string())
        .execute(&pool)
        .await?;
    let next_sequence = store.reserve_poi_publication_sequence(1).await?;
    assert_eq!(next_sequence, 41);
    let new_legacy = old_legacy;
    let new_v4 = old_v4;
    let mut tx = store.begin().await?;
    Audit::record_manifest_pin(&mut tx, &new_legacy, next_sequence, 64, &[1; 32], 2).await?;
    Audit::record_poi_artifact_manifest_pin(
        &mut tx,
        &new_v4,
        &[],
        &[],
        next_sequence,
        64,
        &[2; 32],
    )
    .await?;
    tx.commit().await?;

    let mut tx = store.begin().await?;
    Audit::record_manifest_ipns_publication(&mut tx, &new_legacy, next_sequence).await?;
    tx.commit().await?;
    let old_v4_superseded: Option<i64> = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM superseded_at)::BIGINT \
         FROM published_poi_v4_manifests \
         WHERE cid = $1 AND reconciliation_invalidated_at IS NOT NULL",
    )
    .bind(old_v4.to_string())
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        old_v4_superseded, None,
        "legacy activation is channel-local"
    );

    let mut tx = store.begin().await?;
    Audit::record_poi_artifact_manifest_ipns_publication(&mut tx, &new_v4, next_sequence).await?;
    tx.commit().await?;
    let old_rows: (Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT \
         (SELECT EXTRACT(EPOCH FROM superseded_at)::BIGINT FROM published_manifests \
          WHERE cid = $1 AND reconciliation_invalidated_at IS NOT NULL), \
         (SELECT EXTRACT(EPOCH FROM superseded_at)::BIGINT FROM published_poi_v4_manifests \
          WHERE cid = $2 AND reconciliation_invalidated_at IS NOT NULL)",
    )
    .bind(old_legacy.to_string())
    .bind(old_v4.to_string())
    .fetch_one(&pool)
    .await?;
    assert!(old_rows.0.is_some());
    assert!(old_rows.1.is_some());
    assert!(Audit::pending_manifest_publication(&pool).await?.is_none());
    assert!(
        Audit::pending_poi_artifact_manifest_publication(&pool)
            .await?
            .is_none()
    );

    Ok(())
}

#[tokio::test]
async fn v14_tracks_event_hydration_independently_of_zero_shield_signature()
-> Result<(), Box<dyn std::error::Error>> {
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping V14 event hydration migration test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await?;
    run_migrations(&pool).await?;
    sqlx::query("ALTER TABLE poi_events DROP COLUMN event_data_complete")
        .execute(&pool)
        .await?;
    sqlx::query("UPDATE poi_indexer_schema_version SET version = 13 WHERE id = TRUE")
        .execute(&pool)
        .await?;

    let list_key = FixedBytes::from([1_u8; 32]);
    for (event_index, signature) in [(0_i64, vec![0_u8; 64]), (1, vec![3_u8; 64])] {
        sqlx::query(
            "INSERT INTO poi_events \
             (list_key, chain_id, event_index, blinded_commitment, signature, event_type) \
             VALUES ($1, 1, $2, $3, $4, 0)",
        )
        .bind(list_key.as_slice())
        .bind(event_index)
        .bind([2_u8; 32].as_slice())
        .bind(signature)
        .execute(&pool)
        .await?;
    }

    run_migrations(&pool).await?;
    let hydration = sqlx::query_as::<_, (i64, bool)>(
        "SELECT event_index, event_data_complete FROM poi_events ORDER BY event_index",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(hydration, vec![(0, false), (1, true)]);

    let store = Store::new(pool);
    assert_eq!(
        store.first_incomplete_event_index(&list_key, 1).await?,
        Some(0)
    );
    assert!(matches!(
        store
            .page_event_range(&list_key, 1, 0, 1)
            .await
            .expect_err("incomplete migrated event must fail the shared read boundary"),
        StoreError::IncompletePoiEvent {
            chain_id: 1,
            event_index: 0
        }
    ));
    let complete_unsigned_shield = SignedPoiEvent {
        index: 0,
        blinded_commitment: FixedBytes::from([2_u8; 32]),
        signature: "00".repeat(64),
        event_type: PoiEventType::Shield,
    };
    let mut tx = store.begin().await?;
    Store::insert_events(
        &mut tx,
        &list_key,
        1,
        std::slice::from_ref(&complete_unsigned_shield),
    )
    .await?;
    tx.commit().await?;
    assert_eq!(
        store.first_incomplete_event_index(&list_key, 1).await?,
        None
    );
    assert_eq!(store.page_event_range(&list_key, 1, 0, 1).await?.len(), 2);

    let mut tx = store.begin().await?;
    Store::insert_events(
        &mut tx,
        &list_key,
        1,
        std::slice::from_ref(&complete_unsigned_shield),
    )
    .await?;
    Store::insert_event_leaves(&mut tx, &list_key, 1, 0, &[U256::from_be_bytes([2_u8; 32])])
        .await?;
    tx.commit().await?;

    let mut tx = store.begin().await?;
    let conflict = Store::insert_events(
        &mut tx,
        &list_key,
        1,
        &[SignedPoiEvent {
            blinded_commitment: FixedBytes::from([9_u8; 32]),
            ..complete_unsigned_shield.clone()
        }],
    )
    .await
    .expect_err("complete unsigned Shield must be immutable");
    assert!(matches!(
        conflict,
        StoreError::PoiEventConflict {
            chain_id: 1,
            event_index: 0
        }
    ));
    tx.rollback().await?;

    let mut tx = store.begin().await?;
    let conflict = Store::insert_event_leaves(&mut tx, &list_key, 1, 0, &[U256::from(9_u8)])
        .await
        .expect_err("differing leaf must not mutate a complete event");
    assert!(matches!(
        conflict,
        StoreError::PoiEventConflict {
            chain_id: 1,
            event_index: 0
        }
    ));
    tx.rollback().await?;

    let mut tx = store.begin().await?;
    Store::insert_event_leaves(&mut tx, &list_key, 1, 2, &[U256::from(4_u8)]).await?;
    Store::insert_event_leaves(&mut tx, &list_key, 1, 2, &[U256::from(4_u8)]).await?;
    tx.commit().await?;
    assert_eq!(
        store.first_incomplete_event_index(&list_key, 1).await?,
        Some(2)
    );
    assert!(matches!(
        store
            .page_event_range(&list_key, 1, 0, 2)
            .await
            .expect_err("placeholder must not be returned as complete event data"),
        StoreError::IncompletePoiEvent {
            chain_id: 1,
            event_index: 2
        }
    ));

    let mut tx = store.begin().await?;
    let conflict = Store::insert_event_leaves(&mut tx, &list_key, 1, 2, &[U256::from(5_u8)])
        .await
        .expect_err("differing placeholder leaf must conflict");
    assert!(matches!(
        conflict,
        StoreError::PoiEventConflict {
            chain_id: 1,
            event_index: 2
        }
    ));
    tx.rollback().await?;

    let mut tx = store.begin().await?;
    let conflict = Store::insert_events(
        &mut tx,
        &list_key,
        1,
        &[SignedPoiEvent {
            index: 2,
            blinded_commitment: FixedBytes::from([6_u8; 32]),
            signature: "07".repeat(64),
            event_type: PoiEventType::Transact,
        }],
    )
    .await
    .expect_err("hydration must match the placeholder commitment");
    assert!(matches!(
        conflict,
        StoreError::PoiEventConflict {
            chain_id: 1,
            event_index: 2
        }
    ));
    tx.rollback().await?;
    assert_eq!(
        store.first_incomplete_event_index(&list_key, 1).await?,
        Some(2)
    );

    let hydrated_event = SignedPoiEvent {
        index: 2,
        blinded_commitment: FixedBytes::from(U256::from(4_u8).to_be_bytes::<32>()),
        signature: "07".repeat(64),
        event_type: PoiEventType::Transact,
    };
    let mut tx = store.begin().await?;
    Store::insert_events(&mut tx, &list_key, 1, std::slice::from_ref(&hydrated_event)).await?;
    tx.commit().await?;

    let restarted_store = Store::new(store.pool().clone());
    assert_eq!(
        restarted_store
            .first_incomplete_event_index(&list_key, 1)
            .await?,
        None
    );
    assert_eq!(
        restarted_store
            .page_event_range(&list_key, 1, 0, 2)
            .await?
            .len(),
        3
    );

    let mut tx = restarted_store.begin().await?;
    Store::insert_events(&mut tx, &list_key, 1, std::slice::from_ref(&hydrated_event)).await?;
    tx.commit().await?;

    let mut tx = restarted_store.begin().await?;
    let conflict = Store::insert_events(
        &mut tx,
        &list_key,
        1,
        &[SignedPoiEvent {
            event_type: PoiEventType::Unshield,
            ..hydrated_event
        }],
    )
    .await
    .expect_err("hydrated event may not transition again");
    assert!(matches!(
        conflict,
        StoreError::PoiEventConflict {
            chain_id: 1,
            event_index: 2
        }
    ));
    tx.rollback().await?;

    Ok(())
}

#[tokio::test]
async fn v11_conservatively_backfills_active_manifest_artifact_references()
-> Result<(), Box<dyn std::error::Error>> {
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping V11 manifest reference migration test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await?;
    run_migrations(&pool).await?;

    sqlx::query("DROP TABLE published_indexed_manifest_artifacts")
        .execute(&pool)
        .await?;
    sqlx::query("UPDATE poi_indexer_schema_version SET version = 10 WHERE id = TRUE")
        .execute(&pool)
        .await?;
    sqlx::query(
        r"
        INSERT INTO published_indexed_artifacts (
            artifact_kind, dataset_kind, chain_type, chain_id, railgun_contract,
            range_kind, range_start, range_end, cid, byte_size, content_hash, format_version
        ) VALUES ('chunk', 'wallet_scan', 0, 1, '0x0000000000000000000000000000000000000001',
            'block', 100, 200, 'artifact-cid', 128, $1, 1)
        ",
    )
    .bind([1_u8; 32].as_slice())
    .execute(&pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO published_indexed_manifests (
            cid, ipns_sequence, byte_size, content_hash, format_version, ipns_published_at
        ) VALUES ('manifest-cid', 1, 96, $1, 1, now())
        ",
    )
    .bind([2_u8; 32].as_slice())
    .execute(&pool)
    .await?;

    run_migrations(&pool).await?;

    assert_eq!(schema_version(&pool).await?, 19);
    let references: Vec<(String, String)> = sqlx::query_as(
        r"
        SELECT manifest.cid, reference.artifact_cid
        FROM published_indexed_manifest_artifacts AS reference
        JOIN published_indexed_manifests AS manifest ON manifest.id = reference.manifest_id
        ",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        references,
        vec![("manifest-cid".to_string(), "artifact-cid".to_string())]
    );

    let missing_manifest_cid = raw_block_cid(b"manifest with missing artifact")?;
    let mut tx = pool.begin().await?;
    let missing = Audit::record_indexed_manifest_pin(
        &mut tx,
        &missing_manifest_cid,
        &["missing-artifact-cid".to_string()],
        2,
        96,
        &[3_u8; 32],
        1,
        "{}",
    )
    .await
    .expect_err("manifest with missing artifact rejected");
    assert!(matches!(
        missing,
        railgun_indexer_core::audit::AuditError::MissingIndexedManifestArtifacts {
            expected: 1,
            actual: 0,
        }
    ));
    tx.rollback().await?;
    Ok(())
}

#[tokio::test]
async fn v15_to_v17_invalidates_bodyless_indexed_pending_and_replaces_at_higher_same_cid()
-> Result<(), Box<dyn std::error::Error>> {
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping V15-to-V17 indexed reconciliation test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&connection_string)
        .await?;
    let trusted_publisher_pubkey = indexed_manifest_signing_key().verifying_key().to_bytes();
    run_migrations(&pool).await?;
    sqlx::query("DROP INDEX IF EXISTS published_indexed_manifests_one_pending")
        .execute(&pool)
        .await?;
    sqlx::query(
        "ALTER TABLE published_indexed_manifests DROP COLUMN reconciliation_invalidated_at",
    )
    .execute(&pool)
    .await?;
    sqlx::query("ALTER TABLE published_indexed_manifests DROP COLUMN manifest_json")
        .execute(&pool)
        .await?;
    sqlx::query("UPDATE poi_indexer_schema_version SET version = 15 WHERE id = TRUE")
        .execute(&pool)
        .await?;

    let store = Store::new(pool.clone());
    store.record_chain_indexed_ipns_sequence(4).await?;
    let manifest_cid = raw_block_cid(b"v15 bodyless indexed pending")?;
    let old_artifact_cid = raw_block_cid(b"v15 bodyless indexed artifact")?;
    let mut tx = store.begin().await?;
    Audit::record_indexed_artifact_pin(
        &mut tx,
        IndexedArtifactPublicationKind::Catalog,
        ManifestIndexedDatasetKind::WalletScan,
        &indexed_scope(),
        &IndexedArtifactRange {
            kind: IndexedArtifactRangeKind::Block,
            start: 0,
            end: 0,
        },
        &old_artifact_cid,
        64,
        &[11; 32],
        1,
    )
    .await?;
    tx.commit().await?;
    let old_manifest_id: i64 = sqlx::query_scalar(
        r"
        INSERT INTO published_indexed_manifests (
            cid, ipns_sequence, byte_size, content_hash, format_version
        ) VALUES ($1, 17, 64, $2, 1)
        RETURNING id
        ",
    )
    .bind(manifest_cid.to_string())
    .bind([12_u8; 32].as_slice())
    .fetch_one(&pool)
    .await?;
    insert_indexed_manifest_edge(&pool, old_manifest_id, &old_artifact_cid).await?;

    run_migrations(&pool).await?;

    assert_eq!(schema_version(&pool).await?, 19);
    assert_eq!(store.last_chain_indexed_ipns_sequence().await?, Some(17));
    assert!(
        Audit::pending_indexed_manifest_publication(&pool, &trusted_publisher_pubkey)
            .await?
            .is_none()
    );
    let old_state: (bool, bool, bool) = sqlx::query_as(
        "SELECT reconciliation_invalidated_at IS NOT NULL, \
                superseded_at IS NOT NULL, unpinned_at IS NOT NULL \
         FROM published_indexed_manifests WHERE id = $1",
    )
    .bind(old_manifest_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(old_state, (true, false, false));
    assert_eq!(
        indexed_manifest_edge_count(&pool, old_manifest_id).await?,
        1
    );

    age_indexed_rows(&pool, 100).await?;
    let ipfs = RecordingIpfsClient::default();
    let protected = Retention::sweep(
        &pool,
        &ipfs,
        UNIX_EPOCH + Duration::from_secs(200),
        Duration::from_secs(50),
    )
    .await?;
    assert!(protected.unpinned_cids.is_empty());

    let (equal_manifest, equal_json) = signed_indexed_manifest(17)?;
    let mut tx = store.begin().await?;
    Audit::record_indexed_manifest_pin(
        &mut tx,
        &manifest_cid,
        &[],
        17,
        u64::try_from(equal_json.len())?,
        &content_hash(equal_json.as_bytes()),
        equal_manifest.format_version,
        &equal_json,
    )
    .await?;
    let equal_error = Audit::record_indexed_manifest_ipns_publication(&mut tx, &manifest_cid, 17)
        .await
        .expect_err("equal sequence must not replace invalidated indexed pending");
    assert!(matches!(
        equal_error,
        railgun_indexer_core::audit::AuditError::ReconciliationSequenceNotNewer {
            channel: "chain-indexed",
            sequence: 17,
            invalidated_sequence: 17,
            ..
        }
    ));
    tx.rollback().await?;

    let (replacement, replacement_json) = signed_indexed_manifest(18)?;
    let mut tx = store.begin().await?;
    Audit::record_indexed_manifest_pin(
        &mut tx,
        &manifest_cid,
        &[],
        18,
        u64::try_from(replacement_json.len())?,
        &content_hash(replacement_json.as_bytes()),
        replacement.format_version,
        &replacement_json,
    )
    .await?;
    tx.commit().await?;
    let pending = Audit::pending_indexed_manifest_publication(&pool, &trusted_publisher_pubkey)
        .await?
        .expect("body-bearing replacement remains restart-reconcilable");
    assert_eq!(pending.manifest, replacement);
    assert_eq!(
        pending.manifest_json.as_bytes(),
        replacement_json.as_bytes()
    );
    let (blocked, blocked_json) = signed_indexed_manifest(19)?;
    let mut tx = store.begin().await?;
    let blocked_error = Audit::record_indexed_manifest_pin(
        &mut tx,
        &raw_block_cid(b"second ordinary indexed pending")?,
        &[],
        19,
        u64::try_from(blocked_json.len())?,
        &content_hash(blocked_json.as_bytes()),
        blocked.format_version,
        &blocked_json,
    )
    .await
    .expect_err("ordinary unresolved indexed pending must block new admission");
    assert!(matches!(
        blocked_error,
        railgun_indexer_core::audit::AuditError::UnresolvedPendingManifest {
            channel: "chain-indexed",
            sequence: 18,
            ..
        }
    ));
    tx.rollback().await?;

    let mut tx = store.begin().await?;
    Audit::record_indexed_manifest_ipns_publication(&mut tx, &manifest_cid, 18).await?;
    tx.commit().await?;
    let states: Vec<(i64, bool, bool, bool)> = sqlx::query_as(
        "SELECT ipns_sequence, ipns_published_at IS NOT NULL, \
                superseded_at IS NOT NULL, unpinned_at IS NOT NULL \
         FROM published_indexed_manifests WHERE cid = $1 ORDER BY ipns_sequence",
    )
    .bind(manifest_cid.to_string())
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        states,
        vec![(17, false, true, false), (18, true, false, false)]
    );

    age_indexed_rows(&pool, 100).await?;
    let eligible = Retention::sweep(
        &pool,
        &ipfs,
        UNIX_EPOCH + Duration::from_secs(200),
        Duration::from_secs(50),
    )
    .await?;
    assert_eq!(eligible.unpinned_cids, vec![old_artifact_cid]);
    assert!(!ipfs.unpinned_cids().contains(&manifest_cid.to_string()));
    Ok(())
}

#[tokio::test]
async fn v16_to_v17_invalidates_bodyless_indexed_pending_without_lowering_sequence_floor()
-> Result<(), Box<dyn std::error::Error>> {
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping V16-to-V17 indexed reconciliation test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await?;
    run_migrations(&pool).await?;
    sqlx::query("DROP INDEX IF EXISTS published_indexed_manifests_one_pending")
        .execute(&pool)
        .await?;
    sqlx::query(
        "ALTER TABLE published_indexed_manifests DROP COLUMN reconciliation_invalidated_at",
    )
    .execute(&pool)
    .await?;
    sqlx::query("UPDATE poi_indexer_schema_version SET version = 16 WHERE id = TRUE")
        .execute(&pool)
        .await?;
    let store = Store::new(pool.clone());
    store.record_chain_indexed_ipns_sequence(30).await?;
    let cid = raw_block_cid(b"v16 bodyless indexed pending")?;
    let manifest_id = insert_raw_indexed_pending(&pool, &cid, 22, None, 64, &[21; 32]).await?;

    run_migrations(&pool).await?;

    assert_eq!(schema_version(&pool).await?, 19);
    assert_eq!(store.last_chain_indexed_ipns_sequence().await?, Some(30));
    let state: (bool, bool, bool) = sqlx::query_as(
        "SELECT reconciliation_invalidated_at IS NOT NULL, \
                superseded_at IS NOT NULL, unpinned_at IS NOT NULL \
         FROM published_indexed_manifests WHERE id = $1",
    )
    .bind(manifest_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(state, (true, false, false));
    Ok(())
}

#[tokio::test]
async fn current_schema_indexed_pending_bodies_fail_closed_on_every_identity_mismatch()
-> Result<(), Box<dyn std::error::Error>> {
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping indexed pending body validation test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await?;
    let trusted_publisher_pubkey = indexed_manifest_signing_key().verifying_key().to_bytes();
    run_migrations(&pool).await?;

    let cid = raw_block_cid(b"current schema indexed pending")?;
    let null_id = insert_raw_indexed_pending(&pool, &cid, 40, None, 64, &[31; 32]).await?;
    assert!(matches!(
        Audit::pending_indexed_manifest_publication(&pool, &trusted_publisher_pubkey)
            .await
            .expect_err("current-schema null body must fail closed"),
        railgun_indexer_core::audit::AuditError::MissingIndexedManifestBody { .. }
    ));
    delete_indexed_manifest(&pool, null_id).await?;

    let corrupt = "{";
    let corrupt_id = insert_raw_indexed_pending(
        &pool,
        &cid,
        41,
        Some(corrupt),
        u64::try_from(corrupt.len())?,
        &content_hash(corrupt.as_bytes()),
    )
    .await?;
    assert!(matches!(
        Audit::pending_indexed_manifest_publication(&pool, &trusted_publisher_pubkey)
            .await
            .expect_err("corrupt JSON body must fail closed"),
        railgun_indexer_core::audit::AuditError::Json(_)
    ));
    delete_indexed_manifest(&pool, corrupt_id).await?;

    let (_, valid_json) = signed_indexed_manifest(42)?;
    let hash_mismatch_id = insert_raw_indexed_pending(
        &pool,
        &cid,
        42,
        Some(&valid_json),
        u64::try_from(valid_json.len())?,
        &[32; 32],
    )
    .await?;
    assert!(matches!(
        Audit::pending_indexed_manifest_publication(&pool, &trusted_publisher_pubkey)
            .await
            .expect_err("body/hash mismatch must fail closed"),
        railgun_indexer_core::audit::AuditError::IndexedManifestBodyMismatch { .. }
    ));
    delete_indexed_manifest(&pool, hash_mismatch_id).await?;

    let (mut bad_signature, _) = signed_indexed_manifest(43)?;
    bad_signature.sequence = 44;
    let bad_signature_json = serde_json::to_string(&bad_signature)?;
    let bad_signature_id = insert_raw_indexed_pending(
        &pool,
        &cid,
        44,
        Some(&bad_signature_json),
        u64::try_from(bad_signature_json.len())?,
        &content_hash(bad_signature_json.as_bytes()),
    )
    .await?;
    assert!(matches!(
        Audit::pending_indexed_manifest_publication(&pool, &trusted_publisher_pubkey)
            .await
            .expect_err("signature mismatch must fail closed"),
        railgun_indexer_core::audit::AuditError::IndexedManifest(_)
    ));
    delete_indexed_manifest(&pool, bad_signature_id).await?;

    let wrong_signing_key = SigningKey::from_bytes(&[92; 32]);
    let (_, wrong_signer_json) = signed_indexed_manifest_with_key(45, &wrong_signing_key)?;
    let wrong_signer_id = insert_raw_indexed_pending(
        &pool,
        &cid,
        45,
        Some(&wrong_signer_json),
        u64::try_from(wrong_signer_json.len())?,
        &content_hash(wrong_signer_json.as_bytes()),
    )
    .await?;
    assert!(matches!(
        Audit::pending_indexed_manifest_publication(&pool, &trusted_publisher_pubkey)
            .await
            .expect_err("internally valid wrong signer must fail closed"),
        railgun_indexer_core::audit::AuditError::IndexedManifest(
            railgun_indexer_core::manifest::IndexedArtifactError::PublisherKeyMismatch { .. }
        )
    ));
    delete_indexed_manifest(&pool, wrong_signer_id).await?;

    let (_, sequence_json) = signed_indexed_manifest(45)?;
    let sequence_id = insert_raw_indexed_pending(
        &pool,
        &cid,
        46,
        Some(&sequence_json),
        u64::try_from(sequence_json.len())?,
        &content_hash(sequence_json.as_bytes()),
    )
    .await?;
    assert!(matches!(
        Audit::pending_indexed_manifest_publication(&pool, &trusted_publisher_pubkey)
            .await
            .expect_err("stored/body sequence mismatch must fail closed"),
        railgun_indexer_core::audit::AuditError::IndexedManifestSequenceMismatch {
            stored: 46,
            body: 45,
            ..
        }
    ));
    delete_indexed_manifest(&pool, sequence_id).await?;
    Ok(())
}

#[tokio::test]
async fn indexed_log_batch_persistence_is_idempotent() -> Result<(), Box<dyn std::error::Error>> {
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping indexed log persistence test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await?;

    run_migrations(&pool).await?;

    let store = Store::new(pool.clone());
    let railgun_contract = Address::from([0xbb; 20]);
    let batch = indexed_log_batch_at(100);

    let mut tx = store.begin().await?;
    Store::persist_indexed_log_batch(&mut tx, 0, 1, railgun_contract, &batch).await?;
    Store::persist_indexed_log_batch(&mut tx, 0, 1, railgun_contract, &batch).await?;
    tx.commit().await?;

    assert_eq!(row_count(&pool, "indexed_transact_commitments").await?, 1);
    assert_eq!(row_count(&pool, "indexed_shield_commitments").await?, 1);
    assert_eq!(row_count(&pool, "indexed_nullifiers").await?, 1);
    assert_eq!(
        row_count(&pool, "indexed_legacy_encrypted_commitments").await?,
        1
    );
    assert_eq!(
        row_count(&pool, "indexed_legacy_generated_commitments").await?,
        1
    );
    assert_eq!(row_count(&pool, "indexed_public_transactions").await?, 1);

    let (first_log_index, last_log_index): (i64, i64) =
        sqlx::query_as("SELECT first_log_index, last_log_index FROM indexed_public_transactions")
            .fetch_one(&pool)
            .await?;
    assert_eq!((first_log_index, last_log_index), (1, 5));

    let public_rows = store
        .public_txid_rows(0, 1, railgun_contract, 0, 10)
        .await?;
    assert_eq!(public_rows.len(), 1);
    assert_eq!(public_rows[0].txid_index, 0);
    assert_eq!(public_rows[0].block_number, 100);
    assert_eq!(public_rows[0].first_log_index, 1);
    assert_eq!(public_rows[0].last_log_index, 5);

    let wallet_rows = store
        .wallet_scan_rows(0, 1, railgun_contract, 0, 200)
        .await?;
    assert_eq!(wallet_rows.transact_commitments.len(), 1);
    assert_eq!(
        wallet_rows.transact_commitments[0].source.block_timestamp,
        Some(1_700_000_100)
    );

    sqlx::query(
        "UPDATE indexed_transact_commitments SET block_timestamp = NULL \
         WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3",
    )
    .bind(0_i16)
    .bind(1_i64)
    .bind(railgun_contract.to_string())
    .execute(&pool)
    .await?;
    assert_eq!(
        store
            .count_missing_wallet_scan_timestamps(0, 1, railgun_contract, 0, 200)
            .await?,
        1
    );
    let missing = store
        .missing_wallet_scan_timestamp_blocks(0, 1, railgun_contract, 0, 200, 10)
        .await?;
    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0].block_number, 100);

    let mut tx = store.begin().await?;
    let seeded = Store::backfill_wallet_scan_timestamps_from_local_sources(
        &mut tx,
        0,
        1,
        railgun_contract,
        0,
        200,
    )
    .await?;
    tx.commit().await?;
    assert_eq!(seeded, 1);
    assert_eq!(
        store
            .count_missing_wallet_scan_timestamps(0, 1, railgun_contract, 0, 200)
            .await?,
        0
    );

    sqlx::query(
        "UPDATE indexed_transact_commitments SET block_timestamp = NULL \
         WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3",
    )
    .bind(0_i16)
    .bind(1_i64)
    .bind(railgun_contract.to_string())
    .execute(&pool)
    .await?;
    let missing = store
        .missing_wallet_scan_timestamp_blocks(0, 1, railgun_contract, 0, 200, 10)
        .await?;

    let mut tx = store.begin().await?;
    let updated = Store::backfill_wallet_scan_block_timestamps(
        &mut tx,
        0,
        1,
        railgun_contract,
        &[StoredWalletScanTimestampBackfill {
            block_number: missing[0].block_number,
            block_hash: missing[0].block_hash,
            block_timestamp: 1_700_000_999,
        }],
    )
    .await?;
    tx.commit().await?;
    assert_eq!(updated, 1);

    sqlx::query(
        "UPDATE indexed_transact_commitments SET block_timestamp = NULL \
         WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3",
    )
    .bind(0_i16)
    .bind(1_i64)
    .bind(railgun_contract.to_string())
    .execute(&pool)
    .await?;
    let missing = store
        .missing_wallet_scan_timestamp_blocks(0, 1, railgun_contract, 0, 200, 10)
        .await?;
    let mut tx = store.begin().await?;
    let updated = Store::backfill_wallet_scan_block_timestamp(
        &mut tx,
        0,
        1,
        railgun_contract,
        missing[0].block_number,
        &missing[0].block_hash,
        1_700_000_999,
    )
    .await?;
    tx.commit().await?;
    assert_eq!(updated, 1);
    assert_eq!(
        store
            .count_missing_wallet_scan_timestamps(0, 1, railgun_contract, 0, 200)
            .await?,
        0
    );

    Ok(())
}

#[tokio::test]
async fn commitment_tree_checkpoint_fills_sparse_hash_only_transact_leaves()
-> Result<(), Box<dyn std::error::Error>> {
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping commitment tree checkpoint test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await?;

    run_migrations(&pool).await?;

    let store = Store::new(pool.clone());
    let railgun_contract = Address::from([0xbb; 20]);
    let batch = sparse_commitment_batch();
    let mut tx = store.begin().await?;
    Store::persist_indexed_log_batch(&mut tx, 0, 1, railgun_contract, &batch).await?;
    tx.commit().await?;
    assert_eq!(row_count(&pool, "indexed_transact_commitments").await?, 2);

    let wallet_scan_rows = store
        .wallet_scan_rows(0, 1, railgun_contract, 0, 200)
        .await?;
    assert_eq!(wallet_scan_rows.transact_commitments.len(), 1);
    assert_eq!(wallet_scan_rows.transact_commitments[0].tree_position, 0);

    let summaries = store
        .commitment_tree_summaries(0, 1, railgun_contract, None)
        .await?;
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].tree_number, 0);
    assert_eq!(summaries[0].leaf_count, 3);
    assert_eq!(summaries[0].last_indexed_block, 102);

    let rows = store
        .commitment_rows(0, 1, railgun_contract, 0, 2, None)
        .await?;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].tree_position, 0);
    assert_eq!(rows[1].tree_position, 2);
    assert!(
        rows.iter()
            .all(|row| row.family == StoredCommitmentFamily::Transact)
    );
    assert_eq!(rows[0].commitment_hash, [0x30_u8; 32]);
    assert_eq!(rows[1].commitment_hash, [0x32_u8; 32]);

    let bounded_summaries = store
        .commitment_tree_summaries(0, 1, railgun_contract, Some(100))
        .await?;
    assert_eq!(bounded_summaries.len(), 1);
    assert_eq!(bounded_summaries[0].leaf_count, 1);
    assert_eq!(bounded_summaries[0].last_indexed_block, 100);
    let bounded_rows = store
        .commitment_rows(0, 1, railgun_contract, 0, 2, Some(100))
        .await?;
    assert_eq!(bounded_rows.len(), 1);
    assert_eq!(bounded_rows[0].tree_position, 0);
    let bounded_checkpoint = store
        .commitment_tree_checkpoint(0, 1, railgun_contract, &bounded_summaries[0], Some(100))
        .await?;
    assert_eq!(bounded_checkpoint.leaf_count, 1);
    assert_eq!(bounded_checkpoint.last_indexed_block, 100);
    assert_eq!(bounded_checkpoint.leaves, vec![[0x30_u8; 32]]);

    let checkpoint = store
        .commitment_tree_checkpoint(0, 1, railgun_contract, &summaries[0], None)
        .await?;
    assert_eq!(checkpoint.tree_number, 0);
    assert_eq!(checkpoint.leaf_count, 3);
    assert_eq!(checkpoint.last_indexed_block, 102);
    assert_eq!(
        checkpoint.leaves,
        vec![
            [0x30_u8; 32],
            MERKLE_ZERO_VALUE.to_be_bytes::<32>(),
            [0x32_u8; 32],
        ]
    );

    Ok(())
}

#[tokio::test]
async fn chain_indexing_progress_resumes_after_persisted_block()
-> Result<(), Box<dyn std::error::Error>> {
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping chain indexing progress test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await?;

    run_migrations(&pool).await?;

    let store = Store::new(pool.clone());
    let railgun_contract = Address::from([0xbb; 20]);
    assert_eq!(
        store
            .chain_indexing_resume_block(
                0,
                1,
                railgun_contract,
                IndexedDatasetKind::WalletScan,
                50,
            )
            .await?,
        50
    );

    let mut tx = store.begin().await?;
    Store::record_chain_indexing_progress(
        &mut tx,
        0,
        1,
        railgun_contract,
        IndexedDatasetKind::WalletScan,
        100,
        &[0xaa; 32],
    )
    .await?;
    tx.commit().await?;

    let progress = store
        .chain_indexing_progress(0, 1, railgun_contract, IndexedDatasetKind::WalletScan)
        .await?
        .expect("progress exists");
    assert_eq!(progress.indexed_through_block, 100);
    assert_eq!(progress.indexed_through_block_hash, [0xaa; 32]);
    assert_eq!(
        store
            .chain_indexing_resume_block(
                0,
                1,
                railgun_contract,
                IndexedDatasetKind::WalletScan,
                50,
            )
            .await?,
        101
    );

    let mut tx = store.begin().await?;
    Store::record_chain_indexing_progress(
        &mut tx,
        0,
        1,
        railgun_contract,
        IndexedDatasetKind::WalletScan,
        90,
        &[0xbb; 32],
    )
    .await?;
    tx.commit().await?;

    let progress = store
        .chain_indexing_progress(0, 1, railgun_contract, IndexedDatasetKind::WalletScan)
        .await?
        .expect("progress still exists");
    assert_eq!(progress.indexed_through_block, 100);
    assert_eq!(progress.indexed_through_block_hash, [0xaa; 32]);

    Ok(())
}

#[tokio::test]
async fn chain_indexing_rewind_deletes_rows_and_rewinds_progress()
-> Result<(), Box<dyn std::error::Error>> {
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping chain indexing rewind test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await?;

    run_migrations(&pool).await?;

    let store = Store::new(pool.clone());
    let railgun_contract = Address::from([0xbb; 20]);
    let mut tx = store.begin().await?;
    Store::record_indexed_block_header(&mut tx, 0, 1, 100, &[0xaa; 32], &[0x99; 32]).await?;
    Store::record_indexed_block_header(&mut tx, 0, 1, 101, &[0xbb; 32], &[0xaa; 32]).await?;
    Store::record_chain_indexing_progress(
        &mut tx,
        0,
        1,
        railgun_contract,
        IndexedDatasetKind::WalletScan,
        101,
        &[0xbb; 32],
    )
    .await?;
    Store::persist_indexed_log_batch(&mut tx, 0, 1, railgun_contract, &indexed_log_batch_at(101))
        .await?;
    sqlx::query(
        "INSERT INTO indexed_block_checkpoints \
         (chain_type, chain_id, railgun_contract, checkpoint_kind, block_number, block_hash, parent_hash) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(0_i16)
    .bind(1_i64)
    .bind(railgun_contract.to_string())
    .bind("wallet_scan")
    .bind(101_i64)
    .bind(vec![0xbb_u8; 32])
    .bind(vec![0xaa_u8; 32])
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let mut tx = store.begin().await?;
    let rewind =
        Store::rewind_chain_indexing_to_replay_block(&mut tx, 0, 1, railgun_contract, 101).await?;
    tx.commit().await?;

    assert_eq!(rewind.deleted_indexed_rows, 5);
    assert_eq!(rewind.deleted_public_transactions, 2);
    assert_eq!(rewind.deleted_block_checkpoints, 1);
    assert_eq!(rewind.deleted_block_headers, 1);
    assert_eq!(rewind.rewound_progress_rows, 1);
    assert_eq!(rewind.deleted_progress_rows, 0);
    assert_eq!(row_count(&pool, "indexed_transact_commitments").await?, 0);
    assert_eq!(row_count(&pool, "indexed_shield_commitments").await?, 0);
    assert_eq!(row_count(&pool, "indexed_nullifiers").await?, 0);
    assert_eq!(
        row_count(&pool, "indexed_legacy_encrypted_commitments").await?,
        0
    );
    assert_eq!(
        row_count(&pool, "indexed_legacy_generated_commitments").await?,
        0
    );
    assert_eq!(row_count(&pool, "indexed_public_transactions").await?, 0);
    assert_eq!(row_count(&pool, "indexed_public_txid_rows").await?, 0);
    assert_eq!(row_count(&pool, "indexed_block_checkpoints").await?, 0);
    assert_eq!(row_count(&pool, "indexed_block_headers").await?, 1);

    let progress = store
        .chain_indexing_progress(0, 1, railgun_contract, IndexedDatasetKind::WalletScan)
        .await?
        .expect("progress remains at previous block");
    assert_eq!(progress.indexed_through_block, 100);
    assert_eq!(progress.indexed_through_block_hash, [0xaa; 32]);
    assert_eq!(
        store
            .chain_indexing_resume_block(
                0,
                1,
                railgun_contract,
                IndexedDatasetKind::WalletScan,
                50,
            )
            .await?,
        101
    );

    Ok(())
}

#[tokio::test]
async fn indexed_artifact_reuse_and_sparse_wallet_ranges() -> Result<(), Box<dyn std::error::Error>>
{
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping indexed artifact reuse test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await?;

    run_migrations(&pool).await?;

    let store = Store::new(pool.clone());
    let railgun_contract = Address::from([0xbb; 20]);
    let scope = indexed_scope();
    let range = IndexedArtifactRange {
        kind: IndexedArtifactRangeKind::Block,
        start: 100,
        end: 200,
    };
    let cid = raw_block_cid(b"wallet scan chunk")?;
    let content_hash = [0x42_u8; 32];
    let mut tx = store.begin().await?;
    Audit::record_indexed_artifact_pin(
        &mut tx,
        IndexedArtifactPublicationKind::Chunk,
        ManifestIndexedDatasetKind::WalletScan,
        &scope,
        &range,
        &cid,
        128,
        &content_hash,
        1,
    )
    .await?;
    tx.commit().await?;

    let reusable = Audit::live_indexed_artifact_cid(
        &pool,
        IndexedArtifactPublicationKind::Chunk,
        ManifestIndexedDatasetKind::WalletScan,
        &scope,
        &range,
        128,
        &content_hash,
        1,
    )
    .await?;
    assert_eq!(reusable, Some(cid));
    let missing = Audit::live_indexed_artifact_cid(
        &pool,
        IndexedArtifactPublicationKind::Chunk,
        ManifestIndexedDatasetKind::WalletScan,
        &scope,
        &range,
        128,
        &[0x43_u8; 32],
        1,
    )
    .await?;
    assert_eq!(missing, None);

    sqlx::query(
        "INSERT INTO indexed_nullifiers \
         (chain_type, chain_id, railgun_contract, block_number, block_hash, transaction_hash, log_index, tree_number, nullifier) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9), \
                ($1, $2, $3, $10, $11, $12, $13, $14, $15)",
    )
    .bind(0_i16)
    .bind(1_i64)
    .bind(railgun_contract.to_string())
    .bind(105_i64)
    .bind(vec![0xaa_u8; 32])
    .bind(vec![0xbb_u8; 32])
    .bind(1_i64)
    .bind(0_i64)
    .bind(vec![0x01_u8; 32])
    .bind(356_i64)
    .bind(vec![0xcc_u8; 32])
    .bind(vec![0xdd_u8; 32])
    .bind(2_i64)
    .bind(0_i64)
    .bind(vec![0x02_u8; 32])
    .execute(&pool)
    .await?;

    let ranges = store
        .wallet_scan_populated_block_ranges(0, 1, railgun_contract, 100, 400, 100)
        .await?
        .into_iter()
        .map(|range| (range.start_block, range.end_block))
        .collect::<Vec<_>>();
    assert_eq!(ranges, vec![(105, 105), (356, 356)]);
    let empty_ranges = store
        .wallet_scan_populated_block_ranges(0, 1, railgun_contract, 106, 355, 100)
        .await?;
    assert!(empty_ranges.is_empty());

    Ok(())
}

#[tokio::test]
async fn store_methods_are_idempotent_and_monotonic() -> Result<(), Box<dyn std::error::Error>> {
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping Postgres store smoke test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await?;

    run_migrations(&pool).await?;

    let store = Store::new(pool.clone());
    let list_key = FixedBytes::from([9_u8; 32]);
    let upstream_url = "https://ppoi.example.invalid";
    let other_upstream_url = "https://ppoi-other.example.invalid";
    let events = vec![
        signed_event(0, 1, PoiEventType::Shield),
        signed_event(1, 2, PoiEventType::Transact),
    ];
    let blocked_shield = signed_blocked_shield(3, 4, 5, Some("first"));
    let updated_blocked_shield = signed_blocked_shield(3, 4, 6, Some("second"));
    let removed_blocked_shield = signed_blocked_shield(7, 8, 9, Some("removed"));

    assert_eq!(store.last_ipns_sequence().await?, None);
    store.record_ipns_sequence(5).await?;
    store.record_ipns_sequence(4).await?;
    assert_eq!(store.last_ipns_sequence().await?, Some(5));
    let partially_failed_cycle = store.reserve_poi_publication_sequence(5).await?;
    assert_eq!(partially_failed_cycle, 6);
    let restarted_store = Store::new(pool.clone());
    assert_eq!(
        restarted_store.reserve_poi_publication_sequence(1).await?,
        7
    );
    restarted_store.record_ipns_sequence(20).await?;
    assert_eq!(store.reserve_poi_publication_sequence(10).await?, 21);

    let mut tx = store.begin().await?;
    Store::insert_events(&mut tx, &list_key, 1, &events).await?;
    Store::insert_events(&mut tx, &list_key, 1, &events).await?;
    Store::advance_chain_tip(
        &mut tx,
        &list_key,
        1,
        upstream_url,
        1,
        Some(&hex_bytes(7, 32)),
    )
    .await?;
    let regression = Store::advance_chain_tip(
        &mut tx,
        &list_key,
        1,
        upstream_url,
        0,
        Some(&hex_bytes(8, 32)),
    )
    .await
    .expect_err("backward chain tip should be rejected");
    assert!(matches!(
        regression,
        railgun_indexer_core::store::StoreError::ChainTipRegression { .. }
    ));
    Store::upsert_blocked_shields(&mut tx, &list_key, 1, &[blocked_shield]).await?;
    Store::upsert_blocked_shields(
        &mut tx,
        &list_key,
        1,
        std::slice::from_ref(&updated_blocked_shield),
    )
    .await?;
    Store::upsert_blocked_shields(&mut tx, &list_key, 1, &[removed_blocked_shield]).await?;
    tx.commit().await?;

    let stored_events = store.page_event_range(&list_key, 1, 0, 10).await?;
    assert_eq!(stored_events.len(), 2);
    assert_eq!(stored_events[0].event_index, 0);
    assert_eq!(stored_events[1].event_index, 1);
    assert_eq!(
        store.last_event_index(&list_key, 1, upstream_url).await?,
        Some(1)
    );

    let stored_tip_root: Vec<u8> = sqlx::query_scalar(
        "SELECT last_tip_merkleroot FROM chain_tips \
         WHERE list_key = $1 AND chain_id = $2 AND upstream_url = $3",
    )
    .bind(list_key.as_slice())
    .bind(1_i64)
    .bind(upstream_url)
    .fetch_one(&pool)
    .await?;
    assert_eq!(stored_tip_root, vec![7_u8; 32]);

    let blocked_shields = store.all_blocked_shields(&list_key, 1).await?;
    assert_eq!(blocked_shields.len(), 2);
    assert_eq!(blocked_shields[0].block_reason.as_deref(), Some("second"));
    assert_eq!(blocked_shields[0].signature, [6_u8; 64]);

    let mut tx = store.begin().await?;
    Store::replace_blocked_shields(
        &mut tx,
        &list_key,
        1,
        std::slice::from_ref(&updated_blocked_shield),
    )
    .await?;
    tx.commit().await?;
    let blocked_shields = store.all_blocked_shields(&list_key, 1).await?;
    assert_eq!(blocked_shields.len(), 1);
    assert_eq!(blocked_shields[0].blinded_commitment, [4_u8; 32]);

    let old_base_cid = raw_block_cid(b"old base")?;
    let delta_cid = raw_block_cid(b"delta")?;
    let new_base_cid = raw_block_cid(b"new base")?;
    let switched_upstream_base_cid = new_base_cid;
    let old_blocked_cid = raw_block_cid(b"old blocked")?;
    let new_blocked_cid = raw_block_cid(b"new blocked")?;
    let old_manifest_cid = raw_block_cid(b"old manifest")?;
    let new_manifest_cid = raw_block_cid(b"new manifest")?;
    let failed_manifest_cid = raw_block_cid(b"failed manifest")?;
    let indexed_artifact_cid = raw_block_cid(b"indexed wallet scan chunk")?;
    let old_indexed_manifest_cid = raw_block_cid(b"old indexed manifest")?;
    let new_indexed_manifest_cid = raw_block_cid(b"new indexed manifest")?;
    let mut tx = store.begin().await?;
    Audit::record_publication(
        &mut tx,
        &list_key,
        1,
        upstream_url,
        SnapshotKind::Base,
        0,
        1,
        &old_base_cid,
        256,
        &[17_u8; 32],
        1,
        &[7_u8; 32],
    )
    .await?;
    Audit::record_publication(
        &mut tx,
        &list_key,
        1,
        upstream_url,
        SnapshotKind::Delta,
        2,
        2,
        &delta_cid,
        128,
        &[18_u8; 32],
        1,
        &[7_u8; 32],
    )
    .await?;
    Audit::record_publication(
        &mut tx,
        &list_key,
        1,
        upstream_url,
        SnapshotKind::Base,
        0,
        2,
        &new_base_cid,
        384,
        &[19_u8; 32],
        1,
        &[7_u8; 32],
    )
    .await?;
    Audit::record_publication(
        &mut tx,
        &list_key,
        1,
        other_upstream_url,
        SnapshotKind::Base,
        0,
        2,
        &switched_upstream_base_cid,
        384,
        &[20_u8; 32],
        1,
        &[7_u8; 32],
    )
    .await?;
    Audit::record_blocked_shields_publication(
        &mut tx,
        &list_key,
        1,
        upstream_url,
        &old_blocked_cid,
        128,
        2,
        &[10_u8; 32],
    )
    .await?;
    Audit::record_blocked_shields_publication(
        &mut tx,
        &list_key,
        1,
        upstream_url,
        &new_blocked_cid,
        128,
        2,
        &[11_u8; 32],
    )
    .await?;
    Audit::record_manifest_pin(&mut tx, &old_manifest_cid, 10, 96, &[12_u8; 32], 2).await?;
    Audit::record_manifest_ipns_publication(&mut tx, &old_manifest_cid, 10).await?;
    Audit::record_manifest_pin(&mut tx, &new_manifest_cid, 11, 112, &[13_u8; 32], 2).await?;
    Audit::record_manifest_ipns_publication(&mut tx, &new_manifest_cid, 11).await?;
    Audit::record_manifest_pin(&mut tx, &failed_manifest_cid, 13, 80, &[15_u8; 32], 2).await?;
    Audit::record_indexed_artifact_pin(
        &mut tx,
        IndexedArtifactPublicationKind::Chunk,
        ManifestIndexedDatasetKind::WalletScan,
        &indexed_scope(),
        &IndexedArtifactRange {
            kind: IndexedArtifactRangeKind::Block,
            start: 100,
            end: 200,
        },
        &indexed_artifact_cid,
        512,
        &[21_u8; 32],
        1,
    )
    .await?;
    Audit::record_indexed_manifest_pin(
        &mut tx,
        &old_indexed_manifest_cid,
        &[],
        20,
        96,
        &[22_u8; 32],
        1,
        "{}",
    )
    .await?;
    Audit::record_indexed_manifest_ipns_publication(&mut tx, &old_indexed_manifest_cid, 20).await?;
    Audit::record_indexed_manifest_pin(
        &mut tx,
        &new_indexed_manifest_cid,
        &[],
        21,
        112,
        &[23_u8; 32],
        1,
        "{}",
    )
    .await?;
    Audit::record_indexed_manifest_ipns_publication(&mut tx, &new_indexed_manifest_cid, 21).await?;
    tx.commit().await?;

    let (total_publications, superseded_publications): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COUNT(superseded_at) FROM published_snapshots \
         WHERE list_key = $1 AND chain_id = $2",
    )
    .bind(list_key.as_slice())
    .bind(1_i64)
    .fetch_one(&pool)
    .await?;
    assert_eq!(total_publications, 4);
    assert_eq!(superseded_publications, 1);
    let active_blocked = store
        .active_blocked_shields_publication(&list_key, 1, upstream_url)
        .await?
        .expect("active blocked-shields publication");
    assert_eq!(active_blocked.cid, new_blocked_cid.to_string());
    assert_eq!(active_blocked.content_hash, [11_u8; 32]);
    let (total_manifests, active_manifests, superseded_manifests): (i64, i64, i64) =
        sqlx::query_as(
            "SELECT \
             COUNT(*), \
             COUNT(*) FILTER (WHERE ipns_published_at IS NOT NULL AND superseded_at IS NULL), \
             COUNT(superseded_at) \
             FROM published_manifests",
        )
        .fetch_one(&pool)
        .await?;
    assert_eq!(total_manifests, 3);
    assert_eq!(active_manifests, 1);
    assert_eq!(superseded_manifests, 1);
    let (indexed_artifacts, active_indexed_manifests, superseded_indexed_manifests): (
        i64,
        i64,
        i64,
    ) = sqlx::query_as(
        "SELECT \
         (SELECT COUNT(*) FROM published_indexed_artifacts), \
         COUNT(*) FILTER (WHERE ipns_published_at IS NOT NULL AND superseded_at IS NULL), \
         COUNT(superseded_at) \
         FROM published_indexed_manifests",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(indexed_artifacts, 1);
    assert_eq!(active_indexed_manifests, 1);
    assert_eq!(superseded_indexed_manifests, 1);
    let retained_publications = store
        .active_publications(&list_key, 1, upstream_url)
        .await?;
    assert_eq!(retained_publications.len(), 2);
    assert!(retained_publications.iter().any(|publication| {
        publication.kind == SnapshotKind::Base && publication.cid == new_base_cid.to_string()
    }));
    assert!(retained_publications.iter().any(|publication| {
        publication.kind == SnapshotKind::Delta && publication.cid == delta_cid.to_string()
    }));
    let switched_upstream_publications = store
        .active_publications(&list_key, 1, other_upstream_url)
        .await?;
    assert_eq!(switched_upstream_publications.len(), 1);
    assert_eq!(
        switched_upstream_publications[0].cid,
        switched_upstream_base_cid.to_string()
    );
    assert_eq!(switched_upstream_publications[0].content_hash, [20_u8; 32]);

    sqlx::query(
        "UPDATE published_snapshots \
         SET superseded_at = to_timestamp(100) \
         WHERE superseded_at IS NOT NULL",
    )
    .execute(&pool)
    .await?;
    sqlx::query(
        "UPDATE published_blocked_shields \
         SET superseded_at = to_timestamp(100) \
         WHERE superseded_at IS NOT NULL",
    )
    .execute(&pool)
    .await?;
    sqlx::query(
        "UPDATE published_manifests \
         SET superseded_at = to_timestamp(100) \
         WHERE superseded_at IS NOT NULL",
    )
    .execute(&pool)
    .await?;
    sqlx::query(
        "UPDATE published_indexed_manifests \
         SET superseded_at = to_timestamp(100) \
         WHERE superseded_at IS NOT NULL",
    )
    .execute(&pool)
    .await?;
    sqlx::query(
        "UPDATE published_manifests \
         SET published_at = to_timestamp(100) \
         WHERE ipns_published_at IS NULL",
    )
    .execute(&pool)
    .await?;

    let ipfs_client = RecordingIpfsClient::default();
    let sweep = Retention::sweep(
        &pool,
        &ipfs_client,
        UNIX_EPOCH + Duration::from_secs(200),
        Duration::from_secs(50),
    )
    .await?;
    let mut unpinned = ipfs_client.unpinned_cids();
    let mut expected = vec![
        old_manifest_cid.to_string(),
        old_indexed_manifest_cid.to_string(),
        old_base_cid.to_string(),
        old_blocked_cid.to_string(),
    ];
    expected.sort();
    unpinned.sort();
    assert_eq!(unpinned, expected);
    assert_eq!(sorted_cids(sweep.unpinned_cids), expected);
    assert_eq!(row_count(&pool, "published_snapshots").await?, 4);
    assert_eq!(row_count(&pool, "published_manifests").await?, 3);
    assert_eq!(row_count(&pool, "published_indexed_artifacts").await?, 1);
    assert_eq!(row_count(&pool, "published_indexed_manifests").await?, 2);
    let live_indexed_artifact_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM published_indexed_artifacts \
         WHERE cid = $1 AND unpinned_at IS NULL",
    )
    .bind(indexed_artifact_cid.to_string())
    .fetch_one(&pool)
    .await?;
    assert_eq!(live_indexed_artifact_count, 1);

    let current_pending_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM published_manifests \
         WHERE cid = $1 \
             AND ipns_published_at IS NULL \
             AND superseded_at IS NULL \
             AND unpinned_at IS NULL",
    )
    .bind(failed_manifest_cid.to_string())
    .fetch_one(&pool)
    .await?;
    assert_eq!(current_pending_count, 1);

    let mut tx = store.begin().await?;
    Audit::record_manifest_ipns_publication(&mut tx, &failed_manifest_cid, 13).await?;
    tx.commit().await?;
    let invalid_published_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM published_manifests \
         WHERE cid = $1 \
             AND ipns_published_at IS NOT NULL \
             AND unpinned_at IS NOT NULL",
    )
    .bind(failed_manifest_cid.to_string())
    .fetch_one(&pool)
    .await?;
    assert_eq!(invalid_published_count, 0);

    let second_sweep = Retention::sweep(
        &pool,
        &ipfs_client,
        UNIX_EPOCH + Duration::from_mins(5),
        Duration::from_secs(50),
    )
    .await?;
    assert!(second_sweep.unpinned_cids.is_empty());
    assert_eq!(ipfs_client.unpinned_cids(), expected);

    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn v4_graph_retention_protects_active_pending_and_shared_descendants()
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
    let store = Store::new(pool.clone());
    let scope = Scope::new(FixedBytes::from([71; 32]), 0, 1, "V2_PoseidonMerkle");
    let shared_catalog = raw_block_cid(b"v4 shared catalog")?;
    let old_only = raw_block_cid(b"v4 old only")?;
    let active_only = raw_block_cid(b"v4 active only")?;
    let pending_only = raw_block_cid(b"v4 pending only")?;
    let old_manifest = raw_block_cid(b"v4 old manifest")?;
    let active_manifest = raw_block_cid(b"v4 active manifest")?;
    let pending_manifest = raw_block_cid(b"v4 pending manifest")?;

    let mut tx = store.begin().await?;
    for (kind, cid, hash) in [
        (
            PoiArtifactPublicationKind::CheckpointCatalog,
            shared_catalog,
            [1; 32],
        ),
        (
            PoiArtifactPublicationKind::BlockedShields,
            old_only,
            [2; 32],
        ),
        (
            PoiArtifactPublicationKind::BlockedShields,
            active_only,
            [3; 32],
        ),
        (
            PoiArtifactPublicationKind::BlockedShields,
            pending_only,
            [4; 32],
        ),
    ] {
        Audit::record_poi_artifact_pin(
            &mut tx,
            kind,
            &scope,
            None,
            &cid,
            64,
            &hash,
            None,
            &format!("{{\"cid\":\"{cid}\"}}"),
        )
        .await?;
    }
    let old_entry = empty_v4_entry(&scope, &shared_catalog, &old_only);
    Audit::record_poi_artifact_manifest_pin(
        &mut tx,
        &old_manifest,
        std::slice::from_ref(&old_entry),
        &[shared_catalog.to_string(), old_only.to_string()],
        1,
        128,
        &[5; 32],
    )
    .await?;
    Audit::record_poi_artifact_manifest_ipns_publication(&mut tx, &old_manifest, 1).await?;
    let active_entry = empty_v4_entry(&scope, &shared_catalog, &active_only);
    Audit::record_poi_artifact_manifest_pin(
        &mut tx,
        &active_manifest,
        std::slice::from_ref(&active_entry),
        &[shared_catalog.to_string(), active_only.to_string()],
        2,
        128,
        &[6; 32],
    )
    .await?;
    Audit::record_poi_artifact_manifest_ipns_publication(&mut tx, &active_manifest, 2).await?;
    let pending_entry = empty_v4_entry(&scope, &shared_catalog, &pending_only);
    Audit::record_poi_artifact_manifest_pin(
        &mut tx,
        &pending_manifest,
        std::slice::from_ref(&pending_entry),
        &[shared_catalog.to_string(), pending_only.to_string()],
        3,
        128,
        &[7; 32],
    )
    .await?;
    tx.commit().await?;

    let reused = Audit::live_poi_artifact_cid(
        &pool,
        PoiArtifactPublicationKind::CheckpointCatalog,
        &scope,
        None,
        64,
        &[1; 32],
        None,
    )
    .await?;
    assert_eq!(reused, Some(shared_catalog));

    sqlx::query(
        "UPDATE published_poi_v4_artifacts SET published_at = to_timestamp(100), last_referenced_at = to_timestamp(100)",
    )
    .execute(&pool)
    .await?;
    sqlx::query(
        "UPDATE published_poi_v4_manifests SET published_at = to_timestamp(100), superseded_at = to_timestamp(100) WHERE cid = $1",
    )
    .bind(old_manifest.to_string())
    .execute(&pool)
    .await?;

    let ipfs = RecordingIpfsClient::default();
    let sweep = Retention::sweep(
        &pool,
        &ipfs,
        UNIX_EPOCH + Duration::from_secs(200),
        Duration::from_secs(50),
    )
    .await?;
    assert_eq!(
        sorted_cids(sweep.unpinned_cids),
        sorted_strings([old_manifest.to_string(), old_only.to_string()])
    );
    for protected in [
        shared_catalog,
        active_only,
        active_manifest,
        pending_only,
        pending_manifest,
    ] {
        assert!(!ipfs.unpinned_cids().contains(&protected.to_string()));
    }
    Ok(())
}

#[tokio::test]
async fn v15_invalidated_manifests_and_v4_descendants_wait_for_newer_channel_activation()
-> Result<(), Box<dyn std::error::Error>> {
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping V15 graph retention test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await?;
    run_migrations(&pool).await?;
    let store = Store::new(pool.clone());
    let scope = Scope::new(FixedBytes::from([81; 32]), 0, 1, "V2_PoseidonMerkle");
    let shared_catalog = raw_block_cid(b"v15 shared catalog")?;
    let old_only = raw_block_cid(b"v15 old-only blocked")?;
    let new_only = raw_block_cid(b"v15 new-only blocked")?;
    let old_legacy = raw_block_cid(b"v15 invalidated legacy manifest")?;
    let new_legacy = old_legacy;
    let old_v4 = raw_block_cid(b"v15 invalidated v4 manifest")?;
    let new_v4 = old_v4;

    let mut tx = store.begin().await?;
    Audit::record_poi_artifact_pin(
        &mut tx,
        PoiArtifactPublicationKind::CheckpointCatalog,
        &scope,
        None,
        &shared_catalog,
        64,
        &[1; 32],
        None,
        &format!("{{\"cid\":\"{shared_catalog}\"}}"),
    )
    .await?;
    Audit::record_poi_artifact_pin(
        &mut tx,
        PoiArtifactPublicationKind::BlockedShields,
        &scope,
        None,
        &old_only,
        64,
        &[2; 32],
        None,
        &format!("{{\"cid\":\"{old_only}\"}}"),
    )
    .await?;
    Audit::record_manifest_pin(&mut tx, &old_legacy, 1, 64, &[3; 32], 2).await?;
    let old_entry = empty_v4_entry(&scope, &shared_catalog, &old_only);
    Audit::record_poi_artifact_manifest_pin(
        &mut tx,
        &old_v4,
        std::slice::from_ref(&old_entry),
        &[shared_catalog.to_string(), old_only.to_string()],
        1,
        128,
        &[4; 32],
    )
    .await?;
    tx.commit().await?;
    sqlx::query("DROP INDEX published_manifests_one_pending")
        .execute(&pool)
        .await?;
    let ambiguous_legacy = raw_block_cid(b"ambiguous legacy recovery row")?;
    sqlx::query(
        "INSERT INTO published_manifests \
         (cid, ipns_sequence, byte_size, content_hash, format_version) \
         VALUES ($1, 0, 64, $2, 2)",
    )
    .bind(ambiguous_legacy.to_string())
    .bind([9_u8; 32].as_slice())
    .execute(&pool)
    .await?;
    let mut tx = store.begin().await?;
    let ambiguous = Audit::invalidate_pending_poi_manifest_reconciliation(
        &mut tx,
        PoiManifestChannel::Legacy,
        &old_legacy,
        1,
    )
    .await
    .expect_err("multiple unresolved rows must reject recovery as ambiguous");
    assert!(matches!(
        ambiguous,
        railgun_indexer_core::audit::AuditError::AmbiguousPendingManifests {
            channel: "legacy",
            count: 2,
        }
    ));
    tx.rollback().await?;
    sqlx::query("DELETE FROM published_manifests WHERE cid = $1")
        .bind(ambiguous_legacy.to_string())
        .execute(&pool)
        .await?;
    sqlx::query(
        "CREATE UNIQUE INDEX published_manifests_one_pending \
         ON published_manifests ((TRUE)) \
         WHERE ipns_published_at IS NULL AND superseded_at IS NULL \
           AND unpinned_at IS NULL AND reconciliation_invalidated_at IS NULL",
    )
    .execute(&pool)
    .await?;
    for (channel, cid, sequence) in [
        (PoiManifestChannel::Legacy, old_v4, 1),
        (PoiManifestChannel::Legacy, old_legacy, 2),
        (
            PoiManifestChannel::Legacy,
            raw_block_cid(b"wrong recovery CID")?,
            1,
        ),
    ] {
        let mut tx = store.begin().await?;
        let error =
            Audit::invalidate_pending_poi_manifest_reconciliation(&mut tx, channel, &cid, sequence)
                .await
                .expect_err("recovery authorization must match channel, CID, and sequence exactly");
        assert!(matches!(
            error,
            railgun_indexer_core::audit::AuditError::PendingManifestAuthorizationMismatch { .. }
        ));
        tx.rollback().await?;
    }
    let mut tx = store.begin().await?;
    Audit::invalidate_pending_poi_manifest_reconciliation(
        &mut tx,
        PoiManifestChannel::Legacy,
        &old_legacy,
        1,
    )
    .await?;
    tx.commit().await?;
    let mut tx = store.begin().await?;
    Audit::invalidate_pending_poi_manifest_reconciliation(
        &mut tx,
        PoiManifestChannel::V4,
        &old_v4,
        1,
    )
    .await?;
    tx.commit().await?;
    let mut tx = store.begin().await?;
    let already_invalidated = Audit::invalidate_pending_poi_manifest_reconciliation(
        &mut tx,
        PoiManifestChannel::V4,
        &old_v4,
        1,
    )
    .await
    .expect_err("already invalidated pending manifest must be rejected");
    assert!(matches!(
        already_invalidated,
        railgun_indexer_core::audit::AuditError::PendingManifestNotRecoverable {
            state: "already invalidated",
            ..
        }
    ));
    tx.rollback().await?;
    let invalidated_state: (bool, bool, bool, bool) = sqlx::query_as(
        "SELECT reconciliation_invalidated_at IS NOT NULL, \
                ipns_published_at IS NOT NULL, superseded_at IS NOT NULL, unpinned_at IS NOT NULL \
         FROM published_poi_v4_manifests WHERE cid = $1 AND ipns_sequence = 1",
    )
    .bind(old_v4.to_string())
    .fetch_one(&pool)
    .await?;
    assert_eq!(invalidated_state, (true, false, false, false));
    let reopened = PgPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await?;
    assert!(
        Audit::pending_manifest_publication(&reopened)
            .await?
            .is_none()
    );
    assert!(
        Audit::pending_poi_artifact_manifest_publication(&reopened)
            .await?
            .is_none()
    );
    reopened.close().await;
    sqlx::query(
        "UPDATE published_poi_v4_artifacts \
         SET published_at = to_timestamp(100), last_referenced_at = to_timestamp(100)",
    )
    .execute(&pool)
    .await?;

    let ipfs = RecordingIpfsClient::default();
    let before_replacement = Retention::sweep(
        &pool,
        &ipfs,
        UNIX_EPOCH + Duration::from_secs(200),
        Duration::from_secs(50),
    )
    .await?;
    assert!(before_replacement.unpinned_cids.is_empty());

    let replacement_sequence = store.reserve_poi_publication_sequence(1).await?;
    assert_eq!(replacement_sequence, 2);
    let mut tx = store.begin().await?;
    Audit::record_manifest_pin(&mut tx, &new_legacy, replacement_sequence, 64, &[5; 32], 2).await?;
    Audit::record_poi_artifact_pin(
        &mut tx,
        PoiArtifactPublicationKind::CheckpointCatalog,
        &scope,
        None,
        &shared_catalog,
        64,
        &[1; 32],
        None,
        &format!("{{\"cid\":\"{shared_catalog}\"}}"),
    )
    .await?;
    Audit::record_poi_artifact_pin(
        &mut tx,
        PoiArtifactPublicationKind::BlockedShields,
        &scope,
        None,
        &new_only,
        64,
        &[2; 32],
        None,
        &format!("{{\"cid\":\"{new_only}\"}}"),
    )
    .await?;
    let new_entry = empty_v4_entry(&scope, &shared_catalog, &new_only);
    Audit::record_poi_artifact_manifest_pin(
        &mut tx,
        &new_v4,
        std::slice::from_ref(&new_entry),
        &[shared_catalog.to_string(), new_only.to_string()],
        replacement_sequence,
        128,
        &[6; 32],
    )
    .await?;
    Audit::record_manifest_ipns_publication(&mut tx, &new_legacy, replacement_sequence).await?;
    Audit::record_poi_artifact_manifest_ipns_publication(&mut tx, &new_v4, replacement_sequence)
        .await?;
    tx.commit().await?;

    let mut tx = store.begin().await?;
    let active_error = Audit::invalidate_pending_poi_manifest_reconciliation(
        &mut tx,
        PoiManifestChannel::V4,
        &new_v4,
        replacement_sequence,
    )
    .await
    .expect_err("active replacement must not be invalidated");
    assert!(matches!(
        active_error,
        railgun_indexer_core::audit::AuditError::PendingManifestNotRecoverable {
            state: "active",
            ..
        }
    ));
    tx.rollback().await?;

    sqlx::query(
        "UPDATE published_manifests SET superseded_at = to_timestamp(100) \
         WHERE cid = $1 AND reconciliation_invalidated_at IS NOT NULL",
    )
    .bind(old_legacy.to_string())
    .execute(&pool)
    .await?;
    sqlx::query(
        "UPDATE published_poi_v4_manifests SET superseded_at = to_timestamp(100) \
         WHERE cid = $1 AND reconciliation_invalidated_at IS NOT NULL",
    )
    .bind(old_v4.to_string())
    .execute(&pool)
    .await?;
    sqlx::query("UPDATE published_poi_v4_artifacts SET last_referenced_at = to_timestamp(100)")
        .execute(&pool)
        .await?;

    let after_replacement = Retention::sweep(
        &pool,
        &ipfs,
        UNIX_EPOCH + Duration::from_secs(200),
        Duration::from_secs(50),
    )
    .await?;
    assert_eq!(
        sorted_cids(after_replacement.unpinned_cids),
        sorted_strings([old_only.to_string(),])
    );
    for retained in [new_legacy, new_v4, shared_catalog, new_only] {
        assert!(!ipfs.unpinned_cids().contains(&retained.to_string()));
    }

    Ok(())
}

#[tokio::test]
async fn retention_expires_deltas_only_after_covering_base_ages()
-> Result<(), Box<dyn std::error::Error>> {
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping retention expiry test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await?;
    run_migrations(&pool).await?;

    let store = Store::new(pool.clone());
    let list_key = FixedBytes::from([42_u8; 32]);
    let upstream_url = "https://ppoi.example.invalid";
    let old_base_cid = raw_block_cid(b"expiry old base")?;
    let retained_delta_cid = raw_block_cid(b"expiry retained delta")?;
    let old_covering_base_cid = raw_block_cid(b"expiry old covering base")?;
    let new_base_cid = raw_block_cid(b"expiry new base")?;

    let mut tx = store.begin().await?;
    Audit::record_publication(
        &mut tx,
        &list_key,
        1,
        upstream_url,
        SnapshotKind::Base,
        0,
        4,
        &old_base_cid,
        256,
        &[31_u8; 32],
        1,
        &[41_u8; 32],
    )
    .await?;
    Audit::record_publication(
        &mut tx,
        &list_key,
        1,
        upstream_url,
        SnapshotKind::Delta,
        5,
        9,
        &retained_delta_cid,
        128,
        &[32_u8; 32],
        1,
        &[42_u8; 32],
    )
    .await?;
    Audit::record_publication(
        &mut tx,
        &list_key,
        1,
        upstream_url,
        SnapshotKind::Base,
        0,
        9,
        &old_covering_base_cid,
        384,
        &[33_u8; 32],
        1,
        &[42_u8; 32],
    )
    .await?;
    Audit::record_publication(
        &mut tx,
        &list_key,
        1,
        upstream_url,
        SnapshotKind::Base,
        0,
        9,
        &new_base_cid,
        512,
        &[34_u8; 32],
        1,
        &[42_u8; 32],
    )
    .await?;
    tx.commit().await?;

    let retained = store
        .active_publications(&list_key, 1, upstream_url)
        .await?;
    assert_eq!(retained.len(), 2);
    assert!(retained.iter().any(|publication| {
        publication.kind == SnapshotKind::Delta && publication.cid == retained_delta_cid.to_string()
    }));

    sqlx::query(
        "UPDATE published_snapshots \
         SET published_at = to_timestamp(100), superseded_at = to_timestamp(160) \
         WHERE cid = $1",
    )
    .bind(old_covering_base_cid.to_string())
    .execute(&pool)
    .await?;
    sqlx::query(
        "UPDATE published_snapshots \
         SET published_at = to_timestamp(180) \
         WHERE cid = $1",
    )
    .bind(new_base_cid.to_string())
    .execute(&pool)
    .await?;

    let ipfs_client = RecordingIpfsClient::default();
    let first_sweep = Retention::sweep(
        &pool,
        &ipfs_client,
        UNIX_EPOCH + Duration::from_secs(200),
        Duration::from_secs(50),
    )
    .await?;
    assert!(first_sweep.unpinned_cids.is_empty());
    assert!(ipfs_client.unpinned_cids().is_empty());

    let active_after_expiry = store
        .active_publications(&list_key, 1, upstream_url)
        .await?;
    assert_eq!(active_after_expiry.len(), 1);
    assert_eq!(active_after_expiry[0].cid, new_base_cid.to_string());

    let second_sweep = Retention::sweep(
        &pool,
        &ipfs_client,
        UNIX_EPOCH + Duration::from_mins(5),
        Duration::from_secs(50),
    )
    .await?;
    let mut expected = vec![
        old_covering_base_cid.to_string(),
        retained_delta_cid.to_string(),
    ];
    expected.sort();
    assert_eq!(sorted_cids(second_sweep.unpinned_cids), expected);
    assert_eq!(ipfs_client.unpinned_cids(), expected);

    Ok(())
}

#[tokio::test]
async fn retention_prunes_stale_indexed_artifacts() -> Result<(), Box<dyn std::error::Error>> {
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping indexed artifact retention test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await?;
    run_migrations(&pool).await?;

    let store = Store::new(pool.clone());
    let scope = indexed_scope();
    let stale_cid = raw_block_cid(b"stale indexed artifact")?;
    let fresh_cid = raw_block_cid(b"fresh indexed artifact")?;
    let shared_cid = raw_block_cid(b"shared indexed artifact")?;
    let active_catalog_cid = raw_block_cid(b"active indexed catalog")?;
    let active_chunk_cid = raw_block_cid(b"active indexed chunk")?;
    let active_indexed_manifest_cid = raw_block_cid(b"active indexed manifest")?;
    let pending_catalog_cid = raw_block_cid(b"pending indexed catalog")?;
    let pending_indexed_manifest_cid = raw_block_cid(b"pending indexed manifest")?;
    let stale_range = indexed_block_range(0, 9);
    let fresh_range = indexed_block_range(10, 19);
    let shared_stale_range = indexed_block_range(20, 29);
    let shared_fresh_range = indexed_block_range(30, 39);
    let active_catalog_range = indexed_block_range(40, 49);
    let active_chunk_range = indexed_block_range(50, 59);
    let pending_catalog_range = indexed_block_range(60, 69);

    let mut tx = store.begin().await?;
    Audit::record_indexed_artifact_pin(
        &mut tx,
        IndexedArtifactPublicationKind::Chunk,
        ManifestIndexedDatasetKind::WalletScan,
        &scope,
        &stale_range,
        &stale_cid,
        128,
        &[31_u8; 32],
        1,
    )
    .await?;
    Audit::record_indexed_artifact_pin(
        &mut tx,
        IndexedArtifactPublicationKind::Chunk,
        ManifestIndexedDatasetKind::WalletScan,
        &scope,
        &fresh_range,
        &fresh_cid,
        128,
        &[32_u8; 32],
        1,
    )
    .await?;
    Audit::record_indexed_artifact_pin(
        &mut tx,
        IndexedArtifactPublicationKind::Chunk,
        ManifestIndexedDatasetKind::WalletScan,
        &scope,
        &shared_stale_range,
        &shared_cid,
        128,
        &[33_u8; 32],
        1,
    )
    .await?;
    Audit::record_indexed_artifact_pin(
        &mut tx,
        IndexedArtifactPublicationKind::Chunk,
        ManifestIndexedDatasetKind::WalletScan,
        &scope,
        &shared_fresh_range,
        &shared_cid,
        128,
        &[33_u8; 32],
        1,
    )
    .await?;
    Audit::record_indexed_artifact_pin(
        &mut tx,
        IndexedArtifactPublicationKind::Chunk,
        ManifestIndexedDatasetKind::WalletScan,
        &scope,
        &active_catalog_range,
        &active_catalog_cid,
        128,
        &[34_u8; 32],
        1,
    )
    .await?;
    Audit::record_indexed_artifact_pin(
        &mut tx,
        IndexedArtifactPublicationKind::Chunk,
        ManifestIndexedDatasetKind::WalletScan,
        &scope,
        &active_chunk_range,
        &active_chunk_cid,
        128,
        &[35_u8; 32],
        1,
    )
    .await?;
    Audit::record_indexed_manifest_pin(
        &mut tx,
        &active_indexed_manifest_cid,
        &[active_catalog_cid.to_string(), active_chunk_cid.to_string()],
        10,
        96,
        &[36_u8; 32],
        1,
        "{}",
    )
    .await?;
    Audit::record_indexed_manifest_ipns_publication(&mut tx, &active_indexed_manifest_cid, 10)
        .await?;
    Audit::record_indexed_artifact_pin(
        &mut tx,
        IndexedArtifactPublicationKind::Catalog,
        ManifestIndexedDatasetKind::WalletScan,
        &scope,
        &pending_catalog_range,
        &pending_catalog_cid,
        128,
        &[37_u8; 32],
        1,
    )
    .await?;
    Audit::record_indexed_manifest_pin(
        &mut tx,
        &pending_indexed_manifest_cid,
        &[pending_catalog_cid.to_string()],
        11,
        96,
        &[38_u8; 32],
        1,
        "{}",
    )
    .await?;
    tx.commit().await?;

    for range_start in [0_i64, 20, 40, 50, 60] {
        sqlx::query(
            "UPDATE published_indexed_artifacts \
             SET published_at = to_timestamp(100), last_referenced_at = to_timestamp(100) \
             WHERE range_start = $1",
        )
        .bind(range_start)
        .execute(&pool)
        .await?;
    }
    for range_start in [10_i64, 30] {
        sqlx::query(
            "UPDATE published_indexed_artifacts \
             SET published_at = to_timestamp(180), last_referenced_at = to_timestamp(180) \
             WHERE range_start = $1",
        )
        .bind(range_start)
        .execute(&pool)
        .await?;
    }

    let ipfs_client = RecordingIpfsClient::default();
    let sweep = Retention::sweep(
        &pool,
        &ipfs_client,
        UNIX_EPOCH + Duration::from_secs(200),
        Duration::from_secs(50),
    )
    .await?;
    let expected = vec![stale_cid.to_string()];
    assert_eq!(sorted_cids(sweep.unpinned_cids), expected);
    assert_eq!(ipfs_client.unpinned_cids(), expected);

    let stale_unpinned_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM published_indexed_artifacts \
         WHERE cid = $1 AND unpinned_at IS NOT NULL",
    )
    .bind(stale_cid.to_string())
    .fetch_one(&pool)
    .await?;
    assert_eq!(stale_unpinned_count, 1);

    let preserved_unpinned_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM published_indexed_artifacts \
         WHERE (cid = $1 OR cid = $2 OR cid = $3 OR cid = $4 OR cid = $5) \
              AND unpinned_at IS NOT NULL",
    )
    .bind(fresh_cid.to_string())
    .bind(shared_cid.to_string())
    .bind(active_catalog_cid.to_string())
    .bind(active_chunk_cid.to_string())
    .bind(pending_catalog_cid.to_string())
    .fetch_one(&pool)
    .await?;
    assert_eq!(preserved_unpinned_count, 0);

    let mut tx = store.begin().await?;
    Audit::record_indexed_manifest_ipns_publication(&mut tx, &pending_indexed_manifest_cid, 11)
        .await?;
    tx.commit().await?;
    let superseded_sweep = Retention::sweep(
        &pool,
        &ipfs_client,
        UNIX_EPOCH + Duration::from_mins(5),
        Duration::from_secs(200),
    )
    .await?;
    let mut expected_superseded =
        vec![active_catalog_cid.to_string(), active_chunk_cid.to_string()];
    expected_superseded.sort();
    assert_eq!(
        sorted_cids(superseded_sweep.unpinned_cids),
        expected_superseded
    );
    assert!(
        !ipfs_client
            .unpinned_cids()
            .contains(&pending_catalog_cid.to_string())
    );

    let mut tx = store.begin().await?;
    Audit::record_indexed_artifact_pin(
        &mut tx,
        IndexedArtifactPublicationKind::Chunk,
        ManifestIndexedDatasetKind::WalletScan,
        &scope,
        &stale_range,
        &stale_cid,
        128,
        &[31_u8; 32],
        1,
    )
    .await?;
    tx.commit().await?;
    let repinned_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM published_indexed_artifacts \
         WHERE cid = $1 AND unpinned_at IS NULL",
    )
    .bind(stale_cid.to_string())
    .fetch_one(&pool)
    .await?;
    assert_eq!(repinned_count, 1);

    Ok(())
}

#[tokio::test]
async fn retention_first_forces_concurrent_reuse_to_observe_unpinned_state()
-> Result<(), Box<dyn std::error::Error>> {
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping indexed artifact retention race test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&connection_string)
        .await?;
    run_migrations(&pool).await?;

    let store = Store::new(pool.clone());
    let scope = indexed_scope();
    let range = indexed_block_range(0, 9);
    let cid = raw_block_cid(b"retention race artifact")?;
    let mut tx = store.begin().await?;
    Audit::record_indexed_artifact_pin(
        &mut tx,
        IndexedArtifactPublicationKind::Chunk,
        ManifestIndexedDatasetKind::WalletScan,
        &scope,
        &range,
        &cid,
        128,
        &[41_u8; 32],
        1,
    )
    .await?;
    tx.commit().await?;
    sqlx::query("UPDATE published_indexed_artifacts SET last_referenced_at = to_timestamp(100)")
        .execute(&pool)
        .await?;

    let coordinator = PinLifecycleCoordinator::default();
    let ipfs_client = Arc::new(BlockingUnpinIpfsClient::default());
    let retention_pool = pool.clone();
    let retention_coordinator = coordinator.clone();
    let retention_client = Arc::clone(&ipfs_client);
    let retention = tokio::spawn(async move {
        Retention::sweep_with_coordinator(
            &retention_pool,
            retention_client.as_ref(),
            UNIX_EPOCH + Duration::from_secs(200),
            Duration::from_secs(50),
            &retention_coordinator,
        )
        .await
    });
    ipfs_client.unpin_entered.notified().await;

    let reuse_pool = pool.clone();
    let reuse_coordinator = coordinator.clone();
    let reuse_scope = scope.clone();
    let mut reuse = tokio::spawn(async move {
        let _pin_lifecycle = reuse_coordinator.lock().await;
        Audit::live_indexed_artifact_cid(
            &reuse_pool,
            IndexedArtifactPublicationKind::Chunk,
            ManifestIndexedDatasetKind::WalletScan,
            &reuse_scope,
            &range,
            128,
            &[41_u8; 32],
            1,
        )
        .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut reuse)
            .await
            .is_err(),
        "reuse must wait while retention owns the pin lifecycle"
    );

    ipfs_client.allow_unpin.notify_one();
    let sweep = retention.await??;
    assert_eq!(sweep.unpinned_cids, vec![cid]);
    assert_eq!(reuse.await??, None);
    assert!(!ipfs_client.pinned.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn v4_retention_first_forces_concurrent_reuse_to_observe_unpinned_state()
-> Result<(), Box<dyn std::error::Error>> {
    let node = Postgres::default().start().await?;
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&connection_string)
        .await?;
    run_migrations(&pool).await?;

    let store = Store::new(pool.clone());
    let scope = Scope::new(FixedBytes::from([91; 32]), 0, 1, "V2_PoseidonMerkle");
    let cid = raw_block_cid(b"POI v4 retention race artifact")?;
    let hash = [41_u8; 32];
    let mut tx = store.begin().await?;
    Audit::record_poi_artifact_pin(
        &mut tx,
        PoiArtifactPublicationKind::CheckpointCatalog,
        &scope,
        None,
        &cid,
        128,
        &hash,
        None,
        "{}",
    )
    .await?;
    tx.commit().await?;
    sqlx::query("UPDATE published_poi_v4_artifacts SET last_referenced_at = to_timestamp(100)")
        .execute(&pool)
        .await?;

    let coordinator = PinLifecycleCoordinator::default();
    let ipfs_client = Arc::new(BlockingUnpinIpfsClient::default());
    let retention_pool = pool.clone();
    let retention_coordinator = coordinator.clone();
    let retention_client = Arc::clone(&ipfs_client);
    let retention = tokio::spawn(async move {
        Retention::sweep_with_coordinator(
            &retention_pool,
            retention_client.as_ref(),
            UNIX_EPOCH + Duration::from_secs(200),
            Duration::from_secs(50),
            &retention_coordinator,
        )
        .await
    });
    ipfs_client.unpin_entered.notified().await;

    let reuse_pool = pool.clone();
    let reuse_coordinator = coordinator.clone();
    let reuse_scope = scope.clone();
    let mut reuse = tokio::spawn(async move {
        let _pin_lifecycle = reuse_coordinator.lock().await;
        Audit::live_poi_artifact_cid(
            &reuse_pool,
            PoiArtifactPublicationKind::CheckpointCatalog,
            &reuse_scope,
            None,
            128,
            &hash,
            None,
        )
        .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut reuse)
            .await
            .is_err(),
        "POI artifact reuse must wait while retention owns the pin lifecycle"
    );

    ipfs_client.allow_unpin.notify_one();
    let sweep = retention.await??;
    assert_eq!(sweep.unpinned_cids, vec![cid]);
    assert_eq!(reuse.await??, None);
    assert!(!ipfs_client.pinned.load(Ordering::SeqCst));
    Ok(())
}

fn is_docker_unavailable(error: &impl std::fmt::Debug) -> bool {
    let message = format!("{error:?}");
    message.contains("SocketNotFoundError")
        || message.contains("Connection refused")
        || message.to_ascii_lowercase().contains("permission denied")
}

async fn row_count(pool: &sqlx::PgPool, table: &str) -> Result<i64, sqlx::Error> {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    sqlx::query_scalar(&sql).fetch_one(pool).await
}

async fn table_exists(pool: &sqlx::PgPool, table: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = 'public' AND table_name = $1
        )
        ",
    )
    .bind(table)
    .fetch_one(pool)
    .await
}

async fn schema_version(pool: &sqlx::PgPool) -> Result<i32, sqlx::Error> {
    sqlx::query_scalar("SELECT version FROM poi_indexer_schema_version WHERE id = TRUE")
        .fetch_one(pool)
        .await
}

fn signed_event(index: u64, byte: u8, event_type: PoiEventType) -> SignedPoiEvent {
    SignedPoiEvent {
        index,
        blinded_commitment: FixedBytes::from([byte; 32]),
        signature: hex_bytes(byte + 10, 64),
        event_type,
    }
}

fn signed_blocked_shield(
    commitment_hash_byte: u8,
    blinded_commitment_byte: u8,
    signature_byte: u8,
    block_reason: Option<&str>,
) -> SignedBlockedShield {
    SignedBlockedShield {
        commitment_hash: hex_bytes(commitment_hash_byte, 32),
        blinded_commitment: hex_bytes(blinded_commitment_byte, 32),
        block_reason: block_reason.map(ToString::to_string),
        signature: hex_bytes(signature_byte, 64),
    }
}

fn hex_bytes(byte: u8, len: usize) -> String {
    hex::encode_prefixed(vec![byte; len])
}

fn indexed_scope() -> ChainScope {
    ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .parse()
            .expect("scope address"),
    }
}

const fn indexed_block_range(start: u64, end: u64) -> IndexedArtifactRange {
    IndexedArtifactRange {
        kind: IndexedArtifactRangeKind::Block,
        start,
        end,
    }
}

fn indexed_source_at(block_number: u64, log_index: u64) -> IndexedLogSource {
    IndexedLogSource {
        block_number,
        block_timestamp: Some(1_700_000_000 + block_number),
        block_hash: AlloyFixedBytes::from([0xaa; 32]),
        transaction_hash: AlloyFixedBytes::from([0xcc; 32]),
        log_index,
    }
}

fn indexed_log_batch_at(block_number: u64) -> IndexedLogBatch {
    IndexedLogBatch {
        transact_commitments: vec![IndexedTransactCommitment {
            tree_number: 1,
            tree_position: 10,
            hash: AlloyFixedBytes::from([0x10; 32]),
            ciphertext: Some(commitment_ciphertext(0x11)),
            source: indexed_source_at(block_number, 1),
        }],
        shield_commitments: vec![IndexedShieldCommitment {
            tree_number: 1,
            tree_position: 11,
            preimage: commitment_preimage(0x12),
            shield_ciphertext: shield_ciphertext(0x13),
            source: indexed_source_at(block_number, 2),
        }],
        nullifiers: vec![IndexedNullifier {
            tree_number: 1,
            nullifier: AlloyFixedBytes::from([0x14; 32]),
            source: indexed_source_at(block_number, 3),
        }],
        legacy_encrypted_commitments: vec![IndexedLegacyEncryptedCommitment {
            tree_number: 0,
            tree_position: 1,
            hash: AlloyFixedBytes::from([0x15; 32]),
            ciphertext: legacy_commitment_ciphertext(0x16),
            source: indexed_source_at(block_number, 4),
        }],
        legacy_generated_commitments: vec![IndexedLegacyGeneratedCommitment {
            tree_number: 0,
            tree_position: 2,
            preimage: legacy_commitment_preimage(0x17),
            encrypted_random: [U256::from(0x18_u64), U256::from(0x19_u64)],
            source: indexed_source_at(block_number, 5),
        }],
        public_transactions: vec![IndexedPublicTransaction {
            source: indexed_source_at(block_number, 1),
            first_log_index: 1,
            last_log_index: 5,
            railgun_transaction_index: 0,
            id: format!("0x{block_number:x}:0"),
            block_timestamp: 1_700_000_000 + block_number,
            merkle_root: AlloyFixedBytes::from([0x20; 32]),
            nullifiers: vec![AlloyFixedBytes::from([0x21; 32])],
            commitments: vec![AlloyFixedBytes::from([0x22; 32])],
            bound_params_hash: AlloyFixedBytes::from([0x23; 32]),
            has_unshield: false,
            utxo_tree_in: 1,
            utxo_tree_out: 1,
            utxo_batch_start_position_out: 10,
            railgun_txid: U256::from(0x24_u64),
        }],
    }
}

fn sparse_commitment_batch() -> IndexedLogBatch {
    IndexedLogBatch {
        transact_commitments: vec![
            IndexedTransactCommitment {
                tree_number: 0,
                tree_position: 0,
                hash: AlloyFixedBytes::from([0x30; 32]),
                ciphertext: Some(commitment_ciphertext(0x33)),
                source: indexed_source_at(100, 1),
            },
            IndexedTransactCommitment {
                tree_number: 0,
                tree_position: 2,
                hash: AlloyFixedBytes::from([0x32; 32]),
                ciphertext: None,
                source: indexed_source_at(102, 1),
            },
        ],
        public_transactions: vec![IndexedPublicTransaction {
            source: indexed_source_at(102, 3),
            first_log_index: 3,
            last_log_index: 3,
            railgun_transaction_index: 0,
            id: "0xcontiguous:0".to_string(),
            block_timestamp: 1_700_000_102,
            merkle_root: AlloyFixedBytes::from([0x36; 32]),
            nullifiers: Vec::new(),
            commitments: vec![
                AlloyFixedBytes::from([0x40; 32]),
                AlloyFixedBytes::from([0x41; 32]),
            ],
            bound_params_hash: AlloyFixedBytes::from([0x37; 32]),
            has_unshield: false,
            utxo_tree_in: 0,
            utxo_tree_out: 0,
            utxo_batch_start_position_out: 1,
            railgun_txid: U256::from(0x38_u64),
        }],
        ..Default::default()
    }
}

fn commitment_ciphertext(byte: u8) -> CommitmentCiphertext {
    CommitmentCiphertext {
        ciphertext: std::array::from_fn(|_| AlloyFixedBytes::from([byte; 32])),
        blindedSenderViewingKey: AlloyFixedBytes::from([byte.wrapping_add(1); 32]),
        blindedReceiverViewingKey: AlloyFixedBytes::from([byte.wrapping_add(2); 32]),
        annotationData: Bytes::from(vec![byte.wrapping_add(3)]),
        memo: Bytes::from(vec![byte.wrapping_add(4)]),
    }
}

fn shield_ciphertext(byte: u8) -> ShieldCiphertext {
    ShieldCiphertext {
        encryptedBundle: std::array::from_fn(|_| AlloyFixedBytes::from([byte; 32])),
        shieldKey: AlloyFixedBytes::from([byte.wrapping_add(1); 32]),
    }
}

fn commitment_preimage(byte: u8) -> CommitmentPreimage {
    CommitmentPreimage {
        npk: AlloyFixedBytes::from([byte; 32]),
        token: token_data(),
        value: Uint::<120, 2>::from(1_u64),
    }
}

fn legacy_commitment_ciphertext(byte: u8) -> LegacyCommitmentCiphertext {
    LegacyCommitmentCiphertext {
        ciphertext: std::array::from_fn(|index| U256::from(u64::from(byte) + index as u64)),
        ephemeralKeys: std::array::from_fn(|index| {
            U256::from(u64::from(byte.wrapping_add(4)) + index as u64)
        }),
        memo: vec![U256::from(byte.wrapping_add(6))],
    }
}

fn legacy_commitment_preimage(byte: u8) -> LegacyCommitmentPreimage {
    LegacyCommitmentPreimage {
        npk: U256::from(byte),
        token: token_data(),
        value: Uint::<120, 2>::from(1_u64),
    }
}

const fn token_data() -> TokenData {
    TokenData {
        tokenType: 0,
        tokenAddress: Address::ZERO,
        tokenSubID: U256::ZERO,
    }
}

fn signed_indexed_manifest(
    sequence: u64,
) -> Result<(IndexedArtifactManifest, String), Box<dyn std::error::Error>> {
    let signing_key = indexed_manifest_signing_key();
    signed_indexed_manifest_with_key(sequence, &signing_key)
}

fn signed_indexed_manifest_with_key(
    sequence: u64,
    signing_key: &SigningKey,
) -> Result<(IndexedArtifactManifest, String), Box<dyn std::error::Error>> {
    let mut manifest = IndexedArtifactManifest::new(
        1_700_000_000_000,
        sequence,
        PublisherIdentity::ed25519(FixedBytes::ZERO),
        Vec::new(),
    );
    manifest.sign_manifest(signing_key)?;
    let json = serde_json::to_string(&manifest)?;
    Ok((manifest, json))
}

fn indexed_manifest_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[91; 32])
}

async fn insert_raw_indexed_pending(
    pool: &sqlx::PgPool,
    cid: &Cid,
    sequence: u64,
    manifest_json: Option<&str>,
    byte_size: u64,
    hash: &[u8; 32],
) -> Result<i64, Box<dyn std::error::Error>> {
    Ok(sqlx::query_scalar(
        r"
        INSERT INTO published_indexed_manifests (
            cid, ipns_sequence, byte_size, content_hash, format_version, manifest_json
        ) VALUES ($1, $2, $3, $4, 1, $5)
        RETURNING id
        ",
    )
    .bind(cid.to_string())
    .bind(i64::try_from(sequence)?)
    .bind(i64::try_from(byte_size)?)
    .bind(hash.as_slice())
    .bind(manifest_json)
    .fetch_one(pool)
    .await?)
}

async fn insert_indexed_manifest_edge(
    pool: &sqlx::PgPool,
    manifest_id: i64,
    artifact_cid: &Cid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO published_indexed_manifest_artifacts (manifest_id, artifact_cid) \
         VALUES ($1, $2)",
    )
    .bind(manifest_id)
    .bind(artifact_cid.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

async fn indexed_manifest_edge_count(
    pool: &sqlx::PgPool,
    manifest_id: i64,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM published_indexed_manifest_artifacts WHERE manifest_id = $1",
    )
    .bind(manifest_id)
    .fetch_one(pool)
    .await
}

async fn delete_indexed_manifest(pool: &sqlx::PgPool, manifest_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM published_indexed_manifests WHERE id = $1")
        .bind(manifest_id)
        .execute(pool)
        .await?;
    Ok(())
}

async fn age_indexed_rows(pool: &sqlx::PgPool, seconds: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE published_indexed_manifests \
         SET published_at = to_timestamp($1), \
             superseded_at = CASE WHEN superseded_at IS NULL THEN NULL ELSE to_timestamp($1) END",
    )
    .bind(seconds)
    .execute(pool)
    .await?;
    sqlx::query(
        "UPDATE published_indexed_artifacts \
         SET published_at = to_timestamp($1), last_referenced_at = to_timestamp($1)",
    )
    .bind(seconds)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, Default)]
struct RecordingIpfsClient {
    unpinned: Mutex<Vec<Cid>>,
}

#[derive(Debug)]
struct BlockingUnpinIpfsClient {
    unpin_entered: Notify,
    allow_unpin: Notify,
    pinned: AtomicBool,
}

impl Default for BlockingUnpinIpfsClient {
    fn default() -> Self {
        Self {
            unpin_entered: Notify::new(),
            allow_unpin: Notify::new(),
            pinned: AtomicBool::new(true),
        }
    }
}

#[async_trait]
impl IpfsClient for BlockingUnpinIpfsClient {
    fn service_name(&self) -> &'static str {
        "blocking-unpin"
    }

    async fn pin_bytes(&self, bytes: &[u8]) -> Result<Cid, IpfsError> {
        self.pinned.store(true, Ordering::SeqCst);
        raw_block_cid(bytes)
    }

    async fn unpin(&self, _cid: &Cid) -> Result<(), IpfsError> {
        self.unpin_entered.notify_one();
        self.allow_unpin.notified().await;
        self.pinned.store(false, Ordering::SeqCst);
        Ok(())
    }

    async fn contains(&self, _cid: &Cid) -> Result<bool, IpfsError> {
        Ok(self.pinned.load(Ordering::SeqCst))
    }
}

impl RecordingIpfsClient {
    fn unpinned_cids(&self) -> Vec<String> {
        sorted_cids(self.unpinned.lock().expect("unpinned cids lock").clone())
    }
}

#[async_trait]
impl IpfsClient for RecordingIpfsClient {
    fn service_name(&self) -> &'static str {
        "recording"
    }

    async fn pin_bytes(&self, bytes: &[u8]) -> Result<Cid, IpfsError> {
        raw_block_cid(bytes)
    }

    async fn unpin(&self, cid: &Cid) -> Result<(), IpfsError> {
        self.unpinned.lock().expect("unpinned cids lock").push(*cid);
        Ok(())
    }

    async fn contains(&self, _cid: &Cid) -> Result<bool, IpfsError> {
        Ok(true)
    }
}

fn sorted_cids(cids: Vec<Cid>) -> Vec<String> {
    let mut cids = cids
        .into_iter()
        .map(|cid| cid.to_string())
        .collect::<Vec<_>>();
    cids.sort();
    cids
}

fn sorted_strings(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort();
    values
}

fn empty_v4_entry(scope: &Scope, catalog_cid: &Cid, blocked_cid: &Cid) -> ManifestEntry {
    ManifestEntry {
        scope: scope.clone(),
        event_count: 0,
        current_tip_index: None,
        current_root: None,
        checkpoint_catalog: CheckpointCatalogDescriptor {
            artifact: ArtifactDescriptor {
                cid: catalog_cid.to_string(),
                sha256: FixedBytes::from([1; 32]),
                byte_size: 64,
            },
            format_version: FORMAT_VERSION,
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
                cid: blocked_cid.to_string(),
                sha256: FixedBytes::from([2; 32]),
                byte_size: 64,
            },
            format_version: FORMAT_VERSION,
            scope: scope.clone(),
            row_count: 0,
            encoding: ArtifactEncoding::CanonicalJson,
            compression: Compression::Identity,
        },
    }
}
