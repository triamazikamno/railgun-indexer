use alloy::primitives::{Address, Bytes, FixedBytes, Log as PrimitiveLog, U256};
use alloy::sol_types::SolEvent;
use alloy::uint;
use alloy_rpc_types_eth::Log;
use broadcaster_core::contracts::railgun::{CommitmentCiphertext, Nullified, Transact};
use railgun_indexer_core::chain_logs::ingest_chain_logs;
use railgun_indexer_core::store::{Store, run_migrations};
use sqlx::postgres::PgPoolOptions;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

#[tokio::test]
async fn rpc_log_fixture_persists_indexed_rows_without_squid_upstream()
-> Result<(), Box<dyn std::error::Error>> {
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping RPC log indexing fixture: Docker is unavailable");
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

    let logs = vec![
        log_for(
            &Transact {
                treeNumber: uint!(1_U256),
                startPosition: U256::from(10),
                hash: vec![FixedBytes::from([0x10; 32])],
                ciphertext: vec![commitment_ciphertext()],
            },
            1,
        ),
        log_for(
            &Nullified {
                treeNumber: 1,
                nullifier: vec![FixedBytes::from([0x11; 32])],
            },
            2,
        ),
    ];
    let mut batch = ingest_chain_logs(&logs)?;
    for item in &mut batch.transact_commitments {
        item.source.block_timestamp = Some(1_700_000_100);
    }
    for item in &mut batch.nullifiers {
        item.source.block_timestamp = Some(1_700_000_100);
    }

    let store = Store::new(pool.clone());
    let mut tx = store.begin().await?;
    Store::persist_indexed_log_batch(&mut tx, 0, 1, Address::from([0xbb; 20]), &batch).await?;
    tx.commit().await?;

    assert_eq!(row_count(&pool, "indexed_transact_commitments").await?, 1);
    assert_eq!(row_count(&pool, "indexed_nullifiers").await?, 1);
    assert_eq!(row_count(&pool, "indexed_public_transactions").await?, 1);
    assert_eq!(row_count(&pool, "chain_tips").await?, 0);
    assert_eq!(row_count(&pool, "published_snapshots").await?, 0);

    Ok(())
}

fn log_for<E: SolEvent>(event: &E, log_index: u64) -> Log {
    Log {
        inner: PrimitiveLog {
            address: Address::from([0xbb; 20]),
            data: event.encode_log_data(),
        },
        block_hash: Some(FixedBytes::from([0xaa; 32])),
        block_number: Some(100),
        transaction_hash: Some(FixedBytes::from([0xcc; 32])),
        log_index: Some(log_index),
        ..Log::default()
    }
}

const fn commitment_ciphertext() -> CommitmentCiphertext {
    CommitmentCiphertext {
        ciphertext: [FixedBytes::ZERO; 4],
        blindedSenderViewingKey: FixedBytes::ZERO,
        blindedReceiverViewingKey: FixedBytes::ZERO,
        annotationData: Bytes::new(),
        memo: Bytes::new(),
    }
}

fn is_docker_unavailable(error: &impl std::fmt::Debug) -> bool {
    let message = format!("{error:?}");
    message.contains("SocketNotFoundError") || message.contains("Connection refused")
}

async fn row_count(pool: &sqlx::PgPool, table: &str) -> Result<i64, sqlx::Error> {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    sqlx::query_scalar(&sql).fetch_one(pool).await
}
