use alloy::primitives::{Address, FixedBytes, U256, Uint};
use alloy::sol_types::SolValue;
use broadcaster_core::contracts::railgun::{
    CommitmentPreimage, LegacyCommitmentPreimage, ShieldCiphertext, TokenData,
};
use railgun_indexer_core::amount_statistics::{
    AmountStatisticsDerivationError, AmountStatisticsRecords, ShieldRecord, UnshieldRecord,
    read_amount_statistics_records, read_amount_statistics_records_at,
};
use railgun_indexer_core::audit::ChainCanonicalityCoordinator;
use railgun_indexer_core::chain_logs::{
    IndexedLegacyGeneratedCommitment, IndexedLogBatch, IndexedLogSource, IndexedPublicTransaction,
    IndexedShieldCommitment,
};
use railgun_indexer_core::manifest::{AmountStatisticsCoveredBlock, ChainScope, ChainType};
use railgun_indexer_core::store::{IndexedDatasetKind, Store, run_migrations};
use sqlx::postgres::PgPoolOptions;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ContainerAsync;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CHAIN_ID: u64 = 1;
const RAILGUN: Address = Address::repeat_byte(0xbb);
const USDC: Address = Address::repeat_byte(0x11);
const NOTE: u64 = 997_500_000;
const SCOPE: ChainScope = ChainScope {
    chain_type: ChainType::Evm,
    chain_id: CHAIN_ID,
    railgun_contract: RAILGUN,
};

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn legacy_deposits_count_alongside_current_shields() -> TestResult {
    let (_node, store) = migrated_store().await?;
    let batch = IndexedLogBatch {
        shield_commitments: vec![shield_at(90, 1, 0)],
        legacy_generated_commitments: vec![legacy_deposit_at(10, 0, 0)],
        ..Default::default()
    };
    seed(&store, &batch, &[(100, 0x64), (100, 0x64)]).await?;

    let mut records = read_records(&store).await?;

    records.shields.sort_by_key(|shield| shield.tree);
    assert_eq!(
        records.shields,
        vec![counted_shield(0, 10), counted_shield(1, 90)]
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn covered_block_is_the_lower_indexed_height() -> TestResult {
    let (_node, store) = migrated_store().await?;
    let batch = IndexedLogBatch {
        shield_commitments: vec![shield_at(101, 1, 0), shield_at(102, 1, 1)],
        public_transactions: vec![unshield_at(101, 0), unshield_at(102, 1)],
        ..Default::default()
    };
    // Shields are indexed through 102, unshields through 101.
    seed(&store, &batch, &[(102, 0x66), (101, 0x65)]).await?;
    // Rows above the covered block are not counted, so their gaps do not matter.
    sqlx::query(
        "UPDATE indexed_shield_commitments SET block_timestamp = NULL WHERE block_number = 102",
    )
    .execute(store.pool())
    .await?;

    let records = read_records(&store).await?;

    assert_eq!(records.covered_block_number, 101);
    assert_eq!(records.covered_block_hash, FixedBytes::repeat_byte(0x65));
    assert_eq!(records.shields, vec![counted_shield(1, 101)]);
    assert_eq!(
        records.unshields,
        vec![UnshieldRecord {
            token: USDC,
            value: U256::from(1_000_000_000_u64),
            timestamp: timestamp_at(101),
        }]
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn counted_shield_without_timestamp_fails_the_snapshot() -> TestResult {
    let (_node, store) = migrated_store().await?;
    let batch = IndexedLogBatch {
        shield_commitments: vec![shield_at(100, 1, 0)],
        ..Default::default()
    };
    seed(&store, &batch, &[(100, 0x64), (100, 0x64)]).await?;
    sqlx::query("UPDATE indexed_shield_commitments SET block_timestamp = NULL")
        .execute(store.pool())
        .await?;

    let result = read_records(&store).await;

    assert!(
        matches!(
            result,
            Err(AmountStatisticsDerivationError::MissingShieldTimestamp {
                chain_id: CHAIN_ID,
                block_number: 100,
            })
        ),
        "unexpected result: {result:?}"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn recomputation_checks_the_covered_block_against_this_database() -> TestResult {
    let (_node, store) = migrated_store().await?;
    seed_shields_in_blocks_100_and_101(&store).await?;

    let (records, hash_checked) = read_records_at(&store, 100, 0xaa).await?;
    assert!(hash_checked);
    assert_eq!(records.shields, vec![counted_shield(1, 100)]);

    // Block 101 has no indexed header, so it is read by number with the hash unchecked.
    let (records, hash_checked) = read_records_at(&store, 101, 0xbb).await?;
    assert!(!hash_checked);
    assert_eq!(records.shields.len(), 2);

    let reorged = read_records_at(&store, 100, 0xcc).await;
    assert!(
        matches!(
            reorged,
            Err(AmountStatisticsDerivationError::CoveredBlockHashMismatch {
                block_number: 100,
                ..
            })
        ),
        "unexpected result: {reorged:?}"
    );

    rewind_to_block_100(&store).await?;
    // The publication path covers the rewound height and leaves the block 101 shield out.
    let records = read_records(&store).await?;
    assert_eq!(records.covered_block_number, 100);
    assert_eq!(records.covered_block_hash, FixedBytes::repeat_byte(0xaa));
    assert_eq!(records.shields, vec![counted_shield(1, 100)]);

    let rewound = read_records_at(&store, 101, 0xbb).await;
    assert!(
        matches!(
            rewound,
            Err(AmountStatisticsDerivationError::CoveredBlockNotIndexed {
                block_number: 101,
                indexed_through: 100,
                ..
            })
        ),
        "unexpected result: {rewound:?}"
    );
    Ok(())
}

/// Indexes one shield in each of blocks 100 and 101, with both datasets through block 101 (hash
/// `0xbb..`) and an indexed header only at block 100 (hash `0xaa..`).
async fn seed_shields_in_blocks_100_and_101(
    store: &Store,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut tx = store.begin().await?;
    Store::record_indexed_block_header(&mut tx, 0, CHAIN_ID, 100, &[0xaa; 32], &[0x99; 32]).await?;
    tx.commit().await?;
    let batch = IndexedLogBatch {
        shield_commitments: vec![shield_at(100, 1, 0), shield_at(101, 1, 1)],
        ..Default::default()
    };
    seed(store, &batch, &[(101, 0xbb), (101, 0xbb)]).await
}

async fn rewind_to_block_100(store: &Store) -> Result<(), Box<dyn std::error::Error>> {
    let mut tx = store.begin().await?;
    Store::rewind_chain_indexing_to_replay_block(&mut tx, 0, CHAIN_ID, RAILGUN, 101).await?;
    tx.commit().await?;
    Ok(())
}

async fn migrated_store() -> Result<(ContainerAsync<Postgres>, Store), Box<dyn std::error::Error>> {
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
    Ok((node, Store::new(pool)))
}

/// Persists `batch` and records the wallet scan and public TXID heights as
/// `(block, hash byte)` pairs, in that order.
async fn seed(
    store: &Store,
    batch: &IndexedLogBatch,
    heights: &[(u64, u8); 2],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut tx = store.begin().await?;
    Store::persist_indexed_log_batch(&mut tx, 0, CHAIN_ID, RAILGUN, batch).await?;
    let kinds = [
        IndexedDatasetKind::WalletScan,
        IndexedDatasetKind::PublicTxid,
    ];
    for (dataset_kind, &(block, hash)) in kinds.into_iter().zip(heights) {
        Store::record_chain_indexing_progress(
            &mut tx,
            0,
            CHAIN_ID,
            RAILGUN,
            dataset_kind,
            block,
            &[hash; 32],
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

async fn read_records(
    store: &Store,
) -> Result<AmountStatisticsRecords, AmountStatisticsDerivationError> {
    let lease = ChainCanonicalityCoordinator::default()
        .publication_lease()
        .await;
    read_amount_statistics_records(store.pool(), &SCOPE, &lease).await
}

async fn read_records_at(
    store: &Store,
    block_number: u64,
    hash: u8,
) -> Result<(AmountStatisticsRecords, bool), AmountStatisticsDerivationError> {
    let covered_block = AmountStatisticsCoveredBlock {
        number: block_number,
        hash: FixedBytes::repeat_byte(hash),
        timestamp: timestamp_at(block_number),
    };
    read_amount_statistics_records_at(store.pool(), &SCOPE, &covered_block).await
}

const fn timestamp_at(block_number: u64) -> u64 {
    1_700_000_000 + block_number
}

fn counted_shield(tree: u32, block_number: u64) -> ShieldRecord {
    ShieldRecord {
        token: USDC,
        value: U256::from(NOTE),
        tree,
        timestamp: timestamp_at(block_number),
    }
}

const fn source_at(block_number: u64, transaction_byte: u8) -> IndexedLogSource {
    IndexedLogSource {
        block_number,
        block_timestamp: Some(timestamp_at(block_number)),
        block_hash: FixedBytes::repeat_byte(0xaa),
        transaction_hash: FixedBytes::repeat_byte(transaction_byte),
        log_index: 0,
    }
}

const fn usdc() -> TokenData {
    TokenData {
        tokenType: 0,
        tokenAddress: USDC,
        tokenSubID: U256::ZERO,
    }
}

fn shield_at(block_number: u64, tree_number: u32, tree_position: u64) -> IndexedShieldCommitment {
    IndexedShieldCommitment {
        tree_number,
        tree_position,
        preimage: CommitmentPreimage {
            npk: FixedBytes::repeat_byte(0x01),
            token: usdc(),
            value: Uint::<120, 2>::from(NOTE),
        },
        shield_ciphertext: ShieldCiphertext {
            encryptedBundle: [FixedBytes::repeat_byte(0x02); 3],
            shieldKey: FixedBytes::repeat_byte(0x03),
        },
        source: source_at(block_number, 0x10 + tree_position as u8),
    }
}

fn legacy_deposit_at(
    block_number: u64,
    tree_number: u32,
    tree_position: u64,
) -> IndexedLegacyGeneratedCommitment {
    IndexedLegacyGeneratedCommitment {
        tree_number,
        tree_position,
        preimage: LegacyCommitmentPreimage {
            npk: U256::from(1_u64),
            token: usdc(),
            value: Uint::<120, 2>::from(NOTE),
        },
        encrypted_random: [U256::from(2_u64), U256::from(3_u64)],
        source: source_at(block_number, 0x20 + tree_position as u8),
    }
}

fn unshield_at(block_number: u64, railgun_transaction_index: u64) -> IndexedPublicTransaction {
    let preimage = CommitmentPreimage {
        npk: FixedBytes::repeat_byte(0x04),
        token: usdc(),
        value: Uint::<120, 2>::from(1_000_000_000_u64),
    };
    IndexedPublicTransaction {
        source: source_at(block_number, 0x30),
        first_log_index: 0,
        last_log_index: 0,
        railgun_transaction_index,
        id: format!("0x{block_number:x}:{railgun_transaction_index}"),
        block_timestamp: timestamp_at(block_number),
        nullifiers: vec![FixedBytes::repeat_byte(0x31)],
        commitments: vec![FixedBytes::repeat_byte(0x33)],
        bound_params_hash: FixedBytes::repeat_byte(0x32),
        has_unshield: true,
        unshield_preimage: Some(preimage.abi_encode()),
        utxo_tree_in: 1,
        utxo_tree_out: 1,
        utxo_batch_start_position_out: 0,
        railgun_txid: U256::from(railgun_transaction_index),
    }
}
