use crate::chain_logs::{IndexedLogBatch, IndexedLogSource};
use crate::snapshot::SnapshotKind;
use alloy::primitives::Address;
use alloy::sol_types::SolValue;
use alloy_primitives::{FixedBytes, U256, hex};
use broadcaster_core::transact::MERKLE_ZERO_VALUE;
use broadcaster_core::tree::TREE_LEAF_COUNT;
use poi::poi::{PoiEventType, SignedBlockedShield, SignedPoiEvent};
use sqlx::{PgPool, Postgres, Transaction};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::info;

const IPNS_SEQUENCE_STATE_KEY: &str = "ipns_last_sequence";
const CHAIN_INDEXED_IPNS_SEQUENCE_STATE_KEY: &str = "chain_indexed_ipns_last_sequence";
const CURRENT_SCHEMA_VERSION: i32 = 11;

#[derive(Debug, Clone)]
pub struct Store {
    pool: PgPool,
}

impl Store {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn begin(&self) -> Result<Transaction<'_, Postgres>, StoreError> {
        self.pool.begin().await.map_err(StoreError::Sqlx)
    }

    pub async fn last_event_index(
        &self,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        upstream_url: &str,
    ) -> Result<Option<u64>, StoreError> {
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let index = sqlx::query_scalar::<_, i64>(
            r"
            SELECT last_event_index
            FROM chain_tips
            WHERE list_key = $1 AND chain_id = $2 AND upstream_url = $3
            ",
        )
        .bind(list_key.as_slice())
        .bind(chain_id)
        .bind(upstream_url)
        .fetch_optional(&self.pool)
        .await?;

        index
            .map(|index| i64_to_u64(index, "last_event_index"))
            .transpose()
    }

    pub async fn chain_tip(
        &self,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        upstream_url: &str,
    ) -> Result<Option<StoredChainTip>, StoreError> {
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let row = sqlx::query_as::<_, (i64, Option<Vec<u8>>)>(
            r"
            SELECT last_event_index, last_tip_merkleroot
            FROM chain_tips
            WHERE list_key = $1 AND chain_id = $2 AND upstream_url = $3
            ",
        )
        .bind(list_key.as_slice())
        .bind(chain_id)
        .bind(upstream_url)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|(last_event_index, last_tip_merkleroot)| {
            Ok(StoredChainTip {
                last_event_index: i64_to_u64(last_event_index, "last_event_index")?,
                last_tip_merkleroot: last_tip_merkleroot
                    .map(|bytes| exact_array("last_tip_merkleroot", &bytes))
                    .transpose()?,
            })
        })
        .transpose()
    }

    pub async fn active_publications(
        &self,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        upstream_url: &str,
    ) -> Result<Vec<StoredPublication>, StoreError> {
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let rows =
            sqlx::query_as::<_, (String, i64, i64, String, i64, Vec<u8>, Option<Vec<u8>>, i64)>(
                r"
            SELECT
                kind,
                start_index,
                end_index,
                cid,
                byte_size,
                content_hash,
                tip_merkleroot,
                EXTRACT(EPOCH FROM published_at)::BIGINT AS published_at_unix_seconds
            FROM published_snapshots
            WHERE list_key = $1
                AND chain_id = $2
                AND upstream_url = $3
                AND superseded_at IS NULL
                AND content_hash IS NOT NULL
            ORDER BY
                CASE kind WHEN 'base' THEN 0 ELSE 1 END,
                start_index ASC,
                id ASC
            ",
            )
            .bind(list_key.as_slice())
            .bind(chain_id)
            .bind(upstream_url)
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter()
            .map(
                |(
                    kind,
                    start_index,
                    end_index,
                    cid,
                    byte_size,
                    content_hash,
                    tip_merkleroot,
                    published_at,
                )| {
                    Ok(StoredPublication {
                        kind: parse_snapshot_kind(&kind)?,
                        start_index: i64_to_u64(start_index, "start_index")?,
                        end_index: i64_to_u64(end_index, "end_index")?,
                        cid,
                        byte_size: i64_to_u64(byte_size, "byte_size")?,
                        content_hash: exact_array("snapshot_content_hash", &content_hash)?,
                        tip_merkleroot: tip_merkleroot
                            .map(|bytes| exact_array("tip_merkleroot", &bytes))
                            .transpose()?,
                        published_at: i64_to_system_time(published_at, "published_at")?,
                    })
                },
            )
            .collect()
    }

    pub async fn active_blocked_shields_publication(
        &self,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        upstream_url: &str,
    ) -> Result<Option<StoredBlockedShieldsPublication>, StoreError> {
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let row = sqlx::query_as::<_, (String, i64, Vec<u8>, i64)>(
            r"
            SELECT
                cid,
                byte_size,
                content_hash,
                EXTRACT(EPOCH FROM published_at)::BIGINT AS published_at_unix_seconds
            FROM published_blocked_shields
            WHERE list_key = $1
                AND chain_id = $2
                AND upstream_url = $3
                AND superseded_at IS NULL
            ORDER BY id DESC
            LIMIT 1
            ",
        )
        .bind(list_key.as_slice())
        .bind(chain_id)
        .bind(upstream_url)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|(cid, byte_size, content_hash, published_at)| {
            Ok(StoredBlockedShieldsPublication {
                cid,
                byte_size: i64_to_u64(byte_size, "byte_size")?,
                content_hash: exact_array("blocked_shields_content_hash", &content_hash)?,
                published_at: i64_to_system_time(published_at, "published_at")?,
            })
        })
        .transpose()
    }

    pub async fn insert_events(
        tx: &mut Transaction<'_, Postgres>,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        events: &[SignedPoiEvent],
    ) -> Result<(), StoreError> {
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        for event in events {
            let event_index = u64_to_i64(event.index, "event_index")?;
            let blinded_commitment = event.blinded_commitment;
            let signature = decode_fixed_hex::<SIGNATURE_BYTES>("signature", &event.signature)?;

            sqlx::query(
                r"
                INSERT INTO poi_events (
                    list_key, chain_id, event_index, blinded_commitment, signature, event_type
                )
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (list_key, chain_id, event_index) DO NOTHING
                ",
            )
            .bind(list_key.as_slice())
            .bind(chain_id)
            .bind(event_index)
            .bind(blinded_commitment.as_slice())
            .bind(signature.as_slice())
            .bind(event_type_discriminant(event.event_type))
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }

    pub async fn insert_event_leaves(
        tx: &mut Transaction<'_, Postgres>,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        start_index: u64,
        leaves: &[U256],
    ) -> Result<(), StoreError> {
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let signature = [0_u8; SIGNATURE_BYTES];
        for (offset, leaf) in leaves.iter().enumerate() {
            let event_index = start_index.checked_add(offset as u64).ok_or_else(|| {
                StoreError::IntegerOutOfRange {
                    field: "event_index",
                    value: format!("{start_index}+{offset}"),
                }
            })?;
            let event_index = u64_to_i64(event_index, "event_index")?;
            let blinded_commitment = leaf.to_be_bytes::<BLINDED_COMMITMENT_BYTES>();

            sqlx::query(
                r"
                INSERT INTO poi_events (
                    list_key, chain_id, event_index, blinded_commitment, signature, event_type
                )
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (list_key, chain_id, event_index) DO UPDATE SET
                    blinded_commitment = EXCLUDED.blinded_commitment
                ",
            )
            .bind(list_key.as_slice())
            .bind(chain_id)
            .bind(event_index)
            .bind(blinded_commitment.as_slice())
            .bind(signature.as_slice())
            .bind(event_type_discriminant(PoiEventType::Shield))
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }

    pub async fn advance_chain_tip(
        tx: &mut Transaction<'_, Postgres>,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        upstream_url: &str,
        last_event_index: u64,
        last_tip_merkleroot: Option<&str>,
    ) -> Result<(), StoreError> {
        let chain_id_u64 = chain_id;
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let proposed_event_index = last_event_index;
        let last_event_index = u64_to_i64(last_event_index, "last_event_index")?;
        let last_tip_merkleroot = last_tip_merkleroot
            .map(|root| decode_fixed_hex::<MERKLEROOT_BYTES>("last_tip_merkleroot", root))
            .transpose()?;

        let row = sqlx::query_scalar::<_, i64>(
            r"
            INSERT INTO chain_tips (
                list_key, chain_id, upstream_url, last_event_index, last_tip_merkleroot
            )
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (list_key, chain_id, upstream_url) DO UPDATE SET
                last_event_index = EXCLUDED.last_event_index,
                last_tip_merkleroot = EXCLUDED.last_tip_merkleroot,
                updated_at = now()
            WHERE EXCLUDED.last_event_index >= chain_tips.last_event_index
            RETURNING last_event_index
            ",
        )
        .bind(list_key.as_slice())
        .bind(chain_id)
        .bind(upstream_url)
        .bind(last_event_index)
        .bind(last_tip_merkleroot.as_ref().map(<[u8; 32]>::as_slice))
        .fetch_optional(&mut **tx)
        .await?;

        if row.is_none() {
            return Err(StoreError::ChainTipRegression {
                list_key: hex::encode_prefixed(list_key.as_slice()),
                chain_id: chain_id_u64,
                upstream_url: upstream_url.to_string(),
                proposed: proposed_event_index,
            });
        }

        Ok(())
    }

    pub async fn upsert_blocked_shields(
        tx: &mut Transaction<'_, Postgres>,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        records: &[SignedBlockedShield],
    ) -> Result<(), StoreError> {
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        for record in records {
            let commitment_hash = decode_fixed_hex::<COMMITMENT_HASH_BYTES>(
                "commitment_hash",
                &record.commitment_hash,
            )?;
            let blinded_commitment = decode_fixed_hex::<BLINDED_COMMITMENT_BYTES>(
                "blinded_commitment",
                &record.blinded_commitment,
            )?;
            let signature = decode_fixed_hex::<SIGNATURE_BYTES>("signature", &record.signature)?;

            sqlx::query(
                r"
                INSERT INTO blocked_shields (
                    list_key, chain_id, blinded_commitment, commitment_hash, signature, block_reason
                )
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (list_key, chain_id, blinded_commitment) DO UPDATE SET
                    commitment_hash = EXCLUDED.commitment_hash,
                    signature = EXCLUDED.signature,
                    block_reason = EXCLUDED.block_reason,
                    fetched_at = now()
                ",
            )
            .bind(list_key.as_slice())
            .bind(chain_id)
            .bind(blinded_commitment.as_slice())
            .bind(commitment_hash.as_slice())
            .bind(signature.as_slice())
            .bind(&record.block_reason)
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }

    pub async fn replace_blocked_shields(
        tx: &mut Transaction<'_, Postgres>,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        records: &[SignedBlockedShield],
    ) -> Result<(), StoreError> {
        let chain_id_i64 = u64_to_i64(chain_id, "chain_id")?;
        sqlx::query(
            r"
            DELETE FROM blocked_shields
            WHERE list_key = $1 AND chain_id = $2
            ",
        )
        .bind(list_key.as_slice())
        .bind(chain_id_i64)
        .execute(&mut **tx)
        .await?;

        Self::upsert_blocked_shields(tx, list_key, chain_id, records).await
    }

    pub async fn page_event_range(
        &self,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        start_index: u64,
        end_index: u64,
    ) -> Result<Vec<StoredEvent>, StoreError> {
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let start_index = u64_to_i64(start_index, "start_index")?;
        let end_index = u64_to_i64(end_index, "end_index")?;
        let rows = sqlx::query_as::<_, (i64, Vec<u8>, Vec<u8>, i16)>(
            r"
            SELECT event_index, blinded_commitment, signature, event_type
            FROM poi_events
            WHERE list_key = $1
                AND chain_id = $2
                AND event_index BETWEEN $3 AND $4
            ORDER BY event_index ASC
            ",
        )
        .bind(list_key.as_slice())
        .bind(chain_id)
        .bind(start_index)
        .bind(end_index)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|(event_index, blinded_commitment, signature, event_type)| {
                Ok(StoredEvent {
                    event_index: i64_to_u64(event_index, "event_index")?,
                    blinded_commitment: exact_array("blinded_commitment", &blinded_commitment)?,
                    signature: exact_array("signature", &signature)?,
                    event_type: event_type_from_discriminant(event_type)?,
                })
            })
            .collect()
    }

    pub async fn all_blocked_shields(
        &self,
        list_key: &FixedBytes<32>,
        chain_id: u64,
    ) -> Result<Vec<StoredBlockedShield>, StoreError> {
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let rows = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, Option<String>, Vec<u8>)>(
            r"
            SELECT commitment_hash, blinded_commitment, block_reason, signature
            FROM blocked_shields
            WHERE list_key = $1 AND chain_id = $2
            ORDER BY blinded_commitment ASC
            ",
        )
        .bind(list_key.as_slice())
        .bind(chain_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(
                |(commitment_hash, blinded_commitment, block_reason, signature)| {
                    Ok(StoredBlockedShield {
                        commitment_hash: exact_array("commitment_hash", &commitment_hash)?,
                        blinded_commitment: exact_array("blinded_commitment", &blinded_commitment)?,
                        block_reason,
                        signature: exact_array("signature", &signature)?,
                    })
                },
            )
            .collect()
    }

    pub async fn last_ipns_sequence(&self) -> Result<Option<u64>, StoreError> {
        self.last_state_sequence(IPNS_SEQUENCE_STATE_KEY, "ipns_last_sequence")
            .await
    }

    pub async fn record_ipns_sequence(&self, sequence: u64) -> Result<(), StoreError> {
        self.record_state_sequence(IPNS_SEQUENCE_STATE_KEY, "ipns_last_sequence", sequence)
            .await
    }

    pub async fn last_chain_indexed_ipns_sequence(&self) -> Result<Option<u64>, StoreError> {
        self.last_state_sequence(
            CHAIN_INDEXED_IPNS_SEQUENCE_STATE_KEY,
            "chain_indexed_ipns_last_sequence",
        )
        .await
    }

    pub async fn record_chain_indexed_ipns_sequence(
        &self,
        sequence: u64,
    ) -> Result<(), StoreError> {
        self.record_state_sequence(
            CHAIN_INDEXED_IPNS_SEQUENCE_STATE_KEY,
            "chain_indexed_ipns_last_sequence",
            sequence,
        )
        .await
    }

    async fn last_state_sequence(
        &self,
        key: &'static str,
        field: &'static str,
    ) -> Result<Option<u64>, StoreError> {
        let value = sqlx::query_scalar::<_, i64>("SELECT value FROM indexer_state WHERE key = $1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;

        value.map(|value| i64_to_u64(value, field)).transpose()
    }

    async fn record_state_sequence(
        &self,
        key: &'static str,
        field: &'static str,
        sequence: u64,
    ) -> Result<(), StoreError> {
        let sequence = u64_to_i64(sequence, field)?;
        sqlx::query(
            r"
            INSERT INTO indexer_state (key, value)
            VALUES ($1, $2)
            ON CONFLICT (key) DO UPDATE SET
                value = GREATEST(indexer_state.value, EXCLUDED.value),
                updated_at = now()
            ",
        )
        .bind(key)
        .bind(sequence)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn chain_indexing_progress(
        &self,
        chain_type: u8,
        chain_id: u64,
        railgun_contract: Address,
        dataset_kind: IndexedDatasetKind,
    ) -> Result<Option<StoredChainIndexingProgress>, StoreError> {
        let chain_type = i16::from(chain_type);
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let railgun_contract = railgun_contract.to_string();
        let row = sqlx::query_as::<_, (i64, Vec<u8>)>(
            r"
            SELECT indexed_through_block, indexed_through_block_hash
            FROM chain_indexing_progress
            WHERE chain_type = $1
                AND chain_id = $2
                AND railgun_contract = $3
                AND dataset_kind = $4
            ",
        )
        .bind(chain_type)
        .bind(chain_id)
        .bind(railgun_contract)
        .bind(dataset_kind.as_str())
        .fetch_optional(&self.pool)
        .await?;

        row.map(|(indexed_through_block, indexed_through_block_hash)| {
            Ok(StoredChainIndexingProgress {
                indexed_through_block: i64_to_u64(indexed_through_block, "indexed_through_block")?,
                indexed_through_block_hash: exact_array(
                    "indexed_through_block_hash",
                    &indexed_through_block_hash,
                )?,
            })
        })
        .transpose()
    }

    pub async fn chain_indexing_resume_block(
        &self,
        chain_type: u8,
        chain_id: u64,
        railgun_contract: Address,
        dataset_kind: IndexedDatasetKind,
        configured_start_block: u64,
    ) -> Result<u64, StoreError> {
        Ok(self
            .chain_indexing_progress(chain_type, chain_id, railgun_contract, dataset_kind)
            .await?
            .map_or(configured_start_block, |progress| {
                progress.indexed_through_block.saturating_add(1)
            }))
    }

    pub async fn public_txid_rows(
        &self,
        chain_type: u8,
        chain_id: u64,
        railgun_contract: Address,
        offset: u64,
        limit: u64,
    ) -> Result<Vec<StoredPublicTxidRow>, StoreError> {
        self.public_txid_rows_with_max_block(
            chain_type,
            chain_id,
            railgun_contract,
            offset,
            limit,
            None,
        )
        .await
    }

    pub async fn public_txid_rows_through_block(
        &self,
        chain_type: u8,
        chain_id: u64,
        railgun_contract: Address,
        offset: u64,
        limit: u64,
        max_block: u64,
    ) -> Result<Vec<StoredPublicTxidRow>, StoreError> {
        self.public_txid_rows_with_max_block(
            chain_type,
            chain_id,
            railgun_contract,
            offset,
            limit,
            Some(max_block),
        )
        .await
    }

    async fn public_txid_rows_with_max_block(
        &self,
        chain_type: u8,
        chain_id: u64,
        railgun_contract: Address,
        offset: u64,
        limit: u64,
        max_block: Option<u64>,
    ) -> Result<Vec<StoredPublicTxidRow>, StoreError> {
        let chain_type = i16::from(chain_type);
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let railgun_contract = railgun_contract.to_string();
        let offset = u64_to_i64(offset, "offset")?;
        let limit = u64_to_i64(limit, "limit")?;
        let max_block = max_block
            .map(|block| u64_to_i64(block, "max_block"))
            .transpose()?;
        let rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                i64,
                i64,
                Vec<u8>,
                Vec<u8>,
                i64,
                i64,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                bool,
                i64,
                i64,
                i64,
            ),
        >(
            r"
            WITH ordered AS (
                SELECT
                    ROW_NUMBER() OVER (ORDER BY block_number, first_log_index, transaction_hash, railgun_transaction_index) - 1 AS txid_index,
                    row_id,
                    block_number,
                    block_timestamp,
                    block_hash,
                    transaction_hash,
                    first_log_index,
                    last_log_index,
                    merkle_root,
                    nullifiers,
                    commitments,
                    bound_params_hash,
                    has_unshield,
                    utxo_tree_in,
                    utxo_tree_out,
                    utxo_batch_start_position_out
                FROM indexed_public_txid_rows
                WHERE chain_type = $1
                    AND chain_id = $2
                    AND railgun_contract = $3
                    AND ($6::BIGINT IS NULL OR block_number <= $6)
            )
            SELECT
                txid_index,
                row_id,
                block_number,
                block_timestamp,
                block_hash,
                transaction_hash,
                first_log_index,
                last_log_index,
                merkle_root,
                nullifiers,
                commitments,
                bound_params_hash,
                has_unshield,
                utxo_tree_in,
                utxo_tree_out,
                utxo_batch_start_position_out
            FROM ordered
            WHERE txid_index >= $4
            ORDER BY txid_index
            LIMIT $5
            ",
        )
        .bind(chain_type)
        .bind(chain_id)
        .bind(railgun_contract)
        .bind(offset)
        .bind(limit)
        .bind(max_block)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(
                |(
                    txid_index,
                    id,
                    block_number,
                    block_timestamp,
                    block_hash,
                    transaction_hash,
                    first_log_index,
                    last_log_index,
                    merkle_root,
                    nullifiers,
                    commitments,
                    bound_params_hash,
                    has_unshield,
                    utxo_tree_in,
                    utxo_tree_out,
                    utxo_batch_start_position_out,
                )| {
                    Ok(StoredPublicTxidRow {
                        txid_index: i64_to_u64(txid_index, "txid_index")?,
                        id,
                        block_number: i64_to_u64(block_number, "block_number")?,
                        block_timestamp: i64_to_u64(block_timestamp, "block_timestamp")?,
                        block_hash: exact_array("block_hash", &block_hash)?,
                        transaction_hash: exact_array("transaction_hash", &transaction_hash)?,
                        first_log_index: i64_to_u64(first_log_index, "first_log_index")?,
                        last_log_index: i64_to_u64(last_log_index, "last_log_index")?,
                        merkle_root: exact_array("merkle_root", &merkle_root)?,
                        nullifiers: fixed_bytes_vec("nullifiers", &nullifiers)?,
                        commitments: fixed_bytes_vec("commitments", &commitments)?,
                        bound_params_hash: exact_array("bound_params_hash", &bound_params_hash)?,
                        has_unshield,
                        utxo_tree_in: i64_to_u64(utxo_tree_in, "utxo_tree_in")?,
                        utxo_tree_out: i64_to_u64(utxo_tree_out, "utxo_tree_out")?,
                        utxo_batch_start_position_out: i64_to_u64(
                            utxo_batch_start_position_out,
                            "utxo_batch_start_position_out",
                        )?,
                    })
                },
            )
            .collect()
    }

    pub async fn wallet_scan_rows(
        &self,
        chain_type: u8,
        chain_id: u64,
        railgun_contract: Address,
        start_block: u64,
        end_block: u64,
    ) -> Result<StoredWalletScanRows, StoreError> {
        let chain_type = i16::from(chain_type);
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let railgun_contract = railgun_contract.to_string();
        let start_block = u64_to_i64(start_block, "start_block")?;
        let end_block = u64_to_i64(end_block, "end_block")?;

        let transact_commitments = sqlx::query_as::<
            _,
            (
                i64,
                Option<i64>,
                Vec<u8>,
                Vec<u8>,
                i64,
                i64,
                i64,
                Vec<u8>,
                Vec<u8>,
            ),
        >(
            r"
            SELECT
                block_number,
                block_timestamp,
                block_hash,
                transaction_hash,
                log_index,
                tree_number,
                tree_position,
                commitment_hash,
                ciphertext
            FROM indexed_transact_commitments
            WHERE chain_type = $1
                AND chain_id = $2
                AND railgun_contract = $3
                AND ciphertext IS NOT NULL
                AND block_number BETWEEN $4 AND $5
            ORDER BY block_number ASC, log_index ASC, tree_number ASC, tree_position ASC
            ",
        )
        .bind(chain_type)
        .bind(chain_id)
        .bind(&railgun_contract)
        .bind(start_block)
        .bind(end_block)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(
            |(
                block_number,
                block_timestamp,
                block_hash,
                transaction_hash,
                log_index,
                tree_number,
                tree_position,
                commitment_hash,
                ciphertext,
            )| {
                Ok(StoredTransactCommitmentRow {
                    source: indexed_source_row(
                        block_number,
                        block_timestamp,
                        &block_hash,
                        &transaction_hash,
                        log_index,
                    )?,
                    tree_number: i64_to_u32(tree_number, "tree_number")?,
                    tree_position: i64_to_u64(tree_position, "tree_position")?,
                    commitment_hash: exact_array("commitment_hash", &commitment_hash)?,
                    ciphertext,
                })
            },
        )
        .collect::<Result<Vec<_>, StoreError>>()?;

        let shield_commitments = sqlx::query_as::<
            _,
            (
                i64,
                Option<i64>,
                Vec<u8>,
                Vec<u8>,
                i64,
                i64,
                i64,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
            ),
        >(
            r"
            SELECT
                block_number,
                block_timestamp,
                block_hash,
                transaction_hash,
                log_index,
                tree_number,
                tree_position,
                commitment_hash,
                preimage,
                shield_ciphertext
            FROM indexed_shield_commitments
            WHERE chain_type = $1
                AND chain_id = $2
                AND railgun_contract = $3
                AND block_number BETWEEN $4 AND $5
            ORDER BY block_number ASC, log_index ASC, tree_number ASC, tree_position ASC
            ",
        )
        .bind(chain_type)
        .bind(chain_id)
        .bind(&railgun_contract)
        .bind(start_block)
        .bind(end_block)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(
            |(
                block_number,
                block_timestamp,
                block_hash,
                transaction_hash,
                log_index,
                tree_number,
                tree_position,
                commitment_hash,
                preimage,
                shield_ciphertext,
            )| {
                Ok(StoredShieldCommitmentRow {
                    source: indexed_source_row(
                        block_number,
                        block_timestamp,
                        &block_hash,
                        &transaction_hash,
                        log_index,
                    )?,
                    tree_number: i64_to_u32(tree_number, "tree_number")?,
                    tree_position: i64_to_u64(tree_position, "tree_position")?,
                    commitment_hash: exact_array("commitment_hash", &commitment_hash)?,
                    preimage,
                    shield_ciphertext,
                })
            },
        )
        .collect::<Result<Vec<_>, StoreError>>()?;

        let nullifiers =
            sqlx::query_as::<_, (i64, Option<i64>, Vec<u8>, Vec<u8>, i64, i64, Vec<u8>)>(
                r"
            SELECT
                block_number,
                block_timestamp,
                block_hash,
                transaction_hash,
                log_index,
                tree_number,
                nullifier
            FROM indexed_nullifiers
            WHERE chain_type = $1
                AND chain_id = $2
                AND railgun_contract = $3
                AND block_number BETWEEN $4 AND $5
            ORDER BY block_number ASC, log_index ASC, tree_number ASC, nullifier ASC
            ",
            )
            .bind(chain_type)
            .bind(chain_id)
            .bind(&railgun_contract)
            .bind(start_block)
            .bind(end_block)
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(
                |(
                    block_number,
                    block_timestamp,
                    block_hash,
                    transaction_hash,
                    log_index,
                    tree_number,
                    nullifier,
                )| {
                    Ok(StoredNullifierRow {
                        source: indexed_source_row(
                            block_number,
                            block_timestamp,
                            &block_hash,
                            &transaction_hash,
                            log_index,
                        )?,
                        tree_number: i64_to_u32(tree_number, "tree_number")?,
                        nullifier: exact_array("nullifier", &nullifier)?,
                    })
                },
            )
            .collect::<Result<Vec<_>, StoreError>>()?;

        let legacy_encrypted_commitments = sqlx::query_as::<
            _,
            (
                i64,
                Option<i64>,
                Vec<u8>,
                Vec<u8>,
                i64,
                i64,
                i64,
                Vec<u8>,
                Vec<u8>,
            ),
        >(
            r"
            SELECT
                block_number,
                block_timestamp,
                block_hash,
                transaction_hash,
                log_index,
                tree_number,
                tree_position,
                commitment_hash,
                ciphertext
            FROM indexed_legacy_encrypted_commitments
            WHERE chain_type = $1
                AND chain_id = $2
                AND railgun_contract = $3
                AND block_number BETWEEN $4 AND $5
            ORDER BY block_number ASC, log_index ASC, tree_number ASC, tree_position ASC
            ",
        )
        .bind(chain_type)
        .bind(chain_id)
        .bind(&railgun_contract)
        .bind(start_block)
        .bind(end_block)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(
            |(
                block_number,
                block_timestamp,
                block_hash,
                transaction_hash,
                log_index,
                tree_number,
                tree_position,
                commitment_hash,
                ciphertext,
            )| {
                Ok(StoredLegacyEncryptedCommitmentRow {
                    source: indexed_source_row(
                        block_number,
                        block_timestamp,
                        &block_hash,
                        &transaction_hash,
                        log_index,
                    )?,
                    tree_number: i64_to_u32(tree_number, "tree_number")?,
                    tree_position: i64_to_u64(tree_position, "tree_position")?,
                    commitment_hash: exact_array("commitment_hash", &commitment_hash)?,
                    ciphertext,
                })
            },
        )
        .collect::<Result<Vec<_>, StoreError>>()?;

        let legacy_generated_commitments = sqlx::query_as::<
            _,
            (
                i64,
                Option<i64>,
                Vec<u8>,
                Vec<u8>,
                i64,
                i64,
                i64,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
            ),
        >(
            r"
            SELECT
                block_number,
                block_timestamp,
                block_hash,
                transaction_hash,
                log_index,
                tree_number,
                tree_position,
                commitment_hash,
                preimage,
                encrypted_random
            FROM indexed_legacy_generated_commitments
            WHERE chain_type = $1
                AND chain_id = $2
                AND railgun_contract = $3
                AND block_number BETWEEN $4 AND $5
            ORDER BY block_number ASC, log_index ASC, tree_number ASC, tree_position ASC
            ",
        )
        .bind(chain_type)
        .bind(chain_id)
        .bind(&railgun_contract)
        .bind(start_block)
        .bind(end_block)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(
            |(
                block_number,
                block_timestamp,
                block_hash,
                transaction_hash,
                log_index,
                tree_number,
                tree_position,
                commitment_hash,
                preimage,
                encrypted_random,
            )| {
                Ok(StoredLegacyGeneratedCommitmentRow {
                    source: indexed_source_row(
                        block_number,
                        block_timestamp,
                        &block_hash,
                        &transaction_hash,
                        log_index,
                    )?,
                    tree_number: i64_to_u32(tree_number, "tree_number")?,
                    tree_position: i64_to_u64(tree_position, "tree_position")?,
                    commitment_hash: exact_array("commitment_hash", &commitment_hash)?,
                    preimage,
                    encrypted_random: exact_array("encrypted_random", &encrypted_random)?,
                })
            },
        )
        .collect::<Result<Vec<_>, StoreError>>()?;

        Ok(StoredWalletScanRows {
            transact_commitments,
            shield_commitments,
            nullifiers,
            legacy_encrypted_commitments,
            legacy_generated_commitments,
        })
    }

    pub async fn wallet_scan_populated_block_ranges(
        &self,
        chain_type: u8,
        chain_id: u64,
        railgun_contract: Address,
        start_block: u64,
        end_block: u64,
        bucket_span: u64,
    ) -> Result<Vec<StoredBlockRange>, StoreError> {
        if start_block > end_block {
            return Ok(Vec::new());
        }
        if bucket_span == 0 {
            return Err(StoreError::IntegerOutOfRange {
                field: "bucket_span",
                value: bucket_span.to_string(),
            });
        }

        let chain_type = i16::from(chain_type);
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let railgun_contract = railgun_contract.to_string();
        let start_block = u64_to_i64(start_block, "start_block")?;
        let end_block = u64_to_i64(end_block, "end_block")?;
        let bucket_span = u64_to_i64(bucket_span, "bucket_span")?;

        let rows = sqlx::query_as::<_, (i64, i64)>(
            r"
            WITH wallet_scan_blocks AS (
                SELECT block_number
                FROM indexed_transact_commitments
                WHERE chain_type = $1
                    AND chain_id = $2
                    AND railgun_contract = $3
                    AND ciphertext IS NOT NULL
                    AND block_number BETWEEN $4 AND $5
                UNION ALL
                SELECT block_number
                FROM indexed_shield_commitments
                WHERE chain_type = $1
                    AND chain_id = $2
                    AND railgun_contract = $3
                    AND block_number BETWEEN $4 AND $5
                UNION ALL
                SELECT block_number
                FROM indexed_nullifiers
                WHERE chain_type = $1
                    AND chain_id = $2
                    AND railgun_contract = $3
                    AND block_number BETWEEN $4 AND $5
                UNION ALL
                SELECT block_number
                FROM indexed_legacy_encrypted_commitments
                WHERE chain_type = $1
                    AND chain_id = $2
                    AND railgun_contract = $3
                    AND block_number BETWEEN $4 AND $5
                UNION ALL
                SELECT block_number
                FROM indexed_legacy_generated_commitments
                WHERE chain_type = $1
                    AND chain_id = $2
                    AND railgun_contract = $3
                    AND block_number BETWEEN $4 AND $5
            )
            SELECT MIN(block_number), MAX(block_number)
            FROM wallet_scan_blocks
            GROUP BY (block_number - $4) / $6
            ORDER BY MIN(block_number) ASC
            ",
        )
        .bind(chain_type)
        .bind(chain_id)
        .bind(&railgun_contract)
        .bind(start_block)
        .bind(end_block)
        .bind(bucket_span)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|(start_block, end_block)| {
                Ok(StoredBlockRange {
                    start_block: i64_to_u64(start_block, "start_block")?,
                    end_block: i64_to_u64(end_block, "end_block")?,
                })
            })
            .collect()
    }

    pub async fn missing_wallet_scan_timestamp_blocks(
        &self,
        chain_type: u8,
        chain_id: u64,
        railgun_contract: Address,
        start_block: u64,
        end_block: u64,
        limit: u64,
    ) -> Result<Vec<StoredMissingWalletScanTimestampBlock>, StoreError> {
        if start_block > end_block {
            return Ok(Vec::new());
        }
        if limit == 0 {
            return Err(StoreError::IntegerOutOfRange {
                field: "limit",
                value: limit.to_string(),
            });
        }
        let rows = sqlx::query_as::<_, (i64, Vec<u8>, i64)>(
            r"
            WITH missing_sources AS (
                SELECT block_number, block_hash
                FROM indexed_transact_commitments
                WHERE chain_type = $1
                    AND chain_id = $2
                    AND railgun_contract = $3
                    AND ciphertext IS NOT NULL
                    AND block_timestamp IS NULL
                    AND block_number BETWEEN $4 AND $5
                UNION ALL
                SELECT block_number, block_hash
                FROM indexed_shield_commitments
                WHERE chain_type = $1
                    AND chain_id = $2
                    AND railgun_contract = $3
                    AND block_timestamp IS NULL
                    AND block_number BETWEEN $4 AND $5
                UNION ALL
                SELECT block_number, block_hash
                FROM indexed_nullifiers
                WHERE chain_type = $1
                    AND chain_id = $2
                    AND railgun_contract = $3
                    AND block_timestamp IS NULL
                    AND block_number BETWEEN $4 AND $5
                UNION ALL
                SELECT block_number, block_hash
                FROM indexed_legacy_encrypted_commitments
                WHERE chain_type = $1
                    AND chain_id = $2
                    AND railgun_contract = $3
                    AND block_timestamp IS NULL
                    AND block_number BETWEEN $4 AND $5
                UNION ALL
                SELECT block_number, block_hash
                FROM indexed_legacy_generated_commitments
                WHERE chain_type = $1
                    AND chain_id = $2
                    AND railgun_contract = $3
                    AND block_timestamp IS NULL
                    AND block_number BETWEEN $4 AND $5
            )
            SELECT block_number, block_hash, COUNT(*) AS missing_rows
            FROM missing_sources
            GROUP BY block_number, block_hash
            ORDER BY block_number ASC
            LIMIT $6
            ",
        )
        .bind(i16::from(chain_type))
        .bind(u64_to_i64(chain_id, "chain_id")?)
        .bind(railgun_contract.to_string())
        .bind(u64_to_i64(start_block, "start_block")?)
        .bind(u64_to_i64(end_block, "end_block")?)
        .bind(u64_to_i64(limit, "limit")?)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|(block_number, block_hash, missing_rows)| {
                Ok(StoredMissingWalletScanTimestampBlock {
                    block_number: i64_to_u64(block_number, "block_number")?,
                    block_hash: exact_array("block_hash", &block_hash)?,
                    missing_rows: i64_to_u64(missing_rows, "missing_rows")?,
                })
            })
            .collect()
    }

    pub async fn count_missing_wallet_scan_timestamps(
        &self,
        chain_type: u8,
        chain_id: u64,
        railgun_contract: Address,
        start_block: u64,
        end_block: u64,
    ) -> Result<u64, StoreError> {
        if start_block > end_block {
            return Ok(0);
        }
        let count = sqlx::query_scalar::<_, i64>(
            r"
            WITH missing_sources AS (
                SELECT 1
                FROM indexed_transact_commitments
                WHERE chain_type = $1
                    AND chain_id = $2
                    AND railgun_contract = $3
                    AND ciphertext IS NOT NULL
                    AND block_timestamp IS NULL
                    AND block_number BETWEEN $4 AND $5
                UNION ALL
                SELECT 1
                FROM indexed_shield_commitments
                WHERE chain_type = $1
                    AND chain_id = $2
                    AND railgun_contract = $3
                    AND block_timestamp IS NULL
                    AND block_number BETWEEN $4 AND $5
                UNION ALL
                SELECT 1
                FROM indexed_nullifiers
                WHERE chain_type = $1
                    AND chain_id = $2
                    AND railgun_contract = $3
                    AND block_timestamp IS NULL
                    AND block_number BETWEEN $4 AND $5
                UNION ALL
                SELECT 1
                FROM indexed_legacy_encrypted_commitments
                WHERE chain_type = $1
                    AND chain_id = $2
                    AND railgun_contract = $3
                    AND block_timestamp IS NULL
                    AND block_number BETWEEN $4 AND $5
                UNION ALL
                SELECT 1
                FROM indexed_legacy_generated_commitments
                WHERE chain_type = $1
                    AND chain_id = $2
                    AND railgun_contract = $3
                    AND block_timestamp IS NULL
                    AND block_number BETWEEN $4 AND $5
            )
            SELECT COUNT(*) FROM missing_sources
            ",
        )
        .bind(i16::from(chain_type))
        .bind(u64_to_i64(chain_id, "chain_id")?)
        .bind(railgun_contract.to_string())
        .bind(u64_to_i64(start_block, "start_block")?)
        .bind(u64_to_i64(end_block, "end_block")?)
        .fetch_one(&self.pool)
        .await?;
        i64_to_u64(count, "missing_wallet_scan_timestamps")
    }

    pub async fn backfill_wallet_scan_block_timestamp(
        tx: &mut Transaction<'_, Postgres>,
        chain_type: u8,
        chain_id: u64,
        railgun_contract: Address,
        block_number: u64,
        block_hash: &[u8],
        block_timestamp: u64,
    ) -> Result<u64, StoreError> {
        let block_hash = exact_array("block_hash", block_hash)?;
        Self::backfill_wallet_scan_block_timestamps(
            tx,
            chain_type,
            chain_id,
            railgun_contract,
            &[StoredWalletScanTimestampBackfill {
                block_number,
                block_hash,
                block_timestamp,
            }],
        )
        .await
    }

    pub async fn backfill_wallet_scan_block_timestamps(
        tx: &mut Transaction<'_, Postgres>,
        chain_type: u8,
        chain_id: u64,
        railgun_contract: Address,
        updates: &[StoredWalletScanTimestampBackfill],
    ) -> Result<u64, StoreError> {
        if updates.is_empty() {
            return Ok(0);
        }
        let chain_type = i16::from(chain_type);
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let railgun_contract = railgun_contract.to_string();
        let block_numbers = updates
            .iter()
            .map(|update| u64_to_i64(update.block_number, "block_number"))
            .collect::<Result<Vec<_>, _>>()?;
        let block_hashes = updates
            .iter()
            .map(|update| update.block_hash.to_vec())
            .collect::<Vec<_>>();
        let block_timestamps = updates
            .iter()
            .map(|update| u64_to_i64(update.block_timestamp, "block_timestamp"))
            .collect::<Result<Vec<_>, _>>()?;
        let mut updated = 0_u64;
        for (table, extra_predicate) in [
            ("indexed_transact_commitments", "AND ciphertext IS NOT NULL"),
            ("indexed_shield_commitments", ""),
            ("indexed_nullifiers", ""),
            ("indexed_legacy_encrypted_commitments", ""),
            ("indexed_legacy_generated_commitments", ""),
        ] {
            let sql = format!(
                "WITH timestamp_updates AS ( \
                    SELECT block_number, block_hash, MIN(block_timestamp) AS block_timestamp \
                    FROM UNNEST($4::BIGINT[], $5::BYTEA[], $6::BIGINT[]) \
                        AS source(block_number, block_hash, block_timestamp) \
                    GROUP BY block_number, block_hash \
                    HAVING MIN(block_timestamp) = MAX(block_timestamp) \
                 ) \
                 UPDATE {table} AS target \
                 SET block_timestamp = timestamp_updates.block_timestamp \
                 FROM timestamp_updates \
                 WHERE target.chain_type = $1 \
                    AND target.chain_id = $2 \
                    AND target.railgun_contract = $3 \
                    AND target.block_number = timestamp_updates.block_number \
                    AND target.block_hash = timestamp_updates.block_hash \
                    AND target.block_timestamp IS NULL \
                    {extra_predicate}"
            );
            let result = sqlx::query(&sql)
                .bind(chain_type)
                .bind(chain_id)
                .bind(&railgun_contract)
                .bind(&block_numbers)
                .bind(&block_hashes)
                .bind(&block_timestamps)
                .execute(&mut **tx)
                .await?;
            updated = updated.saturating_add(result.rows_affected());
        }
        Ok(updated)
    }

    pub async fn backfill_wallet_scan_timestamps_from_local_sources(
        tx: &mut Transaction<'_, Postgres>,
        chain_type: u8,
        chain_id: u64,
        railgun_contract: Address,
        start_block: u64,
        end_block: u64,
    ) -> Result<u64, StoreError> {
        if start_block > end_block {
            return Ok(0);
        }
        let chain_type = i16::from(chain_type);
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let railgun_contract = railgun_contract.to_string();
        let start_block = u64_to_i64(start_block, "start_block")?;
        let end_block = u64_to_i64(end_block, "end_block")?;
        let source_cte = r"
            WITH timestamp_sources AS (
                SELECT block_number, block_hash, MIN(block_timestamp) AS block_timestamp
                FROM (
                    SELECT block_number, block_hash, block_timestamp
                    FROM indexed_public_txid_rows
                    WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3
                        AND block_number BETWEEN $4 AND $5
                    UNION ALL
                    SELECT block_number, block_hash, block_timestamp
                    FROM indexed_public_transactions
                    WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3
                        AND block_timestamp IS NOT NULL
                        AND block_number BETWEEN $4 AND $5
                    UNION ALL
                    SELECT block_number, block_hash, block_timestamp
                    FROM indexed_transact_commitments
                    WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3
                        AND block_timestamp IS NOT NULL
                        AND block_number BETWEEN $4 AND $5
                    UNION ALL
                    SELECT block_number, block_hash, block_timestamp
                    FROM indexed_shield_commitments
                    WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3
                        AND block_timestamp IS NOT NULL
                        AND block_number BETWEEN $4 AND $5
                    UNION ALL
                    SELECT block_number, block_hash, block_timestamp
                    FROM indexed_nullifiers
                    WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3
                        AND block_timestamp IS NOT NULL
                        AND block_number BETWEEN $4 AND $5
                    UNION ALL
                    SELECT block_number, block_hash, block_timestamp
                    FROM indexed_legacy_encrypted_commitments
                    WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3
                        AND block_timestamp IS NOT NULL
                        AND block_number BETWEEN $4 AND $5
                    UNION ALL
                    SELECT block_number, block_hash, block_timestamp
                    FROM indexed_legacy_generated_commitments
                    WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3
                        AND block_timestamp IS NOT NULL
                        AND block_number BETWEEN $4 AND $5
                ) AS sources
                GROUP BY block_number, block_hash
                HAVING MIN(block_timestamp) = MAX(block_timestamp)
            )
        ";
        let mut updated = 0_u64;
        for (table, extra_predicate) in [
            (
                "indexed_transact_commitments",
                "AND target.ciphertext IS NOT NULL",
            ),
            ("indexed_shield_commitments", ""),
            ("indexed_nullifiers", ""),
            ("indexed_legacy_encrypted_commitments", ""),
            ("indexed_legacy_generated_commitments", ""),
        ] {
            let sql = format!(
                "{source_cte} \
                 UPDATE {table} AS target \
                 SET block_timestamp = timestamp_sources.block_timestamp \
                 FROM timestamp_sources \
                 WHERE target.chain_type = $1 \
                    AND target.chain_id = $2 \
                    AND target.railgun_contract = $3 \
                    AND target.block_number = timestamp_sources.block_number \
                    AND target.block_hash = timestamp_sources.block_hash \
                    AND target.block_timestamp IS NULL \
                    {extra_predicate}"
            );
            let result = sqlx::query(&sql)
                .bind(chain_type)
                .bind(chain_id)
                .bind(&railgun_contract)
                .bind(start_block)
                .bind(end_block)
                .execute(&mut **tx)
                .await?;
            updated = updated.saturating_add(result.rows_affected());
        }
        Ok(updated)
    }

    pub async fn commitment_rows(
        &self,
        chain_type: u8,
        chain_id: u64,
        railgun_contract: Address,
        start_global_position: u64,
        end_global_position: u64,
        indexed_through_block: Option<u64>,
    ) -> Result<Vec<StoredCommitmentRow>, StoreError> {
        let chain_type = i16::from(chain_type);
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let railgun_contract = railgun_contract.to_string();
        let start_global_position = u64_to_i64(start_global_position, "start_global_position")?;
        let end_global_position = u64_to_i64(end_global_position, "end_global_position")?;
        let tree_leaf_count = u64_to_i64(TREE_LEAF_COUNT, "tree_leaf_count")?;
        let indexed_through_block = indexed_through_block
            .map(|block| u64_to_i64(block, "indexed_through_block"))
            .transpose()?;
        let rows = sqlx::query_as::<_, (String, i64, i64, i64, Vec<u8>)>(
            r"
            WITH all_commitments AS (
                SELECT
                    'transact' AS family,
                    block_number,
                    tree_number,
                    tree_position,
                    commitment_hash
                FROM indexed_transact_commitments
                WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3
                    AND tree_number * $6 + tree_position BETWEEN $4 AND $5
                    AND ($7::BIGINT IS NULL OR block_number <= $7)
                UNION ALL
                SELECT
                    'shield' AS family,
                    block_number,
                    tree_number,
                    tree_position,
                    commitment_hash
                FROM indexed_shield_commitments
                WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3
                    AND ($7::BIGINT IS NULL OR block_number <= $7)
                UNION ALL
                SELECT
                    'legacy_encrypted' AS family,
                    block_number,
                    tree_number,
                    tree_position,
                    commitment_hash
                FROM indexed_legacy_encrypted_commitments
                WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3
                    AND ($7::BIGINT IS NULL OR block_number <= $7)
                UNION ALL
                SELECT
                    'legacy_generated' AS family,
                    block_number,
                    tree_number,
                    tree_position,
                    commitment_hash
                FROM indexed_legacy_generated_commitments
                WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3
                    AND ($7::BIGINT IS NULL OR block_number <= $7)
            )
            SELECT
                family,
                block_number,
                tree_number,
                tree_position,
                commitment_hash
            FROM all_commitments
            WHERE tree_number * $6 + tree_position BETWEEN $4 AND $5
            ORDER BY tree_number * $6 + tree_position ASC,
                block_number ASC,
                family ASC
            ",
        )
        .bind(chain_type)
        .bind(chain_id)
        .bind(&railgun_contract)
        .bind(start_global_position)
        .bind(end_global_position)
        .bind(tree_leaf_count)
        .bind(indexed_through_block)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(
                |(family, block_number, tree_number, tree_position, commitment_hash)| {
                    let tree_number = i64_to_u32(tree_number, "tree_number")?;
                    let tree_position = i64_to_u64(tree_position, "tree_position")?;
                    Ok(StoredCommitmentRow {
                        global_position: global_tree_position(tree_number, tree_position)?,
                        block_number: i64_to_u64(block_number, "block_number")?,
                        family: parse_commitment_family(&family)?,
                        tree_number,
                        tree_position,
                        commitment_hash: exact_array("commitment_hash", &commitment_hash)?,
                    })
                },
            )
            .collect()
    }

    pub async fn commitment_tree_summaries(
        &self,
        chain_type: u8,
        chain_id: u64,
        railgun_contract: Address,
        indexed_through_block: Option<u64>,
    ) -> Result<Vec<StoredCommitmentTreeSummary>, StoreError> {
        let rows = sqlx::query_as::<_, (i64, i64, i64)>(
            r"
            WITH all_commitments AS (
                SELECT
                    tree_number,
                    tree_position,
                    block_number
                FROM indexed_transact_commitments
                WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3
                    AND ($4::BIGINT IS NULL OR block_number <= $4)
                UNION ALL
                SELECT tree_number, tree_position, block_number
                FROM indexed_shield_commitments
                WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3
                    AND ($4::BIGINT IS NULL OR block_number <= $4)
                UNION ALL
                SELECT tree_number, tree_position, block_number
                FROM indexed_legacy_encrypted_commitments
                WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3
                    AND ($4::BIGINT IS NULL OR block_number <= $4)
                UNION ALL
                SELECT tree_number, tree_position, block_number
                FROM indexed_legacy_generated_commitments
                WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3
                    AND ($4::BIGINT IS NULL OR block_number <= $4)
            )
            SELECT
                tree_number,
                MAX(tree_position) + 1 AS leaf_count,
                MAX(block_number) AS last_indexed_block
            FROM all_commitments
            GROUP BY tree_number
            ORDER BY tree_number ASC
            ",
        )
        .bind(i16::from(chain_type))
        .bind(u64_to_i64(chain_id, "chain_id")?)
        .bind(railgun_contract.to_string())
        .bind(
            indexed_through_block
                .map(|block| u64_to_i64(block, "indexed_through_block"))
                .transpose()?,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|(tree_number, leaf_count, last_indexed_block)| {
                Ok(StoredCommitmentTreeSummary {
                    tree_number: i64_to_u32(tree_number, "tree_number")?,
                    leaf_count: i64_to_u64(leaf_count, "leaf_count")?,
                    last_indexed_block: i64_to_u64(last_indexed_block, "last_indexed_block")?,
                })
            })
            .collect()
    }

    pub async fn commitment_tree_checkpoint(
        &self,
        chain_type: u8,
        chain_id: u64,
        railgun_contract: Address,
        summary: &StoredCommitmentTreeSummary,
        indexed_through_block: Option<u64>,
    ) -> Result<StoredCommitmentTreeCheckpoint, StoreError> {
        let end_position =
            summary
                .leaf_count
                .checked_sub(1)
                .ok_or_else(|| StoreError::IntegerOutOfRange {
                    field: "leaf_count",
                    value: summary.leaf_count.to_string(),
                })?;
        let start_global_position = global_tree_position(summary.tree_number, 0)?;
        let end_global_position = global_tree_position(summary.tree_number, end_position)?;
        let rows = self
            .commitment_rows(
                chain_type,
                chain_id,
                railgun_contract,
                start_global_position,
                end_global_position,
                indexed_through_block,
            )
            .await?;

        let leaf_count =
            usize::try_from(summary.leaf_count).map_err(|_| StoreError::IntegerOutOfRange {
                field: "leaf_count",
                value: summary.leaf_count.to_string(),
            })?;
        let zero_leaf = MERKLE_ZERO_VALUE.to_be_bytes::<32>();
        let mut leaves = vec![zero_leaf; leaf_count];
        let mut seen = vec![false; leaf_count];
        for row in rows {
            let wrong_tree = row.tree_number != summary.tree_number;
            let beyond_leaf_count = row.tree_position >= summary.leaf_count;
            if wrong_tree || beyond_leaf_count {
                return Err(StoreError::CommitmentTreePositionOutOfRange {
                    tree_number: summary.tree_number,
                    actual: row.tree_position,
                    leaf_count: summary.leaf_count,
                });
            }
            let index =
                usize::try_from(row.tree_position).map_err(|_| StoreError::IntegerOutOfRange {
                    field: "tree_position",
                    value: row.tree_position.to_string(),
                })?;
            if seen[index] {
                return Err(StoreError::DuplicateCommitmentTreePosition {
                    tree_number: summary.tree_number,
                    position: row.tree_position,
                });
            }
            seen[index] = true;
            leaves[index] = row.commitment_hash;
        }

        Ok(StoredCommitmentTreeCheckpoint {
            tree_number: summary.tree_number,
            leaf_count: summary.leaf_count,
            last_indexed_block: summary.last_indexed_block,
            leaves,
        })
    }

    pub async fn record_chain_indexing_progress(
        tx: &mut Transaction<'_, Postgres>,
        chain_type: u8,
        chain_id: u64,
        railgun_contract: Address,
        dataset_kind: IndexedDatasetKind,
        indexed_through_block: u64,
        indexed_through_block_hash: &[u8],
    ) -> Result<(), StoreError> {
        sqlx::query(
            r"
            INSERT INTO chain_indexing_progress (
                chain_type, chain_id, railgun_contract, dataset_kind,
                indexed_through_block, indexed_through_block_hash
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (chain_type, chain_id, railgun_contract, dataset_kind)
            DO UPDATE SET
                indexed_through_block = EXCLUDED.indexed_through_block,
                indexed_through_block_hash = EXCLUDED.indexed_through_block_hash,
                updated_at = now()
            WHERE chain_indexing_progress.indexed_through_block <= EXCLUDED.indexed_through_block
            ",
        )
        .bind(i16::from(chain_type))
        .bind(u64_to_i64(chain_id, "chain_id")?)
        .bind(railgun_contract.to_string())
        .bind(dataset_kind.as_str())
        .bind(u64_to_i64(indexed_through_block, "indexed_through_block")?)
        .bind(indexed_through_block_hash)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    pub async fn record_indexed_block_header(
        tx: &mut Transaction<'_, Postgres>,
        chain_type: u8,
        chain_id: u64,
        block_number: u64,
        block_hash: &[u8],
        parent_hash: &[u8],
    ) -> Result<(), StoreError> {
        sqlx::query(
            r"
            INSERT INTO indexed_block_headers (
                chain_type, chain_id, block_number, block_hash, parent_hash
            )
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (chain_type, chain_id, block_number)
            DO UPDATE SET
                block_hash = EXCLUDED.block_hash,
                parent_hash = EXCLUDED.parent_hash,
                indexed_at = now()
            ",
        )
        .bind(i16::from(chain_type))
        .bind(u64_to_i64(chain_id, "chain_id")?)
        .bind(u64_to_i64(block_number, "block_number")?)
        .bind(block_hash)
        .bind(parent_hash)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    pub async fn indexed_block_header(
        &self,
        chain_type: u8,
        chain_id: u64,
        block_number: u64,
    ) -> Result<Option<StoredIndexedBlockHeader>, StoreError> {
        let row = sqlx::query_as::<_, (Vec<u8>, Vec<u8>)>(
            r"
            SELECT block_hash, parent_hash
            FROM indexed_block_headers
            WHERE chain_type = $1 AND chain_id = $2 AND block_number = $3
            ",
        )
        .bind(i16::from(chain_type))
        .bind(u64_to_i64(chain_id, "chain_id")?)
        .bind(u64_to_i64(block_number, "block_number")?)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|(block_hash, parent_hash)| {
            Ok(StoredIndexedBlockHeader {
                block_number,
                block_hash: exact_array("block_hash", &block_hash)?,
                parent_hash: exact_array("parent_hash", &parent_hash)?,
            })
        })
        .transpose()
    }

    pub async fn rewind_chain_indexing_to_replay_block(
        tx: &mut Transaction<'_, Postgres>,
        chain_type: u8,
        chain_id: u64,
        railgun_contract: Address,
        replay_from_block: u64,
    ) -> Result<ChainIndexingRewind, StoreError> {
        let chain_type = i16::from(chain_type);
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let railgun_contract = railgun_contract.to_string();
        let replay_from_block = u64_to_i64(replay_from_block, "replay_from_block")?;
        let previous_block = (replay_from_block > 0).then_some(replay_from_block - 1);
        let previous_hash = if let Some(previous_block) = previous_block {
            sqlx::query_scalar::<_, Vec<u8>>(
                r"
                SELECT block_hash
                FROM indexed_block_headers
                WHERE chain_type = $1 AND chain_id = $2 AND block_number = $3
                ",
            )
            .bind(chain_type)
            .bind(chain_id)
            .bind(previous_block)
            .fetch_optional(&mut **tx)
            .await?
        } else {
            None
        };

        let mut rewind = ChainIndexingRewind::default();
        rewind.deleted_indexed_rows += sqlx::query(
            r"
            DELETE FROM indexed_transact_commitments
            WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3 AND block_number >= $4
            ",
        )
        .bind(chain_type)
        .bind(chain_id)
        .bind(&railgun_contract)
        .bind(replay_from_block)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        rewind.deleted_indexed_rows += sqlx::query(
            r"
            DELETE FROM indexed_shield_commitments
            WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3 AND block_number >= $4
            ",
        )
        .bind(chain_type)
        .bind(chain_id)
        .bind(&railgun_contract)
        .bind(replay_from_block)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        rewind.deleted_indexed_rows += sqlx::query(
            r"
            DELETE FROM indexed_nullifiers
            WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3 AND block_number >= $4
            ",
        )
        .bind(chain_type)
        .bind(chain_id)
        .bind(&railgun_contract)
        .bind(replay_from_block)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        rewind.deleted_indexed_rows += sqlx::query(
            r"
            DELETE FROM indexed_legacy_encrypted_commitments
            WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3 AND block_number >= $4
            ",
        )
        .bind(chain_type)
        .bind(chain_id)
        .bind(&railgun_contract)
        .bind(replay_from_block)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        rewind.deleted_indexed_rows += sqlx::query(
            r"
            DELETE FROM indexed_legacy_generated_commitments
            WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3 AND block_number >= $4
            ",
        )
        .bind(chain_type)
        .bind(chain_id)
        .bind(&railgun_contract)
        .bind(replay_from_block)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        rewind.deleted_public_transactions = sqlx::query(
            r"
            DELETE FROM indexed_public_transactions
            WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3 AND block_number >= $4
            ",
        )
        .bind(chain_type)
        .bind(chain_id)
        .bind(&railgun_contract)
        .bind(replay_from_block)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        rewind.deleted_public_transactions += sqlx::query(
            r"
            DELETE FROM indexed_public_txid_rows
            WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3 AND block_number >= $4
            ",
        )
        .bind(chain_type)
        .bind(chain_id)
        .bind(&railgun_contract)
        .bind(replay_from_block)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        rewind.deleted_block_checkpoints = sqlx::query(
            r"
            DELETE FROM indexed_block_checkpoints
            WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3 AND block_number >= $4
            ",
        )
        .bind(chain_type)
        .bind(chain_id)
        .bind(&railgun_contract)
        .bind(replay_from_block)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        rewind.deleted_block_headers = sqlx::query(
            r"
            DELETE FROM indexed_block_headers
            WHERE chain_type = $1 AND chain_id = $2 AND block_number >= $3
            ",
        )
        .bind(chain_type)
        .bind(chain_id)
        .bind(replay_from_block)
        .execute(&mut **tx)
        .await?
        .rows_affected();

        if let (Some(previous_block), Some(previous_hash)) = (previous_block, previous_hash) {
            rewind.rewound_progress_rows = sqlx::query(
                r"
                UPDATE chain_indexing_progress
                SET indexed_through_block = $5,
                    indexed_through_block_hash = $6,
                    updated_at = now()
                WHERE chain_type = $1
                    AND chain_id = $2
                    AND railgun_contract = $3
                    AND indexed_through_block >= $4
                ",
            )
            .bind(chain_type)
            .bind(chain_id)
            .bind(&railgun_contract)
            .bind(replay_from_block)
            .bind(previous_block)
            .bind(previous_hash)
            .execute(&mut **tx)
            .await?
            .rows_affected();
        } else {
            rewind.deleted_progress_rows = sqlx::query(
                r"
                DELETE FROM chain_indexing_progress
                WHERE chain_type = $1
                    AND chain_id = $2
                    AND railgun_contract = $3
                    AND indexed_through_block >= $4
                ",
            )
            .bind(chain_type)
            .bind(chain_id)
            .bind(&railgun_contract)
            .bind(replay_from_block)
            .execute(&mut **tx)
            .await?
            .rows_affected();
        }

        Ok(rewind)
    }

    pub async fn persist_indexed_log_batch(
        tx: &mut Transaction<'_, Postgres>,
        chain_type: u8,
        chain_id: u64,
        railgun_contract: Address,
        batch: &IndexedLogBatch,
    ) -> Result<(), StoreError> {
        let chain_type = i16::from(chain_type);
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let railgun_contract = railgun_contract.to_string();

        for item in &batch.transact_commitments {
            record_source_transaction(tx, chain_type, chain_id, &railgun_contract, &item.source)
                .await?;
            sqlx::query(
                r"
                INSERT INTO indexed_transact_commitments (
                    chain_type, chain_id, railgun_contract, block_number, block_timestamp,
                    block_hash, transaction_hash, log_index, tree_number, tree_position,
                    commitment_hash, ciphertext
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                ON CONFLICT (chain_type, chain_id, railgun_contract, tree_number, tree_position)
                DO UPDATE SET
                    block_number = EXCLUDED.block_number,
                    block_timestamp = EXCLUDED.block_timestamp,
                    block_hash = EXCLUDED.block_hash,
                    transaction_hash = EXCLUDED.transaction_hash,
                    log_index = EXCLUDED.log_index,
                    commitment_hash = EXCLUDED.commitment_hash,
                    ciphertext = EXCLUDED.ciphertext
                ",
            )
            .bind(chain_type)
            .bind(chain_id)
            .bind(&railgun_contract)
            .bind(u64_to_i64(item.source.block_number, "block_number")?)
            .bind(source_block_timestamp_i64(&item.source)?)
            .bind(item.source.block_hash.as_slice())
            .bind(item.source.transaction_hash.as_slice())
            .bind(u64_to_i64(item.source.log_index, "log_index")?)
            .bind(i64::from(item.tree_number))
            .bind(u64_to_i64(item.tree_position, "tree_position")?)
            .bind(item.hash.as_slice())
            .bind(item.ciphertext.as_ref().map(SolValue::abi_encode))
            .execute(&mut **tx)
            .await?;
        }

        for item in &batch.shield_commitments {
            record_source_transaction(tx, chain_type, chain_id, &railgun_contract, &item.source)
                .await?;
            let commitment_hash = item.preimage.hash().to_be_bytes::<32>();
            sqlx::query(
                r"
                INSERT INTO indexed_shield_commitments (
                    chain_type, chain_id, railgun_contract, block_number, block_timestamp,
                    block_hash, transaction_hash, log_index, tree_number, tree_position,
                    commitment_hash, preimage, shield_ciphertext
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                ON CONFLICT (chain_type, chain_id, railgun_contract, tree_number, tree_position)
                DO UPDATE SET
                    block_number = EXCLUDED.block_number,
                    block_timestamp = EXCLUDED.block_timestamp,
                    block_hash = EXCLUDED.block_hash,
                    transaction_hash = EXCLUDED.transaction_hash,
                    log_index = EXCLUDED.log_index,
                    commitment_hash = EXCLUDED.commitment_hash,
                    preimage = EXCLUDED.preimage,
                    shield_ciphertext = EXCLUDED.shield_ciphertext
                ",
            )
            .bind(chain_type)
            .bind(chain_id)
            .bind(&railgun_contract)
            .bind(u64_to_i64(item.source.block_number, "block_number")?)
            .bind(source_block_timestamp_i64(&item.source)?)
            .bind(item.source.block_hash.as_slice())
            .bind(item.source.transaction_hash.as_slice())
            .bind(u64_to_i64(item.source.log_index, "log_index")?)
            .bind(i64::from(item.tree_number))
            .bind(u64_to_i64(item.tree_position, "tree_position")?)
            .bind(commitment_hash.as_slice())
            .bind(item.preimage.abi_encode())
            .bind(item.shield_ciphertext.abi_encode())
            .execute(&mut **tx)
            .await?;
        }

        for item in &batch.nullifiers {
            record_source_transaction(tx, chain_type, chain_id, &railgun_contract, &item.source)
                .await?;
            sqlx::query(
                r"
                INSERT INTO indexed_nullifiers (
                    chain_type, chain_id, railgun_contract, block_number, block_timestamp,
                    block_hash, transaction_hash, log_index, tree_number, nullifier
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ON CONFLICT (chain_type, chain_id, railgun_contract, tree_number, nullifier)
                DO UPDATE SET
                    block_number = EXCLUDED.block_number,
                    block_timestamp = EXCLUDED.block_timestamp,
                    block_hash = EXCLUDED.block_hash,
                    transaction_hash = EXCLUDED.transaction_hash,
                    log_index = EXCLUDED.log_index
                ",
            )
            .bind(chain_type)
            .bind(chain_id)
            .bind(&railgun_contract)
            .bind(u64_to_i64(item.source.block_number, "block_number")?)
            .bind(source_block_timestamp_i64(&item.source)?)
            .bind(item.source.block_hash.as_slice())
            .bind(item.source.transaction_hash.as_slice())
            .bind(u64_to_i64(item.source.log_index, "log_index")?)
            .bind(i64::from(item.tree_number))
            .bind(item.nullifier.as_slice())
            .execute(&mut **tx)
            .await?;
        }

        for item in &batch.legacy_encrypted_commitments {
            record_source_transaction(tx, chain_type, chain_id, &railgun_contract, &item.source)
                .await?;
            sqlx::query(
                r"
                INSERT INTO indexed_legacy_encrypted_commitments (
                    chain_type, chain_id, railgun_contract, block_number, block_timestamp,
                    block_hash, transaction_hash, log_index, tree_number, tree_position,
                    commitment_hash, ciphertext
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                ON CONFLICT (chain_type, chain_id, railgun_contract, tree_number, tree_position)
                DO UPDATE SET
                    block_number = EXCLUDED.block_number,
                    block_timestamp = EXCLUDED.block_timestamp,
                    block_hash = EXCLUDED.block_hash,
                    transaction_hash = EXCLUDED.transaction_hash,
                    log_index = EXCLUDED.log_index,
                    commitment_hash = EXCLUDED.commitment_hash,
                    ciphertext = EXCLUDED.ciphertext
                ",
            )
            .bind(chain_type)
            .bind(chain_id)
            .bind(&railgun_contract)
            .bind(u64_to_i64(item.source.block_number, "block_number")?)
            .bind(source_block_timestamp_i64(&item.source)?)
            .bind(item.source.block_hash.as_slice())
            .bind(item.source.transaction_hash.as_slice())
            .bind(u64_to_i64(item.source.log_index, "log_index")?)
            .bind(i64::from(item.tree_number))
            .bind(u64_to_i64(item.tree_position, "tree_position")?)
            .bind(item.hash.as_slice())
            .bind(item.ciphertext.abi_encode())
            .execute(&mut **tx)
            .await?;
        }

        for item in &batch.legacy_generated_commitments {
            record_source_transaction(tx, chain_type, chain_id, &railgun_contract, &item.source)
                .await?;
            let commitment_hash = item.preimage.hash().to_be_bytes::<32>();
            let mut encrypted_random = Vec::with_capacity(64);
            encrypted_random.extend_from_slice(&item.encrypted_random[0].to_be_bytes::<32>());
            encrypted_random.extend_from_slice(&item.encrypted_random[1].to_be_bytes::<32>());
            sqlx::query(
                r"
                INSERT INTO indexed_legacy_generated_commitments (
                    chain_type, chain_id, railgun_contract, block_number, block_timestamp,
                    block_hash, transaction_hash, log_index, tree_number, tree_position,
                    commitment_hash, preimage, encrypted_random
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                ON CONFLICT (chain_type, chain_id, railgun_contract, tree_number, tree_position)
                DO UPDATE SET
                    block_number = EXCLUDED.block_number,
                    block_timestamp = EXCLUDED.block_timestamp,
                    block_hash = EXCLUDED.block_hash,
                    transaction_hash = EXCLUDED.transaction_hash,
                    log_index = EXCLUDED.log_index,
                    commitment_hash = EXCLUDED.commitment_hash,
                    preimage = EXCLUDED.preimage,
                    encrypted_random = EXCLUDED.encrypted_random
                ",
            )
            .bind(chain_type)
            .bind(chain_id)
            .bind(&railgun_contract)
            .bind(u64_to_i64(item.source.block_number, "block_number")?)
            .bind(source_block_timestamp_i64(&item.source)?)
            .bind(item.source.block_hash.as_slice())
            .bind(item.source.transaction_hash.as_slice())
            .bind(u64_to_i64(item.source.log_index, "log_index")?)
            .bind(i64::from(item.tree_number))
            .bind(u64_to_i64(item.tree_position, "tree_position")?)
            .bind(commitment_hash.as_slice())
            .bind(item.preimage.abi_encode())
            .bind(encrypted_random)
            .execute(&mut **tx)
            .await?;
        }

        for item in &batch.public_transactions {
            let nullifiers = flatten_fixed_bytes(&item.nullifiers);
            let commitments = flatten_fixed_bytes(&item.commitments);
            sqlx::query(
                r"
                INSERT INTO indexed_public_txid_rows (
                    chain_type, chain_id, railgun_contract, block_number, block_timestamp,
                    block_hash, transaction_hash, first_log_index, last_log_index,
                    railgun_transaction_index, row_id, merkle_root, nullifiers,
                    commitments, bound_params_hash, has_unshield, utxo_tree_in,
                    utxo_tree_out, utxo_batch_start_position_out
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
                ON CONFLICT (chain_type, chain_id, railgun_contract, transaction_hash, railgun_transaction_index)
                DO UPDATE SET
                    block_number = EXCLUDED.block_number,
                    block_timestamp = EXCLUDED.block_timestamp,
                    block_hash = EXCLUDED.block_hash,
                    first_log_index = EXCLUDED.first_log_index,
                    last_log_index = EXCLUDED.last_log_index,
                    row_id = EXCLUDED.row_id,
                    merkle_root = EXCLUDED.merkle_root,
                    nullifiers = EXCLUDED.nullifiers,
                    commitments = EXCLUDED.commitments,
                    bound_params_hash = EXCLUDED.bound_params_hash,
                    has_unshield = EXCLUDED.has_unshield,
                    utxo_tree_in = EXCLUDED.utxo_tree_in,
                    utxo_tree_out = EXCLUDED.utxo_tree_out,
                    utxo_batch_start_position_out = EXCLUDED.utxo_batch_start_position_out
                ",
            )
            .bind(chain_type)
            .bind(chain_id)
            .bind(&railgun_contract)
            .bind(u64_to_i64(item.source.block_number, "block_number")?)
            .bind(u64_to_i64(item.block_timestamp, "block_timestamp")?)
            .bind(item.source.block_hash.as_slice())
            .bind(item.source.transaction_hash.as_slice())
            .bind(u64_to_i64(item.first_log_index, "first_log_index")?)
            .bind(u64_to_i64(item.last_log_index, "last_log_index")?)
            .bind(u64_to_i64(
                item.railgun_transaction_index,
                "railgun_transaction_index",
            )?)
            .bind(&item.id)
            .bind(item.merkle_root.as_slice())
            .bind(nullifiers)
            .bind(commitments)
            .bind(item.bound_params_hash.as_slice())
            .bind(item.has_unshield)
            .bind(u64_to_i64(item.utxo_tree_in, "utxo_tree_in")?)
            .bind(u64_to_i64(item.utxo_tree_out, "utxo_tree_out")?)
            .bind(u64_to_i64(
                item.utxo_batch_start_position_out,
                "utxo_batch_start_position_out",
            )?)
            .execute(&mut **tx)
            .await?;
        }

        Ok(())
    }
}

async fn record_source_transaction(
    tx: &mut Transaction<'_, Postgres>,
    chain_type: i16,
    chain_id: i64,
    railgun_contract: &str,
    source: &IndexedLogSource,
) -> Result<(), StoreError> {
    sqlx::query(
        r"
        INSERT INTO indexed_public_transactions (
            chain_type, chain_id, railgun_contract, block_number, block_timestamp, block_hash,
            transaction_hash, first_log_index, last_log_index
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
        ON CONFLICT (chain_type, chain_id, railgun_contract, transaction_hash)
        DO UPDATE SET
            block_number = LEAST(indexed_public_transactions.block_number, EXCLUDED.block_number),
            block_timestamp = EXCLUDED.block_timestamp,
            block_hash = EXCLUDED.block_hash,
            first_log_index = LEAST(indexed_public_transactions.first_log_index, EXCLUDED.first_log_index),
            last_log_index = GREATEST(indexed_public_transactions.last_log_index, EXCLUDED.last_log_index)
        ",
    )
    .bind(chain_type)
    .bind(chain_id)
    .bind(railgun_contract)
    .bind(u64_to_i64(source.block_number, "block_number")?)
    .bind(source_block_timestamp_i64(source)?)
    .bind(source.block_hash.as_slice())
    .bind(source.transaction_hash.as_slice())
    .bind(u64_to_i64(source.log_index, "log_index")?)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn source_block_timestamp_i64(source: &IndexedLogSource) -> Result<i64, StoreError> {
    let block_timestamp =
        source
            .block_timestamp
            .ok_or_else(|| StoreError::MissingBlockTimestamp {
                block_number: source.block_number,
                block_hash: hex::encode_prefixed(source.block_hash),
            })?;
    u64_to_i64(block_timestamp, "block_timestamp")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvent {
    pub event_index: u64,
    pub blinded_commitment: [u8; 32],
    pub signature: [u8; 64],
    pub event_type: PoiEventType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBlockedShield {
    pub commitment_hash: [u8; 32],
    pub blinded_commitment: [u8; 32],
    pub block_reason: Option<String>,
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredChainTip {
    pub last_event_index: u64,
    pub last_tip_merkleroot: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredChainIndexingProgress {
    pub indexed_through_block: u64,
    pub indexed_through_block_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredIndexedBlockHeader {
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub parent_hash: [u8; 32],
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ChainIndexingRewind {
    pub deleted_indexed_rows: u64,
    pub deleted_public_transactions: u64,
    pub deleted_block_checkpoints: u64,
    pub deleted_block_headers: u64,
    pub rewound_progress_rows: u64,
    pub deleted_progress_rows: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPublicTxidRow {
    pub txid_index: u64,
    pub id: String,
    pub block_number: u64,
    pub block_timestamp: u64,
    pub block_hash: [u8; 32],
    pub transaction_hash: [u8; 32],
    pub first_log_index: u64,
    pub last_log_index: u64,
    pub merkle_root: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    pub commitments: Vec<[u8; 32]>,
    pub bound_params_hash: [u8; 32],
    pub has_unshield: bool,
    pub utxo_tree_in: u64,
    pub utxo_tree_out: u64,
    pub utxo_batch_start_position_out: u64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StoredWalletScanRows {
    pub transact_commitments: Vec<StoredTransactCommitmentRow>,
    pub shield_commitments: Vec<StoredShieldCommitmentRow>,
    pub nullifiers: Vec<StoredNullifierRow>,
    pub legacy_encrypted_commitments: Vec<StoredLegacyEncryptedCommitmentRow>,
    pub legacy_generated_commitments: Vec<StoredLegacyGeneratedCommitmentRow>,
}

impl StoredWalletScanRows {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.transact_commitments.is_empty()
            && self.shield_commitments.is_empty()
            && self.nullifiers.is_empty()
            && self.legacy_encrypted_commitments.is_empty()
            && self.legacy_generated_commitments.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBlockRange {
    pub start_block: u64,
    pub end_block: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMissingWalletScanTimestampBlock {
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub missing_rows: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredWalletScanTimestampBackfill {
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub block_timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredIndexedLogSourceRow {
    pub block_number: u64,
    pub block_timestamp: Option<u64>,
    pub block_hash: [u8; 32],
    pub transaction_hash: [u8; 32],
    pub log_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTransactCommitmentRow {
    pub source: StoredIndexedLogSourceRow,
    pub tree_number: u32,
    pub tree_position: u64,
    pub commitment_hash: [u8; 32],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredShieldCommitmentRow {
    pub source: StoredIndexedLogSourceRow,
    pub tree_number: u32,
    pub tree_position: u64,
    pub commitment_hash: [u8; 32],
    pub preimage: Vec<u8>,
    pub shield_ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredNullifierRow {
    pub source: StoredIndexedLogSourceRow,
    pub tree_number: u32,
    pub nullifier: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredLegacyEncryptedCommitmentRow {
    pub source: StoredIndexedLogSourceRow,
    pub tree_number: u32,
    pub tree_position: u64,
    pub commitment_hash: [u8; 32],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredLegacyGeneratedCommitmentRow {
    pub source: StoredIndexedLogSourceRow,
    pub tree_number: u32,
    pub tree_position: u64,
    pub commitment_hash: [u8; 32],
    pub preimage: Vec<u8>,
    pub encrypted_random: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCommitmentRow {
    pub global_position: u64,
    pub block_number: u64,
    pub family: StoredCommitmentFamily,
    pub tree_number: u32,
    pub tree_position: u64,
    pub commitment_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCommitmentTreeSummary {
    pub tree_number: u32,
    pub leaf_count: u64,
    pub last_indexed_block: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCommitmentTreeCheckpoint {
    pub tree_number: u32,
    pub leaf_count: u64,
    pub last_indexed_block: u64,
    pub leaves: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredCommitmentFamily {
    Transact,
    Shield,
    LegacyEncrypted,
    LegacyGenerated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexedDatasetKind {
    WalletScan,
    Commitments,
    MerkleCheckpoint,
    PublicTxid,
}

impl IndexedDatasetKind {
    pub const ALL: [Self; 4] = [
        Self::WalletScan,
        Self::Commitments,
        Self::MerkleCheckpoint,
        Self::PublicTxid,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WalletScan => "wallet_scan",
            Self::Commitments => "commitments",
            Self::MerkleCheckpoint => "merkle_checkpoint",
            Self::PublicTxid => "public_txid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPublication {
    pub kind: SnapshotKind,
    pub start_index: u64,
    pub end_index: u64,
    pub cid: String,
    pub byte_size: u64,
    pub content_hash: [u8; 32],
    pub tip_merkleroot: Option<[u8; 32]>,
    pub published_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBlockedShieldsPublication {
    pub cid: String,
    pub byte_size: u64,
    pub content_hash: [u8; 32],
    pub published_at: SystemTime,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database operation failed")]
    Sqlx(#[from] sqlx::Error),
    #[error("invalid hex in {field}")]
    Hex {
        field: &'static str,
        #[source]
        source: hex::FromHexError,
    },
    #[error("decoded {field} has {actual} bytes, expected {expected}")]
    HexLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("{field} value {value} is outside supported range")]
    IntegerOutOfRange { field: &'static str, value: String },
    #[error(
        "chain tip would regress for list_key={list_key} chain_id={chain_id} upstream={upstream_url} proposed={proposed}"
    )]
    ChainTipRegression {
        list_key: String,
        chain_id: u64,
        upstream_url: String,
        proposed: u64,
    },
    #[error("invalid stored POI event type {0}")]
    InvalidEventType(i16),
    #[error("invalid stored snapshot kind {0}")]
    InvalidSnapshotKind(String),
    #[error("invalid stored commitment family {0}")]
    InvalidCommitmentFamily(String),
    #[error("commitment tree {tree_number} position {position} is duplicated")]
    DuplicateCommitmentTreePosition { tree_number: u32, position: u64 },
    #[error("commitment tree {tree_number} position {actual} is outside leaf count {leaf_count}")]
    CommitmentTreePositionOutOfRange {
        tree_number: u32,
        actual: u64,
        leaf_count: u64,
    },
    #[error("indexed log source at block {block_number} ({block_hash}) is missing block_timestamp")]
    MissingBlockTimestamp {
        block_number: u64,
        block_hash: String,
    },
}

pub async fn run_migrations(pool: &PgPool) -> Result<(), StoreError> {
    sqlx::query(SCHEMA_VERSION_TABLE).execute(pool).await?;

    let mut tx = pool.begin().await?;
    sqlx::query(
        r"
        INSERT INTO poi_indexer_schema_version (id, version, applied_at)
        VALUES (TRUE, 0, now())
        ON CONFLICT (id) DO NOTHING
        ",
    )
    .execute(&mut *tx)
    .await?;

    let current_version = sqlx::query_scalar::<_, i32>(
        r"
        SELECT version
        FROM poi_indexer_schema_version
        WHERE id = TRUE
        FOR UPDATE
        ",
    )
    .fetch_one(&mut *tx)
    .await?;

    if current_version >= CURRENT_SCHEMA_VERSION {
        tx.commit().await?;
        info!(version = current_version, "POI indexer schema is current");
        return Ok(());
    }

    info!(
        from_version = current_version,
        to_version = CURRENT_SCHEMA_VERSION,
        "applying POI indexer schema migrations"
    );

    for &(target_version, statements) in VERSIONED_MIGRATIONS {
        if target_version <= current_version {
            continue;
        }

        for statement in statements {
            sqlx::query(statement).execute(&mut *tx).await?;
        }

        sqlx::query(
            r"
            UPDATE poi_indexer_schema_version
            SET version = $1, applied_at = now()
            WHERE id = TRUE
            ",
        )
        .bind(target_version)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(())
}

const BLINDED_COMMITMENT_BYTES: usize = 32;
const COMMITMENT_HASH_BYTES: usize = 32;
const MERKLEROOT_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;

const SCHEMA_VERSION_TABLE: &str = r"
CREATE TABLE IF NOT EXISTS poi_indexer_schema_version (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    version INTEGER NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
";

const VERSIONED_MIGRATIONS: &[(i32, &[&str])] = &[
    (4, V4_MIGRATIONS),
    (5, V5_MIGRATIONS),
    (6, V6_MIGRATIONS),
    (7, V7_MIGRATIONS),
    (8, V8_MIGRATIONS),
    (9, V9_MIGRATIONS),
    (10, V10_MIGRATIONS),
    (11, V11_MIGRATIONS),
];

const V4_MIGRATIONS: &[&str] = &[
    r"
    CREATE TABLE IF NOT EXISTS poi_events (
        list_key BYTEA NOT NULL,
        chain_id BIGINT NOT NULL,
        event_index BIGINT NOT NULL,
        blinded_commitment BYTEA NOT NULL,
        signature BYTEA NOT NULL,
        event_type SMALLINT NOT NULL,
        fetched_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (list_key, chain_id, event_index)
    )
    ",
    r"
    CREATE TABLE IF NOT EXISTS blocked_shields (
        list_key BYTEA NOT NULL,
        chain_id BIGINT NOT NULL,
        blinded_commitment BYTEA NOT NULL,
        commitment_hash BYTEA NOT NULL,
        signature BYTEA NOT NULL,
        block_reason TEXT,
        fetched_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (list_key, chain_id, blinded_commitment)
    )
    ",
    r"
    CREATE TABLE IF NOT EXISTS chain_tips (
        list_key BYTEA NOT NULL,
        chain_id BIGINT NOT NULL,
        upstream_url TEXT NOT NULL,
        last_event_index BIGINT NOT NULL,
        last_tip_merkleroot BYTEA,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (list_key, chain_id, upstream_url)
    )
    ",
    r"
    CREATE TABLE IF NOT EXISTS published_snapshots (
        id BIGSERIAL PRIMARY KEY,
        list_key BYTEA NOT NULL,
        chain_id BIGINT NOT NULL,
        upstream_url TEXT NOT NULL,
        kind TEXT NOT NULL,
        start_index BIGINT NOT NULL,
        end_index BIGINT NOT NULL,
        cid TEXT NOT NULL,
        byte_size BIGINT NOT NULL,
        content_hash BYTEA,
        format_version INTEGER NOT NULL,
        tip_merkleroot BYTEA,
        published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        superseded_at TIMESTAMPTZ,
        unpinned_at TIMESTAMPTZ
    )
    ",
    r"
    CREATE TABLE IF NOT EXISTS published_blocked_shields (
        id BIGSERIAL PRIMARY KEY,
        list_key BYTEA NOT NULL,
        chain_id BIGINT NOT NULL,
        upstream_url TEXT NOT NULL,
        cid TEXT NOT NULL,
        byte_size BIGINT NOT NULL,
        format_version INTEGER NOT NULL,
        content_hash BYTEA NOT NULL,
        published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        superseded_at TIMESTAMPTZ,
        unpinned_at TIMESTAMPTZ
    )
    ",
    r"
    CREATE TABLE IF NOT EXISTS indexer_state (
        key TEXT PRIMARY KEY,
        value BIGINT NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    ",
    r"
    ALTER TABLE poi_events
        ALTER COLUMN event_type TYPE SMALLINT USING CASE event_type::TEXT
            WHEN 'Shield' THEN 0
            WHEN 'Transact' THEN 1
            WHEN 'Unshield' THEN 2
            WHEN 'LegacyTransact' THEN 3
            ELSE event_type::SMALLINT
        END
    ",
    r"
    ALTER TABLE published_snapshots
        ADD COLUMN IF NOT EXISTS upstream_url TEXT
    ",
    r"
    WITH upstream_counts AS (
        SELECT
            list_key,
            chain_id,
            COUNT(DISTINCT upstream_url) AS upstream_count,
            MIN(upstream_url) AS upstream_url
        FROM chain_tips
        GROUP BY list_key, chain_id
    )
    UPDATE published_snapshots AS snapshots
    SET upstream_url = upstream_counts.upstream_url
    FROM upstream_counts
    WHERE snapshots.list_key = upstream_counts.list_key
        AND snapshots.chain_id = upstream_counts.chain_id
        AND upstream_counts.upstream_count = 1
        AND snapshots.upstream_url IS NULL
    ",
    r"
    UPDATE published_snapshots
    SET upstream_url = '__unknown_upstream__'
    WHERE upstream_url IS NULL
    ",
    r"
    ALTER TABLE published_snapshots
        ALTER COLUMN upstream_url SET NOT NULL
    ",
    r"
    ALTER TABLE published_snapshots
        ADD COLUMN IF NOT EXISTS unpinned_at TIMESTAMPTZ
    ",
    r"
    ALTER TABLE published_snapshots
        ADD COLUMN IF NOT EXISTS content_hash BYTEA
    ",
    r"
    UPDATE published_snapshots
    SET superseded_at = now()
    WHERE content_hash IS NULL
        AND superseded_at IS NULL
    ",
    r"
    UPDATE published_snapshots
    SET superseded_at = now()
    WHERE upstream_url = '__unknown_upstream__'
        AND superseded_at IS NULL
    ",
    r"
    DO $$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'poi_events_event_type_check') THEN
            ALTER TABLE poi_events
                ADD CONSTRAINT poi_events_event_type_check CHECK (event_type BETWEEN 0 AND 3);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'poi_events_list_key_len_check') THEN
            ALTER TABLE poi_events
                ADD CONSTRAINT poi_events_list_key_len_check CHECK (octet_length(list_key) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'poi_events_blinded_len_check') THEN
            ALTER TABLE poi_events
                ADD CONSTRAINT poi_events_blinded_len_check CHECK (octet_length(blinded_commitment) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'poi_events_signature_len_check') THEN
            ALTER TABLE poi_events
                ADD CONSTRAINT poi_events_signature_len_check CHECK (octet_length(signature) = 64);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'blocked_shields_list_key_len_check') THEN
            ALTER TABLE blocked_shields
                ADD CONSTRAINT blocked_shields_list_key_len_check CHECK (octet_length(list_key) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'blocked_shields_blinded_len_check') THEN
            ALTER TABLE blocked_shields
                ADD CONSTRAINT blocked_shields_blinded_len_check CHECK (octet_length(blinded_commitment) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'blocked_shields_commitment_len_check') THEN
            ALTER TABLE blocked_shields
                ADD CONSTRAINT blocked_shields_commitment_len_check CHECK (octet_length(commitment_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'blocked_shields_signature_len_check') THEN
            ALTER TABLE blocked_shields
                ADD CONSTRAINT blocked_shields_signature_len_check CHECK (octet_length(signature) = 64);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chain_tips_tip_root_len_check') THEN
            ALTER TABLE chain_tips
                ADD CONSTRAINT chain_tips_tip_root_len_check CHECK (last_tip_merkleroot IS NULL OR octet_length(last_tip_merkleroot) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'published_snapshots_kind_check') THEN
            ALTER TABLE published_snapshots
                ADD CONSTRAINT published_snapshots_kind_check CHECK (kind IN ('base', 'delta'));
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'published_snapshots_tip_root_len_check') THEN
            ALTER TABLE published_snapshots
                ADD CONSTRAINT published_snapshots_tip_root_len_check CHECK (tip_merkleroot IS NULL OR octet_length(tip_merkleroot) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'published_snapshots_content_hash_len_check') THEN
            ALTER TABLE published_snapshots
                ADD CONSTRAINT published_snapshots_content_hash_len_check CHECK (content_hash IS NULL OR octet_length(content_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'published_blocked_shields_list_key_len_check') THEN
            ALTER TABLE published_blocked_shields
                ADD CONSTRAINT published_blocked_shields_list_key_len_check CHECK (octet_length(list_key) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'published_blocked_shields_content_hash_len_check') THEN
            ALTER TABLE published_blocked_shields
                ADD CONSTRAINT published_blocked_shields_content_hash_len_check CHECK (octet_length(content_hash) = 32);
        END IF;
    END $$
    ",
    "CREATE INDEX IF NOT EXISTS poi_events_lookup ON poi_events (list_key, chain_id, blinded_commitment)",
    "CREATE INDEX IF NOT EXISTS published_snapshots_active_lookup ON published_snapshots (list_key, chain_id, upstream_url, kind, start_index, id) WHERE superseded_at IS NULL",
    "CREATE INDEX IF NOT EXISTS published_snapshots_retention_lookup ON published_snapshots (superseded_at, unpinned_at, cid) WHERE superseded_at IS NOT NULL AND unpinned_at IS NULL",
    "CREATE INDEX IF NOT EXISTS published_snapshots_cid_live_lookup ON published_snapshots (cid) WHERE superseded_at IS NULL",
    "CREATE INDEX IF NOT EXISTS published_blocked_shields_active_lookup ON published_blocked_shields (list_key, chain_id, upstream_url, id) WHERE superseded_at IS NULL",
    "CREATE INDEX IF NOT EXISTS published_blocked_shields_retention_lookup ON published_blocked_shields (superseded_at, unpinned_at, cid) WHERE superseded_at IS NOT NULL AND unpinned_at IS NULL",
    "CREATE INDEX IF NOT EXISTS published_blocked_shields_cid_live_lookup ON published_blocked_shields (cid) WHERE superseded_at IS NULL",
];

const V5_MIGRATIONS: &[&str] = &[
    r"
    CREATE TABLE IF NOT EXISTS published_manifests (
        id BIGSERIAL PRIMARY KEY,
        cid TEXT NOT NULL,
        ipns_sequence BIGINT NOT NULL,
        byte_size BIGINT NOT NULL,
        content_hash BYTEA NOT NULL,
        format_version INTEGER NOT NULL,
        published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        ipns_published_at TIMESTAMPTZ,
        superseded_at TIMESTAMPTZ,
        unpinned_at TIMESTAMPTZ
    )
    ",
    r"
    DO $$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'published_manifests_content_hash_len_check') THEN
            ALTER TABLE published_manifests
                ADD CONSTRAINT published_manifests_content_hash_len_check CHECK (octet_length(content_hash) = 32);
        END IF;
    END $$
    ",
    "CREATE INDEX IF NOT EXISTS published_manifests_retention_lookup ON published_manifests (superseded_at, published_at, unpinned_at, cid) WHERE unpinned_at IS NULL",
    "CREATE INDEX IF NOT EXISTS published_manifests_cid_live_lookup ON published_manifests (cid) WHERE ipns_published_at IS NOT NULL AND superseded_at IS NULL",
];

const V6_MIGRATIONS: &[&str] = &[
    r"
    CREATE TABLE IF NOT EXISTS chain_indexing_progress (
        chain_type SMALLINT NOT NULL,
        chain_id BIGINT NOT NULL,
        railgun_contract TEXT NOT NULL,
        dataset_kind TEXT NOT NULL,
        indexed_through_block BIGINT NOT NULL,
        indexed_through_block_hash BYTEA NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (chain_type, chain_id, railgun_contract, dataset_kind)
    )
    ",
    r"
    CREATE TABLE IF NOT EXISTS indexed_block_checkpoints (
        chain_type SMALLINT NOT NULL,
        chain_id BIGINT NOT NULL,
        railgun_contract TEXT NOT NULL,
        checkpoint_kind TEXT NOT NULL,
        block_number BIGINT NOT NULL,
        block_hash BYTEA NOT NULL,
        parent_hash BYTEA NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (chain_type, chain_id, railgun_contract, checkpoint_kind, block_number)
    )
    ",
    r"
    CREATE TABLE IF NOT EXISTS indexed_block_headers (
        chain_type SMALLINT NOT NULL,
        chain_id BIGINT NOT NULL,
        block_number BIGINT NOT NULL,
        block_hash BYTEA NOT NULL,
        parent_hash BYTEA NOT NULL,
        indexed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (chain_type, chain_id, block_number),
        UNIQUE (chain_type, chain_id, block_hash)
    )
    ",
    r"
    DO $$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chain_indexing_progress_chain_type_check') THEN
            ALTER TABLE chain_indexing_progress
                ADD CONSTRAINT chain_indexing_progress_chain_type_check CHECK (chain_type = 0);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chain_indexing_progress_dataset_kind_check') THEN
            ALTER TABLE chain_indexing_progress
                ADD CONSTRAINT chain_indexing_progress_dataset_kind_check CHECK (dataset_kind IN ('wallet_scan', 'commitments', 'merkle_checkpoint', 'public_txid'));
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chain_indexing_progress_block_hash_len_check') THEN
            ALTER TABLE chain_indexing_progress
                ADD CONSTRAINT chain_indexing_progress_block_hash_len_check CHECK (octet_length(indexed_through_block_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'indexed_block_checkpoints_chain_type_check') THEN
            ALTER TABLE indexed_block_checkpoints
                ADD CONSTRAINT indexed_block_checkpoints_chain_type_check CHECK (chain_type = 0);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'indexed_block_checkpoints_kind_check') THEN
            ALTER TABLE indexed_block_checkpoints
                ADD CONSTRAINT indexed_block_checkpoints_kind_check CHECK (checkpoint_kind IN ('wallet_scan', 'commitments', 'merkle_checkpoint', 'public_txid'));
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'indexed_block_checkpoints_block_hash_len_check') THEN
            ALTER TABLE indexed_block_checkpoints
                ADD CONSTRAINT indexed_block_checkpoints_block_hash_len_check CHECK (octet_length(block_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'indexed_block_checkpoints_parent_hash_len_check') THEN
            ALTER TABLE indexed_block_checkpoints
                ADD CONSTRAINT indexed_block_checkpoints_parent_hash_len_check CHECK (octet_length(parent_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'indexed_block_headers_chain_type_check') THEN
            ALTER TABLE indexed_block_headers
                ADD CONSTRAINT indexed_block_headers_chain_type_check CHECK (chain_type = 0);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'indexed_block_headers_block_hash_len_check') THEN
            ALTER TABLE indexed_block_headers
                ADD CONSTRAINT indexed_block_headers_block_hash_len_check CHECK (octet_length(block_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'indexed_block_headers_parent_hash_len_check') THEN
            ALTER TABLE indexed_block_headers
                ADD CONSTRAINT indexed_block_headers_parent_hash_len_check CHECK (octet_length(parent_hash) = 32);
        END IF;
    END $$
    ",
    "CREATE INDEX IF NOT EXISTS chain_indexing_progress_tip_lookup ON chain_indexing_progress (chain_type, chain_id, dataset_kind, indexed_through_block)",
    "CREATE INDEX IF NOT EXISTS indexed_block_checkpoints_latest_lookup ON indexed_block_checkpoints (chain_type, chain_id, railgun_contract, checkpoint_kind, block_number DESC)",
    "CREATE INDEX IF NOT EXISTS indexed_block_headers_parent_lookup ON indexed_block_headers (chain_type, chain_id, parent_hash)",
];

const V7_MIGRATIONS: &[&str] = &[
    r"
    CREATE TABLE IF NOT EXISTS indexed_public_transactions (
        chain_type SMALLINT NOT NULL,
        chain_id BIGINT NOT NULL,
        railgun_contract TEXT NOT NULL,
        block_number BIGINT NOT NULL,
        block_timestamp BIGINT,
        block_hash BYTEA NOT NULL,
        transaction_hash BYTEA NOT NULL,
        first_log_index BIGINT NOT NULL,
        last_log_index BIGINT NOT NULL,
        indexed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (chain_type, chain_id, railgun_contract, transaction_hash)
    )
    ",
    r"
    CREATE TABLE IF NOT EXISTS indexed_transact_commitments (
        chain_type SMALLINT NOT NULL,
        chain_id BIGINT NOT NULL,
        railgun_contract TEXT NOT NULL,
        block_number BIGINT NOT NULL,
        block_timestamp BIGINT,
        block_hash BYTEA NOT NULL,
        transaction_hash BYTEA NOT NULL,
        log_index BIGINT NOT NULL,
        tree_number BIGINT NOT NULL,
        tree_position BIGINT NOT NULL,
        commitment_hash BYTEA NOT NULL,
        ciphertext BYTEA,
        indexed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (chain_type, chain_id, railgun_contract, tree_number, tree_position)
    )
    ",
    r"
    CREATE TABLE IF NOT EXISTS indexed_shield_commitments (
        chain_type SMALLINT NOT NULL,
        chain_id BIGINT NOT NULL,
        railgun_contract TEXT NOT NULL,
        block_number BIGINT NOT NULL,
        block_timestamp BIGINT,
        block_hash BYTEA NOT NULL,
        transaction_hash BYTEA NOT NULL,
        log_index BIGINT NOT NULL,
        tree_number BIGINT NOT NULL,
        tree_position BIGINT NOT NULL,
        commitment_hash BYTEA NOT NULL,
        preimage BYTEA NOT NULL,
        shield_ciphertext BYTEA NOT NULL,
        indexed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (chain_type, chain_id, railgun_contract, tree_number, tree_position)
    )
    ",
    r"
    CREATE TABLE IF NOT EXISTS indexed_nullifiers (
        chain_type SMALLINT NOT NULL,
        chain_id BIGINT NOT NULL,
        railgun_contract TEXT NOT NULL,
        block_number BIGINT NOT NULL,
        block_timestamp BIGINT,
        block_hash BYTEA NOT NULL,
        transaction_hash BYTEA NOT NULL,
        log_index BIGINT NOT NULL,
        tree_number BIGINT NOT NULL,
        nullifier BYTEA NOT NULL,
        indexed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (chain_type, chain_id, railgun_contract, tree_number, nullifier)
    )
    ",
    r"
    CREATE TABLE IF NOT EXISTS indexed_legacy_encrypted_commitments (
        chain_type SMALLINT NOT NULL,
        chain_id BIGINT NOT NULL,
        railgun_contract TEXT NOT NULL,
        block_number BIGINT NOT NULL,
        block_timestamp BIGINT,
        block_hash BYTEA NOT NULL,
        transaction_hash BYTEA NOT NULL,
        log_index BIGINT NOT NULL,
        tree_number BIGINT NOT NULL,
        tree_position BIGINT NOT NULL,
        commitment_hash BYTEA NOT NULL,
        ciphertext BYTEA NOT NULL,
        indexed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (chain_type, chain_id, railgun_contract, tree_number, tree_position)
    )
    ",
    r"
    CREATE TABLE IF NOT EXISTS indexed_legacy_generated_commitments (
        chain_type SMALLINT NOT NULL,
        chain_id BIGINT NOT NULL,
        railgun_contract TEXT NOT NULL,
        block_number BIGINT NOT NULL,
        block_timestamp BIGINT,
        block_hash BYTEA NOT NULL,
        transaction_hash BYTEA NOT NULL,
        log_index BIGINT NOT NULL,
        tree_number BIGINT NOT NULL,
        tree_position BIGINT NOT NULL,
        commitment_hash BYTEA NOT NULL,
        preimage BYTEA NOT NULL,
        encrypted_random BYTEA NOT NULL,
        indexed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (chain_type, chain_id, railgun_contract, tree_number, tree_position)
    )
    ",
    r"
    DO $$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_public_tx_chain_type_check') THEN
            ALTER TABLE indexed_public_transactions
                ADD CONSTRAINT idx_public_tx_chain_type_check CHECK (chain_type = 0);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_public_tx_block_hash_len') THEN
            ALTER TABLE indexed_public_transactions
                ADD CONSTRAINT idx_public_tx_block_hash_len CHECK (octet_length(block_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_public_tx_hash_len') THEN
            ALTER TABLE indexed_public_transactions
                ADD CONSTRAINT idx_public_tx_hash_len CHECK (octet_length(transaction_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_transact_chain_type_check') THEN
            ALTER TABLE indexed_transact_commitments
                ADD CONSTRAINT idx_transact_chain_type_check CHECK (chain_type = 0);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_transact_block_hash_len') THEN
            ALTER TABLE indexed_transact_commitments
                ADD CONSTRAINT idx_transact_block_hash_len CHECK (octet_length(block_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_transact_tx_hash_len') THEN
            ALTER TABLE indexed_transact_commitments
                ADD CONSTRAINT idx_transact_tx_hash_len CHECK (octet_length(transaction_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_transact_commit_hash_len') THEN
            ALTER TABLE indexed_transact_commitments
                ADD CONSTRAINT idx_transact_commit_hash_len CHECK (octet_length(commitment_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_shield_chain_type_check') THEN
            ALTER TABLE indexed_shield_commitments
                ADD CONSTRAINT idx_shield_chain_type_check CHECK (chain_type = 0);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_shield_block_hash_len') THEN
            ALTER TABLE indexed_shield_commitments
                ADD CONSTRAINT idx_shield_block_hash_len CHECK (octet_length(block_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_shield_tx_hash_len') THEN
            ALTER TABLE indexed_shield_commitments
                ADD CONSTRAINT idx_shield_tx_hash_len CHECK (octet_length(transaction_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_shield_commit_hash_len') THEN
            ALTER TABLE indexed_shield_commitments
                ADD CONSTRAINT idx_shield_commit_hash_len CHECK (octet_length(commitment_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_nullifier_chain_type_check') THEN
            ALTER TABLE indexed_nullifiers
                ADD CONSTRAINT idx_nullifier_chain_type_check CHECK (chain_type = 0);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_nullifier_block_hash_len') THEN
            ALTER TABLE indexed_nullifiers
                ADD CONSTRAINT idx_nullifier_block_hash_len CHECK (octet_length(block_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_nullifier_tx_hash_len') THEN
            ALTER TABLE indexed_nullifiers
                ADD CONSTRAINT idx_nullifier_tx_hash_len CHECK (octet_length(transaction_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_nullifier_len') THEN
            ALTER TABLE indexed_nullifiers
                ADD CONSTRAINT idx_nullifier_len CHECK (octet_length(nullifier) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_legacy_enc_chain_type_check') THEN
            ALTER TABLE indexed_legacy_encrypted_commitments
                ADD CONSTRAINT idx_legacy_enc_chain_type_check CHECK (chain_type = 0);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_legacy_enc_block_hash_len') THEN
            ALTER TABLE indexed_legacy_encrypted_commitments
                ADD CONSTRAINT idx_legacy_enc_block_hash_len CHECK (octet_length(block_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_legacy_enc_tx_hash_len') THEN
            ALTER TABLE indexed_legacy_encrypted_commitments
                ADD CONSTRAINT idx_legacy_enc_tx_hash_len CHECK (octet_length(transaction_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_legacy_enc_commit_hash_len') THEN
            ALTER TABLE indexed_legacy_encrypted_commitments
                ADD CONSTRAINT idx_legacy_enc_commit_hash_len CHECK (octet_length(commitment_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_legacy_gen_chain_type_check') THEN
            ALTER TABLE indexed_legacy_generated_commitments
                ADD CONSTRAINT idx_legacy_gen_chain_type_check CHECK (chain_type = 0);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_legacy_gen_block_hash_len') THEN
            ALTER TABLE indexed_legacy_generated_commitments
                ADD CONSTRAINT idx_legacy_gen_block_hash_len CHECK (octet_length(block_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_legacy_gen_tx_hash_len') THEN
            ALTER TABLE indexed_legacy_generated_commitments
                ADD CONSTRAINT idx_legacy_gen_tx_hash_len CHECK (octet_length(transaction_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_legacy_gen_commit_hash_len') THEN
            ALTER TABLE indexed_legacy_generated_commitments
                ADD CONSTRAINT idx_legacy_gen_commit_hash_len CHECK (octet_length(commitment_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_legacy_gen_random_len') THEN
            ALTER TABLE indexed_legacy_generated_commitments
                ADD CONSTRAINT idx_legacy_gen_random_len CHECK (octet_length(encrypted_random) = 64);
        END IF;
    END $$
    ",
    "CREATE INDEX IF NOT EXISTS idx_public_tx_block_lookup ON indexed_public_transactions (chain_type, chain_id, railgun_contract, block_number, first_log_index)",
    "CREATE INDEX IF NOT EXISTS idx_transact_block_lookup ON indexed_transact_commitments (chain_type, chain_id, railgun_contract, block_number, log_index)",
    "CREATE INDEX IF NOT EXISTS idx_transact_tree_lookup ON indexed_transact_commitments (chain_type, chain_id, railgun_contract, tree_number, tree_position)",
    "CREATE INDEX IF NOT EXISTS idx_shield_block_lookup ON indexed_shield_commitments (chain_type, chain_id, railgun_contract, block_number, log_index)",
    "CREATE INDEX IF NOT EXISTS idx_shield_tree_lookup ON indexed_shield_commitments (chain_type, chain_id, railgun_contract, tree_number, tree_position)",
    "CREATE INDEX IF NOT EXISTS idx_nullifier_block_lookup ON indexed_nullifiers (chain_type, chain_id, railgun_contract, block_number, log_index)",
    "CREATE INDEX IF NOT EXISTS idx_legacy_enc_block_lookup ON indexed_legacy_encrypted_commitments (chain_type, chain_id, railgun_contract, block_number, log_index)",
    "CREATE INDEX IF NOT EXISTS idx_legacy_enc_tree_lookup ON indexed_legacy_encrypted_commitments (chain_type, chain_id, railgun_contract, tree_number, tree_position)",
    "CREATE INDEX IF NOT EXISTS idx_legacy_gen_block_lookup ON indexed_legacy_generated_commitments (chain_type, chain_id, railgun_contract, block_number, log_index)",
    "CREATE INDEX IF NOT EXISTS idx_legacy_gen_tree_lookup ON indexed_legacy_generated_commitments (chain_type, chain_id, railgun_contract, tree_number, tree_position)",
];

const V8_MIGRATIONS: &[&str] = &[
    r"
    CREATE TABLE IF NOT EXISTS published_indexed_artifacts (
        id BIGSERIAL PRIMARY KEY,
        artifact_kind TEXT NOT NULL,
        dataset_kind TEXT NOT NULL,
        chain_type SMALLINT NOT NULL,
        chain_id BIGINT NOT NULL,
        railgun_contract TEXT NOT NULL,
        range_kind TEXT NOT NULL,
        range_start BIGINT NOT NULL,
        range_end BIGINT NOT NULL,
        cid TEXT NOT NULL,
        byte_size BIGINT NOT NULL,
        content_hash BYTEA NOT NULL,
        format_version INTEGER NOT NULL,
        published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_referenced_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        unpinned_at TIMESTAMPTZ,
        UNIQUE (
            artifact_kind, dataset_kind, chain_type, chain_id, railgun_contract,
            range_kind, range_start, range_end, cid
        )
    )
    ",
    r"
    CREATE TABLE IF NOT EXISTS published_indexed_manifests (
        id BIGSERIAL PRIMARY KEY,
        cid TEXT NOT NULL,
        ipns_sequence BIGINT NOT NULL,
        byte_size BIGINT NOT NULL,
        content_hash BYTEA NOT NULL,
        format_version INTEGER NOT NULL,
        published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        ipns_published_at TIMESTAMPTZ,
        superseded_at TIMESTAMPTZ,
        unpinned_at TIMESTAMPTZ
    )
    ",
    r"
    DO $$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'published_indexed_artifacts_kind_check') THEN
            ALTER TABLE published_indexed_artifacts
                ADD CONSTRAINT published_indexed_artifacts_kind_check CHECK (artifact_kind IN ('chunk', 'catalog'));
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'published_indexed_artifacts_dataset_check') THEN
            ALTER TABLE published_indexed_artifacts
                ADD CONSTRAINT published_indexed_artifacts_dataset_check CHECK (dataset_kind IN ('wallet_scan', 'commitments', 'merkle_checkpoint', 'public_txid'));
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'published_indexed_artifacts_chain_type_check') THEN
            ALTER TABLE published_indexed_artifacts
                ADD CONSTRAINT published_indexed_artifacts_chain_type_check CHECK (chain_type = 0);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'published_indexed_artifacts_range_kind_check') THEN
            ALTER TABLE published_indexed_artifacts
                ADD CONSTRAINT published_indexed_artifacts_range_kind_check CHECK (range_kind IN ('block', 'txid_index', 'tree_position', 'poi_event_index'));
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'published_indexed_artifacts_range_order_check') THEN
            ALTER TABLE published_indexed_artifacts
                ADD CONSTRAINT published_indexed_artifacts_range_order_check CHECK (range_start <= range_end);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'published_indexed_artifacts_hash_len_check') THEN
            ALTER TABLE published_indexed_artifacts
                ADD CONSTRAINT published_indexed_artifacts_hash_len_check CHECK (octet_length(content_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'published_indexed_manifests_hash_len_check') THEN
            ALTER TABLE published_indexed_manifests
                ADD CONSTRAINT published_indexed_manifests_hash_len_check CHECK (octet_length(content_hash) = 32);
        END IF;
    END $$
    ",
    "CREATE INDEX IF NOT EXISTS published_indexed_artifacts_lookup ON published_indexed_artifacts (dataset_kind, chain_type, chain_id, railgun_contract, range_kind, range_start, range_end)",
    "CREATE INDEX IF NOT EXISTS published_indexed_artifacts_cid_live_lookup ON published_indexed_artifacts (cid) WHERE unpinned_at IS NULL",
    "CREATE INDEX IF NOT EXISTS published_indexed_manifests_retention_lookup ON published_indexed_manifests (superseded_at, published_at, unpinned_at, cid) WHERE unpinned_at IS NULL",
    "CREATE INDEX IF NOT EXISTS published_indexed_manifests_cid_live_lookup ON published_indexed_manifests (cid) WHERE ipns_published_at IS NOT NULL AND superseded_at IS NULL",
];

const V9_MIGRATIONS: &[&str] = &[
    r"
    CREATE TABLE IF NOT EXISTS indexed_public_txid_rows (
        chain_type SMALLINT NOT NULL,
        chain_id BIGINT NOT NULL,
        railgun_contract TEXT NOT NULL,
        block_number BIGINT NOT NULL,
        block_timestamp BIGINT NOT NULL,
        block_hash BYTEA NOT NULL,
        transaction_hash BYTEA NOT NULL,
        first_log_index BIGINT NOT NULL,
        last_log_index BIGINT NOT NULL,
        railgun_transaction_index BIGINT NOT NULL,
        row_id TEXT NOT NULL,
        merkle_root BYTEA NOT NULL,
        nullifiers BYTEA NOT NULL,
        commitments BYTEA NOT NULL,
        bound_params_hash BYTEA NOT NULL,
        has_unshield BOOLEAN NOT NULL,
        utxo_tree_in BIGINT NOT NULL,
        utxo_tree_out BIGINT NOT NULL,
        utxo_batch_start_position_out BIGINT NOT NULL,
        indexed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (chain_type, chain_id, railgun_contract, transaction_hash, railgun_transaction_index)
    )
    ",
    r"
    DO $$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_public_txid_rows_chain_type_check') THEN
            ALTER TABLE indexed_public_txid_rows
                ADD CONSTRAINT idx_public_txid_rows_chain_type_check CHECK (chain_type = 0);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_public_txid_rows_block_hash_len') THEN
            ALTER TABLE indexed_public_txid_rows
                ADD CONSTRAINT idx_public_txid_rows_block_hash_len CHECK (octet_length(block_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_public_txid_rows_tx_hash_len') THEN
            ALTER TABLE indexed_public_txid_rows
                ADD CONSTRAINT idx_public_txid_rows_tx_hash_len CHECK (octet_length(transaction_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_public_txid_rows_merkle_root_len') THEN
            ALTER TABLE indexed_public_txid_rows
                ADD CONSTRAINT idx_public_txid_rows_merkle_root_len CHECK (octet_length(merkle_root) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_public_txid_rows_nullifiers_len') THEN
            ALTER TABLE indexed_public_txid_rows
                ADD CONSTRAINT idx_public_txid_rows_nullifiers_len CHECK (octet_length(nullifiers) % 32 = 0);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_public_txid_rows_commitments_len') THEN
            ALTER TABLE indexed_public_txid_rows
                ADD CONSTRAINT idx_public_txid_rows_commitments_len CHECK (octet_length(commitments) % 32 = 0);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idx_public_txid_rows_bound_hash_len') THEN
            ALTER TABLE indexed_public_txid_rows
                ADD CONSTRAINT idx_public_txid_rows_bound_hash_len CHECK (octet_length(bound_params_hash) = 32);
        END IF;
    END $$
    ",
    "CREATE INDEX IF NOT EXISTS idx_public_txid_rows_order ON indexed_public_txid_rows (chain_type, chain_id, railgun_contract, block_number, first_log_index, transaction_hash, railgun_transaction_index)",
];

const V10_MIGRATIONS: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS published_indexed_artifacts_retention_lookup ON published_indexed_artifacts (last_referenced_at, cid) WHERE unpinned_at IS NULL",
];

const V11_MIGRATIONS: &[&str] = &[
    r"
    CREATE TABLE IF NOT EXISTS published_indexed_manifest_artifacts (
        manifest_id BIGINT NOT NULL REFERENCES published_indexed_manifests(id) ON DELETE CASCADE,
        artifact_cid TEXT NOT NULL,
        PRIMARY KEY (manifest_id, artifact_cid)
    )
    ",
    "CREATE INDEX IF NOT EXISTS published_indexed_manifest_artifacts_cid_lookup ON published_indexed_manifest_artifacts (artifact_cid, manifest_id)",
    r"
    INSERT INTO published_indexed_manifest_artifacts (manifest_id, artifact_cid)
    SELECT manifest.id, artifact.cid
    FROM published_indexed_manifests AS manifest
    CROSS JOIN (
        SELECT DISTINCT cid
        FROM published_indexed_artifacts
        WHERE unpinned_at IS NULL
    ) AS artifact
    WHERE manifest.superseded_at IS NULL
        AND manifest.unpinned_at IS NULL
    ON CONFLICT (manifest_id, artifact_cid) DO NOTHING
    ",
];

fn decode_fixed_hex<const N: usize>(
    field: &'static str,
    value: &str,
) -> Result<[u8; N], StoreError> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|source| StoreError::Hex { field, source })?;
    exact_array(field, &bytes)
}

fn exact_array<const N: usize>(field: &'static str, bytes: &[u8]) -> Result<[u8; N], StoreError> {
    bytes.try_into().map_err(|_| StoreError::HexLength {
        field,
        expected: N,
        actual: bytes.len(),
    })
}

fn fixed_bytes_vec(field: &'static str, bytes: &[u8]) -> Result<Vec<[u8; 32]>, StoreError> {
    if !bytes.len().is_multiple_of(32) {
        return Err(StoreError::HexLength {
            field,
            expected: (bytes.len() / 32 + 1) * 32,
            actual: bytes.len(),
        });
    }
    bytes
        .chunks_exact(32)
        .map(|chunk| exact_array(field, chunk))
        .collect()
}

fn flatten_fixed_bytes(values: &[FixedBytes<32>]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(values.len().saturating_mul(32));
    for value in values {
        bytes.extend_from_slice(value.as_slice());
    }
    bytes
}

fn u64_to_i64(value: u64, field: &'static str) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::IntegerOutOfRange {
        field,
        value: value.to_string(),
    })
}

fn i64_to_u64(value: i64, field: &'static str) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::IntegerOutOfRange {
        field,
        value: value.to_string(),
    })
}

fn i64_to_u32(value: i64, field: &'static str) -> Result<u32, StoreError> {
    u32::try_from(value).map_err(|_| StoreError::IntegerOutOfRange {
        field,
        value: value.to_string(),
    })
}

fn indexed_source_row(
    block_number: i64,
    block_timestamp: Option<i64>,
    block_hash: &[u8],
    transaction_hash: &[u8],
    log_index: i64,
) -> Result<StoredIndexedLogSourceRow, StoreError> {
    Ok(StoredIndexedLogSourceRow {
        block_number: i64_to_u64(block_number, "block_number")?,
        block_timestamp: block_timestamp
            .map(|value| i64_to_u64(value, "block_timestamp"))
            .transpose()?,
        block_hash: exact_array("block_hash", block_hash)?,
        transaction_hash: exact_array("transaction_hash", transaction_hash)?,
        log_index: i64_to_u64(log_index, "log_index")?,
    })
}

fn global_tree_position(tree_number: u32, tree_position: u64) -> Result<u64, StoreError> {
    u64::from(tree_number)
        .checked_mul(TREE_LEAF_COUNT)
        .and_then(|tree_offset| tree_offset.checked_add(tree_position))
        .ok_or_else(|| StoreError::IntegerOutOfRange {
            field: "global_tree_position",
            value: format!("tree={tree_number} position={tree_position}"),
        })
}

fn i64_to_system_time(value: i64, field: &'static str) -> Result<SystemTime, StoreError> {
    let seconds = i64_to_u64(value, field)?;
    Ok(UNIX_EPOCH + Duration::from_secs(seconds))
}

fn parse_snapshot_kind(value: &str) -> Result<SnapshotKind, StoreError> {
    match value {
        "base" => Ok(SnapshotKind::Base),
        "delta" => Ok(SnapshotKind::Delta),
        _ => Err(StoreError::InvalidSnapshotKind(value.to_string())),
    }
}

fn parse_commitment_family(value: &str) -> Result<StoredCommitmentFamily, StoreError> {
    match value {
        "transact" => Ok(StoredCommitmentFamily::Transact),
        "shield" => Ok(StoredCommitmentFamily::Shield),
        "legacy_encrypted" => Ok(StoredCommitmentFamily::LegacyEncrypted),
        "legacy_generated" => Ok(StoredCommitmentFamily::LegacyGenerated),
        _ => Err(StoreError::InvalidCommitmentFamily(value.to_string())),
    }
}

const fn event_type_discriminant(event_type: PoiEventType) -> i16 {
    match event_type {
        PoiEventType::Shield => 0,
        PoiEventType::Transact => 1,
        PoiEventType::Unshield => 2,
        PoiEventType::LegacyTransact => 3,
    }
}

const fn event_type_from_discriminant(value: i16) -> Result<PoiEventType, StoreError> {
    match value {
        0 => Ok(PoiEventType::Shield),
        1 => Ok(PoiEventType::Transact),
        2 => Ok(PoiEventType::Unshield),
        3 => Ok(PoiEventType::LegacyTransact),
        _ => Err(StoreError::InvalidEventType(value)),
    }
}
