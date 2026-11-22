//! Amount statistics derived from the shield and unshield rows the indexer
//! already holds, aggregated into the shared snapshot types.

use std::collections::BTreeMap;

use alloy::primitives::{Address, FixedBytes, U256};
use alloy::providers::Provider;
use alloy::sol_types::SolValue;
use broadcaster_core::contracts::railgun::CommitmentPreimage;
use railgun_indexed_artifacts::{
    AMOUNT_STATISTICS_SNAPSHOT_ENCODING_VERSION, AmountStatisticsCoveredBlock,
    AmountStatisticsSnapshot, ChainScope, ChainType, RepeatedShieldAmount, RepeatedUnshieldAmount,
    ShieldValueBucketCount, TokenAmountStatistics, TreeShieldAmountCount, TreeShieldValueBuckets,
    amount_value_bucket,
};
use sqlx::{PgPool, Postgres, Transaction};
use thiserror::Error;

use crate::audit::ChainCanonicalityLease;
use crate::chain_logs::{ChainLogIngestionError, block_timestamp_for_source};
use crate::store::IndexedDatasetKind;

const ERC20_TOKEN_TYPE: u8 = 0;
const WINDOW_24H_SECONDS: u64 = 86_400;
const WINDOW_30D_SECONDS: u64 = 30 * WINDOW_24H_SECONDS;

/// A counted shield: an ERC-20 note at or below the covered block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShieldRecord {
    pub token: Address,
    /// Note value in the commitment preimage, after the shield fee.
    pub value: U256,
    pub tree: u32,
    /// Unix seconds.
    pub timestamp: u64,
}

/// A counted unshield: an ERC-20 unshield preimage at or below the covered block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnshieldRecord {
    pub token: Address,
    /// Note value in the unshield preimage: amount received plus the unshield fee.
    pub value: U256,
    /// Unix seconds.
    pub timestamp: u64,
}

/// Counted records at one covered height. The indexer stores no block
/// timestamps, so [`derive_amount_statistics`] fetches the covered block's by hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmountStatisticsRecords {
    pub covered_block_number: u64,
    pub covered_block_hash: FixedBytes<32>,
    pub shields: Vec<ShieldRecord>,
    pub unshields: Vec<UnshieldRecord>,
}

/// Derives a chain's snapshot at the lower of its shield and public TXID
/// indexed heights. The caller keeps `lease` until it has published the
/// snapshot, so no reorg rewind removes a counted record in between.
pub async fn derive_amount_statistics<P: Provider + ?Sized>(
    pool: &PgPool,
    provider: &P,
    scope: &ChainScope,
    lease: &ChainCanonicalityLease,
) -> Result<AmountStatisticsSnapshot, AmountStatisticsDerivationError> {
    let records = read_amount_statistics_records(pool, scope, lease).await?;
    let timestamp = block_timestamp_for_source(
        provider,
        records.covered_block_hash,
        records.covered_block_number,
    )
    .await
    .map_err(AmountStatisticsDerivationError::CoveredBlockTimestamp)?;
    Ok(aggregate_amount_statistics(
        scope.clone(),
        AmountStatisticsCoveredBlock {
            number: records.covered_block_number,
            hash: records.covered_block_hash,
            timestamp,
        },
        &records.shields,
        &records.unshields,
    ))
}

/// Reads the covered height and every counted shield and unshield at or below
/// it in one repeatable-read transaction, so all three reads see one state.
pub async fn read_amount_statistics_records(
    pool: &PgPool,
    scope: &ChainScope,
    _lease: &ChainCanonicalityLease,
) -> Result<AmountStatisticsRecords, AmountStatisticsDerivationError> {
    let chain = ChainRows::new(scope)?;
    let mut tx = begin_read_snapshot(pool).await?;
    let (through_block, covered_block_hash) = chain.covered_height(&mut tx).await?;
    let records = chain
        .records(&mut tx, through_block, covered_block_hash)
        .await?;
    tx.commit().await?;
    Ok(records)
}

/// Reads every counted shield and unshield at or below a published snapshot's
/// covered block, to recompute that snapshot, and whether an indexed header
/// confirmed the covered hash. The same repeatable-read transaction checks the
/// indexed heights and header, so it needs no publication lease.
pub async fn read_amount_statistics_records_at(
    pool: &PgPool,
    scope: &ChainScope,
    covered_block: &AmountStatisticsCoveredBlock,
) -> Result<(AmountStatisticsRecords, bool), AmountStatisticsDerivationError> {
    let chain = ChainRows::new(scope)?;
    let through_block = i64::try_from(covered_block.number)
        .map_err(|_| chain.invalid_column("covered_block_number"))?;
    let mut tx = begin_read_snapshot(pool).await?;
    let hash_checked = chain
        .check_covered_block(&mut tx, through_block, covered_block)
        .await?;
    let records = chain
        .records(&mut tx, through_block, covered_block.hash)
        .await?;
    tx.commit().await?;
    Ok((records, hash_checked))
}

async fn begin_read_snapshot(pool: &PgPool) -> Result<Transaction<'static, Postgres>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

/// Bind values for one chain's rows, and the chain id its errors name.
struct ChainRows {
    chain_id: u64,
    chain_type_param: i16,
    chain_id_param: i64,
    railgun_contract: String,
}

impl ChainRows {
    fn new(scope: &ChainScope) -> Result<Self, AmountStatisticsDerivationError> {
        let chain_type_param = match scope.chain_type {
            ChainType::Evm => 0,
        };
        let chain_id_param = i64::try_from(scope.chain_id).map_err(|_| {
            AmountStatisticsDerivationError::InvalidColumn {
                chain_id: scope.chain_id,
                field: "chain_id",
            }
        })?;
        Ok(Self {
            chain_id: scope.chain_id,
            chain_type_param,
            chain_id_param,
            railgun_contract: scope.railgun_contract.to_string(),
        })
    }

    const fn invalid_column(&self, field: &'static str) -> AmountStatisticsDerivationError {
        AmountStatisticsDerivationError::InvalidColumn {
            chain_id: self.chain_id,
            field,
        }
    }

    fn unsigned(
        &self,
        value: i64,
        field: &'static str,
    ) -> Result<u64, AmountStatisticsDerivationError> {
        u64::try_from(value).map_err(|_| self.invalid_column(field))
    }

    /// The lower of the shield (wallet scan) and public TXID indexed heights,
    /// which both datasets have reached.
    async fn covered_height(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<(i64, FixedBytes<32>), AmountStatisticsDerivationError> {
        let heights = sqlx::query_as::<_, (i64, Vec<u8>)>(
            r"
            SELECT indexed_through_block, indexed_through_block_hash
            FROM chain_indexing_progress
            WHERE chain_type = $1
                AND chain_id = $2
                AND railgun_contract = $3
                AND dataset_kind IN ($4, $5)
            ORDER BY indexed_through_block, dataset_kind
            ",
        )
        .bind(self.chain_type_param)
        .bind(self.chain_id_param)
        .bind(&self.railgun_contract)
        .bind(IndexedDatasetKind::WalletScan.as_str())
        .bind(IndexedDatasetKind::PublicTxid.as_str())
        .fetch_all(&mut **tx)
        .await?;
        let [(number, hash), _] = heights.as_slice() else {
            return Err(AmountStatisticsDerivationError::NotIndexed {
                chain_id: self.chain_id,
            });
        };
        let hash = FixedBytes::try_from(hash.as_slice())
            .map_err(|_| self.invalid_column("indexed_through_block_hash"))?;
        Ok((*number, hash))
    }

    /// Fails when either dataset is indexed only below the covered block, which
    /// a rewind past it causes, or when the indexed header at that number has
    /// another hash. Returns false when there is no header to check: the
    /// indexer records one only where an indexing range ended.
    async fn check_covered_block(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        through_block: i64,
        covered_block: &AmountStatisticsCoveredBlock,
    ) -> Result<bool, AmountStatisticsDerivationError> {
        let (indexed_through, _) = self.covered_height(tx).await?;
        if indexed_through < through_block {
            return Err(AmountStatisticsDerivationError::CoveredBlockNotIndexed {
                chain_id: self.chain_id,
                block_number: covered_block.number,
                indexed_through: self.unsigned(indexed_through, "indexed_through_block")?,
            });
        }
        let Some(indexed) = sqlx::query_scalar::<_, Vec<u8>>(
            r"
            SELECT block_hash
            FROM indexed_block_headers
            WHERE chain_type = $1 AND chain_id = $2 AND block_number = $3
            ",
        )
        .bind(self.chain_type_param)
        .bind(self.chain_id_param)
        .bind(through_block)
        .fetch_optional(&mut **tx)
        .await?
        else {
            return Ok(false);
        };
        let indexed = FixedBytes::try_from(indexed.as_slice())
            .map_err(|_| self.invalid_column("block_hash"))?;
        if indexed != covered_block.hash {
            return Err(AmountStatisticsDerivationError::CoveredBlockHashMismatch {
                chain_id: self.chain_id,
                block_number: covered_block.number,
                covered: covered_block.hash,
                indexed,
            });
        }
        Ok(true)
    }

    async fn records(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        through_block: i64,
        covered_block_hash: FixedBytes<32>,
    ) -> Result<AmountStatisticsRecords, AmountStatisticsDerivationError> {
        Ok(AmountStatisticsRecords {
            covered_block_number: self.unsigned(through_block, "indexed_through_block")?,
            covered_block_hash,
            shields: self.shields(tx, through_block).await?,
            unshields: self.unshields(tx, through_block).await?,
        })
    }

    async fn shields(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        through_block: i64,
    ) -> Result<Vec<ShieldRecord>, AmountStatisticsDerivationError> {
        let rows = sqlx::query_as::<_, (i64, i64, Option<i64>, Vec<u8>)>(
            r"
            SELECT tree_number, block_number, block_timestamp, preimage
            FROM indexed_shield_commitments
            WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3 AND block_number <= $4
            UNION ALL
            SELECT tree_number, block_number, block_timestamp, preimage
            FROM indexed_legacy_generated_commitments
            WHERE chain_type = $1 AND chain_id = $2 AND railgun_contract = $3 AND block_number <= $4
            ",
        )
        .bind(self.chain_type_param)
        .bind(self.chain_id_param)
        .bind(&self.railgun_contract)
        .bind(through_block)
        .fetch_all(&mut **tx)
        .await?;
        let mut shields = Vec::with_capacity(rows.len());
        for (tree, block_number, timestamp, preimage) in rows {
            let block_number = self.unsigned(block_number, "block_number")?;
            let Some((token, value)) = erc20_note(&preimage).map_err(|_| {
                AmountStatisticsDerivationError::InvalidPreimage {
                    chain_id: self.chain_id,
                    section: "shield",
                    block_number,
                }
            })?
            else {
                continue;
            };
            let timestamp =
                timestamp.ok_or(AmountStatisticsDerivationError::MissingShieldTimestamp {
                    chain_id: self.chain_id,
                    block_number,
                })?;
            shields.push(ShieldRecord {
                token,
                value,
                tree: u32::try_from(tree).map_err(|_| self.invalid_column("tree_number"))?,
                timestamp: self.unsigned(timestamp, "block_timestamp")?,
            });
        }
        Ok(shields)
    }

    async fn unshields(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        through_block: i64,
    ) -> Result<Vec<UnshieldRecord>, AmountStatisticsDerivationError> {
        let rows = sqlx::query_as::<_, (i64, i64, Option<Vec<u8>>)>(
            r"
            SELECT block_number, block_timestamp, unshield_preimage
            FROM indexed_public_txid_rows
            WHERE chain_type = $1
                AND chain_id = $2
                AND railgun_contract = $3
                AND has_unshield
                AND block_number <= $4
            ",
        )
        .bind(self.chain_type_param)
        .bind(self.chain_id_param)
        .bind(&self.railgun_contract)
        .bind(through_block)
        .fetch_all(&mut **tx)
        .await?;
        let mut unshields = Vec::with_capacity(rows.len());
        for (block_number, timestamp, preimage) in rows {
            let block_number = self.unsigned(block_number, "block_number")?;
            let preimage =
                preimage.ok_or(AmountStatisticsDerivationError::MissingUnshieldPreimage {
                    chain_id: self.chain_id,
                    block_number,
                })?;
            let Some((token, value)) = erc20_note(&preimage).map_err(|_| {
                AmountStatisticsDerivationError::InvalidPreimage {
                    chain_id: self.chain_id,
                    section: "unshield",
                    block_number,
                }
            })?
            else {
                continue;
            };
            unshields.push(UnshieldRecord {
                token,
                value,
                timestamp: self.unsigned(timestamp, "block_timestamp")?,
            });
        }
        Ok(unshields)
    }
}

/// Token and note value of an ABI-encoded ERC-20 preimage, or `None` for
/// another token type. Legacy generated commitments store
/// `(uint256 npk, TokenData, uint120 value)`, which encodes to the same bytes
/// as `CommitmentPreimage`, so this decodes both shield tables and unshields.
fn erc20_note(encoded: &[u8]) -> Result<Option<(Address, U256)>, alloy::sol_types::Error> {
    let preimage = CommitmentPreimage::abi_decode(encoded)?;
    Ok((preimage.token.tokenType == ERC20_TOKEN_TYPE)
        .then(|| (preimage.token.tokenAddress, U256::from(preimage.value))))
}

/// Builds the snapshot from counted records. Windows end at the covered
/// block's timestamp, and the output depends only on the inputs, not their order.
#[must_use]
pub fn aggregate_amount_statistics(
    scope: ChainScope,
    covered_block: AmountStatisticsCoveredBlock,
    shields: &[ShieldRecord],
    unshields: &[UnshieldRecord],
) -> AmountStatisticsSnapshot {
    let windows = Windows::ending_at(covered_block.timestamp);
    let mut tokens = BTreeMap::<Address, TokenAccumulator>::new();
    for shield in shields {
        tokens
            .entry(shield.token)
            .or_default()
            .add_shield(shield, windows);
    }
    // Only tokens with a counted shield are listed, so other unshields drop out.
    for unshield in unshields {
        if let Some(token) = tokens.get_mut(&unshield.token) {
            token.add_unshield(unshield, windows);
        }
    }
    AmountStatisticsSnapshot {
        encoding_version: AMOUNT_STATISTICS_SNAPSHOT_ENCODING_VERSION,
        scope,
        covered_block,
        tokens: tokens
            .into_iter()
            .map(|(token, accumulator)| accumulator.finish(token))
            .collect(),
    }
}

/// A record is inside a window when its timestamp is after the window's start.
#[derive(Clone, Copy)]
struct Windows {
    last_24h_after: u64,
    last_30d_after: u64,
}

impl Windows {
    const fn ending_at(timestamp: u64) -> Self {
        Self {
            last_24h_after: timestamp.saturating_sub(WINDOW_24H_SECONDS),
            last_30d_after: timestamp.saturating_sub(WINDOW_30D_SECONDS),
        }
    }
}

#[derive(Default)]
struct TokenAccumulator {
    shielded: U256,
    unshielded: U256,
    shields_last_24h: u64,
    shields_last_30d: u64,
    unshields_last_24h: u64,
    unshields_last_30d: u64,
    /// Note value, then tree, to (all time, last 30 days) shield counts.
    shield_amounts: BTreeMap<U256, BTreeMap<u32, (u64, u64)>>,
    /// Tree, then bucket, to shield count.
    shield_buckets: BTreeMap<u32, BTreeMap<u16, u64>>,
    /// Note value to unshield count in the last 30 days.
    recent_unshield_amounts: BTreeMap<U256, u64>,
}

impl TokenAccumulator {
    fn add_shield(&mut self, shield: &ShieldRecord, windows: Windows) {
        let in_last_30d = u64::from(shield.timestamp > windows.last_30d_after);
        self.shielded = self.shielded.saturating_add(shield.value);
        self.shields_last_24h += u64::from(shield.timestamp > windows.last_24h_after);
        self.shields_last_30d += in_last_30d;
        let (all_time, last_30d) = self
            .shield_amounts
            .entry(shield.value)
            .or_default()
            .entry(shield.tree)
            .or_default();
        *all_time += 1;
        *last_30d += in_last_30d;
        *self
            .shield_buckets
            .entry(shield.tree)
            .or_default()
            .entry(amount_value_bucket(shield.value))
            .or_default() += 1;
    }

    fn add_unshield(&mut self, unshield: &UnshieldRecord, windows: Windows) {
        self.unshielded = self.unshielded.saturating_add(unshield.value);
        self.unshields_last_24h += u64::from(unshield.timestamp > windows.last_24h_after);
        if unshield.timestamp > windows.last_30d_after {
            self.unshields_last_30d += 1;
            *self
                .recent_unshield_amounts
                .entry(unshield.value)
                .or_default() += 1;
        }
    }

    fn finish(self, token: Address) -> TokenAmountStatistics {
        let repeated_shield_amounts = self
            .shield_amounts
            .into_iter()
            .filter(|(_, trees)| trees.values().map(|(all_time, _)| all_time).sum::<u64>() >= 2)
            .map(|(value, trees)| RepeatedShieldAmount {
                value,
                trees: trees
                    .into_iter()
                    .map(|(tree, (all_time, last_30d))| TreeShieldAmountCount {
                        tree,
                        all_time,
                        last_30d,
                    })
                    .collect(),
            })
            .collect();
        let shield_value_buckets = self
            .shield_buckets
            .into_iter()
            .map(|(tree, buckets)| TreeShieldValueBuckets {
                tree,
                buckets: buckets
                    .into_iter()
                    .map(|(bit_length, count)| ShieldValueBucketCount { bit_length, count })
                    .collect(),
            })
            .collect();
        let repeated_unshield_amounts = self
            .recent_unshield_amounts
            .into_iter()
            .filter(|(_, count)| *count >= 2)
            .map(|(value, last_30d)| RepeatedUnshieldAmount { value, last_30d })
            .collect();
        TokenAmountStatistics {
            token,
            pool_balance: self.shielded.saturating_sub(self.unshielded),
            shields_last_24h: self.shields_last_24h,
            shields_last_30d: self.shields_last_30d,
            unshields_last_24h: self.unshields_last_24h,
            unshields_last_30d: self.unshields_last_30d,
            repeated_shield_amounts,
            shield_value_buckets,
            repeated_unshield_amounts,
        }
    }
}

#[derive(Debug, Error)]
pub enum AmountStatisticsDerivationError {
    #[error("chain {chain_id} lacks a shield or public TXID indexed height")]
    NotIndexed { chain_id: u64 },
    #[error(
        "chain {chain_id} is indexed only through block {indexed_through}, below covered block {block_number}, so records up to the covered block cannot be read"
    )]
    CoveredBlockNotIndexed {
        chain_id: u64,
        block_number: u64,
        indexed_through: u64,
    },
    #[error(
        "chain {chain_id} covered block {block_number} has hash {covered}, but the indexed canonical header has {indexed}"
    )]
    CoveredBlockHashMismatch {
        chain_id: u64,
        block_number: u64,
        covered: FixedBytes<32>,
        indexed: FixedBytes<32>,
    },
    #[error("chain {chain_id} shield at block {block_number} is missing block_timestamp")]
    MissingShieldTimestamp { chain_id: u64, block_number: u64 },
    #[error("chain {chain_id} unshield at block {block_number} is missing its unshield preimage")]
    MissingUnshieldPreimage { chain_id: u64, block_number: u64 },
    #[error("chain {chain_id} {section} preimage at block {block_number} does not decode")]
    InvalidPreimage {
        chain_id: u64,
        section: &'static str,
        block_number: u64,
    },
    #[error("chain {chain_id} indexed {field} value is out of range")]
    InvalidColumn { chain_id: u64, field: &'static str },
    #[error("read covered block timestamp")]
    CoveredBlockTimestamp(#[source] ChainLogIngestionError),
    #[error("database operation failed")]
    Sqlx(#[from] sqlx::Error),
}

#[cfg(test)]
mod tests;
