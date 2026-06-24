use crate::manifest::{
    ChainScope, ChainType, IndexedArtifactRange, IndexedArtifactRangeKind, IndexedDatasetKind,
};
use crate::publish::ipfs::IpfsClient;
use crate::snapshot::SnapshotKind;
use alloy_primitives::{FixedBytes, hex};
use cid::Cid;
use sqlx::{PgPool, Postgres, Transaction};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{info, warn};

pub struct Audit;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexedArtifactPublicationKind {
    Chunk,
    Catalog,
}

impl Audit {
    pub async fn live_indexed_artifact_cid(
        pool: &PgPool,
        artifact_kind: IndexedArtifactPublicationKind,
        dataset_kind: IndexedDatasetKind,
        scope: &ChainScope,
        range: &IndexedArtifactRange,
        byte_size: u64,
        content_hash: &[u8; 32],
        format_version: u16,
    ) -> Result<Option<Cid>, AuditError> {
        let chain_id = u64_to_i64(scope.chain_id, "chain_id")?;
        let range_start = u64_to_i64(range.start, "range_start")?;
        let range_end = u64_to_i64(range.end, "range_end")?;
        let byte_size = u64_to_i64(byte_size, "byte_size")?;
        let format_version = i32::from(format_version);

        let cid = sqlx::query_scalar::<_, String>(
            r"
            SELECT cid
            FROM published_indexed_artifacts
            WHERE artifact_kind = $1
                AND dataset_kind = $2
                AND chain_type = $3
                AND chain_id = $4
                AND railgun_contract = $5
                AND range_kind = $6
                AND range_start = $7
                AND range_end = $8
                AND byte_size = $9
                AND content_hash = $10
                AND format_version = $11
                AND unpinned_at IS NULL
            ORDER BY last_referenced_at DESC, published_at DESC
            LIMIT 1
            ",
        )
        .bind(indexed_artifact_publication_kind_str(artifact_kind))
        .bind(indexed_dataset_kind_str(dataset_kind))
        .bind(chain_type_discriminant(scope.chain_type))
        .bind(chain_id)
        .bind(hex::encode_prefixed(scope.railgun_contract.as_slice()))
        .bind(indexed_range_kind_str(range.kind))
        .bind(range_start)
        .bind(range_end)
        .bind(byte_size)
        .bind(content_hash.as_slice())
        .bind(format_version)
        .fetch_optional(pool)
        .await?;

        cid.map(|cid| parse_cid(&cid)).transpose()
    }

    pub async fn record_publication(
        tx: &mut Transaction<'_, Postgres>,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        upstream_url: &str,
        kind: SnapshotKind,
        start_index: u64,
        end_index: u64,
        cid: &Cid,
        byte_size: u64,
        content_hash: &[u8; 32],
        format_version: u16,
        tip_merkleroot: &[u8; 32],
    ) -> Result<(), AuditError> {
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let start_index = u64_to_i64(start_index, "start_index")?;
        let end_index = u64_to_i64(end_index, "end_index")?;
        let byte_size = u64_to_i64(byte_size, "byte_size")?;
        let format_version = i32::from(format_version);

        if matches!(kind, SnapshotKind::Base) {
            sqlx::query(
                r"
                UPDATE published_snapshots
                SET superseded_at = now()
                WHERE list_key = $1
                    AND chain_id = $2
                    AND upstream_url = $3
                    AND kind = 'base'
                    AND superseded_at IS NULL
                ",
            )
            .bind(list_key.as_slice())
            .bind(chain_id)
            .bind(upstream_url)
            .execute(&mut **tx)
            .await?;
        }

        sqlx::query(
            r"
            INSERT INTO published_snapshots (
                list_key,
                chain_id,
                upstream_url,
                kind,
                start_index,
                end_index,
                cid,
                byte_size,
                content_hash,
                format_version,
                tip_merkleroot
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ",
        )
        .bind(list_key.as_slice())
        .bind(chain_id)
        .bind(upstream_url)
        .bind(snapshot_kind_str(kind))
        .bind(start_index)
        .bind(end_index)
        .bind(cid.to_string())
        .bind(byte_size)
        .bind(content_hash.as_slice())
        .bind(format_version)
        .bind(tip_merkleroot.as_slice())
        .execute(&mut **tx)
        .await?;

        Ok(())
    }

    pub async fn record_blocked_shields_publication(
        tx: &mut Transaction<'_, Postgres>,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        upstream_url: &str,
        cid: &Cid,
        byte_size: u64,
        format_version: u16,
        content_hash: &[u8; 32],
    ) -> Result<(), AuditError> {
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let byte_size = u64_to_i64(byte_size, "byte_size")?;
        let format_version = i32::from(format_version);

        sqlx::query(
            r"
            UPDATE published_blocked_shields
            SET superseded_at = now()
            WHERE list_key = $1
                AND chain_id = $2
                AND superseded_at IS NULL
            ",
        )
        .bind(list_key.as_slice())
        .bind(chain_id)
        .execute(&mut **tx)
        .await?;

        sqlx::query(
            r"
            INSERT INTO published_blocked_shields (
                list_key,
                chain_id,
                upstream_url,
                cid,
                byte_size,
                format_version,
                content_hash
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ",
        )
        .bind(list_key.as_slice())
        .bind(chain_id)
        .bind(upstream_url)
        .bind(cid.to_string())
        .bind(byte_size)
        .bind(format_version)
        .bind(content_hash.as_slice())
        .execute(&mut **tx)
        .await?;

        Ok(())
    }

    pub async fn record_manifest_pin(
        tx: &mut Transaction<'_, Postgres>,
        cid: &Cid,
        sequence: u64,
        byte_size: u64,
        content_hash: &[u8; 32],
        format_version: u16,
    ) -> Result<(), AuditError> {
        let sequence = u64_to_i64(sequence, "sequence")?;
        let byte_size = u64_to_i64(byte_size, "byte_size")?;
        let format_version = i32::from(format_version);

        sqlx::query(
            r"
            UPDATE published_manifests
            SET superseded_at = now()
            WHERE ipns_published_at IS NULL
                AND superseded_at IS NULL
            ",
        )
        .execute(&mut **tx)
        .await?;

        sqlx::query(
            r"
            INSERT INTO published_manifests (
                cid,
                ipns_sequence,
                byte_size,
                content_hash,
                format_version
            )
            VALUES ($1, $2, $3, $4, $5)
            ",
        )
        .bind(cid.to_string())
        .bind(sequence)
        .bind(byte_size)
        .bind(content_hash.as_slice())
        .bind(format_version)
        .execute(&mut **tx)
        .await?;

        Ok(())
    }

    pub async fn record_manifest_ipns_publication(
        tx: &mut Transaction<'_, Postgres>,
        cid: &Cid,
    ) -> Result<(), AuditError> {
        let cid = cid.to_string();
        let result = sqlx::query(
            r"
            UPDATE published_manifests
            SET ipns_published_at = COALESCE(ipns_published_at, now())
            WHERE cid = $1
                AND superseded_at IS NULL
                AND unpinned_at IS NULL
            ",
        )
        .bind(&cid)
        .execute(&mut **tx)
        .await?;
        if result.rows_affected() == 0 {
            let (superseded, unpinned): (bool, bool) = sqlx::query_as(
                r"
                SELECT
                    EXISTS(SELECT 1 FROM published_manifests WHERE cid = $1 AND superseded_at IS NOT NULL),
                    EXISTS(SELECT 1 FROM published_manifests WHERE cid = $1 AND unpinned_at IS NOT NULL)
                ",
            )
            .bind(&cid)
            .fetch_one(&mut **tx)
            .await?;
            if unpinned {
                return Err(AuditError::UnpinnedManifest { cid });
            }
            if superseded {
                return Err(AuditError::SupersededManifest { cid });
            }
            return Err(AuditError::UnrecordedManifest { cid });
        }

        sqlx::query(
            r"
            UPDATE published_manifests
            SET superseded_at = now()
            WHERE cid <> $1
                AND ipns_published_at IS NOT NULL
                AND superseded_at IS NULL
            ",
        )
        .bind(&cid)
        .execute(&mut **tx)
        .await?;

        Ok(())
    }

    pub async fn record_indexed_artifact_pin(
        tx: &mut Transaction<'_, Postgres>,
        artifact_kind: IndexedArtifactPublicationKind,
        dataset_kind: IndexedDatasetKind,
        scope: &ChainScope,
        range: &IndexedArtifactRange,
        cid: &Cid,
        byte_size: u64,
        content_hash: &[u8; 32],
        format_version: u16,
    ) -> Result<(), AuditError> {
        let chain_id = u64_to_i64(scope.chain_id, "chain_id")?;
        let range_start = u64_to_i64(range.start, "range_start")?;
        let range_end = u64_to_i64(range.end, "range_end")?;
        let byte_size = u64_to_i64(byte_size, "byte_size")?;
        let format_version = i32::from(format_version);

        sqlx::query(
            r"
            INSERT INTO published_indexed_artifacts (
                artifact_kind,
                dataset_kind,
                chain_type,
                chain_id,
                railgun_contract,
                range_kind,
                range_start,
                range_end,
                cid,
                byte_size,
                content_hash,
                format_version
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            ON CONFLICT (
                artifact_kind, dataset_kind, chain_type, chain_id, railgun_contract,
                range_kind, range_start, range_end, cid
            ) DO UPDATE SET
                byte_size = EXCLUDED.byte_size,
                content_hash = EXCLUDED.content_hash,
                format_version = EXCLUDED.format_version,
                last_referenced_at = now(),
                unpinned_at = NULL
            ",
        )
        .bind(indexed_artifact_publication_kind_str(artifact_kind))
        .bind(indexed_dataset_kind_str(dataset_kind))
        .bind(chain_type_discriminant(scope.chain_type))
        .bind(chain_id)
        .bind(hex::encode_prefixed(scope.railgun_contract.as_slice()))
        .bind(indexed_range_kind_str(range.kind))
        .bind(range_start)
        .bind(range_end)
        .bind(cid.to_string())
        .bind(byte_size)
        .bind(content_hash.as_slice())
        .bind(format_version)
        .execute(&mut **tx)
        .await?;

        Ok(())
    }

    pub async fn record_indexed_manifest_pin(
        tx: &mut Transaction<'_, Postgres>,
        cid: &Cid,
        sequence: u64,
        byte_size: u64,
        content_hash: &[u8; 32],
        format_version: u16,
    ) -> Result<(), AuditError> {
        let sequence = u64_to_i64(sequence, "sequence")?;
        let byte_size = u64_to_i64(byte_size, "byte_size")?;
        let format_version = i32::from(format_version);

        sqlx::query(
            r"
            UPDATE published_indexed_manifests
            SET superseded_at = now()
            WHERE ipns_published_at IS NULL
                AND superseded_at IS NULL
            ",
        )
        .execute(&mut **tx)
        .await?;

        sqlx::query(
            r"
            INSERT INTO published_indexed_manifests (
                cid,
                ipns_sequence,
                byte_size,
                content_hash,
                format_version
            )
            VALUES ($1, $2, $3, $4, $5)
            ",
        )
        .bind(cid.to_string())
        .bind(sequence)
        .bind(byte_size)
        .bind(content_hash.as_slice())
        .bind(format_version)
        .execute(&mut **tx)
        .await?;

        Ok(())
    }

    pub async fn record_indexed_manifest_ipns_publication(
        tx: &mut Transaction<'_, Postgres>,
        cid: &Cid,
    ) -> Result<(), AuditError> {
        let cid = cid.to_string();
        let result = sqlx::query(
            r"
            UPDATE published_indexed_manifests
            SET ipns_published_at = COALESCE(ipns_published_at, now())
            WHERE cid = $1
                AND superseded_at IS NULL
                AND unpinned_at IS NULL
            ",
        )
        .bind(&cid)
        .execute(&mut **tx)
        .await?;
        if result.rows_affected() == 0 {
            let (superseded, unpinned): (bool, bool) = sqlx::query_as(
                r"
                SELECT
                    EXISTS(SELECT 1 FROM published_indexed_manifests WHERE cid = $1 AND superseded_at IS NOT NULL),
                    EXISTS(SELECT 1 FROM published_indexed_manifests WHERE cid = $1 AND unpinned_at IS NOT NULL)
                ",
            )
            .bind(&cid)
            .fetch_one(&mut **tx)
            .await?;
            if unpinned {
                return Err(AuditError::UnpinnedManifest { cid });
            }
            if superseded {
                return Err(AuditError::SupersededManifest { cid });
            }
            return Err(AuditError::UnrecordedManifest { cid });
        }

        sqlx::query(
            r"
            UPDATE published_indexed_manifests
            SET superseded_at = now()
            WHERE cid <> $1
                AND ipns_published_at IS NOT NULL
                AND superseded_at IS NULL
            ",
        )
        .bind(&cid)
        .execute(&mut **tx)
        .await?;

        Ok(())
    }
}

pub struct Retention;

impl Retention {
    pub async fn sweep(
        pool: &PgPool,
        ipfs_client: &dyn IpfsClient,
        now: SystemTime,
        retention_interval: Duration,
    ) -> Result<RetentionSweep, AuditError> {
        let cutoff = unix_seconds(
            now.checked_sub(retention_interval)
                .ok_or(AuditError::TimeBeforeUnixEpoch)?,
        )?;
        let swept_at = unix_seconds(now)?;
        sqlx::query(
            r"
            UPDATE published_snapshots AS delta
            SET superseded_at = to_timestamp($2)
            WHERE delta.kind = 'delta'
                AND delta.superseded_at IS NULL
                AND EXISTS (
                    SELECT 1
                    FROM published_snapshots AS base
                    WHERE base.list_key = delta.list_key
                        AND base.chain_id = delta.chain_id
                        AND base.upstream_url = delta.upstream_url
                        AND base.kind = 'base'
                        AND base.superseded_at IS NULL
                        AND base.end_index >= delta.end_index
                        AND base.published_at <= to_timestamp($1)
                )
            ",
        )
        .bind(cutoff)
        .bind(swept_at)
        .execute(pool)
        .await?;
        let cids = sqlx::query_scalar::<_, String>(
            r"
            WITH candidates AS (
                SELECT cid
                FROM published_snapshots
                WHERE superseded_at IS NOT NULL
                    AND superseded_at <= to_timestamp($1)
                    AND unpinned_at IS NULL
                UNION
                SELECT cid
                FROM published_blocked_shields
                WHERE superseded_at IS NOT NULL
                    AND superseded_at <= to_timestamp($1)
                    AND unpinned_at IS NULL
                UNION
                SELECT cid
                FROM published_manifests
                WHERE unpinned_at IS NULL
                    AND superseded_at IS NOT NULL
                    AND superseded_at <= to_timestamp($1)
                UNION
                SELECT cid
                FROM published_indexed_manifests
                WHERE unpinned_at IS NULL
                    AND superseded_at IS NOT NULL
                    AND superseded_at <= to_timestamp($1)
            )
            SELECT DISTINCT candidates.cid
            FROM candidates
            WHERE NOT EXISTS (
                    SELECT 1
                    FROM published_snapshots AS active
                    WHERE active.cid = candidates.cid
                        AND active.superseded_at IS NULL
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM published_blocked_shields AS active
                    WHERE active.cid = candidates.cid
                        AND active.superseded_at IS NULL
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM published_manifests AS active
                    WHERE active.cid = candidates.cid
                        AND active.ipns_published_at IS NOT NULL
                        AND active.superseded_at IS NULL
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM published_indexed_manifests AS active
                    WHERE active.cid = candidates.cid
                        AND active.ipns_published_at IS NOT NULL
                        AND active.superseded_at IS NULL
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM published_indexed_artifacts AS active
                    WHERE active.cid = candidates.cid
                        AND active.unpinned_at IS NULL
                )
            ORDER BY candidates.cid ASC
            ",
        )
        .bind(cutoff)
        .fetch_all(pool)
        .await?;

        let mut unpinned_cids = Vec::with_capacity(cids.len());
        let mut failed_cids = Vec::new();
        for cid_text in cids {
            let cid = parse_cid(&cid_text)?;
            if let Err(error) = ipfs_client.unpin(&cid).await {
                warn!(cid = %cid, error = %error, "failed to unpin superseded railgun-indexer publication CID");
                failed_cids.push(RetentionFailure {
                    cid,
                    error: error.to_string(),
                });
                continue;
            }
            sqlx::query(
                r"
                UPDATE published_snapshots
                SET unpinned_at = to_timestamp($1)
                WHERE cid = $2
                    AND superseded_at IS NOT NULL
                    AND superseded_at <= to_timestamp($3)
                    AND unpinned_at IS NULL
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_snapshots AS active
                        WHERE active.cid = $2
                            AND active.superseded_at IS NULL
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_blocked_shields AS active
                        WHERE active.cid = $2
                            AND active.superseded_at IS NULL
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_manifests AS active
                        WHERE active.cid = $2
                            AND active.ipns_published_at IS NOT NULL
                            AND active.superseded_at IS NULL
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_indexed_manifests AS active
                        WHERE active.cid = $2
                            AND active.ipns_published_at IS NOT NULL
                            AND active.superseded_at IS NULL
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_indexed_artifacts AS active
                        WHERE active.cid = $2
                            AND active.unpinned_at IS NULL
                    )
                ",
            )
            .bind(swept_at)
            .bind(&cid_text)
            .bind(cutoff)
            .execute(pool)
            .await?;
            sqlx::query(
                r"
                UPDATE published_blocked_shields
                SET unpinned_at = to_timestamp($1)
                WHERE cid = $2
                    AND superseded_at IS NOT NULL
                    AND superseded_at <= to_timestamp($3)
                    AND unpinned_at IS NULL
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_snapshots AS active
                        WHERE active.cid = $2
                            AND active.superseded_at IS NULL
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_blocked_shields AS active
                        WHERE active.cid = $2
                            AND active.superseded_at IS NULL
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_manifests AS active
                        WHERE active.cid = $2
                            AND active.ipns_published_at IS NOT NULL
                            AND active.superseded_at IS NULL
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_indexed_manifests AS active
                        WHERE active.cid = $2
                            AND active.ipns_published_at IS NOT NULL
                            AND active.superseded_at IS NULL
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_indexed_artifacts AS active
                        WHERE active.cid = $2
                            AND active.unpinned_at IS NULL
                    )
                ",
            )
            .bind(swept_at)
            .bind(&cid_text)
            .bind(cutoff)
            .execute(pool)
            .await?;
            sqlx::query(
                r"
                UPDATE published_manifests
                SET unpinned_at = to_timestamp($1)
                WHERE cid = $2
                    AND unpinned_at IS NULL
                    AND superseded_at IS NOT NULL
                    AND superseded_at <= to_timestamp($3)
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_snapshots AS active
                        WHERE active.cid = $2
                            AND active.superseded_at IS NULL
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_blocked_shields AS active
                        WHERE active.cid = $2
                            AND active.superseded_at IS NULL
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_manifests AS active
                        WHERE active.cid = $2
                            AND active.ipns_published_at IS NOT NULL
                            AND active.superseded_at IS NULL
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_indexed_manifests AS active
                        WHERE active.cid = $2
                            AND active.ipns_published_at IS NOT NULL
                            AND active.superseded_at IS NULL
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_indexed_artifacts AS active
                        WHERE active.cid = $2
                            AND active.unpinned_at IS NULL
                    )
                ",
            )
            .bind(swept_at)
            .bind(&cid_text)
            .bind(cutoff)
            .execute(pool)
            .await?;
            sqlx::query(
                r"
                UPDATE published_indexed_manifests
                SET unpinned_at = to_timestamp($1)
                WHERE cid = $2
                    AND unpinned_at IS NULL
                    AND superseded_at IS NOT NULL
                    AND superseded_at <= to_timestamp($3)
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_snapshots AS active
                        WHERE active.cid = $2
                            AND active.superseded_at IS NULL
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_blocked_shields AS active
                        WHERE active.cid = $2
                            AND active.superseded_at IS NULL
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_manifests AS active
                        WHERE active.cid = $2
                            AND active.ipns_published_at IS NOT NULL
                            AND active.superseded_at IS NULL
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_indexed_manifests AS active
                        WHERE active.cid = $2
                            AND active.ipns_published_at IS NOT NULL
                            AND active.superseded_at IS NULL
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_indexed_artifacts AS active
                        WHERE active.cid = $2
                            AND active.unpinned_at IS NULL
                    )
                ",
            )
            .bind(swept_at)
            .bind(&cid_text)
            .bind(cutoff)
            .execute(pool)
            .await?;
            info!(cid = %cid, "unpinned superseded railgun-indexer publication CID");
            unpinned_cids.push(cid);
        }

        Ok(RetentionSweep {
            unpinned_cids,
            failed_cids,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionSweep {
    pub unpinned_cids: Vec<Cid>,
    pub failed_cids: Vec<RetentionFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionFailure {
    pub cid: Cid,
    pub error: String,
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("database operation failed")]
    Sqlx(#[from] sqlx::Error),
    #[error("invalid stored publication CID {cid}")]
    InvalidCid {
        cid: String,
        #[source]
        source: cid::Error,
    },
    #[error("{field} value {value} is outside supported range")]
    IntegerOutOfRange { field: &'static str, value: String },
    #[error("retention cutoff is before unix epoch")]
    TimeBeforeUnixEpoch,
    #[error("manifest CID {cid} was not recorded before IPNS publication")]
    UnrecordedManifest { cid: String },
    #[error("manifest CID {cid} was superseded before IPNS publication")]
    SupersededManifest { cid: String },
    #[error("manifest CID {cid} was unpinned before IPNS publication")]
    UnpinnedManifest { cid: String },
}

const fn snapshot_kind_str(kind: SnapshotKind) -> &'static str {
    match kind {
        SnapshotKind::Base => "base",
        SnapshotKind::Delta => "delta",
    }
}

const fn indexed_artifact_publication_kind_str(
    kind: IndexedArtifactPublicationKind,
) -> &'static str {
    match kind {
        IndexedArtifactPublicationKind::Chunk => "chunk",
        IndexedArtifactPublicationKind::Catalog => "catalog",
    }
}

const fn indexed_dataset_kind_str(kind: IndexedDatasetKind) -> &'static str {
    match kind {
        IndexedDatasetKind::WalletScan => "wallet_scan",
        IndexedDatasetKind::Commitments => "commitments",
        IndexedDatasetKind::MerkleCheckpoint => "merkle_checkpoint",
        IndexedDatasetKind::PublicTxid => "public_txid",
    }
}

const fn indexed_range_kind_str(kind: IndexedArtifactRangeKind) -> &'static str {
    match kind {
        IndexedArtifactRangeKind::Block => "block",
        IndexedArtifactRangeKind::TxidIndex => "txid_index",
        IndexedArtifactRangeKind::TreePosition => "tree_position",
        IndexedArtifactRangeKind::PoiEventIndex => "poi_event_index",
    }
}

const fn chain_type_discriminant(chain_type: ChainType) -> i16 {
    match chain_type {
        ChainType::Evm => 0,
    }
}

fn u64_to_i64(value: u64, field: &'static str) -> Result<i64, AuditError> {
    i64::try_from(value).map_err(|_| AuditError::IntegerOutOfRange {
        field,
        value: value.to_string(),
    })
}

fn unix_seconds(value: SystemTime) -> Result<i64, AuditError> {
    let duration = value
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuditError::TimeBeforeUnixEpoch)?;
    u64_to_i64(duration.as_secs(), "retention cutoff")
}

fn parse_cid(value: &str) -> Result<Cid, AuditError> {
    Cid::try_from(value).map_err(|source| AuditError::InvalidCid {
        cid: value.to_string(),
        source,
    })
}
