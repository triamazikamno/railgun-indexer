use crate::manifest::{
    ChainScope, ChainType, IndexedArtifactManifest, IndexedArtifactRange, IndexedArtifactRangeKind,
    IndexedDatasetKind,
};
use crate::publish::ipfs::IpfsClient;
use crate::snapshot::SnapshotKind;
use crate::store::IPNS_SEQUENCE_STATE_KEY;
use alloy_primitives::{FixedBytes, hex};
use cid::Cid;
use poi::artifacts::v4::{Error as PoiArtifactError, EventRange, ManifestEntry, Scope};
use sqlx::{PgPool, Postgres, Transaction};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::{
    Mutex, OwnedMutexGuard, OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock, watch,
};
use tracing::{info, warn};

pub struct Audit;

#[derive(Clone)]
pub struct PinLifecycleCoordinator {
    gate: Arc<Mutex<()>>,
    ownership: Arc<StdMutex<PinOwnershipState>>,
    owner_count: watch::Sender<usize>,
}

impl PinLifecycleCoordinator {
    pub async fn lock(&self) -> OwnedMutexGuard<()> {
        Arc::clone(&self.gate).lock_owned().await
    }

    #[must_use]
    ///
    /// # Panics
    ///
    /// Panics if the ownership mutex is poisoned or the active-owner count overflows.
    pub fn try_acquire_pin_ownership(&self) -> Option<PinOwnershipLease> {
        let active = {
            let mut state = self.ownership.lock().expect("pin ownership state lock");
            if !state.accepting {
                return None;
            }
            state.active = state
                .active
                .checked_add(1)
                .expect("pin ownership count overflow");
            state.active
        };
        self.owner_count.send_replace(active);
        Some(PinOwnershipLease {
            coordinator: self.clone(),
            settled: false,
        })
    }

    /// # Panics
    ///
    /// Panics if the ownership mutex is poisoned.
    pub fn stop_new_pin_ownership(&self) {
        self.ownership
            .lock()
            .expect("pin ownership state lock")
            .accepting = false;
    }

    #[must_use]
    ///
    /// # Panics
    ///
    /// Panics if the ownership mutex is poisoned.
    pub fn active_pin_owners(&self) -> usize {
        self.ownership
            .lock()
            .expect("pin ownership state lock")
            .active
    }

    pub async fn wait_for_no_pin_owners(&self) {
        let mut owners = self.owner_count.subscribe();
        loop {
            if self.active_pin_owners() == 0 {
                return;
            }
            if owners.changed().await.is_err() {
                return;
            }
        }
    }

    fn settle_pin_ownership(&self) {
        let active = {
            let mut state = self.ownership.lock().expect("pin ownership state lock");
            state.active = state
                .active
                .checked_sub(1)
                .expect("pin ownership settled more than once");
            state.active
        };
        self.owner_count.send_replace(active);
    }
}

impl Default for PinLifecycleCoordinator {
    fn default() -> Self {
        let (owner_count, _) = watch::channel(0);
        Self {
            gate: Arc::new(Mutex::new(())),
            ownership: Arc::new(StdMutex::new(PinOwnershipState {
                accepting: true,
                active: 0,
            })),
            owner_count,
        }
    }
}

struct PinOwnershipState {
    accepting: bool,
    active: usize,
}

pub struct PinOwnershipLease {
    coordinator: PinLifecycleCoordinator,
    settled: bool,
}

impl PinOwnershipLease {
    pub fn settle(mut self) {
        self.coordinator.settle_pin_ownership();
        self.settled = true;
    }
}

impl Drop for PinOwnershipLease {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        warn!("pin ownership lease dropped unsettled; clean shutdown will remain blocked");
    }
}

#[derive(Clone, Default)]
pub struct ChainCanonicalityCoordinator {
    gate: Arc<RwLock<()>>,
}

#[derive(Clone)]
pub struct ChainCanonicalityLease {
    _guard: Arc<OwnedRwLockReadGuard<()>>,
}

impl std::fmt::Debug for ChainCanonicalityLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ChainCanonicalityLease").finish()
    }
}

impl ChainCanonicalityCoordinator {
    pub async fn publication_lease(&self) -> ChainCanonicalityLease {
        ChainCanonicalityLease {
            _guard: Arc::new(Arc::clone(&self.gate).read_owned().await),
        }
    }

    pub async fn reorg_lease(&self) -> OwnedRwLockWriteGuard<()> {
        Arc::clone(&self.gate).write_owned().await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexedArtifactPublicationKind {
    Chunk,
    Catalog,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoiArtifactPublicationKind {
    CheckpointChunk,
    CheckpointCatalog,
    CurrentTail,
    Bridge,
    BlockedShields,
}

#[derive(Debug, Clone)]
pub struct ActivePoiGraph {
    pub entry: ManifestEntry,
    pub checkpoint_published_at: SystemTime,
    pub bridge_published_at: BTreeMap<String, SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingManifestPublication {
    pub cid: String,
    pub sequence: u64,
    pub artifact_cids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingIndexedManifestPublication {
    pub cid: String,
    pub sequence: u64,
    pub artifact_cids: Vec<String>,
    pub manifest: IndexedArtifactManifest,
    pub manifest_json: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoiManifestChannel {
    Legacy,
    V4,
}

impl PoiManifestChannel {
    const fn label(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::V4 => "v4",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveManifestPublication {
    pub cid: String,
    pub sequence: u64,
    pub ipns_published_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivePoiManifestPublication {
    pub cid: String,
    pub sequence: u64,
    pub ipns_published_at: SystemTime,
    pub entries: Vec<ManifestEntry>,
}

impl Audit {
    pub async fn record_pin_cleanup_debt(
        pool: &PgPool,
        cid: &Cid,
        provider: &str,
        error: &str,
    ) -> Result<(), AuditError> {
        sqlx::query(
            r"
            INSERT INTO pin_cleanup_debt (cid, provider, attempts, last_error)
            VALUES ($1, $2, 0, $3)
            ON CONFLICT (cid) DO UPDATE SET
                provider = EXCLUDED.provider,
                last_error = EXCLUDED.last_error,
                updated_at = now()
            ",
        )
        .bind(cid.to_string())
        .bind(provider)
        .bind(error)
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn publication_cid_is_referenced(
        pool: &PgPool,
        cid: &Cid,
    ) -> Result<bool, AuditError> {
        sqlx::query_scalar(
            r"
            SELECT EXISTS(SELECT 1 FROM published_snapshots WHERE cid = $1 AND unpinned_at IS NULL)
                OR EXISTS(SELECT 1 FROM published_blocked_shields WHERE cid = $1 AND unpinned_at IS NULL)
                OR EXISTS(SELECT 1 FROM published_manifests WHERE cid = $1 AND unpinned_at IS NULL)
                OR EXISTS(SELECT 1 FROM published_indexed_artifacts WHERE cid = $1 AND unpinned_at IS NULL)
                OR EXISTS(SELECT 1 FROM published_indexed_manifests WHERE cid = $1 AND unpinned_at IS NULL)
                OR EXISTS(SELECT 1 FROM published_poi_v4_artifacts WHERE cid = $1 AND unpinned_at IS NULL)
                OR EXISTS(SELECT 1 FROM published_poi_v4_manifests WHERE cid = $1 AND unpinned_at IS NULL)
                OR EXISTS(
                    SELECT 1
                    FROM published_indexed_manifest_artifacts AS edge
                    JOIN published_indexed_manifests AS manifest ON manifest.id = edge.manifest_id
                    WHERE edge.artifact_cid = $1 AND manifest.unpinned_at IS NULL
                )
                OR EXISTS(
                    SELECT 1
                    FROM published_poi_v4_manifest_artifacts AS edge
                    JOIN published_poi_v4_manifests AS manifest ON manifest.id = edge.manifest_id
                    WHERE edge.artifact_cid = $1 AND manifest.unpinned_at IS NULL
                )
            ",
        )
        .bind(cid.to_string())
        .fetch_one(pool)
        .await
        .map_err(AuditError::Sqlx)
    }

    pub async fn invalidate_pending_poi_manifest_reconciliation(
        tx: &mut Transaction<'_, Postgres>,
        channel: PoiManifestChannel,
        cid: &Cid,
        sequence: u64,
    ) -> Result<(), AuditError> {
        invalidate_pending_poi_manifest_reconciliation(tx, channel, cid, sequence).await
    }

    pub async fn pending_manifest_publication(
        pool: &PgPool,
    ) -> Result<Option<PendingManifestPublication>, AuditError> {
        pending_manifest_publication(pool, "published_manifests", None).await
    }

    pub async fn pending_poi_artifact_manifest_publication(
        pool: &PgPool,
    ) -> Result<Option<PendingManifestPublication>, AuditError> {
        pending_manifest_publication(
            pool,
            "published_poi_v4_manifests",
            Some("published_poi_v4_manifest_artifacts"),
        )
        .await
    }

    pub async fn pending_indexed_manifest_publication(
        pool: &PgPool,
        trusted_publisher_pubkey: &[u8; 32],
    ) -> Result<Option<PendingIndexedManifestPublication>, AuditError> {
        let rows = sqlx::query_as::<_, (i64, String, i64, i64, Vec<u8>, Option<String>)>(
            r"
            SELECT id, cid, ipns_sequence, byte_size, content_hash, manifest_json
            FROM published_indexed_manifests
            WHERE ipns_published_at IS NULL
              AND superseded_at IS NULL
              AND unpinned_at IS NULL
              AND reconciliation_invalidated_at IS NULL
            ORDER BY ipns_sequence DESC, id DESC
            LIMIT 2
            ",
        )
        .fetch_all(pool)
        .await?;
        if rows.len() > 1 {
            return Err(AuditError::AmbiguousPendingManifests {
                channel: "chain-indexed",
                count: rows.len(),
            });
        }
        let Some((manifest_id, cid, sequence, byte_size, content_hash, manifest_json)) =
            rows.into_iter().next()
        else {
            return Ok(None);
        };
        let manifest_json = manifest_json
            .ok_or_else(|| AuditError::MissingIndexedManifestBody { cid: cid.clone() })?;
        let manifest_bytes = manifest_json.as_bytes();
        let actual_byte_size =
            i64::try_from(manifest_bytes.len()).map_err(|_| AuditError::IntegerOutOfRange {
                field: "manifest_json byte size",
                value: manifest_bytes.len().to_string(),
            })?;
        if actual_byte_size != byte_size
            || crate::blocked::content_hash(manifest_bytes).as_slice() != content_hash
        {
            return Err(AuditError::IndexedManifestBodyMismatch { cid });
        }
        let manifest: IndexedArtifactManifest = serde_json::from_slice(manifest_bytes)?;
        manifest
            .verify_trusted_signature(trusted_publisher_pubkey)
            .map_err(AuditError::IndexedManifest)?;
        let sequence = i64_to_u64(sequence, "ipns_sequence")?;
        if manifest.sequence != sequence {
            return Err(AuditError::IndexedManifestSequenceMismatch {
                cid,
                stored: sequence,
                body: manifest.sequence,
            });
        }
        let artifact_cids = sqlx::query_scalar::<_, String>(
            r"
            SELECT artifact_cid
            FROM published_indexed_manifest_artifacts
            WHERE manifest_id = $1
            ORDER BY artifact_cid
            ",
        )
        .bind(manifest_id)
        .fetch_all(pool)
        .await?;
        Ok(Some(PendingIndexedManifestPublication {
            cid,
            sequence,
            artifact_cids,
            manifest,
            manifest_json,
        }))
    }

    pub async fn active_manifest_publication(
        pool: &PgPool,
    ) -> Result<Option<ActiveManifestPublication>, AuditError> {
        let row = sqlx::query_as::<_, (String, i64, i64)>(
            r"
            SELECT cid, ipns_sequence,
                   EXTRACT(EPOCH FROM ipns_published_at)::BIGINT
            FROM published_manifests
            WHERE ipns_published_at IS NOT NULL
              AND superseded_at IS NULL
              AND unpinned_at IS NULL
            ORDER BY ipns_sequence DESC, id DESC
            LIMIT 1
            ",
        )
        .fetch_optional(pool)
        .await?;
        row.map(|(cid, sequence, published_at)| {
            Ok(ActiveManifestPublication {
                cid,
                sequence: i64_to_u64(sequence, "ipns_sequence")?,
                ipns_published_at: i64_to_system_time(published_at, "ipns_published_at")?,
            })
        })
        .transpose()
    }

    pub async fn active_poi_artifact_manifest_publication(
        pool: &PgPool,
    ) -> Result<Option<ActivePoiManifestPublication>, AuditError> {
        let row = sqlx::query_as::<_, (i64, String, i64, i64)>(
            r"
            SELECT id, cid, ipns_sequence,
                   EXTRACT(EPOCH FROM ipns_published_at)::BIGINT
            FROM published_poi_v4_manifests
            WHERE ipns_published_at IS NOT NULL
              AND superseded_at IS NULL
              AND unpinned_at IS NULL
            ORDER BY ipns_sequence DESC, id DESC
            LIMIT 1
            ",
        )
        .fetch_optional(pool)
        .await?;
        let Some((manifest_id, cid, sequence, published_at)) = row else {
            return Ok(None);
        };
        let entry_json = sqlx::query_scalar::<_, String>(
            r"
            SELECT entry_json
            FROM published_poi_v4_manifest_entries
            WHERE manifest_id = $1
            ORDER BY list_key, chain_type, chain_id, txid_version
            ",
        )
        .bind(manifest_id)
        .fetch_all(pool)
        .await?;
        let entries = entry_json
            .into_iter()
            .map(|entry| {
                let entry: ManifestEntry = serde_json::from_str(&entry)?;
                entry.validate().map_err(AuditError::PoiArtifactContract)?;
                Ok(entry)
            })
            .collect::<Result<Vec<_>, AuditError>>()?;
        Ok(Some(ActivePoiManifestPublication {
            cid,
            sequence: i64_to_u64(sequence, "ipns_sequence")?,
            ipns_published_at: i64_to_system_time(published_at, "ipns_published_at")?,
            entries,
        }))
    }

    pub async fn live_poi_artifact_cid(
        pool: &PgPool,
        artifact_kind: PoiArtifactPublicationKind,
        scope: &Scope,
        range: Option<EventRange>,
        byte_size: u64,
        content_hash: &[u8; 32],
        end_root: Option<&FixedBytes<32>>,
    ) -> Result<Option<Cid>, AuditError> {
        let chain_id = u64_to_i64(scope.chain_id, "chain_id")?;
        let byte_size = u64_to_i64(byte_size, "byte_size")?;
        let (range_start, range_end) = poi_artifact_range_columns(range)?;
        let cid = sqlx::query_scalar::<_, String>(
            r"
            SELECT cid
            FROM published_poi_v4_artifacts
            WHERE artifact_kind = $1
                AND list_key = $2
                AND chain_type = $3
                AND chain_id = $4
                AND txid_version = $5
                AND range_start = $6
                AND range_end = $7
                AND byte_size = $8
                AND content_hash = $9
                AND end_root IS NOT DISTINCT FROM $10
                AND format_version = 4
                AND unpinned_at IS NULL
            ORDER BY last_referenced_at DESC, published_at DESC
            LIMIT 1
            ",
        )
        .bind(poi_artifact_kind_str(artifact_kind))
        .bind(scope.list_key.as_slice())
        .bind(i16::from(scope.chain_type))
        .bind(chain_id)
        .bind(&scope.txid_version)
        .bind(range_start)
        .bind(range_end)
        .bind(byte_size)
        .bind(content_hash.as_slice())
        .bind(end_root.map(FixedBytes::as_slice))
        .fetch_optional(pool)
        .await?;
        cid.map(|cid| parse_cid(&cid)).transpose()
    }

    pub async fn active_poi_graph(
        pool: &PgPool,
        scope: &Scope,
    ) -> Result<Option<ActivePoiGraph>, AuditError> {
        let chain_id = u64_to_i64(scope.chain_id, "chain_id")?;
        let row = sqlx::query_as::<_, (String, i64)>(
            r"
            SELECT entry.entry_json,
                   EXTRACT(EPOCH FROM artifact.published_at)::BIGINT
            FROM published_poi_v4_manifest_entries AS entry
            JOIN published_poi_v4_manifests AS manifest ON manifest.id = entry.manifest_id
            JOIN published_poi_v4_artifacts AS artifact
              ON artifact.cid = (entry.entry_json::jsonb #>> '{checkpoint_catalog,artifact,cid}')
             AND artifact.artifact_kind = 'checkpoint_catalog'
             AND artifact.unpinned_at IS NULL
            WHERE entry.list_key = $1
              AND entry.chain_type = $2
              AND entry.chain_id = $3
              AND entry.txid_version = $4
              AND manifest.ipns_published_at IS NOT NULL
              AND manifest.superseded_at IS NULL
              AND manifest.unpinned_at IS NULL
            ORDER BY manifest.ipns_sequence DESC, artifact.published_at DESC
            LIMIT 1
            ",
        )
        .bind(scope.list_key.as_slice())
        .bind(i16::from(scope.chain_type))
        .bind(chain_id)
        .bind(&scope.txid_version)
        .fetch_optional(pool)
        .await?;
        let Some((entry_json, checkpoint_published_at)) = row else {
            return Ok(None);
        };
        let entry: ManifestEntry = serde_json::from_str(&entry_json)?;
        entry.validate().map_err(AuditError::PoiArtifactContract)?;
        let bridge_cids = entry
            .retained_bridges
            .iter()
            .map(|bridge| bridge.artifact.cid.clone())
            .collect::<Vec<_>>();
        let bridge_rows = if bridge_cids.is_empty() {
            Vec::new()
        } else {
            sqlx::query_as::<_, (String, i64)>(
                r"
                SELECT cid, EXTRACT(EPOCH FROM published_at)::BIGINT
                FROM published_poi_v4_artifacts
                WHERE artifact_kind = 'bridge'
                  AND cid = ANY($1::TEXT[])
                  AND unpinned_at IS NULL
                ",
            )
            .bind(&bridge_cids)
            .fetch_all(pool)
            .await?
        };
        let bridge_published_at = bridge_rows
            .into_iter()
            .map(|(cid, timestamp)| {
                Ok((cid, i64_to_system_time(timestamp, "bridge_published_at")?))
            })
            .collect::<Result<BTreeMap<_, _>, AuditError>>()?;
        Ok(Some(ActivePoiGraph {
            entry,
            checkpoint_published_at: i64_to_system_time(
                checkpoint_published_at,
                "checkpoint_published_at",
            )?,
            bridge_published_at,
        }))
    }

    pub async fn record_poi_artifact_pin(
        tx: &mut Transaction<'_, Postgres>,
        artifact_kind: PoiArtifactPublicationKind,
        scope: &Scope,
        range: Option<EventRange>,
        cid: &Cid,
        byte_size: u64,
        content_hash: &[u8; 32],
        end_root: Option<&FixedBytes<32>>,
        descriptor_json: &str,
    ) -> Result<(), AuditError> {
        let chain_id = u64_to_i64(scope.chain_id, "chain_id")?;
        let byte_size_i64 = u64_to_i64(byte_size, "byte_size")?;
        let (range_start, range_end) = poi_artifact_range_columns(range)?;
        let result = sqlx::query(
            r"
            INSERT INTO published_poi_v4_artifacts (
                artifact_kind, list_key, chain_type, chain_id, txid_version,
                range_start, range_end, cid, byte_size, content_hash, end_root,
                descriptor_json, format_version
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 4)
            ON CONFLICT (
                artifact_kind, list_key, chain_type, chain_id, txid_version,
                range_start, range_end, cid
            ) DO UPDATE SET last_referenced_at = now(), unpinned_at = NULL
            WHERE published_poi_v4_artifacts.byte_size = EXCLUDED.byte_size
              AND published_poi_v4_artifacts.content_hash = EXCLUDED.content_hash
              AND published_poi_v4_artifacts.end_root IS NOT DISTINCT FROM EXCLUDED.end_root
              AND published_poi_v4_artifacts.descriptor_json = EXCLUDED.descriptor_json
              AND published_poi_v4_artifacts.format_version = EXCLUDED.format_version
            ",
        )
        .bind(poi_artifact_kind_str(artifact_kind))
        .bind(scope.list_key.as_slice())
        .bind(i16::from(scope.chain_type))
        .bind(chain_id)
        .bind(&scope.txid_version)
        .bind(range_start)
        .bind(range_end)
        .bind(cid.to_string())
        .bind(byte_size_i64)
        .bind(content_hash.as_slice())
        .bind(end_root.map(FixedBytes::as_slice))
        .bind(descriptor_json)
        .execute(&mut **tx)
        .await?;
        if result.rows_affected() == 0 {
            return Err(AuditError::PoiArtifactConflict {
                cid: cid.to_string(),
                byte_size,
            });
        }
        Ok(())
    }

    pub async fn record_poi_artifact_manifest_pin(
        tx: &mut Transaction<'_, Postgres>,
        cid: &Cid,
        entries: &[ManifestEntry],
        artifact_cids: &[String],
        sequence: u64,
        byte_size: u64,
        content_hash: &[u8; 32],
    ) -> Result<(), AuditError> {
        let sequence = u64_to_i64(sequence, "sequence")?;
        let byte_size = u64_to_i64(byte_size, "byte_size")?;
        let expected = artifact_cids
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        if expected > 0 {
            let live_count = sqlx::query_scalar::<_, i64>(
                r"
                SELECT COUNT(DISTINCT cid)
                FROM published_poi_v4_artifacts
                WHERE cid = ANY($1::TEXT[]) AND unpinned_at IS NULL
                ",
            )
            .bind(artifact_cids)
            .fetch_one(&mut **tx)
            .await?;
            let actual = usize::try_from(live_count).unwrap_or(0);
            if actual != expected {
                return Err(AuditError::MissingManifestArtifacts { expected, actual });
            }
        }
        reject_unresolved_pending(tx, "published_poi_v4_manifests", "v4").await?;
        let manifest_id = sqlx::query_scalar::<_, i64>(
            r"
            INSERT INTO published_poi_v4_manifests (
                cid, ipns_sequence, byte_size, content_hash, format_version
            ) VALUES ($1, $2, $3, $4, 4)
            RETURNING id
            ",
        )
        .bind(cid.to_string())
        .bind(sequence)
        .bind(byte_size)
        .bind(content_hash.as_slice())
        .fetch_one(&mut **tx)
        .await?;
        for entry in entries {
            entry.validate().map_err(AuditError::PoiArtifactContract)?;
            sqlx::query(
                r"
                INSERT INTO published_poi_v4_manifest_entries (
                    manifest_id, list_key, chain_type, chain_id, txid_version, entry_json
                ) VALUES ($1, $2, $3, $4, $5, $6)
                ",
            )
            .bind(manifest_id)
            .bind(entry.scope.list_key.as_slice())
            .bind(i16::from(entry.scope.chain_type))
            .bind(u64_to_i64(entry.scope.chain_id, "chain_id")?)
            .bind(&entry.scope.txid_version)
            .bind(serde_json::to_string(entry)?)
            .execute(&mut **tx)
            .await?;
        }
        if !artifact_cids.is_empty() {
            sqlx::query(
                r"
                INSERT INTO published_poi_v4_manifest_artifacts (manifest_id, artifact_cid)
                SELECT $1, artifact_cid FROM UNNEST($2::TEXT[]) AS artifact_cid
                ON CONFLICT (manifest_id, artifact_cid) DO NOTHING
                ",
            )
            .bind(manifest_id)
            .bind(artifact_cids)
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }

    pub async fn record_poi_artifact_manifest_ipns_publication(
        tx: &mut Transaction<'_, Postgres>,
        cid: &Cid,
        sequence: u64,
    ) -> Result<(), AuditError> {
        let cid = cid.to_string();
        let sequence = u64_to_i64(sequence, "sequence")?;
        ensure_newer_than_invalidated_pending(
            tx,
            "published_poi_v4_manifests",
            "v4",
            &cid,
            sequence,
        )
        .await?;
        let result = sqlx::query(
            r"
            UPDATE published_poi_v4_manifests
            SET ipns_published_at = COALESCE(ipns_published_at, now())
            WHERE cid = $1
              AND ipns_sequence = $2
              AND superseded_at IS NULL
              AND unpinned_at IS NULL
              AND reconciliation_invalidated_at IS NULL
            ",
        )
        .bind(&cid)
        .bind(sequence)
        .execute(&mut **tx)
        .await?;
        if result.rows_affected() == 0 {
            return Err(AuditError::UnrecordedManifest { cid });
        }
        sqlx::query(
            r"
            UPDATE published_poi_v4_manifests
            SET superseded_at = now()
            WHERE superseded_at IS NULL
              AND (
                    (cid <> $1 AND ipns_published_at IS NOT NULL)
                    OR (
                        reconciliation_invalidated_at IS NOT NULL
                        AND ipns_sequence < $2
                    )
              )
            ",
        )
        .bind(&cid)
        .bind(sequence)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

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

        reject_unresolved_pending(tx, "published_manifests", "legacy").await?;

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
        sequence: u64,
    ) -> Result<(), AuditError> {
        let cid = cid.to_string();
        let sequence = u64_to_i64(sequence, "sequence")?;
        ensure_newer_than_invalidated_pending(tx, "published_manifests", "legacy", &cid, sequence)
            .await?;
        let result = sqlx::query(
            r"
            UPDATE published_manifests
            SET ipns_published_at = COALESCE(ipns_published_at, now())
            WHERE cid = $1
                AND ipns_sequence = $2
                AND superseded_at IS NULL
                AND unpinned_at IS NULL
                AND reconciliation_invalidated_at IS NULL
            ",
        )
        .bind(&cid)
        .bind(sequence)
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
            WHERE superseded_at IS NULL
              AND (
                    (cid <> $1 AND ipns_published_at IS NOT NULL)
                    OR (
                        reconciliation_invalidated_at IS NOT NULL
                        AND ipns_sequence < $2
                    )
              )
            ",
        )
        .bind(&cid)
        .bind(sequence)
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
        artifact_cids: &[String],
        sequence: u64,
        byte_size: u64,
        content_hash: &[u8; 32],
        format_version: u16,
        manifest_json: &str,
    ) -> Result<(), AuditError> {
        let sequence = u64_to_i64(sequence, "sequence")?;
        let byte_size = u64_to_i64(byte_size, "byte_size")?;
        let format_version = i32::from(format_version);

        if !artifact_cids.is_empty() {
            let live_count = sqlx::query_scalar::<_, i64>(
                r"
                SELECT COUNT(DISTINCT cid)
                FROM published_indexed_artifacts
                WHERE cid = ANY($1::TEXT[])
                    AND unpinned_at IS NULL
                ",
            )
            .bind(artifact_cids)
            .fetch_one(&mut **tx)
            .await?;
            let expected = artifact_cids.len();
            let actual = usize::try_from(live_count).unwrap_or(0);
            if actual != expected {
                return Err(AuditError::MissingIndexedManifestArtifacts { expected, actual });
            }
        }

        reject_unresolved_pending(tx, "published_indexed_manifests", "chain-indexed").await?;

        let manifest_id = sqlx::query_scalar::<_, i64>(
            r"
            INSERT INTO published_indexed_manifests (
                cid,
                ipns_sequence,
                byte_size,
                content_hash,
                format_version,
                manifest_json
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            ",
        )
        .bind(cid.to_string())
        .bind(sequence)
        .bind(byte_size)
        .bind(content_hash.as_slice())
        .bind(format_version)
        .bind(manifest_json)
        .fetch_one(&mut **tx)
        .await?;

        if !artifact_cids.is_empty() {
            sqlx::query(
                r"
                INSERT INTO published_indexed_manifest_artifacts (manifest_id, artifact_cid)
                SELECT $1, artifact_cid
                FROM UNNEST($2::TEXT[]) AS artifact_cid
                ON CONFLICT (manifest_id, artifact_cid) DO NOTHING
                ",
            )
            .bind(manifest_id)
            .bind(artifact_cids)
            .execute(&mut **tx)
            .await?;
        }

        Ok(())
    }

    pub async fn record_indexed_manifest_ipns_publication(
        tx: &mut Transaction<'_, Postgres>,
        cid: &Cid,
        sequence: u64,
    ) -> Result<(), AuditError> {
        let cid = cid.to_string();
        let sequence = u64_to_i64(sequence, "sequence")?;
        ensure_newer_than_invalidated_pending(
            tx,
            "published_indexed_manifests",
            "chain-indexed",
            &cid,
            sequence,
        )
        .await?;
        let result = sqlx::query(
            r"
            UPDATE published_indexed_manifests
            SET ipns_published_at = COALESCE(ipns_published_at, now())
            WHERE cid = $1
                AND ipns_sequence = $2
                AND superseded_at IS NULL
                AND unpinned_at IS NULL
                AND reconciliation_invalidated_at IS NULL
            ",
        )
        .bind(&cid)
        .bind(sequence)
        .execute(&mut **tx)
        .await?;
        if result.rows_affected() == 0 {
            let (superseded, unpinned): (bool, bool) = sqlx::query_as(
                r"
                SELECT
                    EXISTS(SELECT 1 FROM published_indexed_manifests WHERE cid = $1 AND ipns_sequence = $2 AND superseded_at IS NOT NULL),
                    EXISTS(SELECT 1 FROM published_indexed_manifests WHERE cid = $1 AND ipns_sequence = $2 AND unpinned_at IS NOT NULL)
                ",
            )
            .bind(&cid)
            .bind(sequence)
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
            WHERE superseded_at IS NULL
              AND (
                    (
                        ipns_published_at IS NOT NULL
                        AND (cid <> $1 OR ipns_sequence <> $2)
                    )
                    OR (
                        reconciliation_invalidated_at IS NOT NULL
                        AND ipns_sequence < $2
                    )
              )
            ",
        )
        .bind(&cid)
        .bind(sequence)
        .execute(&mut **tx)
        .await?;

        Ok(())
    }
}

async fn invalidate_pending_poi_manifest_reconciliation(
    tx: &mut Transaction<'_, Postgres>,
    channel: PoiManifestChannel,
    cid: &Cid,
    sequence: u64,
) -> Result<(), AuditError> {
    let cid = cid.to_string();
    let sequence = u64_to_i64(sequence, "sequence")?;
    let unresolved = match channel {
        PoiManifestChannel::Legacy => {
            sqlx::query_as::<_, (i64, String, i64)>(
                r"
                SELECT id, cid, ipns_sequence
                FROM published_manifests
                WHERE ipns_published_at IS NULL
                  AND superseded_at IS NULL
                  AND unpinned_at IS NULL
                  AND reconciliation_invalidated_at IS NULL
                ORDER BY id
                FOR UPDATE
                ",
            )
            .fetch_all(&mut **tx)
            .await?
        }
        PoiManifestChannel::V4 => {
            sqlx::query_as::<_, (i64, String, i64)>(
                r"
                SELECT id, cid, ipns_sequence
                FROM published_poi_v4_manifests
                WHERE ipns_published_at IS NULL
                  AND superseded_at IS NULL
                  AND unpinned_at IS NULL
                  AND reconciliation_invalidated_at IS NULL
                ORDER BY id
                FOR UPDATE
                ",
            )
            .fetch_all(&mut **tx)
            .await?
        }
    };
    if unresolved.len() > 1 {
        return Err(AuditError::AmbiguousPendingManifests {
            channel: channel.label(),
            count: unresolved.len(),
        });
    }
    if let Some((id, pending_cid, pending_sequence)) = unresolved.into_iter().next() {
        if pending_cid != cid || pending_sequence != sequence {
            return Err(AuditError::PendingManifestAuthorizationMismatch {
                channel: channel.label(),
                cid,
                sequence: i64_to_u64(sequence, "sequence")?,
            });
        }
        let result = match channel {
            PoiManifestChannel::Legacy => {
                sqlx::query(
                    r"
                    UPDATE published_manifests
                    SET reconciliation_invalidated_at = now()
                    WHERE id = $1
                      AND ipns_published_at IS NULL
                      AND superseded_at IS NULL
                      AND unpinned_at IS NULL
                      AND reconciliation_invalidated_at IS NULL
                    ",
                )
                .bind(id)
                .execute(&mut **tx)
                .await?
            }
            PoiManifestChannel::V4 => {
                sqlx::query(
                    r"
                    UPDATE published_poi_v4_manifests
                    SET reconciliation_invalidated_at = now()
                    WHERE id = $1
                      AND ipns_published_at IS NULL
                      AND superseded_at IS NULL
                      AND unpinned_at IS NULL
                      AND reconciliation_invalidated_at IS NULL
                    ",
                )
                .bind(id)
                .execute(&mut **tx)
                .await?
            }
        };
        if result.rows_affected() != 1 {
            return Err(AuditError::PendingManifestAuthorizationMismatch {
                channel: channel.label(),
                cid: pending_cid,
                sequence: i64_to_u64(pending_sequence, "ipns_sequence")?,
            });
        }
        sqlx::query(
            r"
            INSERT INTO indexer_state (key, value)
            VALUES ($1, $2)
            ON CONFLICT (key) DO UPDATE SET
                value = GREATEST(indexer_state.value, EXCLUDED.value),
                updated_at = now()
            ",
        )
        .bind(IPNS_SEQUENCE_STATE_KEY)
        .bind(sequence)
        .execute(&mut **tx)
        .await?;
        return Ok(());
    }

    let states = match channel {
        PoiManifestChannel::Legacy => {
            sqlx::query_as::<_, (bool, bool, bool, bool)>(
                r"
                SELECT ipns_published_at IS NOT NULL,
                       superseded_at IS NOT NULL,
                       unpinned_at IS NOT NULL,
                       reconciliation_invalidated_at IS NOT NULL
                FROM published_manifests
                WHERE cid = $1 AND ipns_sequence = $2
                ORDER BY id
                FOR UPDATE
                ",
            )
            .bind(&cid)
            .bind(sequence)
            .fetch_all(&mut **tx)
            .await?
        }
        PoiManifestChannel::V4 => {
            sqlx::query_as::<_, (bool, bool, bool, bool)>(
                r"
                SELECT ipns_published_at IS NOT NULL,
                       superseded_at IS NOT NULL,
                       unpinned_at IS NOT NULL,
                       reconciliation_invalidated_at IS NOT NULL
                FROM published_poi_v4_manifests
                WHERE cid = $1 AND ipns_sequence = $2
                ORDER BY id
                FOR UPDATE
                ",
            )
            .bind(&cid)
            .bind(sequence)
            .fetch_all(&mut **tx)
            .await?
        }
    };
    if states.len() > 1 {
        return Err(AuditError::AmbiguousPendingManifests {
            channel: channel.label(),
            count: states.len(),
        });
    }
    if let Some((active, superseded, unpinned, invalidated)) = states.into_iter().next() {
        let state = if active {
            "active"
        } else if superseded {
            "superseded"
        } else if unpinned {
            "unpinned"
        } else if invalidated {
            "already invalidated"
        } else {
            "not pending"
        };
        return Err(AuditError::PendingManifestNotRecoverable {
            channel: channel.label(),
            cid,
            sequence: i64_to_u64(sequence, "sequence")?,
            state,
        });
    }
    Err(AuditError::PendingManifestAuthorizationMismatch {
        channel: channel.label(),
        cid,
        sequence: i64_to_u64(sequence, "sequence")?,
    })
}

async fn pending_manifest_publication(
    pool: &PgPool,
    manifest_table: &'static str,
    artifact_table: Option<&'static str>,
) -> Result<Option<PendingManifestPublication>, AuditError> {
    let rows = match manifest_table {
        "published_manifests" => {
            sqlx::query_as::<_, (i64, String, i64)>(
                r"
                SELECT id, cid, ipns_sequence
                FROM published_manifests
                WHERE ipns_published_at IS NULL
                  AND superseded_at IS NULL
                  AND unpinned_at IS NULL
                  AND reconciliation_invalidated_at IS NULL
                ORDER BY ipns_sequence DESC, id DESC
                LIMIT 2
                ",
            )
            .fetch_all(pool)
            .await?
        }
        "published_poi_v4_manifests" => {
            sqlx::query_as::<_, (i64, String, i64)>(
                r"
                SELECT id, cid, ipns_sequence
                FROM published_poi_v4_manifests
                WHERE ipns_published_at IS NULL
                  AND superseded_at IS NULL
                  AND unpinned_at IS NULL
                  AND reconciliation_invalidated_at IS NULL
                ORDER BY ipns_sequence DESC, id DESC
                LIMIT 2
                ",
            )
            .fetch_all(pool)
            .await?
        }
        _ => unreachable!("pending manifest table is fixed by the audit API"),
    };
    if rows.len() > 1 {
        return Err(AuditError::AmbiguousPendingManifests {
            channel: if artifact_table.is_some() {
                "v4"
            } else {
                "legacy"
            },
            count: rows.len(),
        });
    }
    let Some((manifest_id, cid, sequence)) = rows.into_iter().next() else {
        return Ok(None);
    };
    let artifact_cids = if artifact_table.is_some() {
        sqlx::query_scalar::<_, String>(
            r"
            SELECT artifact_cid
            FROM published_poi_v4_manifest_artifacts
            WHERE manifest_id = $1
            ORDER BY artifact_cid
            ",
        )
        .bind(manifest_id)
        .fetch_all(pool)
        .await?
    } else {
        Vec::new()
    };
    Ok(Some(PendingManifestPublication {
        cid,
        sequence: i64_to_u64(sequence, "ipns_sequence")?,
        artifact_cids,
    }))
}

async fn reject_unresolved_pending(
    tx: &mut Transaction<'_, Postgres>,
    manifest_table: &'static str,
    channel: &'static str,
) -> Result<(), AuditError> {
    let row = match manifest_table {
        "published_manifests" => {
            sqlx::query_as::<_, (String, i64)>(
                r"
                SELECT cid, ipns_sequence
                FROM published_manifests
                WHERE ipns_published_at IS NULL
                  AND superseded_at IS NULL
                  AND unpinned_at IS NULL
                  AND reconciliation_invalidated_at IS NULL
                LIMIT 1
                ",
            )
            .fetch_optional(&mut **tx)
            .await?
        }
        "published_poi_v4_manifests" => {
            sqlx::query_as::<_, (String, i64)>(
                r"
                SELECT cid, ipns_sequence
                FROM published_poi_v4_manifests
                WHERE ipns_published_at IS NULL
                  AND superseded_at IS NULL
                  AND unpinned_at IS NULL
                  AND reconciliation_invalidated_at IS NULL
                LIMIT 1
                ",
            )
            .fetch_optional(&mut **tx)
            .await?
        }
        "published_indexed_manifests" => {
            sqlx::query_as::<_, (String, i64)>(
                r"
                SELECT cid, ipns_sequence
                FROM published_indexed_manifests
                WHERE ipns_published_at IS NULL
                  AND superseded_at IS NULL
                  AND unpinned_at IS NULL
                  AND reconciliation_invalidated_at IS NULL
                LIMIT 1
                ",
            )
            .fetch_optional(&mut **tx)
            .await?
        }
        _ => unreachable!("pending manifest table is fixed by the audit API"),
    };
    if let Some((cid, sequence)) = row {
        return Err(AuditError::UnresolvedPendingManifest {
            channel,
            cid,
            sequence: i64_to_u64(sequence, "ipns_sequence")?,
        });
    }
    Ok(())
}

async fn ensure_newer_than_invalidated_pending(
    tx: &mut Transaction<'_, Postgres>,
    manifest_table: &'static str,
    channel: &'static str,
    cid: &str,
    sequence: i64,
) -> Result<(), AuditError> {
    let invalidated_sequence = match manifest_table {
        "published_manifests" => {
            sqlx::query_scalar::<_, Option<i64>>(
                r"
                SELECT MAX(ipns_sequence)
                FROM published_manifests
                WHERE reconciliation_invalidated_at IS NOT NULL
                  AND superseded_at IS NULL
                ",
            )
            .fetch_one(&mut **tx)
            .await?
        }
        "published_poi_v4_manifests" => {
            sqlx::query_scalar::<_, Option<i64>>(
                r"
                SELECT MAX(ipns_sequence)
                FROM published_poi_v4_manifests
                WHERE reconciliation_invalidated_at IS NOT NULL
                  AND superseded_at IS NULL
                ",
            )
            .fetch_one(&mut **tx)
            .await?
        }
        "published_indexed_manifests" => {
            sqlx::query_scalar::<_, Option<i64>>(
                r"
                SELECT MAX(ipns_sequence)
                FROM published_indexed_manifests
                WHERE reconciliation_invalidated_at IS NOT NULL
                  AND superseded_at IS NULL
                ",
            )
            .fetch_one(&mut **tx)
            .await?
        }
        _ => unreachable!("manifest table is fixed by the audit API"),
    };
    if let Some(invalidated_sequence) = invalidated_sequence
        && sequence <= invalidated_sequence
    {
        return Err(AuditError::ReconciliationSequenceNotNewer {
            channel,
            cid: cid.to_string(),
            sequence: i64_to_u64(sequence, "sequence")?,
            invalidated_sequence: i64_to_u64(invalidated_sequence, "invalidated_sequence")?,
        });
    }
    Ok(())
}

pub struct Retention;

impl Retention {
    pub async fn sweep(
        pool: &PgPool,
        ipfs_client: &dyn IpfsClient,
        now: SystemTime,
        retention_interval: Duration,
    ) -> Result<RetentionSweep, AuditError> {
        let coordinator = PinLifecycleCoordinator::default();
        Self::sweep_with_coordinator(pool, ipfs_client, now, retention_interval, &coordinator).await
    }

    pub async fn sweep_with_coordinator(
        pool: &PgPool,
        ipfs_client: &dyn IpfsClient,
        now: SystemTime,
        retention_interval: Duration,
        coordinator: &PinLifecycleCoordinator,
    ) -> Result<RetentionSweep, AuditError> {
        let cutoff = unix_seconds(
            now.checked_sub(retention_interval)
                .ok_or(AuditError::TimeBeforeUnixEpoch)?,
        )?;
        let swept_at = unix_seconds(now)?;
        let (mut unpinned_cids, mut failed_cids) =
            retry_pin_cleanup_debt(pool, ipfs_client, coordinator).await?;
        sqlx::query(
            r"
            UPDATE published_snapshots AS delta
            SET superseded_at = to_timestamp($2)
            WHERE delta.kind = 'delta'
                AND delta.superseded_at IS NULL
                AND EXISTS (
                    SELECT 1
                    FROM published_snapshots AS active_base
                    WHERE active_base.list_key = delta.list_key
                        AND active_base.chain_id = delta.chain_id
                        AND active_base.upstream_url = delta.upstream_url
                        AND active_base.kind = 'base'
                        AND active_base.superseded_at IS NULL
                        AND active_base.end_index >= delta.end_index
                )
                AND EXISTS (
                    SELECT 1
                    FROM published_snapshots AS retained_base
                    WHERE retained_base.list_key = delta.list_key
                        AND retained_base.chain_id = delta.chain_id
                        AND retained_base.upstream_url = delta.upstream_url
                        AND retained_base.kind = 'base'
                        AND retained_base.unpinned_at IS NULL
                        AND retained_base.end_index >= delta.end_index
                        AND retained_base.published_at <= to_timestamp($1)
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
                UNION
                SELECT cid
                FROM published_indexed_artifacts
                WHERE unpinned_at IS NULL
                GROUP BY cid
                HAVING MAX(last_referenced_at) <= to_timestamp($1)
                UNION
                SELECT cid
                FROM published_poi_v4_manifests
                WHERE unpinned_at IS NULL
                    AND superseded_at IS NOT NULL
                    AND superseded_at <= to_timestamp($1)
                UNION
                SELECT cid
                FROM published_poi_v4_artifacts
                WHERE unpinned_at IS NULL
                GROUP BY cid
                HAVING MAX(last_referenced_at) <= to_timestamp($1)
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
                        AND active.last_referenced_at > to_timestamp($1)
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM published_indexed_manifest_artifacts AS reference
                    JOIN published_indexed_manifests AS manifest
                        ON manifest.id = reference.manifest_id
                    WHERE reference.artifact_cid = candidates.cid
                        AND manifest.superseded_at IS NULL
                        AND manifest.unpinned_at IS NULL
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM published_poi_v4_manifests AS manifest
                    WHERE manifest.cid = candidates.cid
                        AND manifest.superseded_at IS NULL
                        AND manifest.unpinned_at IS NULL
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM published_poi_v4_artifacts AS artifact
                    WHERE artifact.cid = candidates.cid
                        AND artifact.unpinned_at IS NULL
                        AND artifact.last_referenced_at > to_timestamp($1)
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM published_poi_v4_manifest_artifacts AS reference
                    JOIN published_poi_v4_manifests AS manifest
                        ON manifest.id = reference.manifest_id
                    WHERE reference.artifact_cid = candidates.cid
                        AND manifest.superseded_at IS NULL
                        AND manifest.unpinned_at IS NULL
                )
            ORDER BY candidates.cid ASC
            ",
        )
        .bind(cutoff)
        .fetch_all(pool)
        .await?;

        unpinned_cids.reserve(cids.len());
        for cid_text in cids {
            let cid = parse_cid(&cid_text)?;
            let _pin_lifecycle = coordinator.lock().await;
            let mut tx = pool.begin().await?;
            let still_eligible = sqlx::query_scalar::<_, bool>(
                r"
                SELECT (
                    (
                        EXISTS (
                            SELECT 1
                            FROM published_snapshots
                            WHERE cid = $1
                                AND superseded_at IS NOT NULL
                                AND superseded_at <= to_timestamp($2)
                                AND unpinned_at IS NULL
                        )
                        OR EXISTS (
                            SELECT 1
                            FROM published_blocked_shields
                            WHERE cid = $1
                                AND superseded_at IS NOT NULL
                                AND superseded_at <= to_timestamp($2)
                                AND unpinned_at IS NULL
                        )
                        OR EXISTS (
                            SELECT 1
                            FROM published_manifests
                            WHERE cid = $1
                                AND unpinned_at IS NULL
                                AND superseded_at IS NOT NULL
                                AND superseded_at <= to_timestamp($2)
                        )
                        OR EXISTS (
                            SELECT 1
                            FROM published_indexed_manifests
                            WHERE cid = $1
                                AND unpinned_at IS NULL
                                AND superseded_at IS NOT NULL
                                AND superseded_at <= to_timestamp($2)
                        )
                        OR EXISTS (
                            SELECT 1
                            FROM published_indexed_artifacts
                            WHERE cid = $1
                                AND unpinned_at IS NULL
                            GROUP BY cid
                            HAVING MAX(last_referenced_at) <= to_timestamp($2)
                        )
                        OR EXISTS (
                            SELECT 1
                            FROM published_poi_v4_manifests
                            WHERE cid = $1
                                AND unpinned_at IS NULL
                                AND superseded_at IS NOT NULL
                                AND superseded_at <= to_timestamp($2)
                        )
                        OR EXISTS (
                            SELECT 1
                            FROM published_poi_v4_artifacts
                            WHERE cid = $1 AND unpinned_at IS NULL
                            GROUP BY cid
                            HAVING MAX(last_referenced_at) <= to_timestamp($2)
                        )
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_snapshots AS active
                        WHERE active.cid = $1
                            AND active.superseded_at IS NULL
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_blocked_shields AS active
                        WHERE active.cid = $1
                            AND active.superseded_at IS NULL
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_manifests AS active
                        WHERE active.cid = $1
                            AND active.ipns_published_at IS NOT NULL
                            AND active.superseded_at IS NULL
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_indexed_manifests AS active
                        WHERE active.cid = $1
                            AND active.ipns_published_at IS NOT NULL
                            AND active.superseded_at IS NULL
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_indexed_artifacts AS active
                        WHERE active.cid = $1
                            AND active.unpinned_at IS NULL
                            AND active.last_referenced_at > to_timestamp($2)
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_indexed_manifest_artifacts AS reference
                        JOIN published_indexed_manifests AS manifest
                            ON manifest.id = reference.manifest_id
                        WHERE reference.artifact_cid = $1
                            AND manifest.superseded_at IS NULL
                            AND manifest.unpinned_at IS NULL
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_poi_v4_manifests AS manifest
                        WHERE manifest.cid = $1
                            AND manifest.superseded_at IS NULL
                            AND manifest.unpinned_at IS NULL
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_poi_v4_artifacts AS artifact
                        WHERE artifact.cid = $1
                            AND artifact.unpinned_at IS NULL
                            AND artifact.last_referenced_at > to_timestamp($2)
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_poi_v4_manifest_artifacts AS reference
                        JOIN published_poi_v4_manifests AS manifest
                            ON manifest.id = reference.manifest_id
                        WHERE reference.artifact_cid = $1
                            AND manifest.superseded_at IS NULL
                            AND manifest.unpinned_at IS NULL
                    )
                )
                ",
            )
            .bind(&cid_text)
            .bind(cutoff)
            .fetch_one(&mut *tx)
            .await?;
            if !still_eligible {
                tx.rollback().await?;
                continue;
            }
            if let Err(error) = ipfs_client.unpin(&cid).await {
                tx.rollback().await?;
                warn!(cid = %cid, error = %error, "failed to unpin stale railgun-indexer publication CID");
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
                            AND active.last_referenced_at > to_timestamp($3)
                    )
                ",
            )
            .bind(swept_at)
            .bind(&cid_text)
            .bind(cutoff)
            .execute(&mut *tx)
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
                            AND active.last_referenced_at > to_timestamp($3)
                    )
                ",
            )
            .bind(swept_at)
            .bind(&cid_text)
            .bind(cutoff)
            .execute(&mut *tx)
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
                            AND active.last_referenced_at > to_timestamp($3)
                    )
                ",
            )
            .bind(swept_at)
            .bind(&cid_text)
            .bind(cutoff)
            .execute(&mut *tx)
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
                            AND active.last_referenced_at > to_timestamp($3)
                    )
                ",
            )
            .bind(swept_at)
            .bind(&cid_text)
            .bind(cutoff)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                r"
                UPDATE published_indexed_artifacts
                SET unpinned_at = to_timestamp($1)
                WHERE cid = $2
                    AND unpinned_at IS NULL
                    AND last_referenced_at <= to_timestamp($3)
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
                            AND active.last_referenced_at > to_timestamp($3)
                    )
                ",
            )
            .bind(swept_at)
            .bind(&cid_text)
            .bind(cutoff)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                r"
                UPDATE published_poi_v4_manifests
                SET unpinned_at = to_timestamp($1)
                WHERE cid = $2
                    AND unpinned_at IS NULL
                    AND superseded_at IS NOT NULL
                    AND superseded_at <= to_timestamp($3)
                ",
            )
            .bind(swept_at)
            .bind(&cid_text)
            .bind(cutoff)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                r"
                UPDATE published_poi_v4_artifacts
                SET unpinned_at = to_timestamp($1)
                WHERE cid = $2
                    AND unpinned_at IS NULL
                    AND last_referenced_at <= to_timestamp($3)
                ",
            )
            .bind(swept_at)
            .bind(&cid_text)
            .bind(cutoff)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            info!(cid = %cid, "unpinned stale railgun-indexer publication CID");
            unpinned_cids.push(cid);
        }

        Ok(RetentionSweep {
            unpinned_cids,
            failed_cids,
        })
    }
}

async fn retry_pin_cleanup_debt(
    pool: &PgPool,
    ipfs_client: &dyn IpfsClient,
    coordinator: &PinLifecycleCoordinator,
) -> Result<(Vec<Cid>, Vec<RetentionFailure>), AuditError> {
    let debts = sqlx::query_as::<_, (String, i64)>(
        "SELECT cid, attempts FROM pin_cleanup_debt ORDER BY created_at, cid",
    )
    .fetch_all(pool)
    .await?;
    let mut cleaned = Vec::new();
    let mut failed = Vec::new();
    for (cid_text, attempts) in debts {
        let cid = parse_cid(&cid_text)?;
        let _pin_lifecycle = coordinator.lock().await;
        if Audit::publication_cid_is_referenced(pool, &cid).await? {
            sqlx::query("DELETE FROM pin_cleanup_debt WHERE cid = $1")
                .bind(&cid_text)
                .execute(pool)
                .await?;
            continue;
        }
        match ipfs_client.unpin(&cid).await {
            Ok(()) => {
                sqlx::query("DELETE FROM pin_cleanup_debt WHERE cid = $1")
                    .bind(&cid_text)
                    .execute(pool)
                    .await?;
                cleaned.push(cid);
            }
            Err(error) => {
                let next_attempts =
                    attempts
                        .checked_add(1)
                        .ok_or(AuditError::IntegerOutOfRange {
                            field: "pin_cleanup_debt attempts",
                            value: attempts.to_string(),
                        })?;
                sqlx::query(
                    "UPDATE pin_cleanup_debt SET attempts = $2, last_error = $3, updated_at = now() WHERE cid = $1",
                )
                .bind(&cid_text)
                .bind(next_attempts)
                .bind(error.to_string())
                .execute(pool)
                .await?;
                failed.push(RetentionFailure {
                    cid,
                    error: error.to_string(),
                });
            }
        }
    }
    Ok((cleaned, failed))
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
    #[error("{channel} manifest {cid} at sequence {sequence} is still pending IPNS reconciliation")]
    UnresolvedPendingManifest {
        channel: &'static str,
        cid: String,
        sequence: u64,
    },
    #[error("{channel} has {count} unresolved pending manifests")]
    AmbiguousPendingManifests { channel: &'static str, count: usize },
    #[error(
        "{channel} pending manifest authorization did not exactly match CID {cid} sequence {sequence}"
    )]
    PendingManifestAuthorizationMismatch {
        channel: &'static str,
        cid: String,
        sequence: u64,
    },
    #[error("{channel} manifest {cid} sequence {sequence} is {state} and cannot be invalidated")]
    PendingManifestNotRecoverable {
        channel: &'static str,
        cid: String,
        sequence: u64,
        state: &'static str,
    },
    #[error(
        "{channel} manifest {cid} sequence {sequence} is not newer than invalidated pending sequence {invalidated_sequence}"
    )]
    ReconciliationSequenceNotNewer {
        channel: &'static str,
        cid: String,
        sequence: u64,
        invalidated_sequence: u64,
    },
    #[error(
        "indexed manifest references {expected} distinct artifacts but only {actual} remain live"
    )]
    MissingIndexedManifestArtifacts { expected: usize, actual: usize },
    #[error("chain-indexed manifest {cid} has no persisted body for restart reconciliation")]
    MissingIndexedManifestBody { cid: String },
    #[error("chain-indexed manifest {cid} persisted body does not match its audit identity")]
    IndexedManifestBodyMismatch { cid: String },
    #[error("chain-indexed manifest format validation failed")]
    IndexedManifest(#[source] crate::manifest::IndexedArtifactError),
    #[error(
        "chain-indexed manifest {cid} body sequence {body} does not match stored sequence {stored}"
    )]
    IndexedManifestSequenceMismatch { cid: String, stored: u64, body: u64 },
    #[error("POI v4 JSON encoding failed")]
    Json(#[from] serde_json::Error),
    #[error("POI v4 graph contract validation failed")]
    PoiArtifactContract(#[source] PoiArtifactError),
    #[error("POI v4 artifact CID {cid} conflicts with durable metadata at {byte_size} bytes")]
    PoiArtifactConflict { cid: String, byte_size: u64 },
    #[error("POI v4 manifest references {expected} artifacts but only {actual} remain live")]
    MissingManifestArtifacts { expected: usize, actual: usize },
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

const fn poi_artifact_kind_str(kind: PoiArtifactPublicationKind) -> &'static str {
    match kind {
        PoiArtifactPublicationKind::CheckpointChunk => "checkpoint_chunk",
        PoiArtifactPublicationKind::CheckpointCatalog => "checkpoint_catalog",
        PoiArtifactPublicationKind::CurrentTail => "current_tail",
        PoiArtifactPublicationKind::Bridge => "bridge",
        PoiArtifactPublicationKind::BlockedShields => "blocked_shields",
    }
}

fn poi_artifact_range_columns(range: Option<EventRange>) -> Result<(i64, i64), AuditError> {
    range.map_or(Ok((-1, -1)), |range| {
        Ok((
            u64_to_i64(range.start_index, "range_start")?,
            u64_to_i64(range.end_index, "range_end")?,
        ))
    })
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

fn i64_to_u64(value: i64, field: &'static str) -> Result<u64, AuditError> {
    u64::try_from(value).map_err(|_| AuditError::IntegerOutOfRange {
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

fn i64_to_system_time(value: i64, field: &'static str) -> Result<SystemTime, AuditError> {
    let seconds = u64::try_from(value).map_err(|_| AuditError::IntegerOutOfRange {
        field,
        value: value.to_string(),
    })?;
    Ok(UNIX_EPOCH + Duration::from_secs(seconds))
}

fn parse_cid(value: &str) -> Result<Cid, AuditError> {
    Cid::try_from(value).map_err(|source| AuditError::InvalidCid {
        cid: value.to_string(),
        source,
    })
}

#[cfg(test)]
mod pin_ownership_tests {
    use super::*;

    #[tokio::test]
    async fn concurrent_pin_owners_wait_without_lost_wakeup() {
        let coordinator = PinLifecycleCoordinator::default();
        let first = coordinator
            .try_acquire_pin_ownership()
            .expect("first owner");
        let second = coordinator
            .try_acquire_pin_ownership()
            .expect("second owner");
        let waiting = coordinator.clone();
        let mut waiter = tokio::spawn(async move {
            waiting.wait_for_no_pin_owners().await;
        });

        first.settle();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut waiter)
                .await
                .is_err()
        );
        second.settle();
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter notified")
            .expect("waiter task");
        assert_eq!(coordinator.active_pin_owners(), 0);
    }

    #[test]
    fn shutdown_closes_new_pin_ownership_admission() {
        let coordinator = PinLifecycleCoordinator::default();
        coordinator.stop_new_pin_ownership();
        assert!(coordinator.try_acquire_pin_ownership().is_none());
        assert_eq!(coordinator.active_pin_owners(), 0);
    }

    #[test]
    fn dropped_unsettled_lease_remains_visible() {
        let coordinator = PinLifecycleCoordinator::default();
        drop(
            coordinator
                .try_acquire_pin_ownership()
                .expect("owner admitted"),
        );
        assert_eq!(coordinator.active_pin_owners(), 1);
    }
}
