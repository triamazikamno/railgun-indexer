use alloy_primitives::{FixedBytes, hex};
use poi::artifacts::v4::ManifestEntry;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

pub type SharedStatus = Arc<RwLock<Status>>;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub pairs: Vec<PairSyncStatus>,
    pub last_published_manifest_cid: Option<String>,
    pub ipfs_reachable: bool,
    pub poi_ipns_name: Option<String>,
    pub poi_v4_ipns_name: Option<String>,
    pub chain_indexed_ipns_name: Option<String>,
    pub poi_peer_id: Option<String>,
    pub poi_v4_peer_id: Option<String>,
    pub chain_indexed_peer_id: Option<String>,
    #[serde(rename = "poi_v4_publication")]
    pub poi_artifact_publication: Option<PoiArtifactPublicationStatus>,
    pub last_retention_sweep: Option<RetentionSweepStatus>,
}

impl Status {
    #[must_use]
    pub fn for_pairs(
        list_keys: &[FixedBytes<32>],
        chain_ids: &[u64],
        initial_page_size: usize,
    ) -> Self {
        let pairs = list_keys
            .iter()
            .flat_map(|list_key| {
                chain_ids.iter().map(|chain_id| {
                    PairSyncStatus::new(list_key_hex(list_key), *chain_id, initial_page_size)
                })
            })
            .collect();

        Self {
            pairs,
            last_published_manifest_cid: None,
            ipfs_reachable: false,
            poi_ipns_name: None,
            poi_v4_ipns_name: None,
            chain_indexed_ipns_name: None,
            poi_peer_id: None,
            poi_v4_peer_id: None,
            chain_indexed_peer_id: None,
            poi_artifact_publication: None,
            last_retention_sweep: None,
        }
    }

    #[must_use]
    pub fn shared(self) -> SharedStatus {
        Arc::new(RwLock::new(self))
    }

    pub fn record_page_success(
        &mut self,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        last_event_index: u64,
        current_page_size: usize,
    ) {
        let now = unix_now();
        let pair = self.ensure_pair(list_key, chain_id, current_page_size);
        pair.last_event_index = Some(last_event_index);
        pair.last_successful_page_unix_seconds = Some(now);
        pair.seconds_since_last_page = Some(0);
        pair.current_page_size = current_page_size;
        pair.retry_backoff = RetryBackoffStatus::idle();
    }

    pub fn record_page_failure(
        &mut self,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        current_page_size: usize,
        attempts: usize,
        next_backoff: Option<Duration>,
        error: String,
    ) {
        let pair = self.ensure_pair(list_key, chain_id, current_page_size);
        pair.current_page_size = current_page_size;
        pair.retry_backoff = RetryBackoffStatus {
            state: if next_backoff.is_some() {
                RetryBackoffState::BackingOff
            } else {
                RetryBackoffState::Failed
            },
            attempts,
            next_backoff_seconds: next_backoff.map(|duration| duration.as_secs()),
            last_error: Some(error),
        };
    }

    pub fn record_manifest_publication(&mut self, manifest_cid: impl Into<String>) {
        self.last_published_manifest_cid = Some(manifest_cid.into());
        self.ipfs_reachable = true;
    }

    pub const fn set_ipfs_reachable(&mut self, reachable: bool) {
        self.ipfs_reachable = reachable;
    }

    pub fn set_ipns_identities(
        &mut self,
        poi_ipns_name: impl Into<String>,
        poi_v4_ipns_name: impl Into<String>,
        chain_indexed_ipns_name: impl Into<String>,
        poi_peer_id: impl Into<String>,
        poi_v4_peer_id: impl Into<String>,
        chain_indexed_peer_id: impl Into<String>,
    ) {
        self.poi_ipns_name = Some(poi_ipns_name.into());
        self.poi_v4_ipns_name = Some(poi_v4_ipns_name.into());
        self.chain_indexed_ipns_name = Some(chain_indexed_ipns_name.into());
        self.poi_peer_id = Some(poi_peer_id.into());
        self.poi_v4_peer_id = Some(poi_v4_peer_id.into());
        self.chain_indexed_peer_id = Some(chain_indexed_peer_id.into());
    }

    pub fn record_poi_artifact_publication(
        &mut self,
        manifest_cid: String,
        sequence: u64,
        entries: &[ManifestEntry],
        checkpoint_chunks: usize,
        checkpoint_bytes: u64,
        tail_bytes: u64,
        bridge_count: usize,
        reused_cids: usize,
        elapsed_ms: u64,
    ) {
        self.ipfs_reachable = true;
        self.poi_artifact_publication = Some(PoiArtifactPublicationStatus::new(
            manifest_cid,
            sequence,
            entries,
            checkpoint_chunks,
            Some(checkpoint_bytes),
            tail_bytes,
            bridge_count,
            Some(reused_cids),
            Some(elapsed_ms),
        ));
    }

    pub fn restore_poi_artifact_publication(
        &mut self,
        manifest_cid: String,
        sequence: u64,
        entries: &[ManifestEntry],
    ) {
        let checkpoint_chunks = entries.iter().fold(0_usize, |total, entry| {
            total.saturating_add(
                usize::try_from(entry.checkpoint_catalog.chunk_count).unwrap_or(usize::MAX),
            )
        });
        let tail_bytes = entries.iter().fold(0_u64, |total, entry| {
            total.saturating_add(
                entry
                    .current_tail
                    .as_ref()
                    .map_or(0, |tail| tail.artifact.byte_size),
            )
        });
        let bridge_count = entries.iter().fold(0_usize, |total, entry| {
            total.saturating_add(entry.retained_bridges.len())
        });
        self.poi_artifact_publication = Some(PoiArtifactPublicationStatus::new(
            manifest_cid,
            sequence,
            entries,
            checkpoint_chunks,
            None,
            tail_bytes,
            bridge_count,
            None,
            None,
        ));
    }

    pub fn clear_poi_artifact_publication(&mut self) {
        self.poi_artifact_publication = None;
    }

    pub fn record_retention_sweep(&mut self, unpinned_count: usize, failed_count: usize) {
        self.last_retention_sweep = Some(RetentionSweepStatus {
            completed_unix_seconds: unix_now(),
            unpinned_count,
            failed_count,
        });
    }

    #[must_use]
    pub fn snapshot_at(&self, now: SystemTime) -> Self {
        let now = unix_seconds(now);
        let mut status = self.clone();
        for pair in &mut status.pairs {
            pair.seconds_since_last_page = pair
                .last_successful_page_unix_seconds
                .and_then(|last_page| now.checked_sub(last_page))
                .and_then(|seconds| u64::try_from(seconds).ok());
        }
        status
    }

    fn ensure_pair(
        &mut self,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        initial_page_size: usize,
    ) -> &mut PairSyncStatus {
        let list_key = list_key_hex(list_key);
        if let Some(index) = self
            .pairs
            .iter()
            .position(|pair| pair.list_key == list_key && pair.chain_id == chain_id)
        {
            return &mut self.pairs[index];
        }

        self.pairs
            .push(PairSyncStatus::new(list_key, chain_id, initial_page_size));
        self.pairs
            .last_mut()
            .expect("just pushed pair status must exist")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoiArtifactPublicationStatus {
    pub manifest_cid: String,
    pub sequence: u64,
    pub checkpoint_chunks: usize,
    pub checkpoint_bytes: Option<u64>,
    pub tail_bytes: u64,
    pub bridge_count: usize,
    pub reused_cids: Option<usize>,
    pub elapsed_ms: Option<u64>,
    pub scopes: Vec<PoiArtifactScopePublicationStatus>,
}

impl PoiArtifactPublicationStatus {
    fn new(
        manifest_cid: String,
        sequence: u64,
        entries: &[ManifestEntry],
        checkpoint_chunks: usize,
        checkpoint_bytes: Option<u64>,
        tail_bytes: u64,
        bridge_count: usize,
        reused_cids: Option<usize>,
        elapsed_ms: Option<u64>,
    ) -> Self {
        Self {
            manifest_cid,
            sequence,
            checkpoint_chunks,
            checkpoint_bytes,
            tail_bytes,
            bridge_count,
            reused_cids,
            elapsed_ms,
            scopes: entries
                .iter()
                .map(PoiArtifactScopePublicationStatus::from)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoiArtifactScopePublicationStatus {
    pub list_key: String,
    pub chain_type: u8,
    pub chain_id: u64,
    pub txid_version: String,
    pub event_count: u64,
    pub checkpoint_tip_index: Option<u64>,
    pub checkpoint_chunk_count: u64,
    pub checkpoint_catalog_bytes: u64,
    pub tail_start_index: Option<u64>,
    pub tail_end_index: Option<u64>,
    pub tail_bytes: u64,
    pub bridge_count: usize,
    pub bridge_start_index: Option<u64>,
    pub bridge_end_index: Option<u64>,
}

impl From<&ManifestEntry> for PoiArtifactScopePublicationStatus {
    fn from(entry: &ManifestEntry) -> Self {
        Self {
            list_key: hex::encode_prefixed(entry.scope.list_key.as_slice()),
            chain_type: entry.scope.chain_type,
            chain_id: entry.scope.chain_id,
            txid_version: entry.scope.txid_version.clone(),
            event_count: entry.event_count,
            checkpoint_tip_index: entry.checkpoint_catalog.range.map(|range| range.end_index),
            checkpoint_chunk_count: entry.checkpoint_catalog.chunk_count,
            checkpoint_catalog_bytes: entry.checkpoint_catalog.artifact.byte_size,
            tail_start_index: entry
                .current_tail
                .as_ref()
                .map(|tail| tail.range.start_index),
            tail_end_index: entry.current_tail.as_ref().map(|tail| tail.range.end_index),
            tail_bytes: entry
                .current_tail
                .as_ref()
                .map_or(0, |tail| tail.artifact.byte_size),
            bridge_count: entry.retained_bridges.len(),
            bridge_start_index: entry
                .retained_bridges
                .first()
                .map(|bridge| bridge.range.start_index),
            bridge_end_index: entry
                .retained_bridges
                .last()
                .map(|bridge| bridge.range.end_index),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionSweepStatus {
    pub completed_unix_seconds: i64,
    pub unpinned_count: usize,
    pub failed_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairSyncStatus {
    pub list_key: String,
    pub chain_id: u64,
    pub last_event_index: Option<u64>,
    pub last_successful_page_unix_seconds: Option<i64>,
    pub seconds_since_last_page: Option<u64>,
    pub current_page_size: usize,
    pub retry_backoff: RetryBackoffStatus,
}

impl PairSyncStatus {
    #[must_use]
    pub const fn new(list_key: String, chain_id: u64, current_page_size: usize) -> Self {
        Self {
            list_key,
            chain_id,
            last_event_index: None,
            last_successful_page_unix_seconds: None,
            seconds_since_last_page: None,
            current_page_size,
            retry_backoff: RetryBackoffStatus::idle(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryBackoffStatus {
    pub state: RetryBackoffState,
    pub attempts: usize,
    pub next_backoff_seconds: Option<u64>,
    pub last_error: Option<String>,
}

impl RetryBackoffStatus {
    #[must_use]
    pub const fn idle() -> Self {
        Self {
            state: RetryBackoffState::Idle,
            attempts: 0,
            next_backoff_seconds: None,
            last_error: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryBackoffState {
    Idle,
    BackingOff,
    Failed,
}

fn list_key_hex(list_key: &FixedBytes<32>) -> String {
    hex::encode_prefixed(list_key.as_slice())
}

fn unix_now() -> i64 {
    unix_seconds(SystemTime::now())
}

fn unix_seconds(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_snapshot_refreshes_time_since_last_page() {
        let list_key = FixedBytes::from([1_u8; 32]);
        let mut status = Status::for_pairs(&[list_key], &[1], 500);

        status.record_page_success(&list_key, 1, 9, 250);
        status.pairs[0].last_successful_page_unix_seconds = Some(100);

        let snapshot = status.snapshot_at(UNIX_EPOCH + Duration::from_secs(130));

        assert_eq!(snapshot.pairs[0].last_event_index, Some(9));
        assert_eq!(snapshot.pairs[0].seconds_since_last_page, Some(30));
        assert_eq!(snapshot.pairs[0].current_page_size, 250);
        assert_eq!(
            snapshot.pairs[0].retry_backoff.state,
            RetryBackoffState::Idle
        );
    }
}
