use crate::blocked::{BlockedShieldsArtifact, BlockedShieldsArtifactError};
use crate::snapshot::format::FORMAT_VERSION;
use crate::snapshot::{
    SnapshotError, SnapshotEvent, SnapshotHeaderInput, SnapshotKind, SnapshotWriter,
};
use crate::store::{Store, StoreError, StoredBlockedShield, StoredEvent};
use alloy_primitives::{FixedBytes, hex};
use poi::artifacts::v4::{
    BlockedShieldsArtifact as PoiBlockedShieldsArtifact, Error as PoiArtifactError, Scope,
};
use poi::poi::SignedBlockedShield;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Lifecycle {
    store: Store,
    upstream_url: String,
    chain_type: u8,
    upstream_endpoint_hash: [u8; 32],
}

impl Lifecycle {
    #[must_use]
    pub const fn new(
        store: Store,
        upstream_url: String,
        chain_type: u8,
        upstream_endpoint_hash: [u8; 32],
    ) -> Self {
        Self {
            store,
            upstream_url,
            chain_type,
            upstream_endpoint_hash,
        }
    }

    pub async fn build_base(
        &self,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        end_index: u64,
    ) -> Result<Vec<u8>, LifecycleError> {
        let events = self
            .store
            .page_event_range(list_key, chain_id, 0, end_index)
            .await?;
        let header = self
            .snapshot_header(list_key, chain_id, SnapshotKind::Base, 0, end_index)
            .await?;
        encode_legacy_snapshot(&header, &events).map_err(LifecycleError::Snapshot)
    }

    pub async fn build_delta(
        &self,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        start_index: u64,
        end_index: u64,
    ) -> Result<Vec<u8>, LifecycleError> {
        let events = self
            .store
            .page_event_range(list_key, chain_id, start_index, end_index)
            .await?;
        let header = self
            .snapshot_header(
                list_key,
                chain_id,
                SnapshotKind::Delta,
                start_index,
                end_index,
            )
            .await?;
        encode_legacy_snapshot(&header, &events).map_err(LifecycleError::Snapshot)
    }

    pub async fn build_blocked_shields_artifact(
        &self,
        list_key: &FixedBytes<32>,
        chain_id: u64,
    ) -> Result<EncodedLegacyBlockedShieldsArtifact, LifecycleError> {
        let blocked_shields = self.store.all_blocked_shields(list_key, chain_id).await?;
        encode_legacy_blocked_shields_artifact(
            list_key,
            chain_id,
            self.chain_type,
            &self.upstream_endpoint_hash,
            &blocked_shields,
        )
        .map_err(LifecycleError::BlockedShieldsArtifact)
    }

    pub async fn build_poi_blocked_shields_artifact(
        &self,
        scope: &Scope,
    ) -> Result<EncodedPoiBlockedShieldsArtifact, LifecycleError> {
        let blocked_shields = self
            .store
            .all_blocked_shields(&scope.list_key, scope.chain_id)
            .await?;
        encode_poi_blocked_shields_artifact(scope, &blocked_shields)
            .map_err(LifecycleError::PoiArtifact)
    }

    #[must_use]
    pub fn should_publish_delta(
        current_tip: u64,
        last_published_delta_tip: Option<u64>,
        last_published_at: Option<SystemTime>,
        now: SystemTime,
        delta_publish_interval: Duration,
    ) -> bool {
        let tip_advanced = last_published_delta_tip.is_none_or(|tip| current_tip > tip);
        let interval_elapsed = last_published_at.is_none_or(|published_at| {
            now.duration_since(published_at)
                .is_ok_and(|elapsed| elapsed >= delta_publish_interval)
        });
        tip_advanced && interval_elapsed
    }

    #[must_use]
    pub fn should_rebuild_base(
        last_base_at: Option<SystemTime>,
        now: SystemTime,
        base_rebuild_interval: Duration,
    ) -> bool {
        last_base_at.is_none_or(|published_at| {
            now.duration_since(published_at)
                .is_ok_and(|elapsed| elapsed >= base_rebuild_interval)
        })
    }

    async fn snapshot_header(
        &self,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        kind: SnapshotKind,
        start_index: u64,
        end_index: u64,
    ) -> Result<SnapshotHeaderInput, LifecycleError> {
        let tip = self
            .store
            .chain_tip(list_key, chain_id, &self.upstream_url)
            .await?
            .ok_or(LifecycleError::MissingChainTip { chain_id })?;
        if tip.last_event_index < end_index {
            return Err(LifecycleError::TipBeforeSnapshotEnd {
                tip_index: tip.last_event_index,
                end_index,
            });
        }
        let tip_merkleroot = tip
            .last_tip_merkleroot
            .ok_or(LifecycleError::MissingTipMerkleroot)?;

        Ok(SnapshotHeaderInput {
            list_key: fixed_bytes(list_key),
            chain_id,
            chain_type: self.chain_type,
            kind,
            start_index,
            end_index,
            tip_merkleroot,
            upstream_endpoint_hash: self.upstream_endpoint_hash,
            created_at_unix_seconds: unix_now()?,
        })
    }
}

#[derive(Debug, Error)]
pub enum LifecycleError {
    #[error("store operation failed")]
    Store(#[from] StoreError),
    #[error("snapshot encode failed")]
    Snapshot(#[from] SnapshotError),
    #[error("blocked-shields artifact encode failed")]
    BlockedShieldsArtifact(#[from] BlockedShieldsArtifactError),
    #[error("POI v4 blocked-shields artifact encode failed")]
    PoiArtifact(#[from] PoiArtifactError),
    #[error("missing chain tip for chain_id={chain_id}")]
    MissingChainTip { chain_id: u64 },
    #[error("chain tip is missing tip merkleroot")]
    MissingTipMerkleroot,
    #[error("chain tip {tip_index} is before requested snapshot end {end_index}")]
    TipBeforeSnapshotEnd { tip_index: u64, end_index: u64 },
    #[error("{field} has {actual} bytes, expected {expected}")]
    InvalidByteLen {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("system clock is before unix epoch")]
    TimeBeforeUnixEpoch(#[source] std::time::SystemTimeError),
}

const fn fixed_bytes(value: &FixedBytes<32>) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes.copy_from_slice(value.as_slice());
    bytes
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedLegacyBlockedShieldsArtifact {
    pub bytes: Vec<u8>,
    pub row_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedPoiBlockedShieldsArtifact {
    pub bytes: Vec<u8>,
    pub row_count: usize,
}

#[must_use]
pub fn legacy_snapshot_events(events: &[StoredEvent]) -> Vec<SnapshotEvent> {
    events
        .iter()
        .map(|event| SnapshotEvent {
            event_index: event.event_index,
            blinded_commitment: event.blinded_commitment,
            // Released alpha snapshots were leaf-derived. Preserve those bytes while
            // the v4 publisher consumes the signed fields from the shared event store.
            signature: [0; 64],
            event_type: poi::poi::PoiEventType::Shield,
        })
        .collect()
}

pub fn encode_legacy_snapshot(
    header: &SnapshotHeaderInput,
    events: &[StoredEvent],
) -> Result<Vec<u8>, SnapshotError> {
    SnapshotWriter::write(header, &legacy_snapshot_events(events))
}

pub fn encode_legacy_blocked_shields_artifact(
    list_key: &FixedBytes<32>,
    chain_id: u64,
    chain_type: u8,
    upstream_endpoint_hash: &[u8; 32],
    records: &[StoredBlockedShield],
) -> Result<EncodedLegacyBlockedShieldsArtifact, BlockedShieldsArtifactError> {
    let blocked_shields = records
        .iter()
        .map(signed_blocked_shield)
        .collect::<Vec<_>>();
    let artifact = BlockedShieldsArtifact::from_signed_records(
        FORMAT_VERSION,
        &fixed_bytes(list_key),
        chain_id,
        chain_type,
        upstream_endpoint_hash,
        &blocked_shields,
    );
    Ok(EncodedLegacyBlockedShieldsArtifact {
        bytes: artifact.to_bytes()?,
        row_count: blocked_shields.len(),
    })
}

pub fn encode_poi_blocked_shields_artifact(
    scope: &Scope,
    records: &[StoredBlockedShield],
) -> Result<EncodedPoiBlockedShieldsArtifact, PoiArtifactError> {
    let blocked_shields = records
        .iter()
        .map(signed_blocked_shield)
        .collect::<Vec<_>>();
    let artifact = PoiBlockedShieldsArtifact::from_signed_records(scope.clone(), &blocked_shields);
    Ok(EncodedPoiBlockedShieldsArtifact {
        bytes: artifact.to_bytes()?,
        row_count: blocked_shields.len(),
    })
}

fn signed_blocked_shield(record: &StoredBlockedShield) -> SignedBlockedShield {
    SignedBlockedShield {
        commitment_hash: hex::encode_prefixed(record.commitment_hash),
        blinded_commitment: hex::encode_prefixed(record.blinded_commitment),
        block_reason: record.block_reason.clone(),
        signature: hex::encode_prefixed(record.signature),
    }
}

fn unix_now() -> Result<i64, LifecycleError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(LifecycleError::TimeBeforeUnixEpoch)?;
    i64::try_from(duration.as_secs()).map_err(|_| LifecycleError::InvalidByteLen {
        field: "created_at_unix_seconds",
        expected: std::mem::size_of::<i64>(),
        actual: std::mem::size_of::<u64>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use poi::artifacts::ArtifactDescriptor;
    use poi::artifacts::v4::{
        ArtifactEncoding, BlockedShieldsDescriptor, Compression,
        FORMAT_VERSION as POI_ARTIFACT_FORMAT_VERSION,
    };
    use poi::artifacts::verify::canonical_blocked_shield_message;
    use poi::poi::PoiEventType;

    #[test]
    fn delta_publish_requires_tip_advance_and_elapsed_interval() {
        let now = UNIX_EPOCH + Duration::from_secs(100);

        assert!(Lifecycle::should_publish_delta(
            10,
            Some(9),
            Some(UNIX_EPOCH + Duration::from_secs(50)),
            now,
            Duration::from_secs(30),
        ));
        assert!(!Lifecycle::should_publish_delta(
            10,
            Some(10),
            Some(UNIX_EPOCH + Duration::from_secs(50)),
            now,
            Duration::from_secs(30),
        ));
        assert!(!Lifecycle::should_publish_delta(
            11,
            Some(10),
            Some(UNIX_EPOCH + Duration::from_secs(90)),
            now,
            Duration::from_secs(30),
        ));
    }

    #[test]
    fn base_rebuild_requires_elapsed_interval() {
        let now = UNIX_EPOCH + Duration::from_secs(100);

        assert!(Lifecycle::should_rebuild_base(
            Some(UNIX_EPOCH + Duration::from_secs(50)),
            now,
            Duration::from_secs(30),
        ));
        assert!(!Lifecycle::should_rebuild_base(
            Some(UNIX_EPOCH + Duration::from_secs(90)),
            now,
            Duration::from_secs(30),
        ));
    }

    #[test]
    fn legacy_snapshot_encoding_strips_source_signatures_and_forces_shield() {
        let header = SnapshotHeaderInput {
            list_key: [9; 32],
            chain_id: 1,
            chain_type: 0,
            kind: SnapshotKind::Base,
            start_index: 0,
            end_index: 0,
            tip_merkleroot: [8; 32],
            upstream_endpoint_hash: [7; 32],
            created_at_unix_seconds: 1_767_225_600,
        };
        let source = [StoredEvent {
            event_index: 0,
            blinded_commitment: [3; 32],
            signature: [4; 64],
            event_type: PoiEventType::Transact,
        }];

        let bytes = encode_legacy_snapshot(&header, &source).expect("encode legacy snapshot");
        let decoded = crate::snapshot::SnapshotReader::read(&bytes).expect("decode snapshot");

        assert_eq!(decoded.events[0].signature, [0; 64]);
        assert_eq!(decoded.events[0].event_type, PoiEventType::Shield);
        assert_eq!(
            bytes,
            encode_legacy_snapshot(&header, &source).expect("deterministic encoding")
        );
    }

    #[test]
    fn legacy_blocked_shield_encoding_is_deterministic_and_preserves_rows() {
        let list_key = FixedBytes::from([9; 32]);
        let records = [StoredBlockedShield {
            commitment_hash: [3; 32],
            blinded_commitment: [4; 32],
            block_reason: Some("fixture".to_string()),
            signature: [5; 64],
        }];

        let encoded = encode_legacy_blocked_shields_artifact(&list_key, 1, 0, &[7; 32], &records)
            .expect("encode blocked shields");
        let repeated = encode_legacy_blocked_shields_artifact(&list_key, 1, 0, &[7; 32], &records)
            .expect("repeat blocked-shield encoding");
        let decoded = BlockedShieldsArtifact::read(&encoded.bytes).expect("decode artifact");

        assert_eq!(encoded, repeated);
        assert_eq!(encoded.row_count, 1);
        assert_eq!(
            decoded.blocked_shields[0].signature,
            hex::encode_prefixed([5; 64])
        );
    }

    #[test]
    fn v4_blocked_shield_descriptor_verifies_empty_artifact() {
        let scope = Scope::new(FixedBytes::from([9; 32]), 0, 1, "V2_PoseidonMerkle");

        verify_poi_blocked_shields(&scope, &[]);
    }

    #[test]
    fn v4_blocked_shield_descriptor_verifies_signed_artifact() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let scope = Scope::new(
            FixedBytes::from(signing_key.verifying_key().to_bytes()),
            0,
            1,
            "V2_PoseidonMerkle",
        );
        let mut signed = SignedBlockedShield {
            commitment_hash: hex::encode_prefixed([3; 32]),
            blinded_commitment: hex::encode_prefixed([4; 32]),
            block_reason: Some("fixture".to_string()),
            signature: String::new(),
        };
        let signature = signing_key
            .sign(&canonical_blocked_shield_message(&signed))
            .to_bytes();
        signed.signature = hex::encode_prefixed(signature);
        let records = [StoredBlockedShield {
            commitment_hash: [3; 32],
            blinded_commitment: [4; 32],
            block_reason: signed.block_reason,
            signature,
        }];

        verify_poi_blocked_shields(&scope, &records);
    }

    fn verify_poi_blocked_shields(scope: &Scope, records: &[StoredBlockedShield]) {
        let encoded =
            encode_poi_blocked_shields_artifact(scope, records).expect("encode v4 blocked shields");
        let descriptor = BlockedShieldsDescriptor {
            artifact: ArtifactDescriptor::from_bytes("bafyblocked", &encoded.bytes),
            format_version: POI_ARTIFACT_FORMAT_VERSION,
            scope: scope.clone(),
            row_count: u64::try_from(encoded.row_count).expect("row count"),
            encoding: ArtifactEncoding::CanonicalJson,
            compression: Compression::Identity,
        };

        let decoded = descriptor
            .verify_bytes(&encoded.bytes)
            .expect("descriptor verifies v4 bytes");
        assert_eq!(decoded.scope, *scope);
        assert_eq!(decoded.blocked_shields.len(), records.len());
    }
}
