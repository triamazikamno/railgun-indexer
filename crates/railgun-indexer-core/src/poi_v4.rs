use crate::blocked::content_hash;
use crate::store::StoredEvent;
use alloy_primitives::{FixedBytes, hex};
use poi::artifacts::v4::{
    CHECKPOINT_EVENT_SPAN, CheckpointCatalog, Error as PoiArtifactError, EventArtifact,
    EventArtifactDescriptor, EventArtifactKind, Scope,
};
use poi::artifacts::{ArtifactDescriptor, SnapshotEvent, verify_poi_event};
use poi::cache::{PoiCache, PoiCacheError, PoiCacheIdentity};
use poi::poi::SignedPoiEvent;
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct PreparedEventArtifact {
    pub artifact: EventArtifact,
    pub bytes: Vec<u8>,
    pub sha256: [u8; 32],
}

impl PreparedEventArtifact {
    pub fn descriptor(
        &self,
        cid: impl Into<String>,
    ) -> Result<EventArtifactDescriptor, PublicationError> {
        self.artifact.descriptor(cid).map_err(Into::into)
    }
}

#[derive(Debug, Clone)]
pub struct ValidatedCorpus {
    scope: Scope,
    events: Vec<SnapshotEvent>,
    cache: PoiCache,
}

impl ValidatedCorpus {
    pub fn replay(
        scope: Scope,
        stored_events: &[StoredEvent],
        expected_final_root: Option<FixedBytes<32>>,
    ) -> Result<Self, PublicationError> {
        let mut cache = PoiCache::new(PoiCacheIdentity::new(
            scope.chain_type,
            scope.chain_id,
            scope.txid_version.clone(),
            scope.list_key,
        ));
        let mut events = Vec::with_capacity(stored_events.len());
        let list_key = scope.list_key.0;
        for (offset, stored) in stored_events.iter().enumerate() {
            let expected =
                u64::try_from(offset).map_err(|_| PublicationError::ArithmeticOverflow)?;
            if stored.event_index != expected {
                return Err(PublicationError::NonContiguousEvent {
                    expected,
                    actual: stored.event_index,
                });
            }
            let signed = SignedPoiEvent {
                index: stored.event_index,
                blinded_commitment: FixedBytes::from(stored.blinded_commitment),
                signature: hex::encode(stored.signature),
                event_type: stored.event_type,
            };
            verify_poi_event(&signed, &list_key).map_err(|source| {
                PublicationError::InvalidEventSignature {
                    event_index: stored.event_index,
                    source,
                }
            })?;
            events.push(SnapshotEvent {
                event_index: stored.event_index,
                blinded_commitment: stored.blinded_commitment,
                signature: stored.signature,
                event_type: stored.event_type,
            });
        }
        cache.apply_verified_artifact_events(&events)?;

        match (events.last(), expected_final_root) {
            (None, None) => {}
            (None, Some(_)) | (Some(_), None) => {
                return Err(PublicationError::FinalRootPresenceMismatch);
            }
            (Some(last), Some(expected)) => {
                let actual = cache.root_at_global_index(last.event_index).ok_or(
                    PublicationError::MissingRoot {
                        event_index: last.event_index,
                    },
                )?;
                if actual != expected {
                    return Err(PublicationError::FinalRootMismatch {
                        event_index: last.event_index,
                        expected,
                        actual,
                    });
                }
            }
        }

        Ok(Self {
            scope,
            events,
            cache,
        })
    }

    #[must_use]
    pub const fn scope(&self) -> &Scope {
        &self.scope
    }

    #[must_use]
    pub fn event_count(&self) -> u64 {
        u64::try_from(self.events.len()).unwrap_or(u64::MAX)
    }

    pub fn root_at(&self, event_index: u64) -> Result<FixedBytes<32>, PublicationError> {
        self.cache
            .root_at_global_index(event_index)
            .ok_or(PublicationError::MissingRoot { event_index })
    }

    pub fn current_roots(&mut self) -> BTreeMap<u32, FixedBytes<32>> {
        self.cache.current_roots()
    }

    pub fn prepare_checkpoint(
        &self,
        checkpoint_event_count: u64,
    ) -> Result<Vec<PreparedEventArtifact>, PublicationError> {
        if checkpoint_event_count > self.event_count() {
            return Err(PublicationError::CheckpointBeyondTip {
                checkpoint_event_count,
                event_count: self.event_count(),
            });
        }
        let mut chunks = Vec::new();
        let mut start = 0_u64;
        while start < checkpoint_event_count {
            let end = start
                .checked_add(CHECKPOINT_EVENT_SPAN - 1)
                .ok_or(PublicationError::ArithmeticOverflow)?
                .min(checkpoint_event_count - 1);
            chunks.push(self.prepare_event_artifact(EventArtifactKind::Checkpoint, start, end)?);
            start = end
                .checked_add(1)
                .ok_or(PublicationError::ArithmeticOverflow)?;
        }
        Ok(chunks)
    }

    pub fn prepare_event_artifact(
        &self,
        kind: EventArtifactKind,
        start_index: u64,
        end_index: u64,
    ) -> Result<PreparedEventArtifact, PublicationError> {
        if start_index > end_index || end_index >= self.event_count() {
            return Err(PublicationError::InvalidEventRange {
                start_index,
                end_index,
                event_count: self.event_count(),
            });
        }
        let start =
            usize::try_from(start_index).map_err(|_| PublicationError::ArithmeticOverflow)?;
        let end = usize::try_from(end_index).map_err(|_| PublicationError::ArithmeticOverflow)?;
        let start_root = start_index
            .checked_sub(1)
            .map(|index| self.root_at(index))
            .transpose()?;
        let end_root = self.root_at(end_index)?;
        let artifact = EventArtifact::new(
            self.scope.clone(),
            kind,
            start_root,
            end_root,
            self.events[start..=end].to_vec(),
        )?;
        let bytes = artifact.to_bytes()?;
        let sha256 = content_hash(&bytes);
        Ok(PreparedEventArtifact {
            artifact,
            bytes,
            sha256,
        })
    }
}

pub fn checkpoint_catalog(
    scope: Scope,
    chunks: Vec<EventArtifactDescriptor>,
) -> Result<(CheckpointCatalog, Vec<u8>), PublicationError> {
    let catalog = CheckpointCatalog::new(scope, chunks)?;
    let bytes = catalog.to_bytes()?;
    Ok((catalog, bytes))
}

pub fn artifact_descriptor(cid: impl Into<String>, bytes: &[u8]) -> ArtifactDescriptor {
    ArtifactDescriptor::from_bytes(cid, bytes)
}

#[derive(Debug, Error)]
pub enum PublicationError {
    #[error("POI v4 contract validation failed")]
    Contract(#[from] PoiArtifactError),
    #[error("POI cache replay failed")]
    Cache(#[from] PoiCacheError),
    #[error("POI event {event_index} signature validation failed")]
    InvalidEventSignature {
        event_index: u64,
        #[source]
        source: poi::artifacts::VerifyError,
    },
    #[error("POI event index is not contiguous: expected {expected}, got {actual}")]
    NonContiguousEvent { expected: u64, actual: u64 },
    #[error("POI final-root presence does not match event presence")]
    FinalRootPresenceMismatch,
    #[error("POI final root mismatch at event {event_index}: expected {expected}, got {actual}")]
    FinalRootMismatch {
        event_index: u64,
        expected: FixedBytes<32>,
        actual: FixedBytes<32>,
    },
    #[error("POI replay root is unavailable at event {event_index}")]
    MissingRoot { event_index: u64 },
    #[error("checkpoint count {checkpoint_event_count} exceeds event count {event_count}")]
    CheckpointBeyondTip {
        checkpoint_event_count: u64,
        event_count: u64,
    },
    #[error("invalid POI event range {start_index}..={end_index} for {event_count} events")]
    InvalidEventRange {
        start_index: u64,
        end_index: u64,
        event_count: u64,
    },
    #[error("checked POI publisher arithmetic overflow")]
    ArithmeticOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publish::ipfs::raw_block_cid;
    use ed25519_dalek::{Signer, SigningKey};
    use poi::artifacts::v4::{
        ArtifactEncoding, BlockedShieldsDescriptor, Compression, EventRange, FORMAT_VERSION,
        MANIFEST_SIGNATURE_DOMAIN, Manifest, ManifestEntry,
    };
    use poi::artifacts::verify::canonical_poi_event_message;
    use poi::poi::PoiEventType;

    const PRODUCER_GOLDEN_BODY_HASHES: [&str; 6] = [
        "30535cbb6ce23b841d21df5eed9efa1ef644c1cb24da46d40d63cab1dc90f59c",
        "487956c9329cd53153cb43fcfd70d2d5bbf85f3d540b208849c0a3be4eb0eec7",
        "93e6e21cf06524b7b1dad99f4d06bfbd3d01411e6ed0b987b56c8822aa4f62fc",
        "e0edb1cd85ab8b33fe5d43cc676d4b275c60736e4028240052e41bea1659485c",
        "78769462650f91068703148ba86411955aad42abce3fe88c5e58023edacbafbb",
        "503cd8d3715c34549fc0d3ecfa8bb098dbe7f44e2b71c35ed9e1e703bb3c3cdd",
    ];
    const MANIFEST_SIGNATURE_TEST_SEED: [u8; 32] = [7; 32];
    const PRODUCER_GOLDEN_SIGNED_BODY_HASH: &str =
        "b69109db5c1b989d9ae3ade3a5b06ec9e3eefd379405a7a4e4d373f1bf2b3c48";
    const PRODUCER_GOLDEN_SIGNATURE_HASH: &str =
        "e8427b380f033519b42a40cd0a37d11d7920a7c4bda42e78f674500b618e15de";

    #[test]
    fn sealed_checkpoint_chunk_bytes_and_cids_are_stable_after_append() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let first_events = signed_events(&signing_key, CHECKPOINT_EVENT_SPAN + 1);
        let first = validated(&signing_key, &first_events);
        let first_chunk = first
            .prepare_checkpoint(CHECKPOINT_EVENT_SPAN + 1)
            .expect("first checkpoint")
            .remove(0);
        let mut appended = first_events;
        appended.push(signed_event(&signing_key, CHECKPOINT_EVENT_SPAN + 1));
        let second = validated(&signing_key, &appended);
        let second_chunk = second
            .prepare_checkpoint(CHECKPOINT_EVENT_SPAN + 2)
            .expect("second checkpoint")
            .remove(0);

        assert_eq!(first_chunk.bytes, second_chunk.bytes);
        assert_eq!(first_chunk.sha256, second_chunk.sha256);
        assert_eq!(
            raw_block_cid(&first_chunk.bytes).expect("first CID"),
            raw_block_cid(&second_chunk.bytes).expect("second CID")
        );
    }

    #[test]
    fn coalesced_tail_replacement_changes_only_mutable_artifact() {
        let signing_key = SigningKey::from_bytes(&[8; 32]);
        let events = signed_events(&signing_key, 4);
        let first = validated(&signing_key, &events[..3]);
        let second = validated(&signing_key, &events);
        let first_tail = first
            .prepare_event_artifact(EventArtifactKind::CurrentTail, 0, 2)
            .expect("first tail");
        let second_tail = second
            .prepare_event_artifact(EventArtifactKind::CurrentTail, 0, 3)
            .expect("second tail");

        assert_ne!(first_tail.bytes, second_tail.bytes);
        assert_eq!(first_tail.artifact.range.start_index, 0);
        assert_eq!(second_tail.artifact.range.start_index, 0);
        assert_eq!(second_tail.artifact.range.end_index, 3);
    }

    #[test]
    fn replay_rejects_invalid_signature_gap_and_upstream_root() {
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let mut events = signed_events(&signing_key, 2);
        let root = replay_root(&signing_key, &events);
        events[0].signature[0] ^= 1;
        assert!(matches!(
            ValidatedCorpus::replay(scope(&signing_key), &events, Some(root)),
            Err(PublicationError::InvalidEventSignature { event_index: 0, .. })
        ));

        let mut events = signed_events(&signing_key, 2);
        events[1].event_index = 2;
        assert!(matches!(
            ValidatedCorpus::replay(scope(&signing_key), &events, Some(root)),
            Err(PublicationError::NonContiguousEvent {
                expected: 1,
                actual: 2
            })
        ));

        let events = signed_events(&signing_key, 2);
        assert!(matches!(
            ValidatedCorpus::replay(
                scope(&signing_key),
                &events,
                Some(FixedBytes::from([0xff; 32]))
            ),
            Err(PublicationError::FinalRootMismatch { .. })
        ));
    }

    #[test]
    fn replay_accepts_historical_unsigned_shield_but_not_other_unsigned_events() {
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let mut events = signed_events(&signing_key, 2);
        let root = replay_root(&signing_key, &events);
        events[0].signature = [0; 64];
        ValidatedCorpus::replay(scope(&signing_key), &events, Some(root))
            .expect("historical unsigned Shield event");

        events[0].event_type = PoiEventType::Transact;
        assert!(matches!(
            ValidatedCorpus::replay(scope(&signing_key), &events, Some(root)),
            Err(PublicationError::InvalidEventSignature { event_index: 0, .. })
        ));
    }

    #[test]
    fn explicit_no_event_replay_builds_empty_catalog() {
        let signing_key = SigningKey::from_bytes(&[10; 32]);
        let corpus = ValidatedCorpus::replay(scope(&signing_key), &[], None).expect("empty replay");
        assert!(
            corpus
                .prepare_checkpoint(0)
                .expect("empty checkpoint")
                .is_empty()
        );
        let (catalog, bytes) =
            checkpoint_catalog(corpus.scope().clone(), Vec::new()).expect("empty catalog");

        assert_eq!(corpus.event_count(), 0);
        assert!(catalog.chunks.is_empty());
        assert!(catalog.range.is_none());
        assert!(!bytes.is_empty());
    }

    #[test]
    fn producer_manifest_signature_matches_shared_golden_vector() {
        let signing_key = SigningKey::from_bytes(&MANIFEST_SIGNATURE_TEST_SEED);
        let mut manifest = producer_publication_graph(ProducerGraphKind::Partial);
        manifest.sign_manifest(&signing_key).expect("sign manifest");

        assert_eq!(MANIFEST_SIGNATURE_DOMAIN, b"railgun-poi-manifest-v4\0");
        let body = manifest.canonical_body_bytes().expect("canonical body");
        assert_eq!(
            hex::encode(content_hash(&body)),
            PRODUCER_GOLDEN_SIGNED_BODY_HASH
        );
        let signature = manifest
            .publisher_signature
            .as_ref()
            .expect("publisher signature");
        assert_eq!(
            hex::encode(content_hash(signature.as_slice())),
            PRODUCER_GOLDEN_SIGNATURE_HASH
        );
        manifest
            .verify_trusted_signature(&signing_key.verifying_key().to_bytes())
            .expect("golden signature verifies");
    }

    #[test]
    fn producer_publication_graphs_match_canonical_body_hash_vectors() {
        let kinds = [
            ProducerGraphKind::Zero,
            ProducerGraphKind::Partial,
            ProducerGraphKind::OneChunk,
            ProducerGraphKind::MultiChunk,
            ProducerGraphKind::EmptyCheckpointTail,
            ProducerGraphKind::RetainedBridges,
        ];

        for (index, kind) in kinds.into_iter().enumerate() {
            let manifest = producer_publication_graph(kind);
            let body = manifest.canonical_body_bytes().expect("canonical body");
            assert_eq!(
                hex::encode(content_hash(&body)),
                PRODUCER_GOLDEN_BODY_HASHES[index]
            );
        }
    }

    #[test]
    fn blocked_shield_refresh_replaces_content_identity_without_event_advance() {
        let first = artifact_descriptor("bafy-first", b"blocked-a");
        let second = artifact_descriptor("bafy-second", b"blocked-b");

        assert_ne!(first.cid, second.cid);
        assert_ne!(first.sha256, second.sha256);
        assert_eq!(first.byte_size, second.byte_size);
    }

    #[test]
    fn oversized_suffix_after_active_graph_without_tail_exceeds_v4_limit() {
        let signing_key = SigningKey::from_bytes(&[11; 32]);
        let suffix = raw_event_artifact(&signing_key, EventArtifactKind::CurrentTail, 1, 44_000)
            .expect("construct oversized suffix");

        assert!(matches!(
            suffix.to_bytes(),
            Err(PoiArtifactError::EventArtifactByteLimitExceeded { .. })
        ));
    }

    #[test]
    fn oversized_newer_suffix_remains_invalid_after_prior_tail_becomes_bridge() {
        let signing_key = SigningKey::from_bytes(&[12; 32]);
        let prior_tail = raw_event_artifact(&signing_key, EventArtifactKind::Bridge, 1, 1)
            .expect("construct prior-tail bridge");
        let newer_suffix =
            raw_event_artifact(&signing_key, EventArtifactKind::CurrentTail, 2, 44_000)
                .expect("construct oversized newer suffix");

        assert!(prior_tail.to_bytes().is_ok());
        assert!(matches!(
            newer_suffix.to_bytes(),
            Err(PoiArtifactError::EventArtifactByteLimitExceeded { .. })
        ));
    }

    fn validated(signing_key: &SigningKey, events: &[StoredEvent]) -> ValidatedCorpus {
        ValidatedCorpus::replay(
            scope(signing_key),
            events,
            Some(replay_root(signing_key, events)),
        )
        .expect("validated corpus")
    }

    fn replay_root(signing_key: &SigningKey, events: &[StoredEvent]) -> FixedBytes<32> {
        let mut cache = PoiCache::new(PoiCacheIdentity::new(
            0,
            1,
            "V2_PoseidonMerkle",
            FixedBytes::from(signing_key.verifying_key().to_bytes()),
        ));
        let snapshot = events
            .iter()
            .map(|event| SnapshotEvent {
                event_index: event.event_index,
                blinded_commitment: event.blinded_commitment,
                signature: event.signature,
                event_type: event.event_type,
            })
            .collect::<Vec<_>>();
        cache
            .apply_verified_artifact_events(&snapshot)
            .expect("replay events");
        cache
            .root_at_global_index(events.last().expect("nonempty events").event_index)
            .expect("root")
    }

    fn signed_events(signing_key: &SigningKey, count: u64) -> Vec<StoredEvent> {
        (0..count)
            .map(|index| signed_event(signing_key, index))
            .collect()
    }

    fn signed_event(signing_key: &SigningKey, index: u64) -> StoredEvent {
        let mut signed = SignedPoiEvent {
            index,
            blinded_commitment: FixedBytes::from(fixed_index(index)),
            signature: String::new(),
            event_type: PoiEventType::Shield,
        };
        let signature = signing_key
            .sign(&canonical_poi_event_message(&signed))
            .to_bytes();
        signed.signature = hex::encode(signature);
        StoredEvent {
            event_index: index,
            blinded_commitment: signed.blinded_commitment.0,
            signature,
            event_type: signed.event_type,
        }
    }

    fn scope(signing_key: &SigningKey) -> Scope {
        Scope::new(
            FixedBytes::from(signing_key.verifying_key().to_bytes()),
            0,
            1,
            "V2_PoseidonMerkle",
        )
    }

    fn fixed_index(index: u64) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        bytes[24..].copy_from_slice(&index.to_be_bytes());
        bytes
    }

    fn raw_event_artifact(
        signing_key: &SigningKey,
        kind: EventArtifactKind,
        start_index: u64,
        count: u64,
    ) -> Result<EventArtifact, PoiArtifactError> {
        let events = (start_index..start_index + count)
            .map(|event_index| SnapshotEvent {
                event_index,
                blinded_commitment: fixed_index(event_index),
                signature: [0; 64],
                event_type: PoiEventType::Shield,
            })
            .collect();
        EventArtifact::new(
            scope(signing_key),
            kind,
            start_index
                .checked_sub(1)
                .map(|_| FixedBytes::from([1; 32])),
            FixedBytes::from([2; 32]),
            events,
        )
    }

    #[derive(Clone, Copy)]
    enum ProducerGraphKind {
        Zero,
        Partial,
        OneChunk,
        MultiChunk,
        EmptyCheckpointTail,
        RetainedBridges,
    }

    fn producer_publication_graph(kind: ProducerGraphKind) -> Manifest {
        let scope = producer_scope();
        let (catalog_chunks, event_count, current_root, current_tail, retained_bridges) = match kind
        {
            ProducerGraphKind::Zero => (vec![], 0, None, None, vec![]),
            ProducerGraphKind::Partial => (
                vec![producer_chunk(0, 3, None, producer_root(3), 1)],
                3,
                Some(producer_root(3)),
                None,
                vec![],
            ),
            ProducerGraphKind::OneChunk => (
                vec![producer_chunk(
                    0,
                    CHECKPOINT_EVENT_SPAN,
                    None,
                    producer_root(1),
                    1,
                )],
                CHECKPOINT_EVENT_SPAN,
                Some(producer_root(1)),
                None,
                vec![],
            ),
            ProducerGraphKind::MultiChunk => (
                vec![
                    producer_chunk(0, CHECKPOINT_EVENT_SPAN, None, producer_root(1), 1),
                    producer_chunk(
                        CHECKPOINT_EVENT_SPAN,
                        2,
                        Some(producer_root(1)),
                        producer_root(2),
                        2,
                    ),
                ],
                CHECKPOINT_EVENT_SPAN + 2,
                Some(producer_root(2)),
                None,
                vec![],
            ),
            ProducerGraphKind::EmptyCheckpointTail => (
                vec![],
                3,
                Some(producer_root(3)),
                Some(producer_event_descriptor(
                    EventArtifactKind::CurrentTail,
                    0,
                    3,
                    None,
                    producer_root(3),
                    3,
                )),
                vec![],
            ),
            ProducerGraphKind::RetainedBridges => (
                vec![producer_chunk(0, 10, None, producer_root(10), 1)],
                12,
                Some(producer_root(12)),
                Some(producer_event_descriptor(
                    EventArtifactKind::CurrentTail,
                    10,
                    2,
                    Some(producer_root(10)),
                    producer_root(12),
                    4,
                )),
                vec![
                    producer_event_descriptor(
                        EventArtifactKind::Bridge,
                        4,
                        3,
                        Some(producer_root(4)),
                        producer_root(7),
                        2,
                    ),
                    producer_event_descriptor(
                        EventArtifactKind::Bridge,
                        7,
                        3,
                        Some(producer_root(7)),
                        producer_root(10),
                        3,
                    ),
                ],
            ),
        };
        let (catalog, _) =
            checkpoint_catalog(scope.clone(), catalog_chunks).expect("producer checkpoint catalog");
        let checkpoint_catalog = catalog
            .descriptor("bafycatalog")
            .expect("checkpoint catalog descriptor");
        let entry = ManifestEntry {
            scope: scope.clone(),
            event_count,
            current_tip_index: event_count.checked_sub(1),
            current_root,
            checkpoint_catalog,
            current_tail,
            retained_bridges,
            blocked_shields: BlockedShieldsDescriptor {
                artifact: producer_fake_artifact("bafyblocked", 64, 90),
                format_version: FORMAT_VERSION,
                scope,
                row_count: 0,
                encoding: ArtifactEncoding::CanonicalJson,
                compression: Compression::Identity,
            },
        };
        Manifest::new(
            1_700_000_000_000,
            42,
            FixedBytes::from([9; 32]),
            vec![entry],
        )
    }

    fn producer_scope() -> Scope {
        Scope::new(FixedBytes::from([1; 32]), 0, 1, "V3_PoseidonMerkle")
    }

    fn producer_chunk(
        start_index: u64,
        row_count: u64,
        start_root: Option<FixedBytes<32>>,
        end_root: FixedBytes<32>,
        marker: u8,
    ) -> EventArtifactDescriptor {
        producer_event_descriptor(
            EventArtifactKind::Checkpoint,
            start_index,
            row_count,
            start_root,
            end_root,
            marker,
        )
    }

    fn producer_event_descriptor(
        kind: EventArtifactKind,
        start_index: u64,
        row_count: u64,
        start_root: Option<FixedBytes<32>>,
        end_root: FixedBytes<32>,
        marker: u8,
    ) -> EventArtifactDescriptor {
        let end_index = start_index
            .checked_add(row_count - 1)
            .expect("fixture range");
        EventArtifactDescriptor {
            artifact: producer_fake_artifact(
                &format!("bafyevent{marker}"),
                147 + 17 + row_count * 97,
                marker,
            ),
            format_version: FORMAT_VERSION,
            scope: producer_scope(),
            kind,
            range: EventRange {
                start_index,
                end_index,
            },
            row_count,
            encoding: ArtifactEncoding::PoiEventBinary,
            compression: Compression::Identity,
            start_root,
            end_root,
        }
    }

    fn producer_fake_artifact(cid: &str, byte_size: u64, marker: u8) -> ArtifactDescriptor {
        ArtifactDescriptor {
            cid: cid.to_string(),
            sha256: FixedBytes::from([marker; 32]),
            byte_size,
        }
    }

    fn producer_root(marker: u8) -> FixedBytes<32> {
        FixedBytes::from([marker; 32])
    }
}
