use crate::chunk::{
    CHUNK_FORMAT_VERSION, ChunkEnvelope, ChunkEnvelopeHeader, ChunkError, ChunkPlanItem,
    ChunkSection, MAX_COMPRESSED_CHUNK_BYTES, decode_chunk_bytes, encode_chunk_bytes,
};
use crate::manifest::{
    ChainScope, CompressionAlgorithm, DatasetDescriptorMetadata, IndexedArtifactDescriptor,
    IndexedArtifactRange, IndexedArtifactRangeKind, IndexedDatasetKind,
};
use crate::publish::ipfs::{IpfsClient, IpfsError, pin_indexed_chunk};
use crate::store::{StoredCommitmentFamily, StoredCommitmentRow};
use alloy::primitives::FixedBytes;
use sha2::{Digest, Sha256};
use thiserror::Error;

const COMMITMENT_RECORD_SECTION_ID: u16 = 1;

pub fn commitment_chunk_plan_item(
    scope: &ChainScope,
    records: &[StoredCommitmentRow],
    compression: CompressionAlgorithm,
) -> Result<ChunkPlanItem, CommitmentChunkError> {
    let range = commitment_range(records)?;
    let payload = encode_commitment_records(records)?;
    let payload_len = u64::try_from(payload.len()).map_err(|_| ChunkError::PayloadTooLarge)?;
    let row_count = u64::try_from(records.len()).map_err(|_| ChunkError::PayloadTooLarge)?;
    let compressed_bytes = encode_commitment_envelope(
        scope.clone(),
        range.clone(),
        row_count,
        payload_len,
        payload,
        compression,
    )?;
    Ok(ChunkPlanItem {
        range,
        row_count,
        compressed_byte_size: u64::try_from(compressed_bytes.len())
            .map_err(|_| ChunkError::PayloadTooLarge)?,
    })
}

pub async fn publish_commitment_chunk(
    ipfs_client: &dyn IpfsClient,
    scope: ChainScope,
    records: &[StoredCommitmentRow],
    compression: CompressionAlgorithm,
) -> Result<PublishedCommitmentChunk, CommitmentChunkError> {
    let mut published = prepare_commitment_chunk(scope, records, compression)?;
    let cid = pin_indexed_chunk(ipfs_client, &published.compressed_bytes).await?;
    published.descriptor.cid = cid.to_string();
    Ok(published)
}

pub fn prepare_commitment_chunk(
    scope: ChainScope,
    records: &[StoredCommitmentRow],
    compression: CompressionAlgorithm,
) -> Result<PublishedCommitmentChunk, CommitmentChunkError> {
    let range = commitment_range(records)?;
    let payload = encode_commitment_records(records)?;
    let payload_len = u64::try_from(payload.len()).map_err(|_| ChunkError::PayloadTooLarge)?;
    let row_count = u64::try_from(records.len()).map_err(|_| ChunkError::PayloadTooLarge)?;
    let min_block = records
        .iter()
        .map(|record| record.block_number)
        .min()
        .ok_or(CommitmentChunkError::EmptyChunk)?;
    let max_block = records
        .iter()
        .map(|record| record.block_number)
        .max()
        .ok_or(CommitmentChunkError::EmptyChunk)?;
    let compressed_bytes = encode_commitment_envelope(
        scope.clone(),
        range.clone(),
        row_count,
        payload_len,
        payload,
        compression,
    );
    let compressed_bytes = compressed_bytes?;
    let byte_size =
        u64::try_from(compressed_bytes.len()).map_err(|_| ChunkError::PayloadTooLarge)?;
    if byte_size > MAX_COMPRESSED_CHUNK_BYTES {
        return Err(ChunkError::ChunkTooLarge {
            actual: byte_size,
            maximum: MAX_COMPRESSED_CHUNK_BYTES,
        }
        .into());
    }
    let sha256 = FixedBytes::from_slice(&Sha256::digest(&compressed_bytes));
    let descriptor = IndexedArtifactDescriptor {
        dataset_kind: IndexedDatasetKind::Commitments,
        scope,
        range,
        row_count,
        cid: String::new(),
        sha256,
        byte_size,
        encoding_version: CHUNK_FORMAT_VERSION,
        compression,
        metadata: DatasetDescriptorMetadata {
            checkpoint_block: Some(max_block),
            start_block: Some(min_block),
            end_block: Some(max_block),
            last_indexed_block: Some(max_block),
            ..Default::default()
        },
    };

    Ok(PublishedCommitmentChunk {
        descriptor,
        compressed_bytes,
    })
}

fn encode_commitment_envelope(
    scope: ChainScope,
    range: IndexedArtifactRange,
    row_count: u64,
    payload_len: u64,
    payload: Vec<u8>,
    compression: CompressionAlgorithm,
) -> Result<Vec<u8>, ChunkError> {
    let envelope = ChunkEnvelope::new(
        ChunkEnvelopeHeader::new(
            IndexedDatasetKind::Commitments,
            scope,
            range,
            row_count,
            payload_len,
            vec![ChunkSection {
                section_id: COMMITMENT_RECORD_SECTION_ID,
                offset: 0,
                byte_length: payload_len,
            }],
        ),
        payload,
    );
    encode_chunk_bytes(&envelope, compression)
}

pub fn decode_commitment_chunk(
    descriptor: &IndexedArtifactDescriptor,
    bytes: &[u8],
) -> Result<ChunkEnvelope, ChunkError> {
    decode_chunk_bytes(descriptor, bytes)
}

fn commitment_range(
    records: &[StoredCommitmentRow],
) -> Result<IndexedArtifactRange, CommitmentChunkError> {
    let first = records.first().ok_or(CommitmentChunkError::EmptyChunk)?;
    let mut previous_position = first.global_position;
    for record in records.iter().skip(1) {
        if record.global_position <= previous_position {
            return Err(CommitmentChunkError::NonIncreasingGlobalPosition {
                previous: previous_position,
                actual: record.global_position,
            });
        }
        previous_position = record.global_position;
    }
    Ok(IndexedArtifactRange {
        kind: IndexedArtifactRangeKind::TreePosition,
        start: first.global_position,
        end: previous_position,
    })
}

fn encode_commitment_records(records: &[StoredCommitmentRow]) -> Result<Vec<u8>, ChunkError> {
    let mut bytes = Vec::with_capacity(records.len().saturating_mul(132));
    write_len(&mut bytes, records.len())?;
    for record in records {
        write_u64(&mut bytes, record.global_position);
        write_u64(&mut bytes, record.block_number);
        bytes.push(commitment_family_id(record.family));
        write_u32(&mut bytes, record.tree_number);
        write_u64(&mut bytes, record.tree_position);
        bytes.extend_from_slice(&record.commitment_hash);
    }
    if u64::try_from(bytes.len()).is_err() {
        return Err(ChunkError::PayloadTooLarge);
    }
    Ok(bytes)
}

fn write_len(bytes: &mut Vec<u8>, count: usize) -> Result<(), ChunkError> {
    write_u64(
        bytes,
        u64::try_from(count).map_err(|_| ChunkError::PayloadTooLarge)?,
    );
    Ok(())
}

fn write_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

const fn commitment_family_id(value: StoredCommitmentFamily) -> u8 {
    match value {
        StoredCommitmentFamily::Transact => 0,
        StoredCommitmentFamily::Shield => 1,
        StoredCommitmentFamily::LegacyEncrypted => 2,
        StoredCommitmentFamily::LegacyGenerated => 3,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedCommitmentChunk {
    pub descriptor: IndexedArtifactDescriptor,
    pub compressed_bytes: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum CommitmentChunkError {
    #[error("commitment chunk has no records")]
    EmptyChunk,
    #[error(
        "commitment chunk positions must be strictly increasing: previous {previous}, got {actual}"
    )]
    NonIncreasingGlobalPosition { previous: u64, actual: u64 },
    #[error("commitment global position overflowed")]
    GlobalPositionOverflow,
    #[error("chunk encoding failed")]
    Chunk(#[from] ChunkError),
    #[error("IPFS pinning failed")]
    Ipfs(#[from] IpfsError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::ChainType;
    use crate::publish::ipfs::{IpfsError, raw_block_cid};
    use async_trait::async_trait;
    use cid::Cid;
    use std::sync::Mutex;

    #[tokio::test]
    async fn commitment_chunk_publishes_sparse_tree_position_descriptor() {
        let ipfs = RecordingIpfsClient::default();
        let records = vec![record(65_536, 100), record(65_538, 101)];

        let published =
            publish_commitment_chunk(&ipfs, scope(), &records, CompressionAlgorithm::Zstd)
                .await
                .expect("publish chunk");

        assert_eq!(
            published.descriptor.dataset_kind,
            IndexedDatasetKind::Commitments
        );
        assert_eq!(
            published.descriptor.range.kind,
            IndexedArtifactRangeKind::TreePosition
        );
        assert_eq!(published.descriptor.range.start, 65_536);
        assert_eq!(published.descriptor.range.end, 65_538);
        assert_eq!(published.descriptor.row_count, 2);
        assert_eq!(published.descriptor.metadata.checkpoint_block, Some(101));
        assert_eq!(published.descriptor.metadata.start_block, Some(100));
        assert_eq!(published.descriptor.metadata.end_block, Some(101));
        assert_eq!(published.descriptor.metadata.last_indexed_block, Some(101));
        assert!(published.descriptor.metadata.root.is_none());
        assert_eq!(
            published.descriptor.byte_size,
            u64::try_from(published.compressed_bytes.len()).expect("byte size")
        );
        assert_eq!(ipfs.pinned_count(), 1);

        let envelope = decode_commitment_chunk(&published.descriptor, &published.compressed_bytes)
            .expect("decode published chunk");
        assert_eq!(envelope.header.sections.len(), 1);
        assert_eq!(record_count(&envelope), 2);
    }

    #[tokio::test]
    async fn commitment_chunk_rejects_unsorted_positions() {
        let ipfs = RecordingIpfsClient::default();
        let records = vec![record(12, 100), record(10, 101)];

        let error = publish_commitment_chunk(&ipfs, scope(), &records, CompressionAlgorithm::Zstd)
            .await
            .expect_err("unsorted positions should fail");

        assert!(matches!(
            error,
            CommitmentChunkError::NonIncreasingGlobalPosition {
                previous: 12,
                actual: 10,
            }
        ));
        assert_eq!(ipfs.pinned_count(), 0);
    }

    fn record(global_position: u64, block_number: u64) -> StoredCommitmentRow {
        StoredCommitmentRow {
            global_position,
            block_number,
            family: StoredCommitmentFamily::Transact,
            tree_number: u32::try_from(global_position / 65_536).expect("tree number"),
            tree_position: global_position % 65_536,
            commitment_hash: [0xbb; 32],
        }
    }

    fn record_count(envelope: &ChunkEnvelope) -> u64 {
        let section = envelope
            .header
            .sections
            .iter()
            .find(|section| section.section_id == COMMITMENT_RECORD_SECTION_ID)
            .expect("commitment section exists");
        assert_eq!(section.offset, 0);
        let bytes = envelope.payload.get(0..8).expect("record count bytes");
        u64::from_le_bytes(bytes.try_into().expect("u64 count"))
    }

    fn scope() -> ChainScope {
        ChainScope {
            chain_type: ChainType::Evm,
            chain_id: 1,
            railgun_contract: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .parse()
                .expect("scope address"),
        }
    }

    #[derive(Debug, Default)]
    struct RecordingIpfsClient {
        pinned: Mutex<Vec<Vec<u8>>>,
    }

    impl RecordingIpfsClient {
        fn pinned_count(&self) -> usize {
            self.pinned.lock().expect("pinned bytes lock").len()
        }
    }

    #[async_trait]
    impl IpfsClient for RecordingIpfsClient {
        fn service_name(&self) -> &'static str {
            "recording"
        }

        async fn pin_bytes(&self, bytes: &[u8]) -> Result<Cid, IpfsError> {
            self.pinned
                .lock()
                .expect("pinned bytes lock")
                .push(bytes.to_vec());
            raw_block_cid(bytes)
        }

        async fn unpin(&self, _cid: &Cid) -> Result<(), IpfsError> {
            Ok(())
        }

        async fn contains(&self, _cid: &Cid) -> Result<bool, IpfsError> {
            Ok(true)
        }
    }
}
