use crate::chunk::{
    CHUNK_FORMAT_VERSION, ChunkEnvelope, ChunkEnvelopeHeader, ChunkError, ChunkPlanItem,
    ChunkSection, MAX_COMPRESSED_CHUNK_BYTES, encode_chunk_bytes,
};
use crate::manifest::{
    ChainScope, CompressionAlgorithm, DatasetDescriptorMetadata, IndexedArtifactDescriptor,
    IndexedArtifactRange, IndexedArtifactRangeKind, IndexedDatasetKind,
};
use crate::publish::ipfs::{IpfsClient, IpfsError, pin_indexed_chunk};
use crate::store::StoredPublicTxidRow;
use alloy::primitives::{FixedBytes, U256};
use broadcaster_core::transact::{
    compute_railgun_txid_parts, railgun_txid_leaf_hash_with_output_start,
};
use broadcaster_core::tree::TREE_LEAF_COUNT;
use merkletree::tree::DenseMerkleTree;
use sha2::{Digest, Sha256};
use thiserror::Error;

const PUBLIC_TXID_RECORD_SECTION_ID: u16 = 1;

pub fn public_txid_chunk_plan_item(
    scope: &ChainScope,
    records: &[StoredPublicTxidRow],
    compression: CompressionAlgorithm,
) -> Result<ChunkPlanItem, PublicTxidChunkError> {
    let range = public_txid_range(records)?;
    validate_single_txid_tree(&range)?;
    let payload = encode_public_txid_records(records)?;
    let payload_len = u64::try_from(payload.len()).map_err(|_| ChunkError::PayloadTooLarge)?;
    let row_count = u64::try_from(records.len()).map_err(|_| ChunkError::PayloadTooLarge)?;
    let compressed_bytes = encode_public_txid_envelope(
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

pub async fn publish_public_txid_chunk(
    ipfs_client: &dyn IpfsClient,
    scope: ChainScope,
    records: &[StoredPublicTxidRow],
    checkpoint_root: [u8; 32],
    compression: CompressionAlgorithm,
) -> Result<PublishedPublicTxidChunk, PublicTxidChunkError> {
    let mut published = prepare_public_txid_chunk(scope, records, checkpoint_root, compression)?;
    let cid = pin_indexed_chunk(ipfs_client, &published.compressed_bytes).await?;
    published.descriptor.cid = cid.to_string();
    Ok(published)
}

pub fn prepare_public_txid_chunk(
    scope: ChainScope,
    records: &[StoredPublicTxidRow],
    checkpoint_root: [u8; 32],
    compression: CompressionAlgorithm,
) -> Result<PublishedPublicTxidChunk, PublicTxidChunkError> {
    let range = public_txid_range(records)?;
    validate_single_txid_tree(&range)?;
    let payload = encode_public_txid_records(records)?;
    let payload_len = u64::try_from(payload.len()).map_err(|_| ChunkError::PayloadTooLarge)?;
    let row_count = u64::try_from(records.len()).map_err(|_| ChunkError::PayloadTooLarge)?;
    let max_block = records
        .iter()
        .map(|record| record.block_number)
        .max()
        .ok_or(PublicTxidChunkError::EmptyChunk)?;
    let compressed_bytes = encode_public_txid_envelope(
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
        dataset_kind: IndexedDatasetKind::PublicTxid,
        scope,
        range,
        row_count,
        cid: String::new(),
        sha256,
        byte_size,
        encoding_version: CHUNK_FORMAT_VERSION,
        compression,
        metadata: DatasetDescriptorMetadata {
            root: Some(FixedBytes::from(checkpoint_root)),
            checkpoint_block: Some(max_block),
            last_indexed_block: Some(max_block),
            ..Default::default()
        },
    };

    Ok(PublishedPublicTxidChunk {
        descriptor,
        compressed_bytes,
    })
}

fn encode_public_txid_envelope(
    scope: ChainScope,
    range: IndexedArtifactRange,
    row_count: u64,
    payload_len: u64,
    payload: Vec<u8>,
    compression: CompressionAlgorithm,
) -> Result<Vec<u8>, ChunkError> {
    let envelope = ChunkEnvelope::new(
        ChunkEnvelopeHeader::new(
            IndexedDatasetKind::PublicTxid,
            scope,
            range,
            row_count,
            payload_len,
            vec![ChunkSection {
                section_id: PUBLIC_TXID_RECORD_SECTION_ID,
                offset: 0,
                byte_length: payload_len,
            }],
        ),
        payload,
    );
    encode_chunk_bytes(&envelope, compression)
}

pub fn public_txid_checkpoint_root(
    records: &[StoredPublicTxidRow],
) -> Result<[u8; 32], PublicTxidChunkError> {
    let range = public_txid_range(records)?;
    validate_single_txid_tree(&range)?;
    if range.start % TREE_LEAF_COUNT != 0 {
        return Err(PublicTxidChunkError::CheckpointDoesNotStartAtTreePrefix {
            start: range.start,
        });
    }
    let leaves = records
        .iter()
        .map(public_txid_leaf_hash)
        .collect::<Vec<_>>();
    Ok(
        DenseMerkleTree::from_ordered_leaves(leaves, records.len() as u64)
            .root()
            .to_be_bytes::<32>(),
    )
}

const fn validate_single_txid_tree(
    range: &IndexedArtifactRange,
) -> Result<(), PublicTxidChunkError> {
    if range.start / TREE_LEAF_COUNT != range.end / TREE_LEAF_COUNT {
        return Err(PublicTxidChunkError::CrossesTxidTreeBoundary {
            start: range.start,
            end: range.end,
        });
    }
    Ok(())
}

fn public_txid_range(
    records: &[StoredPublicTxidRow],
) -> Result<IndexedArtifactRange, PublicTxidChunkError> {
    let first = records.first().ok_or(PublicTxidChunkError::EmptyChunk)?;
    let mut expected_index = first.txid_index;
    for record in records {
        if record.txid_index != expected_index {
            return Err(PublicTxidChunkError::NonContiguousTxidIndex {
                expected: expected_index,
                actual: record.txid_index,
            });
        }
        expected_index = expected_index
            .checked_add(1)
            .ok_or(PublicTxidChunkError::TxidIndexOverflow)?;
    }
    Ok(IndexedArtifactRange {
        kind: IndexedArtifactRangeKind::TxidIndex,
        start: first.txid_index,
        end: records
            .last()
            .expect("non-empty records checked above")
            .txid_index,
    })
}

fn encode_public_txid_records(records: &[StoredPublicTxidRow]) -> Result<Vec<u8>, ChunkError> {
    let mut bytes = Vec::with_capacity(records.len().saturating_mul(256));
    for record in records {
        write_u64(&mut bytes, record.txid_index);
        write_string(&mut bytes, &record.id)?;
        write_u64(&mut bytes, record.block_number);
        write_u64(&mut bytes, record.block_timestamp);
        bytes.extend_from_slice(&record.block_hash);
        bytes.extend_from_slice(&record.transaction_hash);
        write_u64(&mut bytes, record.first_log_index);
        write_u64(&mut bytes, record.last_log_index);
        bytes.extend_from_slice(&record.merkle_root);
        write_fixed_bytes_vec(&mut bytes, &record.nullifiers)?;
        write_fixed_bytes_vec(&mut bytes, &record.commitments)?;
        bytes.extend_from_slice(&record.bound_params_hash);
        bytes.push(u8::from(record.has_unshield));
        write_u64(&mut bytes, record.utxo_tree_in);
        write_u64(&mut bytes, record.utxo_tree_out);
        write_u64(&mut bytes, record.utxo_batch_start_position_out);
    }
    if u64::try_from(bytes.len()).is_err() {
        return Err(ChunkError::PayloadTooLarge);
    }
    Ok(bytes)
}

fn public_txid_leaf_hash(record: &StoredPublicTxidRow) -> U256 {
    let nullifiers = record
        .nullifiers
        .iter()
        .map(|value| U256::from_be_bytes(*value))
        .collect::<Vec<_>>();
    let commitments = record
        .commitments
        .iter()
        .map(|value| U256::from_be_bytes(*value))
        .collect::<Vec<_>>();
    let railgun_txid = compute_railgun_txid_parts(
        &nullifiers,
        &commitments,
        U256::from_be_bytes(record.bound_params_hash),
    );
    let output_start = u128::from(record.utxo_tree_out)
        .saturating_mul(u128::from(TREE_LEAF_COUNT))
        .saturating_add(u128::from(record.utxo_batch_start_position_out));
    railgun_txid_leaf_hash_with_output_start(
        railgun_txid,
        record.utxo_tree_in,
        U256::from(output_start),
    )
}

fn write_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), ChunkError> {
    write_u16(
        bytes,
        u16::try_from(value.len()).map_err(|_| ChunkError::StringTooLong {
            field: "public_txid.id",
            length: value.len(),
        })?,
    );
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn write_fixed_bytes_vec(bytes: &mut Vec<u8>, values: &[[u8; 32]]) -> Result<(), ChunkError> {
    write_u32(
        bytes,
        u32::try_from(values.len()).map_err(|_| ChunkError::PayloadTooLarge)?,
    );
    for value in values {
        bytes.extend_from_slice(value);
    }
    Ok(())
}

fn write_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedPublicTxidChunk {
    pub descriptor: IndexedArtifactDescriptor,
    pub compressed_bytes: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum PublicTxidChunkError {
    #[error("public TXID chunk has no records")]
    EmptyChunk,
    #[error("public TXID chunk index gap: expected {expected}, got {actual}")]
    NonContiguousTxidIndex { expected: u64, actual: u64 },
    #[error("public TXID index overflowed")]
    TxidIndexOverflow,
    #[error("public TXID chunk crosses TXID tree boundary: start={start}, end={end}")]
    CrossesTxidTreeBoundary { start: u64, end: u64 },
    #[error("public TXID checkpoint rows must start at a TXID tree prefix, got {start}")]
    CheckpointDoesNotStartAtTreePrefix { start: u64 },
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
    async fn public_txid_chunk_publishes_contiguous_descriptor() {
        let ipfs = RecordingIpfsClient::default();
        let records = vec![record(0, 100), record(1, 101)];
        let checkpoint_root = public_txid_checkpoint_root(&records).expect("checkpoint root");

        let published = publish_public_txid_chunk(
            &ipfs,
            scope(),
            &records,
            checkpoint_root,
            CompressionAlgorithm::Zstd,
        )
        .await
        .expect("publish chunk");

        assert_eq!(
            published.descriptor.dataset_kind,
            IndexedDatasetKind::PublicTxid
        );
        assert_eq!(
            published.descriptor.range.kind,
            IndexedArtifactRangeKind::TxidIndex
        );
        assert_eq!(published.descriptor.range.start, 0);
        assert_eq!(published.descriptor.range.end, 1);
        assert_eq!(published.descriptor.row_count, 2);
        assert_eq!(published.descriptor.compression, CompressionAlgorithm::Zstd);
        assert_eq!(published.descriptor.metadata.checkpoint_block, Some(101));
        assert_eq!(published.descriptor.metadata.last_indexed_block, Some(101));
        assert_eq!(
            published.descriptor.metadata.root,
            Some(FixedBytes::from(checkpoint_root))
        );
        assert_eq!(
            published.descriptor.byte_size,
            u64::try_from(published.compressed_bytes.len()).expect("byte size")
        );
        assert_eq!(ipfs.pinned_count(), 1);
    }

    #[tokio::test]
    async fn public_txid_chunk_rejects_index_gaps() {
        let ipfs = RecordingIpfsClient::default();
        let records = vec![record(10, 100), record(12, 101)];

        let error = publish_public_txid_chunk(
            &ipfs,
            scope(),
            &records,
            [0_u8; 32],
            CompressionAlgorithm::Zstd,
        )
        .await
        .expect_err("gap should fail");

        assert!(matches!(
            error,
            PublicTxidChunkError::NonContiguousTxidIndex { .. }
        ));
        assert_eq!(ipfs.pinned_count(), 0);
    }

    #[test]
    fn public_txid_checkpoint_root_requires_tree_prefix() {
        let records = vec![record(1, 100), record(2, 101)];

        let error = public_txid_checkpoint_root(&records).expect_err("non-prefix should fail");

        assert!(matches!(
            error,
            PublicTxidChunkError::CheckpointDoesNotStartAtTreePrefix { start: 1 }
        ));
    }

    fn record(txid_index: u64, block_number: u64) -> StoredPublicTxidRow {
        StoredPublicTxidRow {
            txid_index,
            id: format!("0x{txid_index:04x}"),
            block_number,
            block_timestamp: 1_700_000_000 + block_number,
            block_hash: [0xaa; 32],
            transaction_hash: [txid_index as u8; 32],
            first_log_index: 1,
            last_log_index: 2,
            merkle_root: [0xbb; 32],
            nullifiers: vec![[0x11; 32]],
            commitments: vec![[0x22; 32]],
            bound_params_hash: [0x33; 32],
            has_unshield: false,
            utxo_tree_in: 3,
            utxo_tree_out: 4,
            utxo_batch_start_position_out: txid_index,
        }
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
