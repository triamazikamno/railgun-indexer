use crate::chunk::{
    CHUNK_FORMAT_VERSION, ChunkEnvelope, ChunkEnvelopeHeader, ChunkError, ChunkSection,
    MAX_COMPRESSED_CHUNK_BYTES, decode_chunk_bytes, encode_chunk_bytes,
};
use crate::manifest::{
    ChainScope, CompressionAlgorithm, DatasetDescriptorMetadata, IndexedArtifactDescriptor,
    IndexedArtifactRange, IndexedArtifactRangeKind, IndexedDatasetKind,
};
use crate::publish::ipfs::{IpfsClient, IpfsError, pin_indexed_chunk};
use alloy::primitives::{FixedBytes, U256};
use broadcaster_core::crypto::poseidon::poseidon;
use broadcaster_core::transact::MERKLE_ZERO_VALUE;
use broadcaster_core::tree::{TREE_DEPTH, TREE_LEAF_COUNT};
use sha2::{Digest, Sha256};
use thiserror::Error;

const MERKLE_CHECKPOINT_SECTION_ID: u16 = 1;

pub async fn publish_merkle_checkpoint_artifact(
    ipfs_client: &dyn IpfsClient,
    scope: ChainScope,
    checkpoint: &MerkleCheckpointArtifact,
    compression: CompressionAlgorithm,
) -> Result<PublishedMerkleCheckpointArtifact, MerkleCheckpointArtifactError> {
    let mut published = prepare_merkle_checkpoint_artifact(scope, checkpoint, compression)?;
    let cid = pin_indexed_chunk(ipfs_client, &published.compressed_bytes).await?;
    published.descriptor.cid = cid.to_string();
    Ok(published)
}

pub fn prepare_merkle_checkpoint_artifact(
    scope: ChainScope,
    checkpoint: &MerkleCheckpointArtifact,
    compression: CompressionAlgorithm,
) -> Result<PublishedMerkleCheckpointArtifact, MerkleCheckpointArtifactError> {
    validate_checkpoint(checkpoint)?;
    let root = checkpoint_root(checkpoint);
    let range = checkpoint_range(checkpoint)?;
    let payload = encode_merkle_checkpoint(checkpoint, root)?;
    let payload_len = u64::try_from(payload.len()).map_err(|_| ChunkError::PayloadTooLarge)?;
    let envelope = ChunkEnvelope::new(
        ChunkEnvelopeHeader::new(
            IndexedDatasetKind::MerkleCheckpoint,
            scope.clone(),
            range.clone(),
            checkpoint.leaf_count,
            payload_len,
            vec![ChunkSection {
                section_id: MERKLE_CHECKPOINT_SECTION_ID,
                offset: 0,
                byte_length: payload_len,
            }],
        ),
        payload,
    );
    let compressed_bytes = encode_chunk_bytes(&envelope, compression)?;
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
    let tree_number = u16::try_from(checkpoint.tree_number).map_err(|_| {
        MerkleCheckpointArtifactError::TreeNumberOutOfRange {
            tree_number: checkpoint.tree_number,
        }
    })?;
    let descriptor = IndexedArtifactDescriptor {
        dataset_kind: IndexedDatasetKind::MerkleCheckpoint,
        scope,
        range,
        row_count: checkpoint.leaf_count,
        cid: String::new(),
        sha256,
        byte_size,
        encoding_version: CHUNK_FORMAT_VERSION,
        compression,
        metadata: DatasetDescriptorMetadata {
            root: Some(FixedBytes::from(root)),
            checkpoint_block: Some(checkpoint.last_indexed_block),
            tree_number: Some(tree_number),
            leaf_count: Some(checkpoint.leaf_count),
            start_block: None,
            end_block: None,
            last_indexed_block: Some(checkpoint.last_indexed_block),
            ..DatasetDescriptorMetadata::default()
        },
    };

    Ok(PublishedMerkleCheckpointArtifact {
        descriptor,
        compressed_bytes,
    })
}

pub fn decode_merkle_checkpoint_artifact(
    descriptor: &IndexedArtifactDescriptor,
    bytes: &[u8],
) -> Result<ChunkEnvelope, ChunkError> {
    decode_chunk_bytes(descriptor, bytes)
}

fn validate_checkpoint(
    checkpoint: &MerkleCheckpointArtifact,
) -> Result<(), MerkleCheckpointArtifactError> {
    if checkpoint.leaf_count == 0 {
        return Err(MerkleCheckpointArtifactError::EmptyCheckpoint);
    }
    if checkpoint.leaf_count > TREE_LEAF_COUNT {
        return Err(MerkleCheckpointArtifactError::LeafCountTooLarge {
            leaf_count: checkpoint.leaf_count,
            maximum: TREE_LEAF_COUNT,
        });
    }
    let leaf_len =
        u64::try_from(checkpoint.leaves.len()).map_err(|_| ChunkError::PayloadTooLarge)?;
    if leaf_len != checkpoint.leaf_count {
        return Err(MerkleCheckpointArtifactError::LeafCountMismatch {
            declared: checkpoint.leaf_count,
            actual: leaf_len,
        });
    }
    Ok(())
}

fn checkpoint_range(
    checkpoint: &MerkleCheckpointArtifact,
) -> Result<IndexedArtifactRange, MerkleCheckpointArtifactError> {
    let start = u64::from(checkpoint.tree_number)
        .checked_mul(TREE_LEAF_COUNT)
        .ok_or(MerkleCheckpointArtifactError::RangeOverflow)?;
    let end = start
        .checked_add(checkpoint.leaf_count - 1)
        .ok_or(MerkleCheckpointArtifactError::RangeOverflow)?;
    Ok(IndexedArtifactRange {
        kind: IndexedArtifactRangeKind::TreePosition,
        start,
        end,
    })
}

fn encode_merkle_checkpoint(
    checkpoint: &MerkleCheckpointArtifact,
    root: [u8; 32],
) -> Result<Vec<u8>, ChunkError> {
    let mut bytes = Vec::with_capacity(24 + checkpoint.leaves.len().saturating_mul(32));
    write_u32(&mut bytes, checkpoint.tree_number);
    write_u64(&mut bytes, checkpoint.leaf_count);
    bytes.extend_from_slice(&root);
    write_u64(&mut bytes, checkpoint.last_indexed_block);
    for leaf in &checkpoint.leaves {
        bytes.extend_from_slice(leaf);
    }
    if u64::try_from(bytes.len()).is_err() {
        return Err(ChunkError::PayloadTooLarge);
    }
    Ok(bytes)
}

fn checkpoint_root(checkpoint: &MerkleCheckpointArtifact) -> [u8; 32] {
    let mut layer = checkpoint
        .leaves
        .iter()
        .copied()
        .map(U256::from_be_bytes)
        .collect::<Vec<_>>();
    let mut empty_subtree_root = MERKLE_ZERO_VALUE;

    for _ in 0..TREE_DEPTH {
        if !layer.len().is_multiple_of(2) {
            layer.push(empty_subtree_root);
        }
        let mut parents = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks_exact(2) {
            parents.push(poseidon(vec![pair[0], pair[1]]));
        }
        layer = parents;
        empty_subtree_root = poseidon(vec![empty_subtree_root, empty_subtree_root]);
    }

    layer
        .first()
        .copied()
        .unwrap_or(MERKLE_ZERO_VALUE)
        .to_be_bytes::<32>()
}

fn write_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleCheckpointArtifact {
    pub tree_number: u32,
    pub leaf_count: u64,
    pub last_indexed_block: u64,
    pub leaves: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedMerkleCheckpointArtifact {
    pub descriptor: IndexedArtifactDescriptor,
    pub compressed_bytes: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum MerkleCheckpointArtifactError {
    #[error("merkle checkpoint has no leaves")]
    EmptyCheckpoint,
    #[error("merkle checkpoint leaf count {leaf_count} exceeds maximum {maximum}")]
    LeafCountTooLarge { leaf_count: u64, maximum: u64 },
    #[error("merkle checkpoint leaf count mismatch: declared {declared}, actual {actual}")]
    LeafCountMismatch { declared: u64, actual: u64 },
    #[error("merkle checkpoint tree number {tree_number} exceeds descriptor metadata range")]
    TreeNumberOutOfRange { tree_number: u32 },
    #[error("merkle checkpoint global range overflowed")]
    RangeOverflow,
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
    use merkletree::tree::DenseMerkleTree;
    use std::sync::Mutex;

    #[tokio::test]
    async fn merkle_checkpoint_artifact_publishes_tree_shard_descriptor() {
        let ipfs = RecordingIpfsClient::default();
        let checkpoint = MerkleCheckpointArtifact {
            tree_number: 2,
            leaf_count: 3,
            last_indexed_block: 123,
            leaves: vec![[0x11; 32], [0x22; 32], [0x33; 32]],
        };
        let expected_root = DenseMerkleTree::from_ordered_leaves(
            checkpoint.leaves.iter().copied().map(U256::from_be_bytes),
            checkpoint.leaf_count,
        )
        .root()
        .to_be_bytes::<32>();

        let published = publish_merkle_checkpoint_artifact(
            &ipfs,
            scope(),
            &checkpoint,
            CompressionAlgorithm::Zstd,
        )
        .await
        .expect("publish checkpoint");

        assert_eq!(
            published.descriptor.dataset_kind,
            IndexedDatasetKind::MerkleCheckpoint
        );
        assert_eq!(
            published.descriptor.range.kind,
            IndexedArtifactRangeKind::TreePosition
        );
        assert_eq!(published.descriptor.range.start, 2 * TREE_LEAF_COUNT);
        assert_eq!(published.descriptor.range.end, 2 * TREE_LEAF_COUNT + 2);
        assert_eq!(published.descriptor.row_count, 3);
        assert_eq!(published.descriptor.metadata.tree_number, Some(2));
        assert_eq!(published.descriptor.metadata.leaf_count, Some(3));
        assert_eq!(published.descriptor.metadata.checkpoint_block, Some(123));
        assert_eq!(published.descriptor.metadata.last_indexed_block, Some(123));
        assert_eq!(
            published.descriptor.metadata.root,
            Some(FixedBytes::from(expected_root))
        );
        assert_eq!(
            published.descriptor.byte_size,
            u64::try_from(published.compressed_bytes.len()).expect("byte size")
        );
        assert_eq!(ipfs.pinned_count(), 1);

        let envelope =
            decode_merkle_checkpoint_artifact(&published.descriptor, &published.compressed_bytes)
                .expect("decode checkpoint");
        assert_eq!(envelope.header.sections.len(), 1);
        assert_eq!(read_u32(envelope.payload(), 0), 2);
        assert_eq!(read_u64(envelope.payload(), 4), 3);
        assert_eq!(read_fixed_32(envelope.payload(), 12), expected_root);
    }

    #[tokio::test]
    async fn merkle_checkpoint_artifact_rejects_leaf_count_mismatch() {
        let ipfs = RecordingIpfsClient::default();
        let checkpoint = MerkleCheckpointArtifact {
            tree_number: 0,
            leaf_count: 2,
            last_indexed_block: 123,
            leaves: vec![[0x11; 32]],
        };

        let error = publish_merkle_checkpoint_artifact(
            &ipfs,
            scope(),
            &checkpoint,
            CompressionAlgorithm::Zstd,
        )
        .await
        .expect_err("leaf count mismatch should fail");

        assert!(matches!(
            error,
            MerkleCheckpointArtifactError::LeafCountMismatch {
                declared: 2,
                actual: 1,
            }
        ));
        assert_eq!(ipfs.pinned_count(), 0);
    }

    fn read_u32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("u32 checkpoint field"),
        )
    }

    fn read_u64(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .expect("u64 checkpoint field"),
        )
    }

    fn read_fixed_32(bytes: &[u8], offset: usize) -> [u8; 32] {
        bytes[offset..offset + 32]
            .try_into()
            .expect("32-byte checkpoint field")
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
