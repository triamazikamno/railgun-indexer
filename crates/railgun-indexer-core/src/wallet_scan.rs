use crate::chunk::{
    CHUNK_FORMAT_VERSION, ChunkEnvelope, ChunkEnvelopeHeader, ChunkError, ChunkPlanItem,
    ChunkSection, MAX_COMPRESSED_CHUNK_BYTES, decode_chunk_bytes, encode_chunk_bytes,
};
use crate::manifest::{
    ChainScope, CompressionAlgorithm, DatasetDescriptorMetadata, IndexedArtifactDescriptor,
    IndexedArtifactRange, IndexedArtifactRangeKind, IndexedDatasetKind,
};
use crate::publish::ipfs::{IpfsClient, IpfsError, pin_indexed_chunk};
use crate::store::{
    StoredIndexedLogSourceRow, StoredLegacyEncryptedCommitmentRow,
    StoredLegacyGeneratedCommitmentRow, StoredNullifierRow, StoredShieldCommitmentRow,
    StoredTransactCommitmentRow, StoredWalletScanRows,
};
use alloy::primitives::FixedBytes;
use sha2::{Digest, Sha256};
use thiserror::Error;

const TRANSACT_SECTION_ID: u16 = 1;
const SHIELD_SECTION_ID: u16 = 2;
const NULLIFIER_SECTION_ID: u16 = 3;
const LEGACY_ENCRYPTED_SECTION_ID: u16 = 4;
const LEGACY_GENERATED_SECTION_ID: u16 = 5;

pub fn wallet_scan_chunk_plan_item(
    scope: &ChainScope,
    start_block: u64,
    end_block: u64,
    rows: &StoredWalletScanRows,
    compression: CompressionAlgorithm,
) -> Result<ChunkPlanItem, WalletScanChunkError> {
    if start_block > end_block {
        return Err(WalletScanChunkError::InvalidBlockRange {
            start: start_block,
            end: end_block,
        });
    }
    validate_rows_in_range(rows, start_block, end_block)?;
    let (payload, sections, row_count) = encode_wallet_scan_records(rows)?;
    let payload_len = u64::try_from(payload.len()).map_err(|_| ChunkError::PayloadTooLarge)?;
    let range = IndexedArtifactRange {
        kind: IndexedArtifactRangeKind::Block,
        start: start_block,
        end: end_block,
    };
    let compressed_bytes = encode_wallet_scan_envelope(
        scope.clone(),
        range.clone(),
        row_count,
        payload_len,
        sections,
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

pub async fn publish_wallet_scan_chunk(
    ipfs_client: &dyn IpfsClient,
    scope: ChainScope,
    start_block: u64,
    end_block: u64,
    rows: &StoredWalletScanRows,
    compression: CompressionAlgorithm,
) -> Result<PublishedWalletScanChunk, WalletScanChunkError> {
    let mut published =
        prepare_wallet_scan_chunk(scope, start_block, end_block, rows, compression)?;
    let cid = pin_indexed_chunk(ipfs_client, &published.compressed_bytes).await?;
    published.descriptor.cid = cid.to_string();
    Ok(published)
}

pub fn prepare_wallet_scan_chunk(
    scope: ChainScope,
    start_block: u64,
    end_block: u64,
    rows: &StoredWalletScanRows,
    compression: CompressionAlgorithm,
) -> Result<PublishedWalletScanChunk, WalletScanChunkError> {
    if start_block > end_block {
        return Err(WalletScanChunkError::InvalidBlockRange {
            start: start_block,
            end: end_block,
        });
    }
    validate_rows_in_range(rows, start_block, end_block)?;

    let (payload, sections, row_count) = encode_wallet_scan_records(rows)?;
    let payload_len = u64::try_from(payload.len()).map_err(|_| ChunkError::PayloadTooLarge)?;
    let range = IndexedArtifactRange {
        kind: IndexedArtifactRangeKind::Block,
        start: start_block,
        end: end_block,
    };
    let root = FixedBytes::from_slice(&Sha256::digest(&payload));
    let compressed_bytes = encode_wallet_scan_envelope(
        scope.clone(),
        range.clone(),
        row_count,
        payload_len,
        sections,
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
        dataset_kind: IndexedDatasetKind::WalletScan,
        scope,
        range,
        row_count,
        cid: String::new(),
        sha256,
        byte_size,
        encoding_version: CHUNK_FORMAT_VERSION,
        compression,
        metadata: DatasetDescriptorMetadata {
            root: Some(root),
            checkpoint_block: Some(end_block),
            last_indexed_block: Some(end_block),
            ..Default::default()
        },
    };

    Ok(PublishedWalletScanChunk {
        descriptor,
        compressed_bytes,
    })
}

fn encode_wallet_scan_envelope(
    scope: ChainScope,
    range: IndexedArtifactRange,
    row_count: u64,
    payload_len: u64,
    sections: Vec<ChunkSection>,
    payload: Vec<u8>,
    compression: CompressionAlgorithm,
) -> Result<Vec<u8>, ChunkError> {
    let envelope = ChunkEnvelope::new(
        ChunkEnvelopeHeader::new(
            IndexedDatasetKind::WalletScan,
            scope,
            range,
            row_count,
            payload_len,
            sections,
        ),
        payload,
    );
    encode_chunk_bytes(&envelope, compression)
}

pub fn decode_wallet_scan_chunk(
    descriptor: &IndexedArtifactDescriptor,
    bytes: &[u8],
) -> Result<ChunkEnvelope, ChunkError> {
    decode_chunk_bytes(descriptor, bytes)
}

fn validate_rows_in_range(
    rows: &StoredWalletScanRows,
    start_block: u64,
    end_block: u64,
) -> Result<(), WalletScanChunkError> {
    for record in &rows.transact_commitments {
        validate_source_in_range("transact", &record.source, start_block, end_block)?;
    }
    for record in &rows.shield_commitments {
        validate_source_in_range("shield", &record.source, start_block, end_block)?;
    }
    for record in &rows.nullifiers {
        validate_source_in_range("nullifier", &record.source, start_block, end_block)?;
    }
    for record in &rows.legacy_encrypted_commitments {
        validate_source_in_range("legacy_encrypted", &record.source, start_block, end_block)?;
    }
    for record in &rows.legacy_generated_commitments {
        validate_source_in_range("legacy_generated", &record.source, start_block, end_block)?;
    }
    Ok(())
}

const fn validate_source_in_range(
    section: &'static str,
    source: &StoredIndexedLogSourceRow,
    start_block: u64,
    end_block: u64,
) -> Result<(), WalletScanChunkError> {
    if source.block_number < start_block || source.block_number > end_block {
        return Err(WalletScanChunkError::RecordOutOfRange {
            section,
            block_number: source.block_number,
            start: start_block,
            end: end_block,
        });
    }
    Ok(())
}

fn encode_wallet_scan_records(
    rows: &StoredWalletScanRows,
) -> Result<(Vec<u8>, Vec<ChunkSection>, u64), WalletScanChunkError> {
    let mut payload = Vec::new();
    let mut sections = Vec::new();
    append_section(&mut payload, &mut sections, TRANSACT_SECTION_ID, |bytes| {
        write_transact_records(bytes, &rows.transact_commitments)
    })?;
    append_section(&mut payload, &mut sections, SHIELD_SECTION_ID, |bytes| {
        write_shield_records(bytes, &rows.shield_commitments)
    })?;
    append_section(&mut payload, &mut sections, NULLIFIER_SECTION_ID, |bytes| {
        write_nullifier_records(bytes, &rows.nullifiers)
    })?;
    append_section(
        &mut payload,
        &mut sections,
        LEGACY_ENCRYPTED_SECTION_ID,
        |bytes| write_legacy_encrypted_records(bytes, &rows.legacy_encrypted_commitments),
    )?;
    append_section(
        &mut payload,
        &mut sections,
        LEGACY_GENERATED_SECTION_ID,
        |bytes| write_legacy_generated_records(bytes, &rows.legacy_generated_commitments),
    )?;

    let row_count = [
        rows.transact_commitments.len(),
        rows.shield_commitments.len(),
        rows.nullifiers.len(),
        rows.legacy_encrypted_commitments.len(),
        rows.legacy_generated_commitments.len(),
    ]
    .into_iter()
    .try_fold(0_u64, |total, count| -> Result<u64, WalletScanChunkError> {
        let count = u64::try_from(count).map_err(|_| ChunkError::PayloadTooLarge)?;
        total
            .checked_add(count)
            .ok_or_else(|| ChunkError::PayloadTooLarge.into())
    })?;

    Ok((payload, sections, row_count))
}

fn append_section(
    payload: &mut Vec<u8>,
    sections: &mut Vec<ChunkSection>,
    section_id: u16,
    write: impl FnOnce(&mut Vec<u8>) -> Result<(), WalletScanChunkError>,
) -> Result<(), WalletScanChunkError> {
    let offset = u64::try_from(payload.len()).map_err(|_| ChunkError::PayloadTooLarge)?;
    write(payload)?;
    let end = u64::try_from(payload.len()).map_err(|_| ChunkError::PayloadTooLarge)?;
    sections.push(ChunkSection {
        section_id,
        offset,
        byte_length: end.checked_sub(offset).ok_or(ChunkError::PayloadTooLarge)?,
    });
    Ok(())
}

fn write_transact_records(
    bytes: &mut Vec<u8>,
    records: &[StoredTransactCommitmentRow],
) -> Result<(), WalletScanChunkError> {
    write_len(bytes, records.len())?;
    for record in records {
        write_source(bytes, "transact", &record.source)?;
        write_u32(bytes, record.tree_number);
        write_u64(bytes, record.tree_position);
        bytes.extend_from_slice(&record.commitment_hash);
        write_bytes(bytes, &record.ciphertext)?;
    }
    Ok(())
}

fn write_shield_records(
    bytes: &mut Vec<u8>,
    records: &[StoredShieldCommitmentRow],
) -> Result<(), WalletScanChunkError> {
    write_len(bytes, records.len())?;
    for record in records {
        write_source(bytes, "shield", &record.source)?;
        write_u32(bytes, record.tree_number);
        write_u64(bytes, record.tree_position);
        bytes.extend_from_slice(&record.commitment_hash);
        write_bytes(bytes, &record.preimage)?;
        write_bytes(bytes, &record.shield_ciphertext)?;
    }
    Ok(())
}

fn write_nullifier_records(
    bytes: &mut Vec<u8>,
    records: &[StoredNullifierRow],
) -> Result<(), WalletScanChunkError> {
    write_len(bytes, records.len())?;
    for record in records {
        write_source(bytes, "nullifier", &record.source)?;
        write_u32(bytes, record.tree_number);
        bytes.extend_from_slice(&record.nullifier);
    }
    Ok(())
}

fn write_legacy_encrypted_records(
    bytes: &mut Vec<u8>,
    records: &[StoredLegacyEncryptedCommitmentRow],
) -> Result<(), WalletScanChunkError> {
    write_len(bytes, records.len())?;
    for record in records {
        write_source(bytes, "legacy_encrypted", &record.source)?;
        write_u32(bytes, record.tree_number);
        write_u64(bytes, record.tree_position);
        bytes.extend_from_slice(&record.commitment_hash);
        write_bytes(bytes, &record.ciphertext)?;
    }
    Ok(())
}

fn write_legacy_generated_records(
    bytes: &mut Vec<u8>,
    records: &[StoredLegacyGeneratedCommitmentRow],
) -> Result<(), WalletScanChunkError> {
    write_len(bytes, records.len())?;
    for record in records {
        write_source(bytes, "legacy_generated", &record.source)?;
        write_u32(bytes, record.tree_number);
        write_u64(bytes, record.tree_position);
        bytes.extend_from_slice(&record.commitment_hash);
        write_bytes(bytes, &record.preimage)?;
        bytes.extend_from_slice(&record.encrypted_random);
    }
    Ok(())
}

fn write_source(
    bytes: &mut Vec<u8>,
    section: &'static str,
    source: &StoredIndexedLogSourceRow,
) -> Result<(), WalletScanChunkError> {
    let block_timestamp =
        source
            .block_timestamp
            .ok_or(WalletScanChunkError::MissingBlockTimestamp {
                section,
                block_number: source.block_number,
            })?;
    write_u64(bytes, source.block_number);
    write_u64(bytes, block_timestamp);
    bytes.extend_from_slice(&source.transaction_hash);
    Ok(())
}

fn write_len(bytes: &mut Vec<u8>, count: usize) -> Result<(), ChunkError> {
    write_u64(
        bytes,
        u64::try_from(count).map_err(|_| ChunkError::PayloadTooLarge)?,
    );
    Ok(())
}

fn write_bytes(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), ChunkError> {
    write_u32(
        bytes,
        u32::try_from(value.len()).map_err(|_| ChunkError::PayloadTooLarge)?,
    );
    bytes.extend_from_slice(value);
    Ok(())
}

fn write_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedWalletScanChunk {
    pub descriptor: IndexedArtifactDescriptor,
    pub compressed_bytes: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum WalletScanChunkError {
    #[error("wallet scan chunk range start {start} exceeds end {end}")]
    InvalidBlockRange { start: u64, end: u64 },
    #[error(
        "wallet scan {section} record at block {block_number} is outside chunk range {start}..={end}"
    )]
    RecordOutOfRange {
        section: &'static str,
        block_number: u64,
        start: u64,
        end: u64,
    },
    #[error("wallet scan {section} record at block {block_number} is missing block_timestamp")]
    MissingBlockTimestamp {
        section: &'static str,
        block_number: u64,
    },
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
    async fn wallet_scan_chunk_publishes_complete_block_range_descriptor() {
        let ipfs = RecordingIpfsClient::default();
        let rows = wallet_rows(100);

        let published =
            publish_wallet_scan_chunk(&ipfs, scope(), 100, 110, &rows, CompressionAlgorithm::Zstd)
                .await
                .expect("publish chunk");

        assert_eq!(
            published.descriptor.dataset_kind,
            IndexedDatasetKind::WalletScan
        );
        assert_eq!(
            published.descriptor.range.kind,
            IndexedArtifactRangeKind::Block
        );
        assert_eq!(published.descriptor.range.start, 100);
        assert_eq!(published.descriptor.range.end, 110);
        assert_eq!(published.descriptor.row_count, 5);
        assert_eq!(published.descriptor.compression, CompressionAlgorithm::Zstd);
        assert_eq!(published.descriptor.metadata.checkpoint_block, Some(110));
        assert_eq!(published.descriptor.metadata.last_indexed_block, Some(110));
        assert!(published.descriptor.metadata.root.is_some());
        assert_eq!(
            published.descriptor.byte_size,
            u64::try_from(published.compressed_bytes.len()).expect("byte size")
        );
        assert_eq!(ipfs.pinned_count(), 1);

        let envelope = decode_wallet_scan_chunk(&published.descriptor, &published.compressed_bytes)
            .expect("decode published chunk");
        assert_eq!(envelope.header.sections.len(), 5);
        assert_eq!(section_count(&envelope, TRANSACT_SECTION_ID), 1);
        assert_eq!(section_count(&envelope, SHIELD_SECTION_ID), 1);
        assert_eq!(section_count(&envelope, NULLIFIER_SECTION_ID), 1);
        assert_eq!(section_count(&envelope, LEGACY_ENCRYPTED_SECTION_ID), 1);
        assert_eq!(section_count(&envelope, LEGACY_GENERATED_SECTION_ID), 1);
    }

    #[tokio::test]
    async fn wallet_scan_chunk_allows_empty_complete_block_range() {
        let ipfs = RecordingIpfsClient::default();
        let rows = StoredWalletScanRows::default();

        let published =
            publish_wallet_scan_chunk(&ipfs, scope(), 200, 250, &rows, CompressionAlgorithm::Zstd)
                .await
                .expect("publish empty range");

        assert_eq!(published.descriptor.row_count, 0);
        assert_eq!(published.descriptor.range.start, 200);
        assert_eq!(published.descriptor.range.end, 250);
        let envelope = decode_wallet_scan_chunk(&published.descriptor, &published.compressed_bytes)
            .expect("decode empty chunk");
        assert_eq!(section_count(&envelope, TRANSACT_SECTION_ID), 0);
        assert_eq!(section_count(&envelope, SHIELD_SECTION_ID), 0);
        assert_eq!(section_count(&envelope, NULLIFIER_SECTION_ID), 0);
        assert_eq!(section_count(&envelope, LEGACY_ENCRYPTED_SECTION_ID), 0);
        assert_eq!(section_count(&envelope, LEGACY_GENERATED_SECTION_ID), 0);
    }

    #[tokio::test]
    async fn wallet_scan_chunk_rejects_records_outside_block_range() {
        let ipfs = RecordingIpfsClient::default();
        let rows = wallet_rows(99);

        let error =
            publish_wallet_scan_chunk(&ipfs, scope(), 100, 110, &rows, CompressionAlgorithm::Zstd)
                .await
                .expect_err("out of range row should fail");

        assert!(matches!(
            error,
            WalletScanChunkError::RecordOutOfRange {
                section: "transact",
                block_number: 99,
                start: 100,
                end: 110,
            }
        ));
        assert_eq!(ipfs.pinned_count(), 0);
    }

    #[tokio::test]
    async fn wallet_scan_chunk_rejects_missing_source_timestamp() {
        let ipfs = RecordingIpfsClient::default();
        let mut rows = wallet_rows(100);
        rows.transact_commitments[0].source.block_timestamp = None;

        let error =
            publish_wallet_scan_chunk(&ipfs, scope(), 100, 110, &rows, CompressionAlgorithm::Zstd)
                .await
                .expect_err("missing timestamp should fail");

        assert!(matches!(
            error,
            WalletScanChunkError::MissingBlockTimestamp {
                section: "transact",
                block_number: 100,
            }
        ));
        assert_eq!(ipfs.pinned_count(), 0);
    }

    fn wallet_rows(block_number: u64) -> StoredWalletScanRows {
        StoredWalletScanRows {
            transact_commitments: vec![StoredTransactCommitmentRow {
                source: source(block_number, 1),
                tree_number: 1,
                tree_position: 10,
                commitment_hash: [0x10; 32],
                ciphertext: vec![0x11; 16],
            }],
            shield_commitments: vec![StoredShieldCommitmentRow {
                source: source(101, 2),
                tree_number: 1,
                tree_position: 11,
                commitment_hash: [0x12; 32],
                preimage: vec![0x13; 32],
                shield_ciphertext: vec![0x14; 32],
            }],
            nullifiers: vec![StoredNullifierRow {
                source: source(102, 3),
                tree_number: 1,
                nullifier: [0x15; 32],
            }],
            legacy_encrypted_commitments: vec![StoredLegacyEncryptedCommitmentRow {
                source: source(103, 4),
                tree_number: 0,
                tree_position: 1,
                commitment_hash: [0x16; 32],
                ciphertext: vec![0x17; 24],
            }],
            legacy_generated_commitments: vec![StoredLegacyGeneratedCommitmentRow {
                source: source(104, 5),
                tree_number: 0,
                tree_position: 2,
                commitment_hash: [0x18; 32],
                preimage: vec![0x19; 32],
                encrypted_random: [0x20; 64],
            }],
        }
    }

    fn source(block_number: u64, log_index: u64) -> StoredIndexedLogSourceRow {
        StoredIndexedLogSourceRow {
            block_number,
            block_timestamp: Some(block_number + 1_700_000_000),
            block_hash: [0xaa; 32],
            transaction_hash: [log_index as u8; 32],
            log_index,
        }
    }

    fn section_count(envelope: &ChunkEnvelope, section_id: u16) -> u64 {
        let section = envelope
            .header
            .sections
            .iter()
            .find(|section| section.section_id == section_id)
            .expect("section exists");
        let offset = usize::try_from(section.offset).expect("section offset");
        let bytes = envelope
            .payload
            .get(offset..offset + 8)
            .expect("section count bytes");
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
