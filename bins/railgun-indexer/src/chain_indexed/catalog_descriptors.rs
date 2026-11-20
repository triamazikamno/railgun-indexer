#[allow(clippy::wildcard_imports)]
use super::*;

#[derive(Debug, Clone, Copy)]
pub(super) enum CatalogCoverage {
    DerivedFromChunks,
    ExplicitBlockRange {
        start_block: u64,
        indexed_through_block: u64,
    },
}

pub(super) fn prepare_catalog_artifact(
    scope: &ChainScope,
    dataset_kind: IndexedDatasetKind,
    chunks: Vec<IndexedArtifactDescriptor>,
    coverage: CatalogCoverage,
) -> Result<(
    IndexedArtifactCatalog,
    Vec<u8>,
    [u8; 32],
    IndexedArtifactDescriptor,
)> {
    let catalog = IndexedArtifactCatalog::new(dataset_kind, scope.clone(), chunks);
    let catalog_bytes = catalog
        .deterministic_body_bytes()
        .wrap_err("serialize indexed artifact catalog")?;
    let byte_size = u64::try_from(catalog_bytes.len())
        .wrap_err("indexed artifact catalog byte size overflow")?;
    let catalog_hash = content_hash(&catalog_bytes);
    let descriptor = catalog_descriptor(&catalog, "", byte_size, &catalog_hash, coverage)?;
    Ok((catalog, catalog_bytes, catalog_hash, descriptor))
}

pub(super) fn catalog_descriptor(
    catalog: &IndexedArtifactCatalog,
    cid: &str,
    byte_size: u64,
    content_hash: &[u8; 32],
    coverage: CatalogCoverage,
) -> Result<IndexedArtifactDescriptor> {
    let mut chunks = catalog.chunks.clone();
    chunks.sort_by(|left, right| {
        left.range
            .start
            .cmp(&right.range.start)
            .then_with(|| left.range.end.cmp(&right.range.end))
            .then_with(|| left.cid.cmp(&right.cid))
    });
    if chunks
        .iter()
        .any(|chunk| chunk.dataset_kind != catalog.dataset_kind || chunk.scope != catalog.scope)
    {
        return Err(eyre!(
            "indexed artifact catalog chunks have mixed dataset or scope"
        ));
    }
    let range = match coverage {
        CatalogCoverage::DerivedFromChunks => {
            let first = chunks
                .first()
                .ok_or_else(|| eyre!("indexed artifact catalog cannot be empty"))?;
            let last = chunks.last().expect("non-empty chunks checked above");
            if chunks
                .iter()
                .any(|chunk| chunk.range.kind != first.range.kind)
            {
                return Err(eyre!(
                    "indexed artifact catalog chunks have mixed range kind"
                ));
            }
            IndexedArtifactRange {
                kind: first.range.kind,
                start: first.range.start,
                end: last.range.end,
            }
        }
        CatalogCoverage::ExplicitBlockRange {
            start_block,
            indexed_through_block,
        } => {
            if catalog.dataset_kind != IndexedDatasetKind::WalletScan {
                return Err(eyre!(
                    "explicit block coverage is only supported for wallet-scan catalogs"
                ));
            }
            if start_block > indexed_through_block {
                return Err(eyre!(
                    "indexed artifact catalog coverage start {start_block} exceeds indexed-through block {indexed_through_block}"
                ));
            }
            if chunks.iter().any(|chunk| {
                chunk.range.kind != IndexedArtifactRangeKind::Block
                    || chunk.range.start < start_block
                    || chunk.range.end > indexed_through_block
            }) {
                return Err(eyre!(
                    "indexed artifact catalog chunk is outside explicit block coverage {start_block}-{indexed_through_block}"
                ));
            }
            IndexedArtifactRange {
                kind: IndexedArtifactRangeKind::Block,
                start: start_block,
                end: indexed_through_block,
            }
        }
    };
    let row_count = chunks.iter().try_fold(0_u64, |total, chunk| {
        total
            .checked_add(chunk.row_count)
            .ok_or_else(|| eyre!("indexed catalog row count overflow"))
    })?;
    let last_indexed_block = chunks
        .iter()
        .filter_map(|chunk| chunk.metadata.last_indexed_block)
        .max();
    let start_block = chunks
        .iter()
        .filter_map(|chunk| chunk.metadata.start_block)
        .min();
    let end_block = chunks
        .iter()
        .filter_map(|chunk| chunk.metadata.end_block)
        .max();
    let (start_block, end_block, last_indexed_block, checkpoint_block) = match coverage {
        CatalogCoverage::DerivedFromChunks => (
            start_block,
            end_block,
            last_indexed_block,
            last_indexed_block,
        ),
        CatalogCoverage::ExplicitBlockRange {
            start_block,
            indexed_through_block,
        } => (
            Some(start_block),
            Some(indexed_through_block),
            Some(indexed_through_block),
            Some(indexed_through_block),
        ),
    };

    Ok(IndexedArtifactDescriptor {
        dataset_kind: catalog.dataset_kind,
        scope: catalog.scope.clone(),
        range,
        row_count,
        cid: cid.to_string(),
        sha256: FixedBytes::from(*content_hash),
        byte_size,
        encoding_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
        compression: CompressionAlgorithm::None,
        metadata: DatasetDescriptorMetadata {
            start_block,
            end_block,
            last_indexed_block,
            checkpoint_block,
            ..Default::default()
        },
    })
}

pub(super) fn public_txid_chunk_row_limit(offset: u64, configured_limit: u64) -> u64 {
    let remaining_in_tree = TREE_LEAF_COUNT - (offset % TREE_LEAF_COUNT);
    configured_limit.min(remaining_in_tree)
}

pub(super) fn latest_indexed_block(
    latest_indexed: &[LatestIndexedHeight],
    dataset_kind: IndexedDatasetKind,
) -> Option<u64> {
    latest_indexed
        .iter()
        .find(|height| height.dataset_kind == dataset_kind)
        .map(|height| height.block_number)
}

pub(super) fn public_txid_plan_items(
    scope: &ChainScope,
    rows: &[StoredPublicTxidRow],
) -> Result<Vec<ChunkPlanItem>> {
    rows.chunks(PUBLIC_TXID_PLANNING_ROW_UNIT)
        .map(|rows| {
            public_txid_chunk_plan_item(scope, rows, CompressionAlgorithm::Zstd)
                .wrap_err("plan public TXID artifact chunk unit")
        })
        .collect()
}

pub(super) fn commitment_plan_items(
    scope: &ChainScope,
    rows: &[railgun_indexer_core::store::StoredCommitmentRow],
) -> Result<Vec<ChunkPlanItem>> {
    rows.chunks(COMMITMENT_PLANNING_ROW_UNIT)
        .map(|rows| {
            commitment_chunk_plan_item(scope, rows, CompressionAlgorithm::Zstd)
                .wrap_err("plan commitment artifact chunk unit")
        })
        .collect()
}

pub(super) const fn store_dataset_kind(dataset: IndexedDatasetKind) -> StoreDatasetKind {
    match dataset {
        IndexedDatasetKind::WalletScan => StoreDatasetKind::WalletScan,
        IndexedDatasetKind::Commitments => StoreDatasetKind::Commitments,
        IndexedDatasetKind::MerkleCheckpoint => StoreDatasetKind::MerkleCheckpoint,
        IndexedDatasetKind::PublicTxid => StoreDatasetKind::PublicTxid,
    }
}

pub(super) const fn fixed_bytes(value: &FixedBytes<32>) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(value.as_slice());
    bytes
}
