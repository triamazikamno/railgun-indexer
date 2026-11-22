#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) const FULL_DERIVATION_INTERVAL: Duration = Duration::from_hours(24);

/// One dataset as a publication derived it, so a later cycle can reuse its chunks.
#[derive(Debug, Clone)]
pub(super) struct RememberedDataset {
    pub(super) dataset_kind: IndexedDatasetKind,
    pub(super) height: (u64, FixedBytes<32>),
    pub(super) chunks: Vec<IndexedArtifactDescriptor>,
    /// Public TXID offset or commitment position where the page or window holding the last chunk
    /// started; zero for the other datasets.
    restart: u64,
    /// Public TXID tree leaves through the last chunk; empty for the other datasets.
    public_txid_checkpoint: PublicTxidCheckpoint,
}

impl RememberedDataset {
    pub(super) const fn new(
        height: &LatestIndexedHeight,
        chunks: Vec<IndexedArtifactDescriptor>,
        restart: u64,
        public_txid_checkpoint: PublicTxidCheckpoint,
    ) -> Self {
        Self {
            dataset_kind: height.dataset_kind,
            height: (height.block_number, height.block_hash),
            chunks,
            restart,
            public_txid_checkpoint,
        }
    }

    /// Chunks that end before `restart`, which a derivation starting there leaves unchanged.
    fn chunks_before(&self, restart: u64) -> Vec<IndexedArtifactDescriptor> {
        self.chunks
            .iter()
            .take_while(|chunk| chunk.range.end < restart)
            .cloned()
            .collect()
    }

    /// Start of the wallet-scan planning bucket that holds the last chunk's start.
    fn wallet_scan_restart(&self, start_block: u64) -> u64 {
        self.chunks.last().map_or(start_block, |last| {
            let bucket_offset = last.range.start.saturating_sub(start_block)
                / WALLET_SCAN_PLANNING_BLOCK_SPAN
                * WALLET_SCAN_PLANNING_BLOCK_SPAN;
            start_block.saturating_add(bucket_offset)
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum ChunkReuse<'a> {
    DeriveAll,
    ReuseAll(&'a RememberedDataset),
    ReuseAllButLast(&'a RememberedDataset),
}

impl ChunkReuse<'_> {
    /// Remembered chunks that a derivation under this decision keeps instead of deriving.
    pub(super) fn kept_chunks(self, start_block: u64) -> Vec<IndexedArtifactDescriptor> {
        match self {
            Self::DeriveAll => Vec::new(),
            Self::ReuseAll(previous) => previous.chunks.clone(),
            Self::ReuseAllButLast(previous) => match previous.dataset_kind {
                IndexedDatasetKind::PublicTxid
                | IndexedDatasetKind::Commitments
                | IndexedDatasetKind::WalletScan => {
                    previous.chunks_before(self.restart(start_block))
                }
                IndexedDatasetKind::MerkleCheckpoint => previous
                    .chunks
                    .split_last()
                    .map_or_else(Vec::new, |(_, earlier)| earlier.to_vec()),
            },
        }
    }

    /// Public TXID offset, commitment position or wallet-scan block where derivation restarts.
    /// `start_block` is where a full derivation starts: the chain's start block for wallet scan
    /// and zero for the position-ranged datasets.
    pub(super) fn restart(self, start_block: u64) -> u64 {
        match self {
            Self::DeriveAll => start_block,
            Self::ReuseAll(previous) | Self::ReuseAllButLast(previous) => {
                match previous.dataset_kind {
                    IndexedDatasetKind::WalletScan => previous.wallet_scan_restart(start_block),
                    IndexedDatasetKind::PublicTxid
                    | IndexedDatasetKind::Commitments
                    | IndexedDatasetKind::MerkleCheckpoint => previous.restart,
                }
            }
        }
    }

    /// Public TXID tree leaves before the restart offset, which derivation continues from.
    pub(super) fn public_txid_checkpoint(self) -> Result<PublicTxidCheckpoint> {
        let (Self::ReuseAll(previous) | Self::ReuseAllButLast(previous)) = self else {
            return Ok(PublicTxidCheckpoint::default());
        };
        let mut checkpoint = previous.public_txid_checkpoint.clone();
        checkpoint.truncate(
            usize::try_from(previous.restart % TREE_LEAF_COUNT)
                .wrap_err("public TXID restart tree offset overflow")?,
        );
        Ok(checkpoint)
    }
}

/// Whether the next cycle must derive every chunk; a clock that went backwards counts as due.
pub(super) fn full_derivation_due(
    last_full_derivation: Option<SystemTime>,
    now: SystemTime,
) -> bool {
    last_full_derivation.is_none_or(|last| {
        now.duration_since(last)
            .ok()
            .is_none_or(|elapsed| elapsed >= FULL_DERIVATION_INTERVAL)
    })
}

/// Rows at or below the remembered height are unchanged while the header stored at that block
/// still has the remembered hash, because a rewind at or below it deletes that header.
pub(super) fn chunk_reuse<'a>(
    remembered: Option<&'a RememberedDataset>,
    current: &LatestIndexedHeight,
    stored_hash_at_remembered: Option<[u8; 32]>,
) -> ChunkReuse<'a> {
    let Some(remembered) = remembered else {
        return ChunkReuse::DeriveAll;
    };
    let (block_number, block_hash) = remembered.height;
    if stored_hash_at_remembered != Some(block_hash.0) || current.block_number < block_number {
        ChunkReuse::DeriveAll
    } else if current.block_number > block_number {
        ChunkReuse::ReuseAllButLast(remembered)
    } else if current.block_hash == block_hash {
        ChunkReuse::ReuseAll(remembered)
    } else {
        ChunkReuse::DeriveAll
    }
}
