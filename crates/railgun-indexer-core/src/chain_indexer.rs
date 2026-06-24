use crate::chain_logs::{
    ChainLogIngestionError, fetch_chain_index_logs, hydrate_indexed_log_source_timestamps,
    hydrate_public_transactions, ingest_chain_logs,
};
use crate::store::{IndexedDatasetKind, Store, StoreError};
use alloy::primitives::{Address, FixedBytes};
use alloy::providers::Provider;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct ChainLogIndexingRange {
    pub chain_type: u8,
    pub chain_id: u64,
    pub railgun_contract: Address,
    pub from_block: u64,
    pub to_block: u64,
    pub indexed_through_block_hash: FixedBytes<32>,
    pub indexed_block_headers: Vec<ChainIndexedBlockHeader>,
    pub v2_start_block: u64,
    pub legacy_shield_block: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainIndexedBlockHeader {
    pub block_number: u64,
    pub block_hash: FixedBytes<32>,
    pub parent_hash: FixedBytes<32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainLogIndexingOutcome {
    pub from_block: u64,
    pub to_block: u64,
    pub fetched_log_count: usize,
    pub persisted_row_count: usize,
}

pub async fn index_chain_log_range<P: Provider + ?Sized>(
    store: &Store,
    provider: &P,
    range: ChainLogIndexingRange,
) -> Result<ChainLogIndexingOutcome, ChainIndexingError> {
    let logs = fetch_chain_index_logs(
        provider,
        range.railgun_contract,
        range.from_block,
        range.to_block,
        range.v2_start_block,
        range.legacy_shield_block,
    )
    .await?;
    let fetched_log_count = logs.len();
    let mut batch = ingest_chain_logs(&logs)?;
    hydrate_indexed_log_source_timestamps(provider, &mut batch).await?;
    hydrate_public_transactions(provider, range.railgun_contract, &mut batch).await?;
    let persisted_row_count = batch.transact_commitments.len()
        + batch.shield_commitments.len()
        + batch.nullifiers.len()
        + batch.legacy_encrypted_commitments.len()
        + batch.legacy_generated_commitments.len()
        + batch.public_transactions.len();

    let mut tx = store.begin().await?;
    Store::persist_indexed_log_batch(
        &mut tx,
        range.chain_type,
        range.chain_id,
        range.railgun_contract,
        &batch,
    )
    .await?;
    for header in &range.indexed_block_headers {
        Store::record_indexed_block_header(
            &mut tx,
            range.chain_type,
            range.chain_id,
            header.block_number,
            header.block_hash.as_slice(),
            header.parent_hash.as_slice(),
        )
        .await?;
    }
    for dataset_kind in IndexedDatasetKind::ALL {
        Store::record_chain_indexing_progress(
            &mut tx,
            range.chain_type,
            range.chain_id,
            range.railgun_contract,
            dataset_kind,
            range.to_block,
            range.indexed_through_block_hash.as_slice(),
        )
        .await?;
    }
    tx.commit().await.map_err(StoreError::Sqlx)?;

    Ok(ChainLogIndexingOutcome {
        from_block: range.from_block,
        to_block: range.to_block,
        fetched_log_count,
        persisted_row_count,
    })
}

#[derive(Debug, Error)]
pub enum ChainIndexingError {
    #[error("chain log ingestion failed")]
    ChainLogs(#[from] ChainLogIngestionError),
    #[error("store operation failed")]
    Store(#[from] StoreError),
}
