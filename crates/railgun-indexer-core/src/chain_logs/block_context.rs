#[allow(clippy::wildcard_imports)]
use super::*;

pub async fn hydrate_indexed_log_source_timestamps<P: Provider + ?Sized>(
    provider: &P,
    batch: &mut IndexedLogBatch,
) -> Result<(), ChainLogIngestionError> {
    let mut seen = HashSet::new();
    let mut missing_blocks = Vec::new();
    collect_missing_timestamp_blocks(
        batch.transact_commitments.iter().map(|item| &item.source),
        &mut seen,
        &mut missing_blocks,
    );
    collect_missing_timestamp_blocks(
        batch.shield_commitments.iter().map(|item| &item.source),
        &mut seen,
        &mut missing_blocks,
    );
    collect_missing_timestamp_blocks(
        batch.nullifiers.iter().map(|item| &item.source),
        &mut seen,
        &mut missing_blocks,
    );
    collect_missing_timestamp_blocks(
        batch
            .legacy_encrypted_commitments
            .iter()
            .map(|item| &item.source),
        &mut seen,
        &mut missing_blocks,
    );
    collect_missing_timestamp_blocks(
        batch
            .legacy_generated_commitments
            .iter()
            .map(|item| &item.source),
        &mut seen,
        &mut missing_blocks,
    );

    let mut timestamps = HashMap::new();
    for (block_hash, block_number) in missing_blocks {
        let timestamp = block_timestamp_for_source(provider, block_hash, block_number).await?;
        timestamps.insert(block_hash, timestamp);
    }

    set_source_timestamps(
        batch
            .transact_commitments
            .iter_mut()
            .map(|item| &mut item.source),
        &timestamps,
    );
    set_source_timestamps(
        batch
            .shield_commitments
            .iter_mut()
            .map(|item| &mut item.source),
        &timestamps,
    );
    set_source_timestamps(
        batch.nullifiers.iter_mut().map(|item| &mut item.source),
        &timestamps,
    );
    set_source_timestamps(
        batch
            .legacy_encrypted_commitments
            .iter_mut()
            .map(|item| &mut item.source),
        &timestamps,
    );
    set_source_timestamps(
        batch
            .legacy_generated_commitments
            .iter_mut()
            .map(|item| &mut item.source),
        &timestamps,
    );

    Ok(())
}

fn collect_missing_timestamp_blocks<'a>(
    sources: impl Iterator<Item = &'a IndexedLogSource>,
    seen: &mut HashSet<FixedBytes<32>>,
    missing_blocks: &mut Vec<(FixedBytes<32>, u64)>,
) {
    for source in sources {
        if source.block_timestamp.is_none() && seen.insert(source.block_hash) {
            missing_blocks.push((source.block_hash, source.block_number));
        }
    }
}

fn set_source_timestamps<'a>(
    sources: impl Iterator<Item = &'a mut IndexedLogSource>,
    timestamps: &HashMap<FixedBytes<32>, u64>,
) {
    for source in sources {
        if source.block_timestamp.is_none()
            && let Some(timestamp) = timestamps.get(&source.block_hash)
        {
            source.block_timestamp = Some(*timestamp);
        }
    }
}

pub(super) async fn block_timestamp<P: Provider + ?Sized>(
    provider: &P,
    block_timestamps: &mut HashMap<FixedBytes<32>, u64>,
    summary: &TransactOutputSummary,
) -> Result<u64, ChainLogIngestionError> {
    if let Some(timestamp) = summary.source.block_timestamp {
        return Ok(timestamp);
    }
    if let Some(timestamp) = block_timestamps.get(&summary.source.block_hash) {
        return Ok(*timestamp);
    }

    let timestamp = block_timestamp_for_source(
        provider,
        summary.source.block_hash,
        summary.source.block_number,
    )
    .await?;
    block_timestamps.insert(summary.source.block_hash, timestamp);
    Ok(timestamp)
}

pub async fn block_timestamp_for_source<P: Provider + ?Sized>(
    provider: &P,
    block_hash: FixedBytes<32>,
    block_number: u64,
) -> Result<u64, ChainLogIngestionError> {
    let block = provider.get_block_by_hash(block_hash).await?.ok_or(
        ChainLogIngestionError::MissingBlock {
            block_number,
            block_hash,
        },
    )?;
    validate_source_block_metadata(
        block_number,
        block_hash,
        block.header.hash,
        block.header.number,
    )?;
    Ok(block.header.timestamp)
}

pub(super) async fn full_block_context<'a, P: Provider + ?Sized>(
    provider: &P,
    full_blocks: &'a mut HashMap<FixedBytes<32>, FullBlockContext>,
    block_timestamps: &mut HashMap<FixedBytes<32>, u64>,
    summary: &TransactOutputSummary,
) -> Result<&'a FullBlockContext, ChainLogIngestionError> {
    if full_blocks.contains_key(&summary.source.block_hash) {
        return Ok(full_blocks
            .get(&summary.source.block_hash)
            .expect("full block context exists"));
    }

    let block: Option<Value> = provider
        .client()
        .request("eth_getBlockByHash", (summary.source.block_hash, true))
        .await?;
    let block = block.ok_or(ChainLogIngestionError::MissingBlock {
        block_number: summary.source.block_number,
        block_hash: summary.source.block_hash,
    })?;
    let actual_block_hash = json_fixed_bytes_field(&block, "hash", summary)?;
    let actual_block_number = json_quantity_u64_field(&block, "number", summary)?;
    validate_source_block_metadata(
        summary.source.block_number,
        summary.source.block_hash,
        actual_block_hash,
        actual_block_number,
    )?;
    let timestamp = json_quantity_u64_field(&block, "timestamp", summary)?;
    let transaction_inputs = raw_block_transaction_inputs(&block, summary)?;
    block_timestamps.insert(summary.source.block_hash, timestamp);
    full_blocks.insert(
        summary.source.block_hash,
        FullBlockContext {
            timestamp,
            transaction_inputs,
        },
    );

    Ok(full_blocks
        .get(&summary.source.block_hash)
        .expect("full block context was inserted"))
}

fn raw_block_transaction_inputs(
    block: &Value,
    summary: &TransactOutputSummary,
) -> Result<HashMap<FixedBytes<32>, Vec<u8>>, ChainLogIngestionError> {
    let transactions = block.get("transactions").and_then(Value::as_array).ok_or(
        ChainLogIngestionError::MissingFullBlockTransactions {
            block_number: summary.source.block_number,
            block_hash: summary.source.block_hash,
        },
    )?;

    let mut transaction_inputs = HashMap::new();
    for transaction in transactions {
        let Some(transaction_hash) = transaction
            .get("hash")
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<FixedBytes<32>>().ok())
        else {
            continue;
        };
        let Some(input) = transaction.get("input").and_then(Value::as_str) else {
            continue;
        };
        let Some(input) = decode_hex_bytes(input) else {
            continue;
        };
        transaction_inputs.insert(transaction_hash, input);
    }

    Ok(transaction_inputs)
}

fn json_fixed_bytes_field(
    block: &Value,
    field: &'static str,
    summary: &TransactOutputSummary,
) -> Result<FixedBytes<32>, ChainLogIngestionError> {
    block
        .get(field)
        .and_then(Value::as_str)
        .and_then(|value| value.parse().ok())
        .ok_or(ChainLogIngestionError::InvalidBlockField {
            block_number: summary.source.block_number,
            block_hash: summary.source.block_hash,
            field,
        })
}

fn json_quantity_u64_field(
    block: &Value,
    field: &'static str,
    summary: &TransactOutputSummary,
) -> Result<u64, ChainLogIngestionError> {
    block
        .get(field)
        .and_then(Value::as_str)
        .and_then(parse_hex_quantity_u64)
        .ok_or(ChainLogIngestionError::InvalidBlockField {
            block_number: summary.source.block_number,
            block_hash: summary.source.block_hash,
            field,
        })
}

fn parse_hex_quantity_u64(value: &str) -> Option<u64> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(value, 16).ok()
}

pub(super) fn decode_hex_bytes(value: &str) -> Option<Vec<u8>> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value)).ok()
}

fn validate_source_block_metadata(
    expected_block_number: u64,
    expected_block_hash: FixedBytes<32>,
    actual_block_hash: FixedBytes<32>,
    actual_block_number: u64,
) -> Result<(), ChainLogIngestionError> {
    if actual_block_hash != expected_block_hash || actual_block_number != expected_block_number {
        return Err(ChainLogIngestionError::MismatchedBlock {
            expected_block_number,
            expected_block_hash,
            actual_block_number,
            actual_block_hash,
        });
    }
    Ok(())
}
