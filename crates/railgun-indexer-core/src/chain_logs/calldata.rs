#[allow(clippy::wildcard_imports)]
use super::*;

fn public_transactions_from_calldata(
    summary: &TransactOutputSummary,
    block_timestamp: u64,
    calldata: &[u8],
) -> Result<Vec<IndexedPublicTransaction>, ChainLogIngestionError> {
    let Some(transactions) = decode_railgun_transactions(calldata)? else {
        return Ok(Vec::new());
    };
    public_transactions_from_decoded(summary, block_timestamp, &transactions)
}

pub(super) async fn public_transactions_from_calldata_or_trace<P: Provider + ?Sized>(
    provider: &P,
    railgun_contract: Address,
    summary: &TransactOutputSummary,
    block_timestamp: u64,
    calldata: &[u8],
) -> Result<Vec<IndexedPublicTransaction>, ChainLogIngestionError> {
    match public_transactions_from_calldata(summary, block_timestamp, calldata) {
        Ok(rows) if !rows.is_empty() => Ok(rows),
        Ok(_) | Err(ChainLogIngestionError::UnmatchedEmittedOutputCommitments { .. }) => {
            public_transactions_from_trace(provider, railgun_contract, summary, block_timestamp)
                .await
        }
        Err(error) => Err(error),
    }
}

async fn public_transactions_from_trace<P: Provider + ?Sized>(
    provider: &P,
    railgun_contract: Address,
    summary: &TransactOutputSummary,
    block_timestamp: u64,
) -> Result<Vec<IndexedPublicTransaction>, ChainLogIngestionError> {
    let mut decoded = Vec::new();
    if let Ok(trace) = debug_trace_transaction(provider, summary).await {
        collect_debug_trace_railgun_transactions(&trace, railgun_contract, &mut decoded)?;
    }
    if decoded.is_empty()
        && let Ok(trace) = trace_transaction(provider, summary).await
    {
        collect_trace_transaction_railgun_transactions(&trace, railgun_contract, &mut decoded)?;
    }
    public_transactions_from_decoded(summary, block_timestamp, &decoded)
}

pub(super) async fn debug_trace_transaction<P: Provider + ?Sized>(
    provider: &P,
    summary: &TransactOutputSummary,
) -> Result<Value, TransportError> {
    provider
        .client()
        .request(
            "debug_traceTransaction",
            (
                summary.source.transaction_hash,
                serde_json::json!({
                    "tracer": "callTracer",
                    "timeout": "30s",
                }),
            ),
        )
        .await
}

pub(super) async fn trace_transaction<P: Provider + ?Sized>(
    provider: &P,
    summary: &TransactOutputSummary,
) -> Result<Value, TransportError> {
    provider
        .client()
        .request("trace_transaction", (summary.source.transaction_hash,))
        .await
}

pub(super) fn collect_debug_trace_railgun_transactions(
    frame: &Value,
    railgun_contract: Address,
    decoded: &mut Vec<DecodedRailgunTransaction>,
) -> Result<(), ChainLogIngestionError> {
    if frame.get("error").is_some_and(|error| !error.is_null()) {
        return Ok(());
    }
    if trace_frame_targets_contract(frame, railgun_contract)
        && let Some(input) = trace_input(frame)
        && let Some(mut transactions) = decode_railgun_transactions(&input)?
    {
        decoded.append(&mut transactions);
    }
    if let Some(calls) = frame.get("calls").and_then(Value::as_array) {
        for call in calls {
            collect_debug_trace_railgun_transactions(call, railgun_contract, decoded)?;
        }
    }
    Ok(())
}

pub(super) fn collect_trace_transaction_railgun_transactions(
    trace: &Value,
    railgun_contract: Address,
    decoded: &mut Vec<DecodedRailgunTransaction>,
) -> Result<(), ChainLogIngestionError> {
    let Some(frames) = trace.as_array() else {
        return Ok(());
    };
    // Reverted ancestors may appear after their children in a flat trace.
    let failed_paths = frames
        .iter()
        .filter(|frame| frame.get("error").is_some_and(|error| !error.is_null()))
        .filter_map(|frame| frame.get("traceAddress").and_then(Value::as_array))
        .collect::<Vec<_>>();
    for frame in frames {
        if frame.get("error").is_some_and(|error| !error.is_null())
            || frame
                .get("traceAddress")
                .and_then(Value::as_array)
                .is_some_and(|path| {
                    failed_paths
                        .iter()
                        .any(|failed_path| path.starts_with(failed_path))
                })
        {
            continue;
        }
        let action = frame.get("action").unwrap_or(frame);
        if trace_frame_targets_contract(action, railgun_contract)
            && let Some(input) = trace_input(action)
            && let Some(mut transactions) = decode_railgun_transactions(&input)?
        {
            decoded.append(&mut transactions);
        }
    }
    Ok(())
}

fn trace_frame_targets_contract(frame: &Value, railgun_contract: Address) -> bool {
    frame
        .get("to")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<Address>().ok())
        .is_some_and(|address| address == railgun_contract)
}

fn trace_input(frame: &Value) -> Option<Vec<u8>> {
    frame
        .get("input")
        .or_else(|| frame.get("data"))
        .and_then(Value::as_str)
        .and_then(decode_hex_bytes)
}

pub(super) fn decode_railgun_transactions(
    calldata: &[u8],
) -> Result<Option<Vec<DecodedRailgunTransaction>>, ChainLogIngestionError> {
    if let Ok(call) = transactCall::abi_decode(calldata) {
        return call
            ._transactions
            .into_iter()
            .map(|transaction| try_from_modern_transaction(transaction, RailgunCallKind::Transact))
            .collect::<Result<Vec<_>, _>>()
            .map(Some);
    }
    if let Ok(call) = relayCall::abi_decode(calldata) {
        return call
            ._transactions
            .into_iter()
            .map(|transaction| try_from_modern_transaction(transaction, RailgunCallKind::Relay))
            .collect::<Result<Vec<_>, _>>()
            .map(Some);
    }
    if let Ok(call) = legacy::relayCall::abi_decode(calldata) {
        let transactions = call
            ._transactions
            .into_iter()
            .map(try_from_legacy_relay_transaction)
            .collect::<Vec<_>>();
        return Ok(Some(transactions));
    }
    if let Ok(call) = executeCall::abi_decode(calldata) {
        return call
            ._transactions
            .into_iter()
            .map(|transaction| try_from_modern_transaction(transaction, RailgunCallKind::Execute))
            .collect::<Result<Vec<_>, _>>()
            .map(Some);
    }
    if let Ok(call) = legacy::transactCall::abi_decode(calldata) {
        let transactions = call
            ._transactions
            .into_iter()
            .map(try_from_legacy_transaction)
            .collect::<Vec<_>>();
        return Ok(Some(transactions));
    }
    Ok(None)
}

fn try_from_modern_transaction(
    transaction: Transaction,
    call_kind: RailgunCallKind,
) -> Result<DecodedRailgunTransaction, ChainLogIngestionError> {
    let railgun_txid = compute_railgun_txid(&transaction, Some(DEFAULT_TXID_VERSION))?;
    let has_unshield = transaction.boundParams.unshield != 0;
    let unshield_preimage = has_unshield.then(|| transaction.unshieldPreimage.abi_encode());
    Ok(DecodedRailgunTransaction {
        call_kind,
        nullifiers: transaction.nullifiers,
        commitments: transaction.commitments,
        bound_params_hash: transaction.boundParams.hash().into(),
        has_unshield,
        unshield_preimage,
        utxo_tree_in: transaction.boundParams.treeNumber.into(),
        railgun_txid,
    })
}

fn try_from_legacy_relay_transaction(
    transaction: legacy::LegacyTransaction,
) -> DecodedRailgunTransaction {
    try_from_legacy_transaction_with_kind(transaction, RailgunCallKind::LegacyRelay)
}

fn try_from_legacy_transaction(
    transaction: legacy::LegacyTransaction,
) -> DecodedRailgunTransaction {
    try_from_legacy_transaction_with_kind(transaction, RailgunCallKind::LegacyTransact)
}

fn try_from_legacy_transaction_with_kind(
    transaction: legacy::LegacyTransaction,
    call_kind: RailgunCallKind,
) -> DecodedRailgunTransaction {
    let bound_params_hash = legacy_bound_params_hash(&transaction.boundParams);
    let nullifiers = transaction
        .nullifiers
        .into_iter()
        .map(fixed_bytes_from_u256)
        .collect::<Vec<_>>();
    let commitments = transaction
        .commitments
        .into_iter()
        .map(fixed_bytes_from_u256)
        .collect::<Vec<_>>();
    let railgun_txid = compute_railgun_txid_parts(
        &nullifiers
            .iter()
            .map(|value| U256::from_be_bytes(value.0))
            .collect::<Vec<_>>(),
        &commitments
            .iter()
            .map(|value| U256::from_be_bytes(value.0))
            .collect::<Vec<_>>(),
        U256::from_be_bytes(bound_params_hash.0),
    );
    let has_unshield = transaction.boundParams.withdraw != 0;
    let unshield_preimage = has_unshield.then(|| {
        CommitmentPreimage {
            npk: FixedBytes::from(transaction.unshieldPreimage.npk.to_be_bytes::<32>()),
            token: broadcaster_core::contracts::railgun::TokenData {
                tokenType: transaction.unshieldPreimage.token.tokenType,
                tokenAddress: transaction.unshieldPreimage.token.tokenAddress,
                tokenSubID: transaction.unshieldPreimage.token.tokenSubID,
            },
            value: transaction.unshieldPreimage.value,
        }
        .abi_encode()
    });
    DecodedRailgunTransaction {
        call_kind,
        nullifiers,
        commitments,
        bound_params_hash,
        has_unshield,
        unshield_preimage,
        utxo_tree_in: u64::from(transaction.boundParams.treeNumber),
        railgun_txid,
    }
}

fn legacy_bound_params_hash(bound_params: &legacy::LegacyBoundParams) -> FixedBytes<32> {
    FixedBytes::from(hash_to_scalar(bound_params.abi_encode()).to_be_bytes::<32>())
}

pub(super) fn fixed_bytes_from_u256(value: U256) -> FixedBytes<32> {
    FixedBytes::from(value.to_be_bytes::<32>())
}
