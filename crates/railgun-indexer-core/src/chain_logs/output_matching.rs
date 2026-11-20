#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) fn public_transactions_from_decoded(
    summary: &TransactOutputSummary,
    block_timestamp: u64,
    transactions: &[DecodedRailgunTransaction],
) -> Result<Vec<IndexedPublicTransaction>, ChainLogIngestionError> {
    let mut emitted_outputs = summary.output_commitments.clone();
    emitted_outputs.sort_by_key(|output| {
        comparable_global_tree_position(output.tree_number, output.tree_position)
    });
    let mut emitted_index = 0_usize;
    let mut used_nullifier_groups = HashSet::new();
    let has_legacy_output_events = emitted_outputs.iter().any(|output| {
        matches!(
            output.family,
            EmittedOutputFamily::LegacyEncrypted | EmittedOutputFamily::LegacyGenerated
        )
    });
    let mut relay_legacy_commitment_offset = 0_u64;
    let mut uses_non_sequential_output_mapping = false;
    let uses_legacy_segments = transactions.iter().any(|transaction| {
        transaction.call_kind == RailgunCallKind::LegacyTransact
            && !summary.nullifier_groups.is_empty()
    });
    let mut rows = Vec::with_capacity(transactions.len());
    for (transaction_index, transaction) in transactions.iter().enumerate() {
        let (output_match, row_first_log_index, row_last_log_index) = if transaction.call_kind
            == RailgunCallKind::LegacyTransact
        {
            if let Some(group_index) = legacy_nullifier_group_index(
                summary,
                transaction,
                transaction_index,
                &used_nullifier_groups,
            )? {
                used_nullifier_groups.insert(group_index);
                let candidates = legacy_output_candidates(&emitted_outputs, summary, group_index);
                let output_match = matched_legacy_output_start_global(
                    summary,
                    &candidates,
                    transaction,
                    transaction_index,
                )?;
                uses_non_sequential_output_mapping = true;
                let nullifier_log_index = summary.nullifier_groups[group_index].source.log_index;
                (
                    output_match,
                    nullifier_log_index,
                    nullifier_log_index.max(output_match.last_log_index),
                )
            } else {
                let output_match = matched_output_start_global(
                    summary,
                    &emitted_outputs,
                    &mut emitted_index,
                    transaction,
                    transaction_index,
                )?;
                (
                    output_match,
                    summary.first_log_index,
                    summary.last_log_index,
                )
            }
        } else if matches!(
            transaction.call_kind,
            RailgunCallKind::Relay | RailgunCallKind::LegacyRelay
        ) && has_legacy_output_events
        {
            let output_match = matched_relay_legacy_output_start_global(
                summary,
                &emitted_outputs,
                relay_legacy_commitment_offset,
                transaction_index,
            )?;
            let output_count = relay_legacy_output_count(transaction)?;
            relay_legacy_commitment_offset = relay_legacy_commitment_offset
                .checked_add(output_count)
                .ok_or(ChainLogIngestionError::IntegerOverflow(
                    "relay_legacy_commitment_offset",
                ))?;
            uses_non_sequential_output_mapping = true;
            (
                output_match,
                summary.first_log_index,
                summary.last_log_index,
            )
        } else {
            let output_match = matched_output_start_global(
                summary,
                &emitted_outputs,
                &mut emitted_index,
                transaction,
                transaction_index,
            )?;
            (
                output_match,
                summary.first_log_index,
                summary.last_log_index,
            )
        };
        let (utxo_tree_out, utxo_batch_start_position_out) =
            if emitted_outputs.is_empty() && is_modern_unshield_only(transaction) {
                (
                    MODERN_UNSHIELD_ONLY_UTXO_TREE,
                    MODERN_UNSHIELD_ONLY_UTXO_POSITION,
                )
            } else {
                let (utxo_tree_out, utxo_batch_start_position_out) =
                    normalized_global_position(output_match.output_start)?;
                (u64::from(utxo_tree_out), utxo_batch_start_position_out)
            };
        let row = IndexedPublicTransaction {
            source: summary.source.clone(),
            first_log_index: row_first_log_index,
            last_log_index: row_last_log_index,
            railgun_transaction_index: u64::try_from(transaction_index).map_err(|_| {
                ChainLogIngestionError::IntegerOverflow("railgun_transaction_index")
            })?,
            id: format!("{}:{transaction_index}", summary.source.transaction_hash),
            block_timestamp,
            nullifiers: transaction.nullifiers.clone(),
            commitments: transaction.commitments.clone(),
            bound_params_hash: transaction.bound_params_hash,
            has_unshield: transaction.has_unshield,
            unshield_preimage: transaction.unshield_preimage.clone(),
            utxo_tree_in: transaction.utxo_tree_in,
            utxo_tree_out,
            utxo_batch_start_position_out,
            railgun_txid: transaction.railgun_txid,
        };
        rows.push(row);
    }
    if !(uses_legacy_segments || uses_non_sequential_output_mapping)
        && emitted_index != emitted_outputs.len()
    {
        return Err(ChainLogIngestionError::UnmatchedEmittedOutputCommitments {
            transaction_hash: summary.source.transaction_hash,
            block_number: summary.source.block_number,
            consumed: emitted_index,
            emitted: emitted_outputs.len(),
        });
    }
    Ok(rows)
}

fn relay_legacy_output_count(
    transaction: &DecodedRailgunTransaction,
) -> Result<u64, ChainLogIngestionError> {
    let commitment_count = u64::try_from(transaction.commitments.len())
        .map_err(|_| ChainLogIngestionError::IntegerOverflow("commitment_count"))?;
    if !transaction.has_unshield {
        return Ok(commitment_count);
    }
    Ok(commitment_count.saturating_sub(1))
}

fn legacy_nullifier_group_index(
    summary: &TransactOutputSummary,
    transaction: &DecodedRailgunTransaction,
    transaction_index: usize,
    used_nullifier_groups: &HashSet<usize>,
) -> Result<Option<usize>, ChainLogIngestionError> {
    if summary.nullifier_groups.is_empty() {
        return Ok(None);
    }

    let matches = summary
        .nullifier_groups
        .iter()
        .enumerate()
        .filter(|(index, group)| {
            !used_nullifier_groups.contains(index) && group.nullifiers == transaction.nullifiers
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [index] => Ok(Some(*index)),
        [] => Err(ChainLogIngestionError::MissingTransactionNullifierGroup {
            transaction_hash: summary.source.transaction_hash,
            block_number: summary.source.block_number,
            railgun_transaction_index: transaction_index,
        }),
        _ => Err(ChainLogIngestionError::AmbiguousTransactionNullifierGroup {
            transaction_hash: summary.source.transaction_hash,
            block_number: summary.source.block_number,
            railgun_transaction_index: transaction_index,
            matches: matches.len(),
        }),
    }
}

fn legacy_output_candidates(
    emitted_outputs: &[EmittedOutputCommitment],
    summary: &TransactOutputSummary,
    group_index: usize,
) -> Vec<EmittedOutputCommitment> {
    let nullifier_log_index = summary.nullifier_groups[group_index].source.log_index;
    let next_nullifier_log_index = summary
        .nullifier_groups
        .get(group_index.saturating_add(1))
        .map(|group| group.source.log_index);
    let candidates = emitted_outputs
        .iter()
        .filter(|output| {
            output.log_index > nullifier_log_index
                && next_nullifier_log_index.is_none_or(|next| output.log_index < next)
        })
        .cloned()
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        emitted_outputs.to_vec()
    } else {
        candidates
    }
}

fn matched_legacy_output_start_global(
    summary: &TransactOutputSummary,
    emitted_outputs: &[EmittedOutputCommitment],
    transaction: &DecodedRailgunTransaction,
    transaction_index: usize,
) -> Result<OutputMatch, ChainLogIngestionError> {
    for start_index in 0..emitted_outputs.len() {
        let mut emitted_index = start_index;
        match matched_output_start_global(
            summary,
            emitted_outputs,
            &mut emitted_index,
            transaction,
            transaction_index,
        ) {
            Ok(output_match) => return Ok(output_match),
            Err(ChainLogIngestionError::UnmatchedTransactionOutputCommitments { .. }) => {}
            Err(error) => return Err(error),
        }
    }
    Err(
        ChainLogIngestionError::UnmatchedTransactionOutputCommitments {
            transaction_hash: summary.source.transaction_hash,
            block_number: summary.source.block_number,
            railgun_transaction_index: transaction_index,
        },
    )
}

fn matched_relay_legacy_output_start_global(
    summary: &TransactOutputSummary,
    emitted_outputs: &[EmittedOutputCommitment],
    prior_commitment_count: u64,
    transaction_index: usize,
) -> Result<OutputMatch, ChainLogIngestionError> {
    let mut first_generated_global = None;
    let mut first_encrypted_global = None;
    let mut last_log_index = summary.last_log_index;
    for output in emitted_outputs.iter().filter(|output| {
        matches!(
            output.family,
            EmittedOutputFamily::LegacyEncrypted | EmittedOutputFamily::LegacyGenerated
        )
    }) {
        let output_global = global_tree_position(output.tree_number, output.tree_position)?;
        match output.family {
            EmittedOutputFamily::LegacyGenerated if first_generated_global.is_none() => {
                first_generated_global = Some(output_global);
            }
            EmittedOutputFamily::LegacyEncrypted if first_encrypted_global.is_none() => {
                first_encrypted_global = Some(output_global);
            }
            _ => {}
        }
        last_log_index = last_log_index.max(output.log_index);
    }
    let Some(anchor_global) = first_generated_global.or(first_encrypted_global) else {
        return Err(
            ChainLogIngestionError::UnmatchedTransactionOutputCommitments {
                transaction_hash: summary.source.transaction_hash,
                block_number: summary.source.block_number,
                railgun_transaction_index: transaction_index,
            },
        );
    };
    let output_start = anchor_global.checked_add(prior_commitment_count).ok_or(
        ChainLogIngestionError::IntegerOverflow("relay_legacy_output_start"),
    )?;
    Ok(OutputMatch {
        output_start,
        last_log_index,
    })
}

fn matched_output_start_global(
    summary: &TransactOutputSummary,
    emitted_outputs: &[EmittedOutputCommitment],
    emitted_index: &mut usize,
    transaction: &DecodedRailgunTransaction,
    transaction_index: usize,
) -> Result<OutputMatch, ChainLogIngestionError> {
    let mut output_start = None;
    let mut last_log_index = None;
    for commitment in &transaction.commitments {
        let Some(emitted) = emitted_outputs.get(*emitted_index) else {
            break;
        };
        if emitted.hash == *commitment {
            if output_start.is_none() {
                output_start = Some(global_tree_position(
                    emitted.tree_number,
                    emitted.tree_position,
                )?);
            }
            last_log_index = Some(emitted.log_index);
            *emitted_index = (*emitted_index).saturating_add(1);
        }
    }
    if transaction.has_unshield
        && let Some(emitted) = emitted_outputs.get(*emitted_index)
        && emitted.family == EmittedOutputFamily::LegacyGenerated
    {
        *emitted_index = (*emitted_index).saturating_add(1);
        return Ok(OutputMatch {
            output_start: global_tree_position(emitted.tree_number, emitted.tree_position)?,
            last_log_index: emitted.log_index,
        });
    }
    if output_start.is_none() && is_modern_unshield_only(transaction) {
        return matched_modern_unshield_only_output_start_global(
            summary,
            emitted_outputs,
            *emitted_index,
            transaction_index,
        );
    }
    output_start
        .map(|output_start| OutputMatch {
            output_start,
            last_log_index: last_log_index.unwrap_or(summary.first_log_index),
        })
        .ok_or_else(
            || ChainLogIngestionError::UnmatchedTransactionOutputCommitments {
                transaction_hash: summary.source.transaction_hash,
                block_number: summary.source.block_number,
                railgun_transaction_index: transaction_index,
            },
        )
}

const fn is_modern_unshield_only(transaction: &DecodedRailgunTransaction) -> bool {
    transaction.has_unshield
        && transaction.commitments.len() == 1
        && matches!(
            transaction.call_kind,
            RailgunCallKind::Transact
                | RailgunCallKind::Relay
                | RailgunCallKind::Execute
                | RailgunCallKind::ActionLogs
        )
}

fn matched_modern_unshield_only_output_start_global(
    summary: &TransactOutputSummary,
    emitted_outputs: &[EmittedOutputCommitment],
    emitted_index: usize,
    transaction_index: usize,
) -> Result<OutputMatch, ChainLogIngestionError> {
    if let Some(emitted) = emitted_outputs.get(emitted_index) {
        return Ok(OutputMatch {
            output_start: global_tree_position(emitted.tree_number, emitted.tree_position)?,
            last_log_index: emitted.log_index,
        });
    }
    if emitted_outputs.is_empty() {
        return Ok(OutputMatch {
            output_start: 0,
            last_log_index: summary.first_log_index,
        });
    }
    let Some(previous) = emitted_index
        .checked_sub(1)
        .and_then(|index| emitted_outputs.get(index))
    else {
        return Err(
            ChainLogIngestionError::UnmatchedTransactionOutputCommitments {
                transaction_hash: summary.source.transaction_hash,
                block_number: summary.source.block_number,
                railgun_transaction_index: transaction_index,
            },
        );
    };
    let output_start = global_tree_position(previous.tree_number, previous.tree_position)?
        .checked_add(1)
        .ok_or(ChainLogIngestionError::IntegerOverflow(
            "modern_unshield_only_output_start",
        ))?;
    Ok(OutputMatch {
        output_start,
        last_log_index: previous.log_index,
    })
}
