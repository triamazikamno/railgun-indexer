#[allow(clippy::wildcard_imports)]
use super::*;

/// Builds public TXID rows, from logs at and after `action_start_block`.
///
/// There, unshield-bearing transactions also read calldata for the committed unshield commitment.
/// Earlier blocks use transaction calldata, then traces.
pub async fn hydrate_public_transactions<P: Provider + ?Sized>(
    provider: &P,
    railgun_contract: Address,
    action_start_block: Option<u64>,
    batch: &mut IndexedLogBatch,
) -> Result<(), ChainLogIngestionError> {
    let mut summaries: HashMap<FixedBytes<32>, TransactOutputSummary> = HashMap::new();
    let mut block_timestamps: HashMap<FixedBytes<32>, u64> = HashMap::new();
    let mut full_blocks: HashMap<FixedBytes<32>, FullBlockContext> = HashMap::new();
    let nullifier_groups = nullifier_groups_by_transaction(&batch.nullifiers);
    let nullifier_transaction_hashes = batch
        .nullifiers
        .iter()
        .map(|item| item.source.transaction_hash)
        .collect::<HashSet<_>>();
    for item in &batch.transact_commitments {
        record_public_transaction_summary(
            &mut summaries,
            &item.source,
            EmittedOutputFamily::Transact,
            item.tree_number,
            item.tree_position,
            item.hash,
        );
    }
    for item in &batch.legacy_encrypted_commitments {
        if !nullifier_transaction_hashes.contains(&item.source.transaction_hash) {
            continue;
        }
        record_public_transaction_summary(
            &mut summaries,
            &item.source,
            EmittedOutputFamily::LegacyEncrypted,
            item.tree_number,
            item.tree_position,
            item.hash,
        );
    }
    for item in &batch.legacy_generated_commitments {
        if !nullifier_transaction_hashes.contains(&item.source.transaction_hash) {
            continue;
        }
        record_public_transaction_summary(
            &mut summaries,
            &item.source,
            EmittedOutputFamily::LegacyGenerated,
            item.tree_number,
            item.tree_position,
            FixedBytes::from(item.preimage.hash().to_be_bytes::<32>()),
        );
    }
    for (transaction_hash, groups) in nullifier_groups {
        if let Some(summary) = summaries.get_mut(&transaction_hash) {
            for group in groups {
                summary.first_log_index = summary.first_log_index.min(group.source.log_index);
                summary.last_log_index = summary.last_log_index.max(group.source.log_index);
                summary.nullifier_groups.push(group);
            }
        } else if let Some(first_group) = groups.first() {
            let first_log_index = groups
                .iter()
                .map(|group| group.source.log_index)
                .min()
                .unwrap_or(first_group.source.log_index);
            let last_log_index = groups
                .iter()
                .map(|group| group.source.log_index)
                .max()
                .unwrap_or(first_group.source.log_index);
            summaries.insert(
                transaction_hash,
                TransactOutputSummary {
                    source: first_group.source.clone(),
                    first_log_index,
                    last_log_index,
                    output_commitments: Vec::new(),
                    nullifier_groups: groups,
                },
            );
        }
    }

    let mut action_log_events = action_start_block
        .map(|start| action_log_events_by_transaction(batch, start))
        .unwrap_or_default();
    for summary in summaries.values() {
        let transaction_hash = summary.source.transaction_hash;
        if action_start_block.is_some_and(|start| summary.source.block_number >= start) {
            let mut frames = decoded_transactions_from_action_logs(
                summary,
                action_log_events
                    .remove(&transaction_hash)
                    .unwrap_or_default(),
            )?;
            // No log carries the unshield commitment, so only unshield-bearing transactions read
            // calldata, and never traces.
            if frames
                .iter()
                .flat_map(|(_, transactions)| transactions)
                .any(|(_, transaction)| transaction.has_unshield)
            {
                let calldata = if let Some(tx) =
                    provider.get_transaction_by_hash(transaction_hash).await?
                {
                    tx.input().to_vec()
                } else {
                    full_block_context(provider, &mut full_blocks, &mut block_timestamps, summary)
                        .await?
                        .transaction_inputs
                        .get(&transaction_hash)
                        .cloned()
                        .ok_or(ChainLogIngestionError::MissingTransaction {
                            transaction_hash,
                            block_number: summary.source.block_number,
                            block_hash: summary.source.block_hash,
                            first_log_index: summary.first_log_index,
                            last_log_index: summary.last_log_index,
                        })?
                };
                let (log_derivations, divergences) =
                    resolve_unshield_commitments(summary, &calldata, &mut frames)?;
                batch.unshield_log_derivations += log_derivations;
                batch.unshield_log_divergences += divergences;
            }
            let block_timestamp = block_timestamp(provider, &mut block_timestamps, summary).await?;
            let mut rows = Vec::new();
            for (transact_log_index, frame_transactions) in frames {
                // Each call matches only its own Transact outputs, so a call without one gets the
                // unshield-only sentinel instead of a neighbouring call's position.
                let frame_summary = TransactOutputSummary {
                    source: summary.source.clone(),
                    first_log_index: summary.first_log_index,
                    last_log_index: summary.last_log_index,
                    output_commitments: summary
                        .output_commitments
                        .iter()
                        .filter(|output| Some(output.log_index) == transact_log_index)
                        .cloned()
                        .collect(),
                    nullifier_groups: Vec::new(),
                };
                let (record_indexes, transactions): (Vec<_>, Vec<_>) =
                    frame_transactions.into_iter().unzip();
                rows.extend(
                    public_transactions_from_decoded(
                        &frame_summary,
                        block_timestamp,
                        &transactions,
                    )?
                    .into_iter()
                    .zip(record_indexes),
                );
            }
            // Rows follow Action order, as the SDK and subgraph number them.
            rows.sort_by_key(|(_, record_index)| *record_index);
            for (railgun_transaction_index, (row, _)) in rows.iter_mut().enumerate() {
                row.railgun_transaction_index =
                    u64::try_from(railgun_transaction_index).map_err(|_| {
                        ChainLogIngestionError::IntegerOverflow("railgun_transaction_index")
                    })?;
                row.id = format!("{transaction_hash}:{railgun_transaction_index}");
            }
            batch
                .public_transactions
                .extend(rows.into_iter().map(|(row, _)| row));
            continue;
        }
        let tx = provider
            .get_transaction_by_hash(summary.source.transaction_hash)
            .await?;
        if let Some(tx) = tx {
            let block_timestamp = block_timestamp(provider, &mut block_timestamps, summary).await?;
            let rows = public_transactions_from_calldata_or_trace(
                provider,
                railgun_contract,
                summary,
                block_timestamp,
                tx.input(),
            )
            .await?;
            if rows.is_empty() {
                return Err(ChainLogIngestionError::MissingRailgunCalldata {
                    transaction_hash,
                    block_number: summary.source.block_number,
                    block_hash: summary.source.block_hash,
                    first_log_index: summary.first_log_index,
                    last_log_index: summary.last_log_index,
                });
            }
            batch.public_transactions.extend(rows);
        } else {
            let block_context =
                full_block_context(provider, &mut full_blocks, &mut block_timestamps, summary)
                    .await?;
            let calldata = block_context
                .transaction_inputs
                .get(&transaction_hash)
                .ok_or(ChainLogIngestionError::MissingTransaction {
                    transaction_hash,
                    block_number: summary.source.block_number,
                    block_hash: summary.source.block_hash,
                    first_log_index: summary.first_log_index,
                    last_log_index: summary.last_log_index,
                })?;
            let rows = public_transactions_from_calldata_or_trace(
                provider,
                railgun_contract,
                summary,
                block_context.timestamp,
                calldata,
            )
            .await?;
            if rows.is_empty() {
                return Err(ChainLogIngestionError::MissingRailgunCalldata {
                    transaction_hash,
                    block_number: summary.source.block_number,
                    block_hash: summary.source.block_hash,
                    first_log_index: summary.first_log_index,
                    last_log_index: summary.last_log_index,
                });
            }
            batch.public_transactions.extend(rows);
        }
    }

    batch.public_transactions.sort_by_key(|row| {
        (
            row.source.block_number,
            row.first_log_index,
            row.source.transaction_hash,
            row.railgun_transaction_index,
        )
    });
    Ok(())
}

pub async fn resolve_public_transactions_by_hash<P: Provider + ?Sized>(
    provider: &P,
    railgun_contract: Address,
    transaction_hash: FixedBytes<32>,
) -> Result<Vec<ResolvedPublicTransaction>, ChainLogIngestionError> {
    let transaction = provider
        .get_transaction_by_hash(transaction_hash)
        .await?
        .ok_or(ChainLogIngestionError::MissingTransactionByHash { transaction_hash })?;
    let mut decoded = decode_railgun_transactions(transaction.input())?.unwrap_or_default();
    if decoded.is_empty() {
        let summary = TransactOutputSummary {
            source: IndexedLogSource {
                block_number: 0,
                block_timestamp: None,
                block_hash: FixedBytes::ZERO,
                transaction_hash,
                log_index: 0,
            },
            first_log_index: 0,
            last_log_index: 0,
            output_commitments: Vec::new(),
            nullifier_groups: Vec::new(),
        };
        if let Ok(trace) = debug_trace_transaction(provider, &summary).await {
            collect_debug_trace_railgun_transactions(&trace, railgun_contract, &mut decoded)?;
        }
        if decoded.is_empty()
            && let Ok(trace) = trace_transaction(provider, &summary).await
        {
            collect_trace_transaction_railgun_transactions(&trace, railgun_contract, &mut decoded)?;
        }
    }
    if decoded.is_empty() {
        return Err(ChainLogIngestionError::MissingRailgunCalldataByHash { transaction_hash });
    }
    decoded
        .into_iter()
        .enumerate()
        .map(|(railgun_transaction_index, transaction)| {
            Ok(ResolvedPublicTransaction {
                railgun_transaction_index: u64::try_from(railgun_transaction_index).map_err(
                    |_| ChainLogIngestionError::IntegerOverflow("railgun_transaction_index"),
                )?,
                nullifiers: transaction.nullifiers,
                commitments: transaction.commitments,
                bound_params_hash: transaction.bound_params_hash,
                has_unshield: transaction.has_unshield,
                unshield_preimage: transaction.unshield_preimage,
                utxo_tree_in: transaction.utxo_tree_in,
            })
        })
        .collect()
}

fn record_public_transaction_summary(
    summaries: &mut HashMap<FixedBytes<32>, TransactOutputSummary>,
    source: &IndexedLogSource,
    family: EmittedOutputFamily,
    tree_number: u32,
    tree_position: u64,
    hash: FixedBytes<32>,
) {
    summaries
        .entry(source.transaction_hash)
        .and_modify(|summary| {
            summary.first_log_index = summary.first_log_index.min(source.log_index);
            summary.last_log_index = summary.last_log_index.max(source.log_index);
            summary.output_commitments.push(EmittedOutputCommitment {
                family,
                log_index: source.log_index,
                tree_number,
                tree_position,
                hash,
            });
        })
        .or_insert_with(|| TransactOutputSummary {
            source: source.clone(),
            first_log_index: source.log_index,
            last_log_index: source.log_index,
            output_commitments: vec![EmittedOutputCommitment {
                family,
                log_index: source.log_index,
                tree_number,
                tree_position,
                hash,
            }],
            nullifier_groups: Vec::new(),
        });
}

fn nullifier_groups_by_transaction(
    nullifiers: &[IndexedNullifier],
) -> HashMap<FixedBytes<32>, Vec<NullifierGroup>> {
    let mut grouped: HashMap<(FixedBytes<32>, u64), NullifierGroup> = HashMap::new();
    for item in nullifiers {
        grouped
            .entry((item.source.transaction_hash, item.source.log_index))
            .and_modify(|group| group.nullifiers.push(item.nullifier))
            .or_insert_with(|| NullifierGroup {
                source: item.source.clone(),
                nullifiers: vec![item.nullifier],
            });
    }

    let mut by_transaction = HashMap::<FixedBytes<32>, Vec<NullifierGroup>>::new();
    for group in grouped.into_values() {
        by_transaction
            .entry(group.source.transaction_hash)
            .or_default()
            .push(group);
    }
    for groups in by_transaction.values_mut() {
        groups.sort_by_key(|group| group.source.log_index);
    }
    by_transaction
}
