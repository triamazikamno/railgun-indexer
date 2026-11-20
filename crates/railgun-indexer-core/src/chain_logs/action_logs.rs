#[allow(clippy::wildcard_imports)]
use super::*;

/// One Railgun log of an outer transaction, as read by the `Action` path.
pub(super) enum ActionLogEvent {
    Nullified {
        tree_number: u32,
        nullifiers: Vec<FixedBytes<32>>,
    },
    Action(Vec<TXConfig>),
    Unshield(Unshield),
    Transact(Vec<FixedBytes<32>>),
}

/// An open Railgun call and the logs gathered for it so far.
struct ActionFrame {
    log_index: u64,
    /// Record index of the first configuration, counted in `Action` order across calls.
    record_base: usize,
    configs: Vec<TXConfig>,
    nullified: Vec<(u32, Vec<FixedBytes<32>>)>,
    unshields: Vec<Unshield>,
    expects_transact: bool,
}

impl ActionFrame {
    fn pending_unshields(&self) -> usize {
        self.configs
            .iter()
            .filter(|config| config.hasUnshield)
            .count()
            .saturating_sub(self.unshields.len())
    }
}

pub(super) fn action_log_events_by_transaction(
    batch: &IndexedLogBatch,
    action_start_block: u64,
) -> HashMap<FixedBytes<32>, BTreeMap<u64, ActionLogEvent>> {
    let mut events = HashMap::<FixedBytes<32>, BTreeMap<u64, ActionLogEvent>>::new();
    let is_active = |source: &IndexedLogSource| source.block_number >= action_start_block;
    for item in batch
        .nullifiers
        .iter()
        .filter(|item| is_active(&item.source))
    {
        if let ActionLogEvent::Nullified { nullifiers, .. } = events
            .entry(item.source.transaction_hash)
            .or_default()
            .entry(item.source.log_index)
            .or_insert_with(|| ActionLogEvent::Nullified {
                tree_number: item.tree_number,
                nullifiers: Vec::new(),
            })
        {
            nullifiers.push(item.nullifier);
        }
    }
    for item in batch
        .transact_commitments
        .iter()
        .filter(|item| is_active(&item.source))
    {
        if let ActionLogEvent::Transact(hashes) = events
            .entry(item.source.transaction_hash)
            .or_default()
            .entry(item.source.log_index)
            .or_insert_with(|| ActionLogEvent::Transact(Vec::new()))
        {
            hashes.push(item.hash);
        }
    }
    for item in batch.actions.iter().filter(|item| is_active(&item.source)) {
        events
            .entry(item.source.transaction_hash)
            .or_default()
            .insert(
                item.source.log_index,
                ActionLogEvent::Action(item.txconfigs.clone()),
            );
    }
    for item in batch
        .unshields
        .iter()
        .filter(|item| is_active(&item.source))
    {
        events
            .entry(item.source.transaction_hash)
            .or_default()
            .insert(
                item.source.log_index,
                ActionLogEvent::Unshield(item.unshield.clone()),
            );
    }
    events
}

/// One Railgun call's `Transact` log index, if any, and its transactions with record indexes.
type ActionCallTransactions = (Option<u64>, Vec<(usize, DecodedRailgunTransaction)>);

/// Rebuilds an outer transaction's Railgun transactions from its logs.
///
/// Each Railgun call emits `Nullified…, Action, (Unshield | nested call)*, Transact?`, and a nested
/// call completes before its parent resumes. Transactions are grouped per call in completion order,
/// each group with the log index of the call's `Transact`, or `None` for a call that emitted none;
/// output matching runs per group against that log's commitments. Each transaction carries its
/// record index in `Action` order, which the caller uses to reorder the resulting rows.
pub(super) fn decoded_transactions_from_action_logs(
    summary: &TransactOutputSummary,
    events: BTreeMap<u64, ActionLogEvent>,
) -> Result<Vec<ActionCallTransactions>, ChainLogIngestionError> {
    let transaction_hash = summary.source.transaction_hash;
    let block_number = summary.source.block_number;
    let mut pending_nullified: Vec<(u64, u32, Vec<FixedBytes<32>>)> = Vec::new();
    let mut frames: Vec<ActionFrame> = Vec::new();
    let mut next_record_index = 0_usize;
    let mut decoded = Vec::new();
    for (log_index, event) in events {
        match event {
            ActionLogEvent::Nullified {
                tree_number,
                nullifiers,
            } => pending_nullified.push((log_index, tree_number, nullifiers)),
            ActionLogEvent::Action(configs) => {
                let counts_match = pending_nullified.len() == configs.len()
                    && pending_nullified.iter().zip(&configs).all(
                        |((_, _, nullifiers), config)| {
                            usize::try_from(config.nullifiersCount)
                                .is_ok_and(|count| count == nullifiers.len())
                        },
                    );
                if !counts_match {
                    return Err(ChainLogIngestionError::ActionNullifierCountMismatch {
                        transaction_hash,
                        block_number,
                        log_index,
                    });
                }
                // A shield emits an Action with no configurations and produces no row.
                if !configs.is_empty() {
                    let record_base = next_record_index;
                    next_record_index += configs.len();
                    frames.push(ActionFrame {
                        log_index,
                        record_base,
                        expects_transact: configs.iter().any(|config| config.commitmentsCount > 0),
                        configs,
                        nullified: std::mem::take(&mut pending_nullified)
                            .into_iter()
                            .map(|(_, tree_number, nullifiers)| (tree_number, nullifiers))
                            .collect(),
                        unshields: Vec::new(),
                    });
                }
            }
            ActionLogEvent::Unshield(unshield) => {
                let Some(frame) = frames
                    .last_mut()
                    .filter(|frame| frame.pending_unshields() > 0)
                else {
                    return Err(ChainLogIngestionError::UnmatchedActionLog {
                        transaction_hash,
                        block_number,
                        log_index,
                    });
                };
                frame.unshields.push(unshield);
            }
            ActionLogEvent::Transact(hashes) => {
                let Some(frame) = frames.pop().filter(|frame| frame.expects_transact) else {
                    return Err(ChainLogIngestionError::UnmatchedActionLog {
                        transaction_hash,
                        block_number,
                        log_index,
                    });
                };
                decoded.push((
                    Some(log_index),
                    transactions_from_action_frame(summary, frame, &hashes, log_index)?,
                ));
            }
        }
        // A call without commitments emits no Transact and completes at its last Unshield.
        if frames
            .last()
            .is_some_and(|frame| !frame.expects_transact && frame.pending_unshields() == 0)
            && let Some(frame) = frames.pop()
        {
            let log_index = frame.log_index;
            decoded.push((
                None,
                transactions_from_action_frame(summary, frame, &[], log_index)?,
            ));
        }
    }
    if let Some((log_index, ..)) = pending_nullified.first() {
        return Err(ChainLogIngestionError::ActionNullifierCountMismatch {
            transaction_hash,
            block_number,
            log_index: *log_index,
        });
    }
    if let Some(frame) = frames.last() {
        return Err(if frame.pending_unshields() > 0 {
            ChainLogIngestionError::MissingActionUnshield {
                transaction_hash,
                block_number,
                log_index: frame.log_index,
            }
        } else {
            ChainLogIngestionError::ActionCommitmentCountMismatch {
                transaction_hash,
                block_number,
                log_index: frame.log_index,
            }
        });
    }
    Ok(decoded)
}

/// Splits one Railgun call's logs into one transaction per configuration.
fn transactions_from_action_frame(
    summary: &TransactOutputSummary,
    frame: ActionFrame,
    hashes: &[FixedBytes<32>],
    log_index: u64,
) -> Result<Vec<(usize, DecodedRailgunTransaction)>, ChainLogIngestionError> {
    let transaction_hash = summary.source.transaction_hash;
    let block_number = summary.source.block_number;
    let commitment_count_mismatch = || ChainLogIngestionError::ActionCommitmentCountMismatch {
        transaction_hash,
        block_number,
        log_index,
    };
    if frame.pending_unshields() > 0 {
        return Err(ChainLogIngestionError::MissingActionUnshield {
            transaction_hash,
            block_number,
            log_index: frame.log_index,
        });
    }
    let mut offset = 0_usize;
    let mut unshields = frame.unshields.into_iter();
    let mut transactions = Vec::with_capacity(frame.configs.len());
    for (config_index, (config, (tree_number, nullifiers))) in
        frame.configs.into_iter().zip(frame.nullified).enumerate()
    {
        let end = usize::try_from(config.commitmentsCount)
            .ok()
            .and_then(|count| offset.checked_add(count))
            .ok_or(ChainLogIngestionError::IntegerOverflow(
                "action_commitment_offset",
            ))?;
        let mut commitments = hashes
            .get(offset..end)
            .ok_or_else(commitment_count_mismatch)?
            .to_vec();
        offset = end;
        let unshield_preimage = if config.hasUnshield {
            let unshield =
                unshields
                    .next()
                    .ok_or(ChainLogIngestionError::MissingActionUnshield {
                        transaction_hash,
                        block_number,
                        log_index: frame.log_index,
                    })?;
            let (commitment, preimage) = unshield_commitment_from_event(&unshield)?;
            commitments.push(commitment);
            Some(preimage.abi_encode())
        } else {
            None
        };
        let railgun_txid =
            railgun_txid_from_parts(&nullifiers, &commitments, config.boundParamsHash);
        transactions.push((
            frame.record_base + config_index,
            DecodedRailgunTransaction {
                call_kind: RailgunCallKind::ActionLogs,
                nullifiers,
                commitments,
                bound_params_hash: config.boundParamsHash,
                has_unshield: config.hasUnshield,
                unshield_preimage,
                utxo_tree_in: u64::from(tree_number),
                railgun_txid,
            },
        ));
    }
    if offset != hashes.len() {
        return Err(commitment_count_mismatch());
    }
    Ok(transactions)
}

/// Derives an unshield commitment and preimage from its `Unshield` log.
///
/// `npk` is `to` left-padded to 32 bytes and the value is `amount + fee`.
fn unshield_commitment_from_event(
    unshield: &Unshield,
) -> Result<(FixedBytes<32>, CommitmentPreimage), ChainLogIngestionError> {
    let value = unshield
        .amount
        .checked_add(unshield.fee)
        .and_then(|value| Uint::<120, 2>::checked_from_limbs_slice(value.as_limbs()))
        .ok_or(ChainLogIngestionError::IntegerOverflow("unshield_value"))?;
    let preimage = CommitmentPreimage {
        npk: unshield.to.into_word(),
        token: unshield.token.clone(),
        value,
    };
    Ok((fixed_bytes_from_u256(preimage.hash()), preimage))
}

fn railgun_txid_from_parts(
    nullifiers: &[FixedBytes<32>],
    commitments: &[FixedBytes<32>],
    bound_params_hash: FixedBytes<32>,
) -> U256 {
    compute_railgun_txid_parts(
        &nullifiers
            .iter()
            .map(|value| U256::from_be_bytes(value.0))
            .collect::<Vec<_>>(),
        &commitments
            .iter()
            .map(|value| U256::from_be_bytes(value.0))
            .collect::<Vec<_>>(),
        U256::from_be_bytes(bound_params_hash.0),
    )
}

/// Replaces log-derived unshield commitments with the committed ones from `calldata`.
///
/// Calldata is authoritative, as in the SDK. Each unshield row must match exactly one decoded
/// transaction by its nullifiers, and that transaction must agree with the logs. When no Railgun
/// transaction decodes at all, the `Unshield` log derivation stands. Returns the number of log
/// derivations kept and of log derivations that differed from calldata.
pub(super) fn resolve_unshield_commitments(
    summary: &TransactOutputSummary,
    calldata: &[u8],
    frames: &mut [ActionCallTransactions],
) -> Result<(usize, usize), ChainLogIngestionError> {
    let transaction_hash = summary.source.transaction_hash;
    let block_number = summary.source.block_number;
    let mut decoded = Vec::new();
    collect_nested_railgun_transactions(calldata, 0, &mut decoded);
    let unshield_rows = frames
        .iter_mut()
        .flat_map(|(_, transactions)| transactions)
        .map(|(_, transaction)| transaction)
        .filter(|transaction| transaction.has_unshield);
    if decoded.is_empty() {
        let log_derivations = unshield_rows.count();
        tracing::warn!(target: LOG_TARGET,
            %transaction_hash,
            block_number,
            log_derivations,
            "unshield calldata did not decode; using commitments derived from Unshield logs"
        );
        return Ok((log_derivations, 0));
    }
    let contradiction = |field| ChainLogIngestionError::ContradictingUnshieldCalldata {
        transaction_hash,
        block_number,
        field,
    };
    // An empty nullifier array cannot key a match.
    if decoded
        .iter()
        .any(|transaction| transaction.nullifiers.is_empty())
    {
        return Err(contradiction("nullifiers"));
    }
    let mut divergences = 0;
    for row in unshield_rows {
        if row.nullifiers.is_empty() {
            return Err(contradiction("nullifiers"));
        }
        let matches = decoded
            .iter()
            .filter(|transaction| transaction.nullifiers == row.nullifiers)
            .collect::<Vec<_>>();
        let [matched] = matches.as_slice() else {
            return Err(ChainLogIngestionError::AmbiguousUnshieldCalldata {
                transaction_hash,
                block_number,
                matches: matches.len(),
            });
        };
        if matched.boundParams.unshield == 0 {
            return Err(contradiction("unshield type"));
        }
        if u64::from(matched.boundParams.treeNumber) != row.utxo_tree_in {
            return Err(contradiction("tree number"));
        }
        let (Some((committed, accumulated)), Some((derived, logged))) = (
            matched.commitments.split_last(),
            row.commitments.split_last_mut(),
        ) else {
            return Err(contradiction("commitments"));
        };
        if *logged != *accumulated {
            return Err(contradiction("commitments"));
        }
        if *derived != *committed {
            divergences += 1;
            *derived = *committed;
            row.railgun_txid =
                railgun_txid_from_parts(&row.nullifiers, &row.commitments, row.bound_params_hash);
        }
        row.unshield_preimage = Some(matched.unshieldPreimage.abi_encode());
    }
    if divergences > 0 {
        tracing::warn!(target: LOG_TARGET,
            %transaction_hash,
            block_number,
            divergences,
            "calldata unshield commitments differ from their Unshield log derivation"
        );
    }
    Ok((0, divergences))
}

/// Collects the Railgun transactions reachable from `calldata` through known entrypoints, their
/// nested `Call.data`, and ERC-4337 `handleOps` `callData`. Unknown selectors and calldata that
/// fails to decode contribute nothing.
fn collect_nested_railgun_transactions(
    calldata: &[u8],
    depth: usize,
    transactions: &mut Vec<Transaction>,
) {
    if depth > NESTED_CALLDATA_MAX_DEPTH {
        return;
    }
    let nested_calldata: Vec<Bytes> = if let Ok(call) = transactCall::abi_decode(calldata) {
        transactions.extend(call._transactions);
        Vec::new()
    } else if let Ok(call) = relayCall::abi_decode(calldata) {
        transactions.extend(call._transactions);
        call._actionData
            .calls
            .into_iter()
            .map(|call| call.data)
            .collect()
    } else if let Ok(call) = executeCall::abi_decode(calldata) {
        transactions.extend(call._transactions);
        call._actionData
            .calls
            .into_iter()
            .map(|call| call.data)
            .collect()
    } else if let Ok(call) = RelayAdapt7702::executeCall::abi_decode(calldata) {
        transactions.extend(call._transactions);
        call._actionData
            .calls
            .into_iter()
            .map(|call| call.data)
            .collect()
    } else if let Ok(call) = RelayAdapt7702::multicallCall::abi_decode(calldata) {
        call._calls.into_iter().map(|call| call.data).collect()
    } else if let Ok(call) = nested::multicallCall::abi_decode(calldata) {
        call._calls.into_iter().map(|call| call.data).collect()
    } else if let Ok(call) = nested::handleOpsCall::abi_decode(calldata) {
        call.ops
            .into_iter()
            .map(|operation| operation.callData)
            .collect()
    } else {
        return;
    };
    for inner in nested_calldata {
        collect_nested_railgun_transactions(&inner, depth + 1, transactions);
    }
}
