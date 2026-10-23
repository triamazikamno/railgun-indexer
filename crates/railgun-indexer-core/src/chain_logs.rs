use std::collections::{BTreeMap, HashMap, HashSet};

use alloy::consensus::Transaction as _;
use alloy::hex;
use alloy::primitives::{Address, Bytes, FixedBytes, U256, Uint};
use alloy::providers::Provider;
use alloy::sol_types::{Error as SolError, SolCall, SolEvent, SolValue};
use alloy::transports::TransportError;
use alloy_rpc_types_eth::{Filter, Log};
use broadcaster_core::contracts::railgun::{
    CommitmentBatch, CommitmentCiphertext, CommitmentPreimage, GeneratedCommitmentBatch,
    LegacyCommitmentCiphertext, LegacyCommitmentPreimage, Nullified, Nullifiers,
    RailgunLegacyShieldEvents, RelayAdapt7702, Shield, ShieldCiphertext, Transact, Transaction,
    Unshield, executeCall, relayCall, transactCall,
};
use broadcaster_core::crypto::hash_to_scalar;
use broadcaster_core::transact::{
    DEFAULT_TXID_VERSION, TransactError, compute_railgun_txid, compute_railgun_txid_parts,
};
use broadcaster_core::tree::TREE_LEAF_COUNT;
use serde_json::Value;
use thiserror::Error;

const MODERN_UNSHIELD_ONLY_UTXO_TREE: u64 = 99_999;
const MODERN_UNSHIELD_ONLY_UTXO_POSITION: u64 = 99_999;
const ACTION_EVENT_SIGNATURES: [FixedBytes<32>; 2] =
    [Action::SIGNATURE_HASH, Unshield::SIGNATURE_HASH];
/// Deepest nested call the unshield calldata walk enters, as in the SDK.
const NESTED_CALLDATA_MAX_DEPTH: usize = 4;

use action::Action;
pub use action::TXConfig;

mod action {
    use alloy::sol;

    sol! {
        /// `commitmentsCount` excludes the unshield commitment.
        struct TXConfig {
            uint32 nullifiersCount;
            uint32 commitmentsCount;
            bool hasUnshield;
            bytes32 boundParamsHash;
        }

        event Action(address caller, TXConfig[] txconfigs);
    }
}

/// Entrypoints the unshield calldata walk enters that carry no Railgun transaction themselves.
mod nested {
    use alloy::sol;

    sol! {
        struct Call {
            address to;
            bytes data;
            uint256 value;
        }

        /// ERC-4337 `EntryPoint` v0.7 user operation.
        struct PackedUserOperation {
            address sender;
            uint256 nonce;
            bytes initCode;
            bytes callData;
            bytes32 accountGasLimits;
            uint256 preVerificationGas;
            bytes32 gasFees;
            bytes paymasterAndData;
            bytes signature;
        }

        /// `RelayAdapt` `multicall`.
        function multicall(bool _requireSuccess, Call[] _calls) payable;
        /// ERC-4337 `EntryPoint` v0.7 `handleOps`.
        function handleOps(PackedUserOperation[] ops, address beneficiary);
    }
}

mod legacy {
    use alloy::sol;

    sol! {
        struct LegacyG1Point {
            uint256 x;
            uint256 y;
        }

        struct LegacyG2Point {
            uint256[2] x;
            uint256[2] y;
        }

        struct LegacySnarkProof {
            LegacyG1Point a;
            LegacyG2Point b;
            LegacyG1Point c;
        }

        struct LegacyCommitmentCiphertext {
            uint256[4] ciphertext;
            uint256[2] ephemeralKeys;
            uint256[] memo;
        }

        struct LegacyTokenData {
            uint8 tokenType;
            address tokenAddress;
            uint256 tokenSubID;
        }

        struct LegacyCommitmentPreimage {
            uint256 npk;
            LegacyTokenData token;
            uint120 value;
        }

        struct LegacyBoundParams {
            uint16 treeNumber;
            uint8 withdraw;
            address adaptContract;
            bytes32 adaptParams;
            LegacyCommitmentCiphertext[] commitmentCiphertext;
        }

        struct LegacyTransaction {
            LegacySnarkProof proof;
            uint256 merkleRoot;
            uint256[] nullifiers;
            uint256[] commitments;
            LegacyBoundParams boundParams;
            LegacyCommitmentPreimage unshieldPreimage;
            address verifier;
        }

        struct LegacyCall {
            address to;
            bytes data;
            uint256 value;
        }

        function transact(LegacyTransaction[] _transactions) payable;
        function relay(
            LegacyTransaction[] _transactions,
            uint256 _random,
            bool _requireSuccess,
            uint256 _minGas,
            LegacyCall[] _calls
        ) payable;
    }
}

pub async fn fetch_chain_index_logs<P: Provider + ?Sized>(
    provider: &P,
    contract: Address,
    from_block: u64,
    to_block: u64,
    v2_start_block: u64,
    legacy_shield_block: u64,
    action_start_block: Option<u64>,
) -> Result<Vec<Log>, ChainLogIngestionError> {
    let mut logs = Vec::new();
    for filter in chain_index_log_filters(
        contract,
        from_block,
        to_block,
        v2_start_block,
        legacy_shield_block,
        action_start_block,
    ) {
        logs.extend(provider.get_logs(&filter).await?);
    }
    sort_logs(&mut logs);
    Ok(logs)
}

fn chain_index_log_filters(
    contract: Address,
    from_block: u64,
    to_block: u64,
    v2_start_block: u64,
    legacy_shield_block: u64,
    action_start_block: Option<u64>,
) -> Vec<Filter> {
    if from_block > to_block {
        return Vec::new();
    }
    let filter = |from: u64, to: u64, event_signatures: Vec<FixedBytes<32>>| {
        Filter::new()
            .select(from..=to)
            .address(contract)
            .event_signature(event_signatures)
    };
    // Action and Unshield logs are requested only from the activation block.
    let action_from = action_start_block
        .filter(|start| *start <= to_block)
        .map(|start| start.max(from_block));

    if let Some(event_signatures) = combined_event_signatures_for_range(
        from_block,
        to_block,
        v2_start_block,
        legacy_shield_block,
        action_start_block,
    ) {
        let mut filters = vec![filter(from_block, to_block, event_signatures)];
        // A range straddling activation gets the new topics from a separate filter.
        if let Some(action_from) = action_from.filter(|action_from| *action_from > from_block) {
            filters.push(filter(
                action_from,
                to_block,
                ACTION_EVENT_SIGNATURES.to_vec(),
            ));
        }
        return filters;
    }

    let mut filters = Vec::new();
    if from_block <= v2_start_block {
        let legacy_end = to_block.min(v2_start_block);
        filters.push(filter(
            from_block,
            legacy_end,
            vec![
                CommitmentBatch::SIGNATURE_HASH,
                GeneratedCommitmentBatch::SIGNATURE_HASH,
            ],
        ));
    }

    if to_block >= v2_start_block {
        let v2_start = from_block.max(v2_start_block);
        filters.push(filter(v2_start, to_block, vec![Transact::SIGNATURE_HASH]));

        if v2_start <= legacy_shield_block {
            let legacy_shield_end = to_block.min(legacy_shield_block);
            filters.push(filter(
                v2_start,
                legacy_shield_end,
                vec![RailgunLegacyShieldEvents::Shield::SIGNATURE_HASH],
            ));
        }

        if to_block > legacy_shield_block {
            let modern_start = v2_start.max(legacy_shield_block.saturating_add(1));
            filters.push(filter(modern_start, to_block, vec![Shield::SIGNATURE_HASH]));
        }
    }

    filters.push(filter(
        from_block,
        to_block,
        vec![Nullifiers::SIGNATURE_HASH, Nullified::SIGNATURE_HASH],
    ));
    if let Some(action_from) = action_from {
        filters.push(filter(
            action_from,
            to_block,
            ACTION_EVENT_SIGNATURES.to_vec(),
        ));
    }
    filters
}

pub fn ingest_chain_logs(logs: &[Log]) -> Result<IndexedLogBatch, ChainLogIngestionError> {
    let mut batch = IndexedLogBatch::default();

    for raw_log in logs {
        let topic0 = raw_log.inner.topics().first().copied().unwrap_or_default();
        if topic0 == Transact::SIGNATURE_HASH {
            let event = raw_log.log_decode::<Transact>()?.inner.data;
            let tree_number: u32 = event.treeNumber.to();
            let start_position: u64 = event.startPosition.to();
            let source = source_from_log(raw_log)?;
            for (index, hash) in event.hash.into_iter().enumerate() {
                let (tree_number, tree_position) =
                    normalized_event_position(tree_number, start_position, index)?;
                batch.transact_commitments.push(IndexedTransactCommitment {
                    tree_number,
                    tree_position,
                    hash,
                    ciphertext: event.ciphertext.get(index).cloned(),
                    source: source.clone(),
                });
            }
        } else if topic0 == Shield::SIGNATURE_HASH {
            let event = raw_log.log_decode::<Shield>()?.inner.data;
            let source = source_from_log(raw_log)?;
            ingest_shield_commitments(
                &mut batch,
                event.treeNumber.to(),
                event.startPosition.to(),
                event.commitments,
                &event.shieldCiphertext,
                &source,
            )?;
        } else if topic0 == RailgunLegacyShieldEvents::Shield::SIGNATURE_HASH {
            let event = raw_log
                .log_decode::<RailgunLegacyShieldEvents::Shield>()?
                .inner
                .data;
            let source = source_from_log(raw_log)?;
            ingest_shield_commitments(
                &mut batch,
                event.treeNumber.to(),
                event.startPosition.to(),
                event.commitments,
                &event.shieldCiphertext,
                &source,
            )?;
        } else if topic0 == Nullifiers::SIGNATURE_HASH {
            let event = raw_log.log_decode::<Nullifiers>()?.inner.data;
            let tree_number: u32 = event.treeNumber.to();
            let source = source_from_log(raw_log)?;
            for nullifier in event.nullifier {
                batch.nullifiers.push(IndexedNullifier {
                    tree_number,
                    nullifier: FixedBytes::from(nullifier.to_be_bytes::<32>()),
                    source: source.clone(),
                });
            }
        } else if topic0 == Nullified::SIGNATURE_HASH {
            let event = raw_log.log_decode::<Nullified>()?.inner.data;
            let tree_number = event.treeNumber.into();
            let source = source_from_log(raw_log)?;
            for nullifier in event.nullifier {
                batch.nullifiers.push(IndexedNullifier {
                    tree_number,
                    nullifier,
                    source: source.clone(),
                });
            }
        } else if topic0 == Action::SIGNATURE_HASH {
            let event = raw_log.log_decode::<Action>()?.inner.data;
            batch.actions.push(IndexedAction {
                txconfigs: event.txconfigs,
                source: source_from_log(raw_log)?,
            });
        } else if topic0 == Unshield::SIGNATURE_HASH {
            let unshield = raw_log.log_decode::<Unshield>()?.inner.data;
            batch.unshields.push(IndexedUnshield {
                unshield,
                source: source_from_log(raw_log)?,
            });
        } else if topic0 == CommitmentBatch::SIGNATURE_HASH {
            let event = raw_log.log_decode::<CommitmentBatch>()?.inner.data;
            let tree_number: u32 = event.treeNumber.to();
            let start_position: u64 = event.startPosition.to();
            let source = source_from_log(raw_log)?;
            for (index, ciphertext) in event.ciphertext.into_iter().enumerate() {
                let Some(hash) = event.hash.get(index).copied() else {
                    continue;
                };
                let (tree_number, tree_position) =
                    normalized_event_position(tree_number, start_position, index)?;
                batch
                    .legacy_encrypted_commitments
                    .push(IndexedLegacyEncryptedCommitment {
                        tree_number,
                        tree_position,
                        hash: FixedBytes::from(hash.to_be_bytes::<32>()),
                        ciphertext,
                        source: source.clone(),
                    });
            }
        } else if topic0 == GeneratedCommitmentBatch::SIGNATURE_HASH {
            let event = raw_log.log_decode::<GeneratedCommitmentBatch>()?.inner.data;
            let tree_number: u32 = event.treeNumber.to();
            let start_position: u64 = event.startPosition.to();
            let source = source_from_log(raw_log)?;
            for (index, preimage) in event.commitments.into_iter().enumerate() {
                let Some(encrypted_random) = event.encryptedRandom.get(index).copied() else {
                    continue;
                };
                let (tree_number, tree_position) =
                    normalized_event_position(tree_number, start_position, index)?;
                batch
                    .legacy_generated_commitments
                    .push(IndexedLegacyGeneratedCommitment {
                        tree_number,
                        tree_position,
                        preimage,
                        encrypted_random,
                        source: source.clone(),
                    });
            }
        }
    }

    Ok(batch)
}

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

async fn block_timestamp<P: Provider + ?Sized>(
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

async fn full_block_context<'a, P: Provider + ?Sized>(
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

fn decode_hex_bytes(value: &str) -> Option<Vec<u8>> {
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

struct FullBlockContext {
    timestamp: u64,
    transaction_inputs: HashMap<FixedBytes<32>, Vec<u8>>,
}

#[derive(Debug, Clone)]
struct DecodedRailgunTransaction {
    call_kind: RailgunCallKind,
    nullifiers: Vec<FixedBytes<32>>,
    commitments: Vec<FixedBytes<32>>,
    bound_params_hash: FixedBytes<32>,
    has_unshield: bool,
    unshield_preimage: Option<Vec<u8>>,
    utxo_tree_in: u64,
    railgun_txid: U256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RailgunCallKind {
    Transact,
    Relay,
    Execute,
    LegacyRelay,
    LegacyTransact,
    /// Rebuilt from `Action` logs; matched to outputs like the modern entrypoints.
    ActionLogs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EmittedOutputCommitment {
    family: EmittedOutputFamily,
    log_index: u64,
    tree_number: u32,
    tree_position: u64,
    hash: FixedBytes<32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NullifierGroup {
    source: IndexedLogSource,
    nullifiers: Vec<FixedBytes<32>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OutputMatch {
    output_start: u64,
    last_log_index: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EmittedOutputFamily {
    Transact,
    LegacyEncrypted,
    LegacyGenerated,
}

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

async fn public_transactions_from_calldata_or_trace<P: Provider + ?Sized>(
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

async fn debug_trace_transaction<P: Provider + ?Sized>(
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

async fn trace_transaction<P: Provider + ?Sized>(
    provider: &P,
    summary: &TransactOutputSummary,
) -> Result<Value, TransportError> {
    provider
        .client()
        .request("trace_transaction", (summary.source.transaction_hash,))
        .await
}

fn collect_debug_trace_railgun_transactions(
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

fn collect_trace_transaction_railgun_transactions(
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

fn public_transactions_from_decoded(
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

fn decode_railgun_transactions(
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

fn fixed_bytes_from_u256(value: U256) -> FixedBytes<32> {
    FixedBytes::from(value.to_be_bytes::<32>())
}

/// One Railgun log of an outer transaction, as read by the `Action` path.
enum ActionLogEvent {
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

fn action_log_events_by_transaction(
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
fn decoded_transactions_from_action_logs(
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
fn resolve_unshield_commitments(
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
        tracing::warn!(
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
        tracing::warn!(
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

#[must_use]
pub fn combined_event_signatures_for_range(
    from_block: u64,
    to_block: u64,
    v2_start_block: u64,
    legacy_shield_block: u64,
    action_start_block: Option<u64>,
) -> Option<Vec<FixedBytes<32>>> {
    let mut event_signatures =
        era_event_signatures_for_range(from_block, to_block, v2_start_block, legacy_shield_block)?;
    if action_start_block.is_some_and(|start| from_block >= start) {
        event_signatures.extend(ACTION_EVENT_SIGNATURES);
    }
    Some(event_signatures)
}

fn era_event_signatures_for_range(
    from_block: u64,
    to_block: u64,
    v2_start_block: u64,
    legacy_shield_block: u64,
) -> Option<Vec<FixedBytes<32>>> {
    if v2_start_block > 0 && to_block < v2_start_block {
        return Some(vec![
            CommitmentBatch::SIGNATURE_HASH,
            GeneratedCommitmentBatch::SIGNATURE_HASH,
            Nullifiers::SIGNATURE_HASH,
            Nullified::SIGNATURE_HASH,
        ]);
    }

    if from_block < v2_start_block {
        return None;
    }

    if to_block <= legacy_shield_block {
        return Some(vec![
            Transact::SIGNATURE_HASH,
            RailgunLegacyShieldEvents::Shield::SIGNATURE_HASH,
            Nullifiers::SIGNATURE_HASH,
            Nullified::SIGNATURE_HASH,
        ]);
    }

    if from_block > legacy_shield_block {
        return Some(vec![
            Transact::SIGNATURE_HASH,
            Shield::SIGNATURE_HASH,
            Nullifiers::SIGNATURE_HASH,
            Nullified::SIGNATURE_HASH,
        ]);
    }

    None
}

pub fn sort_logs(logs: &mut [Log]) {
    logs.sort_by_key(|log| {
        (
            log.block_number.unwrap_or_default(),
            log.log_index.unwrap_or_default(),
        )
    });
}

fn ingest_shield_commitments(
    batch: &mut IndexedLogBatch,
    tree_number: u32,
    start_position: u64,
    commitments: Vec<CommitmentPreimage>,
    ciphertexts: &[ShieldCiphertext],
    source: &IndexedLogSource,
) -> Result<(), ChainLogIngestionError> {
    for (index, preimage) in commitments.into_iter().enumerate() {
        let Some(shield_ciphertext) = ciphertexts.get(index).cloned() else {
            continue;
        };
        let (tree_number, tree_position) =
            normalized_event_position(tree_number, start_position, index)?;
        batch.shield_commitments.push(IndexedShieldCommitment {
            tree_number,
            tree_position,
            preimage,
            shield_ciphertext,
            source: source.clone(),
        });
    }
    Ok(())
}

fn normalized_event_position(
    tree_number: u32,
    start_position: u64,
    index: usize,
) -> Result<(u32, u64), ChainLogIngestionError> {
    let index =
        u64::try_from(index).map_err(|_| ChainLogIngestionError::IntegerOverflow("event_index"))?;
    let position = start_position
        .checked_add(index)
        .ok_or(ChainLogIngestionError::IntegerOverflow("tree_position"))?;
    normalize_tree_position(tree_number, position)
}

fn normalize_tree_position(
    tree_number: u32,
    tree_position: u64,
) -> Result<(u32, u64), ChainLogIngestionError> {
    let tree_increment = tree_position / TREE_LEAF_COUNT;
    let tree_increment = u32::try_from(tree_increment)
        .map_err(|_| ChainLogIngestionError::IntegerOverflow("tree_number"))?;
    let tree_number = tree_number
        .checked_add(tree_increment)
        .ok_or(ChainLogIngestionError::IntegerOverflow("tree_number"))?;
    Ok((tree_number, tree_position % TREE_LEAF_COUNT))
}

fn normalized_global_position(global_position: u64) -> Result<(u32, u64), ChainLogIngestionError> {
    normalize_tree_position(0, global_position)
}

fn global_tree_position(
    tree_number: u32,
    tree_position: u64,
) -> Result<u64, ChainLogIngestionError> {
    u64::from(tree_number)
        .checked_mul(TREE_LEAF_COUNT)
        .and_then(|tree_start| tree_start.checked_add(tree_position))
        .ok_or(ChainLogIngestionError::IntegerOverflow(
            "global_tree_position",
        ))
}

fn comparable_global_tree_position(tree_number: u32, tree_position: u64) -> u128 {
    u128::from(tree_number) * u128::from(TREE_LEAF_COUNT) + u128::from(tree_position)
}

fn source_from_log(log: &Log) -> Result<IndexedLogSource, ChainLogIngestionError> {
    Ok(IndexedLogSource {
        block_number: log
            .block_number
            .ok_or(ChainLogIngestionError::MissingLogMetadata("block_number"))?,
        block_timestamp: None,
        block_hash: log
            .block_hash
            .ok_or(ChainLogIngestionError::MissingLogMetadata("block_hash"))?,
        transaction_hash: log.transaction_hash.ok_or(
            ChainLogIngestionError::MissingLogMetadata("transaction_hash"),
        )?,
        log_index: log
            .log_index
            .ok_or(ChainLogIngestionError::MissingLogMetadata("log_index"))?,
    })
}

#[derive(Default, Clone)]
pub struct IndexedLogBatch {
    pub transact_commitments: Vec<IndexedTransactCommitment>,
    pub shield_commitments: Vec<IndexedShieldCommitment>,
    pub nullifiers: Vec<IndexedNullifier>,
    pub legacy_encrypted_commitments: Vec<IndexedLegacyEncryptedCommitment>,
    pub legacy_generated_commitments: Vec<IndexedLegacyGeneratedCommitment>,
    pub actions: Vec<IndexedAction>,
    pub unshields: Vec<IndexedUnshield>,
    pub public_transactions: Vec<IndexedPublicTransaction>,
    /// Unshield commitments taken from `Unshield` logs because calldata did not decode.
    pub unshield_log_derivations: usize,
    /// `Unshield` log derivations that differed from the committed value in calldata.
    pub unshield_log_divergences: usize,
}

#[derive(Clone)]
pub struct IndexedAction {
    pub txconfigs: Vec<TXConfig>,
    pub source: IndexedLogSource,
}

#[derive(Clone)]
pub struct IndexedUnshield {
    pub unshield: Unshield,
    pub source: IndexedLogSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedLogSource {
    pub block_number: u64,
    pub block_timestamp: Option<u64>,
    pub block_hash: FixedBytes<32>,
    pub transaction_hash: FixedBytes<32>,
    pub log_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedPublicTransaction {
    pub source: IndexedLogSource,
    pub first_log_index: u64,
    pub last_log_index: u64,
    pub railgun_transaction_index: u64,
    pub id: String,
    pub block_timestamp: u64,
    pub nullifiers: Vec<FixedBytes<32>>,
    pub commitments: Vec<FixedBytes<32>>,
    pub bound_params_hash: FixedBytes<32>,
    pub has_unshield: bool,
    pub unshield_preimage: Option<Vec<u8>>,
    pub utxo_tree_in: u64,
    pub utxo_tree_out: u64,
    pub utxo_batch_start_position_out: u64,
    pub railgun_txid: U256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPublicTransaction {
    pub railgun_transaction_index: u64,
    pub nullifiers: Vec<FixedBytes<32>>,
    pub commitments: Vec<FixedBytes<32>>,
    pub bound_params_hash: FixedBytes<32>,
    pub has_unshield: bool,
    pub unshield_preimage: Option<Vec<u8>>,
    pub utxo_tree_in: u64,
}

struct TransactOutputSummary {
    source: IndexedLogSource,
    first_log_index: u64,
    last_log_index: u64,
    output_commitments: Vec<EmittedOutputCommitment>,
    nullifier_groups: Vec<NullifierGroup>,
}

#[derive(Clone)]
pub struct IndexedTransactCommitment {
    pub tree_number: u32,
    pub tree_position: u64,
    pub hash: FixedBytes<32>,
    pub ciphertext: Option<CommitmentCiphertext>,
    pub source: IndexedLogSource,
}

#[derive(Clone)]
pub struct IndexedShieldCommitment {
    pub tree_number: u32,
    pub tree_position: u64,
    pub preimage: CommitmentPreimage,
    pub shield_ciphertext: ShieldCiphertext,
    pub source: IndexedLogSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedNullifier {
    pub tree_number: u32,
    pub nullifier: FixedBytes<32>,
    pub source: IndexedLogSource,
}

#[derive(Clone)]
pub struct IndexedLegacyEncryptedCommitment {
    pub tree_number: u32,
    pub tree_position: u64,
    pub hash: FixedBytes<32>,
    pub ciphertext: LegacyCommitmentCiphertext,
    pub source: IndexedLogSource,
}

#[derive(Clone)]
pub struct IndexedLegacyGeneratedCommitment {
    pub tree_number: u32,
    pub tree_position: u64,
    pub preimage: LegacyCommitmentPreimage,
    pub encrypted_random: [U256; 2],
    pub source: IndexedLogSource,
}

#[derive(Debug, Error)]
pub enum ChainLogIngestionError {
    #[error("provider request failed")]
    Provider(#[from] TransportError),
    #[error("decode log failed")]
    Decode(#[from] SolError),
    #[error("decode transact calldata failed")]
    Transact(#[from] TransactError),
    #[error("log missing required metadata: {0}")]
    MissingLogMetadata(&'static str),
    #[error(
        "transaction {transaction_hash} referenced by logs at block {block_number} ({block_hash}), log indexes {first_log_index}..={last_log_index}, was not returned by RPC"
    )]
    MissingTransaction {
        transaction_hash: FixedBytes<32>,
        block_number: u64,
        block_hash: FixedBytes<32>,
        first_log_index: u64,
        last_log_index: u64,
    },
    #[error("transaction {transaction_hash} was not returned by RPC")]
    MissingTransactionByHash { transaction_hash: FixedBytes<32> },
    #[error(
        "transaction {transaction_hash} emitted Railgun public transaction logs at block {block_number} ({block_hash}), log indexes {first_log_index}..={last_log_index}, but no supported Railgun calldata was found in the transaction or traces"
    )]
    MissingRailgunCalldata {
        transaction_hash: FixedBytes<32>,
        block_number: u64,
        block_hash: FixedBytes<32>,
        first_log_index: u64,
        last_log_index: u64,
    },
    #[error("transaction {transaction_hash} did not contain supported Railgun calldata")]
    MissingRailgunCalldataByHash { transaction_hash: FixedBytes<32> },
    #[error(
        "transaction {transaction_hash} at block {block_number} decoded Railgun transaction index {railgun_transaction_index}, but none of its commitments matched the next emitted output commitment"
    )]
    UnmatchedTransactionOutputCommitments {
        transaction_hash: FixedBytes<32>,
        block_number: u64,
        railgun_transaction_index: usize,
    },
    #[error(
        "transaction {transaction_hash} at block {block_number} decoded legacy Railgun transaction index {railgun_transaction_index}, but no unused nullifier log matched its nullifiers"
    )]
    MissingTransactionNullifierGroup {
        transaction_hash: FixedBytes<32>,
        block_number: u64,
        railgun_transaction_index: usize,
    },
    #[error(
        "transaction {transaction_hash} at block {block_number} decoded legacy Railgun transaction index {railgun_transaction_index}, but {matches} unused nullifier logs matched its nullifiers"
    )]
    AmbiguousTransactionNullifierGroup {
        transaction_hash: FixedBytes<32>,
        block_number: u64,
        railgun_transaction_index: usize,
        matches: usize,
    },
    #[error(
        "transaction {transaction_hash} at block {block_number} matched {consumed} of {emitted} emitted output commitments"
    )]
    UnmatchedEmittedOutputCommitments {
        transaction_hash: FixedBytes<32>,
        block_number: u64,
        consumed: usize,
        emitted: usize,
    },
    #[error("block {block_number} ({block_hash}) referenced by logs was not returned by RPC")]
    MissingBlock {
        block_number: u64,
        block_hash: FixedBytes<32>,
    },
    #[error(
        "block metadata mismatch for logs: expected block {expected_block_number} ({expected_block_hash}), got block {actual_block_number} ({actual_block_hash})"
    )]
    MismatchedBlock {
        expected_block_number: u64,
        expected_block_hash: FixedBytes<32>,
        actual_block_number: u64,
        actual_block_hash: FixedBytes<32>,
    },
    #[error("block {block_number} ({block_hash}) did not include full transactions")]
    MissingFullBlockTransactions {
        block_number: u64,
        block_hash: FixedBytes<32>,
    },
    #[error("block {block_number} ({block_hash}) had invalid or missing field: {field}")]
    InvalidBlockField {
        block_number: u64,
        block_hash: FixedBytes<32>,
        field: &'static str,
    },
    #[error(
        "transaction {transaction_hash} at block {block_number}: Action log {log_index} does not match the Nullified logs before it"
    )]
    ActionNullifierCountMismatch {
        transaction_hash: FixedBytes<32>,
        block_number: u64,
        log_index: u64,
    },
    #[error(
        "transaction {transaction_hash} at block {block_number}: Railgun call closed at log {log_index} does not match its Action commitment counts"
    )]
    ActionCommitmentCountMismatch {
        transaction_hash: FixedBytes<32>,
        block_number: u64,
        log_index: u64,
    },
    #[error(
        "transaction {transaction_hash} at block {block_number}: Action log {log_index} declares an unshield without a matching Unshield log"
    )]
    MissingActionUnshield {
        transaction_hash: FixedBytes<32>,
        block_number: u64,
        log_index: u64,
    },
    #[error(
        "transaction {transaction_hash} at block {block_number}: log {log_index} has no open Railgun call expecting it"
    )]
    UnmatchedActionLog {
        transaction_hash: FixedBytes<32>,
        block_number: u64,
        log_index: u64,
    },
    #[error(
        "transaction {transaction_hash} at block {block_number}: {matches} decoded calldata transactions carry an unshield row's nullifiers, expected exactly one"
    )]
    AmbiguousUnshieldCalldata {
        transaction_hash: FixedBytes<32>,
        block_number: u64,
        matches: usize,
    },
    #[error(
        "transaction {transaction_hash} at block {block_number}: decoded calldata disagrees with the logs on {field}"
    )]
    ContradictingUnshieldCalldata {
        transaction_hash: FixedBytes<32>,
        block_number: u64,
        field: &'static str,
    },
    #[error("integer overflow while computing {0}")]
    IntegerOverflow(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::Log as PrimitiveLog;
    use alloy::providers::ProviderBuilder;
    use alloy::transports::mock::Asserter;
    use alloy::uint;
    use broadcaster_core::contracts::railgun::{
        ActionData, BoundParams, Call, RelayAdapt7702ActionData, SnarkProof,
    };
    use serde_json::{Value, json};

    #[test]
    fn parses_all_chain_index_event_families() {
        let logs = vec![
            log_for(Transact {
                treeNumber: uint!(7_U256),
                startPosition: U256::from(TREE_LEAF_COUNT - 1),
                hash: vec![FixedBytes::from([0x11; 32]), FixedBytes::from([0x12; 32])],
                ciphertext: vec![commitment_ciphertext()],
            }),
            log_for(Shield {
                treeNumber: uint!(8_U256),
                startPosition: U256::from(TREE_LEAF_COUNT),
                commitments: vec![commitment_preimage(0x22)],
                shieldCiphertext: vec![shield_ciphertext()],
                fees: vec![U256::ZERO],
            }),
            log_for(RailgunLegacyShieldEvents::Shield {
                treeNumber: uint!(10_U256),
                startPosition: U256::ONE,
                commitments: vec![commitment_preimage(0x23)],
                shieldCiphertext: vec![shield_ciphertext()],
            }),
            log_for(Nullifiers {
                treeNumber: uint!(9_U256),
                nullifier: vec![U256::from(0x33)],
            }),
            log_for(CommitmentBatch {
                treeNumber: uint!(10_U256),
                startPosition: U256::from(TREE_LEAF_COUNT),
                hash: vec![U256::from(0x44)],
                ciphertext: vec![legacy_commitment_ciphertext()],
            }),
            log_for(GeneratedCommitmentBatch {
                treeNumber: uint!(11_U256),
                startPosition: U256::from(TREE_LEAF_COUNT + 1),
                commitments: vec![legacy_commitment_preimage(0x55)],
                encryptedRandom: vec![[U256::from(0x66), U256::from(0x77)]],
            }),
            log_for(Nullified {
                treeNumber: 12,
                nullifier: vec![FixedBytes::from([0x88; 32])],
            }),
        ];

        let batch = ingest_chain_logs(&logs).expect("ingest logs");

        assert_eq!(batch.transact_commitments.len(), 2);
        assert_eq!(batch.transact_commitments[0].tree_number, 7);
        assert_eq!(
            batch.transact_commitments[0].tree_position,
            TREE_LEAF_COUNT - 1
        );
        assert!(batch.transact_commitments[0].ciphertext.is_some());
        assert_eq!(batch.transact_commitments[1].tree_number, 8);
        assert_eq!(batch.transact_commitments[1].tree_position, 0);
        assert!(batch.transact_commitments[1].ciphertext.is_none());
        assert_eq!(batch.shield_commitments.len(), 2);
        assert_eq!(batch.shield_commitments[0].tree_number, 9);
        assert_eq!(batch.shield_commitments[0].tree_position, 0);
        assert_eq!(batch.shield_commitments[1].tree_number, 10);
        assert_eq!(batch.shield_commitments[1].tree_position, 1);
        assert_eq!(batch.nullifiers.len(), 2);
        assert_eq!(batch.legacy_encrypted_commitments.len(), 1);
        assert_eq!(batch.legacy_encrypted_commitments[0].tree_number, 11);
        assert_eq!(batch.legacy_encrypted_commitments[0].tree_position, 0);
        assert_eq!(batch.legacy_generated_commitments.len(), 1);
        assert_eq!(batch.legacy_generated_commitments[0].tree_number, 12);
        assert_eq!(batch.legacy_generated_commitments[0].tree_position, 1);
    }

    #[test]
    fn combined_filter_signatures_match_expected_eras() {
        assert!(combined_event_signatures_for_range(1, 9, 10, 20, None).is_some());
        assert!(combined_event_signatures_for_range(1, 11, 10, 20, None).is_none());
        let legacy_shield = combined_event_signatures_for_range(10, 20, 10, 20, None)
            .expect("legacy shield range can use a combined filter");
        assert!(legacy_shield.contains(&RailgunLegacyShieldEvents::Shield::SIGNATURE_HASH));
        assert_eq!(
            RailgunLegacyShieldEvents::Shield::SIGNATURE_HASH,
            FixedBytes::from(hex!(
                "0xc3821e11e71307afd1d94a490660178ff37aefdd3c0514e5dd08937bd7024f34"
            ))
        );
        let modern = combined_event_signatures_for_range(21, 30, 10, 20, None)
            .expect("modern range can use a combined filter");
        assert!(modern.contains(&Shield::SIGNATURE_HASH));
        assert_eq!(
            Shield::SIGNATURE_HASH,
            FixedBytes::from(hex!(
                "0x3a5b9dc26075a3801a6ddccf95fec485bb7500a91b44cec1add984c21ee6db3b"
            ))
        );
        assert_eq!(
            Action::SIGNATURE_HASH,
            FixedBytes::from(hex!(
                "0x29696e3cb1956aca85bbcae445e3ed9bb933a4b7328445f65e872e49af7229ea"
            ))
        );
    }

    #[test]
    fn straddling_range_requests_action_topics_only_from_start_block() {
        let filters = chain_index_log_filters(railgun_contract(), 90, 110, 10, 20, Some(100));

        let action_filters = filters
            .iter()
            .filter(|filter| {
                ACTION_EVENT_SIGNATURES
                    .iter()
                    .any(|signature| filter.topics[0].contains(signature))
            })
            .collect::<Vec<_>>();
        assert_eq!(action_filters.len(), 1);
        assert_eq!(action_filters[0].get_from_block(), Some(100));
        assert_eq!(action_filters[0].get_to_block(), Some(110));
        assert!(
            ACTION_EVENT_SIGNATURES
                .iter()
                .all(|signature| action_filters[0].topics[0].contains(signature))
        );
        assert!(
            filters
                .iter()
                .any(|filter| filter.get_from_block() == Some(90)
                    && filter.topics[0].contains(&Transact::SIGNATURE_HASH))
        );
    }

    #[tokio::test]
    async fn hydrate_uses_block_timestamp_when_transaction_omits_it() {
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let transaction = transaction_json_with_input(
            transactCall {
                _transactions: vec![railgun_transaction(0x11)],
            }
            .abi_encode(),
        );
        let transaction_hash = fixed_bytes(LEGACY_TRANSACTION_HASH);
        let block_hash = fixed_bytes(LEGACY_BLOCK_HASH);
        let mut batch = transact_batch(transaction_hash, block_hash, LEGACY_BLOCK_NUMBER);

        asserter.push_success(&transaction);
        asserter.push_success(&block_json(
            LEGACY_BLOCK_HASH,
            LEGACY_BLOCK_NUMBER,
            1_714_356_419,
            vec![],
        ));

        hydrate_public_transactions(&provider, railgun_contract(), None, &mut batch)
            .await
            .expect("hydrate public transactions");

        assert_eq!(batch.public_transactions.len(), 1);
        assert_eq!(batch.public_transactions[0].block_timestamp, 1_714_356_419);
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn hydrate_falls_back_to_full_block_when_transaction_lookup_returns_null() {
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let transaction = transaction_json_with_input(
            transactCall {
                _transactions: vec![railgun_transaction(0x11)],
            }
            .abi_encode(),
        );
        let transaction_hash = fixed_bytes(LEGACY_TRANSACTION_HASH);
        let block_hash = fixed_bytes(LEGACY_BLOCK_HASH);
        let mut batch = transact_batch(transaction_hash, block_hash, LEGACY_BLOCK_NUMBER);

        asserter.push_success(&Value::Null);
        asserter.push_success(&block_json(
            LEGACY_BLOCK_HASH,
            LEGACY_BLOCK_NUMBER,
            1_714_356_419,
            vec![transaction],
        ));

        hydrate_public_transactions(&provider, railgun_contract(), None, &mut batch)
            .await
            .expect("hydrate public transactions");

        assert_eq!(batch.public_transactions.len(), 1);
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn hydrate_full_block_fallback_ignores_arbitrum_system_transaction_type() {
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let transaction = transaction_json_with_input(
            transactCall {
                _transactions: vec![railgun_transaction(0x11)],
            }
            .abi_encode(),
        );
        let transaction_hash = fixed_bytes(LEGACY_TRANSACTION_HASH);
        let block_hash = fixed_bytes(LEGACY_BLOCK_HASH);
        let mut batch = transact_batch(transaction_hash, block_hash, LEGACY_BLOCK_NUMBER);

        asserter.push_success(&Value::Null);
        asserter.push_success(&block_json(
            LEGACY_BLOCK_HASH,
            LEGACY_BLOCK_NUMBER,
            1_714_356_419,
            vec![arbitrum_system_transaction_json(), transaction],
        ));

        hydrate_public_transactions(&provider, railgun_contract(), None, &mut batch)
            .await
            .expect("hydrate public transactions");

        assert_eq!(batch.public_transactions.len(), 1);
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn hydrate_anchors_modern_unshield_only_row_after_emitted_outputs() {
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let transaction_hash = fixed_bytes(LEGACY_TRANSACTION_HASH);
        let block_hash = fixed_bytes(LEGACY_BLOCK_HASH);
        let source = IndexedLogSource {
            block_number: LEGACY_BLOCK_NUMBER,
            block_timestamp: None,
            block_hash,
            transaction_hash,
            log_index: 7,
        };
        let mut batch = IndexedLogBatch {
            transact_commitments: [(14323, fixed_bytes_32(0xa0)), (14324, fixed_bytes_32(0xa1))]
                .into_iter()
                .map(|(tree_position, hash)| IndexedTransactCommitment {
                    tree_number: 0,
                    tree_position,
                    hash,
                    ciphertext: Some(commitment_ciphertext()),
                    source: source.clone(),
                })
                .collect(),
            nullifiers: vec![
                IndexedNullifier {
                    tree_number: 0,
                    nullifier: fixed_bytes_32(0x32),
                    source: source.clone(),
                },
                IndexedNullifier {
                    tree_number: 0,
                    nullifier: fixed_bytes_32(0x42),
                    source: source.clone(),
                },
            ],
            ..IndexedLogBatch::default()
        };
        let calldata = transactCall {
            _transactions: vec![
                railgun_transaction_with_commitments(
                    0x31,
                    vec![fixed_bytes_32(0xa0), fixed_bytes_32(0xa1)],
                    false,
                ),
                railgun_transaction_with_commitments(0x41, vec![fixed_bytes_32(0xb0)], true),
            ],
        }
        .abi_encode();

        asserter.push_success(&transaction_json_with_input(calldata));
        asserter.push_success(&block_json(
            LEGACY_BLOCK_HASH,
            LEGACY_BLOCK_NUMBER,
            1_714_356_419,
            vec![],
        ));

        hydrate_public_transactions(&provider, railgun_contract(), None, &mut batch)
            .await
            .expect("hydrate public transactions");

        assert_eq!(batch.public_transactions.len(), 2);
        assert_eq!(
            batch.public_transactions[0].utxo_batch_start_position_out,
            14323
        );
        assert!(batch.public_transactions[1].has_unshield);
        assert_eq!(
            batch.public_transactions[1].unshield_preimage,
            Some(commitment_preimage(0).abi_encode())
        );
        assert_eq!(
            batch.public_transactions[1].commitments,
            vec![fixed_bytes_32(0xb0)]
        );
        assert_eq!(
            batch.public_transactions[1].utxo_batch_start_position_out,
            14325
        );
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn hydrate_anchors_outputless_modern_unshield_only_row_to_sentinel_position() {
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let transaction_hash = fixed_bytes(LEGACY_TRANSACTION_HASH);
        let block_hash = fixed_bytes(LEGACY_BLOCK_HASH);
        let source = IndexedLogSource {
            block_number: LEGACY_BLOCK_NUMBER,
            block_timestamp: None,
            block_hash,
            transaction_hash,
            log_index: 7,
        };
        let mut batch = IndexedLogBatch {
            nullifiers: vec![IndexedNullifier {
                tree_number: 0,
                nullifier: fixed_bytes_32(0x52),
                source: source.clone(),
            }],
            ..IndexedLogBatch::default()
        };
        let calldata = transactCall {
            _transactions: vec![railgun_transaction_with_commitments(
                0x51,
                vec![fixed_bytes_32(0xb0)],
                true,
            )],
        }
        .abi_encode();

        asserter.push_success(&transaction_json_with_input(calldata));
        asserter.push_success(&block_json(
            LEGACY_BLOCK_HASH,
            LEGACY_BLOCK_NUMBER,
            1_714_356_419,
            vec![],
        ));

        hydrate_public_transactions(&provider, railgun_contract(), None, &mut batch)
            .await
            .expect("hydrate public transactions");

        assert_eq!(batch.public_transactions.len(), 1);
        assert!(batch.public_transactions[0].has_unshield);
        assert_eq!(batch.public_transactions[0].utxo_tree_out, 99_999);
        assert_eq!(
            batch.public_transactions[0].utxo_batch_start_position_out,
            99_999
        );
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn hydrate_uses_legacy_commitment_positions_for_public_transactions() {
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let transaction_hash = fixed_bytes(LEGACY_TRANSACTION_HASH);
        let block_hash = fixed_bytes(LEGACY_BLOCK_HASH);
        let source = IndexedLogSource {
            block_number: LEGACY_BLOCK_NUMBER,
            block_timestamp: None,
            block_hash,
            transaction_hash,
            log_index: 7,
        };
        let mut batch = IndexedLogBatch {
            nullifiers: vec![IndexedNullifier {
                tree_number: 0,
                nullifier: FixedBytes::from([0x99; 32]),
                source: source.clone(),
            }],
            legacy_encrypted_commitments: [
                (4, fixed_bytes_32(0x13)),
                (5, fixed_bytes_32(0x14)),
                (6, fixed_bytes_32(0x24)),
                (7, fixed_bytes_32(0x25)),
            ]
            .into_iter()
            .map(|(tree_position, hash)| IndexedLegacyEncryptedCommitment {
                tree_number: 0,
                tree_position,
                hash,
                ciphertext: legacy_commitment_ciphertext(),
                source: source.clone(),
            })
            .collect(),
            ..IndexedLogBatch::default()
        };
        let transactions = vec![railgun_transaction(0x11), railgun_transaction(0x22)];
        let calldata = transactCall {
            _transactions: transactions,
        }
        .abi_encode();

        asserter.push_success(&transaction_json_with_input(calldata));
        asserter.push_success(&block_json(
            LEGACY_BLOCK_HASH,
            LEGACY_BLOCK_NUMBER,
            1_714_356_419,
            vec![],
        ));

        hydrate_public_transactions(&provider, railgun_contract(), None, &mut batch)
            .await
            .expect("hydrate public transactions");

        assert_eq!(batch.public_transactions.len(), 2);
        assert_eq!(batch.public_transactions[0].utxo_tree_out, 0);
        assert_eq!(
            batch.public_transactions[0].utxo_batch_start_position_out,
            4
        );
        assert_eq!(batch.public_transactions[1].utxo_tree_out, 0);
        assert_eq!(
            batch.public_transactions[1].utxo_batch_start_position_out,
            6
        );
        assert_eq!(batch.public_transactions[0].first_log_index, 7);
        assert_eq!(batch.public_transactions[0].last_log_index, 7);
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn hydrate_offsets_relay_legacy_outputs_after_emitted_batch() {
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let transaction_hash = fixed_bytes(LEGACY_TRANSACTION_HASH);
        let block_hash = fixed_bytes(LEGACY_BLOCK_HASH);
        let source = IndexedLogSource {
            block_number: LEGACY_BLOCK_NUMBER,
            block_timestamp: None,
            block_hash,
            transaction_hash,
            log_index: 7,
        };
        let mut batch = IndexedLogBatch {
            nullifiers: vec![IndexedNullifier {
                tree_number: 0,
                nullifier: FixedBytes::from([0x99; 32]),
                source: source.clone(),
            }],
            legacy_encrypted_commitments: [
                (176, fixed_bytes_32(0xa0)),
                (177, fixed_bytes_32(0xa1)),
                (178, fixed_bytes_32(0xa2)),
            ]
            .into_iter()
            .map(|(tree_position, hash)| IndexedLegacyEncryptedCommitment {
                tree_number: 0,
                tree_position,
                hash,
                ciphertext: legacy_commitment_ciphertext(),
                source: source.clone(),
            })
            .collect(),
            legacy_generated_commitments: vec![IndexedLegacyGeneratedCommitment {
                tree_number: 0,
                tree_position: 179,
                preimage: legacy_commitment_preimage(0x42),
                encrypted_random: [U256::ZERO; 2],
                source: source.clone(),
            }],
            ..IndexedLogBatch::default()
        };
        let calldata = legacy::relayCall {
            _transactions: vec![
                legacy_railgun_transaction(0x11),
                legacy_railgun_transaction(0x22),
            ],
            _random: U256::ZERO,
            _requireSuccess: false,
            _minGas: U256::ZERO,
            _calls: Vec::new(),
        }
        .abi_encode();
        assert_eq!(&hex::encode(&calldata[..4]), "4d2a938f");

        asserter.push_success(&transaction_json_with_input(calldata));
        asserter.push_success(&block_json(
            LEGACY_BLOCK_HASH,
            LEGACY_BLOCK_NUMBER,
            1_714_356_419,
            vec![],
        ));

        hydrate_public_transactions(&provider, railgun_contract(), None, &mut batch)
            .await
            .expect("hydrate public transactions");

        assert_eq!(batch.public_transactions.len(), 2);
        assert_eq!(
            batch.public_transactions[0].utxo_batch_start_position_out,
            179
        );
        assert_eq!(
            batch.public_transactions[1].utxo_batch_start_position_out,
            181
        );
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn hydrate_offsets_generated_relay_unshield_rows_by_emitted_outputs() {
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let transaction_hash = fixed_bytes(LEGACY_TRANSACTION_HASH);
        let block_hash = fixed_bytes(LEGACY_BLOCK_HASH);
        let source = IndexedLogSource {
            block_number: LEGACY_BLOCK_NUMBER,
            block_timestamp: None,
            block_hash,
            transaction_hash,
            log_index: 7,
        };
        let mut batch = IndexedLogBatch {
            nullifiers: vec![IndexedNullifier {
                tree_number: 0,
                nullifier: fixed_bytes_32(0x32),
                source: source.clone(),
            }],
            legacy_encrypted_commitments: [
                (1404, fixed_bytes_32(0xa0)),
                (1405, fixed_bytes_32(0xa1)),
            ]
            .into_iter()
            .map(|(tree_position, hash)| IndexedLegacyEncryptedCommitment {
                tree_number: 0,
                tree_position,
                hash,
                ciphertext: legacy_commitment_ciphertext(),
                source: source.clone(),
            })
            .collect(),
            legacy_generated_commitments: vec![IndexedLegacyGeneratedCommitment {
                tree_number: 0,
                tree_position: 1406,
                preimage: legacy_commitment_preimage(0x42),
                encrypted_random: [U256::ZERO; 2],
                source: source.clone(),
            }],
            ..IndexedLogBatch::default()
        };
        let calldata = legacy::relayCall {
            _transactions: vec![
                legacy_railgun_transaction_with_commitments(
                    0x31,
                    vec![fixed_bytes_32(0xa0), fixed_bytes_32(0xa1)],
                    1,
                ),
                legacy_railgun_transaction_with_commitments(
                    0x32,
                    vec![fixed_bytes_32(0xb0), fixed_bytes_32(0xb1)],
                    1,
                ),
            ],
            _random: U256::ZERO,
            _requireSuccess: false,
            _minGas: U256::ZERO,
            _calls: Vec::new(),
        }
        .abi_encode();
        assert_eq!(&hex::encode(&calldata[..4]), "4d2a938f");

        asserter.push_success(&transaction_json_with_input(calldata));
        asserter.push_success(&block_json(
            LEGACY_BLOCK_HASH,
            LEGACY_BLOCK_NUMBER,
            1_714_356_419,
            vec![],
        ));

        hydrate_public_transactions(&provider, railgun_contract(), None, &mut batch)
            .await
            .expect("hydrate public transactions");

        assert_eq!(batch.public_transactions.len(), 2);
        assert!(batch.public_transactions[0].has_unshield);
        assert_eq!(
            batch.public_transactions[0].utxo_batch_start_position_out,
            1406
        );
        assert!(batch.public_transactions[1].has_unshield);
        assert_eq!(
            batch.public_transactions[1].utxo_batch_start_position_out,
            1407
        );
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn hydrate_anchors_relay_unshield_without_generated_output_to_encrypted_batch() {
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let transaction_hash = fixed_bytes(LEGACY_TRANSACTION_HASH);
        let block_hash = fixed_bytes(LEGACY_BLOCK_HASH);
        let source = IndexedLogSource {
            block_number: LEGACY_BLOCK_NUMBER,
            block_timestamp: None,
            block_hash,
            transaction_hash,
            log_index: 7,
        };
        let mut batch = IndexedLogBatch {
            nullifiers: vec![IndexedNullifier {
                tree_number: 0,
                nullifier: fixed_bytes_32(0x32),
                source: source.clone(),
            }],
            legacy_encrypted_commitments: [
                (214, fixed_bytes_32(0xa0)),
                (215, fixed_bytes_32(0xa1)),
            ]
            .into_iter()
            .map(|(tree_position, hash)| IndexedLegacyEncryptedCommitment {
                tree_number: 0,
                tree_position,
                hash,
                ciphertext: legacy_commitment_ciphertext(),
                source: source.clone(),
            })
            .collect(),
            ..IndexedLogBatch::default()
        };
        let calldata = legacy::relayCall {
            _transactions: vec![legacy_railgun_transaction_with_commitments(
                0x31,
                vec![
                    fixed_bytes_32(0xa0),
                    fixed_bytes_32(0xa1),
                    fixed_bytes_32(0xa2),
                ],
                1,
            )],
            _random: U256::ZERO,
            _requireSuccess: false,
            _minGas: U256::ZERO,
            _calls: Vec::new(),
        }
        .abi_encode();
        assert_eq!(&hex::encode(&calldata[..4]), "4d2a938f");

        asserter.push_success(&transaction_json_with_input(calldata));
        asserter.push_success(&block_json(
            LEGACY_BLOCK_HASH,
            LEGACY_BLOCK_NUMBER,
            1_714_356_419,
            vec![],
        ));

        hydrate_public_transactions(&provider, railgun_contract(), None, &mut batch)
            .await
            .expect("hydrate public transactions");

        assert_eq!(batch.public_transactions.len(), 1);
        assert!(batch.public_transactions[0].has_unshield);
        assert_eq!(
            batch.public_transactions[0].utxo_batch_start_position_out,
            214
        );
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn hydrate_offsets_encrypted_only_relay_unshield_rows_by_emitted_outputs() {
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let transaction_hash = fixed_bytes(LEGACY_TRANSACTION_HASH);
        let block_hash = fixed_bytes(LEGACY_BLOCK_HASH);
        let source = IndexedLogSource {
            block_number: LEGACY_BLOCK_NUMBER,
            block_timestamp: None,
            block_hash,
            transaction_hash,
            log_index: 7,
        };
        let mut batch = IndexedLogBatch {
            nullifiers: vec![IndexedNullifier {
                tree_number: 0,
                nullifier: fixed_bytes_32(0x32),
                source: source.clone(),
            }],
            legacy_encrypted_commitments: [
                (328, fixed_bytes_32(0xa0)),
                (329, fixed_bytes_32(0xa1)),
                (330, fixed_bytes_32(0xb0)),
                (331, fixed_bytes_32(0xc0)),
            ]
            .into_iter()
            .map(|(tree_position, hash)| IndexedLegacyEncryptedCommitment {
                tree_number: 0,
                tree_position,
                hash,
                ciphertext: legacy_commitment_ciphertext(),
                source: source.clone(),
            })
            .collect(),
            ..IndexedLogBatch::default()
        };
        let calldata = legacy::relayCall {
            _transactions: vec![
                legacy_railgun_transaction_with_commitments(
                    0x31,
                    vec![fixed_bytes_32(0xa0), fixed_bytes_32(0xa1)],
                    0,
                ),
                legacy_railgun_transaction_with_commitments(
                    0x32,
                    vec![fixed_bytes_32(0xb0), fixed_bytes_32(0xb1)],
                    1,
                ),
                legacy_railgun_transaction_with_commitments(
                    0x33,
                    vec![fixed_bytes_32(0xc0), fixed_bytes_32(0xc1)],
                    1,
                ),
            ],
            _random: U256::ZERO,
            _requireSuccess: false,
            _minGas: U256::ZERO,
            _calls: Vec::new(),
        }
        .abi_encode();
        assert_eq!(&hex::encode(&calldata[..4]), "4d2a938f");

        asserter.push_success(&transaction_json_with_input(calldata));
        asserter.push_success(&block_json(
            LEGACY_BLOCK_HASH,
            LEGACY_BLOCK_NUMBER,
            1_714_356_419,
            vec![],
        ));

        hydrate_public_transactions(&provider, railgun_contract(), None, &mut batch)
            .await
            .expect("hydrate public transactions");

        assert_eq!(batch.public_transactions.len(), 3);
        assert_eq!(
            batch.public_transactions[0].utxo_batch_start_position_out,
            328
        );
        assert!(batch.public_transactions[1].has_unshield);
        assert_eq!(
            batch.public_transactions[1].utxo_batch_start_position_out,
            330
        );
        assert!(batch.public_transactions[2].has_unshield);
        assert_eq!(
            batch.public_transactions[2].utxo_batch_start_position_out,
            331
        );
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn hydrate_decodes_legacy_transact_calldata() {
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let transaction_hash = fixed_bytes(LEGACY_TRANSACTION_HASH);
        let block_hash = fixed_bytes(LEGACY_BLOCK_HASH);
        let source = IndexedLogSource {
            block_number: LEGACY_BLOCK_NUMBER,
            block_timestamp: None,
            block_hash,
            transaction_hash,
            log_index: 7,
        };
        let mut batch = IndexedLogBatch {
            nullifiers: vec![IndexedNullifier {
                tree_number: 0,
                nullifier: FixedBytes::from([0x13; 32]),
                source: source.clone(),
            }],
            legacy_encrypted_commitments: [(4, fixed_bytes_32(0x14)), (5, fixed_bytes_32(0x15))]
                .into_iter()
                .map(|(tree_position, hash)| IndexedLegacyEncryptedCommitment {
                    tree_number: 0,
                    tree_position,
                    hash,
                    ciphertext: legacy_commitment_ciphertext(),
                    source: source.clone(),
                })
                .collect(),
            ..IndexedLogBatch::default()
        };
        let calldata = legacy::transactCall {
            _transactions: vec![legacy_railgun_transaction(0x12)],
        }
        .abi_encode();
        assert_eq!(&hex::encode(&calldata[..4]), "4489999c");

        asserter.push_success(&transaction_json_with_input(calldata));
        asserter.push_success(&block_json(
            LEGACY_BLOCK_HASH,
            LEGACY_BLOCK_NUMBER,
            1_714_356_419,
            vec![],
        ));

        hydrate_public_transactions(&provider, railgun_contract(), None, &mut batch)
            .await
            .expect("hydrate public transactions");

        assert_eq!(batch.public_transactions.len(), 1);
        assert_eq!(
            batch.public_transactions[0].nullifiers,
            vec![fixed_bytes_32(0x13)]
        );
        assert_eq!(
            batch.public_transactions[0].commitments,
            vec![fixed_bytes_32(0x14), fixed_bytes_32(0x15)]
        );
        assert_eq!(batch.public_transactions[0].utxo_tree_in, 0);
        assert_eq!(
            batch.public_transactions[0].utxo_batch_start_position_out,
            4
        );
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn hydrate_anchors_legacy_outputs_after_matching_nullifier_log() {
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let transaction_hash = fixed_bytes(LEGACY_TRANSACTION_HASH);
        let block_hash = fixed_bytes(LEGACY_BLOCK_HASH);
        let source = |log_index| IndexedLogSource {
            block_number: LEGACY_BLOCK_NUMBER,
            block_timestamp: None,
            block_hash,
            transaction_hash,
            log_index,
        };
        let mut batch = IndexedLogBatch {
            nullifiers: vec![IndexedNullifier {
                tree_number: 0,
                nullifier: fixed_bytes_32(0x32),
                source: source(1),
            }],
            legacy_encrypted_commitments: [
                (0, 176, fixed_bytes_32(0x33)),
                (0, 177, fixed_bytes_32(0x34)),
                (2, 178, fixed_bytes_32(0x99)),
                (2, 179, fixed_bytes_32(0x33)),
                (2, 180, fixed_bytes_32(0x34)),
            ]
            .into_iter()
            .map(
                |(log_index, tree_position, hash)| IndexedLegacyEncryptedCommitment {
                    tree_number: 0,
                    tree_position,
                    hash,
                    ciphertext: legacy_commitment_ciphertext(),
                    source: source(log_index),
                },
            )
            .collect(),
            ..IndexedLogBatch::default()
        };
        let calldata = legacy::transactCall {
            _transactions: vec![legacy_railgun_transaction(0x31)],
        }
        .abi_encode();

        asserter.push_success(&transaction_json_with_input(calldata));
        asserter.push_success(&block_json(
            LEGACY_BLOCK_HASH,
            LEGACY_BLOCK_NUMBER,
            1_714_356_419,
            vec![],
        ));

        hydrate_public_transactions(&provider, railgun_contract(), None, &mut batch)
            .await
            .expect("hydrate public transactions");

        assert_eq!(batch.public_transactions.len(), 1);
        assert_eq!(batch.public_transactions[0].first_log_index, 1);
        assert_eq!(batch.public_transactions[0].last_log_index, 2);
        assert_eq!(
            batch.public_transactions[0].utxo_batch_start_position_out,
            179
        );
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn hydrate_uses_traces_for_committed_wrapped_railgun_calls() {
        let railgun_calldata = transactCall {
            _transactions: vec![railgun_transaction(0x11)],
        }
        .abi_encode();
        let reverted_calldata = transactCall {
            _transactions: vec![railgun_transaction(0x22)],
        }
        .abi_encode();
        let successful_call = json!({
            "type": "CALL",
            "to": railgun_contract().to_string(),
            "input": hex::encode_prefixed(&railgun_calldata),
            "error": null,
        });
        let reverted_call = json!({
            "type": "CALL",
            "to": railgun_contract().to_string(),
            "input": hex::encode_prefixed(&reverted_calldata),
            "error": "execution reverted",
        });
        let debug_trace = json!({
            "type": "CALL",
            "to": "0x1111111111111111111111111111111111111111",
            "input": "0xdeadbeef",
            "calls": [successful_call, reverted_call, {
                "type": "CALL",
                "to": "0x1111111111111111111111111111111111111111",
                "input": "0xdeadbeef",
                "error": "execution reverted",
                "calls": [successful_call],
            }],
        });
        let flat_trace = json!([
            {
                "type": "call",
                "action": successful_call,
                "traceAddress": [0],
                "error": null,
            },
            {
                "type": "call",
                "action": reverted_call,
                "traceAddress": [1],
                "error": "Reverted",
            },
            {
                "type": "call",
                "action": successful_call,
                "traceAddress": [2, 0],
            },
            {
                "type": "call",
                "action": {
                    "to": "0x1111111111111111111111111111111111111111",
                    "input": "0xdeadbeef",
                },
                "traceAddress": [2],
                "error": "Reverted",
            },
        ]);

        for use_flat_trace in [false, true] {
            let asserter = Asserter::new();
            let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
            let transaction_hash = fixed_bytes(LEGACY_TRANSACTION_HASH);
            let block_hash = fixed_bytes(LEGACY_BLOCK_HASH);
            let mut batch = transact_batch(transaction_hash, block_hash, LEGACY_BLOCK_NUMBER);

            asserter.push_success(&transaction_json_with_input(vec![0xde, 0xad, 0xbe, 0xef]));
            asserter.push_success(&block_json(
                LEGACY_BLOCK_HASH,
                LEGACY_BLOCK_NUMBER,
                1_714_356_419,
                vec![],
            ));
            if use_flat_trace {
                asserter.push_success(&Value::Null);
                asserter.push_success(&flat_trace);
            } else {
                asserter.push_success(&debug_trace);
            }

            hydrate_public_transactions(&provider, railgun_contract(), None, &mut batch)
                .await
                .expect("hydrate only committed public transactions");

            assert_eq!(batch.public_transactions.len(), 1);
            assert_eq!(
                batch.public_transactions[0].nullifiers,
                vec![fixed_bytes_32(0x12)]
            );
            assert_eq!(batch.public_transactions[0].railgun_transaction_index, 0);
            assert!(asserter.read_q().is_empty());
        }
    }

    #[tokio::test]
    async fn hydrate_traces_relay_actions_with_additional_public_transactions() {
        let initial_transaction = railgun_transaction(0x11);
        let additional_transaction =
            railgun_transaction_with_commitments(0x22, vec![fixed_bytes_32(0x24)], false);
        let initial_calldata = transactCall {
            _transactions: vec![initial_transaction.clone()],
        }
        .abi_encode();
        let additional_calldata = transactCall {
            _transactions: vec![additional_transaction.clone()],
        }
        .abi_encode();
        let action_contract = Address::from([0x11; 20]);
        let relay_calldata = relayCall {
            _transactions: vec![initial_transaction.clone()],
            _actionData: ActionData {
                random: FixedBytes::ZERO,
                requireSuccess: true,
                minGasLimit: U256::ZERO,
                calls: vec![Call {
                    to: action_contract,
                    data: Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]),
                    value: U256::ZERO,
                }],
            },
        }
        .abi_encode();
        let transaction = transaction_json_with_input(relay_calldata.clone());
        let trace = json!({
            "type": "CALL",
            "to": "0x2222222222222222222222222222222222222222",
            "input": hex::encode_prefixed(&relay_calldata),
            "calls": [{
                "type": "CALL",
                "to": railgun_contract().to_string(),
                "input": hex::encode_prefixed(initial_calldata),
            }, {
                "type": "CALL",
                "to": action_contract.to_string(),
                "input": "0xdeadbeef",
                "calls": [{
                    "type": "CALL",
                    "to": railgun_contract().to_string(),
                    "input": hex::encode_prefixed(additional_calldata),
                }],
            }],
        });
        let mut logs = vec![
            log_for(Nullified {
                treeNumber: 0,
                nullifier: initial_transaction.nullifiers,
            }),
            log_for(Transact {
                treeNumber: U256::ONE,
                startPosition: U256::ZERO,
                hash: initial_transaction.commitments,
                ciphertext: vec![commitment_ciphertext(); 2],
            }),
            log_for(Nullified {
                treeNumber: 0,
                nullifier: additional_transaction.nullifiers,
            }),
            log_for(Transact {
                treeNumber: U256::ONE,
                startPosition: U256::from(2),
                hash: additional_transaction.commitments,
                ciphertext: vec![commitment_ciphertext()],
            }),
        ];
        for (index, log) in logs.iter_mut().enumerate() {
            log.block_hash = Some(fixed_bytes(LEGACY_BLOCK_HASH));
            log.block_number = Some(LEGACY_BLOCK_NUMBER);
            log.transaction_hash = Some(fixed_bytes(LEGACY_TRANSACTION_HASH));
            log.log_index = Some(u64::try_from(index).expect("log index") + 7);
        }

        for use_full_block in [false, true] {
            let asserter = Asserter::new();
            let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
            let mut batch = ingest_chain_logs(&logs).expect("ingest relay and action logs");
            if use_full_block {
                asserter.push_success(&Value::Null);
            } else {
                asserter.push_success(&transaction);
            }
            asserter.push_success(&block_json(
                LEGACY_BLOCK_HASH,
                LEGACY_BLOCK_NUMBER,
                1_714_356_419,
                if use_full_block {
                    vec![transaction.clone()]
                } else {
                    vec![]
                },
            ));
            asserter.push_success(&trace);

            hydrate_public_transactions(&provider, railgun_contract(), None, &mut batch)
                .await
                .expect("hydrate relay and action public transactions");

            assert_eq!(batch.public_transactions.len(), 2);
            assert_eq!(
                batch.public_transactions[0].nullifiers,
                vec![fixed_bytes_32(0x12)]
            );
            assert_eq!(
                batch.public_transactions[1].nullifiers,
                vec![fixed_bytes_32(0x23)]
            );
            assert_eq!(batch.public_transactions[0].railgun_transaction_index, 0);
            assert_eq!(batch.public_transactions[1].railgun_transaction_index, 1);
            assert_eq!(
                batch.public_transactions[0].utxo_batch_start_position_out,
                0
            );
            assert_eq!(
                batch.public_transactions[1].utxo_batch_start_position_out,
                2
            );
            assert!(asserter.read_q().is_empty());
        }
    }

    #[tokio::test]
    async fn resolves_unshield_preimage_from_direct_transaction_by_hash() {
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let transaction_hash = fixed_bytes(LEGACY_TRANSACTION_HASH);
        let calldata = transactCall {
            _transactions: vec![railgun_transaction_with_commitments(
                0x41,
                vec![fixed_bytes_32(0xb0)],
                true,
            )],
        }
        .abi_encode();
        asserter.push_success(&transaction_json_with_input(calldata));

        let resolved =
            resolve_public_transactions_by_hash(&provider, railgun_contract(), transaction_hash)
                .await
                .expect("resolve direct transaction");

        assert_eq!(resolved.len(), 1);
        assert!(resolved[0].has_unshield);
        assert_eq!(
            resolved[0].unshield_preimage,
            Some(commitment_preimage(0).abi_encode())
        );
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn resolves_unshield_preimage_from_wrapped_transaction_trace() {
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let transaction_hash = fixed_bytes(LEGACY_TRANSACTION_HASH);
        let railgun_calldata = transactCall {
            _transactions: vec![railgun_transaction_with_commitments(
                0x41,
                vec![fixed_bytes_32(0xb0)],
                true,
            )],
        }
        .abi_encode();
        asserter.push_success(&transaction_json_with_input(vec![0xde, 0xad, 0xbe, 0xef]));
        asserter.push_success(&json!({
            "type": "CALL",
            "to": "0x1111111111111111111111111111111111111111",
            "input": "0xdeadbeef",
            "calls": [{
                "type": "CALL",
                "to": railgun_contract().to_string(),
                "input": hex::encode_prefixed(railgun_calldata),
            }],
        }));

        let resolved =
            resolve_public_transactions_by_hash(&provider, railgun_contract(), transaction_hash)
                .await
                .expect("resolve wrapped transaction");

        assert_eq!(resolved.len(), 1);
        assert!(resolved[0].has_unshield);
        assert_eq!(
            resolved[0].unshield_preimage,
            Some(commitment_preimage(0).abi_encode())
        );
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn hydrate_matches_legacy_unshield_rows_to_emitted_commitments() {
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let transaction_hash = fixed_bytes(LEGACY_TRANSACTION_HASH);
        let block_hash = fixed_bytes(LEGACY_BLOCK_HASH);
        let source = IndexedLogSource {
            block_number: LEGACY_BLOCK_NUMBER,
            block_timestamp: None,
            block_hash,
            transaction_hash,
            log_index: 7,
        };
        let mut batch = IndexedLogBatch {
            nullifiers: vec![
                IndexedNullifier {
                    tree_number: 0,
                    nullifier: FixedBytes::from([0x32; 32]),
                    source: source.clone(),
                },
                IndexedNullifier {
                    tree_number: 0,
                    nullifier: FixedBytes::from([0x33; 32]),
                    source: IndexedLogSource {
                        log_index: 9,
                        ..source.clone()
                    },
                },
                IndexedNullifier {
                    tree_number: 0,
                    nullifier: FixedBytes::from([0x34; 32]),
                    source: IndexedLogSource {
                        log_index: 11,
                        ..source.clone()
                    },
                },
            ],
            legacy_encrypted_commitments: [
                (8, 102, fixed_bytes_32(0xa0)),
                (8, 103, fixed_bytes_32(0xa1)),
                (10, 104, fixed_bytes_32(0xb0)),
                (12, 105, fixed_bytes_32(0xc0)),
            ]
            .into_iter()
            .map(
                |(log_index, tree_position, hash)| IndexedLegacyEncryptedCommitment {
                    tree_number: 0,
                    tree_position,
                    hash,
                    ciphertext: legacy_commitment_ciphertext(),
                    source: IndexedLogSource {
                        log_index,
                        ..source.clone()
                    },
                },
            )
            .collect(),
            ..IndexedLogBatch::default()
        };
        let calldata = legacy::transactCall {
            _transactions: vec![
                legacy_railgun_transaction_with_commitments(
                    0x31,
                    vec![fixed_bytes_32(0xa0), fixed_bytes_32(0xa1)],
                    0,
                ),
                legacy_railgun_transaction_with_commitments(
                    0x32,
                    vec![fixed_bytes_32(0xb0), fixed_bytes_32(0xb1)],
                    1,
                ),
                legacy_railgun_transaction_with_commitments(
                    0x33,
                    vec![fixed_bytes_32(0xc0), fixed_bytes_32(0xc1)],
                    1,
                ),
            ],
        }
        .abi_encode();

        asserter.push_success(&transaction_json_with_input(calldata));
        asserter.push_success(&block_json(
            LEGACY_BLOCK_HASH,
            LEGACY_BLOCK_NUMBER,
            1_714_356_419,
            vec![],
        ));

        hydrate_public_transactions(&provider, railgun_contract(), None, &mut batch)
            .await
            .expect("hydrate public transactions");

        assert_eq!(batch.public_transactions.len(), 3);
        assert_eq!(
            batch.public_transactions[0].utxo_batch_start_position_out,
            102
        );
        assert_eq!(
            batch.public_transactions[1].utxo_batch_start_position_out,
            104
        );
        assert_eq!(
            batch.public_transactions[2].utxo_batch_start_position_out,
            105
        );
        assert_eq!(
            batch.public_transactions[1].unshield_preimage,
            Some(
                CommitmentPreimage {
                    npk: FixedBytes::ZERO,
                    token: token_data(),
                    value: Uint::<120, 2>::ZERO,
                }
                .abi_encode()
            )
        );
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn hydrate_uses_legacy_generated_commitment_as_unshield_output_start() {
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let transaction_hash = fixed_bytes(LEGACY_TRANSACTION_HASH);
        let block_hash = fixed_bytes(LEGACY_BLOCK_HASH);
        let source = IndexedLogSource {
            block_number: LEGACY_BLOCK_NUMBER,
            block_timestamp: None,
            block_hash,
            transaction_hash,
            log_index: 7,
        };
        let generated_preimage = legacy_commitment_preimage(0x42);
        assert_ne!(
            FixedBytes::from(generated_preimage.hash().to_be_bytes::<32>()),
            fixed_bytes_32(0xc0)
        );
        let mut batch = IndexedLogBatch {
            nullifiers: vec![IndexedNullifier {
                tree_number: 0,
                nullifier: FixedBytes::from([0x32; 32]),
                source: source.clone(),
            }],
            legacy_encrypted_commitments: [
                (266, fixed_bytes_32(0xa0)),
                (267, fixed_bytes_32(0xb0)),
            ]
            .into_iter()
            .map(|(tree_position, hash)| IndexedLegacyEncryptedCommitment {
                tree_number: 0,
                tree_position,
                hash,
                ciphertext: legacy_commitment_ciphertext(),
                source: source.clone(),
            })
            .collect(),
            legacy_generated_commitments: vec![IndexedLegacyGeneratedCommitment {
                tree_number: 0,
                tree_position: 268,
                preimage: generated_preimage,
                encrypted_random: [U256::ZERO; 2],
                source: source.clone(),
            }],
            ..IndexedLogBatch::default()
        };
        let calldata = legacy::transactCall {
            _transactions: vec![legacy_railgun_transaction_with_commitments(
                0x31,
                vec![
                    fixed_bytes_32(0xa0),
                    fixed_bytes_32(0xb0),
                    fixed_bytes_32(0xc0),
                ],
                1,
            )],
        }
        .abi_encode();

        asserter.push_success(&transaction_json_with_input(calldata));
        asserter.push_success(&block_json(
            LEGACY_BLOCK_HASH,
            LEGACY_BLOCK_NUMBER,
            1_714_356_419,
            vec![],
        ));

        hydrate_public_transactions(&provider, railgun_contract(), None, &mut batch)
            .await
            .expect("hydrate public transactions");

        assert_eq!(batch.public_transactions.len(), 1);
        assert_eq!(
            batch.public_transactions[0].commitments,
            vec![
                fixed_bytes_32(0xa0),
                fixed_bytes_32(0xb0),
                fixed_bytes_32(0xc0),
            ]
        );
        assert_eq!(
            batch.public_transactions[0].utxo_batch_start_position_out,
            268
        );
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn hydrate_reports_context_when_transaction_is_missing_from_lookup_and_block() {
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let transaction_hash = fixed_bytes(LEGACY_TRANSACTION_HASH);
        let block_hash = fixed_bytes(LEGACY_BLOCK_HASH);
        let mut batch = transact_batch(transaction_hash, block_hash, LEGACY_BLOCK_NUMBER);

        asserter.push_success(&Value::Null);
        asserter.push_success(&block_json(
            LEGACY_BLOCK_HASH,
            LEGACY_BLOCK_NUMBER,
            1_714_356_419,
            vec![],
        ));

        let error = hydrate_public_transactions(&provider, railgun_contract(), None, &mut batch)
            .await
            .expect_err("missing transaction should fail");

        let message = error.to_string();
        assert!(message.contains(LEGACY_TRANSACTION_HASH));
        assert!(message.contains(&LEGACY_BLOCK_NUMBER.to_string()));
        assert!(message.contains(LEGACY_BLOCK_HASH));
    }

    #[tokio::test]
    async fn action_logs_match_calldata_for_direct_transact() {
        let transactions = vec![
            railgun_transaction(0x11),
            unshield_railgun_transaction(0x21, vec![fixed_bytes_32(0x24)]),
        ];
        let calldata = transactCall {
            _transactions: transactions.clone(),
        }
        .abi_encode();

        assert_action_log_rows_match_calldata(calldata, railgun_call_logs(&transactions, 3)).await;
    }

    #[tokio::test]
    async fn action_logs_match_calldata_for_relay_adapt_7702_batch_and_skip_shield_action() {
        let transactions = vec![
            railgun_transaction(0x31),
            unshield_railgun_transaction(0x41, vec![fixed_bytes_32(0x44)]),
            railgun_transaction(0x51),
        ];
        let calldata = executeCall {
            _transactions: transactions.clone(),
            _actionData: RelayAdapt7702ActionData {
                requireSuccess: true,
                minGasLimit: U256::ZERO,
                calls: Vec::new(),
            },
            _signature: Bytes::new(),
        }
        .abi_encode();
        let mut logs = railgun_call_logs(&transactions, 3);
        // The relayed action shields its proceeds; shield's empty Action yields no row.
        logs.push(log_for(Action {
            caller: Address::ZERO,
            txconfigs: Vec::new(),
        }));
        logs.push(log_for(Shield {
            treeNumber: U256::ZERO,
            startPosition: U256::from(8),
            commitments: vec![commitment_preimage(0x61)],
            shieldCiphertext: vec![shield_ciphertext()],
            fees: vec![U256::ZERO],
        }));

        let rows = assert_action_log_rows_match_calldata(calldata, logs).await;

        assert_eq!(rows.len(), 3);
    }

    #[tokio::test]
    async fn action_logs_match_calldata_for_unshield_only_transaction() {
        let transactions = vec![unshield_railgun_transaction(0x61, Vec::new())];
        let calldata = transactCall {
            _transactions: transactions.clone(),
        }
        .abi_encode();

        let rows =
            assert_action_log_rows_match_calldata(calldata, railgun_call_logs(&transactions, 3))
                .await;

        assert_eq!(rows[0].utxo_tree_out, 99_999);
    }

    #[tokio::test]
    async fn action_logs_match_calldata_for_relayed_transaction_without_unshield() {
        let transactions = vec![railgun_transaction(0x71)];
        let calldata = relayCall {
            _transactions: transactions.clone(),
            _actionData: ActionData {
                random: FixedBytes::ZERO,
                requireSuccess: true,
                minGasLimit: U256::ZERO,
                calls: Vec::new(),
            },
        }
        .abi_encode();

        assert_action_log_rows_match_calldata(calldata, railgun_call_logs(&transactions, 3)).await;
    }

    #[tokio::test]
    async fn action_logs_order_nested_call_rows_by_action() {
        let parent = railgun_transaction(0x91);
        let child = railgun_transaction(0xa1);
        // The child call runs inside the parent's Action window and inserts its outputs first.
        let mut logs = railgun_call_logs(std::slice::from_ref(&parent), 5);
        let parent_transact = logs.pop().expect("parent Transact log");
        logs.extend(railgun_call_logs(std::slice::from_ref(&child), 3));
        logs.push(parent_transact);
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let mut batch = ingest_chain_logs(&with_log_metadata(logs)).expect("ingest logs");
        asserter.push_success(&block_json(
            LEGACY_BLOCK_HASH,
            LEGACY_BLOCK_NUMBER,
            1_714_356_419,
            vec![],
        ));

        hydrate_public_transactions(
            &provider,
            railgun_contract(),
            Some(LEGACY_BLOCK_NUMBER),
            &mut batch,
        )
        .await
        .expect("hydrate nested Railgun calls");

        assert_eq!(batch.public_transactions.len(), 2);
        for (index, (transaction, output_start)) in
            [(&parent, 5_u64), (&child, 3_u64)].into_iter().enumerate()
        {
            let row = &batch.public_transactions[index];
            assert_eq!(
                row.railgun_transaction_index,
                u64::try_from(index).expect("index")
            );
            assert_eq!(row.id, format!("{LEGACY_TRANSACTION_HASH}:{index}"));
            assert_eq!(row.nullifiers, transaction.nullifiers);
            assert_eq!(row.utxo_tree_out, 0);
            assert_eq!(row.utxo_batch_start_position_out, output_start);
            assert_eq!(
                row.railgun_txid,
                compute_railgun_txid(transaction, Some(DEFAULT_TXID_VERSION)).expect("txid")
            );
        }
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn action_logs_match_outputs_per_railgun_call() {
        let call_a = unshield_railgun_transaction(0x11, Vec::new());
        let call_b = [
            railgun_transaction(0x21),
            unshield_railgun_transaction(0x31, Vec::new()),
        ];
        let call_c = railgun_transaction_with_commitments(0x41, vec![fixed_bytes_32(0x43)], false);
        // Call A emits no Transact, and a shield inserts between calls B and C.
        let mut logs = railgun_call_logs(std::slice::from_ref(&call_a), 0);
        logs.extend(railgun_call_logs(&call_b, 3));
        logs.push(log_for(Action {
            caller: Address::ZERO,
            txconfigs: Vec::new(),
        }));
        logs.push(log_for(Shield {
            treeNumber: U256::ZERO,
            startPosition: U256::from(5),
            commitments: vec![commitment_preimage(0x61)],
            shieldCiphertext: vec![shield_ciphertext()],
            fees: vec![U256::ZERO],
        }));
        logs.extend(railgun_call_logs(std::slice::from_ref(&call_c), 6));
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let mut batch = ingest_chain_logs(&with_log_metadata(logs)).expect("ingest logs");
        asserter.push_success(&transaction_json_with_input(
            transactCall {
                _transactions: vec![call_a.clone(), call_b[0].clone(), call_b[1].clone()],
            }
            .abi_encode(),
        ));
        asserter.push_success(&block_json(
            LEGACY_BLOCK_HASH,
            LEGACY_BLOCK_NUMBER,
            1_714_356_419,
            vec![],
        ));

        hydrate_public_transactions(
            &provider,
            railgun_contract(),
            Some(LEGACY_BLOCK_NUMBER),
            &mut batch,
        )
        .await
        .expect("hydrate Railgun calls");

        assert_eq!(batch.public_transactions.len(), 4);
        for (index, (transaction, utxo_tree_out, output_start)) in [
            (&call_a, 99_999_u64, 99_999_u64),
            (&call_b[0], 0, 3),
            (&call_b[1], 0, 5),
            (&call_c, 0, 6),
        ]
        .into_iter()
        .enumerate()
        {
            let row = &batch.public_transactions[index];
            assert_eq!(
                row.railgun_transaction_index,
                u64::try_from(index).expect("index")
            );
            assert_eq!(row.id, format!("{LEGACY_TRANSACTION_HASH}:{index}"));
            assert_eq!(row.nullifiers, transaction.nullifiers);
            assert_eq!(row.utxo_tree_out, utxo_tree_out);
            assert_eq!(row.utxo_batch_start_position_out, output_start);
            assert_eq!(
                row.railgun_txid,
                compute_railgun_txid(transaction, Some(DEFAULT_TXID_VERSION)).expect("txid")
            );
        }
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn action_logs_with_mismatched_counts_stop_with_typed_errors() {
        let transactions = vec![unshield_railgun_transaction(
            0x81,
            vec![fixed_bytes_32(0x84)],
        )];
        let logs = railgun_call_logs(&transactions, 3);
        let action_with = |change: fn(&mut TXConfig)| {
            let mut config = tx_config(&transactions[0]);
            change(&mut config);
            log_for(Action {
                caller: Address::ZERO,
                txconfigs: vec![config],
            })
        };
        let mut missing_unshield = logs.clone();
        missing_unshield.remove(2);
        let mut extra_nullifier = logs.clone();
        extra_nullifier[1] = action_with(|config| config.nullifiersCount += 1);
        let mut extra_commitment = logs.clone();
        extra_commitment[1] = action_with(|config| config.commitmentsCount += 1);

        for logs in [missing_unshield, extra_nullifier, extra_commitment] {
            let asserter = Asserter::new();
            let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
            let mut batch = ingest_chain_logs(&with_log_metadata(logs)).expect("ingest logs");
            asserter.push_success(&block_json(
                LEGACY_BLOCK_HASH,
                LEGACY_BLOCK_NUMBER,
                1_714_356_419,
                vec![],
            ));

            let error = hydrate_public_transactions(
                &provider,
                railgun_contract(),
                Some(LEGACY_BLOCK_NUMBER),
                &mut batch,
            )
            .await
            .expect_err("mismatched Action logs should fail");

            let (ChainLogIngestionError::MissingActionUnshield {
                transaction_hash,
                block_number,
                ..
            }
            | ChainLogIngestionError::ActionNullifierCountMismatch {
                transaction_hash,
                block_number,
                ..
            }
            | ChainLogIngestionError::ActionCommitmentCountMismatch {
                transaction_hash,
                block_number,
                ..
            }) = error
            else {
                panic!("unexpected error: {error:?}");
            };
            assert_eq!(transaction_hash, fixed_bytes(LEGACY_TRANSACTION_HASH));
            assert_eq!(block_number, LEGACY_BLOCK_NUMBER);
            assert!(batch.public_transactions.is_empty());
        }
    }

    #[tokio::test]
    async fn action_logs_take_nested_calldata_unshield_over_differing_log_derivation() {
        let mut transaction = unshield_railgun_transaction(0x21, vec![fixed_bytes_32(0x24)]);
        // `Unshield.to` truncates an npk above 160 bits, so the log derivation differs.
        transaction.unshieldPreimage.npk = FixedBytes::left_padding_from(&[0x01; 25]);
        *transaction
            .commitments
            .last_mut()
            .expect("unshield commitment") =
            fixed_bytes_from_u256(transaction.unshieldPreimage.hash());
        let multicall = RelayAdapt7702::multicallCall {
            _requireSuccess: true,
            _calls: vec![Call {
                to: railgun_contract(),
                data: transactCall {
                    _transactions: vec![transaction.clone()],
                }
                .abi_encode()
                .into(),
                value: U256::ZERO,
            }],
            _nonce: U256::ZERO,
            _signature: Bytes::new(),
        };
        let calldata = nested::handleOpsCall {
            ops: vec![nested::PackedUserOperation {
                sender: Address::ZERO,
                nonce: U256::ZERO,
                initCode: Bytes::new(),
                callData: multicall.abi_encode().into(),
                accountGasLimits: FixedBytes::ZERO,
                preVerificationGas: U256::ZERO,
                gasFees: FixedBytes::ZERO,
                paymasterAndData: Bytes::new(),
                signature: Bytes::new(),
            }],
            beneficiary: Address::ZERO,
        }
        .abi_encode();
        assert_eq!(nested::handleOpsCall::SELECTOR, [0x76, 0x5e, 0x82, 0x7f]);
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let mut batch = ingest_chain_logs(&with_log_metadata(railgun_call_logs(
            std::slice::from_ref(&transaction),
            3,
        )))
        .expect("ingest logs");
        asserter.push_success(&transaction_json_with_input(calldata));
        asserter.push_success(&block_json(
            LEGACY_BLOCK_HASH,
            LEGACY_BLOCK_NUMBER,
            1_714_356_419,
            vec![],
        ));

        hydrate_public_transactions(
            &provider,
            railgun_contract(),
            Some(LEGACY_BLOCK_NUMBER),
            &mut batch,
        )
        .await
        .expect("hydrate nested unshield calldata");

        let [row] = batch.public_transactions.as_slice() else {
            panic!("expected one row");
        };
        assert_eq!(row.commitments, transaction.commitments);
        assert_eq!(
            row.unshield_preimage,
            Some(transaction.unshieldPreimage.abi_encode())
        );
        assert_eq!(
            row.railgun_txid,
            compute_railgun_txid(&transaction, Some(DEFAULT_TXID_VERSION)).expect("txid")
        );
        assert_eq!(
            (
                batch.unshield_log_divergences,
                batch.unshield_log_derivations
            ),
            (1, 0)
        );
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn action_logs_derive_undecodable_unshield_from_logs_without_traces() {
        let transaction = unshield_railgun_transaction(0x61, vec![fixed_bytes_32(0x64)]);
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let mut batch = ingest_chain_logs(&with_log_metadata(railgun_call_logs(
            std::slice::from_ref(&transaction),
            3,
        )))
        .expect("ingest logs");
        // An unknown selector, where the pre-activation path would fall back to traces.
        asserter.push_success(&transaction_json_with_input(vec![0xde, 0xad, 0xbe, 0xef]));
        asserter.push_success(&block_json(
            LEGACY_BLOCK_HASH,
            LEGACY_BLOCK_NUMBER,
            1_714_356_419,
            vec![],
        ));

        hydrate_public_transactions(
            &provider,
            railgun_contract(),
            Some(LEGACY_BLOCK_NUMBER),
            &mut batch,
        )
        .await
        .expect("hydrate undecodable unshield calldata");

        // Only the transaction and block responses were queued, so a trace request would have
        // taken one of them and left hydration without a response.
        assert!(asserter.read_q().is_empty());
        let [row] = batch.public_transactions.as_slice() else {
            panic!("expected one row");
        };
        let preimage = CommitmentPreimage::abi_decode(
            row.unshield_preimage.as_deref().expect("unshield preimage"),
        )
        .expect("decode unshield preimage");
        assert_eq!(
            row.commitments.last(),
            Some(&fixed_bytes_from_u256(preimage.hash()))
        );
        assert_eq!(
            (
                batch.unshield_log_derivations,
                batch.unshield_log_divergences
            ),
            (1, 0)
        );
    }

    #[tokio::test]
    async fn action_logs_stop_on_ambiguous_or_contradicting_unshield_calldata() {
        let transaction = unshield_railgun_transaction(0x81, vec![fixed_bytes_32(0x84)]);
        let logs = with_log_metadata(railgun_call_logs(std::slice::from_ref(&transaction), 3));
        let mut other_tree = transaction.clone();
        other_tree.boundParams.treeNumber = 1;
        let mut other_output = transaction.clone();
        other_output.commitments[0] = fixed_bytes_32(0x85);

        for (calldata_transactions, expected_matches, expected_field) in [
            (vec![transaction.clone(), transaction], Some(2), None),
            (vec![railgun_transaction(0x91)], Some(0), None),
            (vec![other_tree], None, Some("tree number")),
            (vec![other_output], None, Some("commitments")),
        ] {
            let asserter = Asserter::new();
            let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
            let mut batch = ingest_chain_logs(&logs).expect("ingest logs");
            asserter.push_success(&transaction_json_with_input(
                transactCall {
                    _transactions: calldata_transactions,
                }
                .abi_encode(),
            ));

            let error = hydrate_public_transactions(
                &provider,
                railgun_contract(),
                Some(LEGACY_BLOCK_NUMBER),
                &mut batch,
            )
            .await
            .expect_err("unresolved unshield calldata should fail");

            let outcome = match error {
                ChainLogIngestionError::AmbiguousUnshieldCalldata {
                    transaction_hash,
                    block_number,
                    matches,
                } => (transaction_hash, block_number, Some(matches), None),
                ChainLogIngestionError::ContradictingUnshieldCalldata {
                    transaction_hash,
                    block_number,
                    field,
                } => (transaction_hash, block_number, None, Some(field)),
                error => panic!("unexpected error: {error:?}"),
            };
            assert_eq!(
                outcome,
                (
                    fixed_bytes(LEGACY_TRANSACTION_HASH),
                    LEGACY_BLOCK_NUMBER,
                    expected_matches,
                    expected_field
                )
            );
            assert!(batch.public_transactions.is_empty());
        }
    }

    /// Hydrates `logs` through calldata and through `Action` logs and asserts identical rows. The
    /// log path gets a transaction response only when it carries an unshield, so a trace lookup,
    /// or a transaction lookup without an unshield, would fail it.
    async fn assert_action_log_rows_match_calldata(
        calldata: Vec<u8>,
        logs: Vec<Log>,
    ) -> Vec<IndexedPublicTransaction> {
        let logs = with_log_metadata(logs);
        let has_unshield = logs
            .iter()
            .any(|log| log.inner.topics().first() == Some(&Unshield::SIGNATURE_HASH));
        let mut rows = Vec::new();
        for action_start_block in [None, Some(LEGACY_BLOCK_NUMBER)] {
            let asserter = Asserter::new();
            let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
            let mut batch = ingest_chain_logs(&logs).expect("ingest Railgun call logs");
            if action_start_block.is_none() || has_unshield {
                asserter.push_success(&transaction_json_with_input(calldata.clone()));
            }
            asserter.push_success(&block_json(
                LEGACY_BLOCK_HASH,
                LEGACY_BLOCK_NUMBER,
                1_714_356_419,
                vec![],
            ));

            hydrate_public_transactions(
                &provider,
                railgun_contract(),
                action_start_block,
                &mut batch,
            )
            .await
            .expect("hydrate public transactions");

            assert!(asserter.read_q().is_empty());
            rows.push(batch.public_transactions);
        }
        let log_rows = rows.pop().expect("log rows");
        let calldata_rows = rows.pop().expect("calldata rows");
        assert!(!calldata_rows.is_empty());
        assert_eq!(log_rows, calldata_rows);
        log_rows
    }

    /// Logs a Railgun `transact` call emits for `transactions`, in contract order.
    fn railgun_call_logs(transactions: &[Transaction], start_position: u64) -> Vec<Log> {
        let mut logs = transactions
            .iter()
            .map(|transaction| {
                log_for(Nullified {
                    treeNumber: transaction.boundParams.treeNumber,
                    nullifier: transaction.nullifiers.clone(),
                })
            })
            .collect::<Vec<_>>();
        logs.push(log_for(Action {
            caller: Address::ZERO,
            txconfigs: transactions.iter().map(tx_config).collect(),
        }));
        for transaction in transactions
            .iter()
            .filter(|transaction| transaction.boundParams.unshield != 0)
        {
            let value = U256::from(transaction.unshieldPreimage.value);
            logs.push(log_for(Unshield {
                to: Address::from_word(transaction.unshieldPreimage.npk),
                token: transaction.unshieldPreimage.token.clone(),
                amount: value - U256::ONE,
                fee: U256::ONE,
            }));
        }
        let hashes = transactions
            .iter()
            .flat_map(|transaction| {
                let output_count = transaction.commitments.len()
                    - usize::from(transaction.boundParams.unshield != 0);
                transaction.commitments[..output_count].iter().copied()
            })
            .collect::<Vec<_>>();
        if !hashes.is_empty() {
            logs.push(log_for(Transact {
                treeNumber: U256::ZERO,
                startPosition: U256::from(start_position),
                ciphertext: vec![commitment_ciphertext(); hashes.len()],
                hash: hashes,
            }));
        }
        logs
    }

    fn tx_config(transaction: &Transaction) -> TXConfig {
        let has_unshield = transaction.boundParams.unshield != 0;
        TXConfig {
            nullifiersCount: u32::try_from(transaction.nullifiers.len()).expect("nullifier count"),
            commitmentsCount: u32::try_from(
                transaction.commitments.len() - usize::from(has_unshield),
            )
            .expect("commitment count"),
            hasUnshield: has_unshield,
            boundParamsHash: transaction.boundParams.hash().into(),
        }
    }

    /// A transaction whose final commitment is the one its `Unshield` log reproduces.
    fn unshield_railgun_transaction(byte: u8, outputs: Vec<FixedBytes<32>>) -> Transaction {
        let unshield_preimage = CommitmentPreimage {
            npk: Address::from([byte; 20]).into_word(),
            token: token_data(),
            value: Uint::<120, 2>::from(3_u64),
        };
        let mut commitments = outputs;
        commitments.push(fixed_bytes_from_u256(unshield_preimage.hash()));
        Transaction {
            unshieldPreimage: unshield_preimage,
            ..railgun_transaction_with_commitments(byte, commitments, true)
        }
    }

    fn with_log_metadata(mut logs: Vec<Log>) -> Vec<Log> {
        for (index, log) in logs.iter_mut().enumerate() {
            log.block_hash = Some(fixed_bytes(LEGACY_BLOCK_HASH));
            log.block_number = Some(LEGACY_BLOCK_NUMBER);
            log.transaction_hash = Some(fixed_bytes(LEGACY_TRANSACTION_HASH));
            log.log_index = Some(u64::try_from(index).expect("log index") + 7);
        }
        logs
    }

    #[allow(clippy::needless_pass_by_value)]
    fn log_for<E: SolEvent>(event: E) -> Log {
        Log {
            inner: PrimitiveLog {
                address: Address::from([0xbb; 20]),
                data: event.encode_log_data(),
            },
            block_hash: Some(FixedBytes::from([0xaa; 32])),
            block_number: Some(100),
            transaction_hash: Some(FixedBytes::from([0xcc; 32])),
            log_index: Some(1),
            ..Log::default()
        }
    }

    fn transact_batch(
        transaction_hash: FixedBytes<32>,
        block_hash: FixedBytes<32>,
        block_number: u64,
    ) -> IndexedLogBatch {
        IndexedLogBatch {
            transact_commitments: vec![IndexedTransactCommitment {
                tree_number: 1,
                tree_position: 0,
                hash: fixed_bytes_32(0x13),
                ciphertext: Some(commitment_ciphertext()),
                source: IndexedLogSource {
                    block_number,
                    block_timestamp: None,
                    block_hash,
                    transaction_hash,
                    log_index: 7,
                },
            }],
            ..IndexedLogBatch::default()
        }
    }

    fn fixed_bytes(value: &str) -> FixedBytes<32> {
        value.parse().expect("valid fixed bytes")
    }

    fn fixed_bytes_32(byte: u8) -> FixedBytes<32> {
        FixedBytes::from([byte; 32])
    }

    fn legacy_merkle_root_call_bytes(byte: u8) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        for (index, value) in bytes.iter_mut().enumerate() {
            *value = byte.wrapping_add(index as u8);
        }
        bytes
    }

    fn railgun_contract() -> Address {
        Address::from([0x59; 20])
    }

    fn transaction_json_with_input(input: Vec<u8>) -> Value {
        json!({
            "blockHash": LEGACY_BLOCK_HASH,
            "blockNumber": format!("0x{:x}", LEGACY_BLOCK_NUMBER),
            "hash": LEGACY_TRANSACTION_HASH,
            "transactionIndex": "0x1",
            "type": "0x0",
            "nonce": "0x43eb",
            "input": hex::encode_prefixed(input),
            "r": "0x3b08715b4403c792b8c7567edea634088bedcd7f60d9352b1f16c69830f3afd5",
            "s": "0x10b9afb67d2ec8b956f0e1dbc07eb79152904f3a7bf789fc869db56320adfe09",
            "chainId": "0x38",
            "v": "0x93",
            "gas": "0xc350",
            "from": "0x32be343b94f860124dc4fee278fdcbd38c102d88",
            "to": "0xdf190dc7190dfba737d7777a163445b7fff16133",
            "value": "0x0",
            "gasPrice": "0xdf8475800"
        })
    }

    fn railgun_transaction(byte: u8) -> Transaction {
        railgun_transaction_with_commitments(
            byte,
            vec![
                FixedBytes::from([byte.wrapping_add(2); 32]),
                FixedBytes::from([byte.wrapping_add(3); 32]),
            ],
            false,
        )
    }

    fn railgun_transaction_with_commitments(
        byte: u8,
        commitments: Vec<FixedBytes<32>>,
        has_unshield: bool,
    ) -> Transaction {
        let ciphertexts = (0..commitments.len())
            .map(|_| commitment_ciphertext())
            .collect();
        let bound_params = if has_unshield {
            BoundParams::new_unshield(0, 0, 56, ciphertexts, Address::ZERO, FixedBytes::ZERO)
        } else {
            BoundParams::new_transact(0, 0, 56, ciphertexts, Address::ZERO, FixedBytes::ZERO)
        };
        Transaction {
            proof: SnarkProof::default(),
            merkleRoot: FixedBytes::from([byte; 32]),
            nullifiers: vec![FixedBytes::from([byte.wrapping_add(1); 32])],
            commitments,
            boundParams: bound_params,
            unshieldPreimage: commitment_preimage(0),
        }
    }

    fn legacy_railgun_transaction(byte: u8) -> legacy::LegacyTransaction {
        legacy_railgun_transaction_with_commitments(
            byte,
            vec![
                fixed_bytes_32(byte.wrapping_add(2)),
                fixed_bytes_32(byte.wrapping_add(3)),
            ],
            0,
        )
    }

    fn legacy_railgun_transaction_with_commitments(
        byte: u8,
        commitments: Vec<FixedBytes<32>>,
        withdraw: u8,
    ) -> legacy::LegacyTransaction {
        legacy::LegacyTransaction {
            proof: legacy::LegacySnarkProof {
                a: legacy::LegacyG1Point {
                    x: U256::ZERO,
                    y: U256::ZERO,
                },
                b: legacy::LegacyG2Point {
                    x: [U256::ZERO; 2],
                    y: [U256::ZERO; 2],
                },
                c: legacy::LegacyG1Point {
                    x: U256::ZERO,
                    y: U256::ZERO,
                },
            },
            merkleRoot: U256::from_be_bytes(legacy_merkle_root_call_bytes(byte)),
            nullifiers: vec![U256::from_be_bytes([byte.wrapping_add(1); 32])],
            commitments: commitments
                .into_iter()
                .map(|commitment| U256::from_be_bytes(commitment.0))
                .collect(),
            boundParams: legacy::LegacyBoundParams {
                treeNumber: 0,
                withdraw,
                adaptContract: Address::ZERO,
                adaptParams: FixedBytes::ZERO,
                commitmentCiphertext: vec![
                    legacy_commitment_ciphertext_for_call(),
                    legacy_commitment_ciphertext_for_call(),
                ],
            },
            unshieldPreimage: legacy::LegacyCommitmentPreimage {
                npk: U256::ZERO,
                token: legacy::LegacyTokenData {
                    tokenType: 0,
                    tokenAddress: Address::ZERO,
                    tokenSubID: U256::ZERO,
                },
                value: Uint::<120, 2>::ZERO,
            },
            verifier: Address::ZERO,
        }
    }

    fn arbitrum_system_transaction_json() -> Value {
        json!({
            "blockHash": LEGACY_BLOCK_HASH,
            "blockNumber": format!("0x{:x}", LEGACY_BLOCK_NUMBER),
            "from": "0x00000000000000000000000000000000000a4b05",
            "gas": "0x0",
            "gasPrice": "0x0",
            "hash": ARBITRUM_SYSTEM_TRANSACTION_HASH,
            "input": "0x6bf6a42d",
            "nonce": "0x0",
            "to": "0x00000000000000000000000000000000000a4b05",
            "transactionIndex": "0x0",
            "value": "0x0",
            "type": "0x6a",
            "chainId": "0xa4b1",
            "v": "0x0",
            "r": "0x0",
            "s": "0x0"
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    fn block_json(
        block_hash: &str,
        block_number: u64,
        timestamp: u64,
        transactions: Vec<Value>,
    ) -> Value {
        json!({
            "hash": block_hash,
            "parentHash": ZERO_B256,
            "sha3Uncles": ZERO_B256,
            "miner": ZERO_ADDRESS,
            "stateRoot": ZERO_B256,
            "transactionsRoot": ZERO_B256,
            "receiptsRoot": ZERO_B256,
            "logsBloom": format!("0x{}", "00".repeat(256)),
            "difficulty": "0x0",
            "number": format!("0x{block_number:x}"),
            "gasLimit": "0x1c9c380",
            "gasUsed": "0x0",
            "timestamp": format!("0x{timestamp:x}"),
            "extraData": "0x",
            "mixHash": ZERO_B256,
            "nonce": "0x0000000000000000",
            "uncles": [],
            "transactions": transactions,
        })
    }

    const LEGACY_TRANSACTION_HASH: &str =
        "0xe9e91f1ee4b56c0df2e9f06c2b8c27c6076195a88a7b8537ba8313d80e6f124e";
    const ARBITRUM_SYSTEM_TRANSACTION_HASH: &str =
        "0xc940b89a1831a73254a1858d32d6c97aead629f18c5df029d4c5271fbc3a4e09";
    const LEGACY_BLOCK_HASH: &str =
        "0x8e38b4dbf6b11fcc3b9dee84fb7986e29ca0a02cecd8977c161ff7333329681e";
    const LEGACY_BLOCK_NUMBER: u64 = 1_000_000;
    const ZERO_B256: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
    const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

    fn commitment_ciphertext() -> CommitmentCiphertext {
        CommitmentCiphertext {
            ciphertext: [FixedBytes::ZERO; 4],
            blindedSenderViewingKey: FixedBytes::ZERO,
            blindedReceiverViewingKey: FixedBytes::ZERO,
            annotationData: Bytes::new(),
            memo: Bytes::new(),
        }
    }

    fn shield_ciphertext() -> ShieldCiphertext {
        ShieldCiphertext {
            encryptedBundle: [FixedBytes::ZERO; 3],
            shieldKey: FixedBytes::ZERO,
        }
    }

    fn commitment_preimage(byte: u8) -> CommitmentPreimage {
        CommitmentPreimage {
            npk: FixedBytes::from([byte; 32]),
            token: token_data(),
            value: Uint::<120, 2>::from(1_u64),
        }
    }

    fn legacy_commitment_ciphertext() -> LegacyCommitmentCiphertext {
        LegacyCommitmentCiphertext {
            ciphertext: [U256::ZERO; 4],
            ephemeralKeys: [U256::ZERO; 2],
            memo: Vec::new(),
        }
    }

    fn legacy_commitment_ciphertext_for_call() -> legacy::LegacyCommitmentCiphertext {
        legacy::LegacyCommitmentCiphertext {
            ciphertext: [U256::ZERO; 4],
            ephemeralKeys: [U256::ZERO; 2],
            memo: Vec::new(),
        }
    }

    fn legacy_commitment_preimage(byte: u8) -> LegacyCommitmentPreimage {
        LegacyCommitmentPreimage {
            npk: U256::from(byte),
            token: token_data(),
            value: Uint::<120, 2>::from(1_u64),
        }
    }

    fn token_data() -> broadcaster_core::contracts::railgun::TokenData {
        broadcaster_core::contracts::railgun::TokenData {
            tokenType: 0,
            tokenAddress: Address::ZERO,
            tokenSubID: U256::ZERO,
        }
    }
}
