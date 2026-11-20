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

mod action_logs;
mod block_context;
mod calldata;
mod hydrate;
mod output_matching;

use action_logs::{
    action_log_events_by_transaction, decoded_transactions_from_action_logs,
    resolve_unshield_commitments,
};
use block_context::{block_timestamp, decode_hex_bytes, full_block_context};
pub use block_context::{block_timestamp_for_source, hydrate_indexed_log_source_timestamps};
use calldata::{
    collect_debug_trace_railgun_transactions, collect_trace_transaction_railgun_transactions,
    debug_trace_transaction, decode_railgun_transactions, fixed_bytes_from_u256,
    public_transactions_from_calldata_or_trace, trace_transaction,
};
pub use hydrate::{hydrate_public_transactions, resolve_public_transactions_by_hash};
use output_matching::public_transactions_from_decoded;

/// Keeps the tracing target of the moved functions at this module's path.
const LOG_TARGET: &str = module_path!();

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
mod tests;
