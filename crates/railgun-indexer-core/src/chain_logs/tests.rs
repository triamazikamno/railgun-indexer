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
            let output_count =
                transaction.commitments.len() - usize::from(transaction.boundParams.unshield != 0);
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
        commitmentsCount: u32::try_from(transaction.commitments.len() - usize::from(has_unshield))
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

mod action_logs;
mod hydrate_positions;
mod hydrate_relay_and_traces;
mod hydrate_unshields;
