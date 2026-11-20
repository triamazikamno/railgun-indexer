use super::*;

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
        legacy_encrypted_commitments: [(214, fixed_bytes_32(0xa0)), (215, fixed_bytes_32(0xa1))]
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
