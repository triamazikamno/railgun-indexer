use super::*;

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
        legacy_encrypted_commitments: [(1404, fixed_bytes_32(0xa0)), (1405, fixed_bytes_32(0xa1))]
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
