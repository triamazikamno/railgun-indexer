use super::*;

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
        legacy_encrypted_commitments: [(266, fixed_bytes_32(0xa0)), (267, fixed_bytes_32(0xb0))]
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
