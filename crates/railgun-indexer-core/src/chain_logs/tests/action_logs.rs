use super::*;

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
        assert_action_log_rows_match_calldata(calldata, railgun_call_logs(&transactions, 3)).await;

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
        assert_eq!(
            batch.public_transactions,
            [] as [IndexedPublicTransaction; 0]
        );
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
        .expect("unshield commitment") = fixed_bytes_from_u256(transaction.unshieldPreimage.hash());
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
        assert_eq!(
            batch.public_transactions,
            [] as [IndexedPublicTransaction; 0]
        );
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
    assert_ne!(calldata_rows, [] as [IndexedPublicTransaction; 0]);
    assert_eq!(log_rows, calldata_rows);
    log_rows
}
