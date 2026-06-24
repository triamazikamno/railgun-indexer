# railgun-indexer Production Validation

Use this checklist before treating chain-indexed artifacts as an official wallet
indexed-data source. It validates the publisher, public artifact availability,
Filebase pinning, dedicated chain-indexed IPNS publication, and wallet fallback
release gates. It does not replace automated tests.

Until wallet artifact ingestion and fallback wiring are enabled and tested, keep
official wallet indexed-artifact settings disabled and keep Squid GraphQL usable
as fallback or as the explicit manual source.

## Inputs

- A production `config.railgun-indexer.yaml` with `chain_indexed.enabled: true`.
- Explicit `chain_indexed.chains[*].rpc_url` and `archive_rpc_url` values for every enabled chain.
- Archive RPC support for `debug_traceTransaction` with `callTracer` or `trace_transaction`, required to hydrate public TXID rows from wrapped/internal Railgun calls.
- A non-zero `railgun_contract`, correct `start_block`, `v2_start_block`, and `legacy_shield_block` per chain.
- Distinct `railgun_indexer.publisher_signing_key_path` and `chain_indexed_publisher_signing_key_path` files.
- Filebase credentials in `RAILGUN_INDEXER_FILEBASE_ACCESS_KEY`, `RAILGUN_INDEXER_FILEBASE_SECRET_KEY`, and `RAILGUN_INDEXER_FILEBASE_BUCKET`.
- Public IPFS gateways that wallets are expected to use for the chain-indexed IPNS name and CIDs.
- A Squid GraphQL endpoint and RPC/archive RPC settings that remain available for fallback validation.

## Preflight

Run the targeted checks from the repository root before deploying the binary:

```bash
cargo fmt --all -- --check
cargo check -p railgun-indexer --locked
cargo test -p railgun-indexer-core public_txid -- --nocapture
cargo test -p railgun-indexer-core chunk -- --nocapture
cargo test -p railgun-indexer-core wallet_scan -- --nocapture
cargo test -p railgun-indexer-core commitment -- --nocapture
cargo test -p railgun-indexer catalog_descriptor -- --nocapture
```

Review the production config before startup:

- `railgun_indexer.ipfs_endpoint` uses the root Filebase S3 endpoint, normally `https://s3.filebase.com`.
- `chain_indexed` has no dependency on Squid or implicit public RPC defaults.
- `public_txid_chunk_row_limit` and `commitment_chunk_row_limit` are production values, with compressed-size planning still enforcing the 32 MiB hard cap. Wallet-scan publication is sparse and size-planned from populated block buckets, so empty historical ranges do not produce chunks and wallet consumers must treat missing wallet-scan chunk coverage as empty rows through `latest_indexed.wallet_scan`.
- IPNS bootstrap peers and `ipns_publish_timeout` are suitable for the production network.

## Startup

Start the indexer with production environment variables and config:

```bash
export RAILGUN_INDEXER_CONFIG=config.railgun-indexer.yaml
export RAILGUN_INDEXER_FILEBASE_ACCESS_KEY=...
export RAILGUN_INDEXER_FILEBASE_SECRET_KEY=...
export RAILGUN_INDEXER_FILEBASE_BUCKET=...
cargo run --bin railgun-indexer -- --config "$RAILGUN_INDEXER_CONFIG"
```

Record the `chain_indexed_ipns_name` from the `loaded railgun indexer config`
log line. This name must be different from the POI IPNS name.

Check the local status server for process health:

```bash
curl -fsS http://127.0.0.1:8080/health
curl -fsS http://127.0.0.1:8080/status
```

The current status endpoint is POI-oriented. For chain-indexed validation, use
the logs, Postgres audit tables, Filebase, IPNS, and gateway checks below.

## Indexing Checks

Wait for logs containing `indexed chain log range` for every enabled chain. Each
log should include `chain_id`, `railgun_contract`, `safe_head`,
`indexing_lag_blocks`, `from_block`, `to_block`, `fetched_log_count`, and
`persisted_row_count`.

Confirm indexing progress is advancing in Postgres. Replace `$POSTGRES_URL` with
`railgun_indexer.postgres_connection_string` from the production config.

```bash
psql "$POSTGRES_URL" -c "
SELECT chain_id, railgun_contract, dataset_kind, indexed_through_block, updated_at
FROM chain_indexing_progress
ORDER BY chain_id, railgun_contract, dataset_kind;
"
```

Expected result:

- Each configured chain and contract has progress rows for `wallet_scan`, `commitments`, `merkle_checkpoint`, and `public_txid`.
- `indexed_through_block` moves forward on subsequent checks and does not exceed the current chain head minus `chain_indexed.safe_confirmations`.
- Any reorg logs are followed by `rewound chain-indexed rows after reorg` and later successful indexing logs.

## Boundary Normalization Recovery

Older chain-indexed builds could persist event-local positions at the tree boundary,
for example `tree_position = 65536`, instead of carrying into the next tree. Before
publishing commitment or Merkle checkpoint artifacts from an existing database,
check for and normalize those rows. New rows from fixed builds are normalized at
ingestion.

Inspect commitment rows that need normalization:

```bash
psql "$POSTGRES_URL" -c "
WITH all_commitments AS (
    SELECT 'transact' AS family, chain_id, railgun_contract, tree_number, tree_position,
           block_number, transaction_hash, log_index
    FROM indexed_transact_commitments
    UNION ALL
    SELECT 'shield' AS family, chain_id, railgun_contract, tree_number, tree_position,
           block_number, transaction_hash, log_index
    FROM indexed_shield_commitments
    UNION ALL
    SELECT 'legacy_encrypted' AS family, chain_id, railgun_contract, tree_number, tree_position,
           block_number, transaction_hash, log_index
    FROM indexed_legacy_encrypted_commitments
    UNION ALL
    SELECT 'legacy_generated' AS family, chain_id, railgun_contract, tree_number, tree_position,
           block_number, transaction_hash, log_index
    FROM indexed_legacy_generated_commitments
)
SELECT family, chain_id, railgun_contract, tree_number, tree_position,
       block_number, encode(transaction_hash, 'hex') AS transaction_hash, log_index
FROM all_commitments
WHERE tree_position >= 65536
ORDER BY chain_id, railgun_contract, tree_number, tree_position, family;
"
```

Check that normalization would not collide with an existing commitment row:

```bash
psql "$POSTGRES_URL" -c "
WITH all_commitments AS (
    SELECT 'transact' AS family, chain_id, railgun_contract, tree_number, tree_position,
           block_number, transaction_hash, log_index
    FROM indexed_transact_commitments
    UNION ALL
    SELECT 'shield' AS family, chain_id, railgun_contract, tree_number, tree_position,
           block_number, transaction_hash, log_index
    FROM indexed_shield_commitments
    UNION ALL
    SELECT 'legacy_encrypted' AS family, chain_id, railgun_contract, tree_number, tree_position,
           block_number, transaction_hash, log_index
    FROM indexed_legacy_encrypted_commitments
    UNION ALL
    SELECT 'legacy_generated' AS family, chain_id, railgun_contract, tree_number, tree_position,
           block_number, transaction_hash, log_index
    FROM indexed_legacy_generated_commitments
), normalized AS (
    SELECT family, chain_id, railgun_contract,
           tree_number + (tree_position / 65536) AS normalized_tree_number,
           tree_position % 65536 AS normalized_tree_position,
           block_number, transaction_hash, log_index
    FROM all_commitments
)
SELECT chain_id, railgun_contract, normalized_tree_number, normalized_tree_position,
       COUNT(*) AS row_count,
       array_agg(family || ':' || block_number || ':' || encode(transaction_hash, 'hex') || ':' || log_index ORDER BY family) AS rows
FROM normalized
GROUP BY chain_id, railgun_contract, normalized_tree_number, normalized_tree_position
HAVING COUNT(*) > 1
ORDER BY chain_id, railgun_contract, normalized_tree_number, normalized_tree_position;
"
```

Inspect public TXID output ranges that need normalization:

```bash
psql "$POSTGRES_URL" -c "
SELECT chain_id, railgun_contract, utxo_tree_out, utxo_batch_start_position_out,
       block_number, encode(transaction_hash, 'hex') AS transaction_hash,
       first_log_index, railgun_transaction_index
FROM indexed_public_txid_rows
WHERE utxo_batch_start_position_out >= 65536
ORDER BY chain_id, railgun_contract, utxo_tree_out, utxo_batch_start_position_out;
"
```

If the collision query returns rows, stop and investigate. If it returns no rows,
stop every old indexer process, deploy the fixed binary, and run the normalization
transaction while the indexer is stopped:

```sql
BEGIN;

LOCK TABLE indexed_transact_commitments IN EXCLUSIVE MODE;
LOCK TABLE indexed_shield_commitments IN EXCLUSIVE MODE;
LOCK TABLE indexed_legacy_encrypted_commitments IN EXCLUSIVE MODE;
LOCK TABLE indexed_legacy_generated_commitments IN EXCLUSIVE MODE;
LOCK TABLE indexed_public_txid_rows IN EXCLUSIVE MODE;

UPDATE indexed_transact_commitments
SET
    tree_number = tree_number + (tree_position / 65536),
    tree_position = tree_position % 65536
WHERE tree_position >= 65536
RETURNING 'transact' AS family, chain_id, railgun_contract, tree_number, tree_position,
          block_number, encode(transaction_hash, 'hex') AS transaction_hash, log_index;

UPDATE indexed_shield_commitments
SET
    tree_number = tree_number + (tree_position / 65536),
    tree_position = tree_position % 65536
WHERE tree_position >= 65536
RETURNING 'shield' AS family, chain_id, railgun_contract, tree_number, tree_position,
          block_number, encode(transaction_hash, 'hex') AS transaction_hash, log_index;

UPDATE indexed_legacy_encrypted_commitments
SET
    tree_number = tree_number + (tree_position / 65536),
    tree_position = tree_position % 65536
WHERE tree_position >= 65536
RETURNING 'legacy_encrypted' AS family, chain_id, railgun_contract, tree_number, tree_position,
          block_number, encode(transaction_hash, 'hex') AS transaction_hash, log_index;

UPDATE indexed_legacy_generated_commitments
SET
    tree_number = tree_number + (tree_position / 65536),
    tree_position = tree_position % 65536
WHERE tree_position >= 65536
RETURNING 'legacy_generated' AS family, chain_id, railgun_contract, tree_number, tree_position,
          block_number, encode(transaction_hash, 'hex') AS transaction_hash, log_index;

UPDATE indexed_public_txid_rows
SET
    utxo_tree_out = utxo_tree_out + (utxo_batch_start_position_out / 65536),
    utxo_batch_start_position_out = utxo_batch_start_position_out % 65536
WHERE utxo_batch_start_position_out >= 65536
RETURNING chain_id, railgun_contract, utxo_tree_out, utxo_batch_start_position_out,
          block_number, encode(transaction_hash, 'hex') AS transaction_hash,
          first_log_index, railgun_transaction_index;

COMMIT;
```

After restart, the bad-position query above and this duplicate-position check must
both return zero rows:

```bash
psql "$POSTGRES_URL" -c "
WITH all_commitments AS (
    SELECT 'transact' AS family, chain_id, railgun_contract, tree_number, tree_position
    FROM indexed_transact_commitments
    UNION ALL
    SELECT 'shield' AS family, chain_id, railgun_contract, tree_number, tree_position
    FROM indexed_shield_commitments
    UNION ALL
    SELECT 'legacy_encrypted' AS family, chain_id, railgun_contract, tree_number, tree_position
    FROM indexed_legacy_encrypted_commitments
    UNION ALL
    SELECT 'legacy_generated' AS family, chain_id, railgun_contract, tree_number, tree_position
    FROM indexed_legacy_generated_commitments
)
SELECT chain_id, railgun_contract, tree_number, tree_position, COUNT(*) AS row_count,
       array_agg(family ORDER BY family) AS families
FROM all_commitments
GROUP BY chain_id, railgun_contract, tree_number, tree_position
HAVING COUNT(*) > 1
ORDER BY chain_id, railgun_contract, tree_number, tree_position;
"
```

## Public TXID Legacy Replay Recovery

Builds that hydrated public TXID rows only from `Transact` events omitted pre-V2
legacy public transactions. Affected artifacts rebase the post-V2 subset to
`txid_index = 0`, which cannot match wallet/Squid offset semantics. BSC is the
fastest production canary: a bad manifest showed `15610` artifact rows versus
`19945` Squid rows, with artifact row `0` starting near `v2_start_block` instead
of the first legacy transaction.

Before publishing a replacement manifest from an existing database, stop every
indexer process, deploy a build that hydrates public TXID summaries from legacy
commitment positions, and force a chain-indexed replay from each affected chain's
configured `start_block`. The scheduler resumes from wallet-scan progress, so
clear all chain-indexed progress rows for the affected chain/contract, not only
the `public_txid` progress row. Keep the other indexed tables; replay upserts
them. Clear public TXID rows so stale rows cannot remain if hydration semantics
changed.

```sql
BEGIN;

DELETE FROM indexed_public_txid_rows
WHERE chain_type = 0
  AND chain_id IN (1, 56, 137, 42161);

DELETE FROM chain_indexing_progress
WHERE chain_type = 0
  AND chain_id IN (1, 56, 137, 42161);

COMMIT;
```

Restart the fixed indexer with production archive RPC settings and wait for every
affected chain to catch up from `start_block` to the safe head. Re-run the
indexing checks above and publish a new manifest only after replay completion.
If the replay encounters Railgun public transaction logs but cannot decode a
direct or traced Railgun call, fix the archive RPC trace support or calldata
decoder before publishing; do not accept silently missing public TXID rows.

Before spending RPC credits on a full replay, validate known legacy BSC ranges
with the read-only range verifier. Pass the provider URL through
`RAILGUN_TXID_RANGE_RPC_URL` rather than `--rpc-url` so shells and cargo do not
echo provider secrets in process args. The verifier derives public TXID rows from
RPC logs/calldata/traces for only the requested blocks, fetches the matching
Squid rows with `transactions(orderBy: id_ASC, offset, limit, where:
{blockNumber_gte, blockNumber_lte})`, and compares row content plus TXID leaf
hashes. RPC log fetching is chunked at `10000` blocks by default; override with
`--rpc-block-chunk-size` only when validating against a provider with a different
limit.

```bash
RAILGUN_TXID_RANGE_RPC_URL="$BSC_ARCHIVE_RPC_URL" \
  cargo run --release -p railgun-indexer --bin verify_txid_range --locked -- \
  --chain-id 56 \
  --from-block 17771899 \
  --to-block 17771899

RAILGUN_TXID_RANGE_RPC_URL="$BSC_ARCHIVE_RPC_URL" \
  cargo run --release -p railgun-indexer --bin verify_txid_range --locked -- \
  --chain-id 56 \
  --from-block 18051855 \
  --to-block 18052305
```

Expected result:

- Both commands complete with `failures=0`.
- The direct legacy range includes BSC tx
  `0x4388f3727fe7f9cfd0d57807f7a2a126fbb7e56a25a17e3e99102931ea2e4b33`.
- The legacy unshield range includes BSC tx
  `0xbc1d1671f7755e566f480f5d05193d85c41acdcbe0b6611c52aa342546843d02` and
  must match Squid output starts `102`, `104`, and `105`.

Validate the replacement manifest against full Squid offset semantics. The
verifier fetches the signed manifest, all public TXID artifact chunks, and all
Squid `transactions(orderBy: id_ASC, offset, limit)` pages until the final short
page. It then compares row counts, row content, leaf hashes, descriptor roots,
and tree roots.

```bash
cargo run --release -p railgun-indexer --bin verify_txid_parity --locked -- --chain-id 56
cargo run --release -p railgun-indexer --bin verify_txid_parity --locked -- --chain-id 137
cargo run --release -p railgun-indexer --bin verify_txid_parity --locked -- --chain-id 1
```

Run Arbitrum only after its RPC-derived indexer is caught up; otherwise treat the
result as provisional. Do not enable wallet ingestion/defaults unless every
non-provisional chain has matching artifact and Squid counts, matching row/root
prefixes through the full dataset, zero descriptor root errors, and matching tree
roots.

## Publication Checks

Wait for logs containing `published indexed artifact catalog` and `published
chain-indexed manifest`. Catalog logs should include `dataset`, `cid`,
`chunk_count`, `total_chunk_byte_size`, `max_chunk_byte_size`, `byte_size`, and
`sha256`. Manifest logs should include `manifest_cid`, `sequence`,
`ipns_published`, `chain_count`, `catalog_count`, `byte_size`, and `sha256`.

Inspect active manifests:

```bash
psql "$POSTGRES_URL" -c "
SELECT cid, ipns_sequence, byte_size, published_at, ipns_published_at
FROM published_indexed_manifests
WHERE superseded_at IS NULL AND unpinned_at IS NULL
ORDER BY ipns_sequence DESC
LIMIT 5;
"
```

Expected result:

- The newest manifest has `ipns_published_at` set.
- `ipns_sequence` is monotonic across publications.
- The active manifest CID matches the most recent `published chain-indexed manifest` log.

Inspect active chunks and catalogs:

```bash
psql "$POSTGRES_URL" -c "
SELECT artifact_kind, dataset_kind, chain_id, range_kind,
       COUNT(*) AS count,
       MIN(range_start) AS first_range_start,
       MAX(range_end) AS last_range_end,
       MAX(byte_size) AS max_byte_size
FROM published_indexed_artifacts
WHERE unpinned_at IS NULL
GROUP BY artifact_kind, dataset_kind, chain_id, range_kind
ORDER BY chain_id, dataset_kind, artifact_kind, range_kind;
"
```

Expected result:

- Every enabled dataset has at least one catalog once indexed rows exist.
- Published chunk `max_byte_size` never exceeds `33554432` bytes.
- Public TXID chunks use `range_kind = 'txid_index'` and contiguous ranges.
- Wallet scan chunks use `range_kind = 'block'` and may be sparse; chunk gaps are valid empty block spans, not publication failures.
- Commitment chunks use `range_kind = 'tree_position'`.

## Filebase And Gateway Checks

Sample active CIDs from the audit table:

```bash
psql "$POSTGRES_URL" -At -c "
SELECT cid
FROM published_indexed_manifests
WHERE superseded_at IS NULL AND unpinned_at IS NULL
UNION
SELECT cid
FROM published_indexed_artifacts
WHERE unpinned_at IS NULL
ORDER BY cid
LIMIT 25;
"
```

For each sampled CID, verify it is retrievable through Filebase-backed access and
through the public gateways planned for wallets. Use gateway URL forms that match
the provider being tested.

```bash
export CID=...
curl -fsS -o /dev/null "https://ipfs.io/ipfs/$CID"
curl -fsS -o /dev/null "https://cloudflare-ipfs.com/ipfs/$CID"
```

Expected result:

- Manifest, catalog, and chunk CIDs are reachable from at least the official gateway set.
- Gateway bytes match the audited CID, SHA-256, and byte-size metadata when verified by the wallet artifact client or an equivalent verifier.
- Transient gateway failures are recorded with provider, CID, status, and time, then retried before release sign-off.

## IPNS Checks

Resolve the dedicated chain-indexed IPNS name through every official gateway:

```bash
export CHAIN_INDEXED_IPNS_NAME=...
curl -fsS "https://ipfs.io/ipns/$CHAIN_INDEXED_IPNS_NAME" -o manifest.ipfs-io.json
curl -fsS "https://cloudflare-ipfs.com/ipns/$CHAIN_INDEXED_IPNS_NAME" -o manifest.cloudflare.json
```

Expected result:

- The resolved manifest verifies under the chain-indexed publisher public key, not the POI publisher key.
- The resolved manifest has the latest active `ipns_sequence` or a documented older valid sequence within expected gateway cache behavior.
- The manifest includes the expected chain entries, `latest_indexed` heights, and catalog descriptors for enabled datasets.
- Catalog descriptors and chunk descriptors verify CID, SHA-256, byte size, scope, range, encoding version, compression, and dataset-specific root metadata.

Do not accept manual JSON inspection as a substitute for signature and descriptor
verification. Use the wallet artifact client tests or an equivalent verifier when
checking manifests, catalogs, and chunks.

## Fallback Checks

Before enabling official wallet defaults, validate fallback behavior in a staging
wallet environment with the same official gateway and publisher settings planned
for production.

Required checks:

- With valid artifacts, the wallet resolves the official chain-indexed IPNS name and verifies manifests, catalogs, and chunks.
- With the artifact source disabled, the wallet uses the configured Squid GraphQL source when quick-sync is enabled.
- With an unreachable gateway or invalid artifact descriptor, the wallet logs the artifact failure and falls back to configured Squid before durable artifact progress advances.
- With both artifact and Squid sources unavailable, the wallet keeps existing RPC/archive RPC fallback behavior for ranges that can be synced from RPC.
- Recovery-targeted public TXID catch-up still works when only a target transaction is needed.
- Squid remains configurable as fallback or as an explicit manual source after official artifact settings are present.

If any fallback check cannot be run because wallet runtime ingestion is still on
hold, do not enable official indexed artifact defaults. Leave the official source
settings disabled and keep Squid as the production indexed data source.

## Release Criteria

The production validation passes only when all of these are true:

- Chain-indexed rows are sourced from explicit RPC/archive RPC providers for every enabled chain.
- Indexing progress advances and reorg handling can resume from persisted state.
- Filebase pinning produces reachable manifest, catalog, and chunk CIDs.
- Dedicated chain-indexed IPNS publishes the latest signed manifest and does not reuse the POI IPNS name or key.
- Official gateways can retrieve and verify the active manifest, catalogs, and representative chunks.
- Public TXID chunks carry checkpoint/root metadata and verify before wallet proof use.
- Squid GraphQL and RPC/archive RPC fallback behavior are validated before artifacts become the wallet default.

If any release criterion fails, keep wallet defaults pointed at Squid/manual source,
leave published CIDs pinned until retention cleanup, fix the publisher or gateway
issue, and repeat this checklist.
