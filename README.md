# railgun-indexer

`railgun-indexer` publishes Railgun artifacts. The current implementation consists of 2 parts:
1. mirrors a POI JSON-RPC node into Postgres, builds POI checkpoint, tail and bridge
artifacts plus current blocked-shields artifacts
2. scans chain RPC(good archive nodes required) for railgun-related events into Postgres, builds binary snapshots  

It pins all artifacts and manifests to IPFS, and updates the POI and chain-indexed IPNS names.

## Prerequisites

- Rust workspace dependencies from the repository root.
- PostgreSQL reachable from the indexer host.
- Filebase S3/IPFS bucket credentials for v1 pinning.
- A 32-byte ed25519 publisher signing key stored on local disk.

## Publisher Key

The key file may contain either 32 raw bytes or hex text for the 32-byte
ed25519 signing seed.

```bash
mkdir -p secrets
openssl rand -hex 32 > secrets/railgun-indexer-publisher.key
chmod 600 secrets/railgun-indexer-publisher.key
```

The same key signs the POI manifest and seeds the POI IPNS identity, which
is derived from it with HKDF, so wallets need only one publisher trust anchor.

## Configuration

Start from the repository-root example:

```bash
cp config.railgun-indexer.example.yaml config.railgun-indexer.yaml
```

Important fields:

- `railgun_indexer.postgres_connection_string`: durable store connection string.
- `railgun_indexer.ipfs_endpoint`: Filebase S3-compatible endpoint, normally `https://s3.filebase.com`.
- `railgun_indexer.publisher_signing_key_path`: key file described above.
- `railgun_indexer.retention_interval`: artifact and manifest cleanup cadence.
- `poi.upstream_url`: POI JSON-RPC endpoint to mirror, for example `https://ppoi.fdi.network`.
- `poi.list_keys`: upstream list operator public keys to mirror.
- `poi.chain_ids`: supported chain IDs: `1`, `56`, `137`, `8453` (Base), `42161`, `11155111` (Sepolia).
- `poi.delta_publish_interval`: the POI publication tick.
- `poi.base_rebuild_interval`: age at which the POI checkpoint rotates.
- `poi.per_pair_concurrency_limit`: maximum concurrent `(list_key, chain_id)` sync workers.
- `chain_indexed.amount_statistics.enabled`: publishes amount statistics after each chain-indexed publication cycle. Defaults to `false`. See Amount Statistics below.

See `docs/railgun-indexer-production-validation.md` for the manual production
validation checklist before enabling chain-indexed artifacts as an official
wallet source.

The binary applies a small inline, idempotent Postgres schema setup at startup;
it does not need external migration files beside the deployed executable.

The Filebase publisher uses normal S3 `PutObject` uploads. Filebase returns
the IPFS CID in object metadata, and the indexer copies each object to a stable
CID-based key so later retention sweeps can delete it by CID.

The POI manifest publishes signed artifact descriptors for each scope's
checkpoint catalog, current tail, retained bridges, and blocked-shields
artifact. Each descriptor contains the IPFS
`cid`, SHA-256 as `sha256`, and `byte_size`; wallets must verify those bytes
before parsing artifacts. IPFS/Filebase/gateways are transport only, while the
publisher signature and upstream list-key signatures are the trust boundaries.

Use the root Filebase S3 endpoint, not a bucket-specific host such as
`https://<bucket>.s3.filebase.io`. The bucket is supplied separately with
`RAILGUN_INDEXER_FILEBASE_BUCKET`.

Filebase credentials are read from environment variables:

```bash
export RAILGUN_INDEXER_FILEBASE_ACCESS_KEY=...
export RAILGUN_INDEXER_FILEBASE_SECRET_KEY=...
export RAILGUN_INDEXER_FILEBASE_BUCKET=...
```

## Running

```bash
cargo run --bin railgun-indexer -- --config config.railgun-indexer.yaml
```

The status server binds to `127.0.0.1:8080` by default. Override with
`--status-bind-addr` or `RAILGUN_INDEXER_STATUS_BIND_ADDR`.

```bash
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/status
```

## Amount Statistics

With `chain_indexed.amount_statistics.enabled: true`, each chain-indexed
publication cycle also publishes one amount-statistics snapshot per chain and a
manifest that lists them. A chain whose covered block has not moved reuses its
pinned snapshot. When no chain's entry changed, nothing is published until
`ipns_republish_interval` has passed since the active manifest's IPNS
publication. The indexer then publishes a new manifest with the next sequence
and the same entries, which renews the IPNS record.

The chain-indexed publisher key signs the manifest. The manifest goes out under
its own IPNS name, which is derived from that key with HKDF and is different
from the chain-indexed and POI names. A statistics failure never fails
chain-indexed publication.

Wallets need the amount-statistics IPNS name and the chain-indexed
manifest-signing public key. This command prints both without loading config or
starting network services:

```bash
cargo run --bin railgun-indexer -- \
  --print-v4-poi-public-identity \
  --publisher-signing-key-path secrets/railgun-indexer-chain-indexed-publisher.key
```

The command derives every field from the key it is given. With the chain-indexed
publisher key, use `manifest_signing_public_key` and
`amount_statistics_ipns_name` and ignore the `v4_*` fields. With the POI
publisher key, the reverse holds: `manifest_signing_public_key` and the `v4_*`
fields apply, and `amount_statistics_ipns_name` does not.

`/status` reports statistics publication under `amount_statistics`, which is
`null` while statistics are disabled and until the first cycle runs:

- `manifest_cid` and `sequence`: the active manifest.
- `last_error`: why the last cycle failed, or `null`.
- `chain_failures`: chains whose snapshot this cycle did not publish, each with `chain_id`, `railgun_contract` and `reason`. The manifest keeps such a chain's previous entry, if it has one. A snapshot over 4 MiB compressed or 32 MiB decoded lands here, and so does a chain whose derivation takes longer than 30 s, with a reason that says it timed out.

To recompute a published snapshot from the indexed tables and compare every
figure, take the snapshot CID from the chain's manifest entry and run:

```bash
cargo run --release -p railgun-indexer --bin verify_amount_statistics --locked -- \
  --config config.railgun-indexer.yaml \
  --chain-id 1 \
  --snapshot-cid "$SNAPSHOT_CID"
```

The verifier only reads Postgres and makes no RPC calls. It fetches the snapshot
from the gateways in `trustless_artifacts::DEFAULT_GATEWAYS` (`dweb.link`,
`ipfs.filebase.io`, `ipfs.io`, `gateway.pinata.cloud`) one at a time and checks
the returned bytes against the requested CID, raw or UnixFS, before decoding. A
gateway that serves other content counts as a failed attempt, and the verifier
fails when no gateway returns matching bytes. It prints `every figure matches`
and exits 0, or prints one
`mismatch token=... figure=... published=... recomputed=...` line per difference
and exits with a failure status. It also fails when this database is indexed only
below the snapshot's covered block, or when its indexed header at that block has
a different hash. The indexer records a header only where an indexing range
ended, so another operator's database usually has none at that block. The
verifier then reads the records by block number and prints a note that the
covered block hash was not checked.

## First Run

The first bootstrap can take multiple hours because the public upstream slows
down at deep offsets. The indexer is resumable: after each committed page it
persists `chain_tips`, so a restart continues from the last committed cursor.

During bootstrap, expect:

- Adaptive page sizes to shrink during slow upstream ranges and grow again after successes.
- A POI manifest on the first publication tick, including empty scopes.
- A new POI manifest on later `delta_publish_interval` ticks when events or blocked shields change.

## Common Failures

- Upstream unreachable: page failures and retry/backoff state appear in `/status`; the scraper retries bounded failures and shrinks page size before surfacing a hard error.
- Postgres connection lost: scrape, publication, and retention cycles log failures and retry; restore Postgres and the next cycle resumes from durable state.
- IPFS pinning quota exceeded: publication cycles log the pinning error and retry on the next publication tick; existing published artifacts remain in Postgres for audit.
- Provider data loss or cleared bucket: before reusing a POI artifact CID, the publisher checks that the provider still holds it and repins the bytes if not. A missing active manifest CID triggers a new manifest, and a pending manifest with a missing CID is abandoned and rebuilt at a higher sequence. Superseded CIDs remain in the audit tables and are cleaned up by retention later.
- IPNS DHT publish timeout: manifest pinning may succeed while IPNS update fails; the scheduler retries on the next publication or republish tick.
- Retention sweep behavior: superseded artifact and manifest CIDs older than `retention_interval` are unpinned, but their publication rows are retained for audit.
