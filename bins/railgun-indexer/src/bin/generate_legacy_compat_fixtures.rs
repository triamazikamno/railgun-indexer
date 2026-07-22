use alloy_primitives::{FixedBytes, hex};
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use eyre::{Result, WrapErr, ensure};
use poi::artifacts::verify::{canonical_blocked_shield_message, canonical_poi_event_message};
use poi::artifacts::{SnapshotHeaderInput, SnapshotKind};
use poi::cache::{PoiCache, PoiCacheIdentity};
use poi::poi::{PoiEventType, SignedBlockedShield, SignedPoiEvent};
use railgun_indexer_core::manifest::{ArtifactDescriptor, Manifest, ManifestEntry};
use railgun_indexer_core::publish::ipfs::raw_block_cid;
use railgun_indexer_core::snapshot::format::FORMAT_VERSION;
use railgun_indexer_core::snapshot::{
    encode_legacy_blocked_shields_artifact, encode_legacy_snapshot, legacy_snapshot_events,
};
use railgun_indexer_core::store::{StoredBlockedShield, StoredEvent};
use std::fs;
use std::path::{Path, PathBuf};

const FIXTURE_ISSUED_AT_MS: u64 = 1_767_225_600_000;
const FIXTURE_SEQUENCE: u64 = 1_767_225_600_000;
const FIXTURE_CREATED_AT_SECONDS: i64 = 1_767_225_600;
const FIXTURE_CHAIN_ID: u64 = 1;
const FIXTURE_CHAIN_TYPE: u8 = 0;
const FIXTURE_TXID_VERSION: &str = "V2_PoseidonMerkle";
const FIXTURE_SIGNING_SEED: [u8; 32] = [42; 32];
const FIXTURE_UPSTREAM_HASH: [u8; 32] = [7; 32];

#[derive(Debug, Parser)]
#[command(about = "Generate deterministic released-client legacy POI fixtures")]
struct Args {
    #[arg(long)]
    check: bool,
    #[arg(value_name = "OUTPUT")]
    output: Option<PathBuf>,
}

impl Args {
    fn output(&self) -> PathBuf {
        self.output.clone().unwrap_or_else(default_output)
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let output = args.output();
    let fixtures = build_fixtures()?;
    if !args.check {
        fs::create_dir_all(&output).wrap_err("create legacy compatibility fixture directory")?;
    }
    for (name, bytes) in fixtures {
        let path = output.join(name);
        if args.check {
            let existing = fs::read(&path)
                .wrap_err_with(|| format!("read generated fixture {}", path.display()))?;
            ensure!(existing == bytes, "fixture {} is stale", path.display());
        } else {
            fs::write(&path, bytes)
                .wrap_err_with(|| format!("write generated fixture {}", path.display()))?;
        }
    }
    Ok(())
}

fn build_fixtures() -> Result<Vec<(&'static str, Vec<u8>)>> {
    let signing_key = SigningKey::from_bytes(&FIXTURE_SIGNING_SEED);
    let list_key = FixedBytes::from(signing_key.verifying_key().to_bytes());
    let events = [
        event(&signing_key, 0, 1, PoiEventType::Shield),
        event(&signing_key, 1, 2, PoiEventType::Transact),
        event(&signing_key, 2, 3, PoiEventType::Unshield),
    ];
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        FIXTURE_CHAIN_TYPE,
        FIXTURE_CHAIN_ID,
        FIXTURE_TXID_VERSION,
        list_key,
    ));
    let legacy_events = legacy_snapshot_events(&events);
    cache.apply_verified_artifact_events(&legacy_events[..2])?;
    let base_root = cache
        .root_at_global_index(1)
        .ok_or_else(|| eyre::eyre!("base fixture root is unavailable"))?;
    let base = encode_legacy_snapshot(
        &header(list_key, SnapshotKind::Base, 0, 1, base_root),
        &events[..2],
    )?;
    cache.apply_verified_artifact_events(&legacy_events[2..])?;
    let final_root = cache
        .root_at_global_index(2)
        .ok_or_else(|| eyre::eyre!("delta fixture root is unavailable"))?;
    let delta = encode_legacy_snapshot(
        &header(list_key, SnapshotKind::Delta, 2, 2, final_root),
        &events[2..],
    )?;
    let blocked_record = SignedBlockedShield {
        commitment_hash: hex::encode_prefixed([21; 32]),
        blinded_commitment: hex::encode_prefixed([22; 32]),
        block_reason: Some("released-client compatibility fixture".to_string()),
        signature: String::new(),
    };
    let blocked_signature = signing_key
        .sign(&canonical_blocked_shield_message(&blocked_record))
        .to_bytes();
    let blocked_record = StoredBlockedShield {
        commitment_hash: [21; 32],
        blinded_commitment: [22; 32],
        block_reason: blocked_record.block_reason,
        signature: blocked_signature,
    };
    let blocked = encode_legacy_blocked_shields_artifact(
        &list_key,
        FIXTURE_CHAIN_ID,
        FIXTURE_CHAIN_TYPE,
        &FIXTURE_UPSTREAM_HASH,
        &[blocked_record],
    )?
    .bytes;
    let entry = ManifestEntry {
        list_key,
        chain_id: FIXTURE_CHAIN_ID,
        base: descriptor(&base)?,
        deltas: vec![descriptor(&delta)?],
        retained_deltas: Vec::new(),
        blocked_shields: descriptor(&blocked)?,
        current_tip_index: 2,
        current_tip_merkleroot: final_root,
    };
    let mut manifest = Manifest::new(
        FORMAT_VERSION,
        FIXTURE_ISSUED_AT_MS,
        FIXTURE_SEQUENCE,
        FixedBytes::ZERO,
        vec![entry],
    );
    manifest.sign_manifest(&signing_key)?;
    let manifest = serde_json::to_vec(&manifest)?;

    Ok(vec![
        ("manifest.json", manifest),
        ("base.bin", base),
        ("delta.bin", delta),
        ("blocked.json", blocked),
    ])
}

fn descriptor(bytes: &[u8]) -> Result<ArtifactDescriptor> {
    Ok(ArtifactDescriptor::from_bytes(
        raw_block_cid(bytes)?.to_string(),
        bytes,
    ))
}

fn event(
    signing_key: &SigningKey,
    event_index: u64,
    byte: u8,
    event_type: PoiEventType,
) -> StoredEvent {
    let signed_event = SignedPoiEvent {
        index: event_index,
        blinded_commitment: FixedBytes::from([byte; 32]),
        signature: String::new(),
        event_type,
    };
    let signature = signing_key
        .sign(&canonical_poi_event_message(&signed_event))
        .to_bytes();
    StoredEvent {
        event_index,
        blinded_commitment: [byte; 32],
        signature,
        event_type,
    }
}

const fn header(
    list_key: FixedBytes<32>,
    kind: SnapshotKind,
    start_index: u64,
    end_index: u64,
    root: FixedBytes<32>,
) -> SnapshotHeaderInput {
    SnapshotHeaderInput {
        list_key: list_key.0,
        chain_id: FIXTURE_CHAIN_ID,
        chain_type: FIXTURE_CHAIN_TYPE,
        kind,
        start_index,
        end_index,
        tip_merkleroot: root.0,
        upstream_endpoint_hash: FIXTURE_UPSTREAM_HASH,
        created_at_unix_seconds: FIXTURE_CREATED_AT_SECONDS,
    }
}

fn default_output() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/released-client-v3")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sole_check_flag_uses_canonical_default_output() {
        let args = Args::try_parse_from(["generator", "--check"]).expect("parse --check");

        assert!(args.check);
        assert_eq!(args.output(), default_output());
    }

    #[test]
    fn explicit_output_and_check_are_order_independent() {
        for argv in [
            ["generator", "fixtures", "--check"],
            ["generator", "--check", "fixtures"],
        ] {
            let args = Args::try_parse_from(argv).expect("parse explicit output");
            assert!(args.check);
            assert_eq!(args.output(), PathBuf::from("fixtures"));
        }
    }
}
