use alloy::hex;
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use poi::artifacts::{
    BlockedShieldsArtifact, Manifest, SnapshotEvent, SnapshotReader, verify_blocked_shield,
};
use poi::cache::{PoiCache, PoiCacheIdentity};
use poi::poi::PoiEventType;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

const RELEASED_BASELINE: &str = "16642b6d9e084f7f1e2f9c9cb649fcca74da60b3";
const FIXTURE_PUBLISHER_SEED: [u8; 32] = [42; 32];

#[test]
fn released_client_consumes_current_legacy_fixtures() -> Result<(), Box<dyn Error>> {
    let fixtures = default_fixtures();
    let manifest_bytes = read(&fixtures, "manifest.json")?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&FIXTURE_PUBLISHER_SEED);
    manifest.verify_trusted_signature(signing_key.verifying_key().as_bytes())?;
    let entry = manifest
        .entries
        .first()
        .ok_or("released compatibility manifest has no entry")?;
    if manifest.entries.len() != 1 {
        return Err("released compatibility manifest must have exactly one entry".into());
    }

    let base_bytes = read(&fixtures, "base.bin")?;
    verify_descriptor(&entry.base, &base_bytes)?;
    let base = SnapshotReader::read(&base_bytes)?;
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        base.header.chain_type,
        base.header.chain_id,
        "V2_PoseidonMerkle",
        entry.list_key,
    ));
    validate_legacy_event_semantics(&base.events)?;
    cache.apply_verified_artifact_events(&base.events)?;

    for (index, descriptor) in entry.deltas.iter().enumerate() {
        let name = if index == 0 {
            "delta.bin"
        } else {
            return Err("unexpected extra delta".into());
        };
        let bytes = read(&fixtures, name)?;
        verify_descriptor(descriptor, &bytes)?;
        let delta = SnapshotReader::read(&bytes)?;
        validate_legacy_event_semantics(&delta.events)?;
        cache.apply_verified_artifact_events(&delta.events)?;
    }

    let blocked_bytes = read(&fixtures, "blocked.json")?;
    verify_descriptor(&entry.blocked_shields, &blocked_bytes)?;
    let blocked = BlockedShieldsArtifact::read(&blocked_bytes)?;
    let blocked = blocked
        .blocked_shields
        .into_iter()
        .map(|record| record.into_signed_blocked_shield())
        .collect::<Vec<_>>();
    for record in &blocked {
        verify_blocked_shield(record, &entry.list_key.0)?;
    }
    cache.replace_blocked_shields(&blocked)?;

    let root = cache
        .root_at_global_index(entry.current_tip_index)
        .ok_or("released client did not reach the manifest tip")?;
    if root != entry.current_tip_merkleroot {
        return Err(format!(
            "released client root mismatch at tip {}: expected {}, got {}",
            entry.current_tip_index,
            hex::encode_prefixed(entry.current_tip_merkleroot),
            hex::encode_prefixed(root)
        )
        .into());
    }
    println!(
        "released POI client baseline {RELEASED_BASELINE} consumed tip {} root {}",
        entry.current_tip_index,
        hex::encode_prefixed(root)
    );
    Ok(())
}

fn validate_legacy_event_semantics(events: &[SnapshotEvent]) -> Result<(), Box<dyn Error>> {
    if events
        .iter()
        .any(|event| event.signature != [0; 64] || event.event_type != PoiEventType::Shield)
    {
        return Err("legacy snapshot events must be unsigned Shield records".into());
    }
    Ok(())
}

fn verify_descriptor(
    descriptor: &poi::artifacts::ArtifactDescriptor,
    bytes: &[u8],
) -> Result<(), Box<dyn Error>> {
    descriptor.verify_bytes(bytes)?;
    let cid = Cid::new_v1(0x55, Code::Sha2_256.digest(bytes));
    if descriptor.cid != cid.to_string() {
        return Err(format!(
            "descriptor CID mismatch: expected {}, got {cid}",
            descriptor.cid
        )
        .into());
    }
    Ok(())
}

fn read(root: &Path, name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(fs::read(root.join(name))?)
}

fn default_fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/released-client-v3")
}
