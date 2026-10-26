use crate::store::{Store, StoreError, StoredBlockedShield};
use alloy_primitives::hex;
use poi::artifacts::v4::{
    BlockedShieldsArtifact as PoiBlockedShieldsArtifact, Error as PoiArtifactError, Scope,
};
use poi::poi::SignedBlockedShield;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Lifecycle {
    store: Store,
}

impl Lifecycle {
    #[must_use]
    pub const fn new(store: Store) -> Self {
        Self { store }
    }

    pub async fn build_poi_blocked_shields_artifact(
        &self,
        scope: &Scope,
    ) -> Result<EncodedPoiBlockedShieldsArtifact, LifecycleError> {
        let blocked_shields = self
            .store
            .all_blocked_shields(&scope.list_key, scope.chain_id)
            .await?;
        encode_poi_blocked_shields_artifact(scope, &blocked_shields)
            .map_err(LifecycleError::PoiArtifact)
    }
}

#[derive(Debug, Error)]
pub enum LifecycleError {
    #[error("store operation failed")]
    Store(#[from] StoreError),
    #[error("POI v4 blocked-shields artifact encode failed")]
    PoiArtifact(#[from] PoiArtifactError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedPoiBlockedShieldsArtifact {
    pub bytes: Vec<u8>,
    pub row_count: usize,
}

pub fn encode_poi_blocked_shields_artifact(
    scope: &Scope,
    records: &[StoredBlockedShield],
) -> Result<EncodedPoiBlockedShieldsArtifact, PoiArtifactError> {
    let blocked_shields = records
        .iter()
        .map(signed_blocked_shield)
        .collect::<Vec<_>>();
    let artifact = PoiBlockedShieldsArtifact::from_signed_records(scope.clone(), &blocked_shields);
    Ok(EncodedPoiBlockedShieldsArtifact {
        bytes: artifact.to_bytes()?,
        row_count: blocked_shields.len(),
    })
}

fn signed_blocked_shield(record: &StoredBlockedShield) -> SignedBlockedShield {
    SignedBlockedShield {
        commitment_hash: hex::encode_prefixed(record.commitment_hash),
        blinded_commitment: hex::encode_prefixed(record.blinded_commitment),
        block_reason: record.block_reason.clone(),
        signature: hex::encode_prefixed(record.signature),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::FixedBytes;
    use ed25519_dalek::{Signer, SigningKey};
    use poi::artifacts::ArtifactDescriptor;
    use poi::artifacts::v4::{
        ArtifactEncoding, BlockedShieldsDescriptor, Compression,
        FORMAT_VERSION as POI_ARTIFACT_FORMAT_VERSION,
    };
    use poi::artifacts::verify::canonical_blocked_shield_message;

    #[test]
    fn v4_blocked_shield_descriptor_verifies_empty_artifact() {
        let scope = Scope::new(FixedBytes::from([9; 32]), 0, 1, "V2_PoseidonMerkle");

        verify_poi_blocked_shields(&scope, &[]);
    }

    #[test]
    fn v4_blocked_shield_descriptor_verifies_signed_artifact() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let scope = Scope::new(
            FixedBytes::from(signing_key.verifying_key().to_bytes()),
            0,
            1,
            "V2_PoseidonMerkle",
        );
        let mut signed = SignedBlockedShield {
            commitment_hash: hex::encode_prefixed([3; 32]),
            blinded_commitment: hex::encode_prefixed([4; 32]),
            block_reason: Some("fixture".to_string()),
            signature: String::new(),
        };
        let signature = signing_key
            .sign(&canonical_blocked_shield_message(&signed))
            .to_bytes();
        signed.signature = hex::encode_prefixed(signature);
        let records = [StoredBlockedShield {
            commitment_hash: [3; 32],
            blinded_commitment: [4; 32],
            block_reason: signed.block_reason,
            signature,
        }];

        verify_poi_blocked_shields(&scope, &records);
    }

    fn verify_poi_blocked_shields(scope: &Scope, records: &[StoredBlockedShield]) {
        let encoded =
            encode_poi_blocked_shields_artifact(scope, records).expect("encode v4 blocked shields");
        let descriptor = BlockedShieldsDescriptor {
            artifact: ArtifactDescriptor::from_bytes("bafyblocked", &encoded.bytes),
            format_version: POI_ARTIFACT_FORMAT_VERSION,
            scope: scope.clone(),
            row_count: u64::try_from(encoded.row_count).expect("row count"),
            encoding: ArtifactEncoding::CanonicalJson,
            compression: Compression::Identity,
        };

        let decoded = descriptor
            .verify_bytes(&encoded.bytes)
            .expect("descriptor verifies v4 bytes");
        assert_eq!(decoded.scope, *scope);
        assert_eq!(decoded.blocked_shields.len(), records.len());
    }
}
