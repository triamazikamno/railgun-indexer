use crate::manifest::{IndexedArtifactError, IndexedArtifactManifest, ManifestError, content_hash};
use crate::publish::ipfs::{IpfsClient, IpfsError, pin_manifest};
use crate::publish::ipns::{IpnsError, ManifestIpnsPublisher};
use ed25519_dalek::SigningKey;
use thiserror::Error;

pub async fn publish_indexed_artifact_manifest(
    ipfs_client: &dyn IpfsClient,
    ipns_publisher: &dyn ManifestIpnsPublisher,
    signing_key: &SigningKey,
    mut manifest: IndexedArtifactManifest,
) -> Result<PublishedIndexedArtifactManifest, IndexedManifestPublicationError> {
    manifest.sign_manifest(signing_key)?;
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(ManifestError::Json)?;
    let byte_size =
        u64::try_from(manifest_bytes.len()).map_err(|_| ManifestError::ByteSizeOverflow)?;
    let sha256 = content_hash(&manifest_bytes);
    let cid = pin_manifest(ipfs_client, &manifest_bytes).await?;
    let cid = cid.to_string();
    let publication = ipns_publisher
        .publish_manifest_cid(&cid, manifest.sequence)
        .await?;

    Ok(PublishedIndexedArtifactManifest {
        manifest,
        cid,
        sha256,
        byte_size,
        ipns_name: publication.ipns_name,
        sequence: publication.sequence,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedIndexedArtifactManifest {
    pub manifest: IndexedArtifactManifest,
    pub cid: String,
    pub sha256: [u8; 32],
    pub byte_size: u64,
    pub ipns_name: String,
    pub sequence: u64,
}

#[derive(Debug, Error)]
pub enum IndexedManifestPublicationError {
    #[error("indexed manifest format failed")]
    IndexedArtifact(#[from] IndexedArtifactError),
    #[error("indexed manifest encoding failed")]
    Manifest(#[from] ManifestError),
    #[error("indexed manifest IPFS pinning failed")]
    Ipfs(#[from] IpfsError),
    #[error("indexed manifest IPNS publication failed")]
    Ipns(#[from] IpnsError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{INDEXED_ARTIFACT_MANIFEST_FORMAT_VERSION, PublisherIdentity};
    use crate::publish::ipfs::{IpfsError, raw_block_cid};
    use crate::publish::ipns::IpnsPublication;
    use alloy_primitives::FixedBytes;
    use async_trait::async_trait;
    use cid::Cid;
    use libp2p::PeerId;
    use std::sync::Mutex;

    #[tokio::test]
    async fn indexed_manifest_is_signed_pinned_and_published_to_ipns() {
        let ipfs = RecordingIpfsClient::default();
        let ipns = RecordingIpnsPublisher::default();
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let manifest = IndexedArtifactManifest::new(
            42,
            10,
            PublisherIdentity::ed25519(FixedBytes::ZERO),
            Vec::new(),
        );

        let published = publish_indexed_artifact_manifest(&ipfs, &ipns, &signing_key, manifest)
            .await
            .expect("publish indexed manifest");

        assert_eq!(
            published.manifest.format_version,
            INDEXED_ARTIFACT_MANIFEST_FORMAT_VERSION
        );
        published
            .manifest
            .verify_trusted_signature(&signing_key.verifying_key().to_bytes())
            .expect("signed manifest verifies");
        assert_eq!(published.sequence, 10);
        assert_eq!(
            published.byte_size,
            u64::try_from(ipfs.pinned_bytes_len()).expect("pinned byte size")
        );
        assert_eq!(published.cid, ipfs.pinned_cid());
        assert_eq!(published.ipns_name, "k51qzi5uqu5dlindexed".to_string());
        assert_eq!(ipns.published(), vec![(published.cid, 10)]);
    }

    #[derive(Debug, Default)]
    struct RecordingIpfsClient {
        pinned: Mutex<Vec<Vec<u8>>>,
    }

    impl RecordingIpfsClient {
        fn pinned_bytes_len(&self) -> usize {
            self.pinned.lock().expect("pinned bytes lock")[0].len()
        }

        fn pinned_cid(&self) -> String {
            raw_block_cid(&self.pinned.lock().expect("pinned bytes lock")[0])
                .expect("raw CID")
                .to_string()
        }
    }

    #[async_trait]
    impl IpfsClient for RecordingIpfsClient {
        fn service_name(&self) -> &'static str {
            "recording"
        }

        async fn pin_bytes(&self, bytes: &[u8]) -> Result<Cid, IpfsError> {
            self.pinned
                .lock()
                .expect("pinned bytes lock")
                .push(bytes.to_vec());
            raw_block_cid(bytes)
        }

        async fn unpin(&self, _cid: &Cid) -> Result<(), IpfsError> {
            Ok(())
        }

        async fn contains(&self, _cid: &Cid) -> Result<bool, IpfsError> {
            Ok(true)
        }
    }

    #[derive(Debug, Default)]
    struct RecordingIpnsPublisher {
        published: Mutex<Vec<(String, u64)>>,
    }

    impl RecordingIpnsPublisher {
        fn published(&self) -> Vec<(String, u64)> {
            self.published.lock().expect("published lock").clone()
        }
    }

    #[async_trait]
    impl ManifestIpnsPublisher for RecordingIpnsPublisher {
        async fn publish_manifest_cid(
            &self,
            manifest_cid: &str,
            sequence: u64,
        ) -> Result<IpnsPublication, IpnsError> {
            self.published
                .lock()
                .expect("published lock")
                .push((manifest_cid.to_string(), sequence));
            Ok(IpnsPublication {
                peer_id: PeerId::random(),
                ipns_name: "k51qzi5uqu5dlindexed".to_string(),
                value: format!("/ipfs/{manifest_cid}"),
                sequence,
            })
        }
    }
}
