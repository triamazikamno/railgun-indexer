#[allow(clippy::wildcard_imports)]
use super::*;

/// Provider availability checks in flight at once before a manifest is published.
const ARTIFACT_AVAILABILITY_CHECK_CONCURRENCY: usize = 8;

/// The chains of one publication cycle: manifest entries, every artifact CID they reference, the
/// datasets to remember once the manifest is published, the chains whose full derivation found
/// reuse mismatches but no catalogs, and the reuse mismatches to report once every chain's
/// watermarks are validated.
#[derive(Default)]
struct PublishedChains {
    entries: Vec<IndexedArtifactChainEntry>,
    /// Validated with the manifest entries but never published.
    catalog_less: Vec<IndexedArtifactChainEntry>,
    artifact_cids: BTreeSet<String>,
    remembered: Vec<((u64, Address), Vec<RememberedDataset>)>,
    reuse_mismatches: Vec<ReuseMismatch>,
}

/// A cycle's manifest chains after their watermarks passed validation under `canonicality_guard`,
/// which stays held until the manifest's IPNS publication is recorded.
struct ValidatedChains {
    entries: Vec<IndexedArtifactChainEntry>,
    artifact_cids: BTreeSet<String>,
    remembered: Vec<((u64, Address), Vec<RememberedDataset>)>,
    full_derivation: bool,
    canonicality_guard: ChainCanonicalityLease,
}

impl ChainIndexedPublicationScheduler {
    pub(super) fn ensure_publication_running(&self) -> Result<()> {
        if shutdown_requested(&self.shutdown) {
            Err(eyre!(
                "publication stopped at a cooperative shutdown boundary"
            ))
        } else {
            Ok(())
        }
    }

    pub(super) fn acquire_pin_ownership(&self) -> Result<PinOwnershipLease> {
        self.ensure_publication_running()?;
        self.pin_lifecycle
            .try_acquire_pin_ownership()
            .ok_or_else(|| eyre!("pin ownership admission is closed for shutdown"))
    }

    pub(super) async fn publish_cycle(&mut self, now: SystemTime) -> Result<()> {
        let result = self.try_publish_cycle(now).await;
        if result.is_err() {
            // A reused chunk that a provider lost would otherwise fail every later cycle; a full
            // derivation re-pins it.
            self.remembered_chains.clear();
        }
        result
    }

    /// Replaces the remembered datasets with those of the manifest just published to IPNS.
    pub(super) fn remember_published_chains(
        &mut self,
        chains: Vec<((u64, Address), Vec<RememberedDataset>)>,
    ) {
        self.remembered_chains = chains.into_iter().collect();
    }

    /// Publishes every configured chain concurrently and gathers what the manifest and the reuse
    /// mismatch report need.
    async fn publish_chain_entries(
        &self,
        configured_chains: &[ChainIndexedChainConfig],
        full_derivation: bool,
    ) -> Result<PublishedChains> {
        let published_chains = join_all(
            configured_chains
                .iter()
                .map(|chain| self.publish_chain_entry(chain, full_derivation)),
        )
        .await;

        let mut published = PublishedChains::default();
        for (chain, result) in configured_chains.iter().zip(published_chains) {
            self.ensure_publication_running()?;
            let Some(chain_entry) = result.wrap_err_with(|| {
                format!(
                    "publish chain-indexed artifacts for chain {} ({})",
                    chain.chain_id, chain.railgun_contract
                )
            })?
            else {
                continue;
            };
            published
                .reuse_mismatches
                .extend(chain_entry.reuse_mismatches);
            if chain_entry.entry.catalogs.is_empty() {
                published.catalog_less.push(chain_entry.entry);
                continue;
            }
            published.remembered.push((
                (chain.chain_id, chain.railgun_contract),
                chain_entry.remembered,
            ));
            published.entries.push(chain_entry.entry);
            published.artifact_cids.extend(chain_entry.artifact_cids);
        }
        Ok(published)
    }

    /// Derives every chain, then validates the result and reports its reuse mismatches under the
    /// final canonicality lease. `None` when the cycle has no manifest to publish.
    async fn derive_validated_chains(
        &mut self,
        now: SystemTime,
    ) -> Result<Option<ValidatedChains>> {
        let rewind_generation = self
            .canonicality
            .publication_lease()
            .await
            .rewind_generation();
        let configured_chains = self.config.chain_indexed.chains.clone();
        let full_derivation = self.remembered_chains.is_empty()
            || full_derivation_due(self.last_full_derivation, now);
        let PublishedChains {
            entries,
            catalog_less,
            artifact_cids,
            remembered,
            reuse_mismatches,
        } = self
            .publish_chain_entries(&configured_chains, full_derivation)
            .await?;
        if entries.is_empty() && reuse_mismatches.is_empty() {
            return Ok(None);
        }

        let canonicality_guard = self.canonicality.publication_lease().await;
        // A replay can restore every watermark header over chunks built from rewound rows.
        if canonicality_guard.rewind_generation() != rewind_generation {
            return Err(eyre!(
                "reorg rewind committed during chain-indexed artifact derivation"
            ));
        }
        self.validate_combined_manifest_snapshot(&configured_chains, &entries)
            .await?;
        self.validate_combined_manifest_snapshot(&configured_chains, &catalog_less)
            .await?;
        self.report_reuse_mismatches(reuse_mismatches).await;
        if entries.is_empty() {
            // The remembered chunks were disproved and no manifest replaces them.
            self.remembered_chains.clear();
            return Ok(None);
        }
        Ok(Some(ValidatedChains {
            entries,
            artifact_cids,
            remembered,
            full_derivation,
            canonicality_guard,
        }))
    }

    async fn try_publish_cycle(&mut self, now: SystemTime) -> Result<()> {
        self.ensure_publication_running()?;
        if self.reconcile_pending_manifest().await? {
            return Ok(());
        }
        let Some(ValidatedChains {
            entries: chains,
            artifact_cids,
            remembered,
            full_derivation,
            canonicality_guard,
        }) = self.derive_validated_chains(now).await?
        else {
            return Ok(());
        };

        let sequence = self.next_ipns_sequence(now).await?;
        let mut manifest = railgun_indexer_core::manifest::IndexedArtifactManifest::new(
            unix_millis(now)?,
            sequence,
            PublisherIdentity::ed25519(FixedBytes::ZERO),
            chains,
        );
        let chain_count = manifest.chains.len();
        let catalog_count = manifest
            .chains
            .iter()
            .map(|chain| chain.catalogs.len())
            .sum::<usize>();
        manifest
            .sign_manifest(&self.signing_key)
            .wrap_err("sign chain-indexed manifest")?;
        let manifest_json =
            serde_json::to_string(&manifest).wrap_err("serialize chain-indexed manifest")?;
        let manifest_bytes = manifest_json.as_bytes();
        let byte_size = u64::try_from(manifest_bytes.len())
            .wrap_err("chain-indexed manifest byte size overflow")?;
        let manifest_hash = content_hash(manifest_bytes);
        let artifact_cids = artifact_cids.into_iter().collect::<Vec<_>>();
        let pin_lifecycle_guard = self.pin_lifecycle.lock().await;
        self.ensure_indexed_artifacts_available(&artifact_cids)
            .await?;
        let ownership = self.acquire_pin_ownership()?;
        let manifest_cid = match pin_manifest(self.ipfs_client.as_ref(), manifest_bytes).await {
            Ok(cid) => cid,
            Err(error) => {
                ownership.settle();
                return Err(error).wrap_err("pin chain-indexed manifest");
            }
        };

        let audit_result = async {
            let mut tx = self
                .store
                .begin()
                .await
                .wrap_err("begin chain-indexed manifest audit transaction")?;
            Audit::record_indexed_manifest_pin(
                &mut tx,
                &manifest_cid,
                &artifact_cids,
                sequence,
                byte_size,
                &manifest_hash,
                INDEXED_ARTIFACT_MANIFEST_FORMAT_VERSION,
                &manifest_json,
            )
            .await
            .wrap_err("record chain-indexed manifest pin")?;
            tx.commit()
                .await
                .wrap_err("commit chain-indexed manifest pin audit")
        }
        .await;
        if let Err(error) = audit_result {
            self.cleanup_uncommitted_pin_while_locked(
                &manifest_cid,
                "chain-indexed manifest",
                ownership,
            )
            .await;
            return Err(error);
        }
        ownership.settle();
        drop(pin_lifecycle_guard);
        self.ensure_publication_running()?;

        let manifest_cid_string = manifest_cid.to_string();
        self.ipns_publisher
            .publish_manifest_cid_with_lease(
                &manifest_cid_string,
                sequence,
                canonicality_guard.clone(),
            )
            .await
            .wrap_err("publish chain-indexed manifest CID to IPNS")?;
        self.ensure_publication_running()?;
        let mut tx = self
            .store
            .begin()
            .await
            .wrap_err("begin chain-indexed manifest IPNS audit transaction")?;
        Audit::record_indexed_manifest_ipns_publication(&mut tx, &manifest_cid, sequence)
            .await
            .wrap_err("record chain-indexed manifest IPNS publication")?;
        tx.commit()
            .await
            .wrap_err("commit chain-indexed manifest IPNS audit")?;
        drop(canonicality_guard);
        self.remember_published_chains(remembered);
        if full_derivation {
            self.last_full_derivation = Some(now);
        }

        info!(target: LOG_TARGET,
            manifest_cid = %manifest_cid_string,
            sequence,
            ipns_published = true,
            chain_count,
            catalog_count,
            byte_size,
            sha256 = %hex::encode_prefixed(manifest_hash),
            "published chain-indexed manifest"
        );
        Ok(())
    }

    pub(super) async fn reconcile_pending_manifest(&mut self) -> Result<bool> {
        let ipns_publisher = self.ipns_publisher.clone();
        self.reconcile_pending_manifest_with(move |cid, sequence, canonicality_lease| async move {
            ipns_publisher
                .publish_manifest_cid_with_lease(&cid, sequence, canonicality_lease)
                .await
                .wrap_err("reconcile pending chain-indexed manifest IPNS publication")?;
            Ok(())
        })
        .await
    }

    pub(super) async fn reconcile_pending_manifest_with<PublishIpns, PublishFuture>(
        &mut self,
        publish_ipns: PublishIpns,
    ) -> Result<bool>
    where
        PublishIpns: FnOnce(String, u64, ChainCanonicalityLease) -> PublishFuture,
        PublishFuture: Future<Output = Result<()>>,
    {
        self.ensure_publication_running()?;
        let Some(pending) = Audit::pending_indexed_manifest_publication(
            self.store.pool(),
            &self.signing_key.verifying_key().to_bytes(),
        )
        .await
        .wrap_err("load pending chain-indexed manifest")?
        else {
            return Ok(false);
        };
        let configured_chains = self.config.chain_indexed.chains.clone();
        let canonicality_guard = self.canonicality.publication_lease().await;
        self.validate_combined_manifest_snapshot(&configured_chains, &pending.manifest.chains)
            .await
            .wrap_err("revalidate pending chain-indexed manifest watermarks")?;
        let pin_lifecycle_guard = self.pin_lifecycle.lock().await;
        self.ensure_indexed_artifacts_available(&pending.artifact_cids)
            .await?;
        let manifest_cid = pending
            .cid
            .parse::<cid::Cid>()
            .wrap_err("parse pending chain-indexed manifest CID")?;
        let ownership = self.acquire_pin_ownership()?;
        let returned_cid =
            match pin_manifest(self.ipfs_client.as_ref(), pending.manifest_json.as_bytes()).await {
                Ok(cid) => cid,
                Err(error) => {
                    ownership.settle();
                    return Err(error).wrap_err("re-pin pending chain-indexed manifest");
                }
            };
        if returned_cid != manifest_cid {
            self.cleanup_uncommitted_pin_while_locked(
                &returned_cid,
                "mismatched chain-indexed reconciliation manifest",
                ownership,
            )
            .await;
            return Err(IpfsError::CidMismatch {
                service: self.ipfs_client.service_name().to_string(),
                expected: Box::new(manifest_cid),
                returned: Box::new(returned_cid),
            }
            .into());
        }
        ownership.settle();
        drop(pin_lifecycle_guard);
        self.ensure_publication_running()?;
        publish_ipns(
            pending.cid.clone(),
            pending.sequence,
            canonicality_guard.clone(),
        )
        .await?;
        self.ensure_publication_running()?;
        let mut tx = self
            .store
            .begin()
            .await
            .wrap_err("begin pending chain-indexed manifest activation")?;
        Audit::record_indexed_manifest_ipns_publication(&mut tx, &manifest_cid, pending.sequence)
            .await
            .wrap_err("activate reconciled chain-indexed manifest")?;
        tx.commit()
            .await
            .wrap_err("commit reconciled chain-indexed manifest activation")?;
        drop(canonicality_guard);
        self.last_ipns_sequence = Some(pending.sequence);
        self.ipns_sequence_loaded = true;
        Ok(true)
    }

    async fn validate_combined_manifest_snapshot(
        &self,
        configured_chains: &[ChainIndexedChainConfig],
        entries: &[IndexedArtifactChainEntry],
    ) -> Result<()> {
        for entry in entries {
            let chain = configured_chains
                .iter()
                .find(|chain| {
                    chain.chain_id == entry.scope.chain_id
                        && chain.railgun_contract == entry.scope.railgun_contract
                })
                .ok_or_else(|| {
                    eyre!(
                        "combined indexed manifest contains unconfigured chain {} ({})",
                        entry.scope.chain_id,
                        entry.scope.railgun_contract
                    )
                })?;
            self.validate_chain_snapshot(chain, &entry.latest_indexed)
                .await?;
        }
        Ok(())
    }

    /// A `full_derivation` derives every chunk and checks the chunks it would have reused. Returns
    /// `None` when the chain has neither catalogs nor reuse mismatches.
    pub(super) async fn publish_chain_entry(
        &self,
        chain: &ChainIndexedChainConfig,
        full_derivation: bool,
    ) -> Result<Option<PublishedChainEntry>> {
        let scope = ChainScope {
            chain_type: ChainType::Evm,
            chain_id: chain.chain_id,
            railgun_contract: chain.railgun_contract,
        };
        let latest_indexed = self.latest_indexed_heights(chain).await?;
        let previous = self
            .remembered_chains
            .get(&(chain.chain_id, chain.railgun_contract))
            .map(Vec::as_slice);
        let mut catalogs = Vec::new();
        let mut artifact_cids = BTreeSet::new();
        let mut remembered = Vec::new();
        let mut reuse_mismatches = Vec::new();
        // `latest_indexed` follows `chain.datasets` order and omits datasets without progress.
        for height in &latest_indexed {
            let reuse = self.dataset_chunk_reuse(chain, previous, height).await?;
            let derivation = if full_derivation {
                ChunkReuse::DeriveAll
            } else {
                reuse
            };
            let (published, dataset) = match height.dataset_kind {
                IndexedDatasetKind::PublicTxid => {
                    self.publish_public_txid_catalog(chain, &scope, height, derivation)
                        .await?
                }
                IndexedDatasetKind::WalletScan => {
                    self.publish_wallet_scan_catalog(chain, &scope, height, derivation)
                        .await?
                }
                IndexedDatasetKind::Commitments => {
                    self.publish_commitment_catalog(chain, &scope, height, derivation)
                        .await?
                }
                IndexedDatasetKind::MerkleCheckpoint => {
                    self.publish_merkle_checkpoint_catalog(chain, &scope, height, derivation)
                        .await?
                }
            };
            if full_derivation {
                reuse_mismatches.extend(changed_reused_chunks(chain, reuse, &dataset));
            }
            extend_published_catalogs(&mut catalogs, &mut artifact_cids, published);
            remembered.push(dataset);
        }
        self.validate_chain_snapshot(chain, &latest_indexed).await?;
        if catalogs.is_empty() && reuse_mismatches.is_empty() {
            return Ok(None);
        }
        Ok(Some(PublishedChainEntry {
            entry: IndexedArtifactChainEntry {
                scope,
                latest_indexed,
                catalogs,
            },
            artifact_cids: artifact_cids.into_iter().collect(),
            remembered,
            reuse_mismatches,
        }))
    }

    /// Logs and records reuse mismatches of chains whose watermarks were just validated.
    async fn report_reuse_mismatches(&self, mismatches: Vec<ReuseMismatch>) {
        for mismatch in mismatches {
            error!(target: LOG_TARGET,
                chain_id = mismatch.chain_id,
                railgun_contract = %mismatch.railgun_contract,
                dataset = ?mismatch.dataset,
                range_start = mismatch.range.start,
                range_end = mismatch.range.end,
                "full derivation changed a chunk that chain-indexed publication would have reused"
            );
            self.status
                .write()
                .await
                .record_chain_indexed_reuse_mismatch(
                    mismatch.chain_id,
                    mismatch.railgun_contract.to_string(),
                    mismatch.dataset,
                    &mismatch.range,
                );
        }
    }

    async fn dataset_chunk_reuse<'a>(
        &self,
        chain: &ChainIndexedChainConfig,
        previous: Option<&'a [RememberedDataset]>,
        height: &LatestIndexedHeight,
    ) -> Result<ChunkReuse<'a>> {
        let Some(remembered) = previous.and_then(|datasets| {
            datasets
                .iter()
                .find(|dataset| dataset.dataset_kind == height.dataset_kind)
        }) else {
            return Ok(ChunkReuse::DeriveAll);
        };
        let stored_header = self
            .store
            .indexed_block_header(EVM_CHAIN_TYPE, chain.chain_id, remembered.height.0)
            .await
            .wrap_err("read remembered chain-indexed publication height")?;
        Ok(chunk_reuse(
            Some(remembered),
            height,
            stored_header.map(|header| header.block_hash),
        ))
    }

    pub(super) async fn ensure_indexed_artifacts_available(
        &self,
        artifact_cids: &[String],
    ) -> Result<()> {
        for batch in artifact_cids.chunks(ARTIFACT_AVAILABILITY_CHECK_CONCURRENCY) {
            let checks = batch
                .iter()
                .map(|cid| self.ensure_indexed_artifact_available(cid));
            for result in join_all(checks).await {
                result?;
            }
        }
        Ok(())
    }

    async fn ensure_indexed_artifact_available(&self, cid: &str) -> Result<()> {
        let parsed = cid
            .parse::<cid::Cid>()
            .wrap_err_with(|| format!("parse indexed manifest artifact CID {cid}"))?;
        if !self
            .ipfs_client
            .contains(&parsed)
            .await
            .wrap_err_with(|| format!("check indexed manifest artifact CID {cid}"))?
        {
            return Err(eyre!(
                "indexed manifest artifact CID {cid} is unavailable before manifest publication"
            ));
        }
        Ok(())
    }

    async fn validate_chain_snapshot(
        &self,
        chain: &ChainIndexedChainConfig,
        latest_indexed: &[LatestIndexedHeight],
    ) -> Result<()> {
        for height in latest_indexed {
            let header = self
                .store
                .indexed_block_header(EVM_CHAIN_TYPE, chain.chain_id, height.block_number)
                .await
                .wrap_err("revalidate chain-indexed publication watermark")?;
            validate_publication_watermark(height, header.as_ref())?;
        }
        Ok(())
    }

    async fn next_ipns_sequence(&mut self, now: SystemTime) -> Result<u64> {
        if !self.ipns_sequence_loaded {
            self.last_ipns_sequence = self
                .store
                .last_chain_indexed_ipns_sequence()
                .await
                .wrap_err("load persisted chain-indexed IPNS sequence")?;
            self.ipns_sequence_loaded = true;
        }
        let sequence = unix_millis(now)?;
        let sequence = self.last_ipns_sequence.map_or(sequence, |last_sequence| {
            sequence.max(last_sequence.saturating_add(1))
        });
        self.store
            .record_chain_indexed_ipns_sequence(sequence)
            .await
            .wrap_err("persist chain-indexed IPNS sequence")?;
        self.last_ipns_sequence = Some(sequence);
        Ok(sequence)
    }
}

/// Every chunk that `reuse` would have kept but `derived` no longer contains.
fn changed_reused_chunks(
    chain: &ChainIndexedChainConfig,
    reuse: ChunkReuse<'_>,
    derived: &RememberedDataset,
) -> Vec<ReuseMismatch> {
    reuse
        .kept_chunks(chain.start_block)
        .into_iter()
        .enumerate()
        .filter(|(index, kept)| {
            !derived.chunks.get(*index).is_some_and(|chunk| {
                chunk.range == kept.range && chunk.sha256 == kept.sha256 && chunk.cid == kept.cid
            })
        })
        .map(|(_, kept)| ReuseMismatch {
            chain_id: chain.chain_id,
            railgun_contract: chain.railgun_contract,
            dataset: derived.dataset_kind,
            range: kept.range,
        })
        .collect()
}

pub(super) fn validate_publication_watermark(
    height: &LatestIndexedHeight,
    header: Option<&StoredIndexedBlockHeader>,
) -> Result<()> {
    let header = header.ok_or_else(|| {
        eyre!(
            "chain-indexed publication watermark {} for {:?} was rewound during publication",
            height.block_number,
            height.dataset_kind
        )
    })?;
    if header.block_hash.as_slice() != height.block_hash.as_slice() {
        return Err(eyre!(
            "chain-indexed publication watermark {} for {:?} changed during publication",
            height.block_number,
            height.dataset_kind
        ));
    }
    Ok(())
}
