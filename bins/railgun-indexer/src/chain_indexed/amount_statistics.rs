#[allow(clippy::wildcard_imports)]
use super::*;

/// Time one chain's derivation may take, so a stalled RPC cannot hold the canonicality lease
/// indefinitely. The chain count times this is the cycle's derivation budget.
const AMOUNT_STATISTICS_CHAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Amount-statistics publication, present only when it is enabled.
pub(super) struct AmountStatisticsPublication {
    pub(super) ipns_publisher: IpnsPublisher,
    /// Each chain with the provider that reads its covered block's timestamp.
    pub(super) chains: Vec<(ChainScope, RootProvider)>,
    pub(super) status: SharedStatus,
    /// Time allowed for one chain's derivation, including its covered-block RPC read.
    pub(super) chain_timeout: Duration,
}

impl AmountStatisticsPublication {
    pub(super) fn new(
        config: &Config,
        ipns_publisher: IpnsPublisher,
        status: SharedStatus,
    ) -> Result<Self> {
        let chains = config
            .chain_indexed
            .chains
            .iter()
            .map(|chain| {
                let provider = build_provider(&chain.rpc_url).wrap_err_with(|| {
                    format!(
                        "build amount-statistics RPC provider for chain {}",
                        chain.chain_id
                    )
                })?;
                let scope = ChainScope {
                    chain_type: ChainType::Evm,
                    chain_id: chain.chain_id,
                    railgun_contract: chain.railgun_contract,
                };
                Ok((scope, provider))
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            ipns_publisher,
            chains,
            status,
            chain_timeout: AMOUNT_STATISTICS_CHAIN_TIMEOUT,
        })
    }
}

impl ChainIndexedPublicationScheduler {
    /// Runs chain-indexed publication, then amount statistics, and returns the chain-indexed
    /// outcome alone.
    pub(super) async fn publish_cycles(&mut self, now: SystemTime) -> Result<()> {
        let chain_indexed = self.publish_cycle(now).await;
        self.publish_amount_statistics_cycle(now).await;
        chain_indexed
    }

    /// Statistics keep their own sequence, rows and error path: a failure goes to the log and
    /// `/status` and never reaches chain-indexed publication.
    async fn publish_amount_statistics_cycle(&self, now: SystemTime) {
        let Some(statistics) = &self.amount_statistics else {
            return;
        };
        let error = self
            .publish_amount_statistics(statistics, now)
            .await
            .err()
            .map(|error| format_report_chain(&error));
        if let Some(error) = &error {
            warn!(target: LOG_TARGET, error = %error, "amount-statistics publication cycle failed");
        }
        statistics
            .status
            .write()
            .await
            .record_amount_statistics_error(error);
    }

    async fn publish_amount_statistics(
        &self,
        statistics: &AmountStatisticsPublication,
        now: SystemTime,
    ) -> Result<()> {
        self.ensure_publication_running()?;
        // Held until the manifest is published, so no reorg rewind removes a counted record.
        let canonicality_guard = self.canonicality.publication_lease().await;
        let active = Audit::active_amount_statistics_manifest(self.store.pool())
            .await
            .wrap_err("load active amount-statistics manifest")?;
        let previous = active
            .as_ref()
            .map(|active| active.manifest.chains.as_slice())
            .unwrap_or_default();
        let chains = self
            .refresh_amount_statistics_chains(statistics, previous, &canonicality_guard)
            .await;
        if let Some(active) = &active {
            statistics
                .status
                .write()
                .await
                .record_amount_statistics_publication(active.cid.clone(), active.sequence);
        }
        // An unchanged covered block reuses its snapshot CID, so its entry matches the active one.
        // Unchanged entries are published again once the active IPNS record is due for renewal.
        let renewal_due = active.as_ref().is_some_and(|active| {
            now.duration_since(active.ipns_published_at)
                .is_ok_and(|elapsed| elapsed >= *self.config.ipns_republish_interval)
        });
        let unchanged = chains == previous && !renewal_due;
        if chains.is_empty() || unchanged {
            return Ok(());
        }

        let issued_at_ms = unix_millis(now)?;
        let manifest = AmountStatisticsManifest {
            format_version: AMOUNT_STATISTICS_MANIFEST_FORMAT_VERSION,
            issued_at_ms,
            sequence: self
                .store
                .reserve_amount_statistics_sequence(issued_at_ms)
                .await
                .wrap_err("reserve amount-statistics sequence")?,
            publisher: PublisherIdentity::ed25519(FixedBytes::ZERO),
            chains,
        };
        let manifest_cid = self.pin_amount_statistics_manifest(&manifest).await?;
        self.ensure_publication_running()?;
        self.activate_amount_statistics_manifest(
            statistics,
            &manifest_cid,
            manifest.sequence,
            canonicality_guard,
        )
        .await?;
        info!(target: LOG_TARGET,
            manifest_cid = %manifest_cid,
            sequence = manifest.sequence,
            chain_count = manifest.chains.len(),
            "published amount-statistics manifest"
        );
        Ok(())
    }

    /// Builds each chain's snapshot and records the chains that kept their last one.
    async fn refresh_amount_statistics_chains(
        &self,
        statistics: &AmountStatisticsPublication,
        previous: &[AmountStatisticsChainEntry],
        lease: &ChainCanonicalityLease,
    ) -> Vec<AmountStatisticsChainEntry> {
        let mut outcomes = Vec::with_capacity(statistics.chains.len());
        for (scope, provider) in &statistics.chains {
            let outcome = self
                .publish_amount_statistics_snapshot(
                    scope,
                    provider,
                    statistics.chain_timeout,
                    lease,
                )
                .await;
            outcomes.push((scope.clone(), outcome));
        }
        let (chains, chain_failures) = next_manifest_chains(previous, outcomes);
        statistics
            .status
            .write()
            .await
            .record_amount_statistics_chain_failures(chain_failures);
        chains
    }

    /// Publishes the pinned manifest through the amount-statistics IPNS name, then records it
    /// as active.
    async fn activate_amount_statistics_manifest(
        &self,
        statistics: &AmountStatisticsPublication,
        manifest_cid: &cid::Cid,
        sequence: u64,
        canonicality_guard: ChainCanonicalityLease,
    ) -> Result<()> {
        let manifest_cid_string = manifest_cid.to_string();
        statistics
            .ipns_publisher
            .publish_manifest_cid_with_lease(
                &manifest_cid_string,
                sequence,
                canonicality_guard.clone(),
            )
            .await
            .wrap_err("publish amount-statistics manifest CID to IPNS")?;
        self.ensure_publication_running()?;
        let mut tx = self
            .store
            .begin()
            .await
            .wrap_err("begin amount-statistics manifest IPNS audit transaction")?;
        Audit::record_amount_statistics_manifest_ipns_publication(&mut tx, manifest_cid, sequence)
            .await
            .wrap_err("record amount-statistics manifest IPNS publication")?;
        tx.commit()
            .await
            .wrap_err("commit amount-statistics manifest IPNS audit")?;
        drop(canonicality_guard);
        statistics
            .status
            .write()
            .await
            .record_amount_statistics_publication(manifest_cid_string, sequence);
        Ok(())
    }

    async fn publish_amount_statistics_snapshot(
        &self,
        scope: &ChainScope,
        provider: &RootProvider,
        chain_timeout: Duration,
        lease: &ChainCanonicalityLease,
    ) -> Result<AmountStatisticsChainEntry> {
        // Only the derivation is bounded: cancelling a pin would leave its ownership unsettled.
        let snapshot = tokio::time::timeout(
            chain_timeout,
            derive_amount_statistics(self.store.pool(), provider, scope, lease),
        )
        .await
        .map_err(|_| eyre!("amount-statistics derivation timed out after {chain_timeout:?}"))?
        .wrap_err("derive amount statistics")?;
        let encoded = encode_amount_statistics_snapshot(&snapshot)
            .wrap_err("encode amount-statistics snapshot")?;
        let mut entry = AmountStatisticsChainEntry {
            scope: snapshot.scope,
            covered_block: snapshot.covered_block,
            snapshot: AmountStatisticsSnapshotDescriptor {
                cid: String::new(),
                sha256: FixedBytes::from(content_hash(&encoded.bytes)),
                byte_size: u64::try_from(encoded.bytes.len())
                    .wrap_err("amount-statistics snapshot byte size overflow")?,
                encoding_version: snapshot.encoding_version,
                compression: CompressionAlgorithm::Zstd,
            },
        };
        entry.snapshot.cid = self
            .reuse_or_pin_amount_statistics_snapshot(
                &entry,
                encoded.decoded_byte_size,
                &encoded.bytes,
            )
            .await?;
        Ok(entry)
    }

    async fn reuse_or_pin_amount_statistics_snapshot(
        &self,
        entry: &AmountStatisticsChainEntry,
        decoded_byte_size: u64,
        bytes: &[u8],
    ) -> Result<String> {
        self.ensure_publication_running()?;
        let _pin_lifecycle = self.pin_lifecycle.lock().await;
        let reusable = Audit::live_amount_statistics_snapshot_cid(self.store.pool(), entry)
            .await
            .wrap_err("lookup reusable amount-statistics snapshot CID")?;
        let (cid, ownership) = self
            .reuse_or_pin_bytes(reusable, IndexedArtifactPublicationKind::Chunk, bytes)
            .await?;
        let audit_result = async {
            let mut tx = self
                .store
                .begin()
                .await
                .wrap_err("begin amount-statistics snapshot audit transaction")?;
            Audit::record_amount_statistics_snapshot_pin(&mut tx, entry, &cid, decoded_byte_size)
                .await
                .wrap_err("record amount-statistics snapshot pin")?;
            tx.commit()
                .await
                .wrap_err("commit amount-statistics snapshot audit")
        }
        .await;
        self.settle_pin_audit(&cid, ownership, audit_result, "amount-statistics snapshot")
            .await?;
        self.ensure_publication_running()?;
        Ok(cid.to_string())
    }

    /// Signs the manifest with the chain-indexed publisher key, pins the envelope and records it
    /// as pending.
    async fn pin_amount_statistics_manifest(
        &self,
        manifest: &AmountStatisticsManifest,
    ) -> Result<cid::Cid> {
        let envelope = AmountStatisticsManifestEnvelope::sign(manifest, &self.signing_key)
            .wrap_err("sign amount-statistics manifest")?;
        let envelope_json = serde_json::to_string(&envelope)
            .wrap_err("serialize amount-statistics manifest envelope")?;
        let snapshot_cids = manifest
            .chains
            .iter()
            .map(|entry| entry.snapshot.cid.clone())
            .collect::<Vec<_>>();
        let _pin_lifecycle = self.pin_lifecycle.lock().await;
        self.ensure_indexed_artifacts_available(&snapshot_cids)
            .await?;
        let ownership = self.acquire_pin_ownership()?;
        let cid = match pin_manifest(self.ipfs_client.as_ref(), envelope_json.as_bytes()).await {
            Ok(cid) => cid,
            Err(error) => {
                ownership.settle();
                return Err(error).wrap_err("pin amount-statistics manifest");
            }
        };
        let audit_result = async {
            let mut tx = self
                .store
                .begin()
                .await
                .wrap_err("begin amount-statistics manifest audit transaction")?;
            Audit::record_amount_statistics_manifest_pin(&mut tx, &cid, manifest, &envelope_json)
                .await
                .wrap_err("record amount-statistics manifest pin")?;
            tx.commit()
                .await
                .wrap_err("commit amount-statistics manifest pin audit")
        }
        .await;
        self.settle_pin_audit(
            &cid,
            Some(ownership),
            audit_result,
            "amount-statistics manifest",
        )
        .await?;
        Ok(cid)
    }
}

/// The next manifest's chains in configured order: each chain's new entry, or the entry of the
/// active manifest when this cycle published no snapshot for the chain.
pub(super) fn next_manifest_chains(
    previous: &[AmountStatisticsChainEntry],
    outcomes: Vec<(ChainScope, Result<AmountStatisticsChainEntry>)>,
) -> (
    Vec<AmountStatisticsChainEntry>,
    Vec<AmountStatisticsChainFailure>,
) {
    let mut chains = Vec::with_capacity(outcomes.len());
    let mut failures = Vec::new();
    for (scope, outcome) in outcomes {
        match outcome {
            Ok(entry) => chains.push(entry),
            Err(error) => {
                let reason = format_report_chain(&error);
                warn!(target: LOG_TARGET,
                    chain_id = scope.chain_id,
                    railgun_contract = %scope.railgun_contract,
                    error = %reason,
                    "amount-statistics snapshot not published; keeping the chain's last snapshot"
                );
                chains.extend(previous.iter().find(|entry| entry.scope == scope).cloned());
                failures.push(AmountStatisticsChainFailure {
                    chain_id: scope.chain_id,
                    railgun_contract: scope.railgun_contract.to_string(),
                    reason,
                });
            }
        }
    }
    (chains, failures)
}
