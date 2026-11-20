#[allow(clippy::wildcard_imports)]
use super::*;

impl PublicationScheduler {
    pub(super) fn new(
        config: Config,
        store: Store,
        ipfs_client: Arc<dyn IpfsClient>,
        signing_key: SigningKey,
        poi_rpc_client: PoiRpcClient,
        v4_ipns_publisher: Arc<dyn ManifestIpnsPublisher>,
        status: SharedStatus,
        pin_lifecycle: PinLifecycleCoordinator,
    ) -> Self {
        let lifecycle = Lifecycle::new(store.clone());
        let sequence_allocator = PoiPublicationSequenceAllocator::new(store.clone());

        Self {
            config,
            store,
            lifecycle,
            ipfs_client,
            signing_key,
            poi_rpc_client,
            v4_ipns_publisher,
            status,
            pin_lifecycle,
            sequence_allocator,
            last_poi_artifact_manifest_cid: None,
            last_poi_artifact_graph_hash: None,
            manifest_needs_publish: true,
            last_ipns_publish_at: None,
            publication_state_loaded: false,
            shutdown: None,
        }
    }

    pub(super) fn ensure_publication_running(&self) -> Result<()> {
        if self.shutdown.as_ref().is_some_and(shutdown_requested) {
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
        self.ensure_publication_running()?;
        let reconciliation = self.reconcile_pending_poi_publications().await?;
        if !self.publication_state_loaded
            || !matches!(reconciliation, PendingPoiPublicationReconciliation::None)
        {
            self.load_durable_publication_state().await?;
            self.publication_state_loaded = true;
        }
        if matches!(
            reconciliation,
            PendingPoiPublicationReconciliation::Activated
        ) {
            return Ok(());
        }
        if matches!(
            reconciliation,
            PendingPoiPublicationReconciliation::Abandoned
        ) {
            self.manifest_needs_publish = true;
        }

        self.ensure_publication_running()?;
        let poi_artifact_started = std::time::Instant::now();
        let poi_graph = self.publish_poi_artifact_graph(now).await?;
        self.ensure_publication_running()?;
        let graph_changed = self
            .last_poi_artifact_graph_hash
            .is_none_or(|hash| hash != poi_graph.graph_hash);
        let mut needs_publication = self.manifest_needs_publish
            || self.last_poi_artifact_manifest_cid.is_none()
            || graph_changed
            || self.should_republish_ipns(now);
        if !needs_publication {
            let current_manifest = self
                .last_poi_artifact_manifest_cid
                .as_ref()
                .expect("POI artifact manifest CID checked above");
            needs_publication = !self.cid_is_available(current_manifest, "manifest").await?;
        }
        if !needs_publication {
            return Ok(());
        }

        let lease = self
            .sequence_allocator
            .reserve_cycle(unix_millis(now)?)
            .await
            .wrap_err("reserve POI publication sequence")?;
        let manifests = self.publish_poi_manifests(now, lease, &poi_graph).await?;
        self.ensure_publication_running()?;
        self.publish_poi_ipns(lease, &manifests).await?;
        self.last_poi_artifact_manifest_cid = Some(manifests.v4.cid.clone());
        self.last_poi_artifact_graph_hash = Some(poi_graph.graph_hash);
        self.manifest_needs_publish = false;
        self.last_ipns_publish_at = Some(now);
        self.status.write().await.record_poi_artifact_publication(
            manifests.v4.cid.clone(),
            manifests.v4.sequence,
            &poi_graph.entries,
            poi_graph.checkpoint_chunks,
            poi_graph.checkpoint_bytes,
            poi_graph.tail_bytes,
            poi_graph.bridge_count,
            poi_graph.reused_cids,
            u64::try_from(poi_artifact_started.elapsed().as_millis()).unwrap_or(u64::MAX),
        );
        info!(target: LOG_TARGET,
            sequence = lease.sequence(),
            checkpoint_chunks = poi_graph.checkpoint_chunks,
            checkpoint_bytes = poi_graph.checkpoint_bytes,
            tail_bytes = poi_graph.tail_bytes,
            bridges = poi_graph.bridge_count,
            reused_cids = poi_graph.reused_cids,
            elapsed_ms = poi_artifact_started.elapsed().as_millis(),
            "published POI v4 cycle"
        );
        Ok(())
    }

    pub(super) async fn publish_poi_artifact_graph(
        &self,
        now: SystemTime,
    ) -> Result<PublishedPoiGraph> {
        let mut corpora = Vec::new();
        for list_key in &self.config.list_keys {
            for chain_id in &self.config.chain_ids {
                let scope = Scope::new(
                    *list_key,
                    EVM_CHAIN_TYPE,
                    *chain_id,
                    self.config.txid_version.clone(),
                );
                let tip = self
                    .store
                    .chain_tip(list_key, *chain_id, &self.config.upstream_url)
                    .await
                    .wrap_err("read POI tip for v4 publication")?;
                let (stored_events, expected_root) = if let Some(tip) = tip {
                    let root = tip
                        .last_tip_merkleroot
                        .ok_or_else(|| eyre!("nonempty POI tip is missing upstream root"))?;
                    (
                        self.store
                            .page_event_range(list_key, *chain_id, 0, tip.last_event_index)
                            .await
                            .wrap_err("read stored POI events for v4 replay")?,
                        Some(FixedBytes::from(root)),
                    )
                } else {
                    (Vec::new(), None)
                };
                corpora.push(
                    ValidatedCorpus::replay(scope, &stored_events, expected_root)
                        .wrap_err("validate stored POI event corpus")?,
                );
            }
        }

        for corpus in &mut corpora {
            if corpus.event_count() == 0 {
                continue;
            }
            let roots = corpus.current_roots();
            let root_hexes = roots.values().map(hex::encode).collect::<Vec<_>>();
            let scope = corpus.scope();
            let accepted = self
                .poi_rpc_client
                .validate_poi_merkleroots(
                    &scope.txid_version,
                    scope.chain_type,
                    scope.chain_id,
                    &scope.list_key,
                    &root_hexes,
                )
                .await
                .wrap_err("revalidate replayed POI roots before v4 publication")?;
            if !accepted {
                return Err(eyre!(
                    "upstream rejected replayed POI roots for list_key={} chain_id={}",
                    list_key_hex(&scope.list_key),
                    scope.chain_id
                ));
            }
        }

        let mut entries = Vec::new();
        let mut artifact_cids = BTreeSet::new();
        let mut checkpoint_chunks = 0usize;
        let mut checkpoint_bytes = 0_u64;
        let mut tail_bytes = 0_u64;
        let mut bridge_count = 0usize;
        let mut reused_cids = 0usize;

        for corpus in &corpora {
            self.ensure_publication_running()?;
            let active = Audit::active_poi_graph(self.store.pool(), corpus.scope())
                .await
                .wrap_err("load active POI v4 graph")?;
            let published = self
                .publish_poi_artifact_entry(now, corpus, active.as_ref())
                .await?;
            checkpoint_chunks += published.checkpoint_chunk_cids.len();
            checkpoint_bytes = checkpoint_bytes
                .checked_add(published.checkpoint_bytes)
                .ok_or_else(|| eyre!("POI checkpoint byte total overflow"))?;
            tail_bytes = tail_bytes
                .checked_add(published.tail_bytes)
                .ok_or_else(|| eyre!("POI tail byte total overflow"))?;
            bridge_count += published.entry.retained_bridges.len();
            reused_cids += published.reused_cids;
            artifact_cids.extend(published.checkpoint_chunk_cids);
            artifact_cids.extend(published.graph_cids);
            entries.push(published.entry);
        }
        entries.sort_by(|left, right| left.scope.cmp(&right.scope));
        let graph_bytes =
            serde_json::to_vec(&entries).wrap_err("serialize POI artifact graph identity")?;
        Ok(PublishedPoiGraph {
            entries,
            artifact_cids: artifact_cids.into_iter().collect(),
            graph_hash: content_hash(&graph_bytes),
            checkpoint_chunks,
            checkpoint_bytes,
            tail_bytes,
            bridge_count,
            reused_cids,
        })
    }

    async fn publish_poi_ipns(
        &self,
        lease: PoiPublicationSequenceLease,
        manifests: &PublishedPoiManifests,
    ) -> Result<()> {
        self.ensure_publication_running()?;
        let mut required_poi_artifacts = manifests.poi_artifact_graph_cids.clone();
        required_poi_artifacts.push(manifests.v4.cid.clone());
        let mut failures = Vec::new();
        let publication = async {
            for cid in &required_poi_artifacts {
                if !self.cid_is_available(cid, "POI v4 graph").await? {
                    return Err(eyre!(
                        "required POI v4 graph CID {cid} is externally unavailable"
                    ));
                }
            }
            self.v4_ipns_publisher
                .publish_manifest_cid(&manifests.v4.cid, lease.v4_manifest_sequence())
                .await
                .map_err(eyre::Report::new)
        }
        .await;
        match publication {
            Ok(_) => {
                if let Err(error) = self.ensure_publication_running() {
                    failures.push(format!("v4 activation: {error}"));
                } else if let Err(error) = self
                    .record_v4_ipns(&manifests.v4.cid, manifests.v4.sequence)
                    .await
                {
                    failures.push(format!("POI artifact audit: {error}"));
                }
            }
            Err(error) => failures.push(format!("v4: {error}")),
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(eyre!(
                "POI IPNS publication failed: {}",
                failures.join(", ")
            ))
        }
    }

    async fn record_v4_ipns(&self, manifest_cid: &str, sequence: u64) -> Result<()> {
        let parsed_cid = manifest_cid.parse().wrap_err("parse POI v4 manifest CID")?;
        let mut tx = self.store.begin().await?;
        Audit::record_poi_artifact_manifest_ipns_publication(&mut tx, &parsed_cid, sequence)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn reconcile_pending_poi_publications(
        &self,
    ) -> Result<PendingPoiPublicationReconciliation> {
        self.ensure_publication_running()?;
        let Some(pending) = Audit::pending_poi_artifact_manifest_publication(self.store.pool())
            .await
            .wrap_err("load pending v4 POI manifest")?
        else {
            return Ok(PendingPoiPublicationReconciliation::None);
        };

        let unavailable_artifact_cid = {
            let mut unavailable = None;
            for cid in &pending.artifact_cids {
                if !self.cid_is_available(cid, "pending v4 graph").await? {
                    unavailable = Some(cid);
                    break;
                }
            }
            unavailable
        };
        let unavailable = if let Some(cid) = unavailable_artifact_cid {
            Some((cid, "artifact"))
        } else if !self
            .cid_is_available(&pending.cid, "pending v4 manifest")
            .await?
        {
            Some((&pending.cid, "manifest"))
        } else {
            None
        };
        if let Some((unavailable_cid, unavailable_kind)) = unavailable {
            let unavailable_cid = unavailable_cid
                .parse::<Cid>()
                .wrap_err("parse unavailable pending v4 CID")?;
            let pending_cid = pending
                .cid
                .parse::<Cid>()
                .wrap_err("parse pending v4 manifest CID")?;
            warn!(target: LOG_TARGET,
                pending_manifest_cid = %pending.cid,
                pending_sequence = pending.sequence,
                unavailable_cid = %unavailable_cid,
                unavailable_kind,
                "abandoning pending POI v4 manifest with unavailable CID"
            );
            let mut tx = self
                .store
                .begin()
                .await
                .wrap_err("begin pending v4 manifest abandonment transaction")?;
            Audit::abandon_pending_poi_v4_manifest_reconciliation(
                &mut tx,
                &pending_cid,
                pending.sequence,
                (unavailable_kind == "artifact").then_some(&unavailable_cid),
            )
            .await
            .wrap_err("abandon pending v4 manifest reconciliation")?;
            tx.commit()
                .await
                .wrap_err("commit pending v4 manifest abandonment")?;
            return Ok(PendingPoiPublicationReconciliation::Abandoned);
        }
        self.v4_ipns_publisher
            .publish_manifest_cid(&pending.cid, pending.sequence)
            .await
            .map_err(eyre::Report::new)?;
        self.ensure_publication_running()?;
        self.record_v4_ipns(&pending.cid, pending.sequence)
            .await
            .wrap_err("activate reconciled v4 POI manifest")?;
        Ok(PendingPoiPublicationReconciliation::Activated)
    }

    async fn load_durable_publication_state(&mut self) -> Result<()> {
        let v4 = Audit::active_poi_artifact_manifest_publication(self.store.pool())
            .await
            .wrap_err("load active v4 POI manifest state")?;
        self.last_poi_artifact_manifest_cid = v4.as_ref().map(|manifest| manifest.cid.clone());
        self.last_poi_artifact_graph_hash = v4
            .as_ref()
            .map(|manifest| serde_json::to_vec(&manifest.entries))
            .transpose()
            .wrap_err("serialize active POI artifact graph identity")?
            .map(|bytes| content_hash(&bytes));
        self.last_ipns_publish_at = v4.as_ref().map(|manifest| manifest.ipns_published_at);
        self.manifest_needs_publish = v4.is_none();
        let mut status = self.status.write().await;
        if let Some(v4) = v4 {
            status.restore_poi_artifact_publication(v4.cid, v4.sequence, &v4.entries);
        } else {
            status.clear_poi_artifact_publication();
        }
        Ok(())
    }

    async fn cid_is_available(&self, cid: &str, label: &'static str) -> Result<bool> {
        cid_is_available(self.ipfs_client.as_ref(), cid, label).await
    }

    pub(super) async fn cleanup_uncommitted_pin_while_locked(
        &self,
        cid: &Cid,
        label: &'static str,
        ownership: PinOwnershipLease,
    ) {
        match Audit::publication_cid_is_referenced(self.store.pool(), cid).await {
            Ok(true) => {
                warn!(target: LOG_TARGET, %cid, label, "preserving uncommitted pin because it is already referenced");
                ownership.settle();
            }
            Ok(false) => match self.ipfs_client.unpin(cid).await {
                Ok(()) => ownership.settle(),
                Err(error) => {
                    warn!(target: LOG_TARGET, %cid, label, %error, "failed to clean up uncommitted provider pin");
                    if Audit::record_pin_cleanup_debt(
                        self.store.pool(),
                        cid,
                        self.ipfs_client.service_name(),
                        &error.to_string(),
                    )
                    .await
                    .is_ok()
                    {
                        ownership.settle();
                    }
                }
            },
            Err(error) => {
                warn!(target: LOG_TARGET, %cid, label, %error, "preserving uncommitted pin because reference recheck failed");
                if Audit::record_pin_cleanup_debt(
                    self.store.pool(),
                    cid,
                    self.ipfs_client.service_name(),
                    &error.to_string(),
                )
                .await
                .is_ok()
                {
                    ownership.settle();
                }
            }
        }
    }

    fn should_republish_ipns(&self, now: SystemTime) -> bool {
        self.last_poi_artifact_manifest_cid.is_some()
            && self.last_ipns_publish_at.is_none_or(|last_published_at| {
                now.duration_since(last_published_at)
                    .is_ok_and(|elapsed| elapsed >= *self.config.ipns_republish_interval)
            })
    }

    pub(super) async fn set_ipfs_reachable(&self, reachable: bool) {
        self.status.write().await.set_ipfs_reachable(reachable);
    }
}
