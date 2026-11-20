#[allow(clippy::wildcard_imports)]
use super::*;

impl PublicationScheduler {
    pub(super) async fn publish_poi_artifact_entry(
        &self,
        now: SystemTime,
        corpus: &ValidatedCorpus,
        active: Option<&ActivePoiGraph>,
    ) -> Result<PublishedPoiEntry> {
        let event_count = corpus.event_count();
        if let Some(active) = active {
            active
                .entry
                .validate()
                .wrap_err("validate active POI artifact entry")?;
            if active.entry.event_count > event_count {
                return Err(eyre!(
                    "stored POI event count {event_count} regresses active POI artifact count {}",
                    active.entry.event_count
                ));
            }
            if active.entry.event_count > 0 {
                let active_tip = active.entry.event_count - 1;
                let replayed = corpus.root_at(active_tip)?;
                if active.entry.current_root != Some(replayed) {
                    return Err(eyre!(
                        "stored POI prefix conflicts with active POI artifact root"
                    ));
                }
            }
        }

        let mut checkpoint_event_count = active.map_or(event_count, |graph| {
            graph.entry.checkpoint_catalog.row_count
        });
        let inherited_bridges = active
            .map(|graph| graph.entry.retained_bridges.clone())
            .unwrap_or_default();
        let mut retained_bridges = active
            .map(|graph| graph.entry.retained_bridges.clone())
            .unwrap_or_default();
        let current_tail_fits = if checkpoint_event_count < event_count {
            match corpus.prepare_event_artifact(
                EventArtifactKind::CurrentTail,
                checkpoint_event_count,
                event_count - 1,
            ) {
                Ok(_) => true,
                Err(PublicationError::Contract(
                    PoiArtifactError::EventArtifactByteLimitExceeded { .. },
                )) => false,
                Err(error) => return Err(error.into()),
            }
        } else {
            true
        };
        let rotate = active.is_some_and(|graph| {
            poi_artifact_rotation_required(
                graph.entry.current_tail.is_some(),
                now.duration_since(graph.checkpoint_published_at).ok(),
                *self.config.base_rebuild_interval,
                current_tail_fits,
            )
        });
        let mut reused_cids = 0usize;

        if rotate {
            let graph =
                active.ok_or_else(|| eyre!("POI artifact rotation requires an active graph"))?;
            let prior_checkpoint_count = graph.entry.checkpoint_catalog.row_count;
            let prior_event_count = graph.entry.event_count;
            // Only the previously published current tail may become a bridge. Advancing the
            // checkpoint past prior_event_count or splitting the unseen suffix into synthetic
            // bridges would violate the v4 graph contract, so an oversized new suffix fails closed.
            if prior_event_count > prior_checkpoint_count {
                let bridge = corpus.prepare_event_artifact(
                    EventArtifactKind::Bridge,
                    prior_checkpoint_count,
                    prior_event_count - 1,
                )?;
                let (bridge, reused) = self
                    .publish_poi_event_artifact(PoiArtifactPublicationKind::Bridge, &bridge)
                    .await?;
                reused_cids += usize::from(reused);
                retained_bridges.push(bridge);
            }
            checkpoint_event_count = prior_event_count;
            retained_bridges = retain_recent_bridges(retained_bridges, graph, now)?;
        }

        let mut materialized_bridges = Vec::with_capacity(retained_bridges.len());
        for bridge in retained_bridges {
            if !inherited_bridges.contains(&bridge) {
                materialized_bridges.push(bridge);
                continue;
            }
            let prepared = corpus.prepare_event_artifact(
                EventArtifactKind::Bridge,
                bridge.range.start_index,
                bridge.range.end_index,
            )?;
            let expected = prepared.descriptor(bridge.artifact.cid.clone())?;
            if expected != bridge {
                return Err(eyre!(
                    "stored POI retained bridge descriptor does not match rebuilt bytes"
                ));
            }
            let (published, reused) = self
                .publish_poi_event_artifact(PoiArtifactPublicationKind::Bridge, &prepared)
                .await?;
            if published != bridge {
                return Err(eyre!(
                    "published POI retained bridge descriptor does not match stored descriptor"
                ));
            }
            reused_cids += usize::from(reused);
            materialized_bridges.push(published);
        }
        retained_bridges = materialized_bridges;

        let prepared_chunks = corpus.prepare_checkpoint(checkpoint_event_count)?;
        let mut checkpoint_descriptors = Vec::with_capacity(prepared_chunks.len());
        let mut checkpoint_chunk_cids = Vec::with_capacity(prepared_chunks.len());
        let mut checkpoint_bytes = 0_u64;
        for chunk in &prepared_chunks {
            let (descriptor, reused) = self
                .publish_poi_event_artifact(PoiArtifactPublicationKind::CheckpointChunk, chunk)
                .await?;
            checkpoint_bytes = checkpoint_bytes
                .checked_add(descriptor.artifact.byte_size)
                .ok_or_else(|| eyre!("POI checkpoint byte total overflow"))?;
            reused_cids += usize::from(reused);
            checkpoint_chunk_cids.push(descriptor.artifact.cid.clone());
            checkpoint_descriptors.push(descriptor);
        }
        let (catalog, catalog_bytes) =
            checkpoint_catalog(corpus.scope().clone(), checkpoint_descriptors)?;
        let scope = catalog.scope.clone();
        let (checkpoint_catalog, catalog_reused) = self
            .publish_poi_checkpoint_catalog(&catalog, &catalog_bytes)
            .await?;
        reused_cids += usize::from(catalog_reused);

        let current_tail = if checkpoint_event_count < event_count {
            let prepared = corpus.prepare_event_artifact(
                EventArtifactKind::CurrentTail,
                checkpoint_event_count,
                event_count - 1,
            )?;
            let (descriptor, reused) = self
                .publish_poi_event_artifact(PoiArtifactPublicationKind::CurrentTail, &prepared)
                .await?;
            reused_cids += usize::from(reused);
            Some(descriptor)
        } else {
            None
        };
        let tail_bytes = current_tail
            .as_ref()
            .map_or(0, |tail| tail.artifact.byte_size);
        let (blocked_shields, blocked_reused) = self.publish_poi_blocked_shields(&scope).await?;
        reused_cids += usize::from(blocked_reused);
        let current_tip_index = event_count.checked_sub(1);
        let current_root = current_tip_index
            .map(|index| corpus.root_at(index))
            .transpose()?;
        let entry = PoiArtifactManifestEntry {
            scope,
            event_count,
            current_tip_index,
            current_root,
            checkpoint_catalog,
            current_tail,
            retained_bridges,
            blocked_shields,
        };
        entry
            .validate()
            .wrap_err("validate prepared POI artifact entry")?;
        let mut graph_cids = vec![
            entry.checkpoint_catalog.artifact.cid.clone(),
            entry.blocked_shields.artifact.cid.clone(),
        ];
        graph_cids.extend(
            entry
                .retained_bridges
                .iter()
                .map(|bridge| bridge.artifact.cid.clone()),
        );
        if let Some(tail) = &entry.current_tail {
            graph_cids.push(tail.artifact.cid.clone());
        }
        Ok(PublishedPoiEntry {
            entry,
            checkpoint_chunk_cids,
            graph_cids,
            checkpoint_bytes,
            tail_bytes,
            reused_cids,
        })
    }

    async fn publish_poi_event_artifact(
        &self,
        kind: PoiArtifactPublicationKind,
        prepared: &PreparedEventArtifact,
    ) -> Result<(EventArtifactDescriptor, bool)> {
        self.ensure_publication_running()?;
        let byte_size = u64::try_from(prepared.bytes.len())
            .wrap_err("POI event artifact byte size overflow")?;
        let _pin_lifecycle = self.pin_lifecycle.lock().await;
        let reusable = Audit::live_poi_artifact_cid(
            self.store.pool(),
            kind,
            &prepared.artifact.scope,
            Some(prepared.artifact.range),
            byte_size,
            &prepared.sha256,
            Some(&prepared.artifact.end_root),
        )
        .await?;
        let (cid, reused, ownership) = if let Some(cid) = reusable {
            if self.ipfs_client.contains(&cid).await? {
                (cid, true, None)
            } else {
                let ownership = self.acquire_pin_ownership()?;
                match self.ipfs_client.pin_bytes(&prepared.bytes).await {
                    Ok(returned) => (returned, false, Some(ownership)),
                    Err(error) => {
                        ownership.settle();
                        return Err(error.into());
                    }
                }
            }
        } else {
            let ownership = self.acquire_pin_ownership()?;
            match self.ipfs_client.pin_bytes(&prepared.bytes).await {
                Ok(returned) => (returned, false, Some(ownership)),
                Err(error) => {
                    ownership.settle();
                    return Err(error.into());
                }
            }
        };
        let audit_result = async {
            let descriptor = prepared.descriptor(cid.to_string())?;
            let mut tx = self.store.begin().await?;
            Audit::record_poi_artifact_pin(
                &mut tx,
                kind,
                &descriptor.scope,
                Some(descriptor.range),
                &cid,
                descriptor.artifact.byte_size,
                &prepared.sha256,
                Some(&descriptor.end_root),
                &serde_json::to_string(&descriptor)?,
            )
            .await?;
            tx.commit().await?;
            Ok::<_, eyre::Report>(descriptor)
        }
        .await;
        let descriptor = match audit_result {
            Ok(descriptor) => descriptor,
            Err(error) => {
                if let Some(ownership) = ownership {
                    self.cleanup_uncommitted_pin_while_locked(
                        &cid,
                        "POI event artifact",
                        ownership,
                    )
                    .await;
                }
                return Err(error);
            }
        };
        if let Some(ownership) = ownership {
            ownership.settle();
        }
        self.ensure_publication_running()?;
        Ok((descriptor, reused))
    }

    async fn publish_poi_checkpoint_catalog(
        &self,
        catalog: &CheckpointCatalog,
        bytes: &[u8],
    ) -> Result<(CheckpointCatalogDescriptor, bool)> {
        self.ensure_publication_running()?;
        let byte_size =
            u64::try_from(bytes.len()).wrap_err("POI checkpoint catalog byte size overflow")?;
        let hash = content_hash(bytes);
        let _pin_lifecycle = self.pin_lifecycle.lock().await;
        let reusable = Audit::live_poi_artifact_cid(
            self.store.pool(),
            PoiArtifactPublicationKind::CheckpointCatalog,
            &catalog.scope,
            catalog.range,
            byte_size,
            &hash,
            catalog.checkpoint_root.as_ref(),
        )
        .await?;
        let (cid, reused, ownership) = if let Some(cid) = reusable {
            if self.ipfs_client.contains(&cid).await? {
                (cid, true, None)
            } else {
                let ownership = self.acquire_pin_ownership()?;
                match self.ipfs_client.pin_bytes(bytes).await {
                    Ok(returned) => (returned, false, Some(ownership)),
                    Err(error) => {
                        ownership.settle();
                        return Err(error.into());
                    }
                }
            }
        } else {
            let ownership = self.acquire_pin_ownership()?;
            match self.ipfs_client.pin_bytes(bytes).await {
                Ok(returned) => (returned, false, Some(ownership)),
                Err(error) => {
                    ownership.settle();
                    return Err(error.into());
                }
            }
        };
        let audit_result = async {
            let descriptor = catalog.descriptor(cid.to_string())?;
            let mut tx = self.store.begin().await?;
            Audit::record_poi_artifact_pin(
                &mut tx,
                PoiArtifactPublicationKind::CheckpointCatalog,
                &catalog.scope,
                catalog.range,
                &cid,
                byte_size,
                &hash,
                catalog.checkpoint_root.as_ref(),
                &serde_json::to_string(&descriptor)?,
            )
            .await?;
            tx.commit().await?;
            Ok::<_, eyre::Report>(descriptor)
        }
        .await;
        let descriptor = match audit_result {
            Ok(descriptor) => descriptor,
            Err(error) => {
                if let Some(ownership) = ownership {
                    self.cleanup_uncommitted_pin_while_locked(
                        &cid,
                        "POI checkpoint catalog",
                        ownership,
                    )
                    .await;
                }
                return Err(error);
            }
        };
        if let Some(ownership) = ownership {
            ownership.settle();
        }
        self.ensure_publication_running()?;
        Ok((descriptor, reused))
    }

    async fn publish_poi_blocked_shields(
        &self,
        scope: &Scope,
    ) -> Result<(BlockedShieldsDescriptor, bool)> {
        self.ensure_publication_running()?;
        let artifact = self
            .lifecycle
            .build_poi_blocked_shields_artifact(scope)
            .await?;
        let bytes = artifact.bytes;
        let byte_size = u64::try_from(bytes.len())
            .wrap_err("POI blocked-shields artifact byte size overflow")?;
        let hash = content_hash(&bytes);
        let row_count = u64::try_from(artifact.row_count)
            .wrap_err("POI blocked-shields artifact row count overflow")?;
        let _pin_lifecycle = self.pin_lifecycle.lock().await;
        let reusable = Audit::live_poi_artifact_cid(
            self.store.pool(),
            PoiArtifactPublicationKind::BlockedShields,
            scope,
            None,
            byte_size,
            &hash,
            None,
        )
        .await?;
        let (cid, reused, ownership) = if let Some(cid) = reusable {
            if self.ipfs_client.contains(&cid).await? {
                (cid, true, None)
            } else {
                let ownership = self.acquire_pin_ownership()?;
                match self.ipfs_client.pin_bytes(&bytes).await {
                    Ok(returned) => (returned, false, Some(ownership)),
                    Err(error) => {
                        ownership.settle();
                        return Err(error.into());
                    }
                }
            }
        } else {
            let ownership = self.acquire_pin_ownership()?;
            match self.ipfs_client.pin_bytes(&bytes).await {
                Ok(returned) => (returned, false, Some(ownership)),
                Err(error) => {
                    ownership.settle();
                    return Err(error.into());
                }
            }
        };
        let audit_result = async {
            let descriptor = BlockedShieldsDescriptor {
                artifact: poi_artifact_descriptor(cid.to_string(), &bytes),
                format_version: POI_ARTIFACT_FORMAT_VERSION,
                scope: scope.clone(),
                row_count,
                encoding: ArtifactEncoding::CanonicalJson,
                compression: Compression::Identity,
            };
            descriptor.validate()?;
            let mut tx = self.store.begin().await?;
            Audit::record_poi_artifact_pin(
                &mut tx,
                PoiArtifactPublicationKind::BlockedShields,
                scope,
                None,
                &cid,
                byte_size,
                &hash,
                None,
                &serde_json::to_string(&descriptor)?,
            )
            .await?;
            tx.commit().await?;
            Ok::<_, eyre::Report>(descriptor)
        }
        .await;
        let descriptor = match audit_result {
            Ok(descriptor) => descriptor,
            Err(error) => {
                if let Some(ownership) = ownership {
                    self.cleanup_uncommitted_pin_while_locked(
                        &cid,
                        "POI blocked-shields artifact",
                        ownership,
                    )
                    .await;
                }
                return Err(error);
            }
        };
        if let Some(ownership) = ownership {
            ownership.settle();
        }
        self.ensure_publication_running()?;
        Ok((descriptor, reused))
    }

    pub(super) async fn publish_poi_manifests(
        &self,
        now: SystemTime,
        lease: PoiPublicationSequenceLease,
        poi_graph: &PublishedPoiGraph,
    ) -> Result<PublishedPoiManifests> {
        self.ensure_publication_running()?;
        let issued_at_ms = unix_millis(now)?;
        let mut poi_manifest = PoiArtifactManifest::new(
            issued_at_ms,
            lease.v4_manifest_sequence(),
            FixedBytes::ZERO,
            poi_graph.entries.clone(),
        );
        poi_manifest
            .sign_manifest(&self.signing_key)
            .wrap_err("sign POI v4 manifest")?;
        let poi_manifest_bytes = poi_manifest
            .to_bytes()
            .wrap_err("serialize POI v4 manifest")?;

        let _pin_lifecycle = self.pin_lifecycle.lock().await;
        let poi_artifact_ownership = self.acquire_pin_ownership()?;
        let poi_artifact_pin =
            match pin_manifest(self.ipfs_client.as_ref(), &poi_manifest_bytes).await {
                Ok(cid) => cid,
                Err(error) => {
                    poi_artifact_ownership.settle();
                    return Err(error).wrap_err("pin POI v4 manifest");
                }
            };
        if let Err(error) = self.ensure_publication_running() {
            self.cleanup_uncommitted_pin_while_locked(
                &poi_artifact_pin,
                "POI artifact manifest",
                poi_artifact_ownership,
            )
            .await;
            return Err(error);
        }
        let audit_result = async {
            let mut tx = self
                .store
                .begin()
                .await
                .wrap_err("begin POI v4 manifest audit transaction")?;
            Audit::record_poi_artifact_manifest_pin(
                &mut tx,
                &poi_artifact_pin,
                &poi_graph.entries,
                &poi_graph.artifact_cids,
                lease.v4_manifest_sequence(),
                u64::try_from(poi_manifest_bytes.len())
                    .wrap_err("POI artifact manifest byte size overflow")?,
                &content_hash(&poi_manifest_bytes),
            )
            .await
            .wrap_err("record POI v4 manifest graph")?;
            tx.commit().await.wrap_err("commit POI v4 manifest audit")
        }
        .await;
        if let Err(error) = audit_result {
            self.cleanup_uncommitted_pin_while_locked(
                &poi_artifact_pin,
                "POI artifact manifest",
                poi_artifact_ownership,
            )
            .await;
            return Err(error);
        }
        poi_artifact_ownership.settle();

        let v4 = PublishedManifest {
            cid: poi_artifact_pin.to_string(),
            sequence: lease.v4_manifest_sequence(),
        };
        self.ensure_publication_running()?;
        Ok(PublishedPoiManifests {
            v4,
            poi_artifact_graph_cids: poi_graph.artifact_cids.clone(),
        })
    }
}
