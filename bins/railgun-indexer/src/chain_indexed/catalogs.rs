#[allow(clippy::wildcard_imports)]
use super::*;

impl ChainIndexedPublicationScheduler {
    pub(super) async fn publish_public_txid_catalog(
        &self,
        chain: &ChainIndexedChainConfig,
        scope: &ChainScope,
        max_block: u64,
    ) -> Result<Vec<PublishedCatalog>> {
        self.validate_public_txid_compatibility_omissions(chain, max_block)
            .await?;
        if !chain.public_txid_compatibility_omissions.is_empty() {
            warn!(target: LOG_TARGET,
                chain_id = chain.chain_id,
                omission_count = chain.public_txid_compatibility_omissions.len(),
                "publishing public TXID catalog with compatibility omissions"
            );
        }
        let mut offset = 0_u64;
        let mut chunks = Vec::new();
        let mut checkpoint = PublicTxidCheckpoint::default();
        loop {
            let row_limit = public_txid_chunk_row_limit(
                offset,
                self.config.chain_indexed.public_txid_chunk_row_limit,
            );
            let rows = self
                .store
                .published_public_txid_rows_through_block(
                    EVM_CHAIN_TYPE,
                    chain.chain_id,
                    chain.railgun_contract,
                    offset,
                    row_limit,
                    max_block,
                    &chain.public_txid_compatibility_omissions,
                )
                .await
                .wrap_err("read public TXID rows for artifact publication")?;
            if rows.is_empty() {
                break;
            }
            let page_row_count = rows.len();
            let page_scope = scope.clone();
            let (returned_checkpoint, prepared) = run_blocking(move || {
                let prepared = prepare_public_txid_page(&page_scope, &rows, &mut checkpoint)?;
                Ok((checkpoint, prepared))
            })
            .await?;
            checkpoint = returned_checkpoint;
            for mut published in prepared {
                published.descriptor = self
                    .reuse_or_pin_chunk(published.descriptor, &published.compressed_bytes)
                    .await?;
                offset = published.descriptor.range.end.saturating_add(1);
                chunks.push(published.descriptor);
            }
            if page_row_count < row_limit as usize {
                break;
            }
        }
        self.publish_catalogs(
            scope,
            IndexedDatasetKind::PublicTxid,
            chunks,
            CatalogCoverage::DerivedFromChunks,
        )
        .await
    }

    async fn validate_public_txid_compatibility_omissions(
        &self,
        chain: &ChainIndexedChainConfig,
        max_block: u64,
    ) -> Result<()> {
        for omission in &chain.public_txid_compatibility_omissions {
            if omission.block_number > max_block {
                continue;
            }
            let match_count = self
                .store
                .public_txid_compatibility_omission_match_count(
                    EVM_CHAIN_TYPE,
                    chain.chain_id,
                    chain.railgun_contract,
                    omission,
                )
                .await
                .wrap_err("validate public TXID compatibility omission")?;
            if match_count != 1 {
                return Err(eyre!(
                    "public TXID compatibility omission for chain {} at block {} transaction {} inner index {} matched {} canonical rows; expected exactly one",
                    chain.chain_id,
                    omission.block_number,
                    hex::encode_prefixed(omission.transaction_hash.as_slice()),
                    omission.railgun_transaction_index,
                    match_count,
                ));
            }
        }
        Ok(())
    }

    async fn wallet_scan_plan_items(
        &self,
        chain: &ChainIndexedChainConfig,
        scope: &ChainScope,
        start_block: u64,
        end_block: u64,
    ) -> Result<Vec<ChunkPlanItem>> {
        let mut items = Vec::new();
        let ranges = self
            .store
            .wallet_scan_populated_block_ranges(
                EVM_CHAIN_TYPE,
                chain.chain_id,
                chain.railgun_contract,
                start_block,
                end_block,
                WALLET_SCAN_PLANNING_BLOCK_SPAN,
            )
            .await
            .wrap_err("read populated wallet-scan block ranges")?;
        for range in ranges {
            let rows = self
                .store
                .wallet_scan_rows(
                    EVM_CHAIN_TYPE,
                    chain.chain_id,
                    chain.railgun_contract,
                    range.start_block,
                    range.end_block,
                )
                .await
                .wrap_err("read wallet scan rows for artifact planning")?;
            if rows.is_empty() {
                continue;
            }
            let item_scope = scope.clone();
            items.push(
                run_blocking(move || {
                    wallet_scan_chunk_plan_item(
                        &item_scope,
                        range.start_block,
                        range.end_block,
                        &rows,
                        CompressionAlgorithm::Zstd,
                    )
                    .wrap_err("plan wallet-scan artifact chunk unit")
                })
                .await?,
            );
        }
        Ok(items)
    }

    pub(super) async fn publish_wallet_scan_catalog(
        &self,
        chain: &ChainIndexedChainConfig,
        scope: &ChainScope,
        max_block: u64,
    ) -> Result<Vec<PublishedCatalog>> {
        if max_block < chain.start_block {
            return Ok(Vec::new());
        }

        let plan_items = self
            .wallet_scan_plan_items(chain, scope, chain.start_block, max_block)
            .await?;
        let planned_chunks = run_blocking(move || {
            plan_chunks(&plan_items, ChunkPlanningConfig::default())
                .wrap_err("plan wallet-scan artifact chunks")
        })
        .await?;
        let mut chunks = Vec::new();
        for planned in planned_chunks {
            let rows = self
                .store
                .wallet_scan_rows(
                    EVM_CHAIN_TYPE,
                    chain.chain_id,
                    chain.railgun_contract,
                    planned.range.start,
                    planned.range.end,
                )
                .await
                .wrap_err("read planned wallet scan rows for artifact publication")?;
            if rows.is_empty() {
                continue;
            }
            let chunk_scope = scope.clone();
            let (start_block, end_block) = (planned.range.start, planned.range.end);
            let mut published = run_blocking(move || {
                prepare_wallet_scan_chunk(
                    chunk_scope,
                    start_block,
                    end_block,
                    &rows,
                    CompressionAlgorithm::Zstd,
                )
                .wrap_err("publish wallet-scan chunk")
            })
            .await?;
            published.descriptor = self
                .reuse_or_pin_chunk(published.descriptor, &published.compressed_bytes)
                .await?;
            chunks.push(published.descriptor);
        }
        self.publish_catalogs(
            scope,
            IndexedDatasetKind::WalletScan,
            chunks,
            CatalogCoverage::ExplicitBlockRange {
                start_block: chain.start_block,
                indexed_through_block: max_block,
            },
        )
        .await
    }

    pub(super) async fn publish_commitment_catalog(
        &self,
        chain: &ChainIndexedChainConfig,
        scope: &ChainScope,
        max_block: u64,
    ) -> Result<Vec<PublishedCatalog>> {
        let summaries = self
            .store
            .commitment_tree_summaries(
                EVM_CHAIN_TYPE,
                chain.chain_id,
                chain.railgun_contract,
                Some(max_block),
            )
            .await
            .wrap_err("read commitment tree summaries for commitment publication")?;
        let mut max_position = None;
        for summary in summaries {
            let last_position = summary
                .leaf_count
                .checked_sub(1)
                .ok_or_else(|| eyre!("commitment tree summary has zero leaves"))?;
            let tree_start = u64::from(summary.tree_number)
                .checked_mul(TREE_LEAF_COUNT)
                .ok_or_else(|| eyre!("commitment tree global position overflow"))?;
            let global_position = tree_start
                .checked_add(last_position)
                .ok_or_else(|| eyre!("commitment tree global position overflow"))?;
            max_position =
                Some(max_position.map_or(global_position, |value: u64| value.max(global_position)));
        }
        let Some(max_position) = max_position else {
            return Ok(Vec::new());
        };

        let mut start_position = 0_u64;
        let mut chunks = Vec::new();
        while start_position <= max_position {
            let end_position = start_position
                .saturating_add(
                    self.config
                        .chain_indexed
                        .commitment_chunk_row_limit
                        .saturating_sub(1),
                )
                .min(max_position);
            let rows = self
                .store
                .commitment_rows(
                    EVM_CHAIN_TYPE,
                    chain.chain_id,
                    chain.railgun_contract,
                    start_position,
                    end_position,
                    Some(max_block),
                )
                .await
                .wrap_err("read commitment rows for artifact publication")?;
            if rows.is_empty() {
                start_position = end_position.saturating_add(1);
                continue;
            }
            let page_scope = scope.clone();
            let planned_chunks = run_blocking(move || {
                let plan_items = commitment_plan_items(&page_scope, &rows)?;
                plan_chunks(&plan_items, ChunkPlanningConfig::default())
                    .wrap_err("plan commitment artifact chunks")
            })
            .await?;
            for planned in planned_chunks {
                let chunk_rows = self
                    .store
                    .commitment_rows(
                        EVM_CHAIN_TYPE,
                        chain.chain_id,
                        chain.railgun_contract,
                        planned.range.start,
                        planned.range.end,
                        Some(max_block),
                    )
                    .await
                    .wrap_err("read planned commitment rows for artifact publication")?;
                let chunk_scope = scope.clone();
                let mut published = run_blocking(move || {
                    prepare_commitment_chunk(chunk_scope, &chunk_rows, CompressionAlgorithm::Zstd)
                        .wrap_err("publish commitment chunk")
                })
                .await?;
                published.descriptor = self
                    .reuse_or_pin_chunk(published.descriptor, &published.compressed_bytes)
                    .await?;
                start_position = published.descriptor.range.end.saturating_add(1);
                chunks.push(published.descriptor);
            }
        }
        self.publish_catalogs(
            scope,
            IndexedDatasetKind::Commitments,
            chunks,
            CatalogCoverage::DerivedFromChunks,
        )
        .await
    }

    pub(super) async fn publish_merkle_checkpoint_catalog(
        &self,
        chain: &ChainIndexedChainConfig,
        scope: &ChainScope,
        max_block: u64,
    ) -> Result<Vec<PublishedCatalog>> {
        let summaries = self
            .store
            .commitment_tree_summaries(
                EVM_CHAIN_TYPE,
                chain.chain_id,
                chain.railgun_contract,
                Some(max_block),
            )
            .await
            .wrap_err("read commitment tree summaries for checkpoint publication")?;
        let mut chunks = Vec::new();
        for summary in summaries {
            let checkpoint = self
                .store
                .commitment_tree_checkpoint(
                    EVM_CHAIN_TYPE,
                    chain.chain_id,
                    chain.railgun_contract,
                    &summary,
                    Some(max_block),
                )
                .await
                .wrap_err("read commitment tree checkpoint leaves")?;
            let artifact = MerkleCheckpointArtifact {
                tree_number: checkpoint.tree_number,
                leaf_count: checkpoint.leaf_count,
                last_indexed_block: checkpoint.last_indexed_block,
                leaves: checkpoint.leaves,
            };
            let artifact_scope = scope.clone();
            let mut published = run_blocking(move || {
                prepare_merkle_checkpoint_artifact(
                    artifact_scope,
                    &artifact,
                    CompressionAlgorithm::Zstd,
                )
                .wrap_err("publish Merkle checkpoint artifact")
            })
            .await?;
            published.descriptor = self
                .reuse_or_pin_chunk(published.descriptor, &published.compressed_bytes)
                .await?;
            chunks.push(published.descriptor);
        }
        self.publish_catalogs(
            scope,
            IndexedDatasetKind::MerkleCheckpoint,
            chunks,
            CatalogCoverage::DerivedFromChunks,
        )
        .await
    }

    async fn publish_catalogs(
        &self,
        scope: &ChainScope,
        dataset_kind: IndexedDatasetKind,
        chunks: Vec<IndexedArtifactDescriptor>,
        coverage: CatalogCoverage,
    ) -> Result<Vec<PublishedCatalog>> {
        if chunks.is_empty() && matches!(coverage, CatalogCoverage::DerivedFromChunks) {
            return Ok(Vec::new());
        }
        let (catalog, catalog_bytes, catalog_hash, mut descriptor) =
            prepare_catalog_artifact(scope, dataset_kind, chunks, coverage)?;
        let chunk_count = catalog.chunks.len();
        let total_chunk_byte_size = catalog.chunks.iter().try_fold(0_u64, |total, chunk| {
            total
                .checked_add(chunk.byte_size)
                .ok_or_else(|| eyre!("indexed artifact chunk byte size overflow"))
        })?;
        let max_chunk_byte_size = catalog
            .chunks
            .iter()
            .map(|chunk| chunk.byte_size)
            .max()
            .unwrap_or(0);
        let catalog_cid = self
            .reuse_or_pin_indexed_artifact(
                IndexedArtifactPublicationKind::Catalog,
                descriptor.dataset_kind,
                &descriptor.scope,
                &descriptor.range,
                descriptor.byte_size,
                &catalog_hash,
                descriptor.encoding_version,
                &catalog_bytes,
            )
            .await
            .wrap_err("pin indexed artifact catalog")?;
        descriptor.cid = catalog_cid;
        info!(target: LOG_TARGET,
            chain_id = scope.chain_id,
            railgun_contract = %scope.railgun_contract,
            dataset = ?dataset_kind,
            cid = %descriptor.cid,
            chunk_count,
            total_chunk_byte_size,
            max_chunk_byte_size,
            byte_size = descriptor.byte_size,
            sha256 = %descriptor.sha256,
            "published indexed artifact catalog"
        );
        let mut artifact_cids = catalog
            .chunks
            .iter()
            .map(|chunk| chunk.cid.clone())
            .collect::<Vec<_>>();
        artifact_cids.push(descriptor.cid.clone());
        Ok(vec![PublishedCatalog {
            descriptor,
            artifact_cids,
        }])
    }

    async fn reuse_or_pin_chunk(
        &self,
        mut descriptor: IndexedArtifactDescriptor,
        compressed_bytes: &[u8],
    ) -> Result<IndexedArtifactDescriptor> {
        let hash = fixed_bytes(&descriptor.sha256);
        let cid = self
            .reuse_or_pin_indexed_artifact(
                IndexedArtifactPublicationKind::Chunk,
                descriptor.dataset_kind,
                &descriptor.scope,
                &descriptor.range,
                descriptor.byte_size,
                &hash,
                descriptor.encoding_version,
                compressed_bytes,
            )
            .await?;
        descriptor.cid = cid;
        Ok(descriptor)
    }

    pub(super) async fn reuse_or_pin_indexed_artifact(
        &self,
        artifact_kind: IndexedArtifactPublicationKind,
        dataset_kind: IndexedDatasetKind,
        scope: &ChainScope,
        range: &IndexedArtifactRange,
        byte_size: u64,
        content_hash: &[u8; 32],
        format_version: u16,
        bytes: &[u8],
    ) -> Result<String> {
        self.ensure_publication_running()?;
        let _pin_lifecycle = self.pin_lifecycle.lock().await;
        let reusable = Audit::live_indexed_artifact_cid(
            self.store.pool(),
            artifact_kind,
            dataset_kind,
            scope,
            range,
            byte_size,
            content_hash,
            format_version,
        )
        .await
        .wrap_err("lookup reusable indexed artifact CID")?;
        let (cid, ownership) = self
            .reuse_or_pin_bytes(reusable, artifact_kind, bytes)
            .await?;
        let audit_result = async {
            let mut tx = self
                .store
                .begin()
                .await
                .wrap_err("begin indexed artifact audit transaction")?;
            Audit::record_indexed_artifact_pin(
                &mut tx,
                artifact_kind,
                dataset_kind,
                scope,
                range,
                &cid,
                byte_size,
                content_hash,
                format_version,
            )
            .await
            .wrap_err("record indexed artifact pin")?;
            tx.commit().await.wrap_err("commit indexed artifact audit")
        }
        .await;
        self.settle_pin_audit(&cid, ownership, audit_result, "indexed artifact")
            .await?;
        self.ensure_publication_running()?;
        Ok(cid.to_string())
    }

    /// Returns `reusable` while the provider still holds it, otherwise pins `bytes` and returns
    /// the pin ownership that `settle_pin_audit` must settle. Call with the pin lifecycle lock
    /// held.
    pub(super) async fn reuse_or_pin_bytes(
        &self,
        reusable: Option<cid::Cid>,
        artifact_kind: IndexedArtifactPublicationKind,
        bytes: &[u8],
    ) -> Result<(cid::Cid, Option<PinOwnershipLease>)> {
        if let Some(cid) = reusable {
            if self
                .ipfs_client
                .contains(&cid)
                .await
                .wrap_err("check reusable indexed artifact availability")?
            {
                return Ok((cid, None));
            }
            warn!(target: LOG_TARGET, %cid, "reusable indexed artifact CID is missing; repinning");
        }
        let ownership = self.acquire_pin_ownership()?;
        match self.pin_indexed_artifact(artifact_kind, bytes).await {
            Ok(returned) => Ok((returned, Some(ownership))),
            Err(error) => {
                ownership.settle();
                Err(error)
            }
        }
    }

    /// Settles a fresh pin once its audit committed, or cleans it up when the audit failed.
    pub(super) async fn settle_pin_audit(
        &self,
        cid: &cid::Cid,
        ownership: Option<PinOwnershipLease>,
        audit_result: Result<()>,
        label: &'static str,
    ) -> Result<()> {
        if let Err(error) = audit_result {
            if let Some(ownership) = ownership {
                self.cleanup_uncommitted_pin_while_locked(cid, label, ownership)
                    .await;
            }
            return Err(error);
        }
        if let Some(ownership) = ownership {
            ownership.settle();
        }
        Ok(())
    }

    async fn pin_indexed_artifact(
        &self,
        artifact_kind: IndexedArtifactPublicationKind,
        bytes: &[u8],
    ) -> Result<cid::Cid> {
        match artifact_kind {
            IndexedArtifactPublicationKind::Chunk => {
                pin_indexed_chunk(self.ipfs_client.as_ref(), bytes)
                    .await
                    .wrap_err("pin indexed artifact chunk")
            }
            IndexedArtifactPublicationKind::Catalog => {
                pin_manifest(self.ipfs_client.as_ref(), bytes)
                    .await
                    .wrap_err("pin indexed artifact catalog")
            }
        }
    }

    pub(super) async fn cleanup_uncommitted_pin_while_locked(
        &self,
        cid: &cid::Cid,
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

    pub(super) async fn latest_indexed_heights(
        &self,
        chain: &ChainIndexedChainConfig,
    ) -> Result<Vec<LatestIndexedHeight>> {
        let mut latest = Vec::new();
        for dataset in &chain.datasets {
            let Some(progress) = self
                .store
                .chain_indexing_progress(
                    EVM_CHAIN_TYPE,
                    chain.chain_id,
                    chain.railgun_contract,
                    store_dataset_kind(*dataset),
                )
                .await
                .wrap_err("read latest indexed height")?
            else {
                continue;
            };
            latest.push(LatestIndexedHeight {
                dataset_kind: *dataset,
                block_number: progress.indexed_through_block,
                block_hash: FixedBytes::from(progress.indexed_through_block_hash),
            });
        }
        Ok(latest)
    }
}
