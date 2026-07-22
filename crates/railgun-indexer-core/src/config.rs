use crate::manifest::IndexedDatasetKind;
use alloy_primitives::{Address, FixedBytes};
use serde::{Deserialize, Deserializer};
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;

pub const SUPPORTED_CHAIN_IDS: &[u64] = &[1, 56, 137, 42161];

const POSTGRES_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const POSTGRES_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(30);
const POSTGRES_BACKGROUND_CONNECTION_HEADROOM: usize = 5;
const UPSTREAM_MAX_PAGE_SIZE: usize = 100;
const DEFAULT_CHAIN_INDEXED_DATASET_COUNT: usize = 4;
const DEFAULT_CHAIN_INDEXED_TAIL_SAFETY_INTERVAL: Duration = Duration::from_mins(5);
const DEFAULT_CHAIN_INDEXED_TAIL_SAFETY_BLOCK_SPAN: u64 = 1_000;
pub const DEFAULT_POI_TXID_VERSION: &str = "V2_PoseidonMerkle";

#[derive(Debug, Clone)]
pub struct Config {
    pub upstream_url: String,
    pub list_keys: Vec<FixedBytes<32>>,
    pub chain_ids: Vec<u64>,
    pub txid_version: String,
    pub postgres_connection_string: String,
    pub ipfs_endpoint: String,
    pub publisher_signing_key_path: PathBuf,
    pub chain_indexed_publisher_signing_key_path: PathBuf,
    pub ipns_bootstrap_peers: Vec<String>,
    pub ipns_record_lifetime: humantime_serde::Serde<Duration>,
    pub ipns_record_ttl: humantime_serde::Serde<Duration>,
    pub ipns_republish_interval: humantime_serde::Serde<Duration>,
    pub ipns_publish_timeout: humantime_serde::Serde<Duration>,
    pub page_size_max: usize,
    pub retry_budget: usize,
    pub polite_interval: humantime_serde::Serde<Duration>,
    pub blocked_shield_resync_interval: humantime_serde::Serde<Duration>,
    pub delta_publish_interval: humantime_serde::Serde<Duration>,
    pub base_rebuild_interval: humantime_serde::Serde<Duration>,
    pub retention_interval: humantime_serde::Serde<Duration>,
    pub per_pair_concurrency_limit: usize,
    pub chain_indexed: ChainIndexedDatasetConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    railgun_indexer: RailgunIndexerConfig,
    poi: PoiDatasetConfig,
    chain_indexed: ChainIndexedDatasetConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RailgunIndexerConfig {
    pub postgres_connection_string: String,
    pub ipfs_endpoint: String,
    pub publisher_signing_key_path: PathBuf,
    pub chain_indexed_publisher_signing_key_path: PathBuf,
    pub ipns_bootstrap_peers: Vec<String>,
    pub ipns_record_lifetime: humantime_serde::Serde<Duration>,
    pub ipns_record_ttl: humantime_serde::Serde<Duration>,
    pub ipns_republish_interval: humantime_serde::Serde<Duration>,
    pub ipns_publish_timeout: humantime_serde::Serde<Duration>,
    pub retention_interval: humantime_serde::Serde<Duration>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoiDatasetConfig {
    pub upstream_url: String,
    pub list_keys: Vec<FixedBytes<32>>,
    pub chain_ids: Vec<u64>,
    #[serde(default = "default_poi_txid_version")]
    pub txid_version: String,
    pub page_size_max: usize,
    pub retry_budget: usize,
    pub polite_interval: humantime_serde::Serde<Duration>,
    pub blocked_shield_resync_interval: humantime_serde::Serde<Duration>,
    pub delta_publish_interval: humantime_serde::Serde<Duration>,
    pub base_rebuild_interval: humantime_serde::Serde<Duration>,
    pub per_pair_concurrency_limit: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainIndexedDatasetConfig {
    pub enabled: bool,
    pub chains: Vec<ChainIndexedChainConfig>,
    pub index_interval: humantime_serde::Serde<Duration>,
    #[serde(default = "default_chain_indexed_tail_safety_interval")]
    pub tail_safety_interval: humantime_serde::Serde<Duration>,
    #[serde(default = "default_chain_indexed_tail_safety_block_span")]
    pub tail_safety_block_span: u64,
    pub publish_interval: humantime_serde::Serde<Duration>,
    pub max_blocks_per_batch: u64,
    pub safe_confirmations: u64,
    pub public_txid_chunk_row_limit: u64,
    pub commitment_chunk_row_limit: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainIndexedChainConfig {
    pub chain_id: u64,
    pub railgun_contract: Address,
    pub rpc_url: String,
    #[serde(default)]
    pub ws_url: Option<String>,
    pub archive_rpc_url: String,
    pub start_block: u64,
    pub v2_start_block: u64,
    pub legacy_shield_block: u64,
    #[serde(default = "default_chain_indexed_datasets")]
    pub datasets: Vec<IndexedDatasetKind>,
}

impl<'de> Deserialize<'de> for Config {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        ConfigFile::deserialize(deserializer).map(Into::into)
    }
}

impl From<ConfigFile> for Config {
    fn from(value: ConfigFile) -> Self {
        let railgun_indexer = value.railgun_indexer;
        let poi = value.poi;
        let chain_indexed = value.chain_indexed;
        Self {
            upstream_url: poi.upstream_url,
            list_keys: poi.list_keys,
            chain_ids: poi.chain_ids,
            txid_version: poi.txid_version,
            postgres_connection_string: railgun_indexer.postgres_connection_string,
            ipfs_endpoint: railgun_indexer.ipfs_endpoint,
            publisher_signing_key_path: railgun_indexer.publisher_signing_key_path,
            chain_indexed_publisher_signing_key_path: railgun_indexer
                .chain_indexed_publisher_signing_key_path,
            ipns_bootstrap_peers: railgun_indexer.ipns_bootstrap_peers,
            ipns_record_lifetime: railgun_indexer.ipns_record_lifetime,
            ipns_record_ttl: railgun_indexer.ipns_record_ttl,
            ipns_republish_interval: railgun_indexer.ipns_republish_interval,
            ipns_publish_timeout: railgun_indexer.ipns_publish_timeout,
            page_size_max: poi.page_size_max,
            retry_budget: poi.retry_budget,
            polite_interval: poi.polite_interval,
            blocked_shield_resync_interval: poi.blocked_shield_resync_interval,
            delta_publish_interval: poi.delta_publish_interval,
            base_rebuild_interval: poi.base_rebuild_interval,
            retention_interval: railgun_indexer.retention_interval,
            per_pair_concurrency_limit: poi.per_pair_concurrency_limit,
            chain_indexed,
        }
    }
}

impl Config {
    /// Validates config values that can be checked before opening external resources.
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.list_keys.is_empty() {
            return Err(ConfigValidationError::EmptyListKeys);
        }
        if self.chain_ids.is_empty() {
            return Err(ConfigValidationError::EmptyChainIds);
        }
        if self.txid_version.trim().is_empty() {
            return Err(ConfigValidationError::EmptyPoiTxidVersion);
        }
        for chain_id in &self.chain_ids {
            if !SUPPORTED_CHAIN_IDS.contains(chain_id) {
                return Err(ConfigValidationError::UnknownChainId(*chain_id));
            }
        }

        if self.blocked_shield_resync_interval.is_zero() {
            return Err(ConfigValidationError::ZeroBlockedShieldResyncInterval);
        }
        if self.ipns_bootstrap_peers.is_empty() {
            return Err(ConfigValidationError::EmptyIpnsBootstrapPeers);
        }
        if self.publisher_signing_key_path == self.chain_indexed_publisher_signing_key_path {
            return Err(ConfigValidationError::SharedPublisherSigningKeyPath);
        }
        if self.ipns_record_lifetime.is_zero() {
            return Err(ConfigValidationError::ZeroIpnsRecordLifetime);
        }
        if self.ipns_record_ttl.is_zero() {
            return Err(ConfigValidationError::ZeroIpnsRecordTtl);
        }
        if self.ipns_republish_interval.is_zero() {
            return Err(ConfigValidationError::ZeroIpnsRepublishInterval);
        }
        if self.ipns_publish_timeout.is_zero() {
            return Err(ConfigValidationError::ZeroIpnsPublishTimeout);
        }
        if self.retry_budget == 0 {
            return Err(ConfigValidationError::ZeroRetryBudget);
        }
        if self.page_size_max == 0 {
            return Err(ConfigValidationError::ZeroPageSizeMax);
        }
        if self.page_size_max > UPSTREAM_MAX_PAGE_SIZE {
            return Err(ConfigValidationError::PageSizeMaxTooLarge {
                configured: self.page_size_max,
                maximum: UPSTREAM_MAX_PAGE_SIZE,
            });
        }
        if self.polite_interval.is_zero() {
            return Err(ConfigValidationError::ZeroPoliteInterval);
        }
        if self.delta_publish_interval.is_zero() {
            return Err(ConfigValidationError::ZeroDeltaPublishInterval);
        }
        if self.base_rebuild_interval.is_zero() {
            return Err(ConfigValidationError::ZeroBaseRebuildInterval);
        }
        if self.retention_interval.is_zero() {
            return Err(ConfigValidationError::ZeroRetentionInterval);
        }
        if self.per_pair_concurrency_limit == 0 {
            return Err(ConfigValidationError::ZeroPerPairConcurrencyLimit);
        }
        self.validate_chain_indexed()?;
        let _pool_size = self.postgres_max_connections()?;

        Ok(())
    }

    fn validate_chain_indexed(&self) -> Result<(), ConfigValidationError> {
        if !self.chain_indexed.enabled {
            return Ok(());
        }
        if self.chain_indexed.chains.is_empty() {
            return Err(ConfigValidationError::EmptyChainIndexedChains);
        }
        if self.chain_indexed.index_interval.is_zero() {
            return Err(ConfigValidationError::ZeroChainIndexedIndexInterval);
        }
        if self.chain_indexed.tail_safety_interval.is_zero() {
            return Err(ConfigValidationError::ZeroChainIndexedTailSafetyInterval);
        }
        if self.chain_indexed.tail_safety_block_span == 0 {
            return Err(ConfigValidationError::ZeroChainIndexedTailSafetyBlockSpan);
        }
        if self.chain_indexed.publish_interval.is_zero() {
            return Err(ConfigValidationError::ZeroChainIndexedPublishInterval);
        }
        if self.chain_indexed.max_blocks_per_batch == 0 {
            return Err(ConfigValidationError::ZeroChainIndexedMaxBlocksPerBatch);
        }
        if self.chain_indexed.public_txid_chunk_row_limit == 0 {
            return Err(ConfigValidationError::ZeroPublicTxidChunkRowLimit);
        }
        if self.chain_indexed.commitment_chunk_row_limit == 0 {
            return Err(ConfigValidationError::ZeroCommitmentChunkRowLimit);
        }

        let mut seen_chains = HashSet::new();
        for chain in &self.chain_indexed.chains {
            if !SUPPORTED_CHAIN_IDS.contains(&chain.chain_id) {
                return Err(ConfigValidationError::UnknownChainId(chain.chain_id));
            }
            if chain.rpc_url.trim().is_empty() {
                return Err(ConfigValidationError::EmptyChainIndexedRpcUrl {
                    chain_id: chain.chain_id,
                });
            }
            if chain
                .ws_url
                .as_deref()
                .is_some_and(|url| url.trim().is_empty())
            {
                return Err(ConfigValidationError::EmptyChainIndexedWsUrl {
                    chain_id: chain.chain_id,
                });
            }
            if chain.archive_rpc_url.trim().is_empty() {
                return Err(ConfigValidationError::EmptyChainIndexedArchiveRpcUrl {
                    chain_id: chain.chain_id,
                });
            }
            if chain.railgun_contract == Address::ZERO {
                return Err(ConfigValidationError::ZeroChainIndexedRailgunContract {
                    chain_id: chain.chain_id,
                });
            }
            if chain.datasets.is_empty() {
                return Err(ConfigValidationError::EmptyChainIndexedDatasets {
                    chain_id: chain.chain_id,
                });
            }
            if !seen_chains.insert((chain.chain_id, chain.railgun_contract)) {
                return Err(ConfigValidationError::DuplicateChainIndexedChain {
                    chain_id: chain.chain_id,
                    railgun_contract: chain.railgun_contract.to_string(),
                });
            }
        }

        Ok(())
    }

    /// Computes the pool size needed for the configured pair concurrency plus background loops.
    pub fn postgres_max_connections(&self) -> Result<u32, ConfigValidationError> {
        let workers = self
            .per_pair_concurrency_limit
            .checked_mul(2)
            .and_then(|workers| workers.checked_add(POSTGRES_BACKGROUND_CONNECTION_HEADROOM))
            .ok_or(ConfigValidationError::PostgresPoolSizeOverflow)?;
        u32::try_from(workers).map_err(|_| ConfigValidationError::PostgresPoolSizeOverflow)
    }

    /// Validates config values and establishes the first Postgres connection.
    pub async fn connect_postgres(&self) -> Result<PgPool, ConfigValidationError> {
        self.validate()?;
        let max_connections = self.postgres_max_connections()?;

        let pool = tokio::time::timeout(
            POSTGRES_CONNECT_TIMEOUT,
            PgPoolOptions::new()
                .max_connections(max_connections)
                .acquire_timeout(POSTGRES_ACQUIRE_TIMEOUT)
                .connect(&self.postgres_connection_string),
        )
        .await
        .map_err(|_| ConfigValidationError::PostgresConnectTimeout(POSTGRES_CONNECT_TIMEOUT))??;

        Ok(pool)
    }
}

#[derive(Debug, Error)]
pub enum ConfigValidationError {
    #[error("list_keys must contain at least one POI list key")]
    EmptyListKeys,
    #[error("chain_ids must contain at least one supported chain id")]
    EmptyChainIds,
    #[error("poi.txid_version must not be empty")]
    EmptyPoiTxidVersion,
    #[error("unsupported chain id {0}; supported chain ids are 1, 56, 137, 42161")]
    UnknownChainId(u64),
    #[error("postgres connection attempt timed out after {0:?}")]
    PostgresConnectTimeout(Duration),
    #[error("computed postgres pool size overflowed")]
    PostgresPoolSizeOverflow,
    #[error("blocked_shield_resync_interval must be greater than zero")]
    ZeroBlockedShieldResyncInterval,
    #[error("ipns_bootstrap_peers must contain at least one public DHT bootstrap peer")]
    EmptyIpnsBootstrapPeers,
    #[error(
        "chain-indexed publisher signing key path must differ from POI publisher signing key path"
    )]
    SharedPublisherSigningKeyPath,
    #[error("ipns_record_lifetime must be greater than zero")]
    ZeroIpnsRecordLifetime,
    #[error("ipns_record_ttl must be greater than zero")]
    ZeroIpnsRecordTtl,
    #[error("ipns_republish_interval must be greater than zero")]
    ZeroIpnsRepublishInterval,
    #[error("ipns_publish_timeout must be greater than zero")]
    ZeroIpnsPublishTimeout,
    #[error("retry_budget must be greater than zero")]
    ZeroRetryBudget,
    #[error("page_size_max must be greater than zero")]
    ZeroPageSizeMax,
    #[error("page_size_max {configured} exceeds upstream maximum {maximum}")]
    PageSizeMaxTooLarge { configured: usize, maximum: usize },
    #[error("polite_interval must be greater than zero")]
    ZeroPoliteInterval,
    #[error("delta_publish_interval must be greater than zero")]
    ZeroDeltaPublishInterval,
    #[error("base_rebuild_interval must be greater than zero")]
    ZeroBaseRebuildInterval,
    #[error("retention_interval must be greater than zero")]
    ZeroRetentionInterval,
    #[error("per_pair_concurrency_limit must be greater than zero")]
    ZeroPerPairConcurrencyLimit,
    #[error("chain_indexed.chains must contain at least one chain when chain_indexed is enabled")]
    EmptyChainIndexedChains,
    #[error("chain_indexed.index_interval must be greater than zero")]
    ZeroChainIndexedIndexInterval,
    #[error("chain_indexed.tail_safety_interval must be greater than zero")]
    ZeroChainIndexedTailSafetyInterval,
    #[error("chain_indexed.tail_safety_block_span must be greater than zero")]
    ZeroChainIndexedTailSafetyBlockSpan,
    #[error("chain_indexed.publish_interval must be greater than zero")]
    ZeroChainIndexedPublishInterval,
    #[error("chain_indexed.max_blocks_per_batch must be greater than zero")]
    ZeroChainIndexedMaxBlocksPerBatch,
    #[error("chain_indexed.public_txid_chunk_row_limit must be greater than zero")]
    ZeroPublicTxidChunkRowLimit,
    #[error("chain_indexed.commitment_chunk_row_limit must be greater than zero")]
    ZeroCommitmentChunkRowLimit,
    #[error("chain_indexed RPC URL must be set for chain id {chain_id}")]
    EmptyChainIndexedRpcUrl { chain_id: u64 },
    #[error("chain_indexed websocket URL must be non-empty when set for chain id {chain_id}")]
    EmptyChainIndexedWsUrl { chain_id: u64 },
    #[error("chain_indexed archive RPC URL must be set for chain id {chain_id}")]
    EmptyChainIndexedArchiveRpcUrl { chain_id: u64 },
    #[error("chain_indexed railgun contract must be non-zero for chain id {chain_id}")]
    ZeroChainIndexedRailgunContract { chain_id: u64 },
    #[error("chain_indexed datasets must not be empty for chain id {chain_id}")]
    EmptyChainIndexedDatasets { chain_id: u64 },
    #[error(
        "duplicate chain_indexed entry for chain id {chain_id} and railgun contract {railgun_contract}"
    )]
    DuplicateChainIndexedChain {
        chain_id: u64,
        railgun_contract: String,
    },
    #[error("postgres connection failed")]
    Postgres(#[from] sqlx::Error),
}

fn default_chain_indexed_datasets() -> Vec<IndexedDatasetKind> {
    let mut datasets = Vec::with_capacity(DEFAULT_CHAIN_INDEXED_DATASET_COUNT);
    datasets.push(IndexedDatasetKind::PublicTxid);
    datasets.push(IndexedDatasetKind::WalletScan);
    datasets.push(IndexedDatasetKind::Commitments);
    datasets.push(IndexedDatasetKind::MerkleCheckpoint);
    datasets
}

fn default_poi_txid_version() -> String {
    DEFAULT_POI_TXID_VERSION.to_string()
}

fn default_chain_indexed_tail_safety_interval() -> humantime_serde::Serde<Duration> {
    DEFAULT_CHAIN_INDEXED_TAIL_SAFETY_INTERVAL.into()
}

const fn default_chain_indexed_tail_safety_block_span() -> u64 {
    DEFAULT_CHAIN_INDEXED_TAIL_SAFETY_BLOCK_SPAN
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> Config {
        Config {
            upstream_url: "https://ppoi.example.invalid".to_string(),
            list_keys: vec![FixedBytes::from([1_u8; 32])],
            chain_ids: vec![1],
            txid_version: DEFAULT_POI_TXID_VERSION.to_string(),
            postgres_connection_string: "not a postgres connection string".to_string(),
            ipfs_endpoint: "https://s3.filebase.com".to_string(),
            publisher_signing_key_path: PathBuf::from("publisher.key"),
            chain_indexed_publisher_signing_key_path: PathBuf::from("chain-indexed-publisher.key"),
            ipns_bootstrap_peers: vec!["/dnsaddr/bootstrap.libp2p.io".to_string()],
            ipns_record_lifetime: Duration::from_secs(1).into(),
            ipns_record_ttl: Duration::from_secs(1).into(),
            ipns_republish_interval: Duration::from_secs(1).into(),
            ipns_publish_timeout: Duration::from_secs(1).into(),
            page_size_max: 100,
            retry_budget: 1,
            polite_interval: Duration::from_secs(1).into(),
            blocked_shield_resync_interval: Duration::from_secs(1).into(),
            delta_publish_interval: Duration::from_secs(1).into(),
            base_rebuild_interval: Duration::from_secs(1).into(),
            retention_interval: Duration::from_secs(1).into(),
            per_pair_concurrency_limit: 1,
            chain_indexed: ChainIndexedDatasetConfig {
                enabled: true,
                chains: vec![ChainIndexedChainConfig {
                    chain_id: 1,
                    railgun_contract: Address::from([0xbb; 20]),
                    rpc_url: "https://rpc.example.invalid".to_string(),
                    ws_url: Some("wss://rpc.example.invalid".to_string()),
                    archive_rpc_url: "https://archive-rpc.example.invalid".to_string(),
                    start_block: 1,
                    v2_start_block: 2,
                    legacy_shield_block: 3,
                    datasets: default_chain_indexed_datasets(),
                }],
                index_interval: Duration::from_secs(1).into(),
                tail_safety_interval: Duration::from_mins(5).into(),
                tail_safety_block_span: 1_000,
                publish_interval: Duration::from_secs(1).into(),
                max_blocks_per_batch: 10,
                safe_confirmations: 12,
                public_txid_chunk_row_limit: 1_000,
                commitment_chunk_row_limit: 1_000,
            },
        }
    }

    #[tokio::test]
    async fn zero_retry_budget_is_rejected_before_postgres_connect() {
        let mut config = valid_config();
        config.retry_budget = 0;

        let error = config
            .connect_postgres()
            .await
            .expect_err("zero retry budget should fail validation");

        assert!(matches!(error, ConfigValidationError::ZeroRetryBudget));
    }

    #[test]
    fn nested_sections_deserialize_to_runtime_config() {
        let config: Config = serde_json::from_value(serde_json::json!({
            "railgun_indexer": {
                "postgres_connection_string": "postgres://railgun_indexer:railgun_indexer@localhost:5432/railgun_indexer",
                "ipfs_endpoint": "https://s3.filebase.com",
                "publisher_signing_key_path": "secrets/railgun-indexer-publisher.key",
                "chain_indexed_publisher_signing_key_path": "secrets/railgun-indexer-chain-indexed-publisher.key",
                "ipns_bootstrap_peers": ["/dnsaddr/bootstrap.libp2p.io"],
                "ipns_record_lifetime": "24h",
                "ipns_record_ttl": "1h",
                "ipns_republish_interval": "12h",
                "ipns_publish_timeout": "60s",
                "retention_interval": "168h"
            },
            "poi": {
                "upstream_url": "https://ppoi.example.invalid",
                "list_keys": ["0x0101010101010101010101010101010101010101010101010101010101010101"],
                "chain_ids": [1],
                "txid_version": "V2_PoseidonMerkle",
                "page_size_max": 100,
                "retry_budget": 5,
                "polite_interval": "1s",
                "blocked_shield_resync_interval": "30m",
                "delta_publish_interval": "10m",
                "base_rebuild_interval": "24h",
                "per_pair_concurrency_limit": 4
            },
            "chain_indexed": {
                "enabled": true,
                "chains": [{
                    "chain_id": 1,
                    "railgun_contract": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "rpc_url": "https://rpc.example.invalid",
                    "ws_url": "wss://rpc.example.invalid",
                    "archive_rpc_url": "https://archive-rpc.example.invalid",
                    "start_block": 100,
                    "v2_start_block": 200,
                    "legacy_shield_block": 300,
                    "datasets": ["public_txid", "wallet_scan", "commitments", "merkle_checkpoint"]
                }],
                "index_interval": "15s",
                "tail_safety_interval": "5m",
                "tail_safety_block_span": 1_000,
                "publish_interval": "10m",
                "max_blocks_per_batch": 1_000,
                "safe_confirmations": 12,
                "public_txid_chunk_row_limit": 10_000,
                "commitment_chunk_row_limit": 50_000
            }
        }))
        .expect("nested config should deserialize");

        assert_eq!(config.upstream_url, "https://ppoi.example.invalid");
        assert_eq!(
            config.postgres_connection_string,
            "postgres://railgun_indexer:railgun_indexer@localhost:5432/railgun_indexer"
        );
        assert_eq!(
            config.publisher_signing_key_path,
            PathBuf::from("secrets/railgun-indexer-publisher.key")
        );
        assert_eq!(
            config.chain_indexed_publisher_signing_key_path,
            PathBuf::from("secrets/railgun-indexer-chain-indexed-publisher.key")
        );
        assert_eq!(config.chain_ids, vec![1]);
        assert_eq!(config.txid_version, DEFAULT_POI_TXID_VERSION);
        assert_eq!(config.per_pair_concurrency_limit, 4);
        assert!(config.chain_indexed.enabled);
        assert_eq!(config.chain_indexed.chains.len(), 1);
        assert_eq!(config.chain_indexed.chains[0].start_block, 100);
        assert_eq!(
            config.chain_indexed.chains[0].ws_url.as_deref(),
            Some("wss://rpc.example.invalid")
        );
        assert_eq!(
            *config.chain_indexed.tail_safety_interval,
            Duration::from_mins(5)
        );
        assert_eq!(config.chain_indexed.tail_safety_block_span, 1_000);
        assert_eq!(config.chain_indexed.public_txid_chunk_row_limit, 10_000);
    }

    #[test]
    fn shared_poi_and_chain_indexed_publisher_key_path_is_rejected() {
        let mut config = valid_config();
        config.chain_indexed_publisher_signing_key_path = config.publisher_signing_key_path.clone();

        let error = config.validate().expect_err("shared key path should fail");

        assert!(matches!(
            error,
            ConfigValidationError::SharedPublisherSigningKeyPath
        ));
    }

    #[test]
    fn zero_concurrency_is_rejected_at_startup_validation() {
        let mut config = valid_config();
        config.per_pair_concurrency_limit = 0;

        let error = config.validate().expect_err("zero concurrency should fail");

        match error {
            ConfigValidationError::ZeroPerPairConcurrencyLimit => {}
            other => panic!("unexpected validation error: {other:?}"),
        }
    }

    #[test]
    fn disabled_chain_indexed_config_does_not_require_rpc_chains() {
        let mut config = valid_config();
        config.chain_indexed.enabled = false;
        config.chain_indexed.chains.clear();
        config.chain_indexed.max_blocks_per_batch = 0;

        config
            .validate()
            .expect("disabled chain-indexed config should not require RPC settings");
    }

    #[test]
    fn enabled_chain_indexed_config_requires_explicit_rpc_urls() {
        let mut config = valid_config();
        config.chain_indexed.chains[0].rpc_url.clear();

        let error = config
            .validate()
            .expect_err("empty RPC URL should fail validation");

        assert!(matches!(
            error,
            ConfigValidationError::EmptyChainIndexedRpcUrl { chain_id: 1 }
        ));
    }

    #[test]
    fn enabled_chain_indexed_config_requires_tail_safety_interval() {
        let mut config = valid_config();
        config.chain_indexed.tail_safety_interval = Duration::ZERO.into();

        let error = config
            .validate()
            .expect_err("zero tail safety interval should fail validation");

        assert!(matches!(
            error,
            ConfigValidationError::ZeroChainIndexedTailSafetyInterval
        ));
    }

    #[test]
    fn enabled_chain_indexed_config_requires_tail_safety_block_span() {
        let mut config = valid_config();
        config.chain_indexed.tail_safety_block_span = 0;

        let error = config
            .validate()
            .expect_err("zero tail safety block span should fail validation");

        assert!(matches!(
            error,
            ConfigValidationError::ZeroChainIndexedTailSafetyBlockSpan
        ));
    }

    #[test]
    fn pool_size_scales_with_pair_concurrency_and_background_headroom() {
        let mut config = valid_config();
        config.per_pair_concurrency_limit = 4;

        assert_eq!(config.postgres_max_connections().expect("pool size"), 13);
    }

    #[test]
    fn page_size_above_upstream_limit_is_rejected() {
        let mut config = valid_config();
        config.page_size_max = 101;

        let error = config.validate().expect_err("oversized page should fail");

        match error {
            ConfigValidationError::PageSizeMaxTooLarge { .. } => {}
            other => panic!("unexpected validation error: {other:?}"),
        }
    }
}
