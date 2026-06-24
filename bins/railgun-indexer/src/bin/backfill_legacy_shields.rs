use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Instant;

use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::sol_types::SolEvent;
use alloy_rpc_types_eth::{Filter, Log};
use broadcaster_core::contracts::railgun::RailgunLegacyShieldEvents;
use clap::Parser;
use eyre::{Context, Result, bail};
use railgun_indexer_core::chain_logs::{hydrate_indexed_log_source_timestamps, ingest_chain_logs};
use railgun_indexer_core::config::{ChainIndexedChainConfig, Config};
use railgun_indexer_core::store::{Store, run_migrations};
use tracing_subscriber::EnvFilter;

const EVM_CHAIN_TYPE: u8 = 0;
const DEFAULT_MAX_BLOCKS_PER_BATCH: u64 = 10_000;

macro_rules! progress {
    ($($arg:tt)*) => {{
        eprintln!("[legacy-shield-backfill] {}", format_args!($($arg)*));
        let _ = io::stderr().flush();
    }};
}

#[derive(Debug, Parser)]
#[command(about = "Backfill only legacy 4-argument Shield logs into indexed_shield_commitments")]
struct Args {
    #[arg(long, env = "RAILGUN_INDEXER_CONFIG")]
    config: PathBuf,

    /// Restrict backfill to specific chain IDs. May be repeated.
    #[arg(long = "chain-id")]
    chain_ids: Vec<u64>,

    /// Override start block. Defaults to max(chain start block, v2 start block).
    #[arg(long)]
    from_block: Option<u64>,

    /// Override end block. Defaults to `legacy_shield_block`.
    #[arg(long)]
    to_block: Option<u64>,

    /// Maximum block span per `eth_getLogs` request.
    #[arg(long, default_value_t = DEFAULT_MAX_BLOCKS_PER_BATCH)]
    max_blocks_per_batch: u64,

    /// Fetch and decode logs without writing rows.
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    if args.max_blocks_per_batch == 0 {
        bail!("--max-blocks-per-batch must be non-zero");
    }

    let config = load_config(&args.config).wrap_err("load config")?;
    let selected = selected_chains(&config, &args)?;
    let pool = config
        .connect_postgres()
        .await
        .wrap_err("connect postgres")?;
    run_migrations(&pool).await.wrap_err("run migrations")?;
    let store = Store::new(pool);

    let mut total_logs = 0_usize;
    let mut total_rows = 0_usize;
    for chain in selected {
        let provider = build_provider(&chain.archive_rpc_url)
            .wrap_err_with(|| format!("build archive RPC provider for chain {}", chain.chain_id))?;
        let from_block = args
            .from_block
            .unwrap_or_else(|| chain.start_block.max(chain.v2_start_block));
        let to_block = args.to_block.unwrap_or(chain.legacy_shield_block);
        if from_block > to_block {
            progress!(
                "chain {}: skipping empty range {}..{}",
                chain.chain_id,
                from_block,
                to_block
            );
            continue;
        }

        let (logs, rows) = backfill_chain(
            &store,
            &provider,
            chain,
            from_block,
            to_block,
            args.max_blocks_per_batch,
            args.dry_run,
        )
        .await?;
        total_logs = total_logs.saturating_add(logs);
        total_rows = total_rows.saturating_add(rows);
    }

    println!(
        "legacy shield backfill complete dry_run={} logs={} shield_rows={}",
        args.dry_run, total_logs, total_rows
    );
    Ok(())
}

async fn backfill_chain(
    store: &Store,
    provider: &RootProvider,
    chain: &ChainIndexedChainConfig,
    from_block: u64,
    to_block: u64,
    max_blocks_per_batch: u64,
    dry_run: bool,
) -> Result<(usize, usize)> {
    let started = Instant::now();
    let mut cursor = from_block;
    let mut total_logs = 0_usize;
    let mut total_rows = 0_usize;
    while cursor <= to_block {
        let end = cursor
            .saturating_add(max_blocks_per_batch.saturating_sub(1))
            .min(to_block);
        let mut logs = fetch_legacy_shield_logs(provider, chain, cursor, end).await?;
        logs.sort_by_key(|log| {
            (
                log.block_number.unwrap_or_default(),
                log.log_index.unwrap_or_default(),
            )
        });
        let mut batch = ingest_chain_logs(&logs).wrap_err_with(|| {
            format!(
                "ingest legacy Shield logs for chain {} range {}..{}",
                chain.chain_id, cursor, end
            )
        })?;
        hydrate_indexed_log_source_timestamps(provider, &mut batch)
            .await
            .wrap_err("hydrate legacy shield block timestamps")?;
        let row_count = batch.shield_commitments.len();
        if !dry_run && row_count > 0 {
            let mut tx = store.begin().await.wrap_err("begin shield backfill tx")?;
            Store::persist_indexed_log_batch(
                &mut tx,
                EVM_CHAIN_TYPE,
                chain.chain_id,
                chain.railgun_contract,
                &batch,
            )
            .await
            .wrap_err("persist legacy shield rows")?;
            tx.commit().await.wrap_err("commit shield backfill tx")?;
        }

        progress!(
            "chain {}: range {}..{} logs={} shield_rows={} dry_run={} elapsed_ms={}",
            chain.chain_id,
            cursor,
            end,
            logs.len(),
            row_count,
            dry_run,
            started.elapsed().as_millis()
        );
        total_logs = total_logs.saturating_add(logs.len());
        total_rows = total_rows.saturating_add(row_count);
        cursor = end.saturating_add(1);
    }
    Ok((total_logs, total_rows))
}

async fn fetch_legacy_shield_logs(
    provider: &RootProvider,
    chain: &ChainIndexedChainConfig,
    from_block: u64,
    to_block: u64,
) -> Result<Vec<Log>> {
    let filter = Filter::new()
        .select(from_block..=to_block)
        .address(chain.railgun_contract)
        .event_signature(RailgunLegacyShieldEvents::Shield::SIGNATURE_HASH);
    provider
        .get_logs(&filter)
        .await
        .wrap_err_with(|| format!("fetch legacy Shield logs {from_block}..{to_block}"))
}

fn selected_chains<'a>(
    config: &'a Config,
    args: &Args,
) -> Result<Vec<&'a ChainIndexedChainConfig>> {
    let chains = config
        .chain_indexed
        .chains
        .iter()
        .filter(|chain| args.chain_ids.is_empty() || args.chain_ids.contains(&chain.chain_id))
        .collect::<Vec<_>>();
    if chains.is_empty() {
        bail!("no chain_indexed chains matched --chain-id filters");
    }
    Ok(chains)
}

fn load_config(path: &PathBuf) -> Result<Config> {
    let data = fs::read_to_string(path).wrap_err("read config file")?;
    serde_yaml::from_str(&data).wrap_err("parse yaml config")
}

fn build_provider(rpc_url: &str) -> Result<RootProvider> {
    let url = url::Url::parse(rpc_url).wrap_err("parse RPC URL")?;
    Ok(ProviderBuilder::new().connect_http(url).root().clone())
}
