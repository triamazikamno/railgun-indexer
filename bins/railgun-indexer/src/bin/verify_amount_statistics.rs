use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use alloy::primitives::Address;
use clap::Parser;
use eyre::{Context, Result, bail, eyre};
use railgun_indexer_core::amount_statistics::{
    aggregate_amount_statistics, read_amount_statistics_records_at,
};
use railgun_indexer_core::config::Config;
use railgun_indexer_core::manifest::{
    AMOUNT_STATISTICS_MAX_COMPRESSED_BYTES, AmountStatisticsSnapshot, ChainScope, ChainType,
    TokenAmountStatistics, decode_amount_statistics_snapshot,
};
use reqwest::Client;
use tracing_subscriber::EnvFilter;
use trustless_artifacts::{DEFAULT_GATEWAYS, TrustlessArtifactFetcher};
use url::Url;

const ABSENT: &str = "absent";
const DUPLICATE: &str = "duplicate entries";

#[derive(Debug, Parser)]
#[command(
    about = "Recompute a published amount-statistics snapshot from the indexed tables and compare every figure"
)]
struct Args {
    #[arg(long, env = "RAILGUN_INDEXER_CONFIG")]
    config: PathBuf,

    /// Chain ID of the snapshot. Must match a `chain_indexed.chains` entry.
    #[arg(long)]
    chain_id: u64,

    /// Snapshot CID from the chain's entry in the amount-statistics manifest.
    #[arg(long)]
    snapshot_cid: String,
}

/// One figure whose published value differs from the recomputed one.
#[derive(Debug, PartialEq, Eq)]
struct Difference {
    token: Address,
    figure: String,
    published: String,
    recomputed: String,
}

type Figures = BTreeMap<String, String>;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let config = load_config(&args.config).wrap_err("load config")?;
    let configured = configured_scopes(&config, args.chain_id)?;
    let client = Client::builder()
        .user_agent("railgun-indexer-amount-statistics-verifier/0.1")
        .build()?;
    let gateways = DEFAULT_GATEWAYS
        .iter()
        .copied()
        .map(Url::parse)
        .collect::<Result<Vec<_>, _>>()
        .wrap_err("parse default IPFS gateways")?;
    // The fetcher checks the bytes against the requested CID, so another body cannot be certified.
    let bytes = TrustlessArtifactFetcher::new(&client, &gateways)
        .fetch_artifact_cid(&args.snapshot_cid, AMOUNT_STATISTICS_MAX_COMPRESSED_BYTES)
        .await
        .wrap_err_with(|| format!("fetch snapshot {}", args.snapshot_cid))?;
    let published = decode_amount_statistics_snapshot(&bytes)
        .wrap_err_with(|| format!("decode snapshot {}", args.snapshot_cid))?;
    if !configured.contains(&published.scope) {
        bail!(
            "snapshot {} covers chain {} contract {}, which is not a configured chain {} contract",
            args.snapshot_cid,
            published.scope.chain_id,
            published.scope.railgun_contract,
            args.chain_id
        );
    }
    let scope = published.scope.clone();

    let pool = config
        .connect_postgres()
        .await
        .wrap_err("connect postgres")?;
    let (records, hash_checked) =
        read_amount_statistics_records_at(&pool, &scope, &published.covered_block)
            .await
            .wrap_err("read indexed records at the covered block")?;
    // Publication read the covered timestamp by block hash, so the windows need no RPC here.
    let recomputed = aggregate_amount_statistics(
        scope,
        published.covered_block.clone(),
        &records.shields,
        &records.unshields,
    );
    println!(
        "chain {} snapshot={} covered_block={} hash={} timestamp={} published_tokens={} recomputed_tokens={}",
        args.chain_id,
        args.snapshot_cid,
        published.covered_block.number,
        published.covered_block.hash,
        published.covered_block.timestamp,
        published.tokens.len(),
        recomputed.tokens.len()
    );
    if !hash_checked {
        println!(
            "note: this database has no indexed header at block {}, so the covered block hash could not be checked against it; records were read by block number",
            published.covered_block.number
        );
    }
    report(&compare_snapshots(&published, &recomputed))
}

/// Every configured scope on `chain_id`; a chain ID may list more than one contract.
fn configured_scopes(config: &Config, chain_id: u64) -> Result<Vec<ChainScope>> {
    let scopes = config
        .chain_indexed
        .chains
        .iter()
        .filter(|chain| chain.chain_id == chain_id)
        .map(|chain| ChainScope {
            chain_type: ChainType::Evm,
            chain_id,
            railgun_contract: chain.railgun_contract,
        })
        .collect::<Vec<_>>();
    if scopes.is_empty() {
        bail!("chain {chain_id} is not in chain_indexed.chains");
    }
    Ok(scopes)
}

/// Prints every difference and fails when there is one, so the process exits with a failure
/// status.
fn report(differences: &[Difference]) -> Result<()> {
    if differences.is_empty() {
        println!("every figure matches");
        return Ok(());
    }
    for difference in differences {
        println!(
            "mismatch token={} figure={} published={} recomputed={}",
            difference.token, difference.figure, difference.published, difference.recomputed
        );
    }
    Err(eyre!(
        "amount statistics differ in {} figure(s)",
        differences.len()
    ))
}

fn compare_snapshots(
    published: &AmountStatisticsSnapshot,
    recomputed: &AmountStatisticsSnapshot,
) -> Vec<Difference> {
    let published = token_figures(published);
    let recomputed = token_figures(recomputed);
    let tokens = published
        .keys()
        .chain(recomputed.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    tokens
        .into_iter()
        .flat_map(|token| figure_differences(token, published.get(&token), recomputed.get(&token)))
        .collect()
}

fn figure_differences(
    token: Address,
    published: Option<&Figures>,
    recomputed: Option<&Figures>,
) -> Vec<Difference> {
    let (Some(published_figures), Some(recomputed_figures)) = (published, recomputed) else {
        // A token listed on one side only is one difference, not one per figure.
        return vec![Difference {
            token,
            figure: "token".to_owned(),
            published: listed(published),
            recomputed: listed(recomputed),
        }];
    };
    published_figures
        .keys()
        .chain(recomputed_figures.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|figure| {
            let published = published_figures.get(figure);
            let recomputed = recomputed_figures.get(figure);
            (published != recomputed).then(|| Difference {
                token,
                figure: figure.clone(),
                published: published.map_or(ABSENT, String::as_str).to_owned(),
                recomputed: recomputed.map_or(ABSENT, String::as_str).to_owned(),
            })
        })
        .collect()
}

fn listed(figures: Option<&Figures>) -> String {
    figures.map_or(ABSENT, |_| "listed").to_owned()
}

/// Each token's figures by name. A repeated token or entry, which the encoder never writes, shows
/// as a duplicate rather than letting the last copy hide the first, which wallets read.
fn token_figures(snapshot: &AmountStatisticsSnapshot) -> BTreeMap<Address, Figures> {
    let mut tokens = BTreeMap::<Address, Figures>::new();
    for token in &snapshot.tokens {
        let figures = tokens.entry(token.token).or_default();
        for (figure, value) in figure_values(token) {
            if figures.insert(figure.clone(), value).is_some() {
                figures.insert(figure, DUPLICATE.to_owned());
            }
        }
    }
    tokens
}

/// Every figure of one token entry, as name and value.
fn figure_values(token: &TokenAmountStatistics) -> Vec<(String, String)> {
    let counts = [
        ("pool_balance", token.pool_balance.to_string()),
        ("shields_last_24h", token.shields_last_24h.to_string()),
        ("shields_last_30d", token.shields_last_30d.to_string()),
        ("unshields_last_24h", token.unshields_last_24h.to_string()),
        ("unshields_last_30d", token.unshields_last_30d.to_string()),
    ]
    .map(|(figure, value)| (figure.to_owned(), value));
    let shield_amounts = token.repeated_shield_amounts.iter().flat_map(|amount| {
        amount.trees.iter().flat_map(move |tree| {
            let prefix = format!(
                "repeated_shield_amount[{}].tree[{}]",
                amount.value, tree.tree
            );
            [
                (format!("{prefix}.all_time"), tree.all_time.to_string()),
                (format!("{prefix}.last_30d"), tree.last_30d.to_string()),
            ]
        })
    });
    let buckets = token.shield_value_buckets.iter().flat_map(|tree| {
        tree.buckets.iter().map(move |bucket| {
            (
                format!(
                    "shield_value_buckets.tree[{}].bit_length[{}]",
                    tree.tree, bucket.bit_length
                ),
                bucket.count.to_string(),
            )
        })
    });
    let unshield_amounts = token.repeated_unshield_amounts.iter().map(|amount| {
        (
            format!("repeated_unshield_amount[{}].last_30d", amount.value),
            amount.last_30d.to_string(),
        )
    });
    counts
        .into_iter()
        .chain(shield_amounts)
        .chain(buckets)
        .chain(unshield_amounts)
        .collect()
}

fn load_config(path: &PathBuf) -> Result<Config> {
    let data = fs::read_to_string(path).wrap_err("read config file")?;
    serde_yaml::from_str(&data).wrap_err("parse yaml config")
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{FixedBytes, U256};
    use railgun_indexer_core::amount_statistics::{ShieldRecord, UnshieldRecord};
    use railgun_indexer_core::manifest::AmountStatisticsCoveredBlock;

    use super::*;

    const USDC: Address = Address::repeat_byte(0x11);
    const T: u64 = 1_800_000_000;

    fn snapshot() -> AmountStatisticsSnapshot {
        let shield = ShieldRecord {
            token: USDC,
            value: U256::from(50_u64),
            tree: 0,
            timestamp: T,
        };
        let unshield = UnshieldRecord {
            token: USDC,
            value: U256::from(40_u64),
            timestamp: T,
        };
        aggregate_amount_statistics(
            ChainScope {
                chain_type: ChainType::Evm,
                chain_id: 1,
                railgun_contract: Address::repeat_byte(0xbb),
            },
            AmountStatisticsCoveredBlock {
                number: 100,
                hash: FixedBytes::repeat_byte(0xaa),
                timestamp: T,
            },
            &[shield.clone(), shield],
            &[unshield.clone(), unshield],
        )
    }

    #[test]
    fn differing_figure_names_token_and_values_and_fails() {
        let mut published = snapshot();
        published.tokens[0].repeated_shield_amounts[0].trees[0].last_30d = 1;

        let differences = compare_snapshots(&published, &snapshot());

        assert_eq!(
            differences,
            vec![Difference {
                token: USDC,
                figure: "repeated_shield_amount[50].tree[0].last_30d".to_owned(),
                published: "1".to_owned(),
                recomputed: "2".to_owned(),
            }]
        );
        assert!(report(&differences).is_err());
        assert!(report(&[]).is_ok());
    }
}
