use super::*;
use alloy::primitives::Uint;
use broadcaster_core::contracts::railgun::TokenData;

const T: u64 = 1_800_000_000;
const DAY: u64 = 86_400;
const USDC: Address = Address::repeat_byte(0x11);
const WETH: Address = Address::repeat_byte(0x22);
const DAI: Address = Address::repeat_byte(0x33);

#[test]
fn non_erc20_preimages_are_not_counted() {
    assert_eq!(decoded_note(&preimage(0, 5)), (USDC, U256::from(5_u64)));
    for token_type in [1, 2] {
        assert_eq!(
            erc20_note(&preimage(token_type, 5)).expect("preimage decodes"),
            None,
            "ERC-721 and ERC-1155 notes are left out"
        );
    }
}

#[test]
fn amounts_repeat_only_when_two_or_more_shields_share_them() {
    let mut shields = vec![shield(USDC, 100, 0, T); 152];
    shields.extend(vec![shield(USDC, 100, 4, T); 35]);
    shields.extend([shield(USDC, 200, 0, T), shield(USDC, 200, 1, T)]);
    shields.push(shield(USDC, 300, 0, T));

    let stats = snapshot(&shields, &[]);

    assert_eq!(
        token_stats(&stats, USDC).repeated_shield_amounts,
        vec![
            RepeatedShieldAmount {
                value: U256::from(100_u64),
                trees: vec![tree_count(0, 152, 152), tree_count(4, 35, 35)],
            },
            RepeatedShieldAmount {
                value: U256::from(200_u64),
                trees: vec![tree_count(0, 1, 1), tree_count(1, 1, 1)],
            },
        ]
    );
}

#[test]
fn windows_end_at_the_covered_block_timestamp() {
    let edges = [T - DAY, T - DAY + 1, T - 30 * DAY, T - 30 * DAY + 1];
    let shields = edges.map(|timestamp| shield(USDC, 7, 0, timestamp));
    let unshields = edges.map(|timestamp| unshield(USDC, 9, timestamp));

    let stats = snapshot(&shields, &unshields);

    let usdc = token_stats(&stats, USDC);
    assert_eq!(usdc.shields_last_24h, 1);
    assert_eq!(usdc.shields_last_30d, 3);
    assert_eq!(usdc.unshields_last_24h, 1);
    assert_eq!(usdc.unshields_last_30d, 3);
    assert_eq!(
        usdc.repeated_shield_amounts[0].trees,
        vec![tree_count(0, 4, 3)]
    );
    assert_eq!(usdc.repeated_unshield_amounts[0].last_30d, 3);
}

#[test]
fn pool_balance_is_shield_values_minus_unshield_values() {
    let shields = [
        shield(USDC, 3_000, 0, T),
        shield(USDC, 2_000, 0, T),
        shield(WETH, 10, 0, T),
    ];
    let unshields = [
        unshield(USDC, 1_000, T),
        unshield(USDC, 200, T),
        unshield(WETH, 15, T),
        unshield(DAI, 40, T),
    ];

    let stats = snapshot(&shields, &unshields);

    assert_eq!(
        token_stats(&stats, USDC).pool_balance,
        U256::from(3_800_u64)
    );
    assert_eq!(token_stats(&stats, WETH).pool_balance, U256::ZERO);
    assert!(
        stats.token(DAI).is_none(),
        "a token without shields is left out"
    );
}

#[test]
fn token_without_recent_activity_keeps_zero_counts() {
    let old = T - 31 * DAY;

    let stats = snapshot(&[shield(USDC, 80, 0, old)], &[unshield(USDC, 30, old)]);

    let usdc = token_stats(&stats, USDC);
    assert_eq!(usdc.pool_balance, U256::from(50_u64));
    assert_eq!(
        (
            usdc.shields_last_24h,
            usdc.shields_last_30d,
            usdc.unshields_last_24h,
            usdc.unshields_last_30d,
        ),
        (0, 0, 0, 0)
    );
}

#[test]
fn every_shield_falls_in_one_bucket_of_its_tree() {
    let mut shields = (0..1_431_u64)
        .map(|index| shield(USDC, 1 + index * 7_919, 0, T))
        .collect::<Vec<_>>();
    shields.push(shield(USDC, 997_500_000, 0, T));
    shields.push(shield(USDC, 997_500_000, 1, T));

    let stats = snapshot(&shields, &[]);

    let buckets = &token_stats(&stats, USDC).shield_value_buckets;
    assert_eq!(buckets.len(), 2);
    let tree_0 = &buckets[0];
    assert_eq!(tree_0.tree, 0);
    assert_eq!(
        tree_0
            .buckets
            .iter()
            .map(|bucket| bucket.count)
            .sum::<u64>(),
        1_432
    );
    assert!(tree_0.buckets.iter().all(|bucket| bucket.count > 0));
    assert_eq!(
        buckets[1],
        TreeShieldValueBuckets {
            tree: 1,
            buckets: vec![ShieldValueBucketCount {
                bit_length: 30,
                count: 1,
            }],
        }
    );
}

#[test]
fn repeated_exit_amounts_count_only_the_last_30_days() {
    let mut unshields = vec![unshield(USDC, 500, T - 60); 40];
    unshields.extend(vec![unshield(USDC, 600, T - 40 * DAY); 25]);
    unshields.push(unshield(USDC, 600, T - 60));

    let stats = snapshot(&[shield(USDC, 1, 0, T)], &unshields);

    assert_eq!(
        token_stats(&stats, USDC).repeated_unshield_amounts,
        vec![RepeatedUnshieldAmount {
            value: U256::from(500_u64),
            last_30d: 40,
        }]
    );
}

fn snapshot(shields: &[ShieldRecord], unshields: &[UnshieldRecord]) -> AmountStatisticsSnapshot {
    aggregate_amount_statistics(
        ChainScope {
            chain_type: ChainType::Evm,
            chain_id: 1,
            railgun_contract: Address::repeat_byte(0xbb),
        },
        AmountStatisticsCoveredBlock {
            number: 100,
            hash: FixedBytes::repeat_byte(0x64),
            timestamp: T,
        },
        shields,
        unshields,
    )
}

fn token_stats(snapshot: &AmountStatisticsSnapshot, token: Address) -> &TokenAmountStatistics {
    snapshot.token(token).expect("token statistics")
}

fn shield(token: Address, value: u64, tree: u32, timestamp: u64) -> ShieldRecord {
    ShieldRecord {
        token,
        value: U256::from(value),
        tree,
        timestamp,
    }
}

fn unshield(token: Address, value: u64, timestamp: u64) -> UnshieldRecord {
    UnshieldRecord {
        token,
        value: U256::from(value),
        timestamp,
    }
}

const fn tree_count(tree: u32, all_time: u64, last_30d: u64) -> TreeShieldAmountCount {
    TreeShieldAmountCount {
        tree,
        all_time,
        last_30d,
    }
}

fn preimage(token_type: u8, value: u64) -> Vec<u8> {
    CommitmentPreimage {
        npk: FixedBytes::repeat_byte(0x01),
        token: TokenData {
            tokenType: token_type,
            tokenAddress: USDC,
            tokenSubID: U256::ZERO,
        },
        value: Uint::<120, 2>::from(value),
    }
    .abi_encode()
}

fn decoded_note(encoded: &[u8]) -> (Address, U256) {
    erc20_note(encoded)
        .expect("preimage decodes")
        .expect("ERC-20 note")
}
