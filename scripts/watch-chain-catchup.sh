#!/usr/bin/env bash
set -euo pipefail

# Prefilled safe heads from public RPC heads minus SAFE_CONFIRMATIONS.
# Update these before a watch session if you want a fresher target.
SAFE_CONFIRMATIONS=12
SAFE_HEAD_ETHEREUM=25323905
SAFE_HEAD_BSC=104401424
SAFE_HEAD_POLYGON=88555809
SAFE_HEAD_ARBITRUM=473796571

INTERVAL="${INTERVAL:-30}"
PSQL="${PSQL:-psql}"
POSTGRES_URL="${POSTGRES_URL:-${DATABASE_URL:-}}"

if [[ -z "$POSTGRES_URL" ]]; then
    printf 'error: set POSTGRES_URL or DATABASE_URL\n' >&2
    exit 1
fi

state_file="${TMPDIR:-/tmp}/railgun-indexer-catchup-watch.$$"
next_state_file="$state_file.next"
trap 'rm -f "$state_file" "$next_state_file"' EXIT

query_progress() {
    "$PSQL" "$POSTGRES_URL" \
        -X \
        -q \
        -t \
        -A \
        -F $'\t' \
        -v ON_ERROR_STOP=1 \
        -v safe_head_ethereum="$SAFE_HEAD_ETHEREUM" \
        -v safe_head_bsc="$SAFE_HEAD_BSC" \
        -v safe_head_polygon="$SAFE_HEAD_POLYGON" \
        -v safe_head_arbitrum="$SAFE_HEAD_ARBITRUM" \
        -c "
WITH safe_heads(chain_id, chain_name, safe_head) AS (
  VALUES
    (1, 'ethereum', :safe_head_ethereum::bigint),
    (56, 'bsc', :safe_head_bsc::bigint),
    (137, 'polygon', :safe_head_polygon::bigint),
    (42161, 'arbitrum', :safe_head_arbitrum::bigint)
), progress AS (
  SELECT
    chain_id,
    MIN(indexed_through_block) AS indexed_through_block,
    MAX(indexed_through_block) - MIN(indexed_through_block) AS progress_span
  FROM chain_indexing_progress
  WHERE chain_type = 0
    AND chain_id IN (SELECT chain_id FROM safe_heads)
  GROUP BY chain_id
)
SELECT
  s.chain_id,
  s.chain_name,
  COALESCE(p.indexed_through_block, 0) AS indexed_through_block,
  s.safe_head,
  GREATEST(s.safe_head - COALESCE(p.indexed_through_block, 0), 0) AS blocks_left,
  COALESCE(p.progress_span, 0) AS progress_span
FROM safe_heads s
LEFT JOIN progress p ON p.chain_id = s.chain_id
ORDER BY s.chain_id;
"
}

print_sample() {
    local now rows
    now="$(date +%s)"
    rows="$(query_progress)"

    printf '\n%s  interval=%ss  safe_confirmations=%s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "$INTERVAL" "$SAFE_CONFIRMATIONS"
    printf '%-8s %-10s %16s %16s %12s %12s %14s\n' \
        'chain_id' 'chain' 'indexed' 'safe_head' 'blocks_left' 'blocks/s' 'eta'

    printf '%s\n' "$rows" | awk -F '\t' -v now="$now" -v state_file="$state_file" '
function format_eta(seconds, days, hours, minutes) {
    seconds = int(seconds + 0.5)
    days = int(seconds / 86400)
    seconds %= 86400
    hours = int(seconds / 3600)
    seconds %= 3600
    minutes = int(seconds / 60)
    seconds %= 60

    if (days > 0) {
        return sprintf("%dd %02dh", days, hours)
    }
    if (hours > 0) {
        return sprintf("%dh %02dm", hours, minutes)
    }
    if (minutes > 0) {
        return sprintf("%dm %02ds", minutes, seconds)
    }
    return sprintf("%ds", seconds)
}

BEGIN {
    while ((getline line < state_file) > 0) {
        split(line, parts, "\t")
        previous_indexed[parts[1]] = parts[2]
        previous_time[parts[1]] = parts[3]
    }
    close(state_file)
}

NF >= 6 {
    chain_id = $1
    chain_name = $2
    indexed = $3 + 0
    safe_head = $4 + 0
    blocks_left = $5 + 0
    progress_span = $6 + 0

    rate = "sampling"
    eta = blocks_left == 0 ? "caught up" : "sampling"
    if (chain_id in previous_indexed && now > previous_time[chain_id]) {
        delta = indexed - previous_indexed[chain_id]
        elapsed = now - previous_time[chain_id]
        if (delta < 0) {
            rate = "reset"
            eta = "unknown"
        } else {
            blocks_per_second = delta / elapsed
            rate = sprintf("%.2f", blocks_per_second)
            if (blocks_left == 0) {
                eta = "caught up"
            } else if (blocks_per_second > 0) {
                eta = format_eta(blocks_left / blocks_per_second)
            } else {
                eta = "unknown"
            }
        }
    }

    note = progress_span == 0 ? "" : sprintf(" span=%s", progress_span)
    printf "%-8s %-10s %16.0f %16.0f %12.0f %12s %14s%s\n", \
        chain_id, chain_name, indexed, safe_head, blocks_left, rate, eta, note
    print chain_id "\t" indexed "\t" now >> state_file ".next"
}
END {
    close(state_file ".next")
}
'

    mv "$next_state_file" "$state_file"
}

while true; do
    print_sample
    sleep "$INTERVAL"
done
