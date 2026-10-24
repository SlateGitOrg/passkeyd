#!/usr/bin/env bash
# Measure statement coverage of the core packages across the whole test
# suite (cross-package tests count) and fail below the threshold.
#
# Usage: scripts/coverage.sh [min-percent]   (default 80)
set -euo pipefail
min="${1:-80}"
core="./cbor/...,./cose/...,./webauthn/...,./challenge/...,./credstore/...,./server/...,./virtualauthn/..."
profile="$(mktemp -t passkeyd-cover.XXXXXX)"
trap 'rm -f "$profile"' EXIT

go test -count=1 -coverpkg="$core" -coverprofile="$profile" ./... >/dev/null
go tool cover -func="$profile" | awk '
  /^total:/ { next }
  {
    split($1, parts, "/"); pkg = parts[4];   # github.com/archit2501/passkeyd/<pkg>/file.go:line:
    sub(/%/, "", $NF); n[pkg]++; s[pkg] += $NF
  }
  END { for (p in n) printf "  %-14s %5.1f%% (mean of %d funcs)\n", p, s[p] / n[p], n[p] }' | sort
total="$(go tool cover -func="$profile" | awk '/^total:/ { sub(/%/, "", $3); print $3 }')"
echo "core statement coverage: ${total}% (threshold ${min}%)"
awk -v t="$total" -v m="$min" 'BEGIN { exit (t + 0 >= m + 0) ? 0 : 1 }' || {
  echo "coverage ${total}% is below ${min}%" >&2
  exit 1
}
