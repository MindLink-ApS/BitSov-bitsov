#!/usr/bin/env bash
# rust-toolchain-channel.sh — print the exact Rust version pinned in
# rust-toolchain.toml, so CI installs the same toolchain `cargo` selects
# locally through rustup. Fails closed when the pin is missing, duplicated,
# or not an exact `x.y.z` version (a channel name such as `stable` would let
# CI and local builds drift apart again).
#
# Usage: scripts/rust-toolchain-channel.sh            # prints e.g. 1.99.1
#        scripts/rust-toolchain-channel.sh --check    # also requires the
#                                                     # active `rustc` to match
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIN_FILE="${RUST_TOOLCHAIN_FILE:-$ROOT/rust-toolchain.toml}"

[ -f "$PIN_FILE" ] || { echo "rust-toolchain: missing $PIN_FILE" >&2; exit 1; }

# One `channel = "..."` line, in the [toolchain] table, ignoring comments.
channel_lines=$(grep -E '^[[:space:]]*channel[[:space:]]*=' "$PIN_FILE" || true)
count=$(printf '%s' "$channel_lines" | grep -c . || true)
[ "$count" -eq 1 ] || { echo "rust-toolchain: expected exactly one channel line, found $count" >&2; exit 1; }
channel=$(printf '%s\n' "$channel_lines" | sed -E 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]*)".*$/\1/')
[[ $channel =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "rust-toolchain: channel must be an exact x.y.z version, got '$channel'" >&2; exit 1; }

if [ "${1:-}" = --check ]; then
  active=$(rustc --version | awk '{print $2}')
  [ "$active" = "$channel" ] || { echo "rust-toolchain: active rustc is $active, pin is $channel" >&2; exit 1; }
fi

printf '%s\n' "$channel"
