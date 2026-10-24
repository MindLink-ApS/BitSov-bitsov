#!/usr/bin/env bash
# Seed-only channel recovery on local regtest (bitcoind only). No downloads.
set -euo pipefail
cd "$(dirname "$0")/../.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/bitsov-target-recover-regtest}"
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
export BITCOIND_SKIP_DOWNLOAD=1

find_binary() {
  local name="$1" candidate
  if candidate="$(command -v "$name" 2>/dev/null)"; then
    printf '%s\n' "$candidate"
    return
  fi
  for candidate in /tmp/bitsov-target-*/debug/build/*/out/bitcoin/bitcoin-*/bin/"$name"; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  echo "Missing $name: set BITCOIND_EXE to a local executable." >&2
  return 1
}

export BITCOIND_EXE="${BITCOIND_EXE:-$(find_binary bitcoind || true)}"
export REGTEST_BUILD_ONLY=0
if [[ ! -x "$BITCOIND_EXE" ]]; then
  if [[ "${REGTEST_ALLOW_MISSING:-0}" != 1 ]]; then
    exit 1
  fi
  echo "Local bitcoind unavailable; compiling recover_regtest before reporting SKIP."
  export REGTEST_BUILD_ONLY=1
fi

echo "Bitcoin Core: $BITCOIND_EXE"
command=(cargo test --offline --locked -p konsensus-lightning --test recover_regtest)
if [[ "$REGTEST_BUILD_ONLY" == 1 ]]; then
  command+=(--no-run)
else
  command+=(
    recover_force_closed_channel_from_seed_after_data_loss
    -- --ignored --nocapture --test-threads=1
  )
fi
"${command[@]}"
if [[ "$REGTEST_BUILD_ONLY" == 1 ]]; then
  echo "SKIP recover regtest: compiled; BITCOIND_EXE unavailable. No daemons started."
  exit 77
fi
echo 'RECOVER REGTEST PASS; seed-only force-close recovery'
