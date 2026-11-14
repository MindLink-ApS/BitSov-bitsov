#!/usr/bin/env bash
# Enable the compiler cache only after setup and a working health probe.
set -euo pipefail

if [ "${1:-failure}" = success ] && command -v sccache >/dev/null 2>&1 &&
  SCCACHE_GHA_ENABLED=true sccache --show-stats >/dev/null 2>&1; then
  {
    echo "SCCACHE_GHA_ENABLED=true"
    echo "RUSTC_WRAPPER=sccache"
  } >> "$GITHUB_ENV"
else
  unset RUSTC_WRAPPER SCCACHE_GHA_ENABLED
  # An empty wrapper also overrides any Cargo configuration in later steps.
  {
    echo "SCCACHE_GHA_ENABLED=false"
    echo "RUSTC_WRAPPER="
  } >> "$GITHUB_ENV"
  echo "sccache unavailable; Cargo will use rustc directly."
fi
