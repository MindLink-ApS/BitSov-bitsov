#!/usr/bin/env bash
# Exercise compiler-cache configuration without network access or Rust builds.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/available" "$WORK/missing"
cat > "$WORK/available/sccache" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[ "$#" -eq 1 ] && [ "$1" = --show-stats ] || exit 64
printf '%s\n' "${SCCACHE_GHA_ENABLED:-}" > "$SCCACHE_PROBE_LOG"
exit "$SCCACHE_PROBE_STATUS"
SH
chmod +x "$WORK/available/sccache"

checks=0
run_case() {
  local name=$1 outcome=$2 executable=$3 probe_status=$4 expected=$5
  local inherited_cache=${6:-true}
  local env_file="$WORK/env" probe_log="$WORK/probe"
  : > "$env_file"
  rm -f "$probe_log"
  PATH="$WORK/$executable:/usr/bin:/bin" \
    RUSTC_WRAPPER=missing-wrapper SCCACHE_GHA_ENABLED="$inherited_cache" \
    SCCACHE_PROBE_STATUS="$probe_status" SCCACHE_PROBE_LOG="$probe_log" \
    GITHUB_ENV="$env_file" /bin/bash "$HERE/configure-sccache.sh" "$outcome"
  (
    # Apply the persisted environment as the next job step would.
    RUSTC_WRAPPER=missing-wrapper
    SCCACHE_GHA_ENABLED=true
    . "$env_file"
    [ "$RUSTC_WRAPPER" = "$expected" ] || exit 1
    if [ -n "$expected" ]; then
      [ "$SCCACHE_GHA_ENABLED" = true ] || exit 1
      [ "$(cat "$probe_log")" = true ] || exit 1
    else
      [ "$SCCACHE_GHA_ENABLED" = false ]
    fi
  ) || { echo "Compiler cache case failed: $name" >&2; exit 1; }
  if [ "$outcome" != success ]; then
    [ ! -e "$probe_log" ] || { echo "Probed cache after unsuccessful setup" >&2; exit 1; }
  fi
  checks=$((checks + 1))
  echo "ok $name"
}

run_case "failed setup without a binary clears an inherited wrapper" failure missing 0 ''
run_case "failed setup with a binary still uses rustc" failure available 0 ''
run_case "successful setup without a binary uses rustc" success missing 0 ''
run_case "failed health probe uses rustc" success available 1 ''
run_case "healthy cache remains enabled" success available 0 sccache false
run_case "cancelled setup uses rustc" cancelled available 0 ''
run_case "skipped setup uses rustc" skipped available 0 ''
run_case "missing setup outcome uses rustc" '' available 0 ''

echo "compiler cache: $checks checks completed"
