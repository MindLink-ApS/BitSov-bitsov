#!/usr/bin/env bash
# test-rust-toolchain.sh — regression tests for scripts/rust-toolchain-channel.sh
# and for the rule that every workflow installs the pinned toolchain.
#
# Cases:
#   pin        the real rust-toolchain.toml yields an exact x.y.z version
#   reject     channel = "stable"; no channel line; two channel lines;
#              missing file
#   check      --check passes when `rustc --version` matches the pin and
#              fails when it does not (stub rustc on PATH, no network)
#   workflows  no dtolnay/rust-toolchain step uses a channel name
#              (stable/beta/nightly); every step that reads the pin passes it
#              on, and nothing else is passed as `toolchain:`
#
# Usage: scripts/test-rust-toolchain.sh      (exit 0 iff every case passes)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SCRIPT="$HERE/rust-toolchain-channel.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass=0
ok() { pass=$((pass + 1)); echo "ok   $*"; }

# pin: the committed file is an exact version and the script prints it.
channel=$(bash "$SCRIPT")
[[ $channel =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "pin is not an exact version: '$channel'"
grep -qF "channel = \"$channel\"" "$ROOT/rust-toolchain.toml" || fail "printed '$channel' is not the committed channel"
ok "pin prints $channel"

# reject: each malformed pin exits non-zero and prints nothing on stdout.
expect_reject() {
  local name=$1 file=$2 out rc=0
  out=$(RUST_TOOLCHAIN_FILE="$file" bash "$SCRIPT" 2>/dev/null) || rc=$?
  [ "$rc" -ne 0 ] || fail "$name: accepted"
  [ -z "$out" ] || fail "$name: printed '$out' despite failing"
  ok "reject $name"
}
printf '[toolchain]\nchannel = "stable"\n' > "$WORK/stable.toml"
expect_reject "channel name" "$WORK/stable.toml"
printf '[toolchain]\ncomponents = ["clippy"]\n' > "$WORK/none.toml"
expect_reject "missing channel" "$WORK/none.toml"
printf '[toolchain]\nchannel = "1.99.1"\nchannel = "1.99.0"\n' > "$WORK/two.toml"
expect_reject "duplicate channel" "$WORK/two.toml"
expect_reject "missing file" "$WORK/absent.toml"
# A commented-out channel line must not count as the pin.
printf '# channel = "1.99.1"\n[toolchain]\nchannel = "1.98.0"\n' > "$WORK/comment.toml"
[ "$(RUST_TOOLCHAIN_FILE="$WORK/comment.toml" bash "$SCRIPT")" = 1.98.0 ] || fail "commented channel line was counted"
ok "comment lines are ignored"

# check: --check compares the pin against the active rustc.
mkdir -p "$WORK/bin"
printf '#!/usr/bin/env bash\nprintf "rustc %%s (stub)\\n" "$STUB_RUSTC_VERSION"\n' > "$WORK/bin/rustc"
chmod +x "$WORK/bin/rustc"
PATH="$WORK/bin:$PATH" STUB_RUSTC_VERSION="$channel" bash "$SCRIPT" --check >/dev/null || fail "--check rejected a matching rustc"
ok "--check accepts rustc $channel"
rc=0
PATH="$WORK/bin:$PATH" STUB_RUSTC_VERSION="0.0.0" bash "$SCRIPT" --check >/dev/null 2>&1 || rc=$?
[ "$rc" -ne 0 ] || fail "--check accepted rustc 0.0.0 against pin $channel"
ok "--check rejects a different rustc"

# workflows: the pin is the only toolchain CI installs, apart from the
# release job's separate reproducible-build pin (scripts/release-toolchain).
workflows=("$ROOT"/.github/workflows/*.yml)
if grep -nE '^[[:space:]]*toolchain:[[:space:]]*(stable|beta|nightly)' "${workflows[@]}"; then
  fail "a workflow installs a floating channel instead of the pin"
fi
ok "no workflow installs stable/beta/nightly"
# Sum of per-file match counts; `grep -c` exits 1 when nothing matches, which
# must read as 0 rather than abort the script under pipefail.
count_in_workflows() {
  { grep -c -F -- "$1" "${workflows[@]}" || true; } | awk -F: '{s+=$NF} END {print s+0}'
}
installs=$(count_in_workflows 'uses: dtolnay/rust-toolchain@')
pinned=$(count_in_workflows 'toolchain: ${{ steps.rust-toolchain.outputs.channel }}')
reads=$(count_in_workflows 'channel=$(bash scripts/rust-toolchain-channel.sh)')
release=$(count_in_workflows 'toolchain: ${{ steps.release-toolchain.outputs.version }}')
[ "$pinned" -eq "$reads" ] || fail "$reads steps read the pin but $pinned steps install it"
[ "$installs" -eq $((pinned + release)) ] || fail "$installs toolchain installs, but only $pinned pinned + $release release"
[ "$pinned" -ge 1 ] || fail "no workflow installs the pin"
ok "all $installs toolchain installs are pinned ($pinned CI pin, $release release pin)"

echo "rust-toolchain: $pass checks passed"
