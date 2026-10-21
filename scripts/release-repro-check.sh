#!/usr/bin/env bash
# Opt-in reproducibility check: build one target twice with the shared release
# recipe, from two detached worktrees at different paths, and compare hashes.
# Slow (two full release builds); for operators and release reviewers, not CI.
set -euo pipefail
[ $# -eq 1 ] || [ $# -eq 2 ] || { echo "usage: $0 <target-triple> [commit]" >&2; exit 1; }
TARGET=$1
ROOT=$(git rev-parse --show-toplevel)
COMMIT=$(git -C "$ROOT" rev-parse --verify "${2:-HEAD}^{commit}")
WORK=$(mktemp -d)
cleanup() {
  git -C "$ROOT" worktree remove --force "$WORK/a" >/dev/null 2>&1 || true
  git -C "$ROOT" worktree remove --force "$WORK/b/nested/path" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
mkdir -p "$WORK/b/nested"
git -C "$ROOT" -c core.hooksPath=/dev/null worktree add --detach "$WORK/a" "$COMMIT" >/dev/null
git -C "$ROOT" -c core.hooksPath=/dev/null worktree add --detach "$WORK/b/nested/path" "$COMMIT" >/dev/null
bin=konsensus
case "$TARGET" in *-windows-msvc) bin=konsensus.exe ;; esac
hashes=()
for dir in "$WORK/a" "$WORK/b/nested/path"; do
  (cd "$dir" && bash scripts/release-build.sh "$TARGET") >&2
  hashes+=("$(shasum -a 256 "$dir/target/$TARGET/release/$bin" | cut -d' ' -f1)")
done
printf 'repro %s %s: %s %s\n' "$TARGET" "$COMMIT" "${hashes[0]}" "${hashes[1]}"
[ "${hashes[0]}" = "${hashes[1]}" ] || { echo "release-repro-check: MISMATCH across build paths" >&2; exit 1; }
echo "release-repro-check: MATCH"
