#!/usr/bin/env bash
# Shared CI/signing-machine recipe. Run from a clean checkout of the release tag.
set -euo pipefail
CHECK_ONLY=false
if [ "${1:-}" = --check-toolchain ]; then CHECK_ONLY=true; shift; fi
[ $# -eq 1 ] || { echo "usage: $0 [--check-toolchain] <target-triple>" >&2; exit 1; }
TARGET=$1
ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"
TOOLCHAIN=$(cat scripts/release-toolchain)
[[ $TOOLCHAIN =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'release toolchain must be an exact version' >&2; exit 1; }
export LC_ALL=C TZ=UTC
case "$TARGET" in
  *-apple-darwin)
    [ -f scripts/release-macos-toolchain.sh ] || { echo 'macOS toolchain preflight: missing pin; prepare a new release' >&2; exit 1; }
    # shellcheck source=scripts/release-macos-toolchain.sh
    source scripts/release-macos-toolchain.sh
    macos_toolchain_prepare
    macos_toolchain_evidence
    ;;
esac
"$CHECK_ONLY" && exit 0
SOURCE_DATE_EPOCH=$(git show -s --format=%ct HEAD)
export SOURCE_DATE_EPOCH
export CARGO_TARGET_DIR="$ROOT/target" CARGO_INCREMENTAL=0
export CARGO_PROFILE_RELEASE_STRIP=symbols CARGO_PROFILE_RELEASE_DEBUG=0
# Do not inherit local Rust flags/wrappers or select a different compiler.
unset RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTC RUSTDOC
CARGO_HOME=${CARGO_HOME:-$HOME/.cargo}
RUSTUP_HOME=${RUSTUP_HOME:-$HOME/.rustup}
export CARGO_HOME RUSTUP_HOME
# Unit separators preserve paths containing spaces (unlike plain RUSTFLAGS).
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$ROOT=/bitsov"$'\x1f'"--remap-path-prefix=$CARGO_HOME=/cargo"$'\x1f'"--remap-path-prefix=$RUSTUP_HOME=/rustup"
case "$TARGET" in
  *-windows-msvc) ;; # Native compiler/SDK must match; see RELEASE_POLICY.md.
  *)
    export CFLAGS="-ffile-prefix-map=$ROOT=/bitsov -ffile-prefix-map=$CARGO_HOME=/cargo"
    export CXXFLAGS="$CFLAGS"
    ;;
esac
case "$TARGET" in
  *-apple-darwin)
    # ld64 derives LC_UUID from the link output, including the debug map whose
    # N_OSO entries hold absolute checkout and rustup paths. Omit that map
    # (-S; the shipped binary is symbol-stripped anyway) so the UUID, and with
    # it the linker signature, no longer depends on where the build ran.
    CARGO_ENCODED_RUSTFLAGS+=$'\x1f'"-Clink-arg=-Wl,-S"
    ;;
esac
if [ "$TARGET" = aarch64-unknown-linux-gnu ]; then
  export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
fi
printf 'release build: toolchain=%s target=%s commit=%s SOURCE_DATE_EPOCH=%s\n' \
  "$TOOLCHAIN" "$TARGET" "$(git rev-parse HEAD)" "$SOURCE_DATE_EPOCH"
case "$TARGET" in
  *-apple-darwin)
    mkdir -p "$CARGO_TARGET_DIR/$TARGET"
    macos_toolchain_evidence > "$CARGO_TARGET_DIR/$TARGET/release-toolchain.txt"
    ;;
esac
rustup run "$TOOLCHAIN" cargo build --locked --release -p konsensus-node --target "$TARGET"
