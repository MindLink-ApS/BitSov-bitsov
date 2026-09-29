#!/usr/bin/env bash
# Mint an owner JWT on loopback using the live /auth/challenge + CLI sign-challenge.
#
# Usage (source, do not exec — the token stays in a shell variable):
#   source docs/ops/owner-token.sh
#   # or:  . docs/ops/owner-token.sh
#
# Required env:
#   KONSENSUS_CONFIG  path to konsensus.toml (mnemonic path is read from it), OR
#   KONSENSUS_MNEMONIC path to the mnemonic file
# Optional:
#   BITSOV_API_BASE   default http://127.0.0.1:3141
#   KONSENSUS_BIN     default: konsensus on PATH
#
# On success sets OWNER_TOKEN in the current shell. Never writes the token or
# mnemonic to disk; never prints the mnemonic. Token is not echoed by default;
# set OWNER_TOKEN_PRINT=1 to print it once (still not written to a file).
#
# Loopback only: BITSOV_API_BASE must be 127.0.0.1 or localhost.

set -euo pipefail

BITSOV_API_BASE="${BITSOV_API_BASE:-http://127.0.0.1:3141}"
KONSENSUS_BIN="${KONSENSUS_BIN:-konsensus}"

case "$BITSOV_API_BASE" in
  http://127.0.0.1:*|http://127.0.0.1|http://localhost:*|http://localhost|http://[::1]:*|http://[::1])
    ;;
  *)
    echo "owner-token: BITSOV_API_BASE must be loopback (got $BITSOV_API_BASE)" >&2
    return 1 2>/dev/null || exit 1
    ;;
esac

sign_args=()
if [[ -n "${KONSENSUS_MNEMONIC:-}" ]]; then
  sign_args+=(--mnemonic "$KONSENSUS_MNEMONIC")
elif [[ -n "${KONSENSUS_CONFIG:-}" ]]; then
  sign_args+=(--config "$KONSENSUS_CONFIG")
else
  echo "owner-token: set KONSENSUS_CONFIG or KONSENSUS_MNEMONIC" >&2
  return 1 2>/dev/null || exit 1
fi

challenge_json="$(curl -fsS "$BITSOV_API_BASE/api/v1/auth/challenge")"
challenge="$(printf '%s' "$challenge_json" | sed -n 's/.*"challenge"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
if [[ -z "$challenge" || "$challenge" != bitsov-auth-v1:* ]]; then
  echo "owner-token: unexpected challenge response: $challenge_json" >&2
  return 1 2>/dev/null || exit 1
fi

signature="$("$KONSENSUS_BIN" sign-challenge --challenge "$challenge" "${sign_args[@]}")"
signature="$(printf '%s' "$signature" | tr -d '[:space:]')"
if [[ -z "$signature" ]]; then
  echo "owner-token: empty signature from sign-challenge" >&2
  return 1 2>/dev/null || exit 1
fi

token_json="$(
  curl -fsS -X POST "$BITSOV_API_BASE/api/v1/auth/token" \
    -H 'content-type: application/json' \
    -d "{\"challenge\":\"$challenge\",\"signature\":\"$signature\"}"
)"
OWNER_TOKEN="$(printf '%s' "$token_json" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
if [[ -z "$OWNER_TOKEN" ]]; then
  echo "owner-token: token exchange failed: $token_json" >&2
  return 1 2>/dev/null || exit 1
fi

export OWNER_TOKEN
echo "owner-token: OWNER_TOKEN set in this shell (not written to disk)" >&2
if [[ "${OWNER_TOKEN_PRINT:-}" == "1" ]]; then
  printf '%s\n' "$OWNER_TOKEN"
fi
