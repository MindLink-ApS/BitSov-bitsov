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
#                     must be http://127.0.0.1:PORT or http://[::1]:PORT
#                     with optional trailing /api/v1 (and optional trailing /)
#   KONSENSUS_BIN     default: konsensus on PATH
#
# On success sets OWNER_TOKEN in the current shell (plain variable, not exported).
# Never writes the token or mnemonic to disk; never prints the mnemonic.
# Token is not echoed by default; set OWNER_TOKEN_PRINT=1 to print it once.
#
# Safe to source: does not enable errexit/nounset/pipefail in the caller, and
# restores the caller's xtrace state. Error paths use return, never exit the
# interactive shell via set -e.

# Refuse exec — token must land in the caller's shell.
if [[ "${BASH_SOURCE[0]-}" == "${0}" ]]; then
  echo "owner-token: source this script (do not exec): source docs/ops/owner-token.sh" >&2
  exit 1
fi

_bitsov_owner_token_mint() {
  # Disable xtrace for the mint so OWNER_TOKEN never appears in traces.
  # Restore the caller's xtrace bit on every exit path.
  local __xtrace_was_on=0
  case "$-" in
    *x*) __xtrace_was_on=1 ;;
  esac
  { set +x; } 2>/dev/null

  _bitsov_owner_token_restore_xtrace() {
    if [[ "${__xtrace_was_on}" -eq 1 ]]; then
      set -x
    fi
  }

  local base api_root challenge_json challenge signature token_json bin
  local -a sign_args

  base="${BITSOV_API_BASE:-http://127.0.0.1:3141}"
  # Strict loopback URL: only 127.0.0.1 / [::1] with a port; optional /api/v1.
  # Rejects userinfo (@), other hosts, query/fragment, and path junk.
  case "$base" in
    *'@'*|*'?'*|*'#'*)
      echo "owner-token: BITSOV_API_BASE must be loopback without userinfo/query/fragment (got $base)" >&2
      _bitsov_owner_token_restore_xtrace
      return 1
      ;;
  esac
  if [[ ! "$base" =~ ^http://127\.0\.0\.1:[0-9]+(/api/v1)?/?$ ]] \
    && [[ ! "$base" =~ ^http://\[::1\]:[0-9]+(/api/v1)?/?$ ]]; then
    echo "owner-token: BITSOV_API_BASE must be http://127.0.0.1:PORT or http://[::1]:PORT[/api/v1] (got $base)" >&2
    _bitsov_owner_token_restore_xtrace
    return 1
  fi

  # Normalize API root to .../api/v1 (no trailing slash).
  base="${base%/}"
  case "$base" in
    */api/v1) api_root="$base" ;;
    *) api_root="$base/api/v1" ;;
  esac

  sign_args=()
  if [[ -n "${KONSENSUS_MNEMONIC:-}" ]]; then
    sign_args+=(--mnemonic "$KONSENSUS_MNEMONIC")
  elif [[ -n "${KONSENSUS_CONFIG:-}" ]]; then
    sign_args+=(--config "$KONSENSUS_CONFIG")
  else
    echo "owner-token: set KONSENSUS_CONFIG or KONSENSUS_MNEMONIC" >&2
    _bitsov_owner_token_restore_xtrace
    return 1
  fi

  challenge_json="$(curl -fsS "$api_root/auth/challenge" 2>/dev/null)" || {
    echo "owner-token: failed to fetch $api_root/auth/challenge" >&2
    _bitsov_owner_token_restore_xtrace
    return 1
  }
  challenge="$(printf '%s' "$challenge_json" | sed -n 's/.*"challenge"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  if [[ -z "$challenge" || ! "$challenge" =~ ^bitsov-auth-v1:[0-9a-f]{64}:[0-9]+$ ]]; then
    echo "owner-token: unexpected challenge response: $challenge_json" >&2
    _bitsov_owner_token_restore_xtrace
    return 1
  fi

  bin="${KONSENSUS_BIN:-konsensus}"
  signature="$("$bin" sign-challenge --challenge "$challenge" "${sign_args[@]}" 2>/dev/null)" || {
    echo "owner-token: sign-challenge failed" >&2
    _bitsov_owner_token_restore_xtrace
    return 1
  }
  signature="$(printf '%s' "$signature" | tr -d '[:space:]')"
  if [[ -z "$signature" ]]; then
    echo "owner-token: empty signature from sign-challenge" >&2
    _bitsov_owner_token_restore_xtrace
    return 1
  fi

  token_json="$(
    curl -fsS -X POST "$api_root/auth/token" \
      -H 'content-type: application/json' \
      -d "{\"challenge\":\"$challenge\",\"signature\":\"$signature\"}" 2>/dev/null
  )" || {
    echo "owner-token: token exchange request failed" >&2
    _bitsov_owner_token_restore_xtrace
    return 1
  }
  # Assign into caller's scope (not local, not exported).
  OWNER_TOKEN="$(printf '%s' "$token_json" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  if [[ -z "$OWNER_TOKEN" ]]; then
    echo "owner-token: token exchange failed: $token_json" >&2
    _bitsov_owner_token_restore_xtrace
    return 1
  fi

  echo "owner-token: OWNER_TOKEN set in this shell (not written to disk, not exported)" >&2
  if [[ "${OWNER_TOKEN_PRINT:-}" == "1" ]]; then
    printf '%s\n' "$OWNER_TOKEN"
  fi

  _bitsov_owner_token_restore_xtrace
  return 0
}

_bitsov_owner_token_mint
_bitsov_owner_token_rc=$?
unset -f _bitsov_owner_token_mint _bitsov_owner_token_restore_xtrace 2>/dev/null || true
return "$_bitsov_owner_token_rc" 2>/dev/null || exit "$_bitsov_owner_token_rc"
