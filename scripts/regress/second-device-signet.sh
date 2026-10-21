#!/usr/bin/env bash
# T18 hardware acceptance runner. Never captures QR URIs or authentication secrets.
# Usage: bash scripts/regress/second-device-signet.sh /path/to/konsensus /path/to/konsensus.toml
set -euo pipefail
if [[ $# != 2 || ! -t 0 ]]; then
  echo 'Usage (interactive terminal): second-device-signet.sh NODE_BINARY CONFIG' >&2
  exit 2
fi
node_binary=$1
node_config=$2
check() {
  local answer
  printf '%s\nType PASS only after observing this: ' "$1"
  read -r answer
  [[ "$answer" == PASS ]] || { echo 'T18 incomplete; no PASS recorded.'; exit 1; }
}
"$node_binary" --version
check 'Verify this is an opt-in SIGNET box. Record node/app commits and OS versions in your acceptance record.'
check 'On the enrolled Mac open Add a device. Scan its QR on the iPhone. No claim code is requested; words appear only after approval_message is non-null and match on both devices.'
check 'Approve with Touch ID / Face ID. The iPhone reports registered and can read/receive.'
"$node_binary" device list --config "$node_config"
check 'Verify the iPhone provenance is second_device:<Mac key id>. Open an iPhone per-contact envelope and verify it is usable.'
printf 'Public key id of the TEST iPhone to revoke: '
read -r device_key
[[ "$device_key" =~ ^[0-9a-f]+$ ]] || { echo 'Invalid public key id'; exit 2; }
"$node_binary" device revoke --key "$device_key" --with-pairing --config "$node_config"
check 'Verify the old iPhone token is refused and its next envelope request fails.'
check 'Repeat enrollment using pair-ticket --second-device --qr with Add a device open on the Mac; verify the console reminder and matching-word approval flow.'
echo 'T18 operator-observed PASS. Save this result with node/app commits, OS versions and timestamp; do not save QR codes or tokens.'
