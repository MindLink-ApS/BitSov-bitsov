# Signet beta testers, phase 0 (v0.3.0-rc24)

This guide is for the invited phase 0 testers. It installs the signed
`v0.3.0-rc24` pre-release on **signet**, connects two testers' nodes over a
shared test tailnet, sends a paid message, and, when both sides are ready, makes
a paid call. A helper bot may type commands for you. **Some steps are yours
alone**, and the bot rules below say which.

Signet coins have no value. **Mainnet is not supported in this beta:** nothing
here uses it, and nothing here funds a mainnet wallet. If any output ever names a
network other than `signet`, stop and report it.

Every command below is copied from the [signet quickstart](QUICKSTART-SIGNET.md),
the [reachability guide](operations/reachability.md) or the
[M6 call runbook](ops/M6-CALL-RUNBOOK.md). Where a step involves money (faucet
amounts, the channel, the paid message), this guide points to the exact
quickstart step instead of repeating it.

## Rules for the helper bot

A bot that helps you with this guide follows these rules. If it does not, stop
it.

- **It never runs `init`.** You run `init` yourself (step 2), because `init`
  shows your recovery phrase.
- **It never reads `mnemonic.txt`** and never asks for your recovery phrase or
  your password.
- **It never puts a token on a command line or in a file.** The owner token
  lives only in your shell (step 4), and it reaches `curl` through stdin.
- **It uses the node's API on loopback only** (`127.0.0.1:3141`).
- **It never touches mainnet**, and never changes `allow_mainnet`.
- **It sends nothing without your OK:** no contact added, no channel opened, no
  message sent and no call made until you say yes.

## 1. Download, check and install

Follow [step 1b of the quickstart](QUICKSTART-SIGNET.md#1b-or-install-a-signed-pre-release-binary)
with `v0.3.0-rc24`. Into an empty directory, download your platform's binary
(`bitsov-<os>-<arch>`), `SHA256SUMS` and `SHA256SUMS.asc` from the
[`v0.3.0-rc24` release](https://github.com/MindLink-ApS/BitSov-bitsov/releases/tag/v0.3.0-rc24),
and the release key:

```sh
TAG=v0.3.0-rc24   # the release you downloaded
curl -fLO "https://raw.githubusercontent.com/MindLink-ApS/BitSov-bitsov/$TAG/RELEASE_KEY.asc"
```

**Check the signature** (exactly as in the quickstart):

```sh
(
  export GNUPGHOME="$(mktemp -d)"
  gpg --batch --quiet --import RELEASE_KEY.asc
  gpg --batch --no-auto-key-retrieve --status-fd 1 --verify SHA256SUMS.asc SHA256SUMS 2>/dev/null > gpg-status.txt
  gpg_exit=$?
  rm -rf "$GNUPGHOME"
  if [ "$gpg_exit" -eq 0 ] &&
     ! grep -qE '^\[GNUPG:\] (BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG) ' gpg-status.txt &&
     [ "$(awk '$2 == "VALIDSIG" { print $12 }' gpg-status.txt)" = B299274C200301714DC6F51A7C2D6F8AC842EF6E ]
  then echo "signature OK"
  else echo "SIGNATURE CHECK FAILED: do not use these files"; exit 1
  fi
)
```

Anything but `signature OK` means stop: do not use the files.

**Check the file:**

```sh
shasum -a 256 -c SHA256SUMS --ignore-missing   # macOS
sha256sum -c --ignore-missing SHA256SUMS       # Linux
```

Look for `OK` after your binary's name.

**Install it as `konsensus`:**

```sh
mv bitsov-darwin-aarch64 konsensus   # your platform's file; or: ln -s bitsov-darwin-aarch64 konsensus
chmod +x konsensus
xattr -d com.apple.quarantine konsensus 2>/dev/null   # macOS only
./konsensus --version                # konsensus 0.3.0-rc24
export PATH="$PWD:$PATH"
```

**Fetch the owner-token helper** (step 4 needs it; it is not a release asset):

```sh
curl -fLO "https://raw.githubusercontent.com/MindLink-ApS/BitSov-bitsov/$TAG/docs/ops/owner-token.sh"
shasum -a 256 owner-token.sh   # Linux: sha256sum owner-token.sh
```

For `v0.3.0-rc24` the hash is
`a23f002e754f91416c5580a3ff6b82ef8447cea7cc6a125e505fef3a5ff95764`. A different
hash means stop. Read the script before you source it.

## 2. Initialize (you alone)

**You run this yourself, not the bot.** It shows your 24-word recovery phrase
and asks you to confirm three words. Write the phrase down, and keep it to
yourself.

```sh
konsensus init --dir ~/bitsov-signet --tier full
```

**Hard stop: check the network before you go on.** Open
`~/bitsov-signet/konsensus.toml`. It must say `network = "signet"`, and every
server URL in it must contain `/signet`. If either is not true, stop here and
report it; do not start the node. `init` writes signet by default, and its last
line of output names the network (`Network:    signet`).

Then add the one manual setting from
[quickstart step 2](QUICKSTART-SIGNET.md#2-initialize-a-node-on-signet), inside
the existing `[lightning]` table:

```toml
[lightning]
hub_only_channels = false
```

## 3. Join the shared test tailnet

The two testers' nodes reach each other over the shared test tailnet you were
invited to. Install Tailscale and join that tailnet, then read your node
host's tailnet address:

```sh
tailscale ip -4
```

Set your node's peer listener and advertised address to that tailnet address
as shown under [Settings in the reachability guide](operations/reachability.md#settings).
Keep `[api] listen_addr` on loopback. Give your tailnet address and port `9736`
to the other tester out of band.

## 4. Start the node and pair your terminal

```sh
konsensus start --config ~/bitsov-signet/konsensus.toml --owner-control
```

Leave it running. In a second terminal, in the directory from step 1:

```sh
cd <the step 1b directory>
export PATH="$PWD:$PATH"
KONSENSUS_CONFIG=~/bitsov-signet/konsensus.toml source ./owner-token.sh
```

Source the helper, never execute it. It keeps `OWNER_TOKEN` in this shell only.
Then define the API helper, which feeds the token to `curl` through stdin:

```sh
api() { printf 'Authorization: Bearer %s\n' "$OWNER_TOKEN" | curl -sS -H @- "$@"; }
API=http://127.0.0.1:3141/api/v1
api $API/status | jq .
```

## 5. Smoke checks

Run these in order and note pass or fail for each in your report.

| # | Check | Command or step | Pass when |
|---|---|---|---|
| S1 | Node starts | step 4 `start` | it keeps running, with no refusal |
| S2 | Node ID | `konsensus node-id --config ~/bitsov-signet/konsensus.toml` | prints your node ID |
| S3 | Owner token | step 4 `source ./owner-token.sh` | `OWNER_TOKEN` is set; nothing is written to disk |
| S4 | Status | `api $API/status \| jq .` | `money_ready: true` (after the wallet sync), `lightning_backend: ldk` |
| S5 | Signet address | `api $API/payments/funding-address \| jq .` | **`"network": "signet"`. Anything else: hard stop** |
| S6 | Faucet funds | [quickstart step 5](QUICKSTART-SIGNET.md#5-fund-it-from-a-signet-faucet), then `api $API/payments/balance \| jq .` | the balance shows the signet funds after one confirmation |
| S7 | Add the other tester (**your OK first**) | [quickstart step 6](QUICKSTART-SIGNET.md#6-add-a-contact) (`konsensus peer add`, with their tailnet address and port `9736`) | `connected` once both sides have added each other |
| S8 | Connected | `api $API/peers/connected \| jq .` | lists the other tester's node ID |
| S9 | Channel (**your OK first**) | [quickstart step 7](QUICKSTART-SIGNET.md#7-open-a-channel-to-the-contact): preview with `dry_run`, then open; one tester opens it | `api $API/payments/channels \| jq .` shows the channel ready on both ends |
| S10 | Paid message (**your OK first**) | [quickstart step 8](QUICKSTART-SIGNET.md#8-send-a-paid-message) | `"state": "acked"`, `"delivered": true`; the other tester reads it |
| S11 | Paid call (**your OK first**) | [M6 call runbook](ops/M6-CALL-RUNBOOK.md) | **only when both nodes run `v0.3.0-rc24`.** Audio needs the matching M6 app build. If the other node is on another version, mark S11 "skipped (mixed versions)"; without the app build, "skipped (no M6 app build)" |

For S11, follow the runbook's "Checks before dialing" first, and its "Capture
proof without publishing private data" afterwards.

## 6. Report

Send your report **privately to the maintainer**, through the channel you were invited
through. Report anything security-related through [SECURITY.md](../SECURITY.md),
never in a public issue.

**Never include** your recovery phrase, password, owner or paired tokens, keys
or node IDs, IP or tailnet addresses, balances, or message content.

```text
Tester: <your first name or alias>
Date (UTC):
OS / arch:
konsensus --version:
Signature check (step 1): OK / FAILED
owner-token.sh hash matched (step 1): yes / no
Network hard stop (step 2): signet / STOPPED (what it said)
S1 node starts:        pass / fail
S2 node ID:            pass / fail
S3 owner token:        pass / fail
S4 status:             pass / fail
S5 signet address:     pass / fail
S6 faucet funds:       pass / fail
S7 add tester:         pass / fail
S8 connected:          pass / fail
S9 channel:            pass / fail
S10 paid message:      pass / fail
S11 paid call:         pass / fail / skipped (mixed versions / no M6 app build)
Errors (exact code or message, with private values removed):
Waits (wallet sync, confirmation, channel ready), roughly:
What was confusing:
```
