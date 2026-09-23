# Client pairing, identity-free bootstrap, and owner-approved elevation (#76)

**Less exposure, not solved local security.**

That sentence is the claim discipline for this feature and everything downstream
of it. Nothing in this document, the code, or the release notes may be quoted as
saying more.

## What it buys

Before pairing, any process that could open a TCP connection to
`127.0.0.1:<port>` could mint a token: a web page doing
`fetch('http://127.0.0.1:3141')`, a process belonging to another OS user, a
container with host networking, an SSH port-forward, a sandboxed app.

Pairing moves the bar from **"can reach loopback"** to **"can read the owner's
data directory"**. Confirming a pairing requires an Ed25519 signature over a
32-byte challenge that exists only in a `0600` file under `data_dir`.

## What it does not buy

A process running as the **same OS user** that can read arbitrary files can read
whatever credential the app can read. No design at this tier stops it. Closing
that gap needs an OS keychain with a per-application ACL, or hardware-backed
keys — later tiers, deliberately out of scope here.

The short code printed to the node's stdout is a **tripwire**, not the control.
In the sidecar deployment the app launches the node and owns its stdout, so it
can read that code by construction. If anyone describes the code comparison as
*preventing* a pairing, that is an overclaim.

## Scopes

| grant | how |
|---|---|
| `read` + `receive` | the pairing default — first run works unattended, and a paired client is no more capable than the old loopback token |
| `spend` | explicit **per-pairing** grant by the owner at the control socket. Not a per-message confirmation: under "payment IS the connection" every message send is a spend, so per-operation prompts would fire on every message |
| `identity` | only on an identity-free node during first-run bootstrap, and stripped from the pairing as part of the transition commit |
| `credential` | never grantable to a pairing |

Paired tokens live **10 minutes** and carry the client id, the pairing epoch and
the identity fingerprint. All three are re-checked against the durable record on
every request, so revoking a pairing (or replacing the identity) invalidates
outstanding tokens immediately rather than at expiry. A mismatch is rejected
outright — never downgraded to a weaker scope set.

`/auth/local` is unchanged: still `read` + `receive`, still loopback-only.

## Elevation is not an HTTP capability

The file challenge proves read access to `data_dir`, and the app has that by
design. So any approval channel gated on `data_dir` access is a channel the app
can drive against itself.

Therefore, per the operator lock:

- The HTTP surface may **create a pending request** and **read its status**. It
  can never write a grant or consume an approval. `POST
  /api/v1/identity/restore` no longer exists on the live router at all — not
  scope-gated, **absent**.
- `spend` grants and live-identity replacement execute only over
  `<data_dir>/control.sock` (mode `0600`, not reachable over loopback TCP),
  created only when the node is started with `--owner-control`.
- **A packaged sidecar app cannot spend, and cannot replace a live identity.**
  It may request elevation and will never obtain it. A user who wants a spending
  client runs the node themselves. This is a real product constraint and belongs
  in the app's copy.
- OS user-presence (Touch ID, Windows Hello) would close the sidecar case
  properly. Out of scope for this step; not approximated by anything weaker.

Elevation consent requires an operation-bound **256-bit random nonce** printed
only to the owner node's controlling terminal (`/dev/tty`), never stdout,
tracing, HTTP, socket status/description, or a file under `data_dir`. The CLI
asks for that full confirmation. Knowing the public operation id/label or
connecting as the same uid is insufficient. Without an owner terminal,
elevation fails closed. Pending challenges are memory-only and lost on restart;
the owner must request a new operation. Arbitrary access to the owner's terminal
or process memory remains outside this tier's threat model.

### Live-identity replacement binds five fields

`{ op_id, client_id, current_identity_fingerprint,
replacement_identity_fingerprint, expires_at }`

The destination fingerprint is computed from the recovery phrase **before
anything is written**, so the owner approves one specific identity rather than
"whatever the app sends afterwards". The owner supplies the phrase again at the
socket, where it is re-derived and compared. Consumption is an atomic
compare-and-delete: exactly one can succeed, replays find the record gone, and a
failed attempt does not burn the owner's approval. The approval record never
stores the recovery phrase; successful replacement writes the configured identity
file.

## Identity-free bootstrap

On a truly empty install, `konsensus start --config <data-dir>/konsensus.toml`
prepares in-memory full-tier defaults without creating an identity or requiring
an existing config. After bootstrap commits, the same command uses
`<data-dir>/identity/mnemonic.txt`. Existing configs retain their configured
identity path. No node is started automatically by the bootstrap response.

Owner replacement writes the configured plaintext mnemonic path, including
bootstrap-created identities. Encrypted mnemonic replacement is refused before
approval consumption; operator-managed re-encryption is required rather than
silently writing plaintext into an encrypted file.

A fresh install has no identity, and the JWT secret is derived from the
identity — so there was nothing to authenticate against. Bootstrap is a mode of
`serve` (not of `init`, which keeps its behaviour).

Entry requires **positive evidence of emptiness**, a conjunction: no
`NODE_INITIALIZED` marker, **and** no identity material, **and** no wallet or
channel state. If the marker is absent but any other clause fails, the node
**refuses to start** and names the repair command:

| state found | outcome |
|---|---|
| nothing | bootstrap opens |
| state but no identity | refuse — a **deleted key** on a node that may hold funds. Repair: `konsensus restore` |
| identity, no marker (with or without config) | refuse; includes pre-#76 installations. Operator repair: `konsensus repair mark-initialized --dir <data-dir> --confirm` |
| marker, no identity | refuse — funded node with a deleted key |
| marker + identity, unreadable store | refuse — operator repair |

**"Fresh" is never "an existing identity with a zero balance."** Balance is not
an authorization input: it is not a field of the probe, so the classifier cannot
consult it.

The bootstrap router is a **separate, small router**: `/livez`,
`/api/v1/bootstrap/state`, the ceremony, and one terminal first-run
create/restore (which requires a bootstrap pairing holding `identity`).
Payments, messaging, peers, gossip, invites, export, content, calendar, mnemonic
reveal and the WebSocket are **unrouted**, not mounted-and-denied — a node with
no keys genuinely cannot pay, and a 403 would manufacture a "looks like a funded
node" surface.

The transition is one commit, **marker last**: stage into `.init-<uuid>/`,
fsync, `rename()` into place, rebind pairings to the committed identity, then
write the marker and fsync the parent. Single-flight — a concurrent second
attempt gets `409` and writes nothing. Bootstrap runs on an **ephemeral**
in-memory signing secret which does not rotate inside the bootstrap process.
Commit rebinds the pairing fingerprint and strips identity authority, so old
bootstrap bindings fail immediately. The separately started live node derives
its own secret and also rejects tokens marked `bst`. A crash before the rename leaves a staging
directory that startup reports and never consumes; a crash after it refuses and
demands repair. The node is never auto-started into live operation by an API
call.

## Unchanged

Protocol admission is untouched and remains governed by settled payment at the
gate. No hardware-bound keys. No config flag, trusted-client list or debug mode
that widens issuance, and no fallback to a stronger scope to keep a screen
green. #74 and #75 remain separate follow-ups, and bitsov-app#19 is not started
here.

Scopes landed on `main` in `ade8b536` and are not in `v0.3.0-rc6` or
`v0.3.0-rc7`. Everything above becomes true of the product only when a build
carrying it ships and the app is re-pinned.
