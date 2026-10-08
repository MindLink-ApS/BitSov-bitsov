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

Pairing codes and full remote pairing links are never written to stdout or
tracing, where launchd/systemd journals could retain them. Local pairing writes
its challenge to a protected `0600` file and prints only that path and expiry.
Remote access writes the complete one-shot `bitsov://pair/...` link to
`<data_dir>/pairing/remote-access-link` at mode `0600`; stdout prints only the
protected path and expiry. The app reads that file and pastes the link. The
automatically issued remote link expires after five minutes. Operator-issued
`konsensus pair-ticket --config <cfg> [--qr] [--ttl 24h]` tickets default to
24 hours and print their URI (and optional QR) only to that CLI's stdout.
Both are file-backed, survive shutdown/restart until expiry, and are removed
on consumption or expiry. Tickets are refused while locked. See
[home-node enrollment](../operations/home-node.md#enrollment-tickets-and-box-labels).

The code is a cross-check, not the control. A sidecar app owns the data
directory and can read it by construction; describing code comparison as
*preventing* such an app from pairing would be an overclaim.

## Box transport key and migration (U1)

`PairingService::open` creates `<data_dir>/pairing/box-transport.key`: a
CSPRNG-generated, raw 32-byte X25519 secret, stored at mode `0600` inside the
`0700` pairing directory. It is independent of the mnemonic and remains stable
across restarts and identity changes. Creation publishes a fully written, synced
key atomically without replacing an existing key. Existing keys are loaded, never
silently rotated; a malformed file or a symlink fails startup. Restore a damaged
key from backup. Deleting it generates a different key on the next open and invalidates
any previously saved box pin. Include it in protected data-directory backups;
it is not recoverable from the mnemonic. Secret bytes are zeroized on drop.
Key creation requires a filesystem that supports hard links (for example NTFS,
ext4 or APFS; exFAT/FAT SD cards are not supported). On Unix, key and identity
metadata publication require successful directory synchronization, including their
parent data directory. Sync failures refuse startup; retrying keeps the published
key and retries synchronization, even for unchanged files. On non-Unix platforms,
directory synchronization is best-effort (std has no directory fsync on
Windows); only a missing directory refuses startup. The files themselves are
still synced before they are published.

On every **unlocked** start, including when remote access is disabled, the node
signs the box public key with its Ed25519 identity and atomically creates or
refreshes `<data_dir>/identity/identity.json`. The public fields are `node_id`,
`identity_fingerprint`, `transport_pubkey`, `transport_signature`,
`box_transport_pubkey`, and `box_transport_signature`;
bootstrap's `committed_at` and other existing metadata are preserved. Keys are
lowercase hex. The signature is base64url without padding over these exact UTF-8
bytes (no trailing newline):

```text
bitsov-box-transport-v1:<node_id>:<box_transport_pubkey>
```

Every successful remote `AuthResponse::Ok`, for first pairing and subsequent
authentication, adds `box_transport_pubkey` and `box_transport_signature` with
the same encoding and proof. A client verifies the signature against its
**already trusted node_id**, then saves the box key under that identity in its
protected credential store. Reject a missing, malformed, tampered, or
wrong-identity proof for box pinning. The box key does not grant any scope or
replace the client's durable pairing key. Client credential storage is in the
app repository; this repository tests the verification rule with a client
fixture and real Noise connections.

**Migration:** U1 deliberately keeps the live tunnel's seed-derived Noise
responder static and the existing pairing-link format. Today's paired clients
can reconnect with their old pin and ignore the additive auth fields. Updated
clients learn the signed box pin over that authenticated live connection before
using it for a future locked connection. Retain the live pin alongside the box
pin; do not overwrite it. There is no automatic switch of the live listener,
no re-pairing requirement, and no change to client epochs, scopes, or revocation.
U1 adds no locked startup, unlock endpoint, or remote bootstrap. A future locked
listener must prove possession of the previously verified box static; a client
must never trust a replacement advertised by a locked node on first use.

This secret is a transport credential, not a seed-decryption key. A disk image
alone does not decrypt an encrypted seed, but a thief with the key **and** the
node's network position could impersonate a future locked box and capture a
password sent during unlock. U1 does not provide hardware protection against
that adversary.

## Scopes

| grant | how |
|---|---|
| `read` + `receive` | the pairing default — first run works unattended, and a paired client is no more capable than the old loopback token |
| `spend` | explicit **per-pairing** grant by the owner at the control socket. Not a per-message confirmation: under "payment IS the connection" every message send is a spend, so per-operation prompts would fire on every message |
| `admin` | never grantable to a pairing (#104) |
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
  Elevation requests return HTTP 409 `owner_approval_unavailable`. A user who
  wants a spending client runs the node themselves. This is a real product
  constraint and belongs in the app's copy.
- OS user-presence (Touch ID, Windows Hello) would close the sidecar case
  properly. Out of scope for this step; not approximated by anything weaker.

Elevation consent requires an operation-bound **256-bit random nonce** (the
full `GRANT … CODE <nonce>` line), or for grants a **short owner code**
(`XXXX-XXXX`) typed into `konsensus grant` after reviewing the terms. The node
first writes these only to its controlling terminal (`/dev/tty`), never stdout,
stderr, tracing, HTTP, or socket status/description. When that succeeds, no
approval file is created and the existing terminal ceremony is unchanged.

For an owner-run node without a working terminal (for example systemd with
`--owner-control`), spend and front-door elevation and device registration write
the full approval instructions to `<data_dir>/pairing/owner-approval-<op_id>`, created
exclusively at mode `0600` inside the `0700` pairing directory. The node logs
**only the path and expiry**, never the code. Read the file privately as the
node's OS user and run `konsensus grant --op <op_id> --config <config>`; grant
still executes only over `control.sock`. Device registration uses
`konsensus device approve --op <op_id> --config <config>` and additionally requires
the owner-key signature. HTTP and control-socket replies contain
no approval secret. On an owner-run node, if neither terminal nor protected-file
delivery succeeds, the request returns HTTP **409 `owner_approval_unavailable`**,
without creating a pending operation. Elevations also return this 409 when
owner-run mode is off.

**Headless approval trusts the node's OS account and data directory.** A process
with that user's file access can read the code and approve over the socket.
Keep the paired app outside that account and directory. This fallback does not
provide user presence or protection against same-user malware. A working owner
terminal still keeps codes off disk, so socket/file access alone cannot approve
those terminal-delivered requests. Live-identity replacement remains
terminal-only and accepts only the full nonce line; unavailable terminal delivery
returns HTTP 409 `owner_approval_unavailable` without a pending operation.

Wrong confirmations are counted per request and node run: the third wrong one
cancels the request; after ten wrong ones, short codes stop working until
restart (the full nonce line still works). Warnings are best-effort on the owner
terminal. These limits bound guessing, not reading a headless approval file.

The node removes headless files on grant, withdrawal, cancellation by wrong
codes, and clean service shutdown. The existing cleanup worker removes expired
files within its one-second sweep interval; reads also clean them. Pending
records are durable but confirmation digests are memory-only. Startup removes
stale files and reissues fresh codes for surviving requests, through the terminal
or protected approval file. Unavailable approvals are warned about and skipped
without stopping reissue of the remaining requests. Old codes stop working.
A cancelled request reads `lost` from `GET /api/v1/pair/elevation/{op_id}`; `konsensus pair-status` marks it
and `konsensus grant` refuses it up front. The client asks again. See
[owner control commands](../v2/OWNER-APPROVALS.md) for headless operation and
[device keys](device-keys.md) for Touch ID per-contact spend.

Doctrine: lines 1, 3, 5 and 6 hold. This changes local owner consent delivery;
requests confer no authority or admission, grants remain bounded, peer service
still requires settlement, and the OS-account trust boundary is explicit.

### Remote spend requests and price preparation

Remote HTTP requests share a rate-limit bucket per authenticated pairing,
including across simultaneous tunnels and reconnects. Separate pairings do not
consume each other's allowance or the owner-local IP allowance. The Noise bridge
registers each internal connection's pairing in server-owned state before
forwarding bytes; HTTP headers cannot select the bucket. Unregistered internal
connections fail closed, and closing a tunnel removes its registration. The
public pre-authentication handshake limiter remains per IP.

An already paired remote client can use these Noise-tunnel HTTP routes with
exactly the same JWT, live pairing binding and `read` scope checks as loopback:

- `POST /api/v1/pair/elevation-request` proposes an owner-approved budget.
  Each client may have at most four unexpired pending elevation requests
  (`MAX_PENDING_ELEVATIONS_PER_CLIENT`), across scope kinds and both routers.
  Additional requests return HTTP 429 without writing a proposal or printing an
  owner challenge. Cancellation, grant, or the 15-minute expiry frees a slot;
  another client's pending requests do not consume that client's allowance.
- `GET /api/v1/pair/elevation/{op_id}` reads only the requesting client's status.
  Another client's operation and an unknown operation both return `UnknownOperation` (HTTP 404).
- `DELETE /api/v1/pair/elevation/{op_id}` withdraws the caller's own request.
- `GET /api/v1/pair/grant` reads the caller's own grant (or `null`).
- `POST /api/v1/pair/device-key` requests device-key registration with proof of
  possession. At most eight unexpired requests may be pending node-wide across
  local and tunnel callers; additional requests return HTTP 429 before an owner
  challenge is produced. The existing per-client bounds remain: a 30-second
  request floor, one in flight (a later request replaces it), a 15-minute TTL,
  and four live keys. Replacement uses the same slot; cancellation, approval,
  or expiry frees capacity.
- `GET /api/v1/pair/device-key/{op_id}` reads the caller's registration status;
  `DELETE` on that path cancels its pending request.
- Read-only `GET /api/v1/pair/device-keys` lists the caller's registered keys.

These routes never issue a grant. The unlocked Noise bridge forwards HTTP bytes
without a path allowlist, but its destination is `build_remote_router_with_limiter`,
which selects `pairing_routes::remote_routes`. Only the four device-key operations
above are exposed. Delegation (`POST /pair/device-key/{op_id}/delegate`),
self-revocation (`DELETE /pair/device-keys/{key_id}`), pairing list/revoke/window/
request/confirm, relation intents, first-contact-grant POST and identity replacement
requests remain absent on the tunnel. Nothing on the tunnel approves a key.
Approval stays at `konsensus device approve` or existing owner-device delegation
on the owner-local API. Console enrollment requires `--owner-control` with a
**typed** seed password; `--password-fd` disables owner device authority in that
mode. Spend elevation is still granted only through the owner control socket.
Asking or quoting confers no spend scope.

The remote router also omits the loopback token mint, public probes and metrics.
Locked mode uses a separate router with only `GET /livez`,
`GET /api/v1/node/lock`, `POST /api/v1/node/unlock/challenge` and
`POST /api/v1/node/unlock`; all device-key enrollment routes stay 404 while locked.
See the [first owner device runbook](../operations/home-node.md#enroll-your-first-owner-device)
for tunnel registration followed by console approval and locked restart.

`POST /api/v1/messages/first-contact/quote` requires `read`, including for a
`read` + `receive` pairing with no spend grant. It performs only bounded payment
preparation: requests and validates the recipient's signed invoice, and caches
it briefly for a later send. It pays nothing, reserves no funds or budget,
creates no obligation, and grants no admission. HTTP and recipient quote rate
limits still apply. Actual sends independently require spend authority and
settlement. The app's other pre-send prices (`GET /pricing`, `/pricing/peers`,
`/pricing/peers/{id}`, `/pricing/peers/{id}/call`, and `/payments/price/{kind}`, under `/api/v1`) already
require only `read`; room prices are assembled from those reads.

Doctrine: lines 1, 3, 5 and 6 hold. Authenticated price preparation and pending
consent requests are control-plane operations; paid peer service remains gated
by settlement, keys retain authority, and custody remains with the owner.

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

That write is unavailable on nodes using LDK or encrypted storage, even if their
current balance is zero or their next persistence write has not happened yet.
Existing database, channel or backup state also causes refusal, using the resolved
configuration paths. A remote store cannot be proven empty by this filesystem
check and is refused. These checks run before approval and consumption. BIP-39
passphrase identities are refused because the destination-binding API does not
yet support that passphrase. There is no channel-close or storage migration in
this command: replacing the seed without such a procedure can lose access to
funds and encrypted history. Fresh identity-free bootstrap restore is separate
and remains supported.

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

## Two-phase local bootstrap

Start a positively empty, loopback-only node with `--password-fd 0
--local-owner-device`. The launcher stores its generated password in Keychain
before spawning, writes it once to the pipe, closes the pipe, and erases its
copy. Neither the password nor the authority flag is stored in config. A
configured identity passphrase is refused. Local first-run trust is the root
of approval; the node cannot attest Secure Enclave hardware.

After the normal bootstrap pairing, use its `bst` token with `identity` scope:

1. `POST /api/v1/identity/create-pending` returns `ceremony_id`, `node_id`,
   `mnemonic`, `expires_at` and three distinct zero-based `backup_check` indices.
   The phrase is returned only here and stays in zeroizing memory. This call
   creates no files. A second pending request returns `409 ceremony_in_progress`.
2. Record the phrase, then `POST /api/v1/identity/finalize` with `ceremony_id`,
   `backup_words` (the three lowercase words, in index order), and `device`:
   `{public_key, name, proof}`. The key is 65-byte uncompressed SEC1 P-256, hex;
   the proof is a hex DER P-256/SHA-256 signature over `registration_message`
   from the device protocol, bound to the pending identity's fingerprint and
   the paired `client_id`. No password field is accepted (`422`) on this local
   path; only [remote first run](#remote-first-run-over-the-tunnel) takes one.
   Missing device is `400`; invalid possession or the wrong fingerprint is `403`.
3. Finalize returns `node_id`, `client_id`, `epoch`, `restart_required: true`,
   `device_key_id`, `device_fingerprint`, and `mnemonic_path`, plus the signed
   transport pairs described below, never the phrase. Bootstrap exits;
   explicitly restart with the same descriptor password and local-owner flag.

The node validates possession, derives the owner signing key transiently from
seed and password, and signs the standard Ed25519 owner approval tuple. It
stages `mnemonic.enc` and identity metadata, fsyncs, renames to `identity/`,
rebinds pairing, installs the owner-signed device record with
`enrolled_by: local_first_run`, aligns config to the encrypted seed, and writes
`NODE_INITIALIZED` last. The client and epoch are checked again under the pairing
lock. A P-256 proof alone never becomes durable owner authority.

The pending ceremony belongs to one client. A different client is forbidden.
`DELETE /api/v1/identity/pending/{ceremony_id}` discards it. Use the same-client
`DELETE /api/v1/identity/pending/current` alias if the create response or app
state was lost; this never reveals the phrase. Three failed backup
checks discard it with `410 ceremony_lost`. It expires after 30 monotonic minutes
and is discarded on the next touch (`410 ceremony_expired` on finalize).
Cancellation, shutdown and failures drop zeroizing buffers. A fresh ceremony
always generates a fresh phrase. There is no resend or mnemonic-reveal route.
`GET /api/v1/bootstrap/state` is unauthenticated. It exposes only `state`,
`can_create`, `can_restore`, and `local_owner: {available, enroll_device, pending}`.
If an interrupted commit requires repair, it returns `state: "refused"` with
`can_create: false` and `can_restore: false`, including before a restart. It
does not expose a refusal object, reason, disk-state details, or repair text.
Detailed refusal diagnostics and repair guidance remain in the CLI/stderr
startup refusal; operators can restart the node to obtain them.

Finalize, cancel, and legacy commits share a single-flight lock. A concurrent
finalize or cancel after commit begins returns `409`; successful commit is
terminal and invalidates bootstrap authority. A lost finalize response is
resolved by reading `bootstrap/state` while the listener remains open or by
restarting; the device key id can be computed from the public key. No API call
starts live services. Legacy create/restore cannot bypass a pending ceremony.

Without a startup password the new routes are absent. A descriptor password
without `--local-owner-device` enables encryption but requires `device` to be
absent (`400` otherwise); it confers no owner authority on later starts. Legacy
create/restore remain terminal and now encrypt whenever a password is present.

Interrupted staging is ignored and reported, never adopted. After rename,
any failure requires explicit repair; the current process also refuses to start
another ceremony. `repair mark-initialized --confirm` still writes only the
marker. **If the crash preceded config alignment, the operator must also align
`identity.mnemonic_file` to `identity/mnemonic.enc` before live startup**; repair
does not silently rewrite config. A crash before pairing rebind also leaves the
old empty-fingerprint pairing unusable: token issuance fails closed. Recover
that pairing explicitly through the owner console (revoke and re-pair); repair
never silently rebinds it. After rebind, a missing device record leaves only
read/receive authority. Enroll through the owner console; the HTTP bootstrap
routes never reopen and the phrase is never shown again.

### Remote first run over the tunnel

A headless box has no launcher to pipe a password. Start it on a positively
empty data dir with `start --remote-unlock --local-owner-device` and
`[remote_access]` configured; `--password-fd` is not used. Bootstrap then also
binds the Noise listener with the persistent box static
(`pairing/box-transport.key`) and bridges it to an internal loopback listener,
as in locked mode. The loopback API stays bound. No peer port is bound.

First pairing needs a pre-bootstrap ticket from `konsensus pair-ticket` on the
box; bootstrap never mints one. The ticket carries only the box public key, and
the client pins it. The client's pairing proof binds the empty node id (`""`).
Consuming the ticket creates the one bootstrap pairing (`read`, `receive`,
`identity`) bound to the client's Noise static. A second ticket, or a ticket
after any other pairing exists, is refused. A ticket never opens the local
`/pair/request` window. The client then fetches its `bst` token through the
tunnel as usual.

`GET /api/v1/bootstrap/state` reports `can_restore: false` and
`local_owner: {available: true, enroll_device: true, pending,
tunnel_password: true}`. `tunnel_password` is absent in local mode. The
ceremony routes change in this mode only:

1. `POST /api/v1/identity/create-pending` takes
   `{"password_commitment": "<blake3(password), 64 lowercase hex>"}`; anything
   else is `400 invalid_password_commitment`. The client generates the
   password and stores it (for example in Keychain) **before** this call. The
   response is the local one.
2. `POST /api/v1/identity/finalize` takes the local body plus `password`.
   `device` is mandatory, because the box cannot be unlocked without a device
   key. The password is decoded into zeroizing memory without a serde scratch
   copy. A malformed body is `400 invalid_finalize_body`, a missing commitment
   is `400 password_commitment_missing`, an empty password is
   `400 password_required`, and a password that does not match the commitment
   is `400 password_commitment_mismatch`. Mismatches count as failed backup
   checks; the third is `410 ceremony_lost`. Nothing is written before the
   check passes.
3. Commit is the local commit with that password: `mnemonic.enc` only, the
   owner approval from `owner_secret(password, node_id)`, and the device record
   says `enrolled_by: remote_first_run`. `identity/identity.json` now carries the
   signed public transport proofs that locked mode and `pair-ticket` require.
   The finalize response includes `box_transport_pubkey` and
   `box_transport_signature` for the bootstrap/locked listener, plus
   `transport_pubkey` and `transport_signature` for the unlocked listener.
   Both pairs come from the proofs committed to `identity/identity.json`.
   The tunnel survives the rebind long enough to deliver it, but a revocation
   or epoch change still closes it.
4. The process exits **75** (`EX_TEMPFAIL`). Under `Restart=on-failure` the same
   command restarts into locked mode. The client completes the
   [first remote unlock](../operations/home-node.md) with the stored password,
   which also proves the stored copy is right.

The additive finalize receipt fields have these wire types:

| Field | JSON type | Meaning |
|-------|-----------|---------|
| `client_id` | string | The paired client that completed the ceremony. |
| `epoch` | integer (u64) | That client's pairing epoch, preserved across commit. |
| `transport_pubkey` | string, optional | Lowercase hex, 32-byte seed-derived X25519 public key for UNLOCKED. |
| `transport_signature` | string, optional | Base64url without padding, Ed25519 identity signature over the live-key proof below. |
| `box_transport_pubkey` | string, optional | Lowercase hex, 32-byte box X25519 public key for bootstrap and LOCKED. |
| `box_transport_signature` | string, optional | Base64url without padding, Ed25519 identity signature over the box-key proof above. |

The live-key proof uses the same domain as PairLink v2, with these exact UTF-8
bytes and no trailing newline:

```text
bitsov-remote-transport-v1:<node_id>:<transport_pubkey>
```

The proof is identity-scoped; it does not include `client_id` or `epoch`.
Those receipt fields describe the pairing and do not change the signature
format. After commit, the bootstrap JWT is invalid; obtain a fresh token after
unlock and check its `epc` against the saved epoch.

A client verifies both signatures under the committed, trusted `node_id`, saves
both pins, and requires the corresponding Noise responder static on connection.
Bootstrap and LOCKED continue to use the box static; UNLOCKED continues to use
the seed-derived live static.

To recover a lost finalize receipt, successful **locked-mode** `AuthResponse::Ok`
replies also include the optional `transport_pubkey` and `transport_signature`
fields with exactly the same values. Reach LOCKED using the box pin already
trusted, verify the live proof under the already trusted `node_id`, and then use
that live pin for UNLOCKED. Locked startup verifies the saved live proof before
serving it. Older `identity.json` files may omit both fields; in that case the
auth reply omits both. A partial, malformed, or invalid proof refuses locked
startup. A missing proof gives the client no new pin and must not trigger TOFU.
Existing clients can ignore the additive fields.

`create-pending` and `finalize` require the caller to arrive through a
registered tunnel whose server-side pairing is the token's client. The
registration is server state keyed by the internal peer address; no header can
claim it. The same calls on the loopback listener, or from another tunnel
client, are `400 tunnel_required`; finalize checks this before it reads the
body. Legacy
`/api/v1/identity/create` and `/api/v1/identity/restore` are not routed in this
mode: a plaintext seed would leave a box that `--remote-unlock` refuses.
Remote restore is not supported. The password never touches disk, logs or
responses, and it is dropped with the ceremony state.

Contract errata (C:§3.3, home-node contract §2.3): "no HTTP password field" is
amended to "never on the loopback path". The tunnel is bound only with
`--remote-unlock`, not whenever `listen_addr` is set: other bootstrap starts
keep the loopback-only surface. Device enrollment is mandatory, and the restart
exit code is 75.

A box that is not the owner's own can serve a fake bootstrap to a client that
scanned its ticket, and the client would then create a seed on that box. Take
the ticket only from your own box.

## Unchanged

Protocol admission is untouched and remains governed by settled payment at the
gate. No hardware-bound keys. No config flag, trusted-client list or debug mode
that widens issuance, and no fallback to a stronger scope to keep a screen
green. #74 and #75 remain separate follow-ups, and bitsov-app#19 is not started
here.

Scopes landed on `main` in `ade8b536` and are not in `v0.3.0-rc6` or
`v0.3.0-rc7`. Everything above becomes true of the product only when a build
carrying it ships and the app is re-pinned.


### Versioned remote endpoint descriptors (N2)

PairLink v2 adds ordered `endpoints` and `endpoints_signature`; `endpoint` must
match entry zero. A non-bootstrap v2 link requires a valid Ed25519 signature over
the UTF-8 JSON tuple `["bitsov-endpoints-v2", 2, node_id, transport_pubkey,
box_transport_pubkey, endpoint, endpoints]`, with no whitespace. Array order is
part of the signature. The signature is base64url without padding, keys are
lowercase hex. Ticket code, expiry and display label retain their existing
independent semantics and are not part of this public descriptor proof.
The transport proofs and Noise/auth wire version remain unchanged.

V1 parsing remains supported; `pair-ticket --legacy` exports a strict v1 link
using the first address for older apps that reject extra fields. V1 cannot carry
a v2 list or its signature. Bootstrap has no node identity to sign with and
retains the box key from the locally obtained ticket as its initial Noise pin.

Endpoints and mDNS are routing hints. A paired client verifies v2 descriptors
against its **saved** node identity, never an identity learned from DNS, and
checks the Noise remote static against its saved transport pin before sending
authentication or unlock secrets. Endpoint fallback never resets that pin.
The home-only optional `_bitsov._tcp` advertisement exposes only a fingerprint
prefix and the TCP port; it is not an identity, pairing or authorization channel.
See [operating endpoint discovery](../operations/home-node.md#endpoint-discovery).


## SAS v1 and the box claim code (N3)

Newly initialized boxes and empty-directory SETUP generate a local `claim-code`
file beside `konsensus.toml`, mode `0600`. It contains 16 uppercase RFC 4648
base32 characters (80 random bits) plus two checksum characters. The checksum
is the first 10 bits, MSB first, of BLAKE3 over the first 16 ASCII characters,
encoded with the same alphabet. There are no separators or trailing newline in
the file. Provisioning may put the code on the box's sticker. Self-flashed boxes
show it once on the controlling terminal when available. Headless daemons never
send it to stdout, stderr, journald, tracing, a QR, HTTP, or a Noise tunnel.
`konsensus claim-code --show --config /path/to/konsensus.toml` reads it only on
an owner console (the data-directory owner on Unix); output goes directly to
that console, including when stdout is redirected. Missing, malformed or
symlinked claim files fail closed; a malformed file is never silently replaced.
Keep the code with the box. Disk access to this file defeats this additional
physical-origin check.

Existing initialized boxes without a claim code retain their console enrollment
flow; this release does not migrate their identity or provision a code remotely.
The new flow is for boxes initialized or put through empty-directory SETUP with
N3. Do not wipe a funded node merely to enable this flow.

For clients explicitly requesting `sas_version: 1`, the exact binary transcript is:

```text
sas_digest = BLAKE3(
  ASCII("bitsov-sas-v1") ||
  noise_handshake_hash[32] || box_transport_pubkey[32] || client_static[32] ||
  device_public_key[65] || box_nonce[16] || claim_code_commitment[32])
claim_code_commitment = BLAKE3(ASCII("bitsov-claim-code-v1") || claim_code_ASCII[18])
```

Keys are raw bytes, not hex text. The device key is an uncompressed SEC1 P-256
point. The box key is the persistent transport key advertised in the pair link
(the live legacy transport may still use its identity-derived Noise responder
key). The handshake hash is the **completed** Noise XX transcript, retained by
the server before switching to transport. The first 44 digest bits, most
significant bit first, become four successive 11-bit indices into the BIP-39
English list. These four words are an authentication string, not recovery words.
Finalization compares the full 32-byte digest in constant time.

A fixed interoperability vector uses handshake bytes `00..1f`, box key `22` × 32,
client static `33` × 32, device key `04 || 44` × 64, nonce `55` × 16 and claim
commitment `66` × 32. Its digest is
`960be0e8e070d1089b55da2113669f8530ee396eb36cd0fa04e82cb9ae346f35`;
indices are `1200, 760, 465, 1543`: **noodle gallery demand science**.

### Remote first run

`POST /api/v1/identity/create-pending` accepts:

```json
{"password_commitment":"<64 lowercase hex>","sas_version":1,
 "device":{"public_key":"<130 hex>","name":"My phone"}}
```

The server verifies the caller's registered Noise bridge, commits the device
key and label under the single-pending lock, then generates a fresh 16-byte
nonce. The existing response gains `sas_version: 1` and `box_nonce` (32 lowercase
hex characters). It never returns the claim code, its commitment, the SAS words,
or the expected digest. Clients derive the commitment locally from the sticker
or trusted console code; they must never send that code to the box. Unsupported
versions and incomplete version/device combinations fail closed.

`finalize` adds `sas_version: 1` and `sas_digest` (64 hex characters); the device
key and label must match create-pending. `device.proof` signs the UTF-8 message
returned by `sas_registration_message`: the existing registration message with
its domain changed from `v1` to `v2`, followed by `\nsas_digest:<lowercase digest>`.
The Noise binding is checked again under the finalization lock after reading the
body. Reconnecting requires cancelling and starting a new ceremony. Correct SAS
cannot replace the password commitment, backup-word check or device proof.

There is one pending ceremony. SAS ceremonies expire within 15 minutes and
cannot outlive the 15-minute process setup window; `expires_at` reports the
earlier deadline. Three SAS mismatches or cancellations close setup until process
restart, including attempts to downgrade to the legacy protocol. Dropping a
ceremony after repeated incorrect password/backup confirmations also counts as
a cancellation. A retry cannot replace a pending nonce. Cancelling an absent
operation does not consume an attempt.

Requests without SAS fields are refused as soon as a claim-code file exists
(including malformed or unreadable files); this is checked again at finalize.
Legacy boxes without that file retain the pre-N3 behavior. Local descriptor
bootstrap remains the separate trusted sidecar path. SAS first-run finalization
also requires `box_approved`, set only by the separate home box page; otherwise
it returns `409 box_approval_pending` before password processing or signing.
On an empty box use `--home`; remote-unlock without home now fails early with
that instruction. Initialized boxes retain their existing unlock flags.
SAS knowledge alone does not add an owner approval route. The app
must compare the words before sending its password or trusting recovery words.
A fake box lacking the physical code computes different words; accepting a
code supplied by that same untrusted page defeats this protection (T2). One-use
pairing tickets, a single pending operation and the rejection budget limit
photographed-QR abuse (T3) and nonce grinding (I3).

### Live device-key enrollment

`POST /api/v1/pair/device-key` can add `sas_version: 1` to the existing key,
name and v1 possession proof. It requires the authenticated Noise bridge and
returns `sas_version` and `box_nonce`. At most one SAS enrollment is pending
box-wide; a legacy request cannot replace it. The 15-minute enrollment expiry
remains, with a monotonic deadline as well as the durable wall-clock expiry.

The enrolling client then sends the tunnel-only
`POST /api/v1/pair/device-key/{op_id}/finalize` with `sas_version: 1`,
`sas_digest` and `proof` over `sas_registration_message`. This records only SAS
confirmation. Existing console approval or an already enrolled device's signed
delegation is still required. The v2 delegation domain additionally binds
`\nsas_digest:<digest>`; its signing message is available only after confirmation.
This PR does not expose delegation or ticket-minting over the tunnel.

Three mismatches/cancellations close new device ceremonies for that process.
SAS confirmation is memory-only; its durable version marker ensures a restart
cannot approve an old SAS request as legacy. Cancel the old request and retry.
Omitting `sas_version` preserves legacy console/delegation messages only on
boxes without a claim code. Claimed boxes reject legacy requests and legacy
pending operations at approval/delegation, so restart cannot enable downgrade.


## LAN box approval (N4)

`--home` starts a separate listener on each private LAN interface (default port
8080, `[setup_page].port` overrides it). Its router is never mounted on the
loopback API or the Noise tunnel. RFC1918, link-local and IPv6 ULA sources are
accepted, with both Tailscale ranges excluded; IPv4-mapped IPv6 is normalized.
Forwarded headers confer no trust. Public and loopback sources are refused.
Every route requires an exact own IP/port or `bitsov.local`/port Host, rejecting
DNS rebinding through arbitrary attacker domains.

GET `/` creates a bounded, random per-page session and CSRF token. The cookie is
HttpOnly, SameSite=Strict, path `/`, maximum age 900 seconds; HTTP is intentional
on the local appliance, so it is not marked Secure. All mutations require both
the cookie and `X-CSRF-Token`; `/setup/state` also checks both. There is no CORS.
Responses use `Cache-Control: no-store`, `nosniff`, no referrer and a strict CSP:
nonce-only inline script/style, same-origin fetch, no other assets, forms,
frames or base URLs. Device labels enter the DOM as text, not HTML.

POST `/setup/start` rotates the five-minute, one-use bootstrap ticket. Its QR
and text are returned only after Start setup. GET `/setup/state` shows the
claimed label and four SAS words. POST `/setup/approve` accepts exactly
`{ceremony_id, sas_digest}`: under the same transition lock as finalize, it
checks the current pending ceremony and all 32 digest bytes using
`subtle::ConstantTimeEq`, then sets only `box_approved`. It does not sign,
install a device, write a seed, commit identity or grant scopes (I1).
No page response contains the claim code, claim commitment, seed, backup words
or password (I2). The app must compare SAS before sending its password.

POST `/setup/cancel` (“Words differ / Not me”) invalidates the shared ticket,
revokes the bootstrap pairing and discards the pending ceremony, pre-commit
only. Ticket consumption and revocation share one lock; approval, cancellation
and finalize share the transition lock. Three cancellations/SAS failures close
the process setup window (I3). Every page action rechecks the 15-minute monotonic
window and SETUP state. After commit or restart into LOCKED/UNLOCKED, only status
HTML is served; old approval sessions confer no authority (T4/T5).

The in-memory ticket slot is the sole home SETUP authority (design item 9).
CLI `pair-ticket` files are imported as a protected mailbox into that same slot,
then removed, with TTL capped by five minutes and the remaining window. Page
rotation, CLI replacement, consumption and revocation cannot leave two valid
tickets. CLI imports cannot replace a claim or reopen an expired window.
Other daemon modes retain the existing protected-file ticket authority.

An attacker on the LAN can still claim and approve an **empty** box (T1); the
page identifies the claim and the owner's app cannot pair until it is cancelled.
A fake appliance is not authenticated by DNS or Host validation: the separate
physical claim code and the owner's word comparison remain necessary (T2).
One use, short ticket lifetime and cancellation limit photographed-QR abuse
(T3). Host, session/CSRF checks, no CORS and the submitted digest prevent a
foreign website from approving a ceremony through the owner's browser (T6).
