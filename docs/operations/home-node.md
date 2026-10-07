# Home node: unlock after a restart

Run one process, data directory, identity and password per person. Use one
command throughout setup and later reboots:

```sh
konsensus start --config /path/to/konsensus.toml --home
```

`--home` combines `--remote-unlock` and `--local-owner-device`. The existing
flags keep their behavior and may also be supplied alongside `--home`.
It conflicts with `--owner-control`, `--password`, `--password-fd` and
`--password-file`. It never opens the owner-control console or grants console
spend authority. After unlock it retains the owner key in memory for existing
owner-device spend envelopes and delegation.

```text
SETUP --remote first-run commit--> exit 75 --service restart--> LOCKED
LOCKED --owner-device unlock--> UNLOCKED (same process)
UNLOCKED --power cut / restart--> LOCKED
```

On a **positively empty box**, install the service before enrollment and follow
[remote first run](#remote-first-run-on-an-empty-box). Setup commits the encrypted
seed and first owner device, then exits 75; the service restarts the same command
into locked mode. No API call starts live services during setup.

On an **already initialized box**, [enroll an owner device](#enroll-your-first-owner-device)
first. On a U1-capable unlocked start, the node writes `identity/identity.json`
and advertises its identity-signed box transport public key to paired clients.
Connect a supporting client to that unlocked node so it pins the signed key
before enabling the service. Never learn a new pin from a locked node. Keep
`pairing/box-transport.key` (0600) and public identity metadata across restarts.
Plaintext seeds and missing/stale public identity metadata are refused; repair
metadata by starting normally with the correct encrypted seed first.

Configure `[api].listen_addr` on loopback and `[remote_access].listen_addr` plus
`advertised_endpoint` for the Noise endpoint reachable by your device. To reach
it off the LAN, see [reachability](reachability.md). Home mode still requires
this configuration; it does not yet provide a box setup page or auto-discovery.
There is no password file, systemd password credential, or password in
argv/environment. On reboot the box waits for a device to unlock it.

While locked, the only routes are `GET /livez`, `GET /api/v1/node/lock`,
`POST /api/v1/node/unlock/challenge` and `POST /api/v1/node/unlock`. The first two
are public on the loopback API. The unlock routes require an existing paired
client authenticated by the Noise tunnel, even on loopback. The tunnel uses the
box static and cannot create pairings. There is no `/api/v1/health`, `/auth/local`,
pairing API, WebSocket, peer TCP listener (normally 9736), Lightning, chain source,
or gossip. Monitor `/api/v1/node/lock`: it reports `state`, `node_id`, `fingerprint`,
`locked_since`, process-wide `attempts_left` and the optional `hosted_by` label.

Unlock uses a fresh 32-byte hex challenge, valid for 120 seconds and consumed on
its first use. The P-256 signature binds the fingerprint, client, pairing epoch,
device key, challenge and pinned box static. Device possession is checked before
password decryption. The password-derived owner approval is then verified again
against the durable device record, and the seed must match the saved identity.
A forged `clients.json` device record cannot unlock the node. Success returns
204, closes the locked listeners within 250 ms, and continues normal startup in
the same process. Clients reconnect to the normal seed-static tunnel after start.
Wrong unlocks are limited to five per key in a sliding 15-minute window and 20
per process run; exhaustion returns 429 (the process cap requires a restart).
`--home` includes local owner-device authority for existing owner-approved spend
intents. With `--remote-unlock` alone those intents remain off with
`seed_password_not_typed`.

## Install the system service

The [bitsov.service system unit](bitsov.service) runs as a dedicated `bitsov`
user, starts at boot, and restarts after failures and setup exit 75. The older
[konsensus.service user unit](konsensus.service) remains available for existing
installations. Run only one service against a data directory.

On a Linux system with systemd, from the repository root, install the verified
binary at `/usr/bin/konsensus` and create the account and data directory:

```sh
sudo useradd --system --user-group --home-dir /var/lib/bitsov --shell /usr/sbin/nologin bitsov
sudo install -d -o bitsov -g bitsov -m 0700 /var/lib/bitsov
```

Prepare `/var/lib/bitsov/konsensus.toml` with ownership `bitsov:bitsov` and mode
0600. Use the node configuration for your chain and Lightning provider, a
loopback API, and a reachable Noise listener with an explicit advertised
endpoint. Keep all writable paths (seed, SQLite database, LDK state, backups,
and logs) under `/var/lib/bitsov`; the unit makes the rest of the filesystem
read-only and hides home directories. Provider credential files must be readable
by `bitsov`. Adjust binary and data paths in the unit if your layout differs.
The config itself must be writable by `bitsov` for first-run finalization.

For a **new box**, point `identity.mnemonic_file` at the not-yet-created
`/var/lib/bitsov/identity/mnemonic.enc`. Do not run `konsensus init`: remote first
run creates the identity and enrolls the first device. Apart from the config
and pairing material, leave the data directory empty. Issue the ticket as the
service user, on a trusted terminal (never in `ExecStartPre` or the journal):

```sh
sudo -u bitsov /usr/bin/konsensus pair-ticket --config /var/lib/bitsov/konsensus.toml --qr
```

For a **retained box**, finish the enrollment and key-pinning steps above first;
preserve the existing identity, pairing records and channel state. Stop its old
process before enabling this unit, and ensure `bitsov` owns the data directory
and can access every configured path. Do not reinitialize or wipe retained data.

Install and enable the system unit (no `--user`):

```sh
sudo install -m 0644 docs/operations/bitsov.service /etc/systemd/system/bitsov.service
sudo systemd-analyze verify /etc/systemd/system/bitsov.service
sudo systemctl daemon-reload
sudo systemctl enable --now bitsov.service
sudo systemctl status bitsov.service
sudo journalctl -u bitsov.service -n 50 --no-pager
```

An empty box is now in SETUP; use a client supporting remote first run to finish
the ceremony below. An initialized box waits in LOCKED. After setup, systemd
restarts it automatically, and the device unlocks it into UNLOCKED without a
second process restart. No mode change is needed between these states.

The unit uses `Restart=on-failure`, `RestartForceExitStatus=75`, a 10-second
restart delay, and at most five starts per 300 seconds. A repeated configuration
failure therefore stops retrying rather than looping indefinitely. Inspect the
journal and fix the reported cause, then run
`sudo systemctl reset-failed bitsov.service` and
`sudo systemctl start bitsov.service`. An explicit
`systemctl stop` keeps it stopped. See the upstream
[systemd service documentation](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
for restart semantics. `NoNewPrivileges`, `ProtectSystem=strict`,
`ReadWritePaths=/var/lib/bitsov`, and `PrivateTmp` confine the service's writes;
none supplies or stores the seed password.

## Enroll your first owner device

For an already initialized box with an encrypted seed, use **option A: console
approval during an unlocked start**. A ticket pairs a client; it does not approve
its owner key. A locked node needs an already approved key, so first enrollment
must happen before enabling remote unlock.

While unlocked, the Noise tunnel exposes enrollment requests, status polling,
cancellation, and read-only key listing. A tunnel-only paired client can request
its key and wait for console approval. The HTTP API stays bound to loopback;
no SSH port forward is needed for those four operations. Nothing on the tunnel
can approve a device: delegation remains on the owner-local API.

Pending registrations are capped at eight node-wide across local and tunnel
requests (HTTP 429 at capacity), with the existing 30-second per-client floor,
one in flight per client, 15-minute expiry, and four live keys per client.
Replacing your own pending request after the floor uses the same slot;
cancellation, approval, or expiry frees a slot.
1. Stop the node service. Use the same config, data directory and OS account for
   every step. Configure the Noise endpoint your device can reach; see the
   [`[remote_access]` Tailscale example](reachability.md#settings). Keep the HTTP
   API on loopback.
2. Start unlocked at the box's terminal (an SSH terminal on the box is fine):

   ```sh
   konsensus start --config /path/to/konsensus.toml --owner-control
   ```

   Type the seed password when prompted. For this console-approval mode,
   `--password-fd` does **not** enable device authority: descriptor-based
   authority requires `--local-owner-device`, which conflicts with
   `--owner-control`. Do not put the password in argv, environment variables or
   a persistent file. Do not combine this start with `--remote-unlock` or
   `--local-owner-device`.
3. In another terminal on the box, issue a private enrollment ticket:

   ```sh
   konsensus pair-ticket --config /path/to/konsensus.toml --qr --ttl 24h
   ```

   Open/scan it on the device and complete pairing. The device must verify and
   save the identity-signed box transport key while the node is unlocked.
4. On the paired device, request owner-key enrollment (for example, **Set up
   Touch ID approvals** in a supporting app). The device creates its P-256 key,
   proves possession, and sends `POST /api/v1/pair/device-key` with its paired
   token over the unlocked Noise tunnel (or to the owner-local API). It receives
   a pending `op_id` and fingerprint. Poll `GET /api/v1/pair/device-key/{op_id}`
   until registered; `DELETE` on that path cancels the request, and
   `GET /api/v1/pair/device-keys` lists this client's registered keys.
   At the box, run:

   ```sh
   konsensus device approve --op <id> --config /path/to/konsensus.toml
   ```

   Compare the fingerprint printed by the command with the device's screen
   before proceeding. Enter the short code from the node's terminal (or the
   owner-only `pairing/owner-approval-<id>` file on a headless start), then type
   the seed password at the approval prompt. Wait until the device reports the
   key as registered. See [device keys](../security/device-keys.md) for details.
5. Stop the foreground node, then restart with:

   ```sh
   konsensus start --config /path/to/konsensus.toml --home
   ```

   Or start the [system unit](bitsov.service) configured with `--home`.
   The node now waits locked. A supporting device connects using its saved box
   pin, requests an unlock challenge, and submits its approved key's signature
   plus the seed password over Noise. Success returns 204; reconnect after normal
   startup. Password entry/storage and biometric prompts depend on the client;
   enrollment alone does not store the seed password on the device.

### Add further devices by delegation

Use **option D** while the node is unlocked after a
`--remote-unlock --local-owner-device` start. Issue another ticket, pair the new
device, and have it request `POST /api/v1/pair/device-key` over the unlocked
Noise tunnel or owner-local API. An already approved
owner device verifies the node and compares the new device's fingerprint, then
signs the exact pending `delegation_message`. Using **the approving device's
paired token**, it submits `{approver_key_id, signature}` to
`POST /api/v1/pair/device-key/{op_id}/delegate` on the owner-local API (available
only through a local connection or a private SSH port forward to the loopback
API, never through the Noise tunnel).

This needs client support for delegation; see the
[delegation contract](../security/device-keys.md#delegating-another-owner-device).
The new device polls its pending operation until registered. After a restart,
each paired device's unlock challenge lists its own approved `key_ids`; a pending,
unapproved key is absent and cannot unlock. The node retains the owner signing
key in memory after local-owner unlock so it can approve delegation. No console
approval command is available in this mode. If there is no approved device,
return to option A rather than trying to enroll while locked.

## Receiving and channel safety while locked

LDK is not running: there is no ChainMonitor, breach punishment or HTLC claim
processing. A counterparty broadcasting a revoked state can steal funds if the
box does not unlock in time to respond within `to_self_delay` (the current LDK
default is 144 blocks, roughly a day; block times vary). Incoming payments fail
or time out. HTLCs already in flight can cause the peer to force-close after the
CLTV deadline (the default `cltv_expiry_delta` is 72 blocks, roughly 12 hours).
Resolution moves funds on-chain, with fees; exact settlement depends on the HTLC
state and deadlines. Outgoing HTLCs also resolve on-chain through the peer.
Unlock promptly after every restart; do not treat these estimates as guarantees.

The local watchtower client core cannot yet send to a guard. There is no active
keyless watch-only protection in W2a. Started with `--remote-unlock`,
the node therefore opens and accepts new channels only with the configured
hub/LSPs (see [hub-only channels](#hub-only-channels-hub_only_while_lockable)).
A longer breach window (below) gives more time to unlock but does not lift that
rule.

### Local watchtower staging (W2a, optional)

Omitting `[tower.clients]`, or leaving it empty, keeps tower staging off and
preserves existing node behaviour. Only the embedded `ldk` backend supports it.
To opt into local staging, configure up to five named entries:

```toml
[tower.clients.friend]
node_id = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
endpoint = "guard.example:9736"
```

This is an example key/address, not a recommended guard. Unknown fields are
rejected. W2a stores candidates and encrypted outbox data under `ldk/tower/`;
it does not connect, create sessions, spend sats or generate tower acks.
Pricing, retention periods and payment caps are TODO(W2b), pending decisions.
The hub-only channel rule remains unchanged.

Owner-authenticated `GET /api/v1/tower/status` returns a cached snapshot with
per-channel guarded/unguarded state counts, queued/sent/acked/expired deliveries,
W1 quarantine/retirement counts, capacity and coverage-gap flags, and the last
64 tower warnings from the current process. `available = false` and `error`
mean the snapshot is incomplete or stale. W1 record counts survive restarts;
warning history does not. Counts describe `to_local_only`; they make no HTLC
coverage claim. Corrupt unsigned journals may contain an unknown number of
missing states, so a coverage-gap flag is significant even when counts are zero.
Enabling staging after channel use cannot recover all missed historical states.

A channel counterparty is always excluded as its own guard. At least one
eligible ack is needed to count a state as guarded; every assigned delivery
must ack before the W1 signed source is removed. The signed handoff and outbox
have hard 10,000-state limits per channel. At capacity W1 retains unsigned
recovery data and reports deferred unguarded states; that recovery journal can
still grow. W2a has no sender to drain it, so this opt-in mode is for preparing
the core, not for claiming offline protection on a busy node.

Removed towers lose their local guard receipts; newly configured towers receive
candidates still in W1. Backfilling already-drained historical states and session
renewal are TODO(W2b). Explicit service expiry prunes local payloads once no
queued/sent delivery remains and makes expired receipts unguarded; commitment
age alone never expires a state. Runtime close pruning waits for LDK to archive
a resolved monitor, rather than the earlier `ChannelClosed` notification.
Remote sends/acks/deletes and authenticated expiry triggers are TODO(W2b).

### Longer breach window (optional)

Home starts with `--remote-unlock` (with or without `--local-owner-device`),
or with `--local-owner-device` and any password source, default to **2016 blocks**
(about two weeks) on the embedded LDK backend. This includes the
`HUB_ONLY_WHILE_LOCKABLE` profile for the whole run, after unlock too. There is
no separate home-node config flag: the startup flags select this policy, not
`tier`, `identity.hosted`, or the display-only `node.hosted_by` label.

An explicit value overrides the default, with a **288-block floor** (about two
days) for home nodes:

```toml
[lightning]
backend = "ldk"
our_to_self_delay_blocks = 500  # optional: about 3.5 days instead of two weeks
```

Home values outside 288..=2016 are refused at startup, before serving locked
mode or building the node, with an error naming
`lightning.our_to_self_delay_blocks` and the allowed range. The hub/LSP service
role (`[lightning.lsps2_service] enabled = true`) and ordinary starts without
either home flag retain W0's 144..=2016 range and LDK's 144-block default when
unset. A local-owner flag does not turn an enabled service into a home node;
`--remote-unlock` still refuses that conflicting service role under #257.

The value is the number of blocks a peer must wait before it can claim its own
balance after it force-closes. During that wait the unlocked node can punish a
revoked state. **This applies only to new channels**, in both directions,
including LSPS2 channels the hub opens to you. Existing channels keep their
negotiated value; restarting or changing this setting does not extend their
window.

The peer must agree. LDK peers accept up to 2016 by default, which is why the
setting cannot exceed 2016. **A peer whose maximum is below 2016 will refuse a
channel requesting the home default.** There is no automatic fallback to 144
or another shorter value. A channel open may initially return a channel id
before the peer rejects the handshake; the channel then never becomes ready,
and the node logs `LDK: channel closed` with the reason when LDK reports the
closure. An immediate failure is returned as a channel-open error. Inspect the
node/LDK logs for the peer's rejection reason; for a hub-initiated open, the hub
also sees the refusal. Agree on a supported delay (at least 288 for a home
node) with the hub/LSP before retrying.

The trade-off is the hub's liquidity: **the hub's own funds are locked for up
to about two weeks after the hub itself force-closes** under the home default
(the relative delay runs from commitment confirmation; block times vary).
A hub or LSP may price that lock-up into its fees. This setting does not set
your own wait when you force-close; that is chosen by the peer. It is not a
watchtower: if the box stays locked or offline beyond the breach window, the
risk above still applies.

## Hub-only channels: `HUB_ONLY_WHILE_LOCKABLE`

Started with `--remote-unlock`, the node opens and accepts new channels only with
the hub/LSP node ids listed under `[lightning.liquidity] providers` (every listed
provider, not only `selected_provider`). The rule holds for the whole run, after
unlock too, because the next reboot leaves every channel unwatched again:

- Owner `POST /api/v1/payments/open-channel` to any other peer returns 403 with
  `"code": "HUB_ONLY_WHILE_LOCKABLE"` and `"retry_allowed": false`. Nothing is
  dialed, funded or signed.
- The onboarding auto-channel worker gets the same refusal and leaves the invite
  pending.
- Inbound channel requests from any other peer are rejected before acceptance
  (`HUB_ONLY_WHILE_LOCKABLE: refusing inbound channel` in `ldk_node.log`).
  The hub's LSPS2 JIT channels are accepted as before.
- `[lightning.lsps2_service] enabled = true` opens channels to arbitrary clients,
  so `--remote-unlock` refuses to start with it.
- With no provider listed, or with a non-LDK backend, every new channel is refused.

Existing channels, payments, forwarding and closes are unaffected. The flag does
not close channels a node opened during an earlier start without it; close any
non-hub channels before relying on remote unlock. A start without
`--remote-unlock` keeps the previous behaviour. The rule relaxes only once
watchtowers exist that are not the channel's counterparty; a hub-run tower cannot
guard against the hub itself.

Peers get connection refused while the node is locked. The tier-2 relay is not a
session forwarder and does not queue messages for it. Paid messages are not
accepted, settlement fails, and senders are not charged for delivery.

## Remaining trust boundary

A stolen disk exposes the encrypted seed, box key and pairing records, but no
seed password. An attacker with both that disk and control of the pinned network
endpoint can impersonate the box at the next unlock and capture the password.
The same risk applies to an untrusted box operator. A secure element or PAKE
could change this boundary in a future release; neither is implemented here.
One person's box hosting another person's process remains self-custody in this
model, distinct from the `identity.hosted` hosted-custody setting.


## Enrollment tickets and box labels

On the box, with remote access configured, run:

```sh
konsensus pair-ticket --config /path/to/konsensus.toml --qr --ttl 24h
```

The CLI prints a `bitsov://pair/…` URI to its own terminal and, with `--qr`,
a terminal QR of that same URI. It never needs `--owner-control` or a control
socket. Package hooks can call this command; keep the output private and out of
service journals. Anyone who can read the ticket can pair once as `read+receive`.
Owner-device enrollment still requires [console approval or delegation](#enroll-your-first-owner-device);
a ticket never grants spend or identity authority on an initialized node.

The protected file `pairing/remote-access-link` (0600) is the ticket authority.
The daemon reloads atomic replacements within a second and at authentication.
Issuing a new ticket replaces the previous one. The default lifetime is 24 hours;
`--ttl` accepts positive `s`, `m`, `h` and `d` durations up to 365 days. Expiry is
stored as Unix seconds, so a restart never resets it. Unused tickets survive
shutdown and restarts, including a locked interval, but cannot be used while
locked. Consumption removes and syncs the file before creating a pairing: a crash
in that interval burns the ticket, so issue another if necessary. An already
created pairing can retry a lost response with the same device keys.

`pair-ticket` refuses while locked. Its conservative locked marker remains after
a stopped/crashed locked run, until a successful unlocked start refreshes public
identity metadata. For an initialized node, start unlocked with this version once
before issuing tickets: `identity/identity.json` contains both signed transport
proofs, and the CLI never reads or decrypts the seed. Pre-bootstrap tickets omit
`node_id` and identity signatures and carry only the persistent box public key.
On an empty box such a ticket grants the one first-run pairing, which can create
the identity (see below), so guard it like the seed itself.

The daemon continues to create a five-minute first-pairing ticket when no ticket
or paired clients exist. It only prints the protected file's path, never its URI
or code. CLI tickets can pair a second device on a running node. A ticket is
its own one-shot grant: it never opens the local `/api/v1/pair/request` window,
which still needs `pair-window` or an `admin` client.

Set a human-readable box label independently of custody:

```toml
[node]
hosted_by = "Rasmus's Pi"
```

The label appears in tickets, `/api/v1/node/lock` and `/api/v1/health` (`null` when
unset). Unknown `[node]` fields are rejected. The label must be 1–64 printable
characters without leading or trailing whitespace; control, bidi-override and
zero-width characters are refused. It is display text only: it neither
sets `identity.hosted` nor changes the sovereignty tier. A box hosting another
person's self-custody node is not the Cloud hosted-custody tier. Use one process,
data directory, seed, password, ticket and set of ports per person (for example,
`konsensus@<name>.service` instances). The OS operator can take a node offline and
read its encrypted seed, box key and pairing records; the network-impersonation
risk above still applies per person.

## Remote first run on an empty box

A headless box can be set up entirely from the owner's phone or Mac. Configure
`[api]`, `[remote_access]` and an `identity.mnemonic_file` that does not exist
yet, leave the data directory otherwise empty, and issue a ticket on the box:

```sh
konsensus pair-ticket --config /path/to/konsensus.toml --qr
```

Then start the same command as above (`--home`, no password source), for example
through the system unit, which may be installed before enrollment. The box serves
bootstrap mode over the box-static Noise tunnel and binds no peer port. The client:

1. Scans the ticket, pins its box key, and pairs with its code. This is the only
   first-run pairing; a second ticket is refused.
2. Stores the startup password (user-chosen for v1) and sends only
   `blake3(password)` to `create-pending`. It shows the phrase to the owner.
3. Sends the backup words, its Secure Enclave device key and the password to
   `finalize`, over the tunnel only. The loopback API refuses both calls.
4. Re-pins the box key from the identity-signed proof in the finalize response.

The box writes only `identity/mnemonic.enc`, records the device as
`enrolled_by: remote_first_run`, and exits with status 75. The system unit
restarts it into locked mode, and the client performs the first unlock with the
stored password immediately. Under a supervisor that does not restart on 75,
start the same command again yourself. If the password is lost before that
unlock, only the recorded phrase can recover the node. Details and error codes:
[remote first run](../security/pairing.md#remote-first-run-over-the-tunnel).
### Local offline safety alert

The unlocked node saves `offline-heartbeat.json` in its data directory: the last
successfully synced chain height and a Unix wall-clock timestamp. It atomically
replaces and syncs this file only when the synced height advances. Keep it with
the node data across restarts. Locked mode does not update it. The checkpoint comes from completion of the full
Lightning sync, not the manager height that can advance during a partial scan.
A separate atomic `offline-channel-windows.json` caches channel IDs and negotiated
windows when that list changes. This allows the reminder to work even when
startup cannot construct LDK because the chain source is unreachable. Such
cached channel data is marked `coverage_complete: false` until LDK is available;
it may include channels that have since closed. Neither file contains amounts.

On each start/unlock, and every 30 seconds while running, the node compares the
chain tip with that heartbeat. Each funded channel still listed by LDK is checked,
including disconnected or unusable channels. The window is **that channel's
negotiated `our_to_self_delay`**: how long the counterparty must wait after its
commitment confirms. It is not the delay on our own force-close, and is not read
from today's configuration. The shortest known window determines the overall
severity:

- Below 50%: no alert.
- At least 50%: **warning**.
- At least 80%: **critical**.

For a 2016-block channel, warning starts at 1008 blocks and critical at 1613
blocks. Existing channels may have much shorter windows. No open channels means
no breach-window alert. If the tip cannot be read or stops advancing, elapsed
time since the heartbeat is converted at 600 seconds per block; the larger of
observed lag and that estimate is used. `estimated: true` identifies this
fallback: it is a reminder based on time, not proof that those blocks were mined.
Clock jumps or unusually slow blocks can therefore produce an early reminder.

Read the amount-free `offline_safety` object on the existing owner-authenticated
`GET /api/v1/status`. It contains `blocks_offline`, `smallest_window_blocks`,
`percentage`, `severity` (`null`, `warning`, or `critical`), `estimated`, and
per-channel IDs, negotiated windows, percentages and severities. It is available
even when sync failure blocks payment operations. It is absent from the public
health response; unsupported Lightning backends return `offline_safety: null`.
`startup_alert` retains a startup warning/critical finding until exit, even after
catch-up makes the current severity clear. One WARN/ERROR alert line is emitted
per run when an alert is first raised; the status continues to update if the
severity changes.

A missing heartbeat (including the first start after upgrading) cannot establish
past offline time: `blocks_offline` is `null` until a heartbeat is established.
`coverage_complete: false` means heartbeat history or a channel's window is
unknown, or only cached channel data is available. `history_available_on_start` preserves whether this run had history;
`heartbeat_error` reports an unreadable heartbeat or a failed durable write.
Unknown history is not a clean bill of health.

**Unlock now**, leave the node running, and restore connectivity to its configured
chain source so it can sync and react. **Then check channels** in the owner status
and channel list for unexpected closes or pending recovery. For a critical alert,
act immediately; the remaining window may be short. An alert indicates time at
risk, not evidence that a peer cheated, and catching up does not prove a prior
breach was harmless. Do not reset the heartbeat to silence it. Keep the node
unlocked and syncing whenever channels are open.

This is a node-local reminder. The hub neither computes nor pushes it, and an
offline/locked node cannot deliver a live notification: it reports on unlock.
It does not extend negotiated windows or replace monitoring or a watchtower.
