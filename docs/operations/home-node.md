# Home node: unlock after a restart

Run one process, data directory, identity and password per person. Initialize
and [enroll an owner device](#enroll-your-first-owner-device) first. On a U1-capable unlocked start, the node writes
`identity/identity.json` and advertises its identity-signed box transport public
key to paired clients. Before enabling remote unlock, connect the owner device
to that unlocked node and ensure its client supports and pins that signed key.
Never learn a new pin from a locked node. Keep `pairing/box-transport.key` (0600)
and the public identity metadata intact across restarts.

Configure `[api].listen_addr` on loopback and `[remote_access].listen_addr` plus
`advertised_endpoint` for the Noise endpoint reachable by your device. To reach
it off the LAN, see [reachability](reachability.md). Then run:

```sh
konsensus start --config /path/to/konsensus.toml --remote-unlock --local-owner-device
```

The example [systemd unit](konsensus.service) uses these switches and
`Restart=on-failure`. Install it only after the unlocked migration and owner
key enrollment. There is no password file, `LoadCredentialEncrypted`, or
password in argv/environment. On reboot the box waits for the device to unlock;
it does not automatically retrieve a password from its disk. A plaintext seed or
missing/stale public identity metadata is refused. Repair metadata by starting
normally with the correct encrypted seed first. A positively empty data
directory starts [remote first run](#remote-first-run-on-an-empty-box) instead.

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
`--local-owner-device` additionally enables existing owner-approved spend intents;
without it those intents remain off with `seed_password_not_typed`.

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
   konsensus start --config /path/to/konsensus.toml --remote-unlock --local-owner-device
   ```

   Or start the [systemd unit](konsensus.service) configured with those switches.
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

## Channel capacity and hub-only admission

For embedded LDK (`[lightning] backend = "ldk"`), new channels have inclusive
capacity ceilings in **satoshis**. Defaults apply to existing configs that omit
the keys, in every start mode:

```toml
[lightning]
backend = "ldk"
max_channel_capacity_sats = 1000000       # 0.01 BTC per channel
max_total_channel_capacity_sats = 2000000 # 0.02 BTC across channels
hub_only_channels = true
```

The caps count the **full funding capacity**, including the peer's contribution,
not just your local balance. Manual outbound opens, automatic onboarding opens,
LSPS2 service opens and inbound requests (including trusted zero-confirmation
LSP requests) use the same admission lock. Ready, disconnected, unusable and
accepted-but-unfunded channels in LDK's channel manager all count. The snapshot
is taken from current manager state, including restored channels, on each
admission; parallel requests cannot each spend the same capacity allowance.
Unaccepted requests do not reserve capacity. Overflow or an unavailable admission
lock fails closed. Exact ceilings are allowed; zero refuses positive new capacity.

An outbound cap refusal reaches the owner API as HTTP 403 with
`"code": "CHANNEL_CAPACITY_EXCEEDED"` (per-channel) or
`"TOTAL_CHANNEL_CAPACITY_EXCEEDED"` (total), and `"retry_allowed": false`.
No channel is created by that refused operation. Inbound requests are rejected
before acceptance with the same code in the peer rejection and `ldk_node.log`.
LDK service retries still obey both ceilings. Changing config requires a restart.
An LSPS2 hub service has the same default caps; its operator must explicitly
raise them for a larger deployment. The onboarding subsidy
`[onboarding_subsidy] max_channel_sats` remains a separate spend ceiling and
neither overrides nor replaces these capacity limits.

For this **channel policy**, a home node is any embedded LDK node without
`[lightning.lsps2_service] enabled = true`. It defaults to hub-only whether the
seed is plaintext, typed at startup, supplied by descriptor, or remotely unlocked,
and whether or not `--local-owner-device` is used. This classification is broader
than the flag-based longer-breach-window profile described above.
Allowed peers are every node id in `[lightning.liquidity] providers` plus the
legacy `lightning.lsp_node_id`, if configured; selection or enabled state of
liquidity purchasing does not narrow this set. No configured peers means no new
channels. Invalid peer keys fail LDK startup.

Owner `POST /api/v1/payments/open-channel` to any other peer returns HTTP 403,
`"code": "HUB_ONLY_WHILE_LOCKABLE"`, and `"retry_allowed": false` before
connection or funding. Automatic opens get the same refusal; inbound non-hub
requests are rejected before acceptance. The owner can explicitly set
`hub_only_channels = false` to allow other peers only in non-lockable start
modes; the capacity caps still apply. Under `--remote-unlock`, this opt-out is
ignored: hub-only is mandatory for the whole run, including after unlock, and
an empty hub set refuses every new channel (`HUB_ONLY_WHILE_LOCKABLE`). Opting
out in a non-lockable mode increases the set of counterparties the owner must
trust during unmonitored periods. An enabled
LSPS2 service defaults to unrestricted peers, refuses explicit hub-only config,
and still cannot run with `--remote-unlock`.

Owner-authenticated `GET /api/v1/status` exposes the active backend policy:

```json
"channel_safety": {
  "max_channel_capacity_sats": 1000000,
  "max_total_channel_capacity_sats": 2000000,
  "hub_only": true
}
```

This object is absent from public health, and is `null` in owner status when the
backend is unavailable or does not implement capacity enforcement. Locked mode
has no live owner status or LDK backend. These caps are implemented only for the
embedded LDK backend, not external LND or mock backends. The pre-existing
remote-unlock outbound peer refusal on non-LDK backends remains, but does not
claim control over their inbound channels.

### Limits and hub trust

**Hub-only is a trust restriction, not protection against a dishonest hub.**
The home node retains its keys, but while it is locked/offline no local LDK
monitor checks the chain or punishes a revoked commitment. Without an effective
independent watchtower, the owner trusts the hub/LSP not to exploit that absence.
A tower operated only by the channel counterparty is not independent protection
against that counterparty. The current tower staging/transport work must not be
read as a promise of deployed watchtower coverage.

Caps bound **newly admitted channel capacity**, not all possible losses or the
wallet's total value. They do not close, shrink or reject startup because of
existing over-cap or non-hub channels. Existing channels continue payments,
forwarding and closes; their full listed capacity counts against subsequent
opens. If already above the total ceiling, no positive-capacity open fits. Review
and close unwanted existing channels before relying on this policy. Lowering
config does not retroactively make existing exposure comply. Closing/on-chain
claims no longer listed by the channel manager, wallet funds, fees and HTLC
resolution risks are not included in the total; the policy is not a lifetime
spend budget or a guaranteed maximum loss.

Capacity-changing splices could otherwise bypass these ceilings. Embedded LDK
therefore rejects new inbound splices and both outbound splice-in and splice-out
operations while caps are active. A splice already negotiated before upgrading
is not undone; let it resolve and inspect actual capacity. There is no automatic
fund movement or channel closure on upgrade, and the caps do not extend breach
windows or keep a locked/offline box monitored.

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

Then start the same command as above (`--remote-unlock --local-owner-device`, no
password source), for example through the systemd unit. The box serves bootstrap
mode over the box-static Noise tunnel and binds no peer port. The client:

1. Scans the ticket, pins its box key, and pairs with its code. This is the only
   first-run pairing; a second ticket is refused.
2. Generates the startup password, stores it, and sends only
   `blake3(password)` to `create-pending`. It shows the phrase to the owner.
3. Sends the backup words, its Secure Enclave device key and the password to
   `finalize`, over the tunnel only. The loopback API refuses both calls.
4. Re-pins the box key from the identity-signed proof in the finalize response.

The box writes only `identity/mnemonic.enc`, records the device as
`enrolled_by: remote_first_run`, and exits with status 75. `Restart=on-failure`
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
