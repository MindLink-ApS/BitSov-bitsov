# Home node: unlock after a restart

Run one process, data directory, identity and password per person. Initialize
and enroll an owner device first. On a U1-capable unlocked start, the node writes
`identity/identity.json` and advertises its identity-signed box transport public
key to paired clients. Before enabling remote unlock, connect the owner device
to that unlocked node and ensure its client supports and pins that signed key.
Never learn a new pin from a locked node. Keep `pairing/box-transport.key` (0600)
and the public identity metadata intact across restarts.

Configure `[api].listen_addr` on loopback and `[remote_access].listen_addr` plus
`advertised_endpoint` for the Noise endpoint reachable by your device. Then run:

```sh
konsensus start --config /path/to/konsensus.toml --remote-unlock --local-owner-device
```

The example [systemd unit](konsensus.service) uses these switches and
`Restart=on-failure`. Install it only after the unlocked migration and owner
key enrollment. There is no password file, `LoadCredentialEncrypted`, or
password in argv/environment. On reboot the box waits for the device to unlock;
it does not automatically retrieve a password from its disk. A plaintext seed,
missing/stale public identity metadata or an empty data directory is refused.
Repair metadata by starting normally with the correct encrypted seed first.

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

LDK has no watchtower client here, and creating a justice transaction requires
keys: there is no keyless watch-only protection. Keep channels only with the
reputable hub while this gap exists. A later change may negotiate an inbound
`our_to_self_delay` of at least 288 blocks; this release does not set that value.

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
Owner-device enrollment still requires delegation from an existing owner device;
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
`node_id` and identity signatures and carry only the persistent box public key;
remote bootstrap itself is a separate P2 feature.

The daemon continues to create a five-minute first-pairing ticket when no ticket
or paired clients exist. It only prints the protected file's path, never its URI
or code. CLI tickets can open pairing for a second device on a running node.

Set a human-readable box label independently of custody:

```toml
[node]
hosted_by = "Rasmus's Pi"
```

The label appears in tickets, `/api/v1/node/lock` and `/api/v1/health` (`null` when
unset). Unknown `[node]` fields are rejected. It is display text only: it neither
sets `identity.hosted` nor changes the sovereignty tier. A box hosting another
person's self-custody node is not the Cloud hosted-custody tier. Use one process,
data directory, seed, password, ticket and set of ports per person (for example,
`konsensus@<name>.service` instances). The OS operator can take a node offline and
read its encrypted seed, box key and pairing records; the network-impersonation
risk above still applies per person.
