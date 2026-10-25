# Paired device keys and signed relation intents

Relation ladder, Before-Mexico steps 1–3. Direction:
`MindLink-Private/pm/projects/bitsov/research/RELATION-LADDER-AND-DEVICE-KEYS.md`.

## What changes for the owner

Before: every spend window was `konsensus grant --op <id>`, typed at the node,
with a code copied from the node's terminal.

Now:

1. **Once per device.** The app creates a P-256 key in the Mac's Secure
   Enclave, gated by Touch ID. It asks the node to register the key. The owner
   runs the command the app shows, once:
   `konsensus device approve --op <id> --config <path>`. That command prints the
   device name and a fingerprint (`XXXX-XXXX-XXXX-XXXX`) to compare with the
   app's screen, then asks for the short code the node printed on its own
   terminal, or delivered in an owner-only approval file on a headless owner-run
   node (see [owner approvals](../v2/OWNER-APPROVALS.md)). It signs only with an
   **encrypted** recovery phrase, whose
   password is typed at the prompt. It refuses a plaintext phrase before asking
   anything. The CLI also signs the registration with the seed-derived
   **owner-approval key**, over `client_pubkey`, `epoch`, the node and the
   device key. Outside local-owner mode the node keeps only that key's public half and re-verifies the
   signature on every use, so a device-key record written into `data_dir`
   without that signature authorizes nothing. This covers device-key records
   only: spend grants in the same file are not yet signed
   (`docs/protocol/ACCOUNT-LAYER.md` §3 and §4 GAPs).
2. **Per contact, one tap.** To let messages pay a contact, the app signs a
   `RelationIntent` (peer, budget, per-act maximum, window, nonce) with that
   key. Touch ID unlocks the key for that one signature. The node verifies the
   signature and opens an envelope for exactly that peer.
3. **Recovery.** `konsensus grant` with the console code still works. If the
   device is lost, the owner runs `konsensus device revoke --key <id>` (or the
   app revokes its own key). An epoch bump or revoking the pairing also
   retires the device's keys.

On a positively empty local node, [two-phase bootstrap](pairing.md#two-phase-local-bootstrap)
can enroll the first device with `--password-fd --local-owner-device`. After
backup confirmation and P-256 possession proof, the node transiently derives
the same owner signing key and signs the same approval tuple. The seed is
persisted only as `mnemonic.enc`; the record says `enrolled_by: local_first_run`.
[Remote first run](pairing.md#remote-first-run-over-the-tunnel) does the same
over the box-static tunnel and records `enrolled_by: remote_first_run`.
Later enrollment can use the owner console or an existing owner device's
signature in local-owner mode.

### Delegating another owner device

On `--local-owner-device` starts the node retains the seed-derived owner
signing key in zeroizing memory for the life of the service. A new paired
device requests enrollment with its P-256 possession proof. The response and
pending status include `delegation_message`: the exact UTF-8 bytes below
(no trailing newline). The app presents these terms on an already enrolled
owner device for approval; it must verify the node and new device fingerprint
before signing, rather than blindly signing bytes supplied by another device.

```text
bitsov-owner-delegation-v1
node:{fp}
client_pubkey:{new pairing public key}
epoch:{new pairing epoch}
device_key:{new SEC1 uncompressed public key hex}
op_id:{pending operation id}
nonce:{server-issued 16-byte lowercase hex nonce}
```

The approver sends `{approver_key_id, signature}` to
`POST /api/v1/pair/device-key/{op_id}/delegate`, using **the approver's paired
token**. The target may belong to another paired client. The signature is
P-256/SHA-256 DER hex. The node re-verifies the approver's owner approval and
current epoch, verifies the exact pending tuple, then signs the standard
`owner_approval_message` and records `enrolled_by: "device:<approver_key_id>"`.
The pending request and nonce are consumed atomically with enrollment. They
survive restart until expiry or cancellation only for legacy non-SAS requests.
SAS ceremonies require a fresh request after restart; legacy requests with no nonce
need a fresh request for delegation. Replays, changed tuples and revoked
approvers fail. Console-only and ordinary sidecar starts refuse delegation.
Console `device revoke` and pairing epoch bumps retire delegated keys and
end their envelopes exactly as for console-enrolled keys. Provenance is
informational, so revoking an approver does not cascade to previously approved
keys on other pairings; revoke those keys explicitly when needed.

### Adding a device over the Noise tunnel

Available while unlocked in `--local-owner-device` mode (including `--home`),
with the owner signing key held in memory. Locked mode exposes none of these
routes. Owner-local v1 delegation remains compatible for legacy non-SAS
requests; **the legacy tunnel `/delegate` route requires SAS v1 enrollment and
v2 signing**. Opt-in claimless SAS v2 uses the separate second-device approval
route described below.

All routes below require the approver's live paired token on its own authenticated
Noise connection. The key must belong to that pairing and current epoch and
carry a valid seed-derived owner approval. An ordinary pairing, including an AI
client with read/receive or a spend grant, has no such authority. Key revocation,
pairing revocation/rotation and epoch changes are checked again under the same
lock as issuance or enrollment; a stale session or token cannot bypass them.

| Route | Request / response |
|---|---|
| `GET /api/v1/pair/ticket?approver_key_id=<key>` | Returns `{nonce, message}`. The server chooses a 32-byte hex nonce, bound to the caller's key and epoch for at most five minutes. Repeated reads reuse the live nonce. |
| `POST /api/v1/pair/ticket` | `{approver_key_id, nonce, signature}` → `{uri, expires_at}`. P-256/SHA-256 DER hex signature over the bytes below. |
| `GET /api/v1/pair/device-key/pending?approver_key_id=<key>` | Returns `{pending: [...]}` for live SAS operations. Lets the owner discover the new device without transferring an operation id. Expired, cancelled, completed and restarted ceremonies are omitted. |
| `GET /api/v1/pair/device-key/{op_id}/delegation?approver_key_id=<key>` | Owner-only view of the new device's operation: `op_id`, `client_id`, `name`, `public_key`, `expires_at`, `sas_version`, `box_nonce`, four `sas_words`, and `delegation_message` (null until SAS finalization). The client obtains the operation id from the owner pending list. |
| `POST /api/v1/pair/device-key/{op_id}/delegate` | Existing `{approver_key_id, signature}` body; returns `{op_id, key_id, status: "registered"}`. |

Ticket signature bytes (UTF-8, no trailing newline; `node` is the identity
fingerprint):

```text
bitsov-ticket-v1
node:{fp}
nonce:{server nonce}
```

Ticket issuance consumes the challenge. The QR URI is PairLink v2 with signed
endpoints and box transport pin. The ticket code is an opaque `owner_`-prefixed
random value, valid once for five minutes. Only its hash is kept in memory;
neither code nor URI is written to disk or the audit log. Challenges and unused
tickets are invalid after restart. Five successful issues per rolling 15 minutes
are allowed node-wide; challenge reads are capped at 30 per minute (HTTP 429).
Invalid signatures do not consume the challenge. Issuer authority is rechecked
when consuming the ticket, so revocation also invalidates unused tickets. Ticket
consumption and pairing creation are serialized, including concurrent requests.
Exact ticket-auth replays fail; after a lost success response, reconnect with
saved pairing keys **without** the code. Tickets never open `/pair/request`.

The new device completes the existing claim-bound SAS ceremony on its own Noise
session; see [SAS protocol](pairing.md). The owner view discloses neither claim
code nor commitment. The enrolled device compares the displayed four words
before signing these bytes:

```text
bitsov-owner-delegation-v2
node:{fp}
client_pubkey:{new pairing public key}
epoch:{new pairing epoch}
device_key:{new SEC1 uncompressed public key hex}
op_id:{pending operation id}
nonce:{server-issued 16-byte lowercase hex nonce}
sas_digest:{full lowercase hex SAS digest}
```

Unconfirmed, cancelled, expired, restarted or legacy non-SAS operations cannot
be delegated through the tunnel. Wrong-node/tuple/digest signatures, self-approval
with an unenrolled key, revoked keys and replays fail. No seed-derived signature
is produced until every existing delegation and SAS check passes. Pending
operation consumption and enrollment persistence are atomic. Ticket and
SAS-view responses use `Cache-Control: no-store`.

Audit events `pair.ticket_issued`, `pair.ticket_refused`,
`pair.device_delegated` and `pair.device_delegation_refused` record the approver
pairing, epoch, key id and (for delegation) operation id. They exclude nonce,
ticket, signature, SAS and claim secrets. Enrollment does not convey the unlock
password or enable console grants.

### Keep a second owner device

`GET /api/v1/pair/device-keys` reports `owner_device_count`, a **node-wide**
count of distinct owner-approved keys bound to current paired-client epochs.
Revoked, stale, unverified and tampered records do not count. If startup cannot
supply the owner verifier, the verified count is zero. The listed
`device_keys` remain scoped to the requesting client.

The app must warn when the count is one, and **the phone must never be the
only owner device**: enroll and retain a Mac or another non-phone owner device
before enabling phone ownership, and prevent app flows that leave only the
phone. The node cannot infer hardware type from a P-256 key or device name;
the count supports this app rule, rather than attesting a device's hardware.
Console recovery and revocation remain available even for the last key.

## API

| Route | Who | Effect |
|---|---|---|
| `GET /api/v1/pair/device-keys` | paired | `{node, client_id, epoch, owner_control, local_owner_device, owner_device_count, device_approvals, device_keys}`. `node`, `client_id` and `epoch` are what a relation intent signs; registration proofs sign `node` and `client_id` |
| `POST /api/v1/pair/device-key` | paired | `{public_key, name, proof}`. Creates a *pending* registration and nothing else |
| `POST /api/v1/pair/device-key/{op}/delegate` | local mode, approver paired token + enrolled device signature | approves the exact pending tuple |
| `GET/DELETE /api/v1/pair/device-key/{op}` | paired, own | status (`pending/registered/expired/lost/absent`) / cancel |
| `DELETE /api/v1/pair/device-keys/{key_id}` | paired, own | retire own key; its envelopes end |
| `POST /api/v1/pair/relation-intent` | paired + device signature | opens or renews one peer's envelope |
| `DELETE /api/v1/pair/elevation/{op}` | paired, own | cancel a pending console grant request |
| control socket `ApproveDeviceKey` | owner | registers the key (short code or full line) |
| control socket `RevokeDeviceKey` | owner | retires a key |

The device signs these exact bytes. `node` is the node's identity
fingerprint, `client_id` is the pairing's id, and both are taken from the
node's own state, never from the request body:

```
bitsov-device-register-v1\nnode:{node}\nclient:{client_id}\npublic_key:{hex}
bitsov-relation-intent-v2\nnode:{node}\nclient:{client_id}\nepoch:{epoch}\ndevice:{key_id}\npeer:{peer}\nlevel:{level}\nbudget_msat:{b}\nper_act_max_msat:{p}\nwindow_secs:{w}\nissued_at:{t}\nnonce:{n}
```

`epoch` is the pairing epoch on the caller's token (`GET /api/v1/pair/device-keys` returns the same value). The node rebuilds these bytes itself; a body field cannot substitute a different epoch. `GET /api/v1/status` advertises `relation_intent_v2`.

`bitsov-relation-intent-v1` omitted `epoch`. It is not accepted. Delegation v1/v2 and ticket v1/v2 keep an older domain only for a different operation that is fully bound by its own bytes. Accepting v1 during a transition would leave the cross-epoch replay open until the transition ended. A device holding a v1 signature signs the v2 bytes again. The acceptance window stays ±300 seconds.

Re-approving the same public key without an epoch bump does not change the signed epoch, so this binding does not cover that case.

Signatures are ECDSA P-256/SHA-256, DER encoded, which is what CryptoKit's
`derRepresentation` produces. Verification uses `ring`, which rejects points
that are not on the curve.

## Enforcement

`--local-owner-device` is an explicit live-start alternative to owner-run mode
for an existing enrolled key. It requires a descriptor password and an encrypted
seed with no plaintext sibling; the owner signing key stays in zeroizing memory
for delegation. Enrollment requires an existing owner device signature.
It never enables console grants, front-door or replacement. First-contact
and ordinary spend windows can be approved by a **different enrolled owner
device** through [owner-approval-v1](../v2/OWNER-APPROVALS.md), over that device's
own token and authenticated Noise session. Local spend scopes, staging and
dispatch require an owner verifier and either a live `device:` relation grant
with a `recipients_only` budget or a verified owner-approval-v1 spend receipt. Startup
refuses local mode before writing files if the owner verifier cannot be derived.
Console grants on disk stay inactive. See
[password input](../operations/password-input.md) for launcher trust and release
requirements. `DeviceKey.enrolled_by` defaults to `console`
for older records and is informational; it grants no authority.

In local mode, `apply_relation_intent` clears the budgets on all other grants
for that client, including console grants.

New and renewed relation grants have a per-call ceiling of 6,000 msat (6 sats),
including fan-out and routing fees, without reducing the total budget. A lower
signed per-act limit still applies. Owner-device `spend_grant` budget approvals
are also messaging grants: the node narrows their proposed per-call limit to
6,000 msat before presenting the terms for signature. `GET /api/v1/pair/grant`
and `konsensus pair-status` expose the effective non-payment `per_call_max_msat`.
Quotes over this ceiling are refused before payment with a fixed explanation
and an info log carrying `reason="per_call"`.

Invoice payments and keysend cannot draw from either messaging grant class;
they require separate explicit owner authority. Console payment budgets retain
the owner's chosen limits. No stored schema or existing signed terms are
rewritten: every non-payment reservation uses the lesser of the stored limit
and 6,000 msat, including console grants and existing live grants on their
first request after upgrade. Renewal is not required.

A relation grant is the client's one budget grant, marked `recipients_only`:

- Only a recipient with a **live** envelope can be paid. Everyone else is
  refused (`recipient`), even if the total has budget left. An owner console
  grant keeps its old behaviour, where unlisted recipients fall through to the
  total.
- Each recipient has its own cap, its own **per-act maximum** and its own
  expiry. A room act that pays several envelope peers is one call, and each
  peer is checked separately.
- A new tap for the same peer adds `budget_msat` on top of what that peer has
  already used. It never lowers another peer's envelope.
- Signing an intent replaces a console budget window for that client. The
  one-budget-per-client invariant stays.
- Checks run under the pairing mutex and are persisted before any dispatch,
  on the same reservation path as every G1 debit.
- **Each recipient's deadline is rechecked at dispatch** (`with_spend_authority`),
  not only at reservation. A relation grant stays live until its latest
  envelope, so without this check a payment reserved inside peer A's 60 s
  window could dispatch after it ended, riding on peer B's 3600 s window. If
  A's envelope is renewed by a new signature, a still-pending reservation to A
  may dispatch in the new window. Its amount was counted in the used total
  that the renewal builds on.

### Per-approval envelope identity

`GET /api/v1/status.api_capabilities` advertises `relation_envelope_id_v1`.
Each accepted contact intent creates a fresh, node-generated random
`envelope_id`, including renewal with identical terms. It is an opaque string,
independent of the signed nonce and the aggregate relation grant's `op_id`.
The node persists it atomically with the envelope and replay nonce before
returning success:

```json
{
  "envelope_id": "<approval B>",
  "grant": {
    "op_id": "<aggregate relation grant>",
    "envelope_id_by_recipient": {
      "<peer node id>": "<approval B>",
      "<legacy peer node id>": null
    }
  }
}
```

The abbreviated `grant` above retains all existing budget/expiry fields.
`GET /api/v1/pair/grant` exposes the same `grant.envelope_id_by_recipient` map,
keyed like `per_recipient_msat`. Replacing A with B reports B for that recipient
while preserving other recipients' identities and the aggregate `op_id`.
Restart preserves B. Reads, spending and token refresh do not mint IDs.
Known recipient caps without recorded envelope identity (including legacy and
console grants) serialize as explicit null; an absent recipient is unknown and
must also be treated as null. No ID is inferred from terms, expiry or `op_id`.
Expiry and the existing grant/budget checks still govern whether an envelope
can be used; the ID alone conveys no authority.

An app can bind a waiting "approve and send" message to the exact ID returned
by its approval and compare that ID with the recipient's current envelope.
It must not substitute B for A or infer a match from unchanged amounts. This
identity contract does not add a send-time compare-and-swap check; existing
reservation/dispatch semantics above remain in force. Signed intent bytes and
nonce replay refusal are unchanged.

Pairing storage **v8** adds the per-recipient identity map. v2–v7 files load
missing identities as unknown and migrate on the next successful write;
legacy approvals never acquire fabricated IDs. A fresh approval gives only
its recipient a new ID. This migration is forward-only: older binaries refuse
v8. Preserve the latest store and roll forward; do not lower its version,
strip fields or restore stale authority to downgrade. See
[upgrade guidance](../UPGRADING.md#rc16--rc17-pairing-storage-v8).

An intent is refused, and nothing is written, when any of these holds:

- the node was neither started in owner-run mode nor started with
  `--password-fd <n> --local-owner-device`;
- the key is unknown, revoked, belongs to another client, or was registered
  at an older epoch;
- the signature does not verify for this node, this client and this pairing epoch;
- `issued_at` is more than 5 minutes from the node's clock;
- the nonce was already used (nonces are kept durably for an hour);
- the level is not 1 (Contact; Knock arrives with first contact, step 4);
- the window is outside 1 min–24 h;
- the budget is 0 or above 100,000 sats, or the per-act maximum is above the
  budget;
- the client has applied more than 30 intents this hour.

The pairing store moves to version 3. A version-2 node refuses the file
instead of reading a relation grant as an unrestricted budget.

## Durable approvals (step 3)

Pending console grants and device registrations were already stored on disk.
Only their codes lived in memory, so a restart made them unapprovable. Now an
owner-run node prints **fresh codes** for every surviving approval when it
starts (`reissue_owner_challenges`), and the app keeps waiting on the same
operation. Old codes stop working. `lost` now means only "cancelled by wrong
codes". The client can withdraw its own pending request (`DELETE …`).

## Security argument

**What the owner proves, and when.**
- *Registration* requires a secret delivered to the node's controlling terminal
  or its owner-only approval file (see `pairing.md`), plus the owner-key
  signature. Headless delivery trusts the node's OS account and data directory;
  keep the paired app outside that boundary.
- The registration request carries a signature by the key being registered
  (proof of possession), so a client can't register a key it doesn't hold, or
  replay one made for another node or pairing.
- The owner also compares the device fingerprint shown by the node's CLI with
  the one the app shows.

**What each spend envelope proves.** A signature by a key the owner
registered, over the exact peer, amounts, window, node, pairing and a fresh
nonce. The node accepts that signature or nothing. There is no "user
confirmed" flag, and a paired token alone writes nothing.

**Why this is no weaker than the console code for the threats it faced.**
- A browser page, another OS user, or a remote peer can't reach the device
  key. The Secure Enclave never releases it, and every use needs Touch ID.
- A process that steals the app's data directory, token or the key's
  encrypted blob can't sign anywhere else, because the blob only works inside
  that Mac's Enclave. On that Mac it can only *ask* for a Touch ID tap, which
  the owner sees as a prompt they didn't expect.
- A replay is refused by the durable nonce. A signature is useless on another
  node or pairing, because both are part of the signed bytes.
- A stolen or wiped Mac is handled by revoking its key.

**What it deliberately changes.** The owner's presence now comes from the
device they hold (Touch ID), not from the node's terminal. That is the
direction set for onboarding without logins: the node can run anywhere, and
the biometric lives on the device.

**Residual risks, stated plainly.**
- *The node can't verify that the key is in hardware.* macOS gives an app
  outside the App Store no key attestation. If the app is compromised **at
  registration**, it could register a software key. The owner's one-time
  approval, including the fingerprint comparison, is the trust root for that
  moment.
- *What you see is what the app shows.* A compromised app can show one thing
  and ask Touch ID to sign another, and the system dialog shows the app's own
  reason text. Every such signature still costs a physical tap, is capped per
  peer, per act and in time, and can't exceed 100,000 sats per envelope. The
  audit line (`device-signed relation envelope opened`) records every
  envelope.
- *Biometry changes.* The key uses `.biometryCurrentSet`: adding or removing a
  fingerprint makes it unusable, and the device must be registered again.
  This is a deliberate fail-closed choice.

**Known limits, accepted for this step.**
- The per-act maximum is checked per reservation. A send that also pays a
  re-admission reserves in parts, so one such send can pay a peer more than
  the per-act maximum, but never more than the peer's envelope.
- A renewal adds its budget on top of what the peer has used, including
  in-flight reservations. If one of those later fails, the released amount
  stays usable in the new window. Cumulative spend never exceeds the sum of
  the signed budgets.
- A live relation grant gives the token the `spend` scope. Routes gated on
  `spend` that move no value (such as the file-upload gate) accept it too.
- Pending identity replacements also get fresh codes after a restart. As
  before, they accept only the full console line.

## Separate-device spend, first-contact and breaker-reset approval

`owner_device_approval_v1` adds proposal-only paired requests and tunnel-only
approval by another owner device. The node renders the exact requester/node
bindings, grant snapshot, budget terms, operation, nonce and expiry; the owner
signs those bytes. `intent_key` rechecks the owner attestation and current epoch.
AI/read-only tokens without an enrolled owner key, revoked keys, and the
requesting pairing itself cannot approve. Consumption and grant persistence
share the pairing mutex, with bounded request/approval rates and secret-free
audit events. First contact reuses console budget checks, lasts at most two
minutes and is consumed once. See [the protocol](../v2/OWNER-APPROVALS.md) for
wire examples, signed receipts, status and compatibility.

The additive `owner_device_approval_breaker_reset_v1` sub-flag allows a different
enrolled owner device to approve `breaker_reset`. A paused pairing can never
reset itself, even with an enrolled key. Exact signed terms include the grant,
tripped breakers, remaining budget, failure streak, unresolved slots and reset
quota. The node rechecks the complete meter snapshot and reset generation under
the pairing mutex. Reset preserves spent budget, pending reservations, dedupe,
expiry and restrictions. Three device resets per grant per rolling day are
persisted across restart and console reset; successful and refused approvals
are audited. Pairing storage v7 prevents older binaries discarding this state.
Console reset and root-of-trust operations retain their existing authority paths.

### Claimless second devices (rc20, opt-in)

`[pairing] second_device_enrollment = false` remains the default. With it enabled
on an unlocked owner-device node, use the owner's **Add a device** screen or
`konsensus pair-ticket --second-device --qr`. The console ticket lasts 10 minutes
by default (`--ttl`, maximum 30 minutes) and requires an existing owner device.
Open **Add a device** on that device so it polls for the request. The claim code
is used only for the first device. Older apps cannot complete this v2 flow.

The new device automatically finalizes SAS v2. **The app shows SAS words only
once `approval_message` is non-null.** The approver compares the four words and
approves with Touch ID / Face ID. It reconstructs the signed message, checks its
pinned node, expiry and ticket id, and treats the device name as untrusted text.
An owner-device QR must be approved on the device that issued it; a console QR
can be approved on any enrolled owner device. The new device has no “They match”
button. Its “They don't match” action cancels the attempt.

On an owner control socket, `device approve --op <id>` can complete a confirmed
v2 request using the existing console code and encrypted-phrase signature.
`device reject --op <id>` (also `pair-cancel --op <id>`) removes the v2 request
and its provisional pairing immediately. `pair-reset-sas` clears both the v1
failure counter and the decaying v2 mismatch window.

`device list` shows enrollment provenance and the approver's name when that key
still exists. Revoking a key alone ends its envelopes; `--with-pairing` also
invalidates its pairing and tokens. It lists descendants left behind. To remove
a lost or malicious approver and everything it approved:

```sh
konsensus device revoke --approved-by <key_id>
konsensus device revoke --approved-by <key_id> --keep <trusted_key_id>
# Equivalent traversal starting with a live key:
konsensus device revoke --key <key_id> --cascade
```

The walk includes the root and follows both `device:` and `second_device:`
provenance transitively, even when the root was already revoked. It is cycle-safe.
The walk uses the provenance still stored on live keys. If an intermediate
approver was previously deleted without cascading, run `--approved-by` on that
deleted key id too: its former parent can no longer discover the missing edge.
The plain `--key` preview lists descendants and the follow-up command before
deleting that edge. Repeat `--keep` to preserve keys; their children are still visited. Pairing
revocation affects every key on that pairing, so a kept key sharing a pairing
with a revoked key causes a refusal. Review the displayed chain, pairings and
remaining owner count before typing `revoke`. A changed preview requires a new
confirmation. Reaching zero owners is refused unless `--allow-zero-owner` is
explicit: recovery then requires the owner console. Keep a trusted owner key
when possible.

For incident response, revocation fails closed without `--owner-control` if the
pairing holds the last owner key or a stored owner-signed device key whose
signature the running process cannot verify. Restart with `--owner-control`
before revoking it through the console's preview and confirmation flow; removing
the last owner additionally needs `--allow-zero-owner`. Stop any home service
before starting the unlocked operator process against the same data directory;
see the [home-node runbook](../operations/home-node.md#add-and-recover-a-second-owner-device-rc20).
Disabling enrollment or re-pairing the same public key cannot bypass the guard.
