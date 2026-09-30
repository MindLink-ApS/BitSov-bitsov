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
   terminal. The CLI also signs the registration with the seed-derived
   **owner-approval key**, over `client_pubkey`, `epoch`, the node and the
   device key. The node keeps only that key's public half and re-verifies the
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

## API

| Route | Who | Effect |
|---|---|---|
| `GET /api/v1/pair/device-keys` | paired | `{node, client_id, owner_control, device_keys}`. `node` and `client_id` are part of every message the device signs |
| `POST /api/v1/pair/device-key` | paired | `{public_key, name, proof}`. Creates a *pending* registration and nothing else |
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
bitsov-relation-intent-v1\nnode:{node}\nclient:{client_id}\ndevice:{key_id}\npeer:{peer}\nlevel:{level}\nbudget_msat:{b}\nper_act_max_msat:{p}\nwindow_secs:{w}\nissued_at:{t}\nnonce:{n}
```

Signatures are ECDSA P-256/SHA-256, DER encoded, which is what CryptoKit's
`derRepresentation` produces. Verification uses `ring`, which rejects points
that are not on the curve.

## Enforcement

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

An intent is refused, and nothing is written, when any of these holds:

- the node was not started in owner-run mode;
- the key is unknown, revoked, belongs to another client, or was registered
  at an older epoch;
- the signature does not verify for this node and this client;
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
- *Registration* keeps the existing guarantee. It needs a secret printed only
  to the node's controlling terminal (see `pairing.md`), so the app cannot
  register a key by itself.
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
