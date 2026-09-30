# Remote signer and custody modes (design)

Status: design for M1/M2. Normative for the custody labels (§2, §6), which
ship now. The signer protocol (§3 to §5) is not built; every **GAP** marks
that. It extends `ACCOUNT-LAYER.md` §7.

Doctrine this must not break (genesis `01_Core_Module_and_Concept.md` §1.2,
`BITSOV-NORTHSTAR.md`):

- **The node is the sovereign identity.** A cloud VM may give a node
  reachability and uptime. It must not become the owner.
- **Data lives only on sender and receiver nodes.** A hosted node is still one
  of those nodes, but it is on a machine the owner does not control, and the
  app must say so.
- **The Cloud tier already promises this.** `NodeTier::Cloud` is documented as
  "the operator may provide reachability but must not hold user keys". Today
  every node holds its seed, so that promise is false on a VM. This document
  makes it either true (a remote signer) or visibly not true (the
  `hosted_custody` label).

## 1. The one rule

> A node that holds its own seed can spend, sign and approve as the owner.
> Whoever controls the machine it runs on can do the same.

So there are only two honest ways to run a node on someone else's machine:

1. The seed and the owner keys stay on **owner hardware** (the owner's Mac or
   phone, or a hardware key). The hosted node asks that **remote signer** for
   every signature that moves money or speaks for the owner.
2. The seed is on the VM, and the app says **hosted custody** everywhere the
   node's money or identity is shown.

There is no third option that pretends to be full remote signing. "Encrypted
on the VM" is not one: the node decrypts the seed into memory at start, and
the operator can read that memory. A **money-only** interim (`money_signer`)
is allowed only when it is labelled as such and discloses that the identity
root stays on the server (§2).

## 2. Custody modes

The node reports one value in `GET /api/v1/status` as `custody_mode`
(owner-only). The app shows it as a badge beside the node.

| `custody_mode` | Meaning | Who can spend / speak | App badge |
|---|---|---|---|
| `local_seed` | The seed is a plaintext `mnemonic.txt` on the node's machine | Any program running as the node's OS user | **Seed on this machine** |
| `encrypted_seed` | The seed is an encrypted `.enc` with no plaintext copy beside it | The node while it runs; at rest, only with the password | **Encrypted seed** |
| `hosted_custody` | The node holds its seed on a machine operated for the owner (`tier = "cloud"`, or `[identity] hosted = true`) | **Whoever runs that machine** | **Hosted custody** (warning colour) |
| `money_signer` | Money and owner-approval keys are on the owner's signer; the **identity root stays on the VM** | Money: only the owner's signer. Identity: whoever runs the VM | **Money on your device** (warns that chat identity is server-held) |
| `remote_signer` | The node holds no seed and no owner key, including the **identity root**. It asks the owner's signer | Only the owner's signer, within its policy | **Your keys, remote node** |

Precedence, highest first: `remote_signer`, then `money_signer`, then
`hosted_custody`, then `encrypted_seed`, then `local_seed`. An encrypted seed
on a hosted machine is `hosted_custody`, because the node decrypts it into
the operator's memory.

**Gate for the full label.** A node may report `remote_signer` only when all
of the following hold:

```
remote_signer_allowed =
    money_keys_off_vm
    && owner_approval_key_off_vm
    && identity_root_off_vm
```

If money signing is ready but the identity root is still on the VM, the node
reports `money_signer`, never `remote_signer`. The app badge for
`money_signer` must name that the NodeId / chat-identity private key is
server-held.

**The node cannot know who owns its machine.** A VM with a default config
looks like a laptop. The app applies one more rule itself, and it can only
make the label stronger:

- A loopback URL is **not** proof the node runs on this machine: an SSH
  forward or local proxy looks identical. The host may show `local_seed` or
  `encrypted_seed` only with **verified local provenance** (for example, the
  supervised node process is listening on the API port — same machine, same
  user, the data dir the host started). Otherwise it classifies
  conservatively as `hosted_custody`, including older nodes that report
  nothing over an unverified connection.
- `remote_signer` and `money_signer` are allowed without that provenance:
  they do not claim the seed is local.
- The Tauri host applies this (`control::custody_mode(reported,
  verified_local_node)`).

The app never shows a weaker label than the node reports, and it never shows
`remote_signer` or `money_signer` unless the node reports them.

Both signer modes are reserved: no node reports them until the matching
protocol slice is built (**GAP**).

## 3. What moves to the signer

Every key comes from the one seed (`ACCOUNT-LAYER.md` §1). A remote-signer
node splits them by what must be online all the time and what must never be
on the VM.

| Key | Where it lives with `remote_signer` | With `money_signer` | Why |
|---|---|---|---|
| Owner approval (Ed25519) | **Signer only** | **Signer only** | Already public-only on the node (`ACCOUNT-LAYER.md` §4). |
| Lightning node key, channel keys | **Signer only** | **Signer only** | They move money. Every commitment update is signed by the signer (§4). |
| On-chain wallet | **Signer only** | **Signer only** | The node builds a PSBT; the signer signs it after checking the outputs. |
| Node identity (Ed25519) | **Signer holds the root**; the VM holds an **operational key** certified by it | **VM holds the root** (disclosed) | Mesh identity signs the front-door card, auth challenges and introductions many times an hour. Full `remote_signer` requires the root off the VM (§3.1). |
| Transport (X25519) | VM | VM | Noise_XX handshakes happen whenever a peer connects. |
| Storage (AES-256) | VM | VM | The node must read its own database. **This is not protected from the operator** (§7). |

### 3.1 Operational key delegation

- The signer holds the root seed. It derives the root NodeId as today.
- For a hosted node it derives an **operational seed** under a new context,
  `konsensus-v2 hosted operational seed v1 || index`, and sends it to the VM
  once, when the owner sets the node up.
- The signer signs a delegation record, which the node attaches to its
  front-door card and introductions:

  ```
  bitsov-delegation-v1\nroot:{root_node_id}\nop:{op_node_id}\nindex:{n}\nnot_after:{t}
  ```

- Peers that hold the root fingerprint accept the operational key while the
  delegation is valid. Petnames and relations bind to the **root**.
- Revocation is the node-key rotation record of `ACCOUNT-LAYER.md` §8, signed
  by the root. The owner can leave a hosted node by rotating to a new index,
  or back to a node at home. The operator keeps a key that peers no longer
  accept.
- **GAP.** Depends on §8 (rotation, M1.5). Until delegation ships, a node that
  has money keys on the signer but still holds the NodeId root on the VM
  reports **`money_signer`**, not `remote_signer`. It must never claim the
  full remote-signer label while the identity root remains on the VM.

## 4. The signer protocol

### 4.1 Channel

- The signer **dials out** to the node. The owner's device is usually behind
  NAT and asleep, so it never listens.
- Transport: the existing Noise_XX transport, pinned to the node's NodeId, on
  a dedicated protocol id (`bitsov-signer/1`). The signer authenticates with
  its own static key. The node accepts a signer connection only from the
  public key recorded at setup.
- Setup is a pairing ceremony run on the owner's device, at the node's
  terminal or the operator's setup page. It is the same shape as device-key
  registration (`ACCOUNT-LAYER.md` §4), inverted: the **signer** signs the
  node's NodeId, a nonce and the setup code, and the node stores the signer's
  public key. No route can replace it without a signature from the old signer.
- Every request carries `(request_id, kind, node_fp, issued_at, expires_at,
  payload)`. The signer refuses expired, replayed (seen `request_id`) or
  foreign-node requests. Each response signs `(request_id, kind, digest of
  payload)`, so a response cannot be replayed onto another request.

### 4.2 Request kinds

| Kind | Payload | What the signer checks before signing |
|---|---|---|
| `owner_approval` | the exact `bitsov-owner-approval-v1` message | Shows the fingerprint and purpose to the owner. Touch ID for **each** approval. |
| `ln_commitment`, `ln_htlc`, `ln_revoke`, `ln_closing` | LDK's `ChannelSigner` calls, with the full channel state the signer needs to validate | The VLS policy set (§4.3). No prompt: these happen per payment. |
| `ln_node` | invoice signing, gossip, `sign_bolt12_invoice`, ECDH | Invoice amount and description are logged for the owner. |
| `onchain_psbt` | a PSBT | Outputs go to the node's own wallet, a channel funding the owner approved, or an address the owner confirms with Touch ID. |
| `delegation` | §3.1 record | Only during setup or rotation. Touch ID. |

### 4.3 Lightning signing: VLS or an LDK remote signer

LDK already separates signing from channel logic. Its `SignerProvider`,
`ChannelSigner`, `NodeSigner` and `EntropySource` traits are the only things
that touch private keys. The Validating Lightning Signer (VLS) project
implements them as a proxy to a separate signer process. That signer keeps
its own copy of each channel's state, and it refuses any signature that
could lose funds: revoking a state before the new one is signed, a
commitment that pays out less than it should, a sweep to an unknown address,
or more than a velocity limit per day.

The plan, leanest first:

1. **Signer side.** Run VLS's policy core (`vls-core`) inside the BitSov app
   on the owner's device, using the seed the app already knows how to restore.
   It is a Rust library, so it links into the Tauri binary.
2. **Node side.** Implement LDK's signer traits in `konsensus-lightning` as a
   thin proxy that forwards each call over §4.1 and waits for the answer.
   Where LDK supports asynchronous signing for a call, return "pending" and
   resume with `signer_unblocked`. Where it does not, block with a timeout
   and fail the operation, never the channel.
3. **The work that decides the cost.** `ldk-node` 0.7 builds its own
   `KeysManager` from the seed and does not accept a custom signer. We
   vendor `ldk-node` already (`vendor/ldk-node`), so the change is a
   constructor that takes our `SignerProvider`, `NodeSigner` and
   `EntropySource`, and never sees the seed. Check the async-signer coverage
   of the pinned `lightning` version before committing to (2).

We do not write our own policy engine. Loss-of-funds validation is the part
that is easy to get wrong, and VLS exists to do it.

## 5. When the signer is offline

The owner's laptop sleeps. The node must stay a reachable, honest server
without it. What still works without the signer:

| Works without the signer | Does not work until it returns |
|---|---|
| Staying online and reachable; Noise handshakes (VM-side transport key) | Sending a paid message, paying an invoice, meeting and call payments |
| Serving the front-door card, which the owner pre-signs with its `expires_at` | Receiving a payment: accepting an HTLC needs a new commitment signature |
| Answering `/health` and the owner's `/status` | Opening, splicing or cooperatively closing a channel |
| Queuing work: approvals, grants and outbound sends wait with their expiry, as console grants already do | Approving a device, a grant or a front-door publish |
| **Breach response** *only if* justice material was pre-signed and left on the node while the signer was connected (**GAP** until that path exists) | On-chain sends |

### 5.1 Planned disconnect

Before the owner deliberately takes the signer offline (sleep, travel, "pause
payments"):

1. The node **drains**: it refuses new inbound and outbound HTLCs and
   forwards, then waits until every accepted HTLC is settled or failed.
2. Only when the pending-HTLC set is empty does `/status` report
   `signer: draining complete` and the app allow "signer offline" as a
   planned state.
3. Peers see "not accepting payments", not silence. Senders get the paid
   admission refusal they get today when the wallet cannot pay or receive.

**GAP.** Drain + status signalling are not built.

### 5.2 Abrupt loss

A crash, network cut, or killed app can leave HTLCs that were already
accepted while the signer was connected. Rejecting *new* HTLCs after
disconnect does **not** clear those. They still have on-chain deadlines
(BOLT 5: unresolved outputs must be monitored and resolved on distinct
local/remote commitment and HTLC paths). Pre-signed justice transactions
address revoked commitments, not every ordinary HTLC resolution.

Required before any "funds stay safe while the signer sleeps" claim:

```
accept_htlc => safe_resolution_material_persisted_for_abrupt_signer_loss
```

That material must let the node (or a designated watchtower the owner chose)
force-close and resolve HTLC outputs **without** exporting the owner key to
the VM, with a validated fee strategy and enough time relative to the
HTLC CLTV / `to_self_delay` windows.

**GAP — offline funds safety.** Until that durable abrupt-loss path exists
and is tested, this design does **not** claim that funds stay safe across an
unexpected signer disappearance. The honest interim statement is: planned
disconnects need a completed drain (§5.1); abrupt loss is an unresolved
risk bounded by each channel's on-chain timeouts; the operator of the VM
must not be handed the seed as a workaround.

### 5.3 Owner visibility

`/status` reports `signer: connected | draining | offline since <t>`, and
the app says so. (**GAP**, with the protocol.)

## 6. The fallback: honest hosted custody

Until a remote signer exists, and after it exists, for owners who choose not
to use one:

- The VM runs a normal node with its seed. Its config says so: `tier =
  "cloud"`, or `[identity] hosted = true` for a VM that keeps another tier.
  The node reports `hosted_custody`.
- The app shows **Hosted custody** beside the node, in the warning colour,
  with this tooltip: "The seed for this node is on a server. Whoever runs
  that server can spend its bitcoin and read its messages. Move it home to
  hold your own keys."
- The label is never hidden by a setting. It is information, like the
  balance.
- **Moving home.** The owner restores the same recovery phrase on their own
  machine (`konsensus restore`) and stops the VM node. The identity and
  money follow the phrase. Channels need the channel-state backup (SCB) from
  the exit bundle. The operator still has the phrase, so the owner should
  sweep funds to a new seed once they are home. The app's move-home flow must
  say this. **GAP**: the flow is not built.
- Pilot VMs (Maya, Josh) are hosted custody today. They must set
  `[identity] hosted = true` at the next upgrade. Until then, the app's
  unverified-connection rule (§2) labels them anyway.

## 7. What a remote signer does not fix

- **Confidentiality.** A hosted node decrypts messages, holds the storage key
  and serves the owner's data. The operator can read it. The remote signer
  protects money and (when `remote_signer`) the identity root, not content.
  The `remote_signer` badge tooltip must say "Messages are stored on the
  server." The `money_signer` badge must say the identity root stays on the
  server.
- **Liveness.** The operator can switch the node off. Offline funds safety
  is §5 (**GAP**); the owner can still move the node home.
- **Metadata.** The operator sees who the node talks to and when.

## 8. Build order

1. **Now (this slice).** `custody_mode` in `/status`, `[identity] hosted`,
   the Cloud tier maps to `hosted_custody`, and the app badge with verified
   local provenance (not mere loopback).
2. **Owner approvals over the signer channel.** §4.1 plus `owner_approval`
   only. Smallest real remote-signing channel: the owner-approval key is
   already off the node, so only transport and setup are new.
3. **On-chain PSBT signing.**
4. **Lightning signing through VLS**, with the `ldk-node` constructor change.
   With identity still on the VM, the node may report **`money_signer`**
   only — never `remote_signer`.
5. **Operational-key delegation**, after node-key rotation (M1.5), plus the
   §5 drain and abrupt-loss resolution material. Only when
   `identity_root_off_vm` and the offline-safety invariant hold may a node
   report `remote_signer`.

## 9. Invariants (tested now)

- The status field is owner-only: `custody_mode` appears in `/status`, never
  in the public `/health` (`auth_tests::status_reports_custody_mode_to_the_owner_only`).
- A Cloud-tier node, or one with `hosted = true`, reports `hosted_custody`
  even when its seed is encrypted (`custody_mode_tests`).
- No config value makes a node report `remote_signer` or `money_signer` today
  (`custody_mode_tests::no_config_claims_a_remote_signer`).
- The app never shows a weaker label than the node reports; local seed labels
  require verified local provenance; an unverified loopback (e.g. SSH forward)
  is classified as hosted custody
  (`control::tests::custody_mode_is_projected_and_only_ever_strengthened`
  and `tests/custody-badge.test.tsx`, in `bitsov-app`).
