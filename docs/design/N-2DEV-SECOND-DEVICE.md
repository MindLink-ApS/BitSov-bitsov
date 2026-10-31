# N-2DEV: owner-device-approved second-device enrollment (no claim code)

Design note, docs only. Source read at `origin/main` `7af21ae`. Paths are under `crates/` unless stated otherwise. No code is changed here.

**Ruling (21 Oct).** A box is claimed **exactly once**, by its owner's first device, with the claim code that the owner types on the owner console. Every later device joins as a **second device**: QR → word match → an **already-enrolled owner device approves** with Touch ID / Face ID. Second devices never use a claim code.

**Problem.** Today the only tunnel path for a later device is the claim-bound SAS v1. `request_device_key_with_sas` loads the claim code and mixes its commitment into the digest (`konsensus-api/src/pairing/device.rs:567`, `konsensus-api/src/sas.rs:116`). Tunnel delegation refuses anything else (`device.rs:860`, `:906`). The new device therefore has to type the claim code to compute the words, which is why app onboarding PR 1 could not drop it. This note defines the node contract that removes the claim from the second-device path and leaves the first-device path unchanged.

**Constraints.**

| # | Constraint | How this design meets it |
|---|---|---|
| C1 | Claim code is first-device only and is typed on the console | SAS v1, remote first run and console `device approve` are unchanged. SAS v2 never reads `claim-code` |
| C2 | The approver sees the same word match: one step, one short line | The approver shows the 4 words and "Approve if these match your new device", then Face ID / Touch ID. The new device has no "They match" button |
| C3 | Approval is revocable from the owner console | `konsensus device revoke --key … [--with-pairing] [--cascade]` and a transitive `--approved-by`, plus provenance in `device list` (§7) |
| C4 | Each person keeps their own seed | Nothing here touches seeds. The node's own seed-derived owner key signs the enrollment, exactly as delegation does today |
| C5 | No new network exposure | No new listener, port, push service or relay. Every call uses the existing Noise tunnel routes, each device on its own session |

## 1. What already exists (reused, not rebuilt)

| Piece | Where | Reused as |
|---|---|---|
| Owner-device ticket: challenge → `bitsov-ticket-v1` P-256 sig → one-use `owner_` PairLink, 5 min, hash-only in memory | `pairing/ticket.rs:103-229` | The QR source on a Mac or iPhone owner device (gains a `purpose`, §3) |
| Console ticket `konsensus pair-ticket [--qr]` | `konsensus-node/src/cli/ticket.rs:84` | The QR source on the box console (gains `--second-device`, §7) |
| Ticket dispatch in the Noise listener | `konsensus-node/src/remote_access.rs:1053` | Routes `second_` / owner tickets of purpose `second_device` to a provisional pairing |
| `NoiseBinding {handshake_hash, box_public_key, client_static}` attached by the server, never from HTTP | `remote_access.rs:899-907`, `rate_limit.rs:33-40` | Bound into the SAS v2 digest and the approval message |
| `PendingDeviceKey` + memory-only `DeviceSas`, a single live SAS op node-wide, `sas_failures ≥ 3` closes SAS | `device.rs:108-176`, `:503-509`, `pairing.rs:661` | The pending second-device record (`sas_version: 2`). v2 ignores `sas_failures` entirely: it neither reads nor raises it (§5) |
| Owner pending list and per-op view over the approver's tunnel | `ticket.rs:232-300`, routes `GET …/device-key/pending`, `GET …/{op}/delegation` | The channel that carries the approval request (§2) |
| `delegate_device_key_inner`: re-verify the approver key, sign `owner_approval_message` with the in-memory seed-derived key, consume atomically | `device.rs:879-994` | The enrollment write, with a new message domain |
| `verify_p256` (ring, ECDSA P-256/SHA-256, DER) and 65-byte SEC1 parsing | `device.rs:323-345` | Verifying the iPhone Secure Enclave key (app #284) |

## 2. Message flow

The approval request reaches the owner device **by pull over the owner device's own existing Noise tunnel**. The owner app polls `GET /api/v1/pair/device-key/pending` every 2 s while its "Add a device" screen is open, and once when it comes to the foreground. There is no push and no relay (C5). The request is bound to the new device's session because the node captures the new device's `NoiseBinding` from its tunnel when the op is created, puts it into the SAS v2 digest, and the approver signs the binding fields and the words (§4).

| # | Actor → actor (channel) | Message | Node state after |
|---|---|---|---|
| 1 | Owner device → node (owner tunnel) | `GET /pair/ticket` → nonce; `POST /pair/ticket {approver_key_id, nonce, purpose:"second_device", signature}` (`bitsov-ticket-v2`) | Ticket hash in memory, 5 min, `purpose=second_device`, issuer key + epoch |
| 1′ | *or* the owner at the console | `konsensus pair-ticket --second-device --qr` | Ticket file with a `second_` code, 10 min default |
| 2 | Owner device / console → new device (camera) | QR = PairLink v2 (signed endpoints, box key pin) | n/a |
| 3 | New device → node (new Noise XX, pinned box key) | Pairing proof with the ticket code (`wire::pairing_proof_message`) | Ticket consumed and a **used-ticket tombstone** `{ticket_hash → client_id}` kept until the provisional deadline. **Provisional pairing**: `scopes: []`, plus a memory record `{client_id, ticket_id, ticket_commitment, issuer, deadline = now+15 min, failures = 0}`. If the client pubkey or Noise static already has a pairing → refuse `already_paired` (§5a). If the tombstone exists (QR already used) → **contested** kill (§6) |
| 4 | New device → node (its tunnel) | `POST /pair/token` (existing challenge flow) | Token valid only on the 4 enrollment routes (§6) |
| 5 | New device → node | `POST /pair/device-key {public_key, name, proof, sas_version:2}`, where `proof` is the Secure Enclave sig over `bitsov-device-register-v1` | `PendingDeviceKey{sas_version:2, created_at}` with `DeviceSas{binding, box_nonce, digest_v2}`, `expires_at = now + SECOND_DEVICE_SAS_TTL_SECS` (300). Response `{op_id, box_nonce, expires_at}` |
| 6 | New device (local) | Computes `digest_v2` from its own handshake hash, box key, own static, own device key, `box_nonce` and the ticket code it scanned | n/a |
| 7 | New device → node | `POST /pair/device-key/{op}/finalize {sas_version:2, sas_digest, proof}` with `proof` over `bitsov-device-register-v2 … sas_digest:` (automatic, no human tap) | Constant-time digest compare. Mismatch → op dropped, the pairing's `failures += 1` (at 3 the **provisional pairing is revoked**), and the self-expiring node-wide `sas_v2_mismatches` window rises (§5). Match → `confirmed = true` |
| 8 | New device (UI) | Shows the 4 words and "Approve on your other device". Quiet "They don't match" → `DELETE /pair/device-key/{op}` | On a v2 op: op dropped, the pairing's `failures += 1` (3 → revoked). No node-wide count |
| 9 | Owner device → node (owner tunnel, poll) | `GET /pair/device-key/pending` → `GET /pair/device-key/{op}/delegation` | Read only |
| 10 | Owner device (UI) | Rebuilds the approval message from the fields and its pinned node fingerprint, recomputes the words from `sas_digest`, and shows the words + one line (the unsigned-by-device name in small secondary text, §4). **Approve is enabled only when `ticket_id` equals the QR this app is showing right now, or when the op's `issuer` is `console`** (console QRs get the same one line and no extra caution: the owner console is trusted). A v2 op from a ticket that another owner device minted shows "Approve on the device that showed the QR" with Approve disabled. Face ID / Touch ID signs | n/a |
| 11 | Owner device → node | `POST /pair/device-key/{op}/second-device/approve {approver_key_id, signature}` | §5 checks. Enrolled `DeviceKey{enrolled_by:"second_device:<approver key_id>"}`, pairing scopes → `[read, receive]`, op + nonce consumed, provisional record removed, all in one lock and one persist |
| 11′ | Owner device → node | `POST …/second-device/reject {approver_key_id, signature}` (domain `…-reject-v1`, same fields) | Op dropped, provisional pairing revoked. No node-wide count (the reject is the owner's own decision) |
| 12 | New device → node | `GET /pair/device-key/{op}` → `registered` | Normal paired device |

The issuer/ticket-id approval gate in step 10 is **UI policy**, not a node authorization check. Owner devices are trusted: the node accepts a valid approval from any enrolled owner device regardless of ticket issuer. The signed `issuer` field covers the UI policy input.

## 3. SAS v2 digest (claimless)

```text
ticket_commitment = BLAKE3(ASCII("bitsov-second-device-ticket-v1") || ticket_code_ASCII)
ticket_id         = hex(BLAKE3(ASCII("bitsov-ticket-id-v1") || ticket_code_ASCII)[..16])
sas_digest_v2 = BLAKE3(
  ASCII("bitsov-sas-v2") ||
  noise_handshake_hash[32] || box_transport_pubkey[32] || client_static[32] ||
  device_public_key[65] || box_nonce[16] || ticket_commitment[32])
words = sas::words(sas_digest_v2)   // same 44-bit, 4-word BIP-39 rule as v1
```

| Field | Source on the node | Source on the new device |
|---|---|---|
| handshake hash, client static | `AuthenticatedNoise.binding` of the request's own tunnel (never HTTP) | Its own completed Noise XX |
| box transport pubkey | `PairingService::box_transport_pubkey()` | The PairLink pin |
| device public key | The request body after `parse_public_key` | Its Secure Enclave key (65-byte SEC1) |
| box nonce | `OsRng` 16 bytes, returned at step 5 | Response at step 5 |
| ticket commitment | Computed once at ticket consumption from the code in hand, then kept on the provisional record. The code itself is not kept | The scanned QR |

The claim commitment is replaced by the ticket commitment, which ties the words to **this QR**. When the owner device minted the ticket, it knows the code and checks `ticket_id` against its own (strong binding to "my QR"). For a console ticket, the approver checks the words only. A frozen v2 vector is added next to the v1 vector in `docs/security/pairing.md`.

## 4. Approval signature

Signed by the approver's enrolled P-256 key (Secure Enclave, biometric-gated). ECDSA P-256 / SHA-256, DER, lowercase hex, verified by `verify_p256`. The bytes are UTF-8, LF-separated, with no trailing newline. Every field comes from node state; the node never accepts the message from a request body.

```text
bitsov-second-device-approval-v1
node:{identity fingerprint}
approver_client:{approver client_id}
approver_epoch:{approver pairing epoch}
approver_key:{approver key_id}
op_id:{24 hex}
nonce:{32 hex, server delegation nonce, single use}
client_pubkey:{new pairing Ed25519 pubkey hex}
epoch:{new pairing epoch}
device_key:{130 hex, SEC1 uncompressed}
device_name:{name as shown, after clean_name; UTF-8}
noise_handshake_hash:{64 hex}
noise_client_static:{64 hex}
box_transport_pubkey:{64 hex}
ticket_id:{32 hex}
issuer:{console or minting key_id}
sas_version:2
sas_digest:{64 hex}
sas_words:{w1} {w2} {w3} {w4}
expires_at:{unix seconds}
```

The reject message is identical except for the domain `bitsov-second-device-reject-v1`. The domain differs from `bitsov-owner-delegation-v1/v2`, `bitsov-device-register-v1/v2`, `bitsov-ticket-v1/v2`, `bitsov-relation-intent-v1` and the app's `unlock-v1`, so a signature from one protocol cannot be used in another. Approver-side rules (normative for the app): rebuild the bytes locally and require them to be byte-equal to `approval_message`, recompute `sas_words` from `sas_digest`, require `node` to equal the pinned fingerprint, and refuse when `expires_at` is in the past. `device_name` is chosen by the new device and proves nothing; it is signed only so that the signed bytes equal what was shown. The words are the primary element on screen and the name is secondary.

## 5. Node verification and state

**Approve: checks, all under the pairing lock, in this order. Nothing is written until all of them pass.**

| # | Check | Error |
|---|---|---|
| 1 | Flag on, `local_owner_device`, owner signing key in memory (a locked box serves only the locked router, so this route is not even mounted there, §6) | `OwnerChannelUnavailable` (503, kind `box_locked`, unlocked process without an owner signing key) |
| 2 | Caller's tunnel `client_id` = token `client_id`; approver pairing is not provisional | 403 |
| 3 | `intent_key(approver_client, epoch, key_id)`: the approver key is registered, at its current epoch, with a valid owner approval | `BadProof` (403) |
| 4 | Approver `client_id` ≠ op `client_id` (no self-approval) and the approver key was registered before the op was created | 403 |
| 5 | Op exists, `sas_version == 2`, `confirmed`, `now < expires_at`, `DeviceSas.created_at.elapsed() < SECOND_DEVICE_SAS_TTL_SECS`, created by this process (`DeviceSas` present) | `UnknownOperation` / `Expired` |
| 6 | The op's pairing is still provisional, not `contested`, at the same epoch and `client_pubkey`, and its provisional deadline has not passed | `PairingInvalid` (kind `contested` when contested) |
| 7 | `key_id_for(device_key)` matches; key not already enrolled; under `MAX_DEVICE_KEYS_PER_CLIENT` | `NotGrantable` |
| 8 | `verify_p256(approver_pubkey, approval_message(node state), sig)` | `BadProof`; counts toward the approver rate limit; the op is **not** consumed |
| 9 | Sign `owner_approval_message` with the seed-derived owner key → `DeviceKey`; set scopes; remove the op and the provisional record; record `registered_ops[op]`; persist (roll back on error) | `Io` |

**State.**

| Record | Persisted? | Lifetime | Single use |
|---|---|---|---|
| Second-device ticket | Memory: owner tickets. File: console `second_` code, as today | 5 min (owner) / 10 min default, 30 min max (console) | Removed on consumption, including exact retries (`OWNER_TICKET_PREFIX` rule extended to `second_`) |
| Used-ticket tombstone | Memory `{blake3(code) → client_id, client_static}` | Until the provisional deadline of the pairing it created (15 min). Lost on restart, together with that pairing, which the start-up sweep removes | A second valid pairing proof for the same code from a different static or pubkey: **(a) while the first pairing is still provisional**, it is marked `contested`: its op is dropped, the pairing revoked, the tombstone kept, and the second device refused. **(b) After the first pairing has been enrolled**, the second device is refused and the enrolled device is **not** revoked. The node emits `pair.second_device_contested_after_enroll`, and the owner app and `pair-status` show "This QR was used again after you approved {name}. Revoke it if it wasn't yours." |
| Provisional pairing | `PairedClient` with `scopes: []` (no file format change) plus a memory record `{ticket_id, ticket_commitment, issuer ("console" or the minting key_id), deadline, failures}` | 15 min. A sweep on start and every minute deletes provisional pairings past their deadline or with no memory record (for example after a restart). The sweep is keyed by `client_id` | One enrollment. Digest mismatches and new-device "don't match" cancels each add 1 to `failures`; at 3 the pairing is revoked. An approver reject or a contested kill revokes it at once |
| `PendingDeviceKey{sas_version:2}` | Yes (`sas_version` only); `DeviceSas` is memory-only | `SECOND_DEVICE_SAS_TTL_SECS = 300` from step 5, and never past the provisional deadline. A restart makes it `lost` | Consumed with its `delegation_nonce` at approve or reject |

**TTL reconciliation.** v1 keeps `ELEVATION_TTL_SECS = 900` (`pairing.rs:112`) unchanged. v2 uses the new `SECOND_DEVICE_SAS_TTL_SECS = 300`, which matches the 5 min owner ticket, in all four places that today hard-code 900 s for SAS: `expires_at`, `require_sas_confirmed`, `pending_device_view` and the monotonic `created_at.elapsed() >= 900` check in `confirm_device_sas` (`device.rs:~663`). The per-client 30 s limit (`device.rs:517`) today derives request time as `expires_at - ELEVATION_TTL_SECS`, which is wrong for a 300 s op. `PendingDeviceKey` gains `#[serde(default)] created_at: i64`, and the limit becomes `now - created_at < 30` for both versions. Records without the field (`0`) never block.

**Rate limits.**

| Limit | Value | Source |
|---|---|---|
| Second-device ticket issues | 5 / 15 min node-wide (shared with owner tickets); challenge reads 30 / min. A ticket that expires **unconsumed** refunds its issue slot, so QR retries after a timeout or camera trouble do not run into 429 | `ticket.rs:12-14` + refund |
| Provisional pairings alive | 2 node-wide | new |
| Live SAS ops node-wide (v1 + v2) | 1 | `device.rs:503-509` |
| Device-key requests per client | 1 / 30 s | `device.rs:512-519` |
| v2 failures per provisional pairing | 3 (digest mismatches + new-device cancels) → that pairing is revoked. Rejects and contested kills revoke at once. None of these locks the node: the owner's next fresh QR works immediately, so a stolen QR cannot lock them out | new |
| v2 finalize digest mismatches node-wide (`sas_v2_mismatches`) | 10 per rolling hour → v2 requests 429 for the rest of that hour. The counter decays, so no restart and no console is needed. `pair-reset-sas` clears it early | new |
| v1 `sas_failures` | Unchanged: 3 per process (`pairing.rs:661`). **v2 ignores it:** the v2 request and finalize paths neither read the `sas_failures >= 3` gate (`device.rs:500`) nor raise it, so a v1 closure never blocks v2 | `pairing.rs:661` |
| Approver bad signatures | 10 / hour per approver key → 429 | `approval.rs` `rate()` helper |

### 5a. SAS version matrix (normative)

| Caller pairing | `sas_version` none | `1` (claim) | `2` (claimless) |
|---|---|---|---|
| Provisional (from a second-device ticket) | 403 | 403 | Allowed |
| Normal pairing | As today | As today (behind `second_device_claim_v1`) | 403 |
| Device that already holds a pairing and scans a second-device QR | n/a | n/a | Ticket consumption refuses `already_paired` (the client pubkey or Noise static matches an existing pairing, `create_remote_pairing_locked` would otherwise return the existing full pairing). **The ticket is not consumed.** The app generates fresh pairing keys and scans again |

**Single SAS slot vs v1.** Any Read pairing can hold the one live SAS slot with an unconfirmed v1 request (creating a v1 op needs no claim). A v2 request **pre-empts an unconfirmed v1 op**: it drops it (its client sees `lost`) and takes the slot. A confirmed v1 op is never pre-empted. Pre-emption does not raise v1 `sas_failures` and must not reuse `cancel_pending`.

The approval routes accept only `sas_version: 2` ops. `delegate_device_key_inner` refuses any op whose `sas_version` is not `None` or `Some(1)` **inside the function**, so every caller (the tunnel `/delegate` and the loopback `device_routes::delegate_device_key`, which passes `require_sas = false`) refuses v2. A v2 op can be enrolled only by `…/second-device/approve` or by console `device approve`.

## 6. Failure modes

| Case | What happens | New device shows | Approver shows |
|---|---|---|---|
| Owner device offline / asleep | Nothing polls. The op expires at 300 s; the new device may re-request (new nonce, new words) until the 15 min provisional deadline, then the pairing is swept | "Approve on your other device" → after expiry "Your other device didn't answer. Try again." | n/a |
| Words mismatch (approver) | Reject → op dropped, pairing revoked. No node-wide count | "Stopped. Nothing was added." | "Stopped. Nothing was added." |
| Words mismatch (new device) | `DELETE` op → op dropped, the pairing's `failures += 1` (3 → revoked). No node-wide count. The owner can retry, or start over at once with a fresh QR | Same | The op disappears from pending |
| New device's view ≠ node's (MITM or wrong box) | Finalize digest mismatch → op dropped, the pairing's `failures += 1` (3 → revoked), `sas_v2_mismatches += 1` (self-expiring); the approver never sees words | "Couldn't verify this box." | n/a |
| Timeout mid-approval | The approve after `expires_at` → `Expired`; nothing written | Expired | "This request expired." |
| Replay of the approve signature | Op and nonce already consumed → `UnknownOperation`. Another node → `node` differs. A changed approver epoch → check 3 | n/a | n/a |
| Stolen QR, thief first | The thief gets a **scopeless** provisional pairing. When the real device then presents the same QR with a valid pairing proof, the tombstone marks the ticket **contested**: the thief's op is dropped and its pairing revoked. The real device is refused too. Nothing can be approved from that QR. `ticket_id` alone does not help here (the stolen QR *is* the owner's), so the contested kill is what defends | "Someone else scanned this QR. Don't approve on your other device. Make a new QR." | "Two devices used this QR. Nothing was added." (the op disappears with kind `contested`) |
| Stolen QR, thief only (the real device never scans) | The thief's words appear on the owner app while it is still showing that QR. Nobody in the room has a device showing words, so the owner must not approve. If the owner does approve, the thief is enrolled → console revoke (§7, transitive) | n/a | Words, with the line "Approve only if your new device shows these words" |
| Two devices racing one ticket | The first consumes it. The second's valid proof triggers the contested kill above, so neither enrolls | "Someone else scanned this QR…" | "Two devices used this QR…" |
| Device already paired to this box scans a second-device QR | Refused `already_paired`, and the ticket is **not** consumed (§5a) | App makes fresh pairing keys and retries the same QR automatically | n/a |
| Lost response after the pairing proof was sent | The node may already have consumed the ticket. **App rule:** never generate fresh keys after a transport error that follows a sent pairing proof. Reconnect with the **same** keys (no code), as `device-keys.md` already requires. Fresh keys only on an explicit `already_paired`. Otherwise the tombstone would contest the app's own pairing, which fails closed and costs a new QR | Reconnecting… then continues | n/a |
| Box locked after a power cut (home mode starts locked; the owner signing key exists only after remote unlock) | Only the locked router is mounted (`locked.rs:160`: `/livez`, `/node/lock`, unlock challenge, unlock), so ticket, approve and `/health` routes are **404**, not 503. The apps detect it by reading `GET /api/v1/node/lock` → `state: "locked"`. 503 kind `box_locked` applies only to an **unlocked** process that has no owner signing key (`device_authority` error or `owner_signing_key: None`). Nothing is consumed | After a failed pairing, it reads `/node/lock`: "Your box is locked. Unlock it on your other device first." If `/node/lock` can't be read either: "Can't reach your box." | Reads `/node/lock`: "Unlock your box first." with the existing unlock action |
| Box restart mid-flow | Memory tickets and `DeviceSas` are gone; the provisional pairing is swept; pending is `lost` | "Start over" | The op disappears |
| Approver revoked mid-flow | Check 3 fails under the lock | n/a | 403 |
| Box has **no** enrolled owner device (`owner_device_count() == 0`) | Ticket `purpose=second_device` and `pair-ticket --second-device` are refused with `no_owner_device`. **Recovery is console-only (re-claim with the owner at the box). Out of scope.** | "This box has no owner device yet." | n/a |

## 7. API and CLI changes

**HTTP.** New routes are on the tunnel router only. The one loopback change is that `delegate` refuses v2 (inside `delegate_device_key_inner`, §5a).

| Route | Who | Change |
|---|---|---|
| `GET/POST /api/v1/pair/ticket` | enrolled owner device | `POST` accepts `purpose: "second_device"`, signed as `bitsov-ticket-v2\nnode:{fp}\nnonce:{n}\npurpose:second_device`. Without `purpose`, the v1 path is unchanged |
| `POST /api/v1/pair/device-key` | provisional or normal pairing | Version matrix §5a: provisional → only `2`; normal → never `2` |
| `POST /api/v1/pair/device-key/{op}/finalize` | own op | Accepts `sas_version: 2` |
| `GET/DELETE /api/v1/pair/device-key/{op}` | own op | Status adds `approval: "owner_device"`. Rejected ops report `lost` |
| `GET /api/v1/pair/device-key/pending` | enrolled owner device | Lists v2 ops (`sas_version: 2`) |
| `GET /api/v1/pair/device-key/{op}/delegation` | enrolled owner device | For v2, adds `noise_handshake_hash`, `noise_client_static`, `box_transport_pubkey`, `ticket_id`, `issuer` ("console" or minting key_id), `sas_digest`, `approval_message` (null until finalized). Never the claim, never the ticket code |
| `POST /api/v1/pair/device-key/{op}/second-device/approve` | enrolled owner device | **New** `{approver_key_id, signature}` → `{op_id, key_id, status:"registered"}` |
| `POST /api/v1/pair/device-key/{op}/second-device/reject` | enrolled owner device | **New**, same body → `204` |
| `POST /api/v1/pair/device-key/{op}/delegate` (tunnel **and** loopback) | n/a | Refuses `sas_version: 2` ops via the check in `delegate_device_key_inner`, so neither an old app nor the loopback path can approve a v2 op with delegation-v2 |
| `POST /api/v1/pair/rotate` (unauthenticated today) | n/a | Refuses a provisional pairing (`provisional`, 403). Rotation is allowed after enrollment |
| Pairing proof on the Noise listener (`remote_access.rs:1053`) | new device | `second_` and `purpose=second_device` owner codes: tombstone check (contested), then the `already_paired` check, then provisional creation |
| `GET /api/v1/health` `api_capabilities` | any | Adds `second_device_enrollment_v1` when the flag is on and owner-device mode is live |

Provisional tokens are accepted **only** by `POST /pair/token`, `GET /pair/challenge`, and the 4 own-op device-key routes above. This needs a new `EnrollmentAuth` extractor and `issue_token_kind` must allow an empty scope set for provisional pairings. Every other route sees no scope and returns 403. All new responses use `Cache-Control: no-store`. Audit events: `pair.second_device_ticket_issued`, `pair.second_device_requested`, `pair.second_device_enrolled`, `pair.second_device_rejected`, `pair.provisional_swept`. They carry the approver client, epoch, key id and op id, and never the nonce, signature, ticket, digest or words.

**CLI (owner console, control socket).**

| Command | Change |
|---|---|
| `konsensus pair-ticket --second-device [--qr] [--ttl 10m]` | New flag: `second_` code, 10 min default, 30 min max. Refused when no owner device is enrolled or the flag is off. Below the QR it prints "Open Add a device on your other device now, so it can approve", because a console QR has no poller unless the owner app is open |
| `konsensus pair-status` | Lists provisional pairings (deadline) and pending v2 ops (device name, fingerprint, words), so the console can watch or cancel |
| `konsensus device list` | Shows `enrolled_by` (`console`, `device:…`, `second_device:<key_id>`) and the approver's device name |
| `konsensus device revoke --key <id> [--with-pairing] [--cascade]` | `--with-pairing` also revokes the device's pairing (all tokens die). **This is the C3 revoke.** Without `--cascade` it prints the keys this key enrolled (from `enrolled_by`) and the command to remove them; with `--cascade` it removes them as in `--approved-by` |
| `konsensus device revoke --approved-by <key_id> [--keep <key_id>]… [--allow-zero-owner]` | **Transitive**: walks `enrolled_by` (`second_device:<id>` and `device:<id>`) breadth-first from the given key, and revokes every reached key **and its pairing** (`--with-pairing` implied), cycle-safe. The walk is over `enrolled_by` strings, so the root may be a key that was **already revoked** (for example with `--key` first). `--keep` (repeatable) skips that key but still walks its children unless they are also kept. It prints the chain and the resulting `owner_device_count()`, and asks for confirmation. If the count would reach **0** it refuses unless `--allow-zero-owner` is given, because zero owner devices means console-only re-claim. Used for a lost, stolen or malicious owner device |
| `konsensus pair-cancel --op <id>` | Drops a pending v2 op and its provisional pairing |
| `konsensus pair-reset-sas` | Clears v1 `sas_failures` and the v2 `sas_v2_mismatches` window |
| `konsensus device approve --op <id>` | Unchanged for v1. For a confirmed v2 op (where `--owner-control` is live, as the console fallback when no owner device is online), `approve_device_key` runs **the same completion as the approve route**: §5 checks 5–7 with the v2 TTL, not contested, provisional deadline not passed; then, in one lock and one persist, register the key (`enrolled_by: console`), set the pairing's scopes to `[read, receive]`, remove the op and the provisional record. Without this, the sweep would delete the newly enrolled pairing |

## 8. Migration and compatibility

| Area | Effect |
|---|---|
| First device (remote first run, claim-bound SAS v1) | Unchanged. `bitsov-sas-v1`, the claim checks and `create-pending`/`finalize` are untouched |
| Existing second-device path (claim-bound SAS v1 + `delegation-v2`) | Kept working for current apps, behind `second_device_claim_v1` (default `true`). **It is retired one rc after the app ships N-2DEV** (the flag default flips to `false`, then the code is removed). The claim code stays first-device only |
| Existing pairings and device keys | Unchanged. No re-enrollment |
| Pairing file | **No version bump** (stays `8`). Provisional = `scopes: []`, which older nodes already treat as inert. `sas_version: 2` on a pending op makes an older binary refuse it (no `DeviceSas`), so a rollback fails closed |
| Old apps | Never request `purpose:"second_device"` and never see the capability. An old app that scans a `second_` console QR gets a scopeless pairing that is swept after 15 min, and the console warns about this when it prints the QR |
| Boxes without a claim code (pre-N3) | v2 does not depend on `claim-code`. It requires an enrolled owner device and owner-device mode, the same as delegation |

## 9. Rollout flag

`[pairing] second_device_enrollment = false` by default in the first rc. When it is `false`, none of the §7 additions are mounted or advertised, and behaviour is byte-identical to today. It is turned on per signet box (the owner's own Pi first, then a second test box) after E2E. The app gates the no-claim flow on `second_device_enrollment_v1` and falls back to the claim flow otherwise. Mainnet stays off until two independent reviews PASS on the same head and one signet E2E run passes with iPhone (Secure Enclave) as the new device and a Mac as the approver.

## 10. Tests

| # | Test | Layer |
|---|---|---|
| T1 | Frozen SAS v2 vector (bytes as v1, ticket commitment `77`×32); flipping each field changes the digest; the v1 vector is unchanged | `sas.rs` unit |
| T2 | v2 request **never reads `claim-code`**: passes with the file absent, unreadable, or a symlink | `device.rs` unit |
| T3 | Approve happy path: iPhone-format key (65-byte, DER sig), owner Mac approves; `enrolled_by`, scopes `[read, receive]`, `registered` status | pairing unit + tunnel integration |
| T4 | Each field of the approval message mutated → `BadProof`, op not consumed | unit, table-driven |
| T5 | Replay after success; replay to a second node; after an approver epoch bump; after approver revoke; self-approval; approver enrolled after the op | unit |
| T6 | `delegation-v2` signature on a v2 op is refused on the **tunnel and loopback** `/delegate` routes, and in `delegate_device_key_inner` directly with `require_sas = false`; a v2 approval signature on a v1 op is refused | unit + both routers |
| T7 | 2 v2 mismatches/cancels keep the pairing and the 3rd revokes it; a reject revokes at once; v1 `sas_failures` stays 0; v1 `sas_failures = 3` does not block v2; a fresh QR works at once; 10 mismatches/hour → 429, which expires by itself; `pair-reset-sas` clears it; a v2 request pre-empts an unconfirmed v1 op without raising v1 `sas_failures`, but not a confirmed one | unit |
| T8 | Reject path revokes the provisional pairing; the new device sees `lost` | unit |
| T9 | Provisional token: 403 on every non-enrollment route (iterate the router table) | router test |
| T10 | Provisional sweep: deadline passes; restart drops the memory record → swept at start; an older-format reader treats `scopes: []` as inert | unit + restart test |
| T11 | v2 expiry at `SECOND_DEVICE_SAS_TTL_SECS` by wall clock and monotonic clock in `expires_at`, `require_sas_confirmed`, `pending_device_view` and `confirm_device_sas`; v1 still 900 s; the per-client 30 s limit uses `created_at` for both versions, and a legacy record with `created_at = 0` does not block | unit |
| T12 | Concurrent approves on one op → exactly one `registered` | unit (`concurrent_approval_consumes_exactly_once` pattern) |
| T13 | Stolen QR: a second valid proof for a used ticket → both refused, the first pairing revoked and its op gone from the owner's pending list (kind `contested`); the thief's provisional pairing cannot read status, balance or history. **After enrollment:** a second proof for the same ticket is refused, the enrolled device stays enrolled, and `pair.second_device_contested_after_enroll` appears in the audit and `pair-status` | tunnel integration |
| T14 | No owner device → ticket refused with `no_owner_device`; flag off → routes 404, capability absent; locked box → only the locked router answers (ticket/approve/health 404) and `GET /node/lock` reports `locked`; an unlocked process without an owner signing key → mint/approve 503 `box_locked`; nothing consumed in either case | unit + router |
| T15 | Rate limits: 2 provisional, 1 live SAS op, 10 bad approver sigs / hour → 429 | unit |
| T16 | Console: `device revoke --with-pairing`; `--approved-by` on a chain of 3 (A approves B, B approves C) removes A, B, C and their pairings, cycle-safe; `--keep B` keeps B but removes C; starting from an already-revoked root works; reaching `owner_device_count() == 0` is refused without `--allow-zero-owner`; console `device approve` on a v2 op sets `[read, receive]`, clears the provisional record, and the pairing survives the next sweep; `--key` lists children and `--cascade` removes them; `pair-cancel`; `pair-status` output carries no secrets | control-socket tests |
| T17 | First-device regression: remote first run with claim SAS v1 and existing v1 delegation pass unchanged | existing suites stay green |
| T19 | Version matrix §5a: provisional with `None`/`1` → 403; normal with `2` → 403; an already-paired device on a second-device QR → `already_paired` with the ticket still usable by fresh keys | unit + tunnel |
| T20 | `/pair/rotate` refuses a provisional pairing; the sweep removes a provisional pairing by `client_id` | unit |
| T21 | An unconsumed expired ticket refunds its issue slot; a consumed one does not | unit |
| T22 | The approval message includes `device_name`; changing it → `BadProof` | unit |
| T23 | App (bitsov-app side, listed for the contract): after a transport error that follows a sent pairing proof, the app reconnects with the same keys and never regenerates them; it regenerates only on `already_paired` | app unit |
| T18 | Signet E2E: iPhone scans the Mac QR, words match, Mac Face ID / Touch ID, iPhone registered; console revoke ends its envelopes | regtest/signet script |

## 11. PR plan

| PR | Scope |
|---|---|
| **A: node core** | SAS v2 digest + vector; ticket `purpose` / `bitsov-ticket-v2`; `second_` console code; provisional pairing, used-ticket tombstone and contested kill, `already_paired`, sweep and `EnrollmentAuth`; version matrix and the v2 refusal in `delegate_device_key_inner`; `SECOND_DEVICE_SAS_TTL_SECS` + `created_at`; per-pairing failure charging and the decaying mismatch counter; rotate refusal; ticket slot refund; v2 request/finalize; approve/reject routes and messages; flag + capability + `box_locked` (unlocked, no signing key); v2 ignores `sas_failures` and pre-empts unconfirmed v1 ops; contested-after-enroll alert; console `device approve` v2 completion; audit; T1–T15, T17, T19–T22 |
| **B: console + docs** | `pair-ticket --second-device` (with the "open Add a device" line), `pair-status`, `device list`, `device revoke --cascade`, transitive `--approved-by` with `--keep` and `--allow-zero-owner`, `pair-cancel`, `pair-reset-sas`; update `docs/security/device-keys.md`, `pairing.md` (v2 vector) and `operations/home-node.md`; T16, T18 |

## 12. Decisions (21 Oct)

| # | Question | Decision |
|---|---|---|
| 1 | Console-minted second-device QRs | Allowed, with the same one line and no extra caution text: the owner console is trusted (§2 step 10) |
| 2 | Retiring the claim-bound second-device path | `second_device_claim_v1` is retired one rc after the app ships N-2DEV. The claim code stays first-device only (§8) |
| 3 | Provisional deadline | 15 min, no extension. A stuck user gets a fresh QR, and each request stays single-use |
| 4 | Failure counting | Not process-wide until restart. Failures count per provisional pairing (3 mismatches kill that pairing), plus a self-expiring process-wide rate limit (`sas_v2_mismatches`, 10/hour). `pair-reset-sas` stays. A stolen QR must not lock the owner out (§5) |
| 5 | Phone approving a phone | Allowed. The "never the only owner device" rule is about the owner-device count, not the approver type |
| 6 | Push / WebSocket hint to the approver | Poll only in v1 (§2) |

## 13. Open question

| # | Question | Default if unanswered |
|---|---|---|
| 1 | Optional, still one step: instead of a yes button, the approver picks the matching 4-word set from 3 candidates (the node derives the 2 decoys from the digest). This makes careless approval of a thief's words harder. Is it worth the extra friction for the owner? | Not in v1; revisit after signet E2E |
