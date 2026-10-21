# N-2DEV: owner-device-approved second-device enrollment (no claim code)

Design note, docs only. Source read at `origin/main` `7af21ae`. Paths are under `crates/` unless stated otherwise. No code is changed here.

**Ruling (Atlas, 21 Oct).** A box is claimed **exactly once**, by its owner's first device, with the claim code that Rasmus types on the owner console. Every later device joins as a **second device**: QR → word match → an **already-enrolled owner device approves** with Touch ID / Face ID. Second devices never use a claim code.

**Problem.** Today the only tunnel path for a later device is the claim-bound SAS v1. `request_device_key_with_sas` loads the claim code and mixes its commitment into the digest (`konsensus-api/src/pairing/device.rs:567`, `sas.rs:115`). Tunnel delegation refuses anything else (`device.rs:860`, `:906`). The new device therefore has to type the claim code to compute the words, which is why app onboarding PR 1 could not drop it. This note defines the node contract that removes the claim from the second-device path and leaves the first-device path unchanged.

**Constraints.**

| # | Constraint | How this design meets it |
|---|---|---|
| C1 | Claim code is first-device only and is typed on the console | SAS v1, remote first run and console `device approve` are unchanged. SAS v2 never reads `claim-code` |
| C2 | The approver sees the same word match: one step, one short line | The approver shows the 4 words and "Approve if these match your new device", then Face ID / Touch ID. The new device has no "They match" button |
| C3 | Approval is revocable from the owner console | `konsensus device revoke --key … [--with-pairing]`, plus provenance in `device list` (§7) |
| C4 | Each person keeps their own seed | Nothing here touches seeds. The node's own seed-derived owner key signs the enrollment, exactly as delegation does today |
| C5 | No new network exposure | No new listener, port, push service or relay. Every call uses the existing Noise tunnel routes, each device on its own session |

## 1. What already exists (reused, not rebuilt)

| Piece | Where | Reused as |
|---|---|---|
| Owner-device ticket: challenge → `bitsov-ticket-v1` P-256 sig → one-use `owner_` PairLink, 5 min, hash-only in memory | `pairing/ticket.rs:103-229` | The QR source on a Mac or iPhone owner device (gains a `purpose`, §3) |
| Console ticket `konsensus pair-ticket [--qr]` | `konsensus-node/src/cli/ticket.rs:84` | The QR source on the box console (gains `--second-device`, §7) |
| Ticket dispatch in the Noise listener | `konsensus-node/src/remote_access.rs:1053` | Routes `second_` / owner tickets of purpose `second_device` to a provisional pairing |
| `NoiseBinding {handshake_hash, box_public_key, client_static}` attached by the server, never from HTTP | `remote_access.rs:899-907`, `rate_limit.rs:33-40` | Bound into the SAS v2 digest and the approval message |
| `PendingDeviceKey` + memory-only `DeviceSas`, a single live SAS op node-wide, `sas_failures ≥ 3` closes SAS | `device.rs:108-176`, `:503-509`, `pairing.rs:661` | The pending second-device record (`sas_version: 2`) |
| Owner pending list and per-op view over the approver's tunnel | `ticket.rs:232-300`, routes `GET …/device-key/pending`, `GET …/{op}/delegation` | The channel that carries the approval request (§2) |
| `delegate_device_key_inner`: re-verify the approver key, sign `owner_approval_message` with the in-memory seed-derived key, consume atomically | `device.rs:879-994` | The enrollment write, with a new message domain |
| `verify_p256` (ring, ECDSA P-256/SHA-256, DER) and 65-byte SEC1 parsing | `device.rs:323-345` | Verifying the iPhone Secure Enclave key (app #284) |

## 2. Message flow

The approval request reaches the owner device **by pull over the owner device's own existing Noise tunnel**. The owner app polls `GET /api/v1/pair/device-key/pending` every 2 s while its "Add a device" screen is open, and once when it comes to the foreground. There is no push and no relay (C5). The request is bound to the new device's session because the node captures the new device's `NoiseBinding` from its tunnel when the op is created, puts it into the SAS v2 digest, and the approver signs the binding fields and the words (§4).

| # | Actor → actor (channel) | Message | Node state after |
|---|---|---|---|
| 1 | Owner device → node (owner tunnel) | `GET /pair/ticket` → nonce; `POST /pair/ticket {approver_key_id, nonce, purpose:"second_device", signature}` (`bitsov-ticket-v2`) | Ticket hash in memory, 5 min, `purpose=second_device`, issuer key + epoch |
| 1′ | *or* Rasmus at the console | `konsensus pair-ticket --second-device --qr` | Ticket file with a `second_` code, 10 min default |
| 2 | Owner device / console → new device (camera) | QR = PairLink v2 (signed endpoints, box key pin) | n/a |
| 3 | New device → node (new Noise XX, pinned box key) | Pairing proof with the ticket code (`wire::pairing_proof_message`) | Ticket consumed. **Provisional pairing**: `scopes: []`, plus a memory record `{client_id, ticket_id, ticket_commitment, issuer, deadline = now+15 min}` |
| 4 | New device → node (its tunnel) | `POST /pair/token` (existing challenge flow) | Token valid only on the 4 enrollment routes (§6) |
| 5 | New device → node | `POST /pair/device-key {public_key, name, proof, sas_version:2}`, where `proof` is the Secure Enclave sig over `bitsov-device-register-v1` | `PendingDeviceKey{sas_version:2}` with `DeviceSas{binding, box_nonce, digest_v2}`. Response `{op_id, box_nonce, expires_at}` |
| 6 | New device (local) | Computes `digest_v2` from its own handshake hash, box key, own static, own device key, `box_nonce` and the ticket code it scanned | n/a |
| 7 | New device → node | `POST /pair/device-key/{op}/finalize {sas_version:2, sas_digest, proof}` with `proof` over `bitsov-device-register-v2 … sas_digest:` (automatic, no human tap) | Constant-time digest compare. Mismatch → op dropped, `sas_failures += 1`. Match → `confirmed = true` |
| 8 | New device (UI) | Shows the 4 words and "Approve on your other device". Quiet "They don't match" → `DELETE /pair/device-key/{op}` | n/a |
| 9 | Owner device → node (owner tunnel, poll) | `GET /pair/device-key/pending` → `GET /pair/device-key/{op}/delegation` | Read only |
| 10 | Owner device (UI) | Rebuilds the approval message from the fields and its pinned node fingerprint, recomputes the words from `sas_digest`, and shows the words + one line. Face ID / Touch ID signs | n/a |
| 11 | Owner device → node | `POST /pair/device-key/{op}/second-device/approve {approver_key_id, signature}` | §5 checks. Enrolled `DeviceKey{enrolled_by:"second_device:<approver key_id>"}`, pairing scopes → `[read, receive]`, op + nonce consumed, provisional record removed, all in one lock and one persist |
| 11′ | Owner device → node | `POST …/second-device/reject {approver_key_id, signature}` (domain `…-reject-v1`, same fields) | Op dropped, provisional pairing revoked, `sas_failures += 1` |
| 12 | New device → node | `GET /pair/device-key/{op}` → `registered` | Normal paired device |

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
noise_handshake_hash:{64 hex}
noise_client_static:{64 hex}
box_transport_pubkey:{64 hex}
ticket_id:{32 hex}
sas_version:2
sas_digest:{64 hex}
sas_words:{w1} {w2} {w3} {w4}
expires_at:{unix seconds}
```

The reject message is identical except for the domain `bitsov-second-device-reject-v1`. The domain differs from `bitsov-owner-delegation-v1/v2`, `bitsov-device-register-v1/v2`, `bitsov-ticket-v1/v2`, `bitsov-relation-intent-v1` and the app's `unlock-v1`, so a signature from one protocol cannot be used in another. Approver-side rules (normative for the app): rebuild the bytes locally and require them to be byte-equal to `approval_message`, recompute `sas_words` from `sas_digest`, require `node` to equal the pinned fingerprint, and refuse when `expires_at` is in the past.

## 5. Node verification and state

**Approve: checks, all under the pairing lock, in this order. Nothing is written until all of them pass.**

| # | Check | Error |
|---|---|---|
| 1 | Flag on, `local_owner_device`, owner signing key in memory, not locked | `OwnerChannelUnavailable` (503) |
| 2 | Caller's tunnel `client_id` = token `client_id`; approver pairing is not provisional | 403 |
| 3 | `intent_key(approver_client, epoch, key_id)`: the approver key is registered, at its current epoch, with a valid owner approval | `BadProof` (403) |
| 4 | Approver `client_id` ≠ op `client_id` (no self-approval) and the approver key was registered before the op was created | 403 |
| 5 | Op exists, `sas_version == 2`, `confirmed`, `now < expires_at`, created by this process (`DeviceSas` present) | `UnknownOperation` / `Expired` |
| 6 | The op's pairing is still provisional, at the same epoch and `client_pubkey`, and its provisional deadline has not passed | `PairingInvalid` |
| 7 | `key_id_for(device_key)` matches; key not already enrolled; under `MAX_DEVICE_KEYS_PER_CLIENT` | `NotGrantable` |
| 8 | `verify_p256(approver_pubkey, approval_message(node state), sig)` | `BadProof`; counts toward the approver rate limit; the op is **not** consumed |
| 9 | Sign `owner_approval_message` with the seed-derived owner key → `DeviceKey`; set scopes; remove the op and the provisional record; record `registered_ops[op]`; persist (roll back on error) | `Io` |

**State.**

| Record | Persisted? | Lifetime | Single use |
|---|---|---|---|
| Second-device ticket | Memory: owner tickets. File: console `second_` code, as today | 5 min (owner) / 10 min default, 30 min max (console) | Removed on consumption, including exact retries (`OWNER_TICKET_PREFIX` rule extended to `second_`) |
| Provisional pairing | `PairedClient` with `scopes: []` (no file format change) plus a memory record `{ticket_id, ticket_commitment, issuer, deadline}` | 15 min. A sweep on start and every minute deletes provisional pairings past their deadline or with no memory record (for example after a restart) | One enrollment |
| `PendingDeviceKey{sas_version:2}` | Yes (`sas_version` only); `DeviceSas` is memory-only | 300 s from step 5, and never past the provisional deadline. A restart makes it `lost` | Consumed with its `delegation_nonce` at approve or reject |

**Rate limits.**

| Limit | Value | Source |
|---|---|---|
| Second-device ticket issues | 5 / 15 min node-wide (shared with owner tickets); challenge reads 30 / min | `ticket.rs:12-14` |
| Provisional pairings alive | 2 node-wide | new |
| Live SAS ops node-wide (v1 + v2) | 1 | `device.rs:503-509` |
| Device-key requests per client | 1 / 30 s | `device.rs:512-519` |
| SAS failures (digest mismatch, cancel, reject) | 3 per process → SAS closed until restart or `konsensus pair-reset-sas` | `pairing.rs:661` + new console reset |
| Approver bad signatures | 10 / hour per approver key → 429 | `approval.rs` `rate()` helper |

## 6. Failure modes

| Case | What happens | New device shows | Approver shows |
|---|---|---|---|
| Owner device offline / asleep | Nothing polls. The op expires at 300 s; the new device may re-request (new nonce, new words) until the 15 min provisional deadline, then the pairing is swept | "Approve on your other device" → after expiry "Your other device didn't answer. Try again." | n/a |
| Words mismatch (approver) | Reject → op dropped, pairing revoked, `sas_failures += 1` | "Stopped. Nothing was added." | "Stopped. Nothing was added." |
| Words mismatch (new device) | `DELETE` op → `sas_failures += 1`; the pairing stays provisional until its deadline | Same | The op disappears from pending |
| New device's view ≠ node's (MITM or wrong box) | Finalize digest mismatch → op dropped, failure counted; the approver never sees words | "Couldn't verify this box." | n/a |
| Timeout mid-approval | The approve after `expires_at` → `Expired`; nothing written | Expired | "This request expired." |
| Replay of the approve signature | Op and nonce already consumed → `UnknownOperation`. Another node → `node` differs. A changed approver epoch → check 3 | n/a | n/a |
| Stolen QR | A thief who consumes the ticket first gets a **scopeless** provisional pairing that can only ask for enrollment. The real device fails with "used". The approver sees words that match no device in hand; if it approves anyway, the thief's device is enrolled → console revoke (§7). An owner-minted ticket also lets the owner app flag a `ticket_id` that it never minted | "This QR was already used." | Words with no device: do not approve |
| Two devices racing one ticket | The single-use ticket picks one; the other fails at the Noise pairing step | "This QR was already used." | n/a |
| Box restart mid-flow | Memory tickets and `DeviceSas` are gone; the provisional pairing is swept; pending is `lost` | "Start over" | The op disappears |
| Approver revoked mid-flow | Check 3 fails under the lock | n/a | 403 |
| Box has **no** enrolled owner device (`owner_device_count() == 0`) | Ticket `purpose=second_device` and `pair-ticket --second-device` are refused with `no_owner_device`. **Recovery is console-only (re-claim with Rasmus at the box). Out of scope.** | "This box has no owner device yet." | n/a |

## 7. API and CLI changes

**HTTP (tunnel router only; the loopback router is unchanged).**

| Route | Who | Change |
|---|---|---|
| `GET/POST /api/v1/pair/ticket` | enrolled owner device | `POST` accepts `purpose: "second_device"`, signed as `bitsov-ticket-v2\nnode:{fp}\nnonce:{n}\npurpose:second_device`. Without `purpose`, the v1 path is unchanged |
| `POST /api/v1/pair/device-key` | provisional or normal pairing | Accepts `sas_version: 2` only from a provisional pairing over its own tunnel |
| `POST /api/v1/pair/device-key/{op}/finalize` | own op | Accepts `sas_version: 2` |
| `GET/DELETE /api/v1/pair/device-key/{op}` | own op | Status adds `approval: "owner_device"`. Rejected ops report `lost` |
| `GET /api/v1/pair/device-key/pending` | enrolled owner device | Lists v2 ops (`sas_version: 2`) |
| `GET /api/v1/pair/device-key/{op}/delegation` | enrolled owner device | For v2, adds `noise_handshake_hash`, `noise_client_static`, `box_transport_pubkey`, `ticket_id`, `sas_digest`, `approval_message` (null until finalized). Never the claim, never the ticket code |
| `POST /api/v1/pair/device-key/{op}/second-device/approve` | enrolled owner device | **New** `{approver_key_id, signature}` → `{op_id, key_id, status:"registered"}` |
| `POST /api/v1/pair/device-key/{op}/second-device/reject` | enrolled owner device | **New**, same body → `204` |
| `POST /api/v1/pair/device-key/{op}/delegate` | n/a | Refuses `sas_version: 2` ops (so an old app cannot approve a v2 op with delegation-v2) |
| `GET /api/v1/health` `api_capabilities` | any | Adds `second_device_enrollment_v1` when the flag is on and owner-device mode is live |

Provisional tokens are accepted **only** by `POST /pair/token`, `GET /pair/challenge`, and the 4 own-op device-key routes above. This needs a new `EnrollmentAuth` extractor and `issue_token_kind` must allow an empty scope set for provisional pairings. Every other route sees no scope and returns 403. All new responses use `Cache-Control: no-store`. Audit events: `pair.second_device_ticket_issued`, `pair.second_device_requested`, `pair.second_device_enrolled`, `pair.second_device_rejected`, `pair.provisional_swept`. They carry the approver client, epoch, key id and op id, and never the nonce, signature, ticket, digest or words.

**CLI (owner console, control socket).**

| Command | Change |
|---|---|
| `konsensus pair-ticket --second-device [--qr] [--ttl 10m]` | New flag: `second_` code, 10 min default, 30 min max. Refused when no owner device is enrolled or the flag is off |
| `konsensus pair-status` | Lists provisional pairings (deadline) and pending v2 ops (device name, fingerprint, words), so the console can watch or cancel |
| `konsensus device list` | Shows `enrolled_by` (`console`, `device:…`, `second_device:<key_id>`) and the approver's device name |
| `konsensus device revoke --key <id> [--with-pairing]` | `--with-pairing` also revokes the device's pairing (all tokens die). **This is the C3 revoke** |
| `konsensus device revoke --approved-by <key_id>` | Revokes every key that this approver enrolled, for a lost or stolen owner device |
| `konsensus pair-cancel --op <id>` | Drops a pending v2 op and its provisional pairing |
| `konsensus pair-reset-sas` | Clears `sas_failures` |
| `konsensus device approve --op <id>` | Unchanged. It also accepts a confirmed v2 op where `--owner-control` is live (console fallback when no owner device is online) |

## 8. Migration and compatibility

| Area | Effect |
|---|---|
| First device (remote first run, claim-bound SAS v1) | Unchanged. `bitsov-sas-v1`, the claim checks and `create-pending`/`finalize` are untouched |
| Existing second-device path (claim-bound SAS v1 + `delegation-v2`) | Kept working for current apps, behind `second_device_claim_v1` (default `true`). Retiring it is open question 2 |
| Existing pairings and device keys | Unchanged. No re-enrollment |
| Pairing file | **No version bump** (stays `8`). Provisional = `scopes: []`, which older nodes already treat as inert. `sas_version: 2` on a pending op makes an older binary refuse it (no `DeviceSas`), so a rollback fails closed |
| Old apps | Never request `purpose:"second_device"` and never see the capability. An old app that scans a `second_` console QR gets a scopeless pairing that is swept after 15 min, and the console warns about this when it prints the QR |
| Boxes without a claim code (pre-N3) | v2 does not depend on `claim-code`. It requires an enrolled owner device and owner-device mode, the same as delegation |

## 9. Rollout flag

`[pairing] second_device_enrollment = false` by default in the first rc. When it is `false`, none of the §7 additions are mounted or advertised, and behaviour is byte-identical to today. It is turned on per signet box (Rasmus's Pi first, then the father's box) after E2E. The app gates the no-claim flow on `second_device_enrollment_v1` and falls back to the claim flow otherwise. Mainnet stays off until two non-builder reviews PASS on the same head and one signet E2E run passes with iPhone (Secure Enclave) as the new device and a Mac as the approver.

## 10. Tests

| # | Test | Layer |
|---|---|---|
| T1 | Frozen SAS v2 vector (bytes as v1, ticket commitment `77`×32); flipping each field changes the digest; the v1 vector is unchanged | `sas.rs` unit |
| T2 | v2 request **never reads `claim-code`**: passes with the file absent, unreadable, or a symlink | `device.rs` unit |
| T3 | Approve happy path: iPhone-format key (65-byte, DER sig), owner Mac approves; `enrolled_by`, scopes `[read, receive]`, `registered` status | pairing unit + tunnel integration |
| T4 | Each field of the approval message mutated → `BadProof`, op not consumed | unit, table-driven |
| T5 | Replay after success; replay to a second node; after an approver epoch bump; after approver revoke; self-approval; approver enrolled after the op | unit |
| T6 | `delegation-v2` signature on a v2 op is refused; a v2 approval signature on a v1 op is refused | unit |
| T7 | Finalize digest mismatch → op dropped, failure counted; 3 failures → closed; `pair-reset-sas` reopens | unit |
| T8 | Reject path revokes the provisional pairing; the new device sees `lost` | unit |
| T9 | Provisional token: 403 on every non-enrollment route (iterate the router table) | router test |
| T10 | Provisional sweep: deadline passes; restart drops the memory record → swept at start; an older-format reader treats `scopes: []` as inert | unit + restart test |
| T11 | Expiry by wall clock and by monotonic clock (`created_at` ≥ 300 s) | unit |
| T12 | Concurrent approves on one op → exactly one `registered` | unit (`concurrent_approval_consumes_exactly_once` pattern) |
| T13 | Stolen QR: a second consumer of the same ticket fails; a thief's provisional pairing cannot read status, balance or history | tunnel integration |
| T14 | No owner device → ticket refused with `no_owner_device`; flag off → routes 404, capability absent | unit + router |
| T15 | Rate limits: 2 provisional, 1 live SAS op, 10 bad approver sigs / hour → 429 | unit |
| T16 | Console: `device revoke --with-pairing`, `--approved-by`, `pair-cancel`, `pair-status` output carries no secrets | control-socket tests |
| T17 | First-device regression: remote first run with claim SAS v1 and existing v1 delegation pass unchanged | existing suites stay green |
| T18 | Signet E2E: iPhone scans the Mac QR, words match, Mac Face ID / Touch ID, iPhone registered; console revoke ends its envelopes | regtest/signet script |

## 11. PR plan

| PR | Scope |
|---|---|
| **A: node core** | SAS v2 digest + vector; ticket `purpose` / `bitsov-ticket-v2`; `second_` console code; provisional pairing, sweep and `EnrollmentAuth`; v2 request/finalize; approve/reject routes and messages; flag + capability; audit; T1–T15, T17 |
| **B: console + docs** | `pair-ticket --second-device`, `pair-status`, `device list`/`revoke` options, `pair-cancel`, `pair-reset-sas`; update `docs/security/device-keys.md`, `pairing.md` (v2 vector) and `operations/home-node.md`; T16, T18 |

## 12. Open questions

| # | Question | Default if unanswered |
|---|---|---|
| 1 | Should an approver that did **not** mint the ticket (a console QR) see an extra caution line, or should console second-device QRs be disallowed entirely so that every QR comes from an owner device? | Allowed, with the same one line |
| 2 | When is the claim-bound second-device path (`second_device_claim_v1`) turned off? Proposed: one rc after the app ships N-2DEV | On for one rc |
| 3 | Is a 15-minute provisional deadline enough for the father pre-mortem's "leave the app to find Tailscale" case, or should re-requests extend it? | 15 min, no extension |
| 4 | Should `sas_failures` stay process-wide (a thief with a stolen QR can block enrollment until restart) or be counted per provisional pairing? | Process-wide plus `pair-reset-sas` |
| 5 | Does the phone's "must never be the only owner device" rule (`device-keys.md` §Keep a second owner device) block a phone from being the **approver** for another phone? | No: the rule is about count, not approver type |
| 6 | Optional WebSocket hint ("pending enrollment changed", no data) on the owner tunnel to replace the 2 s poll? | Poll only in v1 |
