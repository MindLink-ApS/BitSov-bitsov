# P2: bound peer JSON decodes outside Frame

Prepared PR body only. No PR is opened by this change.

## Problem and change

Relay control bodies and raw deposited/held envelopes bypassed the Frame pre-serde string ceiling. A wrong-type string could allocate a large serde diagnostic, and ignored escaped keys could allocate parser scratch. The same gap existed at other live raw peer payload boundaries.

- Expose `wire::envelope_from_bytes`, using the exact borrowing envelope field adapter already used by `Frame::Message`, `Gossip` and paid peer exchange.
- Move the existing borrowing string helpers into core and share the allocation-free raw-token/depth scanner. Generic core serde, reader/Value support and owner configuration parsing stay unchanged.
- Route live raw peer JSON through the shared preflight and fixed `invalid wire JSON` errors. Frame retains its fixed `invalid frame JSON` error contract. No serde error or raw input survives in the new payload error type, including held-mail logging.
- Bound relay register/deposit byte vectors, ACK hex IDs and Merkle proof dimensions during deserialization.
- Preserve legitimate large payload strings only at their typed top-level fields: file `data_b64` allows the base64 size of a 4 MiB upload; page `body` allows 256 KiB decoded UTF-8, including fully escaped input. These exceptions do not apply to keys, wrong-type numeric strings or nested lookalikes.

Resource policy: ordinary JSON string tokens are capped at 393,216 raw bytes, lexical nesting at 128 and admitted input at 16 MiB (earlier transport/payload caps still apply). Narrower envelope field caps remain unchanged. This is a bound on string scratch/error amplification, **not** a claim that all JSON trees or entire decodes allocate at most the token cap. Collection budgets outside the existing Frame and newly bounded relay fields are a separate concern.

## Validation

- `cargo test -p konsensus-core -p konsensus-message -p konsensus-api -p konsensus-node --no-fail-fast`: **PASS (exit 0): 3412 passed, 0 failed, 1 ignored across 121 suites/doc-test targets**. The existing ignored test is `whitelist_replay_tests::recovery_is_complete_above_1000_peers_after_dbh1` (DBH1/#207 prerequisite).
- `cargo clippy --workspace -- -D warnings`: **PASS (exit 0)**. Existing sqlx-postgres future-incompatibility notice remains.
- `python3 scripts/test-core-serde-mutations.py`: **10/10 killed by test assertion failures, no build-error kills; sources restored**. Mutants: raw-token preflight, standalone envelope adapter, pre-copy fixed-width string bound, Deposit body entry, Drain body entry, deposited envelope entry, held envelope entry, large-field decoded bound, unfinished large string, room admission fail-closed.
- Allocation tests exercise actual relay dispatch for Register/Ack/Deposit/Drain and the shared standalone envelope decoder with wrong-type strings and escaped unknown keys at cap+1 and 2 MiB. Oversize rejection must stay at **≤4 KiB largest allocation / ≤16 KiB total**, excluding fixture construction. Below-ceiling oversized envelope IDs/recipient/payment proof/reference strings also test pre-copy field bounds.
- Honest tests cover standalone envelope round-trips and escaped IDs, exact raw-token boundaries, real relay deposit/drain/ack, maximum 4 MiB file data, and maximum fully escaped 256 KiB page bodies. Existing encrypted file / BOLT11 headroom regressions pass.
- Review regressions reproduce and fix unfinished large-string scratch allocation (trailing escape) and prevent oversized room JSON from falling back to unbound chat. Shared Frame token/depth behavior and its transport-level outer-byte cap remain intact.
- Independent read-only review: both findings above resolved; no outstanding findings. Audit table independently checked against baseline grep: all 600 occurrences accounted for.

The first sandboxed suite attempt could not bind loopback sockets; the full run uses local-socket permission. No source changes were made to bypass those integration tests.

## Complete decode-site audit

Inventory command: `rg -n 'serde_json::(from_slice|from_str|from_reader)' crates` on baseline `5a1516e5fc54c4581a1a2a13cbcc3f35258ab29e` (main after #363/#366). There were **600 occurrences across 169 files**; no `from_reader` occurrences. Tables below enumerate every match, including test/benchmark code. Line numbers intentionally refer to that immutable baseline, so moved code remains traceable. Explicit `Deserializer::from_str` use was also checked: the three wire helper uses already operate behind the same preflight/field guards; no imported aliases of the three searched functions were found.

“Peer” here means mesh peer, relay-mailbox depositor, or remote application client. Configured chain/Lightning providers are separately marked external services; their RPC response policies are not changed. Locally regenerated records are distinguished from opaque peer byte strings: the former cannot contain raw JSON syntax chosen by a peer, while relay held bytes can. Owner-imported peer cards/links are guarded even though the owner initiated the import.

### Production/library occurrences (88)

| Baseline file | Lines | Input provenance / peer influence | Disposition |
|---|---|---|---|
| `crates/konsensus-api/src/audit.rs` | 143 | Indirect peer values possible; locally serialized audit records, not raw peer JSON | Unchanged |
| `crates/konsensus-api/src/auth.rs` | 422, 436 | No — node-signed JWT; HMAC verified BEFORE JSON | Unchanged; remote bearer cannot choose decoded bytes without server key |
| `crates/konsensus-api/src/bootstrap.rs` | 1732 | Yes — remote bootstrap tunnel client | Shared `wire_json` preflight and fixed `DecodeError`; keep borrowing/zeroizing password flow |
| `crates/konsensus-api/src/calls.rs` | 212, 232 | Yes — incoming and locally composed call signal paths | Shared `wire_json` preflight and fixed `DecodeError` |
| `crates/konsensus-api/src/control.rs` | 1108, 1246 | No raw peer JSON — owner Unix control socket request/response | Unchanged |
| `crates/konsensus-api/src/handlers/browse.rs` | 529 | No — owner-authored outgoing compose request | Unchanged |
| `crates/konsensus-api/src/handlers/browse.rs` | 261 | Yes — raw mesh peer JSON | `PageResponse::from_wire_bytes`; bounded 256 KiB decoded body exception |
| `crates/konsensus-api/src/handlers/calendar.rs` | 210, 215, 275, 301, 413, 417, 732 | Indirect peer values possible; JSON regenerated locally from typed calendar payloads | Unchanged persistence read; original raw ingress now guarded in `msg_handler` |
| `crates/konsensus-api/src/handlers/front_door.rs` | 237, 259 | No raw peer JSON — owner local card and sequence recovery | Unchanged |
| `crates/konsensus-api/src/handlers/invites.rs` | 475 | Yes — peer-issued invitation imported by owner | Shared `wire_json` preflight and fixed `DecodeError` |
| `crates/konsensus-api/src/handlers/messages/admission_journal.rs` | 65, 231 | No raw peer JSON — local admission journal | Unchanged |
| `crates/konsensus-api/src/handlers/messages/operations.rs` | 82 | No raw peer JSON — locally serialized recovery record | Unchanged |
| `crates/konsensus-api/src/handlers/payments.rs` | 922 | No raw peer JSON — locally serialized operation result | Unchanged |
| `crates/konsensus-api/src/handlers/sponsor.rs` | 305 | No raw peer JSON — owner sponsor ledger | Unchanged |
| `crates/konsensus-api/src/locked_body.rs` | 61 | Yes — unlock client, including remote tunnel | Shared `wire_json` preflight and fixed `DecodeError`; keep borrowing/zeroizing password flow |
| `crates/konsensus-api/src/pairing.rs` | 860, 1333 | No raw peer JSON — owner pairing client database | Unchanged |
| `crates/konsensus-api/src/remote_access.rs` | 79 | Yes — external pairing link imported by owner | Shared `wire_json` preflight and fixed `DecodeError` |
| `crates/konsensus-api/src/ws.rs` | 220 | Yes — authenticated local/remote app client (not mesh envelope) | Shared `wire_json` preflight and fixed `DecodeError` |
| `crates/konsensus-bsx/src/parse.rs` | 46 | Potential untrusted caller input; no production call sites in this workspace (only library/tests) | Unchanged standalone BSX parser; not a mesh/mailbox decode path; existing 1 MiB document cap |
| `crates/konsensus-chain/src/bearer.rs` | 202 | External service, not mesh peer/mailbox — owner-selected bearer service | Unchanged; separate backend trust boundary |
| `crates/konsensus-chain/src/esplora.rs` | 279 | External service, not mesh peer/mailbox — configured Esplora backend | Unchanged; separate backend trust boundary |
| `crates/konsensus-core/src/front_door.rs` | 469, 484 | Yes — peer card, including paid porch reply | Shared `wire_json` preflight and fixed `DecodeError` |
| `crates/konsensus-core/src/introduction.rs` | 323 | Yes — peer introduction pasted/scanned by owner | Shared `wire_json` preflight and fixed `DecodeError` |
| `crates/konsensus-core/src/payloads/call.rs` | 185 | Yes — raw mesh peer JSON | Shared `wire_json` preflight and fixed `DecodeError` |
| `crates/konsensus-core/src/payloads/room.rs` | 124 | Yes — raw mesh peer JSON | Shared `wire_json` preflight and fixed `DecodeError` before the subsequent typed `from_value`; preflight rejection fails closed, never becomes unbound chat |
| `crates/konsensus-crypto/src/session.rs` | 317 | No raw peer JSON — locally serialized, AEAD-authenticated ratchet state | Unchanged |
| `crates/konsensus-lightning/src/cln.rs` | 573 | External service, not mesh peer/mailbox — configured authenticated CLN RPC | Unchanged; separate backend trust boundary |
| `crates/konsensus-lightning/src/ldk.rs` | 2637 | External service, not mesh peer/mailbox — configured Esplora startup fee probe | Unchanged; separate backend trust boundary |
| `crates/konsensus-lightning/src/lnd.rs` | 245, 590, 1035 | External service, not mesh peer/mailbox — configured authenticated LND RPC/streams | Unchanged; separate backend trust boundary |
| `crates/konsensus-lightning/src/move_home/mod.rs` | 183 | No raw peer JSON — owner move-home state | Unchanged |
| `crates/konsensus-lightning/src/recover/journal.rs` | 54 | No raw peer JSON — owner recovery journal | Unchanged |
| `crates/konsensus-lightning/src/tower/outbox.rs` | 228 | No raw peer JSON — locally produced tower delivery blob | Unchanged |
| `crates/konsensus-message/src/wire.rs` | 1315 | Yes — raw mesh peer JSON | Already guarded; now uses shared scanner, retains `invalid frame JSON` |
| `crates/konsensus-message/src/wire/bounded_json.rs` | 76, 111, 134, 160 | Yes — nested admitted wire tokens | Move helpers unchanged to core `wire_json/strings.rs`; caller preflight + individual pre-copy bounds; outer error remains fixed |
| `crates/konsensus-node/src/cli/locked.rs` | 43, 128 | No raw peer JSON — local identity file | Unchanged |
| `crates/konsensus-node/src/cli/ticket.rs` | 151 | No raw peer JSON — owner-selected ticket metadata file | Unchanged |
| `crates/konsensus-node/src/main.rs` | 1229 | No raw peer JSON — local identity file | Unchanged |
| `crates/konsensus-node/src/msg_handler.rs` | 944, 1002, 1089 | Yes — raw mesh peer JSON | Shared `wire_json` preflight and fixed `DecodeError` |
| `crates/konsensus-node/src/msg_handler.rs` | 858 | Yes — raw mesh peer JSON | `FilePayload::from_wire_bytes`; bounded top-level base64 exception |
| `crates/konsensus-node/src/node.rs` | 653 | No raw peer JSON — locally generated fee-rate snapshot | Unchanged |
| `crates/konsensus-node/src/offline_safety.rs` | 108 | No raw peer JSON — local heartbeat records | Unchanged |
| `crates/konsensus-node/src/peer_exchange.rs` | 195 | Peer-carried, but snapshot is locally minted and AEAD-authenticated | Use `Frame::from_bytes` anyway; retain validation and adapters |
| `crates/konsensus-node/src/relay/dispatch.rs` | 278, 413 | Yes — depositor inner bytes / raw held mailbox bytes | `envelope_from_bytes`: identical field adapter to `Frame::Message`, shared preflight, fixed error |
| `crates/konsensus-node/src/relay/dispatch.rs` | 205, 251, 261, 396 | Yes — raw mesh peer JSON | Shared `wire_json` preflight and fixed `DecodeError`; bounded byte arrays, ACK identifiers and Merkle path |
| `crates/konsensus-node/src/remote_access.rs` | 212 | No raw peer JSON — local public identity metadata | Unchanged |
| `crates/konsensus-node/src/remote_access.rs` | 811 | Yes — remote Noise client, before application authentication | Shared `wire_json` preflight and fixed `DecodeError` |
| `crates/konsensus-node/src/restore_fence.rs` | 50 | No raw peer JSON — local INSTANCE record | Unchanged |
| `crates/konsensus-storage/src/encrypted.rs` | 202 | No raw mesh peer JSON — local metadata serialized then AEAD-encrypted | Unchanged |
| `crates/konsensus-storage/src/postgres.rs` | 528 | Indirect peer references; fixed-width IDs serialized locally after envelope admission | Unchanged canonical persistence read; original raw ingress uses envelope adapter |
| `crates/konsensus-storage/src/postgres.rs` | 1369, 1396, 1539, 1564, 2297, 2695 | No raw mesh peer JSON — locally serialized room/peer metadata (owner API/state) | Unchanged |
| `crates/konsensus-storage/src/sqlite.rs` | 376 | Indirect peer references; fixed-width IDs serialized locally after envelope admission | Unchanged canonical persistence read; original raw ingress uses envelope adapter |
| `crates/konsensus-storage/src/sqlite.rs` | 1274, 1301, 1448, 1473, 2201, 2595 | No raw mesh peer JSON — locally serialized room/peer metadata (owner API/state) | Unchanged |
| `crates/konsensus-storage/src/whitelist_backup.rs` | 109 | No raw peer JSON — owner AEAD-authenticated backup | Unchanged |

### Test and benchmark occurrences

All entries below decode fixtures, round-trips, local mock responses, or test outputs. They are not production peer ingress and remain unchanged. Listed separately rather than silently dropping them from the grep inventory.

| File | Baseline lines |
|---|---|
| `crates/konsensus-api/src/audit.rs` | 248, 253, 284, 319 |
| `crates/konsensus-api/src/control.rs` | 1362, 1369, 1371, 1397, 1399, 1401, 1402 |
| `crates/konsensus-api/src/error.rs` | 299 |
| `crates/konsensus-api/src/handlers/gossip.rs` | 219, 227 |
| `crates/konsensus-api/src/handlers/messages/compose.rs` | 4980 |
| `crates/konsensus-api/src/pairing/approval.rs` | 1123, 1249 |
| `crates/konsensus-api/src/pairing/second_device_tests.rs` | 332, 364, 1482, 1690 |
| `crates/konsensus-api/src/spend_budget.rs` | 1373 |
| `crates/konsensus-api/tests/actual_fee_paid.rs` | 40 |
| `crates/konsensus-api/tests/auth_tests.rs` | 25, 50, 75, 166, 266, 464, 522, 526, 597, 616, 654, 737, 769, 834, 912, 1027, 1153, 1363, 1667, 1751, 1978, 2041 |
| `crates/konsensus-api/tests/balance_breakdown_tests.rs` | 70 |
| `crates/konsensus-api/tests/bootstrap_tests.rs` | 422, 456 |
| `crates/konsensus-api/tests/budget_grant/expiry.rs` | 8, 26, 147 |
| `crates/konsensus-api/tests/budget_grant/first_contact.rs` | 203, 326, 329 |
| `crates/konsensus-api/tests/budget_grant/first_contact_grant.rs` | 27 |
| `crates/konsensus-api/tests/budget_grant/lifecycle.rs` | 14, 207, 232, 244 |
| `crates/konsensus-api/tests/budget_grant/sponsor.rs` | 59, 178 |
| `crates/konsensus-api/tests/budget_grant_tests.rs` | 550, 1073, 1080, 1088, 1109, 1159, 2032, 2075, 2207, 2240, 2881 |
| `crates/konsensus-api/tests/calendar_readmission_errors.rs` | 222 |
| `crates/konsensus-api/tests/call_state_tests.rs` | 48 |
| `crates/konsensus-api/tests/channel_id_tests.rs` | 97, 148 |
| `crates/konsensus-api/tests/common/mod.rs` | 669 |
| `crates/konsensus-api/tests/data_freshness_tests.rs` | 60 |
| `crates/konsensus-api/tests/device_key_http_tests.rs` | 96, 160, 971, 1010 |
| `crates/konsensus-api/tests/device_key_tests.rs` | 389, 412, 1210, 1442, 1499, 1518, 1776, 1897 |
| `crates/konsensus-api/tests/elevation_tests.rs` | 89 |
| `crates/konsensus-api/tests/fee_review_regressions.rs` | 17 |
| `crates/konsensus-api/tests/file_tests.rs` | 34, 83, 308, 323, 353, 382, 488, 542, 646 |
| `crates/konsensus-api/tests/first_contact_tests.rs` | 87, 187, 197, 321, 450, 512, 562 |
| `crates/konsensus-api/tests/front_door_scope_tests.rs` | 121 |
| `crates/konsensus-api/tests/front_door_tests.rs` | 86, 470 |
| `crates/konsensus-api/tests/funding_fee_tests.rs` | 134 |
| `crates/konsensus-api/tests/introduction_tests.rs` | 91 |
| `crates/konsensus-api/tests/invites_tests.rs` | 92, 128, 142, 194, 235, 480, 561, 592, 627, 661, 692, 737 |
| `crates/konsensus-api/tests/keysend_cap_tests.rs` | 36 |
| `crates/konsensus-api/tests/local_bootstrap_tests.rs` | 113, 1029, 1207, 1376 |
| `crates/konsensus-api/tests/local_request_tests.rs` | 134, 171, 297 |
| `crates/konsensus-api/tests/local_spend_tests.rs` | 78 |
| `crates/konsensus-api/tests/locked_mode_tests.rs` | 178, 249 |
| `crates/konsensus-api/tests/message_tests.rs` | 41, 89, 120, 151, 180, 216, 254, 295, 313, 331, 444, 483, 507, 544, 577, 660, 739, 932, 1029, 1043, 1147, 1210, 1254, 1280, 1305, 1340, 1383, 1435, 1479, 1509, 1693, 1714, 1767, 1810, 1824, 1865, 1968, 2119, 2443, 2573, 2676, 2715, 3022, 3064, 3341, 3367 |
| `crates/konsensus-api/tests/mnemonic_zeroize_tests.rs` | 17, 18, 19, 27 |
| `crates/konsensus-api/tests/offline_readiness_tests.rs` | 96, 120, 191, 248 |
| `crates/konsensus-api/tests/offline_safety_tests.rs` | 100, 121 |
| `crates/konsensus-api/tests/offline_side_effect_tests.rs` | 59 |
| `crates/konsensus-api/tests/onboarding_state_tests.rs` | 24, 38 |
| `crates/konsensus-api/tests/open_channel_idempotency_tests.rs` | 172, 382 |
| `crates/konsensus-api/tests/organism_tests.rs` | 57 |
| `crates/konsensus-api/tests/outbox_operations.rs` | 63, 294, 539, 565, 651, 746, 779, 1272, 1435, 1603, 1870, 1925, 1995 |
| `crates/konsensus-api/tests/outbox_readmission.rs` | 146 |
| `crates/konsensus-api/tests/owner_approval_http_tests.rs` | 250, 986 |
| `crates/konsensus-api/tests/paid_delivery_errors.rs` | 113, 164 |
| `crates/konsensus-api/tests/pairing_tests.rs` | 105, 1073, 1209, 1282, 1320, 1715, 1744 |
| `crates/konsensus-api/tests/payment_tests.rs` | 57, 92, 113, 141, 162, 183, 204, 236, 258, 357, 381, 410, 444, 521, 563, 634, 655, 708, 730, 767, 789, 1127, 1378, 1497, 1627, 1672, 1693, 1714, 1761, 1887, 2006, 2035, 2080, 2111, 2357, 2460, 2478, 2506, 2529 |
| `crates/konsensus-api/tests/peer_admission_tests.rs` | 142, 153 |
| `crates/konsensus-api/tests/peer_import_tests.rs` | 33 |
| `crates/konsensus-api/tests/peer_mutation_tests.rs` | 112, 217 |
| `crates/konsensus-api/tests/peer_tests.rs` | 27, 64, 78, 114, 134, 211, 237, 259, 273, 335, 373, 441, 550, 598, 628, 646, 769, 812, 846, 1001, 1057, 1166, 1218, 1425, 1502, 1585, 1611, 1663, 1695, 1724, 2026, 2083, 2281 |
| `crates/konsensus-api/tests/peer_validation_tests.rs` | 88, 221 |
| `crates/konsensus-api/tests/price_cap_tests.rs` | 30, 54 |
| `crates/konsensus-api/tests/readmission_quote_generation.rs` | 206 |
| `crates/konsensus-api/tests/reconnect_recovery_tests.rs` | 403, 524, 630 |
| `crates/konsensus-api/tests/recovery_status_tests.rs` | 35, 210 |
| `crates/konsensus-api/tests/room_binding_tests.rs` | 85, 318, 407, 478 |
| `crates/konsensus-api/tests/room_tests.rs` | 65, 99, 125, 165, 197, 324, 338, 385, 414, 427, 498, 575, 601, 624, 646, 673, 1043 |
| `crates/konsensus-api/tests/scope_regression_tests.rs` | 72, 87 |
| `crates/konsensus-api/tests/sponsor_tests.rs` | 81, 281, 406, 469, 490, 554, 560, 574, 619, 627, 689, 711 |
| `crates/konsensus-api/tests/starter_channel_tests.rs` | 264, 336, 388 |
| `crates/konsensus-api/tests/tower_status_tests.rs` | 68 |
| `crates/konsensus-api/tests/unreadable_storage_tests.rs` | 43 |
| `crates/konsensus-api/tests/verify_mnemonic_tests.rs` | 36 |
| `crates/konsensus-chain/src/recovery/adapters_tests.rs` | 185 |
| `crates/konsensus-chain/tests/support/electrum_fixture.rs` | 29 |
| `crates/konsensus-core/benches/envelope_bench.rs` | 105 |
| `crates/konsensus-core/src/calendar.rs` | 699, 706, 755 |
| `crates/konsensus-core/src/envelope.rs` | 378, 444, 585 |
| `crates/konsensus-core/src/federation.rs` | 247 |
| `crates/konsensus-core/src/payloads/calendar.rs` | 147, 161, 184, 196, 219, 229 |
| `crates/konsensus-core/src/payloads/content.rs` | 210, 217, 236, 254, 261, 294, 349 |
| `crates/konsensus-core/src/payloads/discovery.rs` | 185, 193, 261, 268, 346, 353, 407, 414 |
| `crates/konsensus-core/src/profile.rs` | 297, 314, 332, 357, 366, 382, 401, 402 |
| `crates/konsensus-core/src/traits/chain.rs` | 162 |
| `crates/konsensus-core/src/traits/lightning.rs` | 1064 |
| `crates/konsensus-core/src/types.rs` | 678, 687, 734, 821 |
| `crates/konsensus-core/tests/hardening_tests.rs` | 210, 232, 423, 466, 474, 482, 490, 592 |
| `crates/konsensus-crypto/src/tests/double_ratchet.rs` | 247, 248, 288, 345, 373 |
| `crates/konsensus-crypto/src/tests/session.rs` | 368, 411, 445, 461 |
| `crates/konsensus-crypto/tests/crypto_hardening_v2.rs` | 485 |
| `crates/konsensus-crypto/tests/hardening_tests.rs` | 76, 77, 99, 115 |
| `crates/konsensus-lightning/tests/cln.rs` | 100, 147 |
| `crates/konsensus-lightning/tests/move_home.rs` | 200, 269 |
| `crates/konsensus-lightning/tests/recover_regtest.rs` | 257 |
| `crates/konsensus-message/src/peer.rs` | 651, 660, 670 |
| `crates/konsensus-message/src/transport/mod.rs` | 491, 495, 515 |
| `crates/konsensus-message/src/wire.rs` | 1475, 1480, 1554, 2485 |
| `crates/konsensus-message/tests/hardening_tests.rs` | 528, 543, 561, 577 |
| `crates/konsensus-message/tests/peer_fixed_hex_alloc.rs` | 49 |
| `crates/konsensus-message/tests/wire_hardening_v2.rs` | 651, 667 |
| `crates/konsensus-node/src/node.rs` | 799 |
| `crates/konsensus-node/src/remote_access.rs` | 2454, 2611, 2645, 2668, 3038, 3043, 3049, 3155, 3274, 3289 |
| `crates/konsensus-node/src/restore_fence.rs` | 298, 300 |
| `crates/konsensus-node/src/tests/balance_breakdown.rs` | 104 |
| `crates/konsensus-node/src/tests/browse_two_node.rs` | 77 |
| `crates/konsensus-node/src/tests/budgeted_reconnect_two_node.rs` | 274, 287 |
| `crates/konsensus-node/src/tests/config.rs` | 1611, 2034 |
| `crates/konsensus-node/src/tests/funding_fees.rs` | 39, 66, 211 |
| `crates/konsensus-node/src/tests/hub_only_channels.rs` | 143, 395 |
| `crates/konsensus-node/src/tests/paid_first_contact_two_node.rs` | 633 |
| `crates/konsensus-node/src/tests/reconnect_two_node.rs` | 346 |
| `crates/konsensus-node/src/tests/regtest/app.rs` | 525 |
| `crates/konsensus-node/src/tests/shutdown.rs` | 156 |
| `crates/konsensus-node/tests/content_server_test.rs` | 133, 138 |
| `crates/konsensus-node/tests/device_approve_cli.rs` | 36 |
| `crates/konsensus-node/tests/device_revoke_cli.rs` | 37 |
| `crates/konsensus-node/tests/grant_cli.rs` | 41 |
| `crates/konsensus-node/tests/local_bootstrap_cli.rs` | 147 |
| `crates/konsensus-node/tests/locked_mode_tests.rs` | 174, 270, 338, 676, 693, 721 |
| `crates/konsensus-node/tests/owner_approve_cli.rs` | 55 |
| `crates/konsensus-node/tests/pair_ticket_tests.rs` | 41, 83, 167, 266 |
| `crates/konsensus-node/tests/peer_add_cli.rs` | 39 |
| `crates/konsensus-node/tests/remote_bootstrap_tests.rs` | 185, 245, 417, 609 |
| `crates/konsensus-node/tests/restore_fence_cli.rs` | 54, 83 |
| `crates/konsensus-node/tests/sign_challenge_auth.rs` | 139, 167, 182 |
| `crates/konsensus-pricing/src/tests/chain_aware.rs` | 712 |
| `crates/konsensus-pricing/src/tests/static_pricing.rs` | 214 |
| `crates/konsensus-pricing/tests/hardening_tests.rs` | 33, 57, 85, 103, 126, 144, 151 |
| `crates/konsensus-routing/src/table.rs` | 785 |
| `crates/konsensus-routing/src/weight.rs` | 544, 698 |
| `crates/konsensus-storage/src/tests/models.rs` | 46, 68, 131, 152, 170 |

### New/moved raw serde calls

`konsensus-core/src/wire_json.rs::from_slice_with_large_strings` is the sole new raw entry point and runs `check_payload` (byte cap + shared `check_tokens`) first, returning only the unit `DecodeError`. The four `from_str` calls and one `Deserializer::from_str` in `wire_json/strings.rs` were moved unchanged from the wire helper; each checks a borrowed token before parsing it. `wire.rs` re-exports those helpers. All other new payload call sites use these guarded entry points, not plain serde. New tests deliberately call plain serde only to construct/inspect trusted fixtures.
