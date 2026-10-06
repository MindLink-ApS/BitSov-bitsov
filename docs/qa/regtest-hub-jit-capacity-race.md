# JIT capacity assertion: missing commitment synchronization

## Conclusion

The defect is a **test timing race**: the test treats a settled payment receipt as
a barrier for the client's spendable channel balance. Those are different LDK
state transitions. The preimage can be durably claimed and propagated to the
sponsor before the client processes the hub's `revoke_and_ack` (RAA), which
credits its outbound capacity. Neither sponsor settlement nor the hub's earned
skim metric establishes that the client processed that message.

The fix waits for the original capacity postcondition on the same JIT channel,
bounded to 60 seconds. Both strict `> 90_000_000` msat assertions remain, as do
the receipt, private/inbound/usable channel, fee, restart, and paid admission
checks. No production behavior or reserve policy is changed.

Evidence proves the missing synchronization and excludes a change to the
relevant code between these revisions. The old CI log does **not** contain
capacity values or a Lightning message trace, so it cannot identify the exact
in-flight message or establish that the observed capacity was zero. The
regtest cannot be rerun here without Bitcoin Core/electrs; the new timeout
diagnostics distinguish a transient delay from a persistent failure in CI.

## Exact revision comparison

Failing main is `788eea3d220ff8d4090e58603931e7902a8a0e81`, run
`37405609872`. The reported passing run is `37351742266`, at
`a3319fc734f565add0cbe6f2ef7facfdacce9838` (resolved and fetched from origin).
Crucially, **a3319fc is already the implementation subsequently merged as
#236**, “bound LSPS2 opens with owner fee policy and hub metrics.” It is not
the pre-#236 implementation.

This comparison exits 0 with no differences:

```sh
git diff --exit-code a3319fc..788eea3 -- \
  vendor/ldk-node crates/konsensus-lightning \
  crates/konsensus-node/src/tests/regtest/lsps2_service.rs \
  crates/konsensus-node/src/tests/regtest/infra.rs \
  crates/konsensus-node/src/tests/regtest_e2e.rs
```

The only `Cargo.lock` difference is adding the already-resolved `ring` to
`konsensus-node`'s dependency list for #237. In particular, `lightning` remains
**0.2.2**, `lightning-liquidity` remains **0.2.0**, and the vendored `ldk-node`
remains **0.7.0**. Source references below use main 788eea3 and these exact
registry versions, not latest upstream.

| Change | Relevance to this failure |
| --- | --- |
| #234, `74dbd9e` | Porch availability/price and content/session handling. Its only regtest fixture change is `regtest/app.rs:353-354`, adding `content_server: None` and `front_door` to application session dependencies. This test constructs `LdkProvider` directly, never that `App` fixture. |
| #235, `5a3fa9e` | CLI/local-owner authority, password provenance, pairing/device spend grants. The Rust test harness does not invoke `main`/`cmd_start`, and this funding path does not use pairing or application spend grants. |
| #236, `bc30b74` | The relevant JIT/test changes are already present, byte-for-byte, at the passing a3319fc: durable retries/capital limits, explicit funding fee policy, fee-source proxy, hub metrics, and this capacity assertion. |
| #237, `016575b` | Encrypted local-owner bootstrap and CLI hooks; no provider, LDK, reserve, or test-path changes. |
| #238, `788eea3` | Bootstrap-state refusal reporting; no involvement in the three directly constructed Lightning providers. |

## Funding, claim, and balance are separate stages

Repository paths below are relative to the root. `lightning/...` and
`lightning-liquidity/...` paths are relative to the unpacked Cargo registry
crates (`lightning-0.2.2` and `lightning-liquidity-0.2.0`). Line numbers for the
original test refer to 788eea3, before this fix.

1. **Open/fund the channel.** `lsps2_service.rs:122-172` quotes and accepts
   100,000,000 msat with a 1,000,000 msat fee ceiling, deliberately exhausts
   the hub's initial funds, tops it up, then waits for payment settlement.
   `crates/konsensus-lightning/src/lsps2_service.rs:30-41` defaults to
   1,000,000 ppm overprovisioning (100% extra).
   `lightning-liquidity/src/lsps2/service.rs:257-282` subtracts the opening fee
   to obtain the amount to forward. `vendor/ldk-node/src/liquidity.rs:730-743`
   passes that amount to `reserve_jit_open`; `liquidity/jit.rs:103-120` computes
   the channel amount and separately budgets wallet reserves/fees.
   `liquidity/jit.rs:208-213` opens the channel with zero push amount. Thus
   99,000,000 msat net plus 100% extra gives a 198,000 sat channel, initially
   with zero client balance. The 225,000 sat capital metric already asserted
   at test line 204 is 198,000 + 25,000 anchor wallet reserve + 2,000 fee cap.

2. **The client automatically claims the payment.** The provider's JIT invoice
   call is `crates/konsensus-lightning/src/ldk.rs:2317`.
   `vendor/ldk-node/src/payment/bolt11.rs:581-594` selects the automatic-preimage
   flow (no manual payment hash). The LSP is trusted for zero-conf in
   `builder.rs:478-487`; `event.rs:1296-1328` accepts its channel with
   underpaying HTLC support. `event.rs:699-777` checks net/skim limits and saves
   the skim; `event.rs:949-950` calls `channel_manager.claim_funds(preimage)`.
   This is not the manual `claim_for_hash` API. The test's wallet sync at
   `lsps2_service.rs:162` drives chain observation; it is not a peer commitment
   barrier. `client_trusts_lsp: false` in the service config
   (`crates/konsensus-lightning/src/lsps2_service.rs:146-147`) means the hub does
   not defer funding broadcast until the client claims.

3. **A receipt is published on durable claim, not on balance credit.**
   `lightning/src/ln/channelmanager.rs:8702-8703,8864-8886` starts the claim
   and attaches `MonitorUpdateCompletionAction::PaymentClaimed`.
   `channelmanager.rs:9427-9515` emits `PaymentClaimed` on monitor completion.
   The vendored handler at `event.rs:973-1075` stores the net amount and
   `PaymentStatus::Succeeded`, then publishes `PaymentReceived`.
   `crates/konsensus-lightning/src/ldk.rs:1371-1390,2088-2092` maps that payment
   record to `Settled`; `ldk.rs:2333-2347` builds the liquidity receipt from
   the same stored record. None of these reads waits for channel capacity.

4. **Capacity is credited by RAA.** In
   `lightning/src/ln/channel.rs:7392-7418`, claiming marks the inbound HTLC
   `LocalRemoved(Fulfill(...))`; it does not yet add its value to the local
   balance. `get_update_fulfill_htlc_and_commit` at lines 7421-7454 starts the
   commitment update. `Channel::revoke_and_ack` starts at line 8499; at
   8636-8648 it removes the fulfilled inbound HTLC and adds its amount to
   `value_to_self_msat_diff`; at 8780-8782 it applies that difference to
   `funding.value_to_self_msat`.
   `get_available_balances_for_scope`, lines 5657-5669, derives outbound
   capacity from that value minus pending outgoing HTLCs and the counterparty's
   punishment reserve. Until this transition the newly funded client's
   outbound capacity can still be zero. `vendor/ldk-node/src/lib.rs:1066-1068`
   and `types.rs:393-400` simply expose LDK's current capacities; they neither
   cache a receipt-derived balance nor advance the commitment protocol.

5. **The other waits do not close the gap.**
   `lightning/src/ln/channelmanager.rs:11088-11149` handles
   `update_fulfill_htlc` and calls `claim_funds_internal` immediately.
   Lines 9297-9299 explicitly describe the fulfilled HTLC's fast path without
   waiting for RAA. Lines 9398-9413 create `PaymentForwarded`;
   `vendor/ldk-node/src/event.rs:1434-1445` and
   `liquidity.rs:1340-1357` turn this into the earned-skim journal metric.
   For the sender, `channelmanager.rs:9265-9276` calls `claim_htlc`, and
   `lightning/src/ln/outbound_payment.rs:2235-2264` emits `PaymentSent` on
   learning the preimage. Neither event requires the client to have consumed
   the hub's RAA. The original test's `settle(sponsor)` at line 171, metrics
   wait at 196-199, and receipt assertions at 226-233 therefore allow the
   immediate capacity read at 243-245 to race that client's state transition.

## Reserve arithmetic rules out lowering the threshold

`vendor/ldk-node/src/config.rs:338-363` starts from `UserConfig::default()` and
does not override the channel reserve. Lightning's
`src/util/config.rs:256` defaults `their_channel_reserve_proportional_millionths`
to 10,000 (1%); `src/ln/channel.rs:6445-6453` computes the reserve. For this
channel it is **1,980 sat**, not 25,000 sat. The latter is an **on-chain wallet
anchor reserve**, accounted separately in `vendor/ldk-node/src/balance.rs:24-33`
and checked when accepting an anchor channel at `event.rs:1234-1274`.

After the 99,000 sat claim reaches the channel balance, expected outbound
capacity is `(99,000 - 1,980) * 1000 = 97,020,000 msat`. The client is the
fundee, so the hub pays the anchor outputs: Lightning
`src/sign/tx_builder.rs:295-323` subtracts their combined 660 sat from the
funder's side. Expected client inbound capacity for this anchor channel is
`(99,000 - 660 - 1,980) * 1000 = 96,360,000 msat`
(`src/ln/channel.rs:5785-5791`). Commitment-fee/HTLC limits additionally
constrain `next_outbound_htlc_limit_msat`; they are not an extra deduction
from the tested outbound-capacity field. Both 90,000,000 thresholds retain
headroom and should remain unchanged.

## CI evidence and diagnostic fix

The supplied `../jit-fail.log` contains:

```text
1867: 2026-10-06T02:47:30.3734490Z test ...hub_jit_then_stateless_admission ... funding fee: 156 sat, 153 vB (estimator)
1869: 2026-10-06T02:47:41.5963259Z ... panicked at crates/konsensus-node/src/tests/regtest/lsps2_service.rs:245:5:
1870: 2026-10-06T02:47:41.5963752Z assertion failed: channel.outbound_capacity_msat > 90_000_000
```

Reaching line 245 means the receipt's gross/skim/net, the bounded funding fee,
the hub's open/retry/earned-fee metrics, both channel counts, and the client's
usable/private/inbound flags all passed. The funding-fee log above is not a
client-capacity measurement. The later chain-rate-limit errors at lines
1877 onward belong to `three_node_paid_e2e`, which starts at line 1873 after
this test failed; they are not evidence for this failure.

The new wait polls every 100 ms, matching the existing regtest wait convention,
and returns the same snapshot that meets both original capacity thresholds.
It matches the original channel ID, so a replacement channel cannot satisfy
it. It runs before mining confirmations or attempting admission payments.
On timeout it prints the payment hash, expected channel ID, full client and
hub `ChannelDetails` (including `outbound_capacity_msat`,
`inbound_capacity_msat`, `unspendable_punishment_reserve`, channel value,
readiness and fee rate), and client `BalanceDetails` (including
`total_lightning_balance_sats`, per-channel claimable balances and
`total_anchor_channels_reserve_sats`). No fixed sleep or weakened threshold
can hide a persistent capacity failure.

## Validation

Checks completed on 2026-10-06:

- Ran `cargo fmt` on the changed test, preserving unrelated target entry files;
  `rustfmt --edition 2021 --check crates/konsensus-node/src/tests/regtest/lsps2_service.rs`
  and `git diff --check` also pass.
- `cargo clippy --workspace --all-targets --features konsensus-node/regtest-e2e --locked -- -D warnings`
  exits 0, including the changed regtest code. The existing Cargo
  future-incompatibility notice for `sqlx-postgres 0.8.0` remains.
- `cargo test --workspace --locked --features konsensus-node/regtest-e2e -- --skip regtest_e2e`
  exits 0: **4,174 passed, 0 failed, 5 existing ignored, 12 regtests filtered
  out**, including doc tests. The regtest feature is compiled, not executed.
  Build settings: `CARGO_PROFILE_DEV_DEBUG=0`, `CARGO_PROFILE_TEST_DEBUG=0`,
  `CARGO_INCREMENTAL=0`, `CARGO_BUILD_JOBS=2`, using the existing
  `/tmp/bitsov-three-node-target` cache.
- The initial sandboxed suite stopped on local socket `EPERM` in
  `expiry::expiry_api_start_purges_before_binding_listener`,
  `expiry::expiry_api_start_refuses_failed_cleanup_before_binding`,
  `first_contact_grant::owner_socket_first_contact_checks_tuple_and_consumes_once`,
  and `sponsor::owner_socket_gift_checks_every_field_and_refuses_replay`.
  Repeating the full command outside the sandbox resolved all four; the
  totals above are from that completed repeat. Logs are
  `/tmp/pa-jit-tests-unsandboxed.log` and `/tmp/pa-jit-clippy-final.log`.
- Independent read-only review confirmed the relevant revision comparison,
  LDK ordering, reserve arithmetic, and bounded wait without blocking issues.

Bitcoin Core and electrs are absent from PATH and `BITCOIND_EXE`/`ELECTRS_EXE`
are unset. **The paid regtest itself has not been run locally**, so this is
not a claimed reproduction or a claimed passing regtest run.
