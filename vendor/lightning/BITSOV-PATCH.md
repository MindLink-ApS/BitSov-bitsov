# BitSov pinned Lightning patch — issue #157

This directory is the crates.io **lightning 0.2.7** archive, SHA-256
`982ffb82e8362ea95e03a5de8a6004bceb7a577fc1f07d5b02cfc3fc7c930a90`.
Rebased from 0.2.2 for the October 2026 security fixes; all local patches below
are retained. See `../../docs/security/ldk-0.2.7/README.md` for provenance,
companion dependency updates, patch inventory and validation. Original `Cargo.toml.orig` is retained. Upstream:
https://github.com/lightningdevkit/rust-lightning/tree/v0.2.7/lightning

Local changes (plus rustfmt on these files):

- `ln/channelmanager.rs`: one runtime-only atomic policy and its one-way setter
  `require_cooperative_close_consent()`. When set, skip **only**
  `timer_check_closing_negotiation_progress`, which otherwise force-closes
  cooperative negotiation after two timer ticks. All other timers, explicit
  force-close and protocol/chain safety processing remain unchanged. Defaults
  false on fresh construction and deserialization. The host must enable it
  before `Node::start` on every maintenance restart.
- `chain/channelmonitor.rs`: read-only `has_pending_events()` includes queued
  events and the in-progress event handler. Inspect after claimable balances and
  before the output consumer's tracked outputs, so a SpendableOutputs handoff
  cannot produce false migration completion. No event is drained/acknowledged.
- `ln/shutdown_tests.rs`: stalled negotiation still times out normally, but stays
  open without broadcast under the explicit-consent policy.
- `chain/chainmonitor.rs`: pending event visibility through queueing, processing,
  ReplayEvent, and acknowledgement.
- `Cargo.toml`: declare upstream cfg names for local linting.
- Whitespace-only cleanup of two archive lines in `ln/channel.rs` and
  `ln/monitor_tests.rs` for `git diff --check`.
- Include standard MIT/Apache license texts and a standalone test lockfile using
  the workspace Bitcoin/Lightning-types versions.

The issue #157 changes above do not change serialization formats. The offline
safety diagnostic below adds an optional fork-private odd TLV to `ChannelDetails`. No
restore/import support is added; stale SCB restore stays disabled.

Tests:
`cargo test --manifest-path vendor/lightning/Cargo.toml --lib bitsov`
`cargo test --manifest-path vendor/lightning/Cargo.toml --lib test_closing_signed_reinit_timeout`

## Offline safety diagnostics (2026-10-07)

- `ln/channel_state.rs`: expose
  `ChannelDetails.counterparty_force_close_spend_delay`, backed by
  `holder_selected_contest_delay` (`our_to_self_delay`). This is the delay we
  impose on the counterparty's commitment, protecting our breach window; the
  existing `force_close_spend_delay` describes the opposite direction.
- Serialize the optional field as fork-private odd TLV **65,541** (originally
  local type 49; moved in PR #364 round 1 because upstream uses 49 for
  `current_dust_exposure_msat`). Older readers skip unknown odd TLVs and
  records without this field decode with `None`. No legacy type-49 fallback:
  it could misinterpret an upstream field as our diagnostic.
- The companion ldk-node patch forwards this field and uses
  `record_lightning_sync` to capture the process-local, non-persisted
  `latest_lightning_wallet_sync` height/time checkpoint after successful sync.
  See `../ldk-node/BITSOV-PATCH.md` for the checkpoint lifecycle.

These additions are read-only diagnostics. No LDK channel, commitment, sync,
broadcast, or safety behaviour changes.

## Starter push evidence / private TLV allocations (PR #364, round 1)

Negotiated `open_channel.push_msat` is exposed as `initial_push_msat` and retained
across channel-manager restarts and later spending. Missing evidence remains
`None`; starter verification fails closed. No SQL migration is needed.

| Serialization stream | Fork field | Private odd type |
| --- | --- | --- |
| `FundedChannel` (`ln/channel.rs`, read and write) | `initial_push_msat` | **65,537** |
| `ChannelDetails` (`ln/channel_state.rs`) | `initial_push_msat` | **65,539** |
| `ChannelDetails` | `counterparty_force_close_spend_delay` | **65,541** |

Upstream main was checked at commit
[`83f74511954e1ee8070917b38195dae4c822f831`](https://github.com/lightningdevkit/rust-lightning/tree/83f74511954e1ee8070917b38195dae4c822f831/lightning/src/ln):
Channel's highest allocated type is **79**; ChannelDetails' highest is **51**.
Upstream already uses Channel 71 for `holder_commitment_point_previous_revoked`,
ChannelDetails 51 for `splice_details`, and ChannelDetails 49 for
`current_dust_exposure_msat`. The former starter allocations 71/51 must never be
written or treated as legacy push evidence. This correction is before merge;
pre-merge experimental push evidence at those types is intentionally not read.

There was no existing high-range fork convention. New fork fields use odd types
starting at **65,537**, recorded here, well outside upstream's sequential range.
These are local allocations, not an upstream reservation: recheck this ledger
against upstream on every vendor update. Unknown odd types are skippable; an
upstream-shaped record without private fields still reads with unknown evidence.

Regression commands:

```sh
cargo test --manifest-path vendor/lightning/Cargo.toml --lib starter_initial_push_
```

`starter_initial_push_uses_private_tlvs_and_reads_upstream_shape` pins the actual
serialized type numbers and tests absent private fields (including upstream-shaped
ChannelDetails 49/51). `starter_initial_push_survives_spend_and_restart` verifies
the negotiated evidence survives spending and a full ChannelManager reload.
