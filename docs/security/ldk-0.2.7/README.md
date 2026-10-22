# LDK 0.2.7 security integration

Base: `9fdb14806971879661bdb07bd72b414d33974bae`; branch `fix/ldk-0.2.7-security`.

## Verified sources and applicability

The annotated rust-lightning v0.2.7 tag resolves to `5ce2ecb33d32e3b61ef01d5ead0ee6693c0cd7d1`, dated October 1 2026 (tagged October 2 UTC). [Release notes](https://github.com/lightningdevkit/rust-lightning/releases/tag/v0.2.7) and [tagged changelog](https://github.com/lightningdevkit/rust-lightning/blob/v0.2.7/CHANGELOG.md) identify these fixes. GitHub PR URLs return 404: these PRs live on [the upstream forge](https://git.rust-bitcoin.org/lightningdevkit/rust-lightning).

| Issue | Mainline commit | Actual 0.2 release-branch commit | Build applicability |
|---|---|---|---|
| #5057, acknowledged commitment rollback | `e6f108dba271a4de2f9f4a9ec86bf10100bb6a8a` | [7f427fd87ff3c212ca40a511e316a3400fe8d04d](https://github.com/lightningdevkit/rust-lightning/commit/7f427fd87ff3c212ca40a511e316a3400fe8d04d) | Core `Channel::channel_reestablish`: normal channel peers can reach it. Retransmission now requires an outstanding remote revocation. |
| #5042, underfunded LSPS2 forwards | `6f621695542c1bb00e692b7283e49aaee050327f` | [094c5001515938b73daff61cf468ab2f3b32c4b5](https://github.com/lightningdevkit/rust-lightning/commit/094c5001515938b73daff61cf468ab2f3b32c4b5) | Opt-in hub service: `ldk.rs` -> `set_liquidity_provider_lsps2`, vendored event/liquidity handler -> `LSPS2ServiceHandler::htlc_intercepted`. Requires **both** Lightning and lightning-liquidity fixes. |
| #4867, Electrum script-history amplification | `b1f8e3f6e1499b1acb3d2b80569c65c75a1b6c4c` | [1aea235f6e1d6f01803c6ddfc14e5d29e93958ea](https://github.com/lightningdevkit/rust-lightning/commit/1aea235f6e1d6f01803c6ddfc14e5d29e93958ea) | Optional `ldk.rs` -> `set_chain_source_electrum`; lightning-transaction-sync now retains registered scripts and prefers a matching non-OP_RETURN output. Esplora/Core do not use this Electrum history path. |

All three release-branch commits are included in v0.2.7 and absent from v0.2.6. These are the first 0.2 release tags containing these particular changes. Release source and package source were compared, not inferred from version labels alone. The liquidity crate's generated sync utility files differ from the Git tree as expected for packaging; its LSPS2 service source matches.

The LSPS2 release backport keeps the existing handler signature and obtains the authenticated inbound amount via the new `ChannelManager::intercepted_htlc_inbound_amount_msat`. Mainline's fix instead adds a handler argument. Porting mainline blindly would miss this compatibility distinction. The local caps/fee policies do not validate the inbound amount and are not a substitute for this fix.

## Integration decision

Rebase Lightning to 0.2.7, update liquidity and transaction-sync to 0.2.7, retain ldk-node 0.7.0. Lightning also requires types 0.3.5. The build exposed a liquidity persistence return-type mismatch with background-processor 0.2.0; the compatible 0.2.3 background processor is therefore included. Only these five package records change in the workspace/node locks; no unrelated package updates are retained. This includes intervening 0.2.3–0.2.6 security fixes, including other theft fixes in 0.2.5/0.2.6, and avoids maintaining an incomplete hand-selected core security fork. Merely replacing Lightning would leave the LSPS2 service and Electrum problems unfixed.

The ldk-node v0.7.1 annotated tag is dated October 12 2026 and resolves to `edc8916e289d39a4135b6eda66978a9f765396bb`, matching its crate VCS metadata. Its manifest still accepts the 0.2 LDK family; it is not needed for the three requested fixes. Its additional payment, storage, reserve and lifecycle hardening is a separate follow-up: much overlaps our extensive 0.7.0 modifications. Keeping node source unchanged avoids merging unrelated money/persistence behavior in this update. This does **not** claim all 0.7.1 hardening is already present.

## Local patch inventory

`local-history.txt` is the complete ordered list of 24 commits touching either vendor tree through the base commit, not just #265/#270/#275. `local-before.json` records every file differing from the original archives, including additions, deletions, packaging and formatting, with SHA-256 values. Existing `vendor/{lightning,ldk-node}/BITSOV-PATCH.md` describe the behaviors.

Lightning local behaviors: explicit cooperative-close consent, pending-monitor-event visibility, their regressions, offline breach-window diagnostic (originally odd TLV 49; now fork-private 65,541), local lint/test configuration and formatting. Node local behaviors: stateless receipts and duplicate/skim protection; fixed JIT net minimum; wallet reservations/bump isolation; source evidence; sync health/retry/deadline handling; Esplora auth/rate limits/rebroadcast policy; owner funding fees; private forwarding; bounded LSPS2 opens and metrics; move-home; configured contest delay; hub peer admission; watchtower durable candidates/quarantine/bounded outbox; offline sync checkpoint and breach diagnostics; channel-capacity limits. The complete per-file/hash inventory is authoritative for less visible changes.

## Package provenance

All archives downloaded from `https://static.crates.io/crates/<name>/<name>-<version>.crate`; hashes checked against `https://index.crates.io/` sparse index entries.

| Archive | SHA-256 |
|---|---|
| lightning 0.2.2 (baseline) | `4c90397b635e3ece6b9a723fb470a46cb9b3592f217d72e40540a5fada00289d` |
| ldk-node 0.7.0 (retained baseline) | `d830ef2d6b00f089fb6e3ac845370ebf0f35f9d11ce81b3a097c1580d2dce358` |
| lightning 0.2.7 | `982ffb82e8362ea95e03a5de8a6004bceb7a577fc1f07d5b02cfc3fc7c930a90` |
| lightning-liquidity 0.2.7 | `75947be75873138097adb72c080a853ad576a295ac63f73d8fbeb07543c136b1` |
| lightning-transaction-sync 0.2.7 | `dbcb06ccc3abb415465c396448562a811e4405ea3da893c52ccda31d3ed853ad` |
| lightning-background-processor 0.2.3 | `994fb200e17bbe125491cbe3f35602180a360484b9763837b9ea2130b7293b5f` |
| lightning-types 0.3.5 | `c77c676d4a34cceb2ae3756916e446b4d17f9430a24107e099981f0f9aec77e6` |
| ldk-node 0.7.1 (inspected, not adopted) | `9a890a268dd7430d16ae5a867d73070414beab83fc744b07147aab3a33e38360` |

## Limits and uncertainties

- Upstream explicitly states that HTLCs already queued by an old LSPS2 version keep their unvalidated amounts. This upgrade does not retroactively validate them. No deployed state was inspected; operators must account for pending old-version JIT flows before considering the upgrade protective for those flows.
- Feature reachability is confirmed from source, not production configuration. No real node/network tests or migration against live state are authorized or performed.
- The release prose says two denial-of-service vulnerabilities but explicitly lists only the Electrum item. No separate second DoS fix is inferred from that wording.
- GitHub release/API pages for node 0.7.1 were unavailable/stale; its actual Git tag, tagged changelog and registry archive were available. Tag signature identity/trust was not independently verified.
- The general Rust audit skill's supporting scripts are not installed; this is a targeted security integration review, not a whole-codebase Rust audit.

## Preservation and reviewer reproduction

`local-after.json` records the complete final delta from lightning 0.2.7 and
ldk-node 0.7.0 using the same schema as `local-before.json`. All nine Lightning
source files with pre-existing local modifications retain identical normalized
local deltas (whitespace/commas excluded for the formatting comparison); an
independent reviewer confirmed this separately. The sole three-way conflict was
an old brace-format change overlapping upstream's new
`BackgroundEvent::AttemptUnblockMonitorUpdates` handler; the upstream handler is
retained. At this rebase, upstream 0.2.7 ended at TLV 47. PR #364 round 1
subsequently found that upstream main uses 49 and moved the diagnostic to
fork-private 65,541; see [the current allocation ledger](../../../vendor/lightning/BITSOV-PATCH.md).
The old reload whitespace-only delta is absorbed by upstream; the monitor
whitespace cleanup remains inventoried.
Node production **and test source** files are byte-identical to `9fdb1480`.
Node manifest, standalone lock and patch documentation are the only node changes.

To inspect the complete current delta, extract the checksum-verified archives
outside the repo, then run (exit 1 from `git diff --no-index` means differences):

```sh
git diff --no-index /path/to/lightning-0.2.7 vendor/lightning
git diff --no-index /path/to/ldk-node-0.7.0 vendor/ldk-node
git diff 9fdb1480 -- vendor/ldk-node/src
git log --reverse --oneline 9fdb1480 -- vendor/lightning vendor/ldk-node
```

For the exact pre-upgrade delta, first `git archive 9fdb1480 vendor/lightning
vendor/ldk-node` into a separate directory and compare to the 0.2.2/0.7.0
archives. The two JSON inventories include all differences, including intentionally
omitted upstream tests, licenses, Cargo packaging and standalone locks.

Registry companion crates are unmodified. An additional regression is supplied
as `scripts/regress/ldk-lsps2-underfunded.patch`, applied only to an extracted
lightning-liquidity 0.2.7 test copy. It verifies a declaration one msat above the
actual inbound amount fails before opening a channel, consumes/fails that
intercept, and preserves the SCID for a valid payment. See `VALIDATION.md` for
reproduction, red/green evidence and counts.
