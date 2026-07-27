# ADR-027 · Pricing terminology disambiguation

**Status:** Accepted · 2026-05-03
**Superseded by:** —
**Related:** `ADR-028-agreements-layer.md`, `docs/vision/03_Timechain_Pricing.md`,
`docs/v2/UNIFIED_PROTOCOL.md`, `docs/v2/ARCHITECTURE.md`,
`docs/v2/DEVELOPMENT_PLAN.md`

> **Numbering note (2026-05-03 review):** the original draft of this ADR
> was numbered ADR-001, which collided with an earlier internal ADR.
> Renumbered to ADR-027. The companion ADR previously labeled ADR-002
> was renumbered to ADR-028.

## Context

The repo carries three distinct concepts that have collided under
overlapping names. A second-pass review by codex (read-only QA) plus
an independent investigation by Claude Code surfaced this pollution
2026-05-03. The collision shows up in the v2 protocol docs but not in
the live trait surface, so today the pollution is documentation drift
rather than implementation drift — but the drift will mislead the
autonomous factory if any task touches `crates/konsensus-pricing/` or
references "timechain pricing" in its task description.

The three concepts are:

| # | Concept | Where implemented | Status |
|---|---|---|---|
| **1** | **Chain-aware message pricing** | `crates/konsensus-pricing/` (live) — per-UKM-kind msat prices adjusted by Bitcoin fee state, halving epoch sensitivity, EMA smoothing, peer price tables | ✅ implemented; this is what `Principle 5` actually means in the running code |
| **2** | **Timechain contract pricing** | Vision-doc concept — block-height-anchored SaaS contracts (pay-once + open-source-at-end-block, signed JSON contracts, body-hash anchored via Lightning `description_hash` or on-chain `OP_RETURN`). Vision explicitly says implementation lives in EXTERNAL monorepos (`timechain_pricing` TS, `timechain-pricing-rs` Rust) | ⚠️ NOT in core; v2 protocol/architecture docs polluted the core trait sketch with this |
| **3** | **ChainBridge Flywheel** | Strategic / business model — using contract revenue (concept 2) to subsidize new mesh-node operators | ⚠️ business concept; should not appear in core protocol code |

The v2 specs (`UNIFIED_PROTOCOL.md`, `ARCHITECTURE.md`,
`DEVELOPMENT_PLAN.md`) sketched a `verify_contract(TimechainContract)`
trait method, an `anchor_contract(...) -> AnchorProof` constructor,
and a `TimechainPricingEngine::new(...)` test scaffold — none of
which exist in `crates/konsensus-core/src/traits/pricing.rs:35-52`.
The live trait is intentionally simple:
`get_price_msat(kind)` + `get_category_price_msat(category)` +
`as_any()` (already flagged in Track L0 for removal). No contracts.
No subscriptions. No artifact-release logic.

The same three spec docs ALSO carried stale per-message pricing
sketches (`price_message`, `price_session`, `current_base_rate`)
that pre-dated the current `get_price_msat` trait surface. Those
sketches are removed in the same PR that lands this ADR.

The vision doc itself (`docs/vision/03_Timechain_Pricing.md`) is
internally consistent. It explicitly frames timechain-contract
pricing as a separate product layer with its own monorepos. The
pollution was introduced by the v2 spec authors, not by the vision.

## Decision

We adopt three distinct names going forward. Any future task,
factory PR, or factory-runner prompt that touches pricing must use
one of these — never the bare term "timechain pricing":

### Term 1 — "Chain-aware message pricing"

The current implemented Principle 5. Per-UKM-kind msat prices that
adjust to Bitcoin fee-rate state. Lives in `crates/konsensus-pricing/`.
The trait `PricingEngine` exposes only:

```rust
async fn get_price_msat(&self, kind: u16) -> Result<u64, PricingError>;
async fn get_category_price_msat(&self, c: KindCategory) -> Result<u64, PricingError>;
fn as_any(&self) -> &dyn Any;
```

Biological framework anchor: **BTC = ATP**, **fee
rate = ambient ATP availability**, **per-message msat = ATP cost
per cellular operation**, **block height = nucleus timing reference**.
This anchor is preserved.

### Term 2 — "Timechain contract pricing"

The vision-doc concept of block-height-anchored SaaS contracts.
**Lives in a SEPARATE crate `konsensus-agreements` (see ADR-028)
or external monorepo per the vision doc, NEVER inside
`crates/konsensus-pricing/` or any other core trait.**

The existing v2 spec sketches (`verify_contract`, `anchor_contract`,
`TimechainPricingEngine`, `BaseRate`, `ContractStatus`,
`AnchorProof`) are removed from `UNIFIED_PROTOCOL.md`,
`ARCHITECTURE.md`, and `DEVELOPMENT_PLAN.md` as part of this ADR's
landing PR. The vision doc gets a header note pointing to ADR-027
and ADR-028 so future readers know the two are separated.

Biological framework: **timechain-contract pricing has no clean
biological anchor.** It maps to a higher-level "tissue-level"
agreement pattern between cells, not to cellular metabolism. This
is a clue that the concept belongs OUTSIDE the cell-membrane
boundary that defines core.

### Term 3 — "ChainBridge Flywheel"

The strategic/business concept of using contract revenue to subsidize
new mesh-node operators. Lives in operator strategy docs only, not in
core protocol code.

**Never appears in core protocol code, core protocol trait
docstrings, or core protocol specs.** When future factory tasks
need to reason about revenue or subsidies, they reference this term
explicitly and stay in the business-strategy crate or doc surface.

## Implementation guardrail

The bare term "timechain pricing" is **banned** from task descriptions.
Task review MUST reject the task and return it for rewriting using one
of the three disambiguated terms (chain-aware message pricing /
timechain contract pricing / ChainBridge Flywheel).

Implementations MUST NOT add `TimechainContract`, `verify_contract`,
`anchor_contract`, subscription lifecycle, artifact release, open-source
unlock logic, or any constructor matching `TimechainPricingEngine::new(...)`
to the `PricingEngine` trait, to any code in `crates/konsensus-pricing/`,
or to any code in `crates/konsensus-core/src/traits/`.

Such work belongs in `crates/konsensus-agreements/` (see ADR-028), gated
behind explicit scope approval.

## Consequences

### Positive

- Future factory tasks reading the v2 specs no longer see a
  contract-shaped trait sketch and try to implement it.
- Grok daily brief no longer flags false-positive drift between
  spec text (claims contract API exists) and code (which doesn't).
- The biological framework anchor for Principle 5 is preserved
  unambiguously.
- ChainBridge Flywheel becomes a clean business-layer concept that
  cannot accidentally leak into core protocol.

### Negative

- Three v2 spec docs need surgical edits to remove the polluted
  sketches. Done in this ADR's landing PR.
- The trait docstring at `crates/konsensus-core/src/traits/pricing.rs`
  said "Implements Principle 5 (Timechain Pricing)" — renamed to
  "Implements Principle 5 (Chain-aware message pricing)" in the
  same PR.
- Operators who used the bare term "timechain pricing" in
  documentation, chat, or task drafts may need to retrofit their
  language.

### Neutral

- The vision doc text is left intact (it was already correct). A
  short header note links to this ADR for context.

## Implementation checklist (lands in this ADR's PR)

- [x] Write ADR-027 (this file)
- [x] Edit `docs/v2/UNIFIED_PROTOCOL.md`: remove
      `verify_contract(TimechainContract)`, replace stale
      `price_message` / `price_session` / `current_base_rate`
      sketches with the live `get_price_msat` /
      `get_category_price_msat` trait surface, replace
      `impl TimechainPricingEngine` example with a one-line pointer
      to the live `ChainAwarePricingEngine` in
      `crates/konsensus-pricing/src/chain_aware.rs`
- [x] Edit `docs/v2/ARCHITECTURE.md`: remove `verify_contract`,
      `anchor_contract`, `AnchorProof`, `ContractStatus`, and the
      `price_message` / `current_base_rate` sketches; collapse to
      the live trait surface
- [x] Edit `docs/v2/DEVELOPMENT_PLAN.md`: remove the
      `engine.price_message(...)` test scaffold and replace with
      a pointer to the unit tests in
      `crates/konsensus-pricing/src/chain_aware.rs`
- [x] Edit `crates/konsensus-core/src/traits/pricing.rs`: docstring
      "(Timechain Pricing)" → "(Chain-aware message pricing)"
- [x] Edit `crates/konsensus-pricing/src/lib.rs:14` and
      `crates/konsensus-api/src/state.rs:134`: same docstring
      disambiguation
- [x] Edit `docs/v2/HONEST_ASSESSMENT.md`, `docs/v2/PRD.md`,
      `docs/v2/CURRENT_GAPS.md`: disambiguate "Timechain Pricing"
      to either "chain-aware message pricing" (when discussing the
      live engine) or "timechain contract pricing" (when discussing
      the SaaS-contract concept)
- [x] Add header note to `docs/vision/03_Timechain_Pricing.md`
      pointing to ADR-027 + ADR-028 for scope clarification
- [x] Adopt the implementation-guardrail block above in task review
      rules (reject-not-interpret form)
- [x] Record the disambiguation in the project decision log
