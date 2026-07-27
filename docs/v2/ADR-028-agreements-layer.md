# ADR-028 · Agreements layer · architecture & AI permission boundary

**Status:** Accepted as scope decision · 2026-05-03
**Implementation:** deferred · gated on Track L0 closure + operator sign-off
**Related:** `ADR-027-pricing-terminology.md`,
`docs/vision/03_Timechain_Pricing.md`,
`crates/konsensus-pricing/src/peer_prices.rs`,
`crates/konsensus-routing/src/weight.rs`

> **Numbering note (2026-05-03 review):** the original draft of this ADR
> was numbered ADR-002, which collided with an earlier internal ADR.
> Renumbered to ADR-028 (companion to ADR-027 above).

> **Status disclaimer:** this ADR records an architectural **scope
> decision** and a **design thesis**, not a present capability. The
> Agreements layer is not implemented. Adoption depends on operator
> sign-off after Track L0 closure. Until that point, all settlement
> primitives below remain unintegrated.

## Context

The conversation 2026-05-03 surfaced a strategic question: can
Bitcoin's existing settlement primitives (CLTV/CSV timelocks, HTLCs,
DLCs, Miniscript), composed with a constrained AI orchestration
layer, cover most real-world endpoint-market financial agreements
(SaaS subscriptions, vendor maintenance, supply-chain delivery,
escrow, parametric insurance)?

The **design thesis** we adopt as a working hypothesis is:

> **If we compose audited Bitcoin/Lightning settlement primitives
> behind signed templates, with sovereign-identity counterparties on
> a payment-gated mesh, that combination *can plausibly automate the
> mechanical settlement portion* of common endpoint-market
> agreements (SaaS subscriptions, vendor escrow, delivery
> milestones, parametric insurance).**
>
> The non-mechanical portion — jurisdiction, evidence weight,
> dispute resolution, delivery quality judgment, accounting, tax,
> compliance — is **not** in scope for the Agreements layer. That
> portion stays with human counterparties and external legal
> recourse.

We have not validated this thesis with real users or live contracts.
The numbers some early notes attached ("80% mechanics / 20%
judgment", "15-20% gap on payment-gated mesh") are not measurements
— they are intuitions used to motivate the scope decision. They
should not appear in marketing material, investor docs, or technical
claims.

A 2-minute audit of the current code (`Cargo.toml` survey) shows
the settlement-mechanics layer is **barely present**: only
`bitcoin = "0.32"`, `ldk-node = "0.7"`, `lightning-invoice = "0.34"`,
and `secp256k1 = "0.29"` (JWT-only). No `rust-miniscript`, no
`rust-dlc`, no `bdk`, no exposed CLTV/CSV/HTLC composition. HTLC
exists in trait *docstrings* only.

## Decision

We accept the architectural shape for an Agreements layer, gated on
Track L0 closure and operator sign-off before any implementation
work begins.

### Crate placement

A new crate `konsensus-agreements` (or external monorepo per
`docs/vision/03_Timechain_Pricing.md:86-94`) sits as a layer
**ABOVE** core. It depends on core; core never depends on it.

```
                 konsensus-agreements   (NEW · post-L0)
                          │
                  reads ▼ (one-way)
                          │
        ┌─────────────────┼──────────────────┐
        │                 │                  │
   konsensus-routing  konsensus-core    konsensus-lightning
   (SynapticWeight    (NodeIdentity,    (LightningProvider
    plasticity        PricingEngine,    BOLT11 + LDK ops)
    weight signal)    PaymentGate)
```

**Dependency direction is one-way.** Core, lightning, routing, and
pricing crates **never** import `konsensus-agreements`. This
preserves the cell-membrane boundary that defines BitSov core and
prevents the Track L0 freeze surfaces (Lightning, crypto, transport)
from being polluted by contract-layer concerns.

### Settlement primitives the Agreements crate would adopt

The table below lists primitives the Agreements layer is **designed
to compose** when implementation begins. None are currently wired
into BitSov; the column "BitSov status" makes that explicit.

| Primitive | Mature OSS | BitSov status today | What it would unlock |
|---|---|---|---|
| **CLTV** (absolute timelock) | `bitcoin` 0.32 native + `rust-miniscript` 12 | unwired (no Miniscript dep) | Time-bounded service access, vesting cliffs, deadline escrow |
| **CSV** (relative timelock) | `bitcoin` 0.32 native + `rust-miniscript` 12 | unwired | Cooldowns, withdrawal delays, post-funding waits |
| **HTLC** (hash time-locked, on-chain) | `rust-miniscript` 12 | unwired | Atomic swaps, conditional pay-on-secret-reveal |
| **HTLC** (Lightning) | `ldk-node` 0.7 supports them at the BOLT layer | trait surface only · live providers default `unsupported` · only `MockLightningProvider` implements; **future provider work required** | Conditional payments, escrow with reveal-on-delivery |
| **HODL invoices** | `ldk-node` 0.7 supports them at the BOLT layer | trait surface only · live providers default `unsupported` · only `MockLightningProvider` implements; **future provider work required** | Subscription confirmations, escrow with reveal-on-delivery |
| **Multi-sig + descriptor wallets** | `bdk_wallet` (latest 2.x) | unwired (no `bdk` dep) | 2-of-3 escrow, dispute arbitration, organizational signing |
| **DLC** (oracle-attested settlement) | `dlc` 0.7.x + `dlcspecs` | unwired | Derivatives, parametric insurance, supply-chain delivery confirmation |
| **Miniscript composition** | `rust-miniscript` 12.x | unwired | Composable unlock conditions, validation, descriptor canonicalization |

All from widely used OSS. **Audit status of each crate must be
verified before adoption** — adoption is gated on a documented
audit-status review (existence of recent audit, scope, severity
findings, remediation status) added to this ADR before the first
template lands. The Agreements crate **never rolls custom crypto
primitives or custom script** — it composes templates from these
libraries and validates them deterministically.

### Template archive

Templates are versioned, signed, stored in
`crates/konsensus-agreements/templates/`. Examples (initial v1
catalog target):

- `escrow_2of3.rs` — multisig + CLTV refund deadline
- `vesting_cliff.rs` — CLTV cliff + CSV linear vest
- `saas_subscription.rs` — recurring LN invoice + cancellation window
- `dlc_parametric.rs` — oracle-attested settlement (uses `rust-dlc`)
- `htlc_swap.rs` — atomic swap between two parties
- `delivery_milestone.rs` — multi-stage release on attestation

#### Template integrity controls

A signed Miniscript-valid template is necessary but **not sufficient**.
Miniscript validation only proves the script is well-formed and
spendable; it cannot detect a valid-but-malicious template (e.g. a
2-of-3 multisig where a maintainer-controlled key is silently
included as one of the signers, draining the user's funds via the
"valid" path). Every template must therefore satisfy ALL of:

1. **Multi-maintainer signature.** Templates require **≥2 maintainer
   signatures** from a documented, version-pinned maintainer key
   set (committed to `crates/konsensus-agreements/MAINTAINERS.md`).
   No single-maintainer push.
2. **Semantic invariants.** Each template declares invariants the
   Agreements layer enforces at runtime — e.g. "no maintainer key
   appears in the unlock condition", "refund path is always
   signable by the counterparty alone", "oracle key is from the
   operator-approved oracle ID list, not the AI's choice".
   Implemented as Rust unit tests + a runtime check before signing.
3. **Regtest vectors.** Every template ships a regtest test fixture
   exercising **happy path + every documented failure path**
   (counterparty default, oracle disagreement, key loss, deadline
   miss, double-spend attempt). CI enforces 100 % coverage of the
   declared paths.
4. **User-readable summary.** Every template ships a plain-English
   summary describing exactly what the user is committing to,
   shown in the desktop UI before signing. The summary is
   adversarially reviewed and regenerated when the template body
   changes (hash bound).
5. **Maintainer key compromise plan.** A documented revocation
   path: maintainer keys live in a signed list; revocation lands
   as a signed, dated entry; on revocation, all templates relying
   on that key are auto-quarantined until re-signed.

New templates land via human review **and** maintainer-key signing
ceremony. The AI **never invents** new templates; it can only pick
from the archive.

### AI permission boundary

The AI orchestration layer (`konsensus-ai` crate, currently
scaffolded but dormant) interfaces with `konsensus-agreements` ONLY
through a constrained API. The AI's permission boundary, in priority
order:

**Allowed:**
1. Classify the agreement type from natural-language user intent.
2. Pick a signed template from the archive.
3. Explain template tradeoffs and failure paths to the user using
   the template's user-readable summary.
4. Fill template variables (counterparty pubkeys, amounts, block
   heights, oracle endpoints **resolved from operator-approved
   oracle IDs only**) from user-confirmed input.
5. Produce an unsigned PSBT, DLC contract, or LN invoice plan.
6. Simulate failure paths on regtest using the template's regtest
   vectors (counterparty default, oracle disagreement, block-height
   drift, key loss).
7. Monitor block heights, invoices, DLC oracle events, and renewals
   for already-signed contracts.
8. Warn the user before deadlines (cancellation windows, expiry,
   renewal cutoffs).
9. **Read** (only) the counterparty's plasticity weight from
   `crates/konsensus-routing/src/weight.rs::SynapticWeight` as a
   risk-score input.

**Forbidden:**
1. **Generate raw Bitcoin script.** All script comes from the signed
   template archive, validated by `rust-miniscript` + the template's
   semantic invariants. A Miniscript-valid template is **not**
   sufficient — see "Template integrity controls" above.
2. **Sign on the user's behalf.** Every PSBT / DLC commit / LN
   invoice signature requires explicit user signature in the
   desktop UI.
3. **Pick or trust an oracle without operator approval.** DLC
   oracles MUST resolve to an operator-approved oracle ID from a
   signed list (`crates/konsensus-agreements/ORACLES.md`). The AI
   cannot construct an oracle endpoint, accept a user-supplied URL,
   or fall back to a default.
4. **Write into Plasticity, Routing, or Pricing crates.** Read-only
   coupling. No feedback loop where contract success/failure
   modifies routing weight (would conflate two clocks and create
   gameable incentives — see "Plasticity vs Agreements separation"
   below).
5. **Bypass the validation pipeline.** Even if the AI is "sure" a
   contract is correct, all of: `rust-miniscript` compile,
   `dlcspecs` verify, `bdk` descriptor sanity, template semantic
   invariants, regtest vector pass, and user-summary integrity
   must pass before the AI surfaces it to the user.
6. **Call the Agreements layer with a template the user has not
   seen the user-readable summary of.** UI must display the
   summary; AI cannot suppress it.

### Plasticity vs Agreements separation

Plasticity and Agreements are different concerns at different
layers and **must not be merged into one concept**.

| Concern | Plasticity (existing) | Agreements (proposed) |
|---|---|---|
| What it actually is today | a routing/reliability signal — `SynapticWeight` per peer with delivery-success counters and a 50 % message-price discount cap (`MAX_TRUST_DISCOUNT = 0.5`); see `crates/konsensus-pricing/src/peer_prices.rs` | a future settlement-mechanics layer; not yet implemented |
| What it is **not** | legal/commercial trust, identity verification, KYC, or counterparty risk underwriting | a substitute for legal recourse |
| Layer | routing reflex + message-price discount | settlement mechanics |
| Lives in | `konsensus-routing` (weight) + `konsensus-pricing` (discount) | NEW `konsensus-agreements` |
| Data type | `f64` weight per peer + behavior counters | template + parameters + Bitcoin script |
| Time horizon | continuous (every message updates) | discrete (one contract → one settlement) |
| Cost of mistake | bad routing decision (recoverable, low cost: a few resends or a price discount that was unwarranted) | lost funds (irrecoverable, high cost) |
| Trust model | learned from observed mesh behavior | cryptographic + counterparty identity + (optionally) plasticity score as one input |
| Biological anchor | synaptic-weight homeostasis (cellular) | tissue-level agreement pattern |

**One-way coupling allowed:** the AI orchestrating Agreements
**reads** plasticity weight as one input to risk scoring. No
write-back. Contract outcomes do **not** modify routing weight,
because that would create a gameable feedback loop and conflate
mesh-routing health with business-contract performance.

### Out-of-scope for v2 finish line

To keep BitSov v2 focused on its three-node mesh + frontend finish
line, the Agreements crate is **deferred** to a later milestone. It
is documented here so:
- Operators understand the architecture before any task touches it.
- Factory cannot accidentally implement it inside core.
- Future strategic decisions (whether to keep it in-tree or spin
  out as an external monorepo per the vision doc) have an
  authoritative reference.

### Build order (when work begins)

1. Scaffold `konsensus-agreements` crate with `bitcoin`, `bdk`,
   `rust-miniscript`, `rust-dlc` deps.
2. Implement deterministic template-validation pipeline first
   (Miniscript compile + semantic invariants + regtest vectors +
   user-summary hash binding + multi-maintainer signature check).
3. Ship ONE template end-to-end (suggest:
   time-bounded SaaS subscription with cancellation window — the
   highest-volume real-world category).
4. Wire `konsensus-ai` orchestration interface (read-only API into
   Agreements; no write-through to core; oracle resolution against
   the signed `ORACLES.md` list only).
5. Validate UX with real users (Maya, Josh) before scaling
   templates.
6. Decide in-tree vs external monorepo at that point. Vision doc
   recommends external; in-tree is acceptable for the first 1-2
   templates while the API stabilizes.

## Consequences

### Positive

- Architectural separation prevents the Track L0 freeze surfaces
  from being polluted by contract-layer ambition.
- The "design thesis" framing gives the team a calibrated
  hypothesis to test, rather than a marketed claim. The 80%/20%
  numbers stay out of investor and product surfaces until measured.
- AI permission boundary is explicit and structurally enforces the
  "no checkbook for the AI" property: no raw script, no signing,
  no oracle picking, no plasticity write-back, no template-summary
  suppression.
- Plasticity stays a routing reflex; Agreements stay a deliberate
  contract layer; they communicate one-way, never conflate.

### Negative

- Adds future scope. Operator must decide whether the Agreements
  layer is the right next strategic bet after Track L0 + the
  current finish line.
- Requires additional OSS dependencies whose audit status must be
  verified before adoption (`rust-miniscript`, `rust-dlc`, `bdk`).
- Template-archive maintenance becomes a new ongoing responsibility,
  including a multi-maintainer signing ceremony, regtest vectors
  per template, and revocation discipline. Mitigation: start with
  1-2 templates, scale only as real user demand justifies.

### Risk register

- **Oracle trust** for DLC contracts is unsolved at federation level.
  Mitigation: operator-approved oracle IDs only (`ORACLES.md`); use
  existing Suredbits / atomic.finance oracles for v1; defer custom
  oracle federation.
- **Multi-jurisdictional legal recognition** is out of scope for the
  protocol. Mitigation: documentation positions the layer as
  "settlement automation" not "legal substitute"; partners with
  legal for the judgment layer.
- **Subjective performance** ("was the contractor professional?")
  has no oracle. Mitigation: those agreements use multi-sig +
  arbitrator patterns (template `delivery_milestone.rs`), not pure
  DLC.
- **Template archive integrity.** Maintainer key compromise could
  ship malicious templates. Mitigation: ≥2 maintainer signatures,
  semantic invariants enforced at runtime, regtest vectors, signed
  oracle list, signed user-readable summary, documented revocation
  path. A Miniscript-valid template is treated as **necessary, not
  sufficient**.
- **AI orchestration overreach.** AI surfaces a template the user
  doesn't fully understand. Mitigation: user-readable summary is
  hash-bound to the template body; UI cannot suppress it; AI
  cannot bypass.

## Implementation gating

Before the first commit lands in `crates/konsensus-agreements/`:

- [ ] Track L0 (live-funds safety preflight) is closed.
- [ ] ADR-027 is merged and the v2 specs are clean.
- [ ] Operator explicitly approves Agreements as the next workstream
  (vs. Lightning hardening continuation, frontend polish, or other
  v2 finish-line work).
- [ ] A new factory scope regex is added (e.g. `^A[0-9]+$`) gated
  on this ADR. Without the regex, no factory lane can pick
  Agreements tasks.
- [ ] Maintainer key set is documented in
  `crates/konsensus-agreements/MAINTAINERS.md` and ≥2 keys are
  provisioned with a documented revocation path before any
  template lands.

This ADR records the architectural decision and permission boundary.
It does NOT authorize implementation. That authorization is a
separate operator action.
