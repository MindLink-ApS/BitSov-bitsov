# Whitepaper amendment: the receptor

**Status:** Proposed with ADR-042. Not applied to the canonical source.
**Canonical source:** `docs/v2/whitepaper/BitSov_Whitepaper_DRAFT.tex` in
`MindLink-ApS/Konsensus_v02`, section "The doctrine: payment is the
connection". This repository has no whitepaper copy, so a human must apply the
change below there after this PR is approved.

## Change

One sentence is added after the floor list. Nothing else changes; "no service
without settlement" stays intact.

Current:

```latex
Concretely, with no settled,
recipient-bound, single-use payment there is no packet, service, stored state, topology
disclosure, prekey, invoice, peer record, or carrier beyond that floor.
```

Proposed:

```latex
Concretely, with no settled,
recipient-bound, single-use payment there is no packet, service, stored state, topology
disclosure, prekey, invoice, peer record, or carrier beyond that floor. The floor holds one
reply: the \emph{receptor}, a quote for exactly one act, so that a stranger can offer
payment (Line~2) on rails that need a recipient invoice. A receptor is stateless until
settlement, node-signed, short-lived, one per request, rate-capped, discloses only that
act's price, and is the same for a human peer and an AI agent; any other invoice is
beyond the floor.
```

## Rationale

See `ADR-042-receptor-floor.md`.
