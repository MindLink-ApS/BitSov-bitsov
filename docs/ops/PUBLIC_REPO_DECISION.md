# Public Repo Decision

**Decision date:** 2026-07-08
**Decision:** Refresh `MindLink-ApS/BitSov-bitsov` as the public protocol repo
from a fresh allowlisted export. Keep `Konsensus_v02` and its full private
history private.

## Repositories

### Public

- `MindLink-ApS/BitSov-bitsov` — open protocol, reference node, API/CLI, tests,
  and public protocol docs. After debut this is the canonical public protocol
  development repo, not a stale downstream showroom. The post-merge refresh
  removes `frontend/` from this protocol tree and preserves Josh's existing
  `feat/blvm-lightning-free-payments` branch.
- `MindLink-ApS/bitsov-app` — open reference desktop app/client. It consumes
  the public node API and must remain optional.
- `BitSov/bitsov-rfcs` — optional later split for ADR/RFC governance.
- `BitSov/bitsov.dev` — optional public docs site generated from scrubbed docs.

The repo-name decision is closed by D1/D2 in
`docs/ops/LAUNCH_DECISION_REGISTER.md`: no fresh `bitsov-core` repo for the
developer debut. Website metadata, release URLs, and public copy must point to
`MindLink-ApS/BitSov-bitsov` for protocol and `MindLink-ApS/bitsov-app` for the
reference app once those repositories are instantiated/published under the
launch gates.

### Private

- `MindLink-ApS/konsensus_v02-archive` — current repository and full history.
- `MindLink-ApS/Konsensus_v02` — private overlay for ops, services, staging,
  non-public integration work, and release/export preparation.
- `MindLink-ApS/mindlink-ops` — deploy, GCP, monitoring, inventories, secrets
  wiring, factory runtime, live reports.
- `MindLink-ApS/mindlink-business` — GTM, grants, legal, pricing, ChainBridge,
  partner, and jurisdiction strategy.
- `MindLink-ApS/mindlink-distribution` — App Store/Play/PWA signing and
  MindLink-branded packaging.
- `MindLink-ApS/mindlink-services` — billing/admin/customer service surfaces.

## Immediate Public Exclusions

- `konsensus.db` and all runtime databases
- private strategy drafts
- long-form legal/operator charters with subpoena, warrant-canary, or product
  comparison claims until reviewed as public copy
- internal agent context, raw factory/session state, and private roadmaps
- `scripts/ops/**`, `scripts/factory/**`, `scripts/cloud/**`
- live deploy inventories under `deploy/`
- app-store signing, APNS/FCM, customer profile registries
- any GCP project IDs, secret names, Slack/PagerDuty hooks, node IDs, IPs,
  balances, channel IDs, txids, or customer names

## Gate

No public flip until:

- full tree and history secret scan have clean reports
- branch protections, CODEOWNERS, CONTRIBUTING, SECURITY, and release policy are
  in place
- the first public release artifact has checksums and signatures
- README/docs no longer describe managed keys, custodial LNbits, or Tier-3 cloud
  hosting as an available path
