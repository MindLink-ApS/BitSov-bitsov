# Public Repo Decision

**Decision date:** 2026-05-20  
**Decision:** Build a fresh allowlisted public core tree. Keep the current
repository and full history private.

## Repositories

### Public

- `BitSov/bitsov` — open protocol, reference node, neutral client, tests, and
  public docs.
- `BitSov/bitsov-rfcs` — optional later split for ADR/RFC governance.
- `BitSov/bitsov.dev` — optional public docs site generated from scrubbed docs.

### Private

- `MindLink-ApS/konsensus_v02-archive` — current repository and full history.
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
