# Open Core Boundary

**Status:** Active policy  
**Decision date:** 2026-05-20  
**Authority:** `CHARTER.md`

## Rule

If another sovereign operator needs code or specs to interoperate with BitSov,
audit the protocol, fork the stack, migrate away from MindLink, or run an
equivalent relay, it belongs in the open core.

If the code is specifically MindLink's commercial operation, customer
relationship, infrastructure, billing, support, brand, or internal automation,
it belongs in a private MindLink repository.

## Open

- identity derivation, key binding, signing, and device grants
- UKM envelope, kind registry, payment gate, nonce replay rules
- Noise/wire protocol, E2EE session logic, relay wire protocol
- Lightning proof semantics and provider traits
- relay registration/drain/migration protocol
- storage schemas required for portable self-hosting and relay compatibility
- migration/export/import and SCB recovery
- neutral reference node, CLI, API, and client UI
- generic deployment templates with placeholder hosts/secrets
- charter, threat models, ADRs, RFCs, and release verification policy

## Private MindLink

- GCP/Terraform/Pulumi, VM inventories, firewall rules, live node names/IPs
- Secret Manager bindings, Slack/PagerDuty, monitoring targets, deploy reports
- factory agents, private task queues, prompts, watchdogs, session logs
- pricing strategy, grants, GTM, legal, jurisdiction, investor materials
- Stripe/fiat billing, tax/VAT, dunning, refunds, ChainBridge execution
- customer records, CRM, support scripts, incident timelines
- App Store/Play signing, APNS/FCM credentials, branded distribution overlays
- relay fleet admission policy, quotas, abuse heuristics, capacity planning

## Public Tree Rule

The public repository must be assembled from an allowlisted clean tree. Do not
make the current private repository public and do not rely on history rewriting
as the primary cleanup mechanism.

The private archive remains the source of historical operator context. The open
core starts with a clean initial commit.
