# Contributing

BitSov is a sovereign protocol project. Contributions must preserve the
load-bearing commitments in `CHARTER.md`.

## Non-Negotiable Boundary

Do not submit changes that introduce:

- operator-held user mnemonics or device signing keys
- key escrow or custodial recovery
- operator-decryptable message plaintext
- operator-issued user payment proofs
- hidden dependency on MindLink infrastructure for protocol correctness

Commercial vendor code, live infrastructure, billing, customer data, strategy,
and deploy inventories belong outside the open core.

## Pull Requests

- Keep protocol changes small and reviewable.
- Include tests for payment-gate, storage-wrapper, and encrypted-storage paths
  when touching those boundaries.
- Prefer config-gated behavior that defaults off for relay/operator roles.
- Public issues must not contain secrets, live node IDs, customer names, channel
  balances, txids, internal IPs, or unreleased security details.
- Keep a PR under 500 counted lines (the `pr-size` status). Tests, fixtures,
  lockfiles, vendored code and test evidence are not counted. A larger PR
  needs the `large-ok` label and a `## Design note` section explaining why it
  cannot be split.
- Review capacity sets the pace: only the first few open, non-draft PRs (the
  `wip-cap` status, ranked by `m6`/`deadline`, then `security`/`money`, then
  `merge-ready`, then age) are in review. Open new work as a draft while the
  queue is full.

## Security Reports

Use private security disclosure channels. Do not open a public issue for a
suspected vulnerability until maintainers have triaged and published an advisory.
