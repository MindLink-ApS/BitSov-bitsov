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

### Review verdicts

Post a PR conversation comment whose **first line** is exactly
`<VENDOR>-VERDICT PASS|FAIL <40-hex head sha>`, for example:

```text
CODEX-VERDICT PASS 0123456789abcdef0123456789abcdef01234567
Review details follow here.
```

Families are CLAUDE (CLAUDE/FABLE/OPUS), CODEX, and CURSOR
(GROK/COMPOSER/CURSOR). Only the current PR head counts; the latest comment
or edit per family wins. Set one `builder:claude`, `builder:codex`, or
`builder:cursor` label; otherwise `cursor/` and `cloud/` branch prefixes imply
CURSOR and CLAUDE respectively. An unknown or conflicting builder stays pending.

The `review-gate` commit status ignores the builder's verdicts and blocks on
any other family's FAIL. Docs-only PRs (all paths end in `.md` or start with
`docs/`) need one other family's PASS. All other PRs need two. Money/security
PRs must include CODEX, or CLAUDE when CODEX built the PR; these are PRs labeled
`money`/`security`, touching `crates/konsensus-lightning/` or
`crates/konsensus-crypto/`, or with paths containing `spend_budget`, `pairing`,
`invoice`, or `session`. The docs-only exception applies first.

Only comments with an `author_association` of OWNER, MEMBER, or COLLABORATOR
count. The optional repository variable `REVIEW_GATE_AUTHORS` further restricts
verdicts to comma-separated GitHub logins. Vendor tags rely on honest
attribution until per-vendor GitHub Apps exist. The workflow loads gate scripts
from the trusted default branch and becomes active after merging to `main`. On
same-repo branches the workflow YAML comes from the PR head, so this is an
honest-system gate for collaborators.
Fork PR runs have read-only tokens; post or edit a PR comment after head/label
changes to recompute their status from `main`. Merge-queue groups report success
because review is enforced on the PR before enqueue. Making `review-gate`
required is a separate ruleset decision for the owner.

## Security Reports

Use private security disclosure channels. Do not open a public issue for a
suspected vulnerability until maintainers have triaged and published an advisory.
