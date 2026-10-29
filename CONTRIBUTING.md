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

Post a PR conversation comment with a line that is exactly
`<VENDOR>-VERDICT PASS|FAIL <40-hex head sha>`, for example:

```text
_Relayed from the Codex terminal._

CODEX-VERDICT PASS 0123456789abcdef0123456789abcdef01234567
Review details follow here.
```

The verdict line may appear anywhere in the comment. Surrounding spaces or
tabs are ignored, but nothing else may share the line: quoted (`> `), bold,
inline-code, indented-code and fenced-code verdicts do not count. A comment
that gives one family both PASS and FAIL for the head counts as FAIL.

Families are CLAUDE (CLAUDE/FABLE/OPUS), CODEX, and CURSOR
(GROK/COMPOSER/CURSOR). Only the current PR head counts; the most recently
*posted* verdict per family wins. Editing a comment does not make it newer, so
post a new comment to change a verdict. Deleting a comment recomputes the gate. Set one `builder:claude`, `builder:codex`, or
`builder:cursor` label; otherwise `cursor/` and `cloud/` branch prefixes imply
CURSOR and CLAUDE respectively. An unknown or conflicting builder stays pending.

The `review-gate` commit status ignores the builder's verdicts and blocks on
any other family's FAIL. Docs-only PRs (all paths end in `.md` or start with
`docs/`) need one other family's PASS. Paths under `.github/`, any
`CONTRIBUTING.md` or `CODEOWNERS`, and `.sh`, `.yml`, `.yaml` or `.toml` files
under `docs/` are never docs-only. All other PRs need two. Money/security
PRs must include CODEX, or CLAUDE when CODEX built the PR; these are PRs labeled
`money`/`security`, touching `crates/konsensus-lightning/` or
`crates/konsensus-crypto/`, or with paths containing `spend_budget`, `pairing`,
`invoice`, or `session`. The docs-only exception applies first.

Set the repository variable `REVIEW_GATE_AUTHORS` to the comma-separated
GitHub logins that post verdicts: the owner account and the reviewer bots, such
as `cursor[bot]`. When it is set, only those logins count, whatever their
`author_association` (bots post as `NONE`). When it is unset, or has no
non-blank entries (for example `,`), any comment with an `author_association`
of OWNER, MEMBER, or COLLABORATOR counts, which includes every org member and
read-only collaborator. Comments without a user are skipped. Vendor tags rely on honest
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
