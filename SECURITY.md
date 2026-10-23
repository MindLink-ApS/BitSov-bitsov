# Security Policy — BitSov

BitSov is a sovereign mesh network where users hold their own cryptographic identity and funds. A vulnerability in BitSov is not just a software bug — it may compromise a user's Bitcoin keys, Lightning channels, or private communications. We take security reports seriously and respond quickly.

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release candidate (`rc`) of BitSov | Yes |
| Earlier release candidates and other releases | No |

Only the latest release candidate receives security fixes; we do not backport
patches. Upgrade to the latest `rc` before reporting a reproducible issue. See
[releases](https://github.com/MindLink-ApS/BitSov-bitsov/releases) for release
information. This policy covers this repository's node, exported protocol
crates, API, CLI, and protocol documents; other projects have separate policies.

The Daily Security Scan scopes OSV to the root `Cargo.lock`, which resolves all release dependencies (no frontend ships here); vendored crates' standalone lockfiles are not release build inputs, and any future release-input lockfiles must be added explicitly.

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Use GitHub's **Security → Report a vulnerability** for this repository:

[Report a vulnerability privately](https://github.com/MindLink-ApS/BitSov-bitsov/security/advisories/new).

Private vulnerability reporting is enabled. Reports submitted through this flow
are shared privately with the repository's maintainers. Keep reproduction details
and follow-up discussion in the private report until disclosure is coordinated.
Do not include seed phrases, private keys, credentials, or other secrets.

### What to Include

A useful report includes:

- **Description** — what the vulnerability is and what it affects
- **Impact** — what an attacker can do if they exploit it (keys? funds? messages? DoS?)
- **Reproduction** — step-by-step instructions or a minimal proof-of-concept
- **Affected components** — which crate(s), binary, API route, CLI command, or protocol document
- **Suggested fix** (optional) — your proposed patch or mitigation

The more detail you provide, the faster we can triage and respond.

---

## Response Timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgement | Within **48 hours** of receipt |
| Triage & severity assignment | Within **5 business days** |
| Fix for Critical/High | Within **14 days** of confirmation |
| Fix for Medium | Within **30 days** of confirmation |
| Fix for Low/Informational | Within **90 days** or next scheduled release |
| Public disclosure | Coordinated with reporter, typically **90 days** after fix ships |

If we need more time (e.g., coordinated disclosure with downstream users), we will communicate this explicitly. We will not silently miss a deadline.

If you do not receive acknowledgement within 48 hours, follow up in the same private GitHub report.

---

## Severity & Bounty

We pay bounties in **satoshis over Lightning**. Severity is assessed using CVSS 3.1 as a guide, with final judgment reserved for the BitSov team.

| Severity | Examples | Bounty |
|----------|---------|--------|
| **Critical** | Private key extraction, Lightning channel theft, remote code execution, payment gate bypass without detection | **10,000 sats** |
| **High** | Message plaintext leakage, forced node de-anonymization, authentication bypass, whitelist bypass | **5,000 sats** |
| **Medium** | DoS via crafted message, partial metadata leakage, session fixation, non-critical identity correlation | **1,000 sats** |
| **Low / Info** | Minor logic errors, missing hardening, informational leaks with no exploitable path | **100 sats** |

### Bounty Conditions

- The vulnerability must affect the latest supported release candidate
- A working reproduction must be provided (not just theory)
- The issue must not already be known or reported by someone else
- The reporter must supply a Lightning invoice to receive payment
- Bounties are paid after the fix is merged and verified, not at triage
- We reserve the right to adjust severity after full analysis — we communicate changes

Duplicate reports: first reporter wins. If two reports arrive simultaneously, we split the bounty.

---

## What Is In Scope

- `konsensus-node` binary and all exported workspace crates in this repository
  (`konsensus-api`, `konsensus-bsx`, `konsensus-chain`, `konsensus-core`,
  `konsensus-crypto`, `konsensus-fiat`, `konsensus-gossip`,
  `konsensus-lightning`, `konsensus-message`, `konsensus-node`,
  `konsensus-pricing`, `konsensus-routing`, `konsensus-storage`)
- Public node API and CLI surfaces
- Protocol relay code and documents in this repository
- Node-to-node wire protocol
- Key derivation and identity anchoring logic
- Payment gate and Lightning integration
- Federation, routing, invite, recovery, and whitelist enforcement

### Out of Scope

- Attacks requiring physical access to the device
- Vulnerabilities in third-party dependencies (report upstream; let us know so we can track)
- Social engineering of team members
- Spam, phishing, or abuse issues unrelated to software
- Issues in demo/test environments that do not reflect production code

---

## Hall of Fame

Researchers who responsibly disclosed valid vulnerabilities. Listed in chronological order.

| Researcher | Date | Severity | Component | Notes |
|------------|------|----------|-----------|-------|
| *(first report pending)* | — | — | — | — |

We respect anonymity — if you prefer not to be listed, say so in your report.

---

## Disclosure Policy

BitSov follows **coordinated vulnerability disclosure**:

1. Reporter submits a private report using GitHub's **Report a vulnerability** flow
2. BitSov acknowledges within 48 hours
3. BitSov investigates, confirms, and assigns severity
4. BitSov develops and tests a fix — reporter may review draft patch on request
5. Fix is merged to `main` and released
6. Public disclosure is published, crediting the reporter (unless they opt out)
7. Bounty is paid upon confirmation of fix

We will not take legal action against researchers acting in good faith who follow this policy. We will not publicly identify reporters without consent. We will not disparage researchers who report valid issues.

If a vulnerability is being actively exploited in the wild, we may accelerate disclosure and release a fix before the standard timeline.
