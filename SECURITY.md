# Security Policy — BitSov

BitSov is a sovereign mesh network where users hold their own cryptographic identity and funds. A vulnerability in BitSov is not just a software bug — it may compromise a user's Bitcoin keys, Lightning channels, or private communications. We take security reports seriously and respond quickly.

---

## Supported Versions

| Component | Supported |
|-----------|-----------|
| `konsensus-node` CLI/binary and exported protocol crates (latest `main`) | Yes |
| Public node API, CLI, and protocol documents in this repository | Yes |
| Public reference app, hosted relay/service code, website, and commercial operations | Separate policy |
| All earlier tagged releases | No — upgrade to latest |

We do not backport security patches. Users should always run the latest build.

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately to: **info@mindlink.tech**

Encrypt your report using our PGP key (see [`SECURITY_KEY.asc`](./SECURITY_KEY.asc)):

```
Contact:         info@mindlink.tech
Fingerprint:     8407 155E C7A1 F376 A910  C509 CFFC 76C3 AE38 03C4
Encryption:      subkey C6FB 80C6 D322 62C5 EA64  459D 27AA 6449 981D 4865
Expires:         2028-04-20
```

This key encrypts inbound reports only. Release artifacts are signed with a
**separate** release key (`info@mindlink.tech`, fingerprint
`B299 274C 2003 0171 4DC6  F51A 7C2D 6F8A C842 EF6E`) — verify downloads against
that key, published on the release page and as `RELEASE_KEY.asc`.

Import and verify by **fingerprint** before encrypting. The key's embedded UID
reads `security@bitsov.io` — an early project address; the current and only
contact is **info@mindlink.tech**. Trust the fingerprint, not the embedded UID:

```bash
gpg --import SECURITY_KEY.asc
gpg --fingerprint 8407155EC7A1F376A910C509CFFC76C3AE3803C4
# Confirm the printed fingerprint matches the one above before encrypting.
```

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

If you do not receive acknowledgement within 48 hours, follow up at the same address — email may have been filtered.

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

- The vulnerability must affect the current `main` branch
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

1. Reporter submits encrypted report to info@mindlink.tech
2. BitSov acknowledges within 48 hours
3. BitSov investigates, confirms, and assigns severity
4. BitSov develops and tests a fix — reporter may review draft patch on request
5. Fix is merged to `main` and released
6. Public disclosure is published, crediting the reporter (unless they opt out)
7. Bounty is paid upon confirmation of fix

We will not take legal action against researchers acting in good faith who follow this policy. We will not publicly identify reporters without consent. We will not disparage researchers who report valid issues.

If a vulnerability is being actively exploited in the wild, we may accelerate disclosure and release a fix before the standard timeline.

---

## PGP Key

The full public key is in [`SECURITY_KEY.asc`](./SECURITY_KEY.asc) at the root of this repository.

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
(see SECURITY_KEY.asc)
-----END PGP PUBLIC KEY BLOCK-----

Fingerprint: 8407 155E C7A1 F376 A910  C509 CFFC 76C3 AE38 03C4
```

Always verify the fingerprint before encrypting sensitive reports.
