# Security Policy — BitSov

BitSov is a sovereign mesh network where users hold their own cryptographic identity and funds. A vulnerability in BitSov is not just a software bug — it may compromise a user's Bitcoin keys, Lightning channels, or private communications. We take security reports seriously and respond quickly.

---

## Supported Versions

Only the **current pre-release line** is supported. BitSov has not published a stable release, and security fixes are not backported. Run the latest build of this line.

| Version | Supported |
|---------|-----------|
| Current pre-release line: latest `main`, and the newest `v0.3.0-rc*` tag cut from it (workspace version `0.3.0-rc20` when this table was written) | Yes |
| `konsensus-node` and the exported protocol crates on that line | Yes |
| Public node API, CLI, and protocol documents in this repository on that line | Yes |
| Earlier tagged releases, including older `v0.3.0-rc*` tags | No |
| Any other version line | No |

Public reference app, hosted relay or service code, the website, and commercial operations are outside this repository and are not covered here.

---

## Reporting a Vulnerability

**Do not open a public GitHub issue, discussion, or pull request for a suspected vulnerability.** A public report can expose users before a fix exists. Public issues are for defects that are not vulnerabilities.

Report privately with **GitHub private vulnerability reporting**:

1. Open this repository on GitHub.
2. Open the **Security** tab.
3. Choose **Report a vulnerability**.
4. Submit the report there.

That channel is private to the maintainers. It is not a public issue, and it does not require PGP.

You may encrypt supporting files to the disclosure key below and attach them to the same private report. The address on that key is the key's published identity. This policy does not add another reporting address. Prefer the Security tab over sending the report by mail.

### What to Include

A useful report includes:

- **Description** — what the vulnerability is and what it affects
- **Impact** — what an attacker can do if they exploit it (keys, funds, messages, denial of service)
- **Reproduction** — step-by-step instructions or a minimal proof of concept
- **Affected components** — which crate, binary, API route, CLI command, or protocol document
- **Suggested fix** (optional) — your proposed patch or mitigation

The more detail you provide, the faster we can triage and respond.

---

## Response Timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgement | Within **72 hours** of receipt |
| Triage and severity assignment | Within **5 business days** |
| Fix for Critical/High | Within **14 days** of confirmation |
| Fix for Medium | Within **30 days** of confirmation |
| Fix for Low/Informational | Within **90 days** or the next scheduled release |
| Public disclosure | Coordinated with the reporter, typically **90 days** after the fix ships |

If we need more time (for example, coordinated disclosure with downstream users), we will say so. We will not silently miss a deadline.

If you do not receive an acknowledgement within 72 hours, follow up on the same private vulnerability report.

---

## Safe Harbour

We will not pursue civil or criminal action, and we will not support such action by others, against someone who, in good faith, investigates and reports a vulnerability under this policy. Good faith means you report privately through the Security tab, you avoid privacy violations, destruction of data, and interruption of the service beyond what is necessary to demonstrate the issue, you do not take funds, keys, or message plaintext, and you give us a reasonable chance to investigate and ship a fix before any public disclosure. This safe harbour does not cover attacks on other people's nodes, theft, or disruption of the network.

We will not publicly identify reporters without consent.

---

## Disclosure Key

This key encrypts optional attachments. It is not a second reporting channel. Release artifacts are signed with a **separate** release key (`info@mindlink.tech`, fingerprint `B299 274C 2003 0171 4DC6  F51A 7C2D 6F8A C842 EF6E`) — verify downloads against that key, published on the release page and as `RELEASE_KEY.asc`.

```
Contact:         info@mindlink.tech
Fingerprint:     B279 C1F4 EA9B 93DC 834E  97E6 3192 99EA BD6D 3B39
Encryption:      subkey 2DF2 C497 4353 EAAD 3961  BFEC 35EF 7A02 0144 2124
Expires:         2030-09-10
```

The disclosure key is **certified by the release key**: after importing both keys, `gpg --check-sigs B279C1F4EA9B93DC834E97E6319299EABD6D3B39` shows a good signature from `B299 274C … C842 EF6E`. A disclosure key without that certification is not ours.

Import and verify by **fingerprint** before encrypting. Trust the fingerprint, not the UID:

```bash
gpg --import SECURITY_KEY.asc
gpg --fingerprint B279C1F4EA9B93DC834E97E6319299EABD6D3B39
# Confirm the printed fingerprint matches the one above before encrypting.
```

> **Retired key (2026-09-10):** the previous disclosure key `8407 155E C7A1 F376 A910  C509 CFFC 76C3 AE38 03C4` (`security@bitsov.io`) must not be used. It was generated by an automated build session and its private key was never in the maintainers' custody, so reports encrypted to it cannot be read. No revocation certificate exists; if the private key is ever recovered, a revocation will be published here. **Do not encrypt to it.** If you sent a report to it, please re-encrypt to the key above and resend on the private vulnerability report — we honour the original submission date.

The full public key is in [`SECURITY_KEY.asc`](./SECURITY_KEY.asc).

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
(see SECURITY_KEY.asc)
-----END PGP PUBLIC KEY BLOCK-----

Fingerprint: B279 C1F4 EA9B 93DC 834E  97E6 3192 99EA BD6D 3B39
```

---

## Severity and Bounty

We pay bounties in **satoshis over Lightning**. Severity is assessed using CVSS 3.1 as a guide, with final judgment reserved for the maintainers.

| Severity | Examples | Bounty |
|----------|---------|--------|
| **Critical** | Private key extraction, Lightning channel theft, remote code execution, payment gate bypass without detection | **10,000 sats** |
| **High** | Message plaintext leakage, forced node de-anonymization, authentication bypass, whitelist bypass | **5,000 sats** |
| **Medium** | DoS via crafted message, partial metadata leakage, session fixation, non-critical identity correlation | **1,000 sats** |
| **Low / Info** | Minor logic errors, missing hardening, informational leaks with no exploitable path | **100 sats** |

### Bounty Conditions

- The vulnerability must affect the current pre-release line (`main`)
- A working reproduction must be provided (not just theory)
- The issue must not already be known or reported by someone else
- The reporter must supply a Lightning invoice to receive payment
- Bounties are paid after the fix is merged and verified, not at triage
- We reserve the right to adjust severity after full analysis — we communicate changes

Duplicate reports: the first reporter is paid. If two reports arrive together, we split the bounty.

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

- Attacks that require physical access to a device
- Vulnerabilities in third-party dependencies (report them upstream, and tell us so we can track)
- Social engineering of maintainers
- Spam, phishing, or abuse that is not a software defect
- Issues in demo/test environments that do not reflect production code

---

## Hall of Fame

Researchers who responsibly disclosed valid vulnerabilities, in chronological order.

| Researcher | Date | Severity | Component | Notes |
|------------|------|----------|-----------|-------|
| *(first report pending)* | — | — | — | — |

If you prefer not to be listed, say so in your report.

---

## Disclosure Policy

BitSov follows coordinated vulnerability disclosure:

1. The reporter submits a private report: **Security** tab, then **Report a vulnerability**.
2. Maintainers acknowledge within 72 hours.
3. Maintainers investigate, confirm, and assign severity.
4. Maintainers develop and test a fix. The reporter may review a draft patch on request.
5. The fix is merged to `main` and shipped on the current pre-release line.
6. Public disclosure is published, crediting the reporter unless they opt out.
7. The bounty is paid after the fix is confirmed.

We will not disparage researchers who report valid issues. If a vulnerability is being actively exploited, we may ship a fix and disclose before the standard timeline.
