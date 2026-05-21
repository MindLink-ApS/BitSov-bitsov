# Release Policy

BitSov public releases must be independently verifiable.

## Required For Public Releases

- protected signed tag
- Linux binary built from the protected tag
- `SHA256SUMS`
- detached signature for `SHA256SUMS` using the release key
- SBOM
- GitHub artifact attestation or equivalent provenance
- release notes naming protocol-affecting migrations and rollback constraints

## Current Automation

The public CI workflow blocks release tags unless `MINISIGN_PRIVATE_KEY` is
configured as a repository secret. `Cargo Audit` fails CI for unreviewed RustSec
vulnerabilities; temporary accepted-risk advisories are documented in
`.cargo/audit.toml` and must be revisited before the first public release
candidate. CLI release artifacts are uploaded with:

- the binary
- a SHA-256 checksum file
- a detached minisign signature for that checksum
- an SPDX JSON SBOM
- GitHub artifact provenance attestation

Do not publish the repository or create a public tag until the release public
key is documented and the first dry-run tag has produced all five artifacts.

## Private Distribution

MindLink distribution repositories may package BitSov for App Store, Play Store,
PWA, customer installers, or hosted relay operations only after verifying the
public artifact checksum and signature.

Private distribution must not become the canonical source of protocol releases.
The open-core release remains canonical.
