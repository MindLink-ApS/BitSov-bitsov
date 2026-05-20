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

## Private Distribution

MindLink distribution repositories may package BitSov for App Store, Play Store,
PWA, customer installers, or hosted relay operations only after verifying the
public artifact checksum and signature.

Private distribution must not become the canonical source of protocol releases.
The open-core release remains canonical.
