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

## Draft Artifact Staging

Tag-triggered CI may stage draft/prerelease GitHub releases and signed mobile
artifacts for review. Draft staging is not public-release approval. Do not
publish GitHub releases or promote TestFlight/Play builds until every public
release requirement above is verified and the operator signs off.

## Private Distribution

MindLink distribution repositories may package BitSov for App Store, Play Store,
PWA, customer installers, or hosted relay operations only after verifying the
public artifact checksum and signature.

Checksum/signature verification is a minimum artifact-integrity precondition,
not distribution approval. App-store promotion, customer installers, hosted
relay operations, or any managed customer distribution also require the
release-trust, install/migration, legal/compliance, and operator approval gates
to pass for the exact flow being shipped.

Private distribution must not become the canonical source of protocol releases.
The open-core release remains canonical.
