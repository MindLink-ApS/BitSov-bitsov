# PR 174 Zeroization Fix Plan

**Goal:** Remove explicit secret-array copies in identity construction and erase retained private keys without changing identities.

**Spec:** PR #174 fix-round request: same branch, offline tests/clippy, commit with Codex trailer, no push, never contact port 3141.

**Architecture:** Keep bip39 only under the requested offline fallback: an isolated `cargo metadata --offline` probe reports no matching package named `pbkdf2`. Use borrowed key construction and drop-protected storage. x25519-dalek 2.0.1 needs a small vendored borrowed constructor because upstream only accepts arrays by value.

**Files:** workspace Cargo.toml/Cargo.lock; konsensus-core/src/identity.rs; vendor/x25519-dalek (cached upstream source plus borrowed constructor); PR description.

- [x] Add tests first: official 12/18/24-word TREZOR seed vectors; normalization/whitespace parity with bip39; existing fixed node/owner ids; actual key-holder zeroization/drop bounds; borrowed X25519 constructor; secp erasure; JWT byte compatibility.
- [x] Run identity tests to establish missing borrowed constructor / unprotected AES and secp holders.
- [x] Explicitly enable dalek zeroize features. Vendor cached X25519 with `From<&[u8; 32]>` filling `StaticSecret([0; 32])` by reference. Remove the duplicate X25519 raw array; expose `StaticSecret::as_bytes()` instead.
- [x] Wrap secp SecretKey in a private non-Copy holder implementing erasure in Drop via non_secure_erase. Move AES Zeroizing holder into NodeIdentity. Return JWT derivation in Zeroizing, using the existing protected KDF helper.
- [x] Run affected core/crypto/api/node tests and workspace all-target clippy with --offline --locked and -D warnings. Inspect the final diff and vendor-source delta.
- [x] Update PR text with the offline fallback, compiler/move/spill limits, bip39 parsing/PBKDF2 buffers, third-party key-operation buffers, and transport limits; accurately label the unpushed fix.
- Finalize on fix/zeroize-mnemonic-seed with the requested final Co-Authored-By line; verify clean status and report the commit SHA in the completion message.

Review focus: no ID/key byte changes; NFKD and parsed-word canonicalization unchanged; secp cleanup on early exits; no raw-array copies from Zeroizing; no claim that memory erasure prevents compiler/dependency copies.

Validation: 2,571 affected core/crypto/api/node tests passed, 0 failed, 1 ignored. Workspace all-target clippy with `--offline --locked -- -D warnings` exited 0 (existing sqlx-postgres future-incompatibility notice only). Initial test-socket sandbox denials were resolved by rerunning with ephemeral socket permission. A read-only code reviewer found no blocking/important findings; vendor archive checksum and source delta were verified.
