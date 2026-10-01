# Local X25519 borrowed-constructor patch

Source: x25519-dalek 2.0.1 from the existing offline Cargo cache.
Original crates.io archive SHA-256:
`c7e468321c81fb07fa7f4c636c3972b9100f0346e5b6a9f2bd0603a52f7ed277`.
The upstream BSD-3-Clause license is retained in LICENSE.

Upstream only implements `From<[u8; 32]>` for StaticSecret. That requires
copying an array out of a Zeroizing holder before entering the constructor.
The local `From<&[u8; 32]>` implementation instead creates a zero-filled
StaticSecret and copies the borrowed input directly into its private field.
It requires both `static_secrets` and `zeroize`, so its destination always
has upstream's zeroizing Drop implementation. No layout casts or unsafe code
are introduced. The raw Noise key accessor borrows `StaticSecret::as_bytes()`;
there is no second retained copy of that key.

Only src/x25519.rs has a code change. Cargo.toml declares upstream's existing
nightly cfg names to Cargo's check-cfg lint. The source, tests, benchmarks,
README and original manifest otherwise match the cached crate. Trailing
whitespace is normalized in the license and changelog; their text is unchanged.
Documentation artwork is omitted.

The borrowed constructor is exercised by the konsensus-core identity tests,
including unclamped-byte parity and the existing DH exchange test. This
patch does not promise to erase compiler-generated moves/spills or internal
curve-operation temporaries. Remove the patch once upstream provides a
suitable borrowed constructor.
