# BitSov shared Esplora transport

Baseline: crates.io `esplora-client` **0.12.3**, upstream
https://github.com/bitcoindevkit/rust-esplora-client, archive SHA-256
`f19e3ea99dbfbef0c1ec26d83e69de0c579f6aa6aaac4f44597805fcc27e97af`.
Copied from the already cached archive; no download. Original MIT license retained.

Production delta is restricted to `src/async.rs`: an optional `HttpTransport`
trait object, a builder-style setter, and one dispatch helper used at both HTTP
send sites (GET including retries, and POST). Clones share the transport. Without
an override, the upstream request and retry behavior is unchanged. An error from
the transport returns immediately rather than entering upstream's HTTP-status
retry loop. LDK installs its shared cooldown here so it can inspect the original
429 response and Retry-After header before Esplora discards response headers.
No error variants, Bitcoin parsing, blocking-client code, or endpoint semantics
are changed.

Packaging follows the existing LDK vendor: production sources and licenses only.
The upstream `lib.rs` daemon/socket test module and its unused electrsd/lazy_static
and Tokio dev dependencies are omitted. No upstream daemon is downloaded or run.
The new transport is exercised through the real client and LDK wallet/fee/funding/
broadcast methods by `bitsov_http_rate_tests` in the vendored LDK library. Those
fixtures construct HTTP responses in memory; they cannot open a socket.

Verification:

    cargo test --offline --locked --manifest-path vendor/ldk-node/Cargo.toml --lib
    cargo test --offline --locked -p esplora-client --lib
    cargo clippy --offline --locked -p esplora-client --all-targets -- -D warnings

The standalone client library target contains no unit tests; the LDK fixture
suite above is the behavioral verification. Run under OS network denial as
specified in the LDK patch notes. Optional standalone client feature combinations
are not claimed verified; its standalone dependency resolution requires uncached
native-tls. The workspace's locked, shipped async-rustls combination is verified.
