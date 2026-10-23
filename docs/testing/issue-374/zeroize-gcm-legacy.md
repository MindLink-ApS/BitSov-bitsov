# GCM and legacy decryption wiping follow-up

Base: `dc016f18` (#381). Addresses P3-1 and P3-2 from the #381 review.

## Dependency features and limits

Enable `zeroize` on the already locked `ghash 0.5.1` and `polyval 0.6.2`
through normal node dependencies. Neither `aes-gcm/zeroize` nor
`ghash/zeroize` forwards to its authentication backend, so both explicit
feature selections are necessary. No package versions or checksums change.

The locked sources provide these guarantees and limitations:

- GHASH wipes the temporary reversed key and converted POLYVAL key in
  `GHash::new_with_init_block`.
- POLYVAL's software backends wipe their key and accumulator on drop. This
  includes the default aarch64 build, without the opt-in `polyval_armv8` cfg.
- POLYVAL 0.6.2's `backend/autodetect.rs` stores its backend in `ManuallyDrop`
  without a corresponding `Drop` implementation. On x86/x86_64 (and opt-in
  ARM intrinsics builds), dropping the retained GHASH state therefore still
  does not wipe that backend. Finalization consumes the selected backend;
  software and x86 CLMUL backends wipe that consumed state.
- The opt-in ARM PMULL backend's zeroizing drop is also an upstream TODO.

Feature enablement cannot fix those upstream drop gaps. This follow-up does
not vendor a patch, force a different backend, or upgrade dependencies; it
does not claim complete authentication-subkey wiping on every platform.
Relevant locked sources: `ghash-0.5.1/{Cargo.toml,src/lib.rs}` and
`polyval-0.6.2/src/backend{.rs,/autodetect.rs,/soft32.rs,/soft64.rs,/clmul.rs,/pmull.rs}`.

## Legacy plaintext ownership

`decrypt_mnemonic` returns `Zeroizing<String>` by transferring the decrypted
allocation without cloning the phrase. On UTF-8 failure, `FromUtf8Error`
returns ownership of the original bytes, which are explicitly zeroized
before returning the same generic `InvalidFormat` error. `read_mnemonic`
passes the zeroizing value through directly.

In locked aes-gcm 0.10.3, authentication is checked before applying the
decryption keystream. An authentication error therefore drops ciphertext,
not plaintext. Earlier header, KDF and cipher-construction failures likewise
have no plaintext buffer. Password handling, KDF parameters, v1 bytes,
accepted inputs, and error messages are unchanged.

The tests use only synthetic inputs and the existing committed `.enc`
fixture. The non-UTF-8 test checks the returned error payload, Display, Debug,
and absence of an error source; it does not inspect freed memory or claim to
measure physical erasure. The round-trip test also pins the zeroizing return
type at compile time.

## Verification

| Command | Result |
| --- | --- |
| `cargo test -p konsensus-node -p konsensus-api --no-fail-fast` | Exit 0; 2,609 passed, 0 failed, 1 ignored; 99 targets. |
| `cargo clippy --workspace --all-targets -- -D warnings` | Exit 0. |
| `cargo +1.89.0 check --workspace --locked` | Exit 0 on installed Rust 1.89.0. |
| `cargo tree -p konsensus-node -e normal,features --locked` | Both `ghash/zeroize` and `polyval/zeroize` enabled; no `test-support` feature. |
| `git diff --check` | Passed. |

The initial sandboxed test run was stopped after
`pairing::second_device_tests::t16_console_socket_approve_status_revoke_cancel_and_reset`
failed to bind its temporary control socket with `Operation not permitted`.
The complete suite above ran with local socket access and passed, including
that test, the unchanged legacy `.enc` fixture, and the new non-UTF-8 case.
Before the production edit, the round-trip test's `Zeroizing<String>` type
annotation failed compilation against the old plain `String` return.

Existing dependency warnings remain: the vendored electrum-client lifetime
warning and sqlx-postgres 0.8.0 future-incompatibility notice. A separate
read-only code review found no actionable defects. No real seed files were
read.
