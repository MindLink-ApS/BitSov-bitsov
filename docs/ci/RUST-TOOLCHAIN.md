# Rust toolchain pin

`rust-toolchain.toml` at the repository root pins the exact Rust version that
CI installs and that `cargo` selects locally through rustup. It carries
`clippy` and `rustfmt`, so `cargo clippy` and `cargo fmt` run on the same
compiler everywhere.

## Why

CI used to install floating `stable` while contributors built on whatever
their machine had. On #388 a lint new in the CI compiler (`result_large_err`)
failed clippy after the PR had been reviewed, and the local run could not
reproduce it. Pinning one version removes that drift: a PR that is clippy-clean
at `-D warnings` locally is clippy-clean in CI, and the compiler only moves when
someone bumps the pin on purpose.

## How the workflows honour it

Every workflow that installs Rust first runs `scripts/rust-toolchain-channel.sh`,
which prints the `channel` from `rust-toolchain.toml`, and passes that value to
`dtolnay/rust-toolchain` as the `toolchain` input. The script fails closed on a
missing, duplicated or non-exact pin (`stable` is rejected). The `Rust Check &
Test` job also runs `scripts/test-rust-toolchain.sh`, which checks that no
workflow installs `stable`, `beta` or `nightly`, and
`scripts/rust-toolchain-channel.sh --check`, which fails if the `rustc` that
`cargo` will use in the checkout is not the pinned version (for example when a
`RUSTUP_TOOLCHAIN` variable or a rustup directory override masks the file).

Locally, rustup reads the same file: running `cargo` inside the checkout
installs the pinned version on first use (with rustup 1.28.1 or later, or after
`rustup toolchain install` of that version) and uses it for every build.
`RUSTUP_TOOLCHAIN=<version>` or `cargo +<version>` still override it for a
one-off run.

## Three different version numbers

| What | Where | Meaning |
| --- | --- | --- |
| Development and CI toolchain | `rust-toolchain.toml` | The compiler CI tests and lints with. Everyone builds on it. |
| Minimum supported version | `rust-version` in `Cargo.toml` | The oldest compiler the crates claim to build on. Not tested in CI on every PR; raised when a locked dependency needs it. |
| Release-binary toolchain | `scripts/release-toolchain` | The compiler that builds the signed release binaries. It is a reproducibility input and only moves with a reviewed release; see [RELEASE_POLICY.md](../ops/RELEASE_POLICY.md#reproducibility-inputs). |

The release job in `ci.yml` keeps reading `scripts/release-toolchain` and
builds with `rustup run <that version>`, which ignores `rust-toolchain.toml`.
Bumping the development pin therefore never changes the bytes of a release.

## How to bump the pin

1. Install the new stable locally: `rustup toolchain install <x.y.z> --component clippy --component rustfmt`.
2. Change `channel` in `rust-toolchain.toml` to the new exact `x.y.z`. Keep an
   exact version; the helper script rejects channel names.
3. Run on the new compiler and fix every new lint in the same PR:

   ```sh
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace --no-fail-fast
   bash scripts/test-rust-toolchain.sh
   ```

4. Run `cargo fmt` only on files you touched; a new rustfmt may want to
   reformat untouched files, and that churn belongs in its own PR if at all.
5. Open the PR with the clippy and test results in the body. CI installs the
   new version from the file; no workflow edit is needed.

Bump the pin on its own, not inside a feature PR, so a lint-only diff stays
reviewable. If a bump also needs `rust-version` or `scripts/release-toolchain`
to move, say so explicitly; neither follows automatically.
