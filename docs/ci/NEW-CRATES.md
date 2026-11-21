# New crate names

The `New crate names (optional)` pull request job compares the root
`Cargo.lock` at the PR head with the PR's recorded base commit. It lists
every package name present only in the head lockfile in both the job log
and the job summary. Version changes and additional versions of a name
already in the base do not count as new names. Removed names do not count.
Workspace and vendored package names are included alongside registry and
Git dependencies.

The check returns status 1 only when a new name is absent from
`.github/crate-allowlist.txt`. Allowlisted new names are still listed.
Unreadable or malformed inputs return status 2.

The initial allowlist contains every distinct package name in the root
lockfile on main. To add a dependency with a new name, include its name on
its own line in the sorted allowlist and describe the dependency in the
PR. Allowlist changes are reviewed with the dependency change. Blank lines
and lines beginning with `#` are ignored.

This job is initially optional; it is not added to required branch checks.
A missing allowlist entry produces a failed job so it remains visible.

Run the fixture tests with Python 3.11 or later:

```sh
python3 scripts/test-new-crates.py -v
```

Run a local comparison after writing the base lockfile to a temporary file:

```sh
git show origin/main:Cargo.lock > /tmp/base-Cargo.lock
python3 scripts/check-new-crates.py \
  --base-lock /tmp/base-Cargo.lock \
  --head-lock Cargo.lock \
  --allowlist .github/crate-allowlist.txt
```
