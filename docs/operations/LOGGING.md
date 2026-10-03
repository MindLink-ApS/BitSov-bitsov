# Bounded node logging

`konsensus start` writes diagnostics to `node.log` beside its configuration file
and to stdout (the journal under systemd). Embedded LDK writes `ldk_node.log`
in its LDK storage directory. Both file writers use the same optional settings:

```toml
[logging]
max_file_size_bytes = 10485760 # 10 MiB per file
max_files = 5                 # TOTAL: active file plus four archives
```

Existing configurations and partial `[logging]` sections use these defaults.
Both values must be positive integers. Limits apply independently to each log:
by default, each retains at most 50 MiB, or 100 MiB for the two combined.
Changes take effect on restart.

Rotation renames `node.log` to `node.log.1`, shifts older archives up to
`node.log.4`, and deletes the oldest. LDK uses the same naming convention.
Normal writes stay intact; a single write larger than the cap is split across
files so it cannot bypass the bound. On restart, oversized existing files retain
their newest capped bytes and numbered archives beyond the retention count are
removed. A split or trimmed file can start partway through a log line or UTF-8
character. Newly created files have mode `0600` on Unix. Each path must have one
owning process; external writers and external rotation are not supported.

For an existing VM installation, remove any `>> node.log`, `tee node.log`,
`StandardOutput=append:...`, or `nohup` file-redirection wrapper before restarting.
A redirected file descriptor cannot follow application-managed renames, and an
external writer can bypass these bounds. Use the shipped
[user service example](konsensus.service), which sends stdout and stderr to the
journal. Upgrading the binary cannot change an existing supervisor's redirection.
On Unix, startup detects stdout or stderr pointing at the same inode/device as
`node.log`, skips the node file writer, and emits one warning on stdout to remove
the launcher redirect. Logging continues on stdout; the redirected file remains
unbounded until the launcher is fixed. This check cannot detect a downstream `tee`.
Other CLI commands continue to log only to stdout.

Journald retention is configured separately by the host administrator. For example,
`/etc/systemd/journald.conf.d/size.conf` may contain:

```ini
[Journal]
SystemMaxUse=100M
SystemMaxFileSize=10M
SystemMaxFiles=10
RuntimeMaxUse=50M
RuntimeMaxFileSize=10M
RuntimeMaxFiles=5
```

These journal bounds cover all services on the host. The node does not modify
host logging policy or rotate the append-only security audit log.

Existing diagnostic fields, backend-error redaction, and LDK level filtering are
preserved (including Warn-only LDK logging when LSPS2 is enabled). The plaintext
guard rejects forbidden structured content before either node output formats it.
Never add mnemonics, passwords, tokens, payable private invoices, or message
plaintext to log events. Rotation is retention control, not secret redaction.

Regression tests cover actual file rotation, strict total bounds, oversized
writes, concurrent clones, restart with legacy logs, old/partial configurations,
LDK invoice filtering, and plaintext rejection in a subprocess.
