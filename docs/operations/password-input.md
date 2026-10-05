# Passing a seed password from a launcher

`konsensus init --password-fd <n>` encrypts the new recovery phrase without
putting the password in argv, environment variables, or a plaintext file.
`konsensus start --password-fd <n>` unlocks that encrypted seed. Descriptor `0`
selects stdin; other inherited descriptors are supported on Unix (including
macOS). On other platforms only `0` is supported.

For a Keychain-backed Mac launcher:

1. Retrieve the password into protected memory in the launcher.
2. Spawn `konsensus init --dir <dir> --non-interactive --tier full --password-fd 0`
   with piped stdin. On later launches, spawn
   `konsensus start --config <dir>/konsensus.toml --password-fd 0`.
3. Write the UTF-8 password to the child's stdin, then **close the write end**.
   Do this for each invocation; the node reads to EOF once and never retries or
   caches the password. Do not also put it in arguments, environment, or logs.
4. Erase the launcher's password buffer after writing it.

A dedicated inherited pipe is also supported: arrange for its read end to be
open as descriptor 3 in the child (clear close-on-exec), then use
`--password-fd 3`. Close unused pipe ends, especially all copies of the write
end, so the child receives EOF. The node borrows the supplied descriptor,
advances it to EOF, and closes its own duplicate; it does not close the original.

The input is a nonempty UTF-8 password, at most **4096 bytes**, including any
line ending. Trailing CR and LF bytes are removed; spaces and interior newlines
are preserved. Empty, invalid UTF-8, oversized, unreadable, and closed-descriptor
inputs fail without a prompt or a fallback to plaintext initialization. An open
pipe whose writer has not closed will wait for EOF. Use `--non-interactive` for
unattended init so its backup ceremony does not also consume stdin.

`start` rejects combinations of `--password-fd`, `--password`, and
`--password-file`. `init --password-fd` implies encryption and conflicts with
`--encrypt` (including its interactive form); omit `--encrypt` entirely.
The legacy `init --encrypt <password>` and `start --password <password>` forms
still work, but expose the secret in process arguments.

The node reads into a bounded zeroizing buffer, never prints the supplied bytes,
and zeroizes the owned password after encryption or startup's last password use,
including on ordinary errors and cancellation. OS pipe buffers and the sender's
memory remain the sender/OS's responsibility; abrupt process termination cannot
run Rust destructors.

Descriptor input is **non-interactive**: Touch ID device approvals remain off
with `seed_password_not_typed`, just as with `--password-file`. This handoff does
not change owner-channel authority or implement Keychain access in the node.
It applies to CLI init/start; bootstrap HTTP identity creation is unchanged.
