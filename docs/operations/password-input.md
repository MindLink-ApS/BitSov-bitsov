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

Descriptor input alone is **non-interactive**: Touch ID device approvals remain
off with `seed_password_not_typed`, just as with `--password-file`. The explicit
explicit local-owner exception is described below. The node does not implement Keychain
access.

For an initialized local node with a first-run or console-enrolled owner device,
start with `--password-fd 0 --local-owner-device` to enable device-signed,
recipient-bound spend envelopes. This flag is required on every start; it is
not a config setting. It requires `--password-fd` or `--remote-unlock` and conflicts with
`--password`, `--password-file`, and `--owner-control`.

The seed must be encrypted with no sibling `mnemonic.txt`. At startup the node
derives owner authority from the seed and password, then drops the password.
Only local-owner mode retains the owner signing key in zeroizing memory for
[device delegation](../security/device-keys.md#delegating-another-owner-device). No owner public key is trusted from disk.
Console-enrolled device records work unchanged; their owner signatures are
verified on every intent. A restart without the flag disables descriptor-based
device approval again (`seed_password_not_typed`) and honours no spend grants.

This mode opens no control socket. Later enrollment requires an existing owner
device signature over the pending delegation tuple. Console grants, elevation,
front-door, identity replacement, pairing-window control and first-contact
approval retain their console-only rules. Only live `device:` grants with
`recipients_only` budgets supply spend scope and spending authority; `cli`
grants on disk remain inactive. Caps and dispatch deadlines still apply.
On a positively empty directory, `--password-fd` retains the password in
zeroizing memory for encrypted bootstrap. Adding `--local-owner-device` enables
first-run owner enrollment: create a pending identity, record the phrase once,
and finalize with three backup words and the device's P-256 possession proof.
The password is never an HTTP field. Empty passwords are rejected before serving.
Without the enrollment flag, encrypted two-phase creation is available without
a device. Legacy HTTP create/restore also write `identity/mnemonic.enc` whenever
a startup password is supplied (including flag/file passwords, which still
confer no local owner authority). With no password they retain plaintext behavior.
After finalize the process exits; the launcher restarts explicitly with the same
password and flag. Device delegation remains separate work.
See [the ceremony and crash rules](../security/pairing.md#two-phase-local-bootstrap).

The launcher must protect its Keychain password: anyone with that password and
the seed can derive the owner signing key. Release of the Mac launcher requires
Developer ID signing and hardened runtime; an unsigned build must label the
badge **local owner (unsigned app)**. The node cannot attest that a registered
P-256 key lives in Secure Enclave hardware.

Persisted spend grants remain trusted state: the `device:` provenance prefix
and budget fields are not signed grants. A writer of `pairing/clients.json` can
forge those fields. Owner signatures protect device registration records, not
the grant ledger; this mode retains that existing account-layer limitation.

## Remote unlock after reboot

For an initialized home node with an encrypted seed, start with
`--remote-unlock --local-owner-device`. The node waits for an already paired,
owner-approved device over the box-static Noise tunnel. It accepts no password
flag, file, descriptor, or owner console in this mode. The password is held in
zeroizing memory only, never logged, returned, or written to disk, and handed to
the normal startup path after device possession, seed decryption, owner approval,
and the saved node identity all verify. A failed unlock leaves the node locked.
Do not provide a systemd credential containing the seed password.

`--remote-unlock` alone unlocks receiving but keeps device spend approvals off
(`seed_password_not_typed`). Add `--local-owner-device` on each start to enable
existing owner-approved device intents. Neither switch is a configuration key.
The mode rejects plaintext seeds and uninitialized data directories; remote
first-run bootstrap is not part of this release. See [home-node.md](home-node.md)
for migration, listener behavior, and the Lightning risk while locked.

Remote unlock uses zeroizing buffers for tunnel decryption, the collected request,
JSON password decoding and the password handoff, including errors and cancellation.
This does not guarantee erasure of library-owned HTTP read buffers, kernel socket
buffers, compiler temporaries, or memory after abrupt process termination. The
in-process loopback bridge is part of the trusted local process/OS boundary.
