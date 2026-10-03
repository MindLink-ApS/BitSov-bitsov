# Owner approvals from the local CLI

The app hands off two decisions to the node owner. Run these commands in the
owner's terminal on the machine running the node. Each prints the complete
approval tuple before submitting it and exits nonzero if the node refuses it.
The explicit arguments are the approval: there is no additional yes/no prompt.

Both commands reject control characters, Unicode bidi controls, and invisible
formatting controls (U+061C, U+200B–U+200F, U+202A–U+202E, U+2066–U+2069, and
U+FEFF) anywhere in string arguments, including in `--config`, and reject
leading or trailing whitespace. Values are never
silently trimmed. Summary strings are quoted and escaped (for example, a literal
backslash is displayed as `\\`); the control socket receives the original values.
Parse errors for these string/path fields also escape rejected values so they
cannot alter terminal output. Socket connection errors quote and escape paths.

Start the owner-managed node with its existing configuration:

```sh
konsensus start --config /path/to/konsensus.toml --owner-control
```

Both commands use the existing Unix control socket next to that configuration
(`control.sock`, mode `0600`). Add `--config /path/to/konsensus.toml` to either
command when not running from the node's data directory. The default is
`./konsensus.toml`. There is no HTTP fallback, token argument, or owner credential
returned to the app. Unix is required. A packaged app sidecar does not enable
this socket. Keep the owner node and terminal outside the paired app's control;
the socket is not a security boundary against a process running as the owner OS
user. Spend elevation requires a separate owner code, delivered to the node's
terminal or a protected file when headless. Identity replacement still requires
its owner-terminal confirmation.

## Headless spend elevation (systemd / no controlling terminal)

Start the node with `--owner-control`. A paired client's spend or front-door
request creates a pending operation, never a grant. If the node cannot write to
`/dev/tty`, it writes the approval instructions to
`<data_dir>/pairing/owner-approval-<op_id>` (`0600` in a `0700` directory).
The journal contains only that path and expiry. Do not copy the code into logs,
shell arguments, or a journal-captured command.

1. Run `konsensus pair-status --config /path/to/konsensus.toml` as the owner to
   find the pending operation id.
2. Read the matching protected file privately, for example in an editor over an
   owner SSH session. Check its operation id and expiry.
3. Run `konsensus grant --op <op_id> --config /path/to/konsensus.toml`, supplying
   budget flags when the client proposed none. Review the displayed terms and
   type the short code (or full `GRANT … CODE` line) at the prompt.

`grant` sends approval only through `control.sock`; neither `pair-status` nor
socket descriptions return codes. Successful grant removes the file. Withdrawal,
wrong-code cancellation, expiry (within the one-second cleanup sweep), and clean
shutdown also remove it. Restart removes stale files and reissues codes for
unexpired pending requests; read the new file, since the old code is invalid.

Without owner-run mode, or if both the terminal and protected-file delivery are
unavailable, `POST /api/v1/pair/elevation-request` returns HTTP 409 with
`owner_approval_unavailable`; no pending operation is created.

The file fallback trusts the node's OS user: an app with the same file access
can read and submit the code. Use an owner-managed account/data directory outside
the paired app's control. Terminal-delivered codes remain off disk. Device-key
registration and identity replacement still require the node's terminal.

Doctrine: lines 1, 3, 5 and 6 hold. Local consent delivery does not settle a
payment or grant network admission; keys and bounded owner grants retain
authority, custody stays with the owner, and the access boundary is stated.

## First contact

```sh
konsensus approve first-contact --client <id> --op <grant_op_id> --to <recipient> --max-msat N [--contact-budget-msat M]
```

Copy the paired client id, its **current budget grant operation id**, the
recipient's 64-hex node key and the reviewed total first-contact ceiling. `N`
is in millisatoshis and covers admission plus the first message. The command
approves that ceiling; it does not fetch a quote or pay a message itself. The
app must still send within the approved cap. This command cannot create the
underlying spend grant.

The node requires that exact live client/grant binding and checks the ceiling
against its per-call, remaining total and existing recipient limits. Invalid,
revoked or replaced grants fail closed. `M`, if supplied, must cover `N`, fit the
grant's total budget and equal any existing cap for this recipient; it is never
silently clamped or ignored. When the contact has no cap yet, `M` establishes
one, allowing subsequent re-admission within that budget without a new prompt.
Omit it to leave the contact budget unchanged.

The authorization expires after at most two minutes, stays bound to this grant
and recipient, and is consumed once. A mismatched recipient cannot consume it;
a send replay cannot reuse it. Restart drops unused authorizations. Running the
owner command again is a fresh owner approval and replaces that client's unused
first-contact authorization; it does not reset any spending tally. A new quote
or renewed approval is needed when the old one expires.

## Sponsor gift

```sh
konsensus approve gift --intro <id> --newcomer <key> --hash <payment_hash> --gift-msat N --fee-max-msat F --code <6 digits>
```

Review the frozen candidate shown by the app and compare its six-digit code
with the newcomer. Supply the introduction id, newcomer node key, invoice hash,
exact gift amount and exact fee ceiling, all from that same candidate. Amounts
are in millisatoshis; preserve leading zeros in the code, for example `012345`.
Every field is required. The code must contain exactly six ASCII digits.

The node compares every field with the frozen funding intent before reserving
or paying. A mismatch leaves it awaiting approval and pays nothing. The same
sponsor policy, purse, fee and expiry checks apply as for owner HTTP approval.
Approval consumes the kit durably before dispatch: repeating the command cannot
pay it twice, including after restart. A reported `Unknown` state means the
outcome is uncertain and its purse reservation remains held; it is not a retry
instruction. Reconcile the existing kit before creating another one.

## App handoff and authority

The paired app may show or copy these command templates with the tuple filled
in, but must never execute the owner command, access the owner socket, or hold
an owner credential. Pass values as individual arguments if displaying them
through an integration; do not interpolate untrusted values into executable
shell text.

The existing HTTP boundaries remain enforced:

- Paired tokens calling `POST /api/v1/pair/first-contact-grant` receive **403**.
- A paired spend token calling `POST /api/v1/sponsor/approve` receives **409**
  (`sponsor_owner_approval_required`); a token without spend authority gets **403**.

These local commands do not add an app-callable approval route. See also
[F1 capped first contact](F1-CAPPED-FIRST-CONTACT.md) and
[K1 sponsor kit](K1-SPONSOR-KIT.md).
