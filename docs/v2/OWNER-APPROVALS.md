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

## Headless approvals (systemd / no controlling terminal)

Start the node with `--owner-control`. A paired client's spend, front-door, or
device-key registration request creates a pending operation, never authority.
If the node cannot write to `/dev/tty`, it writes the approval instructions to
`<data_dir>/pairing/owner-approval-<op_id>` (`0600` in a `0700` directory).
The journal contains only that path and expiry; the path includes the `op_id`.
Do not copy the code into logs, shell arguments, or a journal-captured command.

1. Read the `op_id` from the journal path, or run
   `konsensus pair-status --config /path/to/konsensus.toml` as the owner to find it.
2. Read the matching protected file privately, for example in an editor over an
   owner SSH session. Check its operation id and expiry.
3. Run `konsensus grant --op <op_id> --config /path/to/konsensus.toml`, supplying
   budget flags when the client proposed none. Review the displayed terms and
   type the short code (or full `GRANT … CODE` line) at the prompt. For device
   registration, run `konsensus device approve --op <op_id> --config
   /path/to/konsensus.toml` and review the device fingerprint before entering its
   code. Device approval also requires the encrypted recovery phrase.

Both commands send approval only through `control.sock`; neither `pair-status` nor
socket descriptions return codes. Successful approval removes the file. Withdrawal,
wrong-code cancellation, expiry (within the one-second cleanup sweep), and clean
shutdown also remove it. Restart removes stale files and reissues codes for
unexpired pending requests; read the new file, since the old code is invalid.

Without owner-run mode, or if both the terminal and protected-file delivery are
unavailable, `POST /api/v1/pair/elevation-request` returns HTTP 409 with
`owner_approval_unavailable`; no pending operation is created. Device-key
registration on an owner-run node returns the same 409 if neither delivery
channel is available.

The file fallback trusts the node's OS user: an app with the same file access
can read and submit the code. Use an owner-managed account/data directory outside
the paired app's control. Terminal-delivered codes remain off disk. Device-key
registration uses the same protected-file fallback. Identity replacement still
requires the node's terminal and returns HTTP 409 `owner_approval_unavailable`
when terminal delivery fails, without creating a pending operation. Startup
warns and skips unavailable approvals, continuing with the remaining requests.

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

---

# Owner device approvals (v1)

`owner_device_approval_v1` in `/api/v1/status` advertises support for
`spend_grant` and `first_contact`. This is the node portion of the feature;
apps must implement display, biometric signing, discovery and continuation.
Older apps and the existing owner console continue to work.

A paired client, including an AI or read-only client, may **request** an
approval. A request grants nothing. Approval requires a **different pairing**
with an enrolled owner-approved P-256 device key at its current epoch, its own
paired token, and its own matching authenticated Noise session. Possession of
a token, a requester signature, or a claimed biometric result is insufficient.
`intent_key` re-verifies the enrolled key's seed-derived owner attestation for
this node. Unknown, revoked, forged and old-epoch keys cannot approve.
Even an enrolled owner device cannot approve its own pairing's request.

The node must be running with `--owner-control` or `--local-owner-device`
(including `--home`), with device approvals enabled. Capability advertisement
indicates protocol support, not that device authority is currently enabled.
Consult the existing `device_approvals` readiness signal before offering approval.

## Request and discover

All paths below are relative to `/api/v1`. Use a paired read token.

```http
POST /pair/approval-request
{"kind":"spend_grant","terms":{"budget_msat":100000,"per_call_max_msat":10000,"window_secs":600}}
```

Spend terms use the console's normalized budget/per-call/window limits and
conservative default circuit breakers. An optional `recipient` is a 64-hex
node id; when present, that recipient is the exclusive payee and its cap is
the total budget. This version cannot customize breakers, authorize liquidity
fees, grant other scopes, or specify multiple recipients.

```http
POST /pair/approval-request
{"kind":"first_contact","terms":{"recipient":"<64-hex node id>","max_total_msat":1000,"budget_msat":50000}}
```

First contact requires a current live spend grant. `max_total_msat` is
1–100,000 msat. Optional `budget_msat` means the console's contact budget:
a persistent recipient cap covering this payment, no larger than the total
budget and equal to an existing recipient cap, if any. First-contact approval
uses the same per-call, remaining-total and remaining-recipient checks as the
console, rechecked at approval time. It does not itself debit money. Compose
consumes its authorization once and still reserves against the live budget.
The device-issued first-contact grant lasts at most **120 seconds**, and never
past the spend window. The console's existing lifetime is unchanged.

Both request bodies reject unknown fields. Client identity, epoch, node,
live `grant_op`, nonce and operation id come exclusively from node state.
The response includes `op_id`, `expires_at`, `approval_message`, `owner_action`,
`status` and the structured operation. After a spend grant is approved, the
requester must refresh its paired token to obtain the new spend scope before
sending; approval does not widen a previously issued read/receive token. Requests expire after five minutes;
restart discards all pending operations. Limits: three unconsumed live requests
and 30 requests per hour per pairing, plus a node-wide bound of 1,024 live
operation records. Consumed records remain readable until expiry/cleanup.

`GET /pair/approval/{op_id}` is restricted to the requesting pairing and epoch.
`GET /pair/approvals/pending?approver_key_id=<key>` requires the owner's token
and matching Noise session and returns `{"pending":[...]}` with exact messages.
Discovery excludes the approver's own requests. `konsensus pair-status` also
lists pending operations, without granting authority.

## Exact bytes to display and sign

The owner app displays and signs the **node-returned** message from discovery,
not text supplied by the requester. UTF-8, no trailing newline:

```text
bitsov-owner-approval-v1
node:{fingerprint}
kind:{spend_grant|first_contact}
client:{requesting client id}
client_pubkey:{requesting pairing public key}
epoch:{requesting pairing epoch}
grant_op:{current live grant op or -}
recipient:{canonical node id or -}
max_total_msat:{maximum first-contact payment or spend total}
budget_msat:{spend total or optional contact budget or -}
per_call_max_msat:{spend per-call cap or -}
window_secs:{spend window or -}
op_id:{server operation id}
nonce:{server 16-byte hex nonce}
expires_at:{absolute approval deadline in Unix seconds}
```

The deadline is signed as well as enforced by both wall time and elapsed time.
The first-contact authorization's separate 120-second lifetime begins when
approved. All numeric values are decimal integers; recipients are lowercase.

```http
POST /pair/approval/{op_id}/approve
{"approver_key_id":"<owner key id>","signature":"<hex DER P-256/SHA-256 signature>"}
```

This route and owner discovery are exposed only on the unlocked remote router.
Requests and own status are also available locally. Approval checks mode,
`intent_key`, expiry, consumption, distinct pairing, requester/node bindings,
signature and the live grant snapshot while holding the pairing mutex.
A replacement/expired grant invalidates the request. Verification, grant write
and single-use consumption cannot race revocation or another approval. Failed
persistence restores the previous grant and leaves the operation unconsumed.
Approval attempts are limited to 30 per hour per enrolled key, including failed
signatures; rate refusals are HTTP 429. Signature/self/binding refusals are 403,
expired operations 409, unknown operations 404; budget failures retain the
console path's `BudgetRefusal` API representation.

Spend grants record `granted_by: device:<key>` and persist the exact operation,
owner-attested device key and signature. The node verifies that evidence and
the immutable grant bounds before using these grants, including in home mode
and after restart. Revocation/epoch checks apply when approving: revoking the
approver later does not retroactively revoke another pairing's completed grant.
Revoke the requesting pairing or its grant to end that authority. First-contact evidence is memory-only with its one-use
authorization, so restart drops it. These receipts do not make the entire
mutable accounting ledger tamper-proof or change the trust model of older
console grants and relation envelopes.

Audit events `pair.owner_approved` and `pair.owner_approval_refused` contain the
approver key id, operation id and kind. They never contain signatures, tokens,
nonce, recovery phrase or other secret material. Invalid transport reaching
the handler is also audited; authentication/malformed-body middleware may
reject a request before the handler runs.

## Boundaries and fallback

Breaker reset is **not** part of v1 PR A; `breaker_reset` is rejected. Identity
replacement, recovery/restore, revoking/opening windows for other pairings,
revoking other device keys, and first-owner enrollment without bootstrap stay
on their existing console/root-of-trust paths. No approval route enables them.

Without the capability or enabled device authority, use the existing console
workflow. Console requests/codes are independent; device requests never expose,
consume or bypass those codes. To approve from the console, use the existing
elevation/first-contact workflow rather than a device-approval operation id.
