# CLN (preview)

BitSov connects to an existing Core Lightning node through clnrest. The preview
supports invoice creation, settlement lookup, payment history, channel listing
and balances, plus fee-capped invoice payments and keysend. Startup checks the
Bitcoin network, requires CLN >= v24.11, and discovers `xpay` using `help`.
A missing/disabled `xpay`, unreadable command list or older version fails startup
with `not_supported`. Existing preview runes must add `help` and the payment
methods before upgrading. Payment readiness requires a healthy, synchronized node
and no detected fee-ceiling violation.
Stateless quotes, hold invoices, inbound keysend TLV watching, channel management
and on-chain sends retain the Lightning trait's unsupported defaults.

## Receive and read operations

| Operation | CLN RPC and interpretation |
| --- | --- |
| Create invoice | `invoice` with numeric `amount_msat`, a fresh random 128-bit `bitsov:` label, `description` and `expiry`. The returned `expires_at` is represented as `created_at + expiry_secs`. |
| Settlement | `listinvoices payment_hash=…` first; only an empty result falls back to `listpays payment_hash=…`. Errors never masquerade as missing payments. Self-payments therefore resolve as incoming. |
| Lightning balance | Sum `spendable_msat` for `CHANNELD_NORMAL` channels, including disconnected peers; this is capacity, not a promise of immediate routability. |
| Channels | `listpeerchannels`: capacity from `total_msat`, local balance from `to_us_msat`, remote balance from their difference. Active requires normal state and a connected peer. Unfunded negotiations without a channel ID are omitted. |
| Wallet breakdown | `listfunds`: unspent outputs (confirmed, unconfirmed and immature) for total. Lightning capacity is rounded down to sats. On-chain spendable, anchor reserve, closing and contested categories remain unknown (`None`): output reservations do not reveal CLN’s emergency/anchor reserve. |
| Payment history | Page forward through `listinvoices` and `listpays` with `index=created` and bounded `limit`; merge newest timestamps first and apply the requested limit. Refresh outgoing records by hash before ranking to obtain canonical timestamps and full multipart totals. |

Paid incoming invoices use **`amount_received_msat`**, including overpayments,
and `payment_preimage`. Unpaid invoices are pending, expired invoices are expired;
outgoing complete/pending/failed records map to settled/in-flight/failed. Only
settled records expose a preimage. CLN's built-in keysend receiver creates an
invoice, so keysend receipts use this same settlement path, even without a fixed
invoice amount. The payment gate still verifies incoming direction, echoed hash,
preimage and both the claimed amount and required price.

History uses invoice `paid_at` when present, otherwise the BOLT11 creation time
(or zero when CLN supplies neither); outgoing entries use `created_at`. A
self-payment can appear in history once in each direction. Reads cover the
node's history, including payments made outside BitSov. History scanning and
outgoing hash lookups cost more on large nodes; an overall timeout returns an error rather than partial
history. Malformed responses, unknown statuses and arithmetic overflow fail
closed. Complete outgoing records without a known amount fail explicitly because
the shared payment type cannot express an unknown amount. External retries of a
hash resolve to a complete attempt first, otherwise a pending attempt, otherwise
the newest failure. No failed read is converted to a zero balance. Responses are
bounded to 64 KiB for `getinfo` and 4 MiB for receive/read RPCs.

## Fee-capped outgoing payments

`pay_invoice` and `pay_invoice_with_fee_limit` parse BOLT11 locally and reject
amountless invoices before dispatch. The effective ceiling is
`routing_fees.ceiling(amount, caller_limit)`: a caller may tighten the policy,
including to zero, but cannot widen it. BitSov always sends a numeric `maxfee`
and `retry_for: 60` to `xpay`; it never falls back to `pay` or relies on CLN's
fee defaults. This path accepts BOLT11 only, not BOLT12, offers or BIP353 names.

Before `xpay`, a mutex protects the local attempt set and a server-side
`listpays payment_hash=…` lookup must return an empty list. Any record (failed,
pending or complete), an unreadable lookup or a locally used hash refuses with
`PaymentNotDispatched`. The hash is inserted **before** POST and retained after
success, errors and cancellation. The lock is released before the payment RPC
so unrelated payments can proceed. After restart, CLN's records supply the
freshness check. This is not an atomic reservation across multiple BitSov
processes or other applications: use a single dispatcher for an invoice hash.

Keysend prefers `xkeysend` on CLN >= v26.06 when discovered, otherwise uses
`keysend` with `maxfee` on CLN >= v24.11. If neither is available it refuses before
dispatch. Both use the same policy ceiling, with no `maxfeepercent` or
`exemptfee`. CLN generates the random preimage. BitSov derives the hash from the
returned preimage (`xpay`/`xkeysend` omit the hash), verifies any echoed hash and
checks it against BOLT11 for invoice payments. Keysend memo text is local to the
returned payment details; it is not delivered as a TLV or persisted by CLN.

The HTTP request timeout is 10 seconds, while CLN can continue routing for 60
seconds or hold HTLCs longer. **Timeouts, 5xx, other HTTP errors and malformed
replies after POST are ambiguous backend errors, never `PaymentNotDispatched`.**
Reconcile invoices using `get_payment_status(hash)`; do not resubmit the same
invoice. For a lost keysend reply, the caller has no preselected hash: reconcile
CLN's outgoing history/operator records before authorizing a new send. BitSov
does not retry or switch keysend methods after POST. A mocked rune/route refusal
tests this conservative classification; it does not prove node-side enforcement.

A successful reply supplies the actual principal and `amount_sent_msat`.
If their difference exceeds the effective cap, BitSov emits an error alert
without secrets and latches `payment_capable`/`money_ready` false. It returns the
actual settlement and fee because the funds have already moved. New sends then
refuse; health checks and later successful replies cannot clear the latch.
Investigate the node before restarting. Invalid amounts, preimages and hashes
never produce a claimed settlement. CLN sync warnings suppress readiness and
new sends while receive/read operations remain available.

## Restricted payment rune

Allow only `getinfo`, `help`, `invoice`, `listinvoices`, `listpays`,
`listpeerchannels`, `listfunds`, `xpay`, `xkeysend` and `keysend`. Do not allow
`withdraw`, channel management or rune creation through this credential.
Add a separate conditional numeric fee restriction for **each** payment method.
For the default absolute policy maximum of 10,000 msat, the restrictions array is:

```json
[
  ["method=getinfo", "method=help", "method=invoice", "method=listinvoices", "method=listpays", "method=listpeerchannels", "method=listfunds", "method=xpay", "method=xkeysend", "method=keysend"],
  ["method/xpay", "pnamemaxfee<10001"],
  ["method/xkeysend", "pnamemaxfee<10001"],
  ["method/keysend", "pnamemaxfee<10001"]
]
```

Use the configured `routing_fees.maximum_msat + 1` instead of `10001` for a
different maximum. Inner alternatives are OR; outer restrictions are AND.
Numeric restrictions are defense in depth, independent of the per-payment client
ceiling. The [manual real-node regtest](regtest-e2e.md#real-cln-release-regtest-t5-t7-t8-t9)
exercises these restrictions; successful runs on both pinned releases are still
required as release evidence. Before production use, verify absent `maxfee`, an
over-limit numeric `maxfee`, and `withdraw` are rejected by the installed CLN release (T9). A rune
fee restriction is not a principal-spend budget; BitSov's spend grants still apply.

## Configuration reference

```toml
[lightning]
backend = "cln"
rest_url = "https://localhost:2107"
ca_cert_path = "/cln/ca.pem"
rune_file = "/secrets/bitsov.rune"
network = "bitcoin"
minimum_version = "v24.11"        # optional; default and lowest allowed minimum
# resolve_ip = "10.21.21.96"     # optional DNS override; TLS still checks URL host
```

| Field | Meaning |
| --- | --- |
| `rest_url` | Required HTTPS origin of clnrest. No userinfo, path other than `/`, query or fragment. HTTP is refused even on loopback. |
| `ca_cert_path` | Required path to the CLN CA certificate in PEM format. This is the sole trust anchor; public/system CA roots are disabled. |
| `rune_file` | Required path to a regular file with Unix mode exactly `0600`. Contains one rune, optionally followed by a newline. Read once at startup; restart BitSov after rotating it. Platforms without Unix mode verification are refused. |
| `network` | Required exact `getinfo.network` value: `bitcoin`, `testnet`, `signet` or `regtest`. A mismatch fails startup and subsequent health checks. |
| `minimum_version` | Optional stable CLN release floor, default `v24.11`. May raise but never lower this minimum. Malformed and prerelease versions are refused. Release-derived git-describe versions are accepted. |
| `resolve_ip` | Optional IPv4/IPv6 address for dialing the URL hostname without changing TLS hostname verification. |

Use the hostname in the CLN certificate's SAN, and obtain `ca.pem` from the CLN
installation through a trusted channel. Do not disable certificate verification.
The client refuses redirects, ignores proxy environment settings, and bounds
connection/request timeouts. It sends named JSON parameters to `POST /v1/<method>`
and the rune only in the sensitive `Rune:` header. No inline rune config field
is accepted. Debug output redacts credentials; errors omit response bodies.

Provision the restricted rune described above through the CLN operator interface. Save it
directly into the private file; do not put its value in shell arguments, URLs,
TOML, logs or source control. Set the file mode with `chmod 600` before starting.
Mount only the CA certificate and rune file, not CLN's full data directory or
`hsm_secret`. CLN owns the wallet and its backups; a BitSov mnemonic does not
recover CLN funds. Tower clients require LDK, and settlement verification cannot
be disabled for this backend.

See upstream [clnrest](https://docs.corelightning.org/docs/rest) and
[getinfo](https://docs.corelightning.org/reference/getinfo) documentation. Local
provider tests use a mocked clnrest server over rustls with public test certificates.
T3 covers invoice/payment status mappings and overpayment; T6 exercises the real
payment gate against mocked keysend receipts, forged proofs and underpayment.
These tests do not replace LDK-to-CLN regtest with real HTLC settlement.

RPC references: [invoice](https://docs.corelightning.org/reference/invoice),
[listinvoices](https://docs.corelightning.org/reference/listinvoices),
[listpays](https://docs.corelightning.org/reference/listpays),
[listpeerchannels](https://docs.corelightning.org/reference/listpeerchannels),
[listfunds](https://docs.corelightning.org/reference/listfunds).

Payment RPC references: [xpay](https://docs.corelightning.org/reference/xpay),
[xkeysend](https://docs.corelightning.org/reference/xkeysend),
[keysend](https://docs.corelightning.org/reference/keysend),
[help](https://docs.corelightning.org/reference/help) and
[createrune](https://docs.corelightning.org/reference/createrune).

PR3 tests in `crates/konsensus-lightning/tests/cln_fee_limits.rs` cover request
ceilings, discovery, duplicate/cancelled attempts, ambiguous errors, response
validation and the sticky overspend latch over local TLS. The ignored
[real CLN regtest](regtest-e2e.md#real-cln-release-regtest-t5-t7-t8-t9) provisions
CLN and LDK for keysend/reply (T7), high-fee-hop refusal with no settled HTLC or
debit (T8), and rune enforcement (T9). Its manual workflow must pass on both
pinned releases before these behaviors are considered verified against real CLN.
