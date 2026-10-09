# CLN (preview)

BitSov connects to an existing Core Lightning node through clnrest. The preview
supports invoice creation, settlement lookup, payment history, channel listing
and balances, with startup checks for version and Bitcoin network.
**Outgoing invoice payments and keysend still refuse before dispatch.** Payment
capability and money readiness remain false until fee-capped sending is available.
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

Provision a restricted rune permitting only `getinfo`, `invoice`, `listinvoices`,
`listpays`, `listpeerchannels` and `listfunds` for this preview. Save it
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
