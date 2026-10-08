# CLN (preview)

BitSov can connect to an existing Core Lightning node through clnrest. This
preview checks connectivity, the node public key, version and Bitcoin network.
**Payments, invoices, settlement lookup and balances are not implemented yet.**
A reachable CLN backend still reports payment capability and money readiness as
false. Unsupported operations retain the Lightning trait's fail-closed defaults;
no funds are moved by this preview.

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
connection/request timeouts. It sends `POST /v1/getinfo` with an empty JSON object
and the rune only in the sensitive `Rune:` header. No inline rune config field
is accepted. Debug output redacts credentials; errors omit response bodies.

Provision a restricted rune permitting only `getinfo` for this preview. Save it
directly into the private file; do not put its value in shell arguments, URLs,
TOML, logs or source control. Set the file mode with `chmod 600` before starting.
Mount only the CA certificate and rune file, not CLN's full data directory or
`hsm_secret`. CLN owns the wallet and its backups; a BitSov mnemonic does not
recover CLN funds. Tower clients require LDK, and settlement verification cannot
be disabled for this backend.

See upstream [clnrest](https://docs.corelightning.org/docs/rest) and
[getinfo](https://docs.corelightning.org/reference/getinfo) documentation. Local
provider tests use rustls and public test certificates, without lightningd.
