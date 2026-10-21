# Local API Host and Origin checks

Loopback TCP is not proof that a request came from a trusted local application:
web browsers can connect to loopback after resolving an attacker-controlled DNS
name. The local token mint and routes using the shared local-connection guard
(WebSocket admission, energy, and membrane reads) therefore also validate HTTP
request headers before granting local trust.

The allowed `Host` values are `localhost`, `127.0.0.1`, and `[::1]`, each with the
API listener's port, plus the concrete IP address configured by `api.listen_addr`
with that port. When the listener port is 80, these same authorities may also
omit the port in `Host` and HTTP `Origin`; other listener ports require an
explicit port. Wildcard bind addresses (`0.0.0.0` and `[::]`) are not additional
trusted hosts. IPv6 addresses require brackets. Host names are case-insensitive;
missing, duplicate, malformed, and unlisted hosts are refused. Forwarded headers
never extend this allowlist.

An absent `Origin` is accepted, preserving curl and the desktop app's native host
process. When present, the origin must be an HTTP origin for an allowed API
host/port, or an exact entry in the CORS origin allowlist when CORS is enabled.
The latter uses `KONSENSUS_CORS_ALLOWED_ORIGINS` (the existing defaults are
`http://localhost:1420`, `http://127.0.0.1:1420`, `http://localhost:4173`, and
`http://127.0.0.1:4173`). Only configure origins whose browser code you trust.
Opaque `null`, duplicate, malformed, and foreign origins are refused. CORS
response headers alone do not enforce this admission check.

Header refusals return HTTP 403 with JSON `code: "local_host_forbidden"` or
`code: "local_origin_forbidden"` and an explanatory `error`. Rejected requests do
not mint a token or consume the local token issuance quota. Peer-IP checks,
JWT scope restrictions, pairing requirements, and rate limits still apply.

Embedders serving the router themselves must use `build_router_for_addr` with
the actual listener address (including its assigned port when binding port zero).
`build_router` uses the default `127.0.0.1:3141`; the production `serve` entry point
supplies the actual bound address automatically.
