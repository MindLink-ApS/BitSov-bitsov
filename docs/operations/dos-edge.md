# Protecting the unpaid peer doorway

The peer TCP listener (9736 by default) applies admission limits before Noise or
payment validation. They apply in both `whitelist` and `price_open` modes. Payment
and federation authorization are unchanged: a cookie proves return routability,
not identity, payment, or permission to receive service.

## Configuration

Existing configurations get these defaults when the fields are omitted. Put
`cookie_mode` at the top level, before TOML table headers:

```toml
cookie_mode = "adaptive"

[dos_edge]
connections_per_second = 10.0
connection_burst = 40
handshakes_per_second = 2.0
handshake_burst = 8
max_pending = 128
max_handshakes = 64
max_per_ip = 4
max_per_subnet = 8
cookie_threshold = 32
max_tracked_sources = 4096
cookie_timeout_secs = 3
handshake_timeout_secs = 10
```

Connection and handshake token buckets are independent. Each is enforced on the
socket's exact source IP and, for IPv6, its /64. IPv4-mapped IPv6 addresses are
canonicalized, so they cannot obtain a second IPv4 allowance. IPv4 neighbors have
separate allowances; the old /24 aggregation has been removed. Source ports and
claimed identities never affect these budgets. Rejected attempts do not refill
budgets or extend their debt. A shared NAT or IPv6 /64 shares its budget.

`max_pending` caps accepted tasks, including cookie exchanges, Noise and federation.
`max_per_ip` and `max_per_subnet` bound these tasks for each source. `max_handshakes`
separately caps simultaneous Noise/federation work. All permits are released on
success, error, timeout, cancellation, or listener shutdown. Completed task records
are reaped; there is no queue of waiters for handshake permits.

`adaptive` allows at most `cookie_threshold` optimistic handshakes. Once those slots
are occupied, further sources must return a cookie. Connection rate/concurrency
refusals also activate cookies for one second, extended by further refusals.
With the defaults, unverified optimistic callers can occupy only 32 of the 64
handshake slots. `required` always demands a cookie. `disabled` preserves the old
cookie-free protocol, but removes the cookie reservation; other limits remain.
Cookie-aware peers retry transparently on the same TCP connection. Older peers
that cannot answer a cookie challenge cannot connect while cookies are required.

The cookie is the existing `BSc1` fixed-size HMAC challenge, bound to the full source
IP and a 30-second epoch. Current and previous epochs are accepted (less than
60 seconds total validity); a restart changes the secret and invalidates old
cookies. It requires no stored challenge or proof-of-work. A cookie can be reused
by its source during validity, so it never bypasses rate or concurrency limits.

## Memory and fairness

No Noise session, DH computation, or peer registration occurs before a required
cookie verifies. The cookie MAC is stateless. TCP itself is **not** stateless:
the kernel socket, bounded task, and small framing buffers exist before verification.
The listener bounds those separately rather than claiming TCP has WireGuard's UDP
allocation behavior. Pre-cookie payloads are at most 64 bytes; inbound Noise
message 1 and 3 are capped at 32 and 64 bytes, and federation frames at 4096 bytes.
Cookie exchanges have a 3-second deadline and the complete inbound handshake has
one 10-second deadline, which cannot be renewed by trickling bytes between phases.

Each of the four rate tables holds at most `max_tracked_sources` entries. Full
tables drop only fully replenished entries, scanning at most once per second.
New sources are refused while all entries carry active debt; IP churn cannot
reset a throttled source's budget. Per-source concurrency maps contain only active
tasks and remove entries at zero. Thus the pre-admission edge has fixed configured
bounds even during an address-rotation or slow-client flood. Successful authenticated
connections leave the edge and remain subject to the transport's existing peer and
payment lifecycle; these bounds are not a cap on established peer storage.

Established paying connections do not spend these new-connection budgets and are
not evicted by the edge. A single abusive IPv4 source cannot consume another
IPv4 source's allowance. Honest cookie responders can use capacity unavailable to
optimistic callers. However, payment is not identifiable before Noise, and a
cookie is not proof of payment: no finite application limiter can guarantee a new
paying peer admission against an unlimited distributed flood, a saturated uplink,
or an attacker sharing its NAT or /64. Keep established sessions alive, let
reconnect backoff run, and retain upstream firewall/SYN-flood protection. This edge
does not replace kernel TCP backlog or bandwidth defenses.

For a shared network with many legitimate nodes, raise per-source bursts/caps
carefully while retaining cookie-reserved capacity. Validation rejects zero,
non-finite or excessive limits, an empty reservation, and inconsistent deadlines.
Partial `[dos_edge]` tables inherit defaults; unknown keys fail configuration parsing.
Normal refusals are debug-level to avoid warning-log amplification during floods.

## Verification

```sh
cargo test -p konsensus-message -p konsensus-node
cargo clippy -p konsensus-message -p konsensus-node --all-targets -- -D warnings
```

The tests cover cookie round trips and invalid cookies, automatic activation,
honest connections with slow optimistic handshakes outstanding, source flooding
before Noise, the global Noise cap even with valid cookies, bounded pending
sockets and limiter tables, IPv6 aggregation, mapped IPv4 addresses, timeout and
shutdown cleanup, and configuration validation.
