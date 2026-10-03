# Remote app access over Noise

Status: node implementation, version 1.

This protocol gives a paired app remote access to the existing HTTP/WebSocket
API without exposing plaintext HTTP. It does not add a new authorization
system: the ordinary pairing JWT and scope checks remain authoritative.

## Configuration

Remote access is closed by default:

```toml
[remote_access]
# listen_addr = "0.0.0.0:8443"
# advertised_endpoint = "node.example:8443"
```

Setting `listen_addr` enables the public TCP listener and requires
`advertised_endpoint`. When enabled, `[api].listen_addr` must be loopback.
Startup refuses TCP port collisions with the API, BitSov P2P, or embedded
Lightning listener. The implementation also creates an ephemeral internal
Axum listener on `127.0.0.1:0`; plaintext HTTP is never bound non-loopback.

## Pairing link

If pairing is open when the listener starts, the node generates a random
256-bit, single-use code. The full link is written to
`<data_dir>/pairing/remote-access-link` at mode `0600`; stdout prints only its
protected path and expiry. The file contains:

```
bitsov://pair/<base64url-no-pad(JSON)>
```

The decoded JSON is:

```json
{
  "v": 1,
  "endpoint": "node.example:8443",
  "node_id": "<64 lowercase hex Ed25519 NodeId>",
  "transport_pubkey": "<64 lowercase hex X25519 static key>",
  "transport_signature": "<base64url-no-pad Ed25519 signature>",
  "code": "<base64url-no-pad 32 random bytes>"
}
```

`transport_signature` signs the exact UTF-8 string:

```
bitsov-remote-transport-v1:<node_id>:<transport_pubkey>
```

The app must verify this signature with `node_id`, pin both node keys from the
link, and refuse a Noise responder static that differs from
`transport_pubkey`. The node test suite verifies its side of the link; pinned
key refusal is also required in the app.

No link is created when pairing is closed. The server-side code is memory-only;
the complete link exists only in the protected file, never stdout or tracing.
It expires after five minutes. Successful pairing consumes it; a wrong code or
proof does not. The file is removed on success, expiry or clean shutdown.
Restarting replaces an unused code.

## Framing and Noise

The app opens TCP to `endpoint` and performs
`Noise_XX_25519_ChaChaPoly_BLAKE2s` as initiator using its own persistent
X25519 static key. The node uses its identity-derived X25519 key as responder.

Every Noise handshake message and every later ciphertext record is framed as:

```
u32 big-endian byte length | exactly length bytes
```

Lengths must be nonzero. Handshake messages are bounded by 65,535 bytes.
Transport records carry at most 16,384 plaintext bytes. A transport record is
the existing `NoiseSession::encrypt` output (its two-byte inner Noise-message
length plus ciphertext), wrapped in the outer `u32` frame. HTTP and WebSocket
byte streams are split into independent records of at most 16,384 plaintext
bytes; record boundaries have no HTTP meaning.

Handshake and first-auth reads each have a 10-second deadline. The public
listener rate-limits attempts before Noise, accepts at most 64 concurrent
connections, and exits on node shutdown.

### Pre-handshake retry hint

Before doing Noise or looking up any pairing, the node applies a per-IP
budget: at most 20 immediate handshakes, replenishing one admission every
three seconds. Only admitted attempts consume budget; rejected retries do
not extend the penalty. After 60 seconds without admitted attempts the full
burst budget is restored. The table holds at most 2,048 IPs and does not
evict active budgets to admit new IPs.

When rate-limited, the first server frame can instead be **plaintext JSON**,
using the same `u32` big-endian length prefix, followed by connection close:

```json
{"code":"rate_limited","v":1,"retry_after_secs":3}
```

`retry_after_secs` is a positive integer number of seconds, rounded up from
the remaining delay, bounded to 1–60. For a full IP table it indicates the
earliest entry expiry. This is the entire refusal: no node or client identity,
pairing state, keys, endpoint, or diagnostic details are disclosed. Paired
and unpaired callers receive the same format.

The app should recognize this frame while waiting for Noise message 2, close
the old connection, and wait at least the indicated delay before opening a
new one (additional jitter is permitted). Other traffic sharing its IP may
consume the next admission first. The hint is unauthenticated and conveys
no authority: a subsequent connection still requires the pinned Noise
handshake and ordinary authentication. It must never clear a durable pairing
or replace pinned keys. Older clients fail the Noise handshake safely.

Refusal writes have a one-second deadline and at most 64 concurrent writers,
separate from the 64 connection slots. Within that same deadline the node
drains the client's first bounded frame without Noise processing, so closing
does not interrupt a legitimate client's handshake write before it can read
the hint. Under resource exhaustion or write
failure the connection may still close without a hint; clients should use
bounded reconnect backoff for that case as well.

## First encrypted auth record

The first transport plaintext is compact JSON. For a new pairing:

```json
{
  "v": 1,
  "code": "<code from link>",
  "client_name": "Maya's phone",
  "client_pubkey": "<64 lowercase hex Ed25519 pairing key>",
  "signature": "<base64url-no-pad Ed25519 signature>"
}
```

The signature uses `client_pubkey` and signs this exact UTF-8 string:

```
bitsov-remote-pair-v1:<node_id>:<client Noise static X25519 hex>:<code>:<client_pubkey>
```

The proof binds the node identity, client transport identity, one-time code,
and durable pairing identity. `client_name` is cosmetic and is sanitized by
the node. A verified request atomically creates a normal `read` + `receive`
pairing and stores the client X25519 public key on that pairing. If the same
Ed25519 client is already paired locally, the node adds the transport binding
without changing its scopes or revocation epoch. An exact retry by that bound
Ed25519 + X25519 identity is idempotent, so a lost success response does not
strand the app after the one-time code has been consumed.

For a returning client the request must omit all pairing fields:

```json
{"v":1}
```

The node looks up the Noise-authenticated client static key in live durable
pairings. Unknown or revoked mappings fail. Revocation therefore blocks future
tunnels; existing JWT binding checks continue to invalidate tokens immediately.

The node responds with one encrypted JSON record:

```json
{"status":"ok","v":1,"client_id":"<32 hex>","scopes":["read","receive"]}
```

or:

```json
{"status":"error","v":1,"code":"authentication_failed","message":"..."}
```

After an error it closes the connection.

## HTTP and WebSocket tunnel

After successful auth, each decrypted byte chunk is written to the internal
loopback Axum connection and response bytes are encrypted back to the app.
HTTP/1.1 keep-alive and WebSocket upgrades work as byte streams.

The remote router excludes the loopback token mint, public probes, metrics,
first-pair file ceremony, and owner-management pairing routes. A tunnel cannot
use the bridge's loopback source address to mint an unbound local JWT. Apps
obtain and present ordinary paired JWTs through `GET /api/v1/pair/challenge`
and `POST /api/v1/pair/token`; `POST /api/v1/pair/rotate` remains available.

It also exposes exactly these spend-request/read routes, using the same
handlers and authorization as loopback:

| Method | Path | Effect |
|---|---|---|
| POST | `/api/v1/pair/elevation-request` | Ask for elevation; at most four unexpired pending requests per client; never grant it |
| GET | `/api/v1/pair/elevation/{op_id}` | Read only the caller's operation status; other clients' IDs return the same 404 as unknown IDs |
| DELETE | `/api/v1/pair/elevation/{op_id}` | Cancel the caller's own pending request |
| GET | `/api/v1/pair/grant` | Read the caller's own live grant, or `null` |

All require `read`; asking, cancelling and reading a grant also require a live
paired-client binding. No remote grant/approve handler is mounted, including
first-contact grants, device-key management or relation intents. The owner
still grants spend through `<data_dir>/control.sock`.

A read-only pairing may obtain a first-contact price via
`POST /api/v1/messages/first-contact/quote` before requesting spend. This remains
rate-limited payment preparation, with no payment, reservation, obligation or
admission; the later send retains its spend and settlement checks.

Doctrine: lines 1, 3, 4, 5 and 6 hold: authenticated preparation creates no free
peer service, authority remains key-bound and local, and no custody or privacy
claim is widened.

There is no TLS, relay, remote signer, new auth system, or remotely exposed
HTTP listener in this protocol.
