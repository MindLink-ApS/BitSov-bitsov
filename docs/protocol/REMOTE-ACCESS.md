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
256-bit, memory-only, single-use code and prints one line to stdout:

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

No link is printed when pairing is closed. The code is never persisted or
logged. A successful pairing consumes it; a wrong code or proof does not.
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

The remote router is the existing API router except
`POST /api/v1/auth/local` is not mounted. A tunnel cannot use the bridge's
loopback source address to mint an unbound local JWT. Apps obtain and present
ordinary paired JWTs through the existing pairing challenge/token flow.

There is no TLS, relay, remote signer, new auth system, or remotely exposed
HTTP listener in this protocol.
