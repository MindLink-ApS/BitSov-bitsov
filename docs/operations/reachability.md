# Reaching your home node off the LAN

A home node behind a router has no inbound path from the internet. The
supported way for the owner, and for the people in their circle, to reach it
from elsewhere is a Tailscale tailnet: every device that needs the node joins
the tailnet (or is shared the node), and the node listens and advertises on its
tailnet address. This needs no node code beyond the settings below.

Strangers off the tailnet cannot reach a node set up this way. Port mapping
and Tor, which would serve them, are not shipped (see the last section).

## Settings

Install Tailscale on the node host and on each device, and read the node's
address with `tailscale ip -4`. Below it is `100.88.12.34`; use your own.

```toml
[api]
listen_addr = "127.0.0.1:3141"

[network]
listen_addr = "100.88.12.34:9736"
advertised_addr = "100.88.12.34:9736"

[remote_access]
listen_addr = "100.88.12.34:9737"
advertised_endpoint = "100.88.12.34:9737"
```

- `[api].listen_addr` stays on loopback. With `[remote_access]` enabled the
  node refuses to start if it is not loopback; plaintext HTTP never leaves the
  host. `127.0.0.1:3141` is the default.
- `[network] advertised_addr` is the peer endpoint signed into your front-door
  card. Leave `stun_server` unset: with an endpoint configured the node never
  sends a STUN query.
- `[remote_access] advertised_endpoint` is the endpoint written into the
  pairing link at `<data_dir>/pairing/remote-access-link`. It is required once
  `listen_addr` is set.
- The peer and remote-access ports must differ from each other, from the API
  port and from the Lightning `listening_address`; startup refuses a
  collision.

Use the 100.x literal, not the MagicDNS name, in `advertised_addr`. The card's
reach comes from the endpoint text: a 100.x address (the shared range
100.64.0.0/10) makes a `local` card, while a DNS name makes a `public` card, and
a public card that resolves to a 100.x address is refused when opened. Anyone
opening a local card must approve the local endpoint before the node dials it.
`[[peers]] addr` takes an IP address and port only.

Binding both listeners to the tailnet address keeps them off the LAN and any
public interface. The cost is that the node cannot start before Tailscale has
the address: the bind fails, the process exits, and the example
[systemd unit](konsensus.service) (`Restart=on-failure`, `RestartSec=10`)
retries every 10 seconds. This also applies to `--remote-unlock`, which binds
`[remote_access].listen_addr` while locked. If you also want LAN peers, bind
`0.0.0.0` and keep the `advertised_*` values on 100.x.

If the node's tailnet address changes (for example after removing and
re-adding it), update all four values. Devices paired earlier learned the old
endpoint from the pairing link.

## What goes over the tailnet

| Traffic | Port | Over the tailnet |
|---|---|---|
| Owner app to node: Noise_XX tunnel, pairing, unlock, API calls | 9737 | yes |
| BitSov peer protocol with circle nodes: messages, quotes | 9736 | yes, for peers that dial the 100.x address |
| HTTP API (`[api]`) and the tunnel's internal API listener | loopback | no, never leaves the host |
| Lightning to the hub, chain source | outbound | no, these go over the normal internet |

Both tailnet ports carry BitSov's own Noise encryption inside Tailscale's
WireGuard. Reaching a port grants nothing: the tunnel still needs a durable
pairing, the app pins the node's transport key from the pairing link, and peer
messages still pass the payment gate or whitelist.

## Circles

Circle members either join your tailnet or are shared the node. A shared
machine is quarantined by Tailscale by default: it accepts connections from the
recipient but cannot start any. For two home nodes to dial each other, share in
both directions or use one tailnet. A shared machine usually keeps its 100.x
address in the recipient's tailnet but can get a different one; the recipient
should check `tailscale status` against your card.

Tailscale access rules can limit circle members to the peer port, for example:

```json
"grants": [
  { "src": ["autogroup:shared"], "dst": ["*"], "ip": ["9736"] }
]
```

## What Tailscale can and cannot see

This is Tailscale's documented behaviour, not something the node controls.

Tailscale can see:

- your account login, and each device's name, operating system, public key,
  tailnet address, and the public IP address and port where it can currently
  be found;
- who you have shared the node with;
- client logs, which by default include open and close events for every
  connection between devices. Opt out per device with
  `TS_NO_LOGS_NO_SUPPORT=true` in `/etc/default/tailscaled` on the Pi; the
  opt-out is not available on every platform;
- for traffic relayed through its DERP servers (used when no direct path
  exists): both devices' public IP addresses, packet timing and volume.

Tailscale cannot see:

- traffic contents. WireGuard keys never leave the device, and the BitSov
  traffic inside is Noise-encrypted again;
- your seed, unlock password, messages or payments.

Tailscale's coordination server distributes device keys, so it could add a
device to your tailnet. [Tailnet Lock](https://tailscale.com/kb/1226/tailnet-lock)
requires your own devices to sign new ones; self-hosting the coordinator with
Headscale removes Tailscale from the path. An added device would still face the
Noise and pairing checks above.

MindLink is not part of this path. The hub is not on your tailnet and does not
see tailnet traffic.

## The hub does not relay

The hub's LSP role is Lightning liquidity only. Your node dials the hub
outbound; no inbound path is needed for that. The hub does not forward peer
connections or the remote-access tunnel for a node it serves as LSP, and no
code exists for it to do so. The tier-2 relay is a separate, default-off role
that stores ciphertext for offline thin nodes; it is not a session forwarder.
If Tailscale is down, the node is unreachable off the LAN until it is back.

## Not shipped

- **Port mapping.** UPnP and NAT-PMP are not implemented, and there is no
  reachability probe. `[network] stun_server` learns the public IP but does not
  open or check the router port, so a STUN-only setup can advertise an endpoint
  nobody can dial. There is no `port_map` setting.
- **Tor.** Peers are dialed by IP address and port only. There is no SOCKS
  proxy, no `.onion` endpoint and no onion service, and Electrum rejects
  `.onion` servers.
