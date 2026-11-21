# BitChat alignment

Status: Research note. Not a spec and not a commitment.
Date: 2026-10-23
Scope: compares BitChat (permissionlesstech) with the BitSov node in this repository, and records integration options with their trade-offs.

## How to read this

**Sources.**
- BitChat claims cite primary sources: its GitHub repositories, whitepaper, docs, release pages and issues.
- BitSov claims cite this repository's own docs.
- `https://bitchat.free/` did not resolve from the research environment on 2026-10-23 (DNS `ENOTFOUND`), so nothing below relies on it.
- The App Store and Google Play pages were also not reachable. Store ratings, download counts and rankings are **not verified** and are not quoted.

**Short links used throughout.**
- iOS repo: `https://github.com/permissionlesstech/bitchat`. Files are cited as `iOS:/<path>`, meaning `https://github.com/permissionlesstech/bitchat/blob/main/<path>`.
- Android repo: `https://github.com/permissionlesstech/bitchat-android`. Files are cited as `Android:/<path>`, meaning `https://github.com/permissionlesstech/bitchat-android/blob/main/<path>`.
- WP: the BitChat whitepaper, v2.0, dated July 6, 2026 (`iOS:/WHITEPAPER.md`).

**Honesty rule.** BitSov today is a signet closed beta. The node's current line is `0.3.0-rc19`. Git tags `v0.3.0-rc19` to `v0.3.0-rc19.2` exist, although the [CHANGELOG.md](../../CHANGELOG.md) heading still reads "prep; not tagged yet"; these are pre-release candidates, not a public release. Signed binaries are not yet published ([README.md](../../README.md), "Developer Preview"). Where this note says BitSov "ships" something, it means "in the node today, on signet or regtest as stated". Everything else is labelled **target** or **not built**.

---

## (a) Side-by-side

| Dimension | BitChat (shipped, per its sources) | BitSov node (this repo) |
|---|---|---|
| **Purpose** | Permissionless, offline-first chat over BLE mesh, with Nostr as fallback (WP §2). | Paid peer-to-peer messaging, calls and payments. Every user runs their own node, and admission is a settled Lightning payment ([README.md](../../README.md)). |
| **Platforms** | One universal iOS/macOS app in Swift ([iOS README](https://github.com/permissionlesstech/bitchat/blob/main/README.md)). Android in Kotlin, API 26+ ([Android README](https://github.com/permissionlesstech/bitchat-android/blob/main/README.md)). Wear OS builds from Android 2.0.1 ([releases](https://github.com/permissionlesstech/bitchat-android/releases)). | A Rust node, with Light and Full tiers today ([README.md](../../README.md), Sovereignty Tiers). The Tauri app for Mac, iPhone and Android lives in a separate repo and is not covered here. A Mac and iPhone second-device acceptance checklist exists for signet ([home-node.md §T18](../operations/home-node.md)). |
| **Transport (online)** | Nostr relays. Tor via in-process Arti is on by default and fails closed ([TOR-INTEGRATION.md](https://github.com/permissionlesstech/bitchat/blob/main/docs/TOR-INTEGRATION.md)). | Direct TCP between nodes under Noise. Off-LAN reach is through a Tailscale tailnet. Port mapping and Tor are **not shipped** ([reachability.md](../operations/reachability.md)). |
| **Transport (offline / local)** | BLE mesh with each device as both GATT central and peripheral. Controlled flood with TTL 7, dedup, jitter and source routing (WP §4). Android adds Wi-Fi Aware, off by default since 1.7.3 ([releases](https://github.com/permissionlesstech/bitchat-android/releases)). | **Not built.** No BLE or local-radio transport exists in code or docs. |
| **Link encryption** | Noise XX, 25519 / ChaChaPoly / SHA-256 (WP §5.1; [BRING_THE_NOISE.md](https://github.com/permissionlesstech/bitchat/blob/main/BRING_THE_NOISE.md)). | `Noise_XX_25519_ChaChaPoly_BLAKE2s` (`crates/konsensus-crypto/src/noise.rs`). |
| **Message E2EE** | The live Noise session itself. Offline courier mail uses one-way Noise X, which has no forward secrecy (WP §5.2). | X3DH plus Double Ratchet for 1:1 (`konsensus-crypto`). PQXDH is a **target**: the code only has an upgrade seam (`x3dh.rs`). MLS is **not built** ([ROOMS.md](../protocol/ROOMS.md), "Honesty"). |
| **Groups** | Public mesh channels and geohash channels (README). Private groups since iOS v1.6.0 ([releases](https://github.com/permissionlesstech/bitchat/releases)). | Rooms of 2 to 4 members, made of pairwise paid 1:1 chats. No group key ([ROOMS.md](../protocol/ROOMS.md)). |
| **Store-and-forward** | Sender outbox: 100 messages per peer, 24 h, 8 resends. Up to 3 couriers per envelope, 16 KiB and 24 h caps, quotas by favorite or verified tier. Nostr mailbox lookback of 24 h (WP §6). | Durable paid outbox with ACK-bound completion ([PAID-DELIVERY-SLICE-1.md](../v2/PAID-DELIVERY-SLICE-1.md)). The paid ciphertext relay is **not shipped**: the spec is "Proposed" ([RELAY_PROTOCOL.md](../v2/RELAY_PROTOCOL.md)), and the engine code is inert and default-off (`crates/konsensus-node/src/relay/engine.rs`). |
| **Identity** | A Curve25519 Noise static key and an Ed25519 signing key per device. WP §3 derives the peer ID from the first 8 bytes of SHA-256 of the static key. Panic wipe replaces the identity; the iOS [v1.7.1 release notes](https://github.com/permissionlesstech/bitchat/releases/tag/v1.7.1) also say device-bound identity no longer survives deleting and reinstalling the app or migration to a new phone, so these events change the peer ID too. The [peer-ID rotation document](https://github.com/permissionlesstech/bitchat/blob/main/docs/PEER-ID-ROTATION.md) is labelled a draft. | An Ed25519 node identity derived from a BIP-39 mnemonic. Current app authentication uses paired JWTs over the Noise tunnel, with signed relation intents for device-key spend authority ([ACCOUNT-LAYER.md §3](../protocol/ACCOUNT-LAYER.md#3-how-an-app-gets-and-holds-access-to-a-node); [pairing.md](../security/pairing.md)). The pairing/session/per-request model in [REMOTE_ACCESS_IDENTITY.md](../v2/REMOTE_ACCESS_IDENTITY.md) is **Proposed**, a target rather than implemented authentication. Keys are identity and nothing is anchored on-chain (see note under (b)). |
| **Verification** | QR verification, in iOS since 1.3.2 and Android since 1.6.0 ([iOS releases](https://github.com/permissionlesstech/bitchat/releases), [Android releases](https://github.com/permissionlesstech/bitchat-android/releases)). | QR pairing with four-word SAS confirmation for the user's own devices ([pairing.md](../security/pairing.md); [home-node.md §T18](../operations/home-node.md)). Invitee-bound signed invites for contacts ([ADR-029](../v2/ADR-029-invite-token-scheme.md)). |
| **Panic wipe** | Triple-tap the logo, or a settings button, to erase messages, keys and identity ([AppInfoView.swift](https://github.com/permissionlesstech/bitchat/blob/main/bitchat/Views/AppInfoView.swift)). | **Not built** as a node or app feature (not found in docs). Note that a node also holds Lightning funds, so a wipe needs a recovery story ([RECOVERY.md](../v2/RECOVERY.md)). |
| **Spam / abuse** | TTL clamps, dedup and quotas on the mesh. Geohash messages are mined with NIP-13 PoW at 8 bits; inbound PoW is scored, not enforced ([NostrPoW.swift](https://github.com/permissionlesstech/bitchat/blob/main/bitchat/Nostr/NostrPoW.swift)). No stated Sybil resistance beyond quotas (WP §8). | Every act needs a settled, recipient-bound payment. First contact is a capped admission payment plus a message payment ([F1-CAPPED-FIRST-CONTACT.md](../v2/F1-CAPPED-FIRST-CONTACT.md)). Unpaid confirmation floods are budgeted ([PAID-DELIVERY-SLICE-1.md](../v2/PAID-DELIVERY-SLICE-1.md)). |
| **Payments** | Cashu tokens are decoded and displayed only; "the app never contacts a mint" ([CashuTokenDecoder.swift](https://github.com/permissionlesstech/bitchat/blob/main/bitchat/Services/CashuTokenDecoder.swift)). `lightning:` URIs open an external wallet ([PaymentChipView.swift](https://github.com/permissionlesstech/bitchat/blob/main/bitchat/Views/Components/PaymentChipView.swift)). No wallet or node. | An embedded LDK or LND node, with CLN as a read-mostly preview ([CLN.md](../CLN.md)). Payments are the admission gate. Fee caps ([ALL-IN-FEE-CAPS.md](../v2/ALL-IN-FEE-CAPS.md)), spend grants ([SPEND_BUDGET_GRANTS.md](../SPEND_BUDGET_GRANTS.md)), and an opt-in signet LSPS2 hub pilot ([LSPS2-LIQUIDITY.md](../LSPS2-LIQUIDITY.md)). |
| **Calls / voice** | Push-to-talk since iOS v1.7.0 ([releases](https://github.com/permissionlesstech/bitchat/releases)). Voice streaming in Android v2.0.1 ([releases](https://github.com/permissionlesstech/bitchat-android/releases)). | A 1:1 WebRTC call **prototype, proven on regtest only**. Paid signalling kinds 400 to 403, STUN only ([CALLS-PROTOTYPE.md](../v2/CALLS-PROTOTYPE.md)). |
| **Metadata** | "Metadata is the weakest part of this design" (WP §8). Packet padding only, and "no cover traffic" ([BitchatProtocol.swift](https://github.com/permissionlesstech/bitchat/blob/main/bitchat/Protocols/BitchatProtocol.swift)). | Leak surfaces are documented in [THREAT_MODEL_TIER2_RELAY.md](../v2/THREAT_MODEL_TIER2_RELAY.md). Padding and cover traffic are mitigations, not shipped. |
| **Supply chain** | Android v2.0.1 was the "first reproducible full-app release" ([releases](https://github.com/permissionlesstech/bitchat-android/releases)). | Pinned-asset, no-downgrade release signing and a Darwin reproducibility check ([CHANGELOG.md](../../CHANGELOG.md)). Signed binaries are not yet published. |
| **License** | iOS/macOS: Unlicense. [`LICENSE`](https://github.com/permissionlesstech/bitchat/blob/main/LICENSE) is the Unlicense text and links to `https://unlicense.org`. The iOS [`README.md`](https://github.com/permissionlesstech/bitchat/blob/main/README.md) License section says the project is released into the public domain, which matches that dedication. Android: [`LICENSE.md`](https://github.com/permissionlesstech/bitchat-android/blob/main/LICENSE.md) is the GNU GPL version 3. It has been GPL-3.0 since commit [`fb2bb64`](https://github.com/permissionlesstech/bitchat-android/commit/fb2bb64d65a2d9a3d3ebd6183f0e9b6d46936b19) (2026-02-28, "change license from MIT to GPLv3"), included in release [1.7.2](https://github.com/permissionlesstech/bitchat-android/releases/tag/1.7.2). The Android [`README.md`](https://github.com/permissionlesstech/bitchat-android/blob/main/README.md) License section still says the project is released into the public domain and points at `LICENSE.md`, which does not match the license file. | MIT ([LICENSE](../../LICENSE)). |
| **Release cadence** | About 20 iOS releases from v1.1 (2025-07) to **v1.7.1 (2026-07-31)** ([releases.atom](https://github.com/permissionlesstech/bitchat/releases.atom)). Android latest is **v2.0.3 (22 Oct 2026)** ([releases](https://github.com/permissionlesstech/bitchat-android/releases)). | Release candidates rc8 to rc19 ([docs/releases/](../releases/)). Pre-release only. |
| **Adoption signals** | iOS repo: 36,718 stars and 5,844 forks. Android repo: 7,853 stars and 1,940 forks. Counts read from GitHub repo metadata on 2026-10-23 ([iOS](https://github.com/permissionlesstech/bitchat), [Android](https://github.com/permissionlesstech/bitchat-android)). | Closed signet beta. No public adoption figures. |

---

## (b) Gaps in both directions

### What BitChat has that BitSov lacks

1. **Offline local delivery.** BitChat has a BLE mesh with relaying, fragmentation and gossip sync (WP §4, §6.3). BitSov has no radio transport at all.
2. **Store-and-forward for offline peers, in production.** BitChat has couriers plus Nostr mailboxes (WP §6). BitSov's paid relay exists only as a proposed spec and inert code ([RELAY_PROTOCOL.md](../v2/RELAY_PROTOCOL.md)).
3. **Shipping consumer apps on three surfaces, with fast cadence.** BitChat ships iOS/macOS, Android and Wear OS. Since July 2025 it has made about 20 iOS releases and more than 40 Android tags ([iOS releases](https://github.com/permissionlesstech/bitchat/releases), [Android releases](https://github.com/permissionlesstech/bitchat-android/releases)).
4. **Tor by default and fail-closed** on the internet path ([TOR-INTEGRATION.md](https://github.com/permissionlesstech/bitchat/blob/main/docs/TOR-INTEGRATION.md)). BitSov reaches off-LAN only through a tailnet ([reachability.md](../operations/reachability.md)).
5. **Panic wipe** ([AppInfoView.swift](https://github.com/permissionlesstech/bitchat/blob/main/bitchat/Views/AppInfoView.swift)).
6. **Public, location-scoped channels.** Geohash channels run on ephemeral Nostr kinds 20000 and 20001 ([GeohashPresenceSpec.md](https://github.com/permissionlesstech/bitchat/blob/main/docs/GeohashPresenceSpec.md)). BitSov deliberately has no unpaid public lane: gossip is disabled ([THREAT_MODEL_TIER2_RELAY.md](../v2/THREAT_MODEL_TIER2_RELAY.md)).
7. **Push-to-talk and voice** (iOS v1.7.0; Android v2.0.1).
8. **A reproducible mobile app build** (Android v2.0.1).
9. **A single readable whitepaper** with explicit limits and future work (WP §8 and §9). BitSov's equivalent is spread across many ADRs and specs.

### What BitSov has that BitChat lacks

1. **Spam economics.**
   - BitChat's abuse controls are rate limits, quotas and an 8-bit PoW on geohash posts that is scored, never enforced ([MessageRateLimiter.swift](https://github.com/permissionlesstech/bitchat/blob/main/bitchat/ViewModels/MessageRateLimiter.swift)).
   - BitSov prices every act. There is no free first message: first contact is a capped admission plus a message payment ([F1-CAPPED-FIRST-CONTACT.md](../v2/F1-CAPPED-FIRST-CONTACT.md)).
   - Under this model, Sybil identities cost sats, not just keys.
2. **Native Lightning.**
   - BitChat hands `lightning:` links and Cashu tokens to external wallets ([PaymentChipView.swift](https://github.com/permissionlesstech/bitchat/blob/main/bitchat/Views/Components/PaymentChipView.swift); [CashuTokenDecoder.swift](https://github.com/permissionlesstech/bitchat/blob/main/bitchat/Services/CashuTokenDecoder.swift)).
   - BitSov embeds LDK or LND, settles in-band, and binds each payment to its recipient. It also has fee caps and exactly-once operations ([EXACTLY-ONCE-OPERATIONS.md](../v2/EXACTLY-ONCE-OPERATIONS.md)).
3. **Owner-node sovereignty.**
   - Each person runs their own node and owns their data, channels and policy ([CHARTER.md](../../CHARTER.md); [home-node.md](../operations/home-node.md)).
   - BitChat has no server of the user's own. Its offline delivery relies on strangers' devices and public Nostr relays (WP §6).
4. **Forward-secret stored messages.**
   - BitSov uses a Double Ratchet for 1:1 messages (`konsensus-crypto`).
   - BitChat's courier and Nostr envelopes have no forward secrecy (WP §5.2 and §5.3).
5. **Multi-device under one identity.** BitSov has an owner-approved device enrolment design ([device-keys.md](../security/device-keys.md)). BitChat's identity is per device (WP §3).
6. **A documented, dated security review cadence** ([docs/security/](../security/)). BitChat publishes no GitHub security advisories ([security page](https://github.com/permissionlesstech/bitchat/security)). Its Android repo carries a self-review listing Critical and High findings, with fix status unstated ([security-review-jul-27.md](https://github.com/permissionlesstech/bitchat-android/blob/main/docs/security-review-jul-27.md)).

> **Documentation inconsistency.** Line 3 of [README.md](../../README.md) says "Bitcoin-anchored identity". Elsewhere in this repository, Bitcoin anchors energy and admission, and identity is derived from user-held keys. This note does not edit the README.

---

## (c) Interop options

Four independent ways a BitSov node could relate to BitChat. The labels are for reference. Each option is described with its mechanism and its trade-offs.

**Constraints applied to every option.**
- **G1:** identity is never anchored in Bitcoin.
- **G2:** there is no free first message.
- **G3:** everything runs on signet first.
- **G4:** the charter holds: no operator-held keys.

### 1. Compatible identity export

- **What it is:**
  - Let a BitSov user show a verifiable link between their BitSov node key and a BitChat or Nostr pubkey.
  - The proof is a signed statement in each direction, displayed or scanned as a QR code.
  - The keys stay separate; this is cross-signing, not shared keys.
- **Effect:** a contact can check that a BitChat or Nostr key and a BitSov node key are held by the same person. The check is a signature on a statement, not an on-chain record.
- **Effort:** low. It is a signed-statement format plus a QR flow. BitChat's QR verification ([releases](https://github.com/permissionlesstech/bitchat/releases)) is the UX benchmark.
- **Doctrine risks:**
  - **G1:** keep it key-to-key. Never put the link on-chain or in an invoice.
  - Don't reuse BitSov's Ed25519 key as a secp256k1 Nostr key, because that cross-protocol key reuse is unsafe. Derive a separate key or sign a link.
  - **Privacy:** a public link joins two social graphs, so disclosure must be opt-in and per contact. Revocation can end the link's future validity, but observers can retain the signed association indefinitely; it cannot undo identity correlation already made public.

### 2. Paid-admission gateway for BitChat users

- **What it is:**
  - A BitSov node publishes a "reach me" card.
  - A BitChat user pays a recipient-bound invoice through their external wallet, which BitChat already hands `lightning:` links to.
  - The BitChat user then gets an admission they can use from a BitSov client, or from a thin web flow.
- **Effect:** BitChat already hands `lightning:` URIs to an external wallet. That wallet can pay a recipient-bound invoice. The admission returned is the same capped first contact any other payer presents, and the recipient's node checks it before delivering a message.
- **Effort:** medium. It reuses F1 capped first contact. The new work is a payer path that is not a BitSov node.
- **Doctrine risks:**
  - **G2:** the gateway must never deliver an unpaid teaser. Preparing the invoice must stay within F1's bounded payment-preparation floor ([F1-CAPPED-FIRST-CONTACT.md](../v2/F1-CAPPED-FIRST-CONTACT.md)).
  - **G3:** signet invoices only, at first. Most BitChat users' wallets are mainnet, so the signet pilot needs signet-capable wallets.
  - **G4:** the gateway must not hold keys for the payer or the recipient.
  - **Cashu:** do not accept Cashu bearer tokens as admission. A token is not recipient-bound or settled until it is redeemed at a mint. The repo already has a "No Cashu default" stance ([N-M7A-STARTER-REQUEST.md](../design/N-M7A-STARTER-REQUEST.md)).

### 3. Bridge BitSov to BitChat's Nostr layer

- **What it is:** a bridge that relays between BitSov UKM envelopes and BitChat's Nostr DMs and geohash events.
- **Hard facts:**
  - BitChat's DM format "is not NIP-17, NIP-44, or NIP-59 compatible" and works only between BitChat clients (WP §5.3).
  - The format has no forward secrecy (WP §5.3).
  - Geohash identities are deterministic per geohash ([NostrIdentityBridge.swift](https://github.com/permissionlesstech/bitchat/blob/main/bitchat/Nostr/NostrIdentityBridge.swift)).
  - A bridge would therefore track a moving, client-specific format.
- **Effort:** medium-high, plus ongoing maintenance whenever BitChat changes its envelope.
- **Doctrine risks:**
  - **G2:** inbound from Nostr is free by default. Under [F1](../v2/F1-CAPPED-FIRST-CONTACT.md#stranger-payment-preparation-and-the-whitepaper-floor), the target must create no pre-settlement message records or unpaid inbound queue. Only bounded transient handling needed to check payment or prepare it within F1's narrow floor is allowed; unpaid events must be rejected, with the sender resubmitting after settlement. That breaks BitChat's UX expectations.
  - **E2EE:** a bridge that re-encrypts sees plaintext. That is acceptable only if the bridge is the user's own node, never an operator (**G4**).
  - **Metadata:** Nostr relays see the recipient `p` tag (WP §5.3).

### 4. Local BLE transport for offline ciphertext

- **What it is:**
  - Add a local radio transport to the app, not the node, for when BitSov devices can't reach their nodes.
  - Ciphertext UKMs would be carried device to device and delivered when a node becomes reachable.
- **Licence:** iOS `LICENSE` is the Unlicense. Android `LICENSE.md` is GPL-3.0 since commit `fb2bb64` (2026-02-28, release 1.7.2); the Android `README.md` License section still says public domain. Copying Android source into an MIT distribution is a GPL-3.0 obligation. An independent implementation can follow the whitepaper (`iOS:/WHITEPAPER.md`).
- **Effort:**
  - High: radio stacks on iOS and Android, battery cost, and background limits.
  - Payment is the hard part. Lightning needs connectivity, so offline acts can't settle.
- **Doctrine risks:**
  - **G2:** an offline message cannot be admitted until payment settles. The proposed [RELAY_PROTOCOL.md](../v2/RELAY_PROTOCOL.md) requires every held UKM to already carry a sender-to-recipient payment proof (commitment 2), with relay storage paid separately (commitment 3); drain verifies that proof rather than deferring settlement until after carriage. Unpaid messages must remain sender-side until settlement. Any proposal to carry unpaid ciphertext through other devices needs a separate admission and storage design that preserves F1's ban on target-side pre-settlement records. Nothing is shown before admission.
  - **Metadata:** BitChat's own threat model calls metadata its weakest part (WP §8). BLE presence leaks location.
  - **G3:** this is not a signet concern by itself, but payment-proof verification on drain must be proven on signet first.

**Trade-offs.** The options are independent.

| Option | Cost | What stays the same |
|---|---|---|
| 1. Identity export | A signed statement format and a QR flow. A published link correlates the two identities and their social graphs. Revocation ends future validity, but cannot undo public disclosure: observers can retain the signed association indefinitely. | Keys stay separate. The link is not written on-chain or into an invoice. Admission rules do not change. |
| 2. Paid-admission gateway | A payer path that is not a BitSov node. A signet pilot needs wallets that can pay signet invoices. | Admission is still a settled, recipient-bound payment under F1. No message is delivered before it settles. Cashu bearer tokens are not admission. The gateway holds no keys. |
| 3. Nostr bridge | Ongoing tracking of a BitChat-only envelope (not NIP-17, NIP-44, or NIP-59) that has no forward secrecy. Unpaid inbound events are rejected after bounded transient payment handling; F1 forbids target-side pre-settlement message records or queues. Re-encryption sees plaintext, so the bridge is the user's own node. | After settlement and resubmission, the BitSov side stays inside existing UKM and admission rules. |
| 4. BLE carriage | Radio stacks on iOS and Android, including battery and background limits. Unpaid messages stay sender-side until settlement; carrying them through other devices would need a separate admission and storage design. Android `LICENSE.md` is GPL-3.0, so an implementation follows the whitepaper rather than copying Android source. iOS `LICENSE` is the Unlicense. | The radio carries ciphertext only. Under proposed [RELAY_PROTOCOL.md](../v2/RELAY_PROTOCOL.md) commitments 2–3, held UKMs already carry payment proofs and relay storage is paid separately. The recipient verifies the proof on drain and shows nothing before admission. |

---

## Unverified or conflicting items

- `bitchat.free`, the App Store page and the Play Store page could not be fetched. Store metrics are omitted.
- The iOS v1.6.0 release notes list "prekey bundles", but WP v2.0, dated a day earlier, calls prekeys future work. Whether courier seals use prekeys is not verified.
- The iOS v1.5.4 notes say it "fixes security audit findings". The auditor is not identified in the sources fetched.
- BRING_THE_NOISE.md claims "identity hiding", while WP §8 says announces carry static keys in cleartext. This note follows the whitepaper.
- Trail of Bits and supernetworks commentary from July and August 2025 was not fetched. The original MitM report is [issue #64](https://github.com/permissionlesstech/bitchat/issues/64), which was closed on 2026-07-10.
