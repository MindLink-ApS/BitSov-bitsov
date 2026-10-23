# BitChat alignment and guide-trail milestones

Status: Research note. Not a spec and not a commitment.
Date: 2026-10-23
Scope: compares BitChat (permissionlesstech) with the BitSov node in this repository, and proposes milestones that use BitChat's shipped features as a benchmark.

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

**Honesty rule.** BitSov today is a signet closed beta. The node's current line is `0.3.0-rc19`, which is in prep and not tagged ([CHANGELOG.md](../../CHANGELOG.md)). Signed binaries are not yet published ([README.md](../../README.md), "Developer Preview"). Where this note says BitSov "ships" something, it means "in the node today, on signet or regtest as stated". Everything else is labelled **target** or **not built**.

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
| **Identity** | A Curve25519 Noise static key and an Ed25519 signing key per device. Peer ID is the first 8 bytes of SHA-256 of the static key and changes only on panic wipe (WP §3). Peer-ID rotation is still a draft ([PEER-ID-ROTATION.md](https://github.com/permissionlesstech/bitchat/blob/main/docs/PEER-ID-ROTATION.md)). | An Ed25519 node identity derived from a BIP-39 mnemonic. Paired device keys hang off it in three layers: pairing, session and per-request ([REMOTE_ACCESS_IDENTITY.md](../v2/REMOTE_ACCESS_IDENTITY.md); [device-keys.md](../security/device-keys.md)). Keys are identity and nothing is anchored on-chain (see note under (b)). |
| **Verification** | QR verification, in iOS since 1.3.2 and Android since 1.6.0 ([iOS releases](https://github.com/permissionlesstech/bitchat/releases), [Android releases](https://github.com/permissionlesstech/bitchat-android/releases)). | QR pairing with four-word SAS confirmation for the user's own devices ([pairing.md](../security/pairing.md); [home-node.md §T18](../operations/home-node.md)). Invitee-bound signed invites for contacts ([ADR-029](../v2/ADR-029-invite-token-scheme.md)). |
| **Panic wipe** | Triple-tap the logo, or a settings button, to erase messages, keys and identity ([AppInfoView.swift](https://github.com/permissionlesstech/bitchat/blob/main/bitchat/Views/AppInfoView.swift)). | **Not built** as a node or app feature (not found in docs). Note that a node also holds Lightning funds, so a wipe needs a recovery story ([RECOVERY.md](../v2/RECOVERY.md)). |
| **Spam / abuse** | TTL clamps, dedup and quotas on the mesh. Geohash messages are mined with NIP-13 PoW at 8 bits; inbound PoW is scored, not enforced ([NostrPoW.swift](https://github.com/permissionlesstech/bitchat/blob/main/bitchat/Nostr/NostrPoW.swift)). No stated Sybil resistance beyond quotas (WP §8). | Every act needs a settled, recipient-bound payment. First contact is a capped admission payment plus a message payment ([F1-CAPPED-FIRST-CONTACT.md](../v2/F1-CAPPED-FIRST-CONTACT.md)). Unpaid confirmation floods are budgeted ([PAID-DELIVERY-SLICE-1.md](../v2/PAID-DELIVERY-SLICE-1.md)). |
| **Payments** | Cashu tokens are decoded and displayed only; "the app never contacts a mint" ([CashuTokenDecoder.swift](https://github.com/permissionlesstech/bitchat/blob/main/bitchat/Services/CashuTokenDecoder.swift)). `lightning:` URIs open an external wallet ([PaymentChipView.swift](https://github.com/permissionlesstech/bitchat/blob/main/bitchat/Views/Components/PaymentChipView.swift)). No wallet or node. | An embedded LDK or LND node, with CLN as a read-mostly preview ([CLN.md](../CLN.md)). Payments are the admission gate. Fee caps ([ALL-IN-FEE-CAPS.md](../v2/ALL-IN-FEE-CAPS.md)), spend grants ([SPEND_BUDGET_GRANTS.md](../SPEND_BUDGET_GRANTS.md)), and an opt-in signet LSPS2 hub pilot ([LSPS2-LIQUIDITY.md](../LSPS2-LIQUIDITY.md)). |
| **Calls / voice** | Push-to-talk since iOS v1.7.0 ([releases](https://github.com/permissionlesstech/bitchat/releases)). Voice streaming in Android v2.0.1 ([releases](https://github.com/permissionlesstech/bitchat-android/releases)). | A 1:1 WebRTC call **prototype, proven on regtest only**. Paid signalling kinds 400 to 403, STUN only ([CALLS-PROTOTYPE.md](../v2/CALLS-PROTOTYPE.md)). |
| **Metadata** | "Metadata is the weakest part of this design" (WP §8). Packet padding only, and "no cover traffic" ([BitchatProtocol.swift](https://github.com/permissionlesstech/bitchat/blob/main/bitchat/Protocols/BitchatProtocol.swift)). | Leak surfaces are documented in [THREAT_MODEL_TIER2_RELAY.md](../v2/THREAT_MODEL_TIER2_RELAY.md). Padding and cover traffic are mitigations, not shipped. |
| **Supply chain** | Android v2.0.1 was the "first reproducible full-app release" ([releases](https://github.com/permissionlesstech/bitchat-android/releases)). | Pinned-asset, no-downgrade release signing and a Darwin reproducibility check ([CHANGELOG.md](../../CHANGELOG.md)). Signed binaries are not yet published. |
| **License** | iOS/macOS: the Unlicense ([LICENSE](https://github.com/permissionlesstech/bitchat/blob/main/LICENSE)). Android: GPL-3.0, changed from MIT in 1.7.2 ([LICENSE.md](https://github.com/permissionlesstech/bitchat-android/blob/main/LICENSE.md); [releases](https://github.com/permissionlesstech/bitchat-android/releases)). | MIT ([LICENSE](../../LICENSE)). |
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

> **Doctrine drift found while reading.** Line 3 of [README.md](../../README.md) says "Bitcoin-anchored identity". The doctrine is that Bitcoin anchors energy and admission, never identity. The code derives identity from user-held keys. This note does not edit the README, which is out of scope; see open question 1.

---

## (c) Interop options

The options are ranked by doctrine fit first, then by effort.

**Doctrine guardrails applied to every option.**
- **G1:** identity is never anchored in Bitcoin.
- **G2:** there is no free first message.
- **G3:** everything runs on signet first.
- **G4:** the charter holds: no operator-held keys.

### 1. Compatible identity export (best fit, low effort)

- **What it is:**
  - Let a BitSov user show a verifiable link between their BitSov node key and a BitChat or Nostr pubkey.
  - The proof is a signed statement in each direction, displayed or scanned as a QR code.
  - The keys stay separate; this is cross-signing, not shared keys.
- **Why:** it lets BitChat contacts verify "this is the same person" before paying to reach them on BitSov.
- **Effort:** low. It is a signed-statement format plus a QR flow. BitChat's QR verification ([releases](https://github.com/permissionlesstech/bitchat/releases)) is the UX benchmark.
- **Doctrine risks:**
  - **G1:** keep it key-to-key. Never put the link on-chain or in an invoice.
  - Don't reuse BitSov's Ed25519 key as a secp256k1 Nostr key, because that cross-protocol key reuse is unsafe. Derive a separate key or sign a link.
  - **Privacy:** a public link welds two social graphs together, so it must be opt-in, per contact, and revocable.

### 2. Paid-admission gateway for BitChat users (strong fit, medium effort)

- **What it is:**
  - A BitSov node publishes a "reach me" card.
  - A BitChat user pays a recipient-bound invoice through their external wallet, which BitChat already hands `lightning:` links to.
  - The BitChat user then gets an admission they can use from a BitSov client, or from a thin web flow.
- **Why:** it turns BitChat's audience into paid first contacts without weakening the gate.
- **Effort:** medium. It reuses F1 capped first contact. The new work is a payer path that is not a BitSov node.
- **Doctrine risks:**
  - **G2:** the gateway must never deliver an unpaid teaser. Preparing the invoice must stay within F1's bounded payment-preparation floor ([F1-CAPPED-FIRST-CONTACT.md](../v2/F1-CAPPED-FIRST-CONTACT.md)).
  - **G3:** signet invoices only, at first. Most BitChat users' wallets are mainnet, so the signet pilot needs signet-capable wallets.
  - **G4:** the gateway must not hold keys for the payer or the recipient.
  - **Cashu:** do not accept Cashu bearer tokens as admission. A token is not recipient-bound or settled until it is redeemed at a mint. The repo already has a "No Cashu default" stance ([N-M7A-STARTER-REQUEST.md](../design/N-M7A-STARTER-REQUEST.md)).

### 3. Bridge BitSov to BitChat's Nostr layer (medium fit, medium-high effort)

- **What it is:** a bridge that relays between BitSov UKM envelopes and BitChat's Nostr DMs and geohash events.
- **Hard facts:**
  - BitChat's DM format "is not NIP-17, NIP-44, or NIP-59 compatible" and works only between BitChat clients (WP §5.3).
  - The format has no forward secrecy (WP §5.3).
  - Geohash identities are deterministic per geohash ([NostrIdentityBridge.swift](https://github.com/permissionlesstech/bitchat/blob/main/bitchat/Nostr/NostrIdentityBridge.swift)).
  - A bridge would therefore track a moving, client-specific format.
- **Effort:** medium-high, plus ongoing maintenance whenever BitChat changes its envelope.
- **Doctrine risks:**
  - **G2:** inbound from Nostr is free by default. The bridge must hold every inbound message until a payment settles, and drop it otherwise. That breaks BitChat's UX expectations.
  - **E2EE:** a bridge that re-encrypts sees plaintext. That is acceptable only if the bridge is the user's own node, never an operator (**G4**).
  - **Metadata:** Nostr relays see the recipient `p` tag (WP §5.3).

### 4. Adopt BitChat's BLE mesh for offline delivery (high value, highest effort)

- **What it is:**
  - Add a local radio transport to the app, not the node, for when BitSov devices can't reach their nodes.
  - Ciphertext UKMs would be carried device to device and delivered when a node becomes reachable.
- **Licence:** the iOS code is under the Unlicense, so it is reusable. The Android code is now GPL-3.0, which is incompatible with MIT distribution if copied. Reimplement from the whitepaper and do not copy Android code.
- **Effort:**
  - High: radio stacks on iOS and Android, battery cost, and background limits.
  - Payment is the hard part. Lightning needs connectivity, so offline acts can't settle.
- **Doctrine risks:**
  - **G2:** an offline message cannot be admitted until payment settles. The only fit is "carry now, admit on reconnect": the recipient's node gates on drain, as in [RELAY_PROTOCOL.md](../v2/RELAY_PROTOCOL.md) commitment 2. Nothing is shown before then.
  - **Metadata:** BitChat's own threat model calls metadata its weakest part (WP §8). BLE presence leaks location.
  - **G3:** this is not a signet concern by itself, but the drain-time payment path must be proven on signet first.

**Recommendation.** Do 1 then 2 soon. Treat 3 as a research spike only. Defer 4 until the paid relay (store-and-forward) ships, because 4 depends on the same "admit on drain" machinery.

---

## (d) Guide-trail milestones

North star: *"Rasmus and his father message, call and pay from iPhone and Mac, each on their own node."*

Each milestone names the BitChat feature that serves as its benchmark. Being "at parity" means matching the user-visible outcome, not copying the design. Every milestone is signet first.

| # | Milestone | BitSov exit criterion (signet) | BitChat benchmark | Today |
|---|---|---|---|---|
| **M1** | **Two nodes, two people, paid chat** | Rasmus and his father each run a home node. Each pairs a Mac and an iPhone, and they exchange paid 1:1 messages with F1 first contact and the durable outbox. | BitChat 1:1 private messages with QR verification (iOS 1.3.2) | Node pieces exist (pairing, F1, paid outbox). The T18 Mac and iPhone checklist exists ([home-node.md](../operations/home-node.md)). The end-to-end two-person run is not recorded in this repo. |
| **M2** | **Delivered while offline** | A message sent while the father's node is down is delivered once it is back. The paid relay holds ciphertext, and the recipient gates on drain. | BitChat couriers plus Nostr mailbox, with 24 h retention (WP §6) | The relay spec is "Proposed" and the engine code is inert ([RELAY_PROTOCOL.md](../v2/RELAY_PROTOCOL.md)). **Not shipped.** |
| **M3** | **Paid call, iPhone to Mac** | A 1:1 call between their own nodes on signet, with paid offer and signalling. | BitChat push-to-talk and voice (iOS 1.7.0; Android 2.0.1) | Prototype, **proven on regtest only** ([CALLS-PROTOTYPE.md](../v2/CALLS-PROTOTYPE.md)). |
| **M4** | **Pay each other in-thread** | A plain payment in the conversation, separate from admission, with fee caps and exactly-once semantics. | BitChat `/pay` Cashu and `lightning:` chips, both external-wallet handoff | The node has payments and spend grants. An in-thread payment UX is not covered in node docs. |
| **M5** | **Hard to watch, easy to wipe** | Tor or equivalent reachability off the tailnet, a panic-wipe flow with a documented fund-recovery path, and padding on stored ciphertext. | BitChat Tor-by-default (Arti), triple-tap wipe, Noise padding buckets | Tor is **not shipped** ([reachability.md](../operations/reachability.md)). Wipe is **not built**. Padding is a mitigation only. |
| **M6** | **Reach from the BitChat world** | Identity export (option 1) and the paid gateway (option 2) live on signet. A BitChat user can pay to reach Rasmus. | BitChat's own reach: about 20 iOS releases and a three-surface footprint | **Not built.** |

Suggested order: M1, M3, M2, M4, M5, M6. M1 and M3 are the north star itself. M2 is the biggest gap against BitChat.

---

## (e) Open questions for the owner

1. **README wording.** Should line 3, "Bitcoin-anchored identity", be corrected to match the doctrine that keys are identity, with Bitcoin anchoring energy and admission? It is a one-line follow-up PR.
2. **Offline doctrine.** Is "carry now, admit on drain" the accepted reading of "no free first message" for offline and BLE delivery? Or is any offline carriage out of doctrine?
3. **Public lanes.** Does BitSov want any public or location channel analogue, which would be paid per post, or stay strictly 1:1 and rooms? BitChat's geohash channels are a large part of its pull.
4. **Cashu.** Should a Cashu token ever count toward admission, for example redeemed by the recipient's node before admitting? Or is Cashu permanently out? The current stance is "No Cashu default".
5. **Licence hygiene.** Confirm the "no copying from the GPL-3.0 Android repo" rule. Reading the Unlicense iOS code and the whitepaper is fine.
6. **Gateway operator.** If option 2 ships, who runs the gateway: each user's own node only, or a MindLink-run signet gateway under the charter?
7. **Panic wipe vs funds.** What should a wipe do to Lightning channel state and the encrypted SCB backups ([RECOVERY.md](../v2/RECOVERY.md))?
8. **Benchmark refresh.** Should this note be re-checked on BitChat's next releases? The current latest are iOS v1.7.1 and Android v2.0.3.

## Unverified or conflicting items

- `bitchat.free`, the App Store page and the Play Store page could not be fetched. Store metrics are omitted.
- The iOS v1.6.0 release notes list "prekey bundles", but WP v2.0, dated a day earlier, calls prekeys future work. Whether courier seals use prekeys is not verified.
- The iOS v1.5.4 notes say it "fixes security audit findings". The auditor is not identified in the sources fetched.
- BRING_THE_NOISE.md claims "identity hiding", while WP §8 says announces carry static keys in cleartext. This note follows the whitepaper.
- Trail of Bits and supernetworks commentary from July and August 2025 was not fetched. The original MitM report is [issue #64](https://github.com/permissionlesstech/bitchat/issues/64), which was closed on 2026-07-10.
