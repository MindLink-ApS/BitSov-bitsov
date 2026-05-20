# BitSov Operator-Tier Sovereignty Charter

> **Status:** Load-bearing governance document. Pinned to the wall.
> **Scope:** All BitSov operators running Tier-2 Relay infrastructure on behalf of other users — whether a solo operator with one VM or a future BitSov S.A. de C.V. with a thousand relays. The charter is the same.
> **Related:** [PRD.md](PRD.md) sovereignty tiers · [CURRENT_GAPS.md](CURRENT_GAPS.md) per-principle scoring · [`crates/konsensus-storage/src/encrypted.rs`](../../crates/konsensus-storage/src/encrypted.rs) at-rest encryption · [`crates/konsensus-node/src/config.rs`](../../crates/konsensus-node/src/config.rs) `NodeTier` enum

---

## 0. Preamble — Why This Document Exists

A user trusts BitSov with the most sovereign thing they own: the ability to speak privately. That trust is not granted by marketing copy. It is granted by what the BitSov stack architecturally **cannot do** to them, regardless of who runs the code, who owns the company, or who serves the subpoena.

Signal, iMessage, WhatsApp, and Telegram all begin every promise with "we won't." BitSov begins every promise with "we can't." The difference between "won't" and "can't" is the difference between a policy that decays under pressure and an architecture that does not bend.

This charter is the public, auditable, fork-triggering specification of what the BitSov operator can and cannot do. It applies identically to:

- A solo operator running a single Tier-2 relay for a circle of 30 friends
- A regional cooperative running 12 relays in El Salvador
- A future BitSov-the-company operating 1,000 relays across multiple jurisdictions

Scale does not soften the charter. The charter softens to no one.

---

## 1. The Cell Test (Architectural Model)

Cells in a multicellular organism trust each other only conditionally. They do not exchange cytoplasm. They expose **specific protein receptors** through their membrane, and only molecules with the correct shape pass through. Everything inside the membrane — the genome, the energy stores, the signaling machinery — is opaque to the rest of the organism.

A BitSov node is a cell. The Tier-2 relay operator is another cell that the user's cell has consented to bind with, in exchange for a metabolic service (message custody, store-and-forward, presence relay). The receptors the node-cell exposes to the operator-cell are narrow and contractual:

| Receptor (what the node lets the operator see) | What the operator gets |
|---|---|
| **Ciphertext envelope** | An opaque blob of bytes with a recipient `NodeId` |
| **Payment proof** | A Lightning preimage / payment hash that proves "this packet was paid for" |
| **Routing metadata** | The two `NodeId`s involved and a timestamp (necessary to forward the packet) |
| **Service heartbeat** | "I am online; here is my Lightning address for subscription payment" |
| **Hosting subscription state** | The operator's own ledger of who paid them what, when |

What the node-cell **never** signals to the operator-cell, because no receptor exists:

| Signal withheld | Why it cannot be read |
|---|---|
| **Message plaintext** | E2EE (PQXDH for 1:1, MLS for groups). The decryption key lives only on sender + receiver. |
| **Private keys / mnemonic** | Derived from a BIP-39 seed held only by the user. The operator has no derivation path. |
| **Conversation graph beyond directly-relayed traffic** | The operator sees only frames it personally relays; it cannot enumerate the user's full social graph. |
| **At-rest message content** | `EncryptedStorage` (AES-256-GCM) wraps `Storage` so even the operator's disk holds only ciphertext keyed to the user. |
| **Identity attestation** | The operator cannot sign as the user. The Ed25519 identity key never leaves the user's node. |

If a cell could rewrite the receptors of another cell from the outside, it would be a tumor, not an organ. The charter is the immune system: it defines which receptors are permitted to exist and rejects any new receptor that would breach the membrane.

---

## 2. Architectural Prohibitions

The hierarchy of guarantees, from strongest to weakest:

- **ARCHITECTURALLY EXCLUDED** — The codebase makes this impossible. Verifiable by reading open-source code. Survives founder turnover, acquisition, and subpoena. **This is the load-bearing differentiator.**
- **POLICY EXCLUDED** — The system permits the action; the operator pledges not to do it. Decays under sufficient pressure. Listed only where architecture cannot yet reach.

### 2.1 Reading message body content
- **ARCHITECTURALLY EXCLUDED.**
- E2EE is established between sender and recipient via PQXDH (1:1) or MLS (groups). The ciphertext field in `UkmEnvelope` is decryptable only by the recipient's private key, which never leaves the recipient's node. The operator sees `Vec<u8>` of opaque bytes.
- Defense-in-depth: `EncryptedStorage` (AES-256-GCM, keyed from the node identity) re-encrypts the already-encrypted ciphertext for at-rest storage, so even an operator with full disk access reads ciphertext-of-ciphertext.

### 2.2 Decrypting at request time (under subpoena, under duress, under acquisition)
- **ARCHITECTURALLY EXCLUDED.**
- The operator does not possess a decryption key for user message content. No code path exists that takes "operator authority" as an input and returns plaintext. There is no master key, no recovery key, no key-escrow channel. A subpoena served on the operator cannot be honored with plaintext because the operator's storage holds none.
- The only thing an operator can hand over is the ciphertext blob and the routing metadata it legitimately has. See §3.6.

### 2.3 Impersonating a user
- **ARCHITECTURALLY EXCLUDED.**
- User identity is an Ed25519 keypair derived from the BIP-39 mnemonic at the user's node (`IdentityConfig::mnemonic_file`). The operator never sees the mnemonic, never derives the key, and cannot forge a signature. Every outbound frame is signed by the sender's identity key; recipients verify signatures before accepting.
- An operator who tries to inject a frame "from" a user it relays for produces an invalid signature and the frame is rejected by every honest node.

### 2.4 Forging payment proofs
- **ARCHITECTURALLY EXCLUDED.**
- Payment proofs are Lightning preimages. A preimage exists only because the recipient's Lightning node generated an invoice and the sender's Lightning node paid it — a fact anchored in Bitcoin's economic substrate, not in any BitSov code. An operator cannot fabricate a preimage that hashes to a real invoice's payment hash without breaking SHA-256.
- The payment-gate verification (`fail-closed`, Principle 2) runs at the recipient node, not at the operator. An operator cannot mark a packet "paid" on the recipient's behalf.

### 2.5 Modifying messages in flight
- **ARCHITECTURALLY EXCLUDED.**
- Every `UkmEnvelope` is signed by the sender. The recipient verifies the signature. Any byte modification by the operator invalidates the signature and the frame is dropped. The operator can refuse to relay, delay relay, or drop a frame — but cannot alter content without the user knowing.

### 2.6 Suspending a specific user account (vs. ending the relay relationship)
- **ARCHITECTURALLY EXCLUDED in the strong sense; POLICY-BOUND in the weak sense.**
- There is no "account" the operator can suspend. The user owns their identity (Bitcoin-anchored keypair). The operator owns the *relay relationship* — a Lightning subscription. The operator can terminate the relay relationship (§3.4), but cannot suspend the user's identity, freeze their keys, or prevent them from using a different operator or running their own Tier-1 node.
- "Account suspension" as it exists at Signal/iMessage (the company controls the account; you go to their support to get it back) **does not exist** in BitSov. There is no support ticket for "unlock my BitSov account" because there is no BitSov account.

### 2.7 Censoring messages by content
- **ARCHITECTURALLY EXCLUDED.**
- The operator cannot read content (§2.1). It cannot filter, scan, classify, or report on what users say. Content-based censorship requires content access, and content access is excluded.
- The operator *can* observe traffic patterns (§3.2) and refuse to relay traffic from a specific peer for abuse reasons. This is censorship by **peer identity**, not by **content** — a categorically narrower power.

### 2.8 Recovering a user's mnemonic
- **ARCHITECTURALLY EXCLUDED.**
- The mnemonic is generated at the user's node and never transmitted. The operator has no copy, no escrow, no shard, no shadow derivation. If the user loses the mnemonic and has no other backup, the operator cannot help. This is the cost of sovereignty and is documented in §6.4 as the operator's hardest user-experience surface.

### 2.9 "Helping" a subpoenaing entity by surrendering decrypted data
- **ARCHITECTURALLY EXCLUDED.**
- An operator served with a subpoena demanding "all messages of user X" can produce:
  - Encrypted ciphertext blobs (useless without the recipient's private key)
  - Routing metadata it legitimately sees (sender NodeId, recipient NodeId, timestamp, size — the same metadata Tor exit nodes leak)
  - Lightning payment records to the operator's own subscription wallet
- The operator cannot produce plaintext because the operator does not possess plaintext. A demand for plaintext is a demand for an impossibility.

### 2.10 Selling user data to third parties
- **ARCHITECTURALLY EXCLUDED for content; POLICY EXCLUDED for metadata.**
- Content is excluded by E2EE. The operator literally has nothing of content-value to sell.
- Routing metadata exists and is monetizable in principle (it would be a graph of NodeIds and timestamps). The charter forbids sale of this metadata as a policy commitment, and §4.3 specifies the audit mechanism that lets users verify the commitment holds.

### 2.11 Building a content moderation backend
- **ARCHITECTURALLY EXCLUDED.**
- A content moderation pipeline requires plaintext access to messages, files, and media. No such access exists. An operator cannot build, ship, or contract out a content moderation product because there is no content to moderate. The product category does not exist in the BitSov stack.

### 2.12 Adding a "lawful intercept" backdoor without forking the protocol
- **ARCHITECTURALLY EXCLUDED.**
- Lawful intercept requires either (a) the operator holds a key, or (b) a master key exists in the protocol. Neither exists. Adding one would require a wire-incompatible protocol change rejected by every existing node (§5.3). A government cannot order BitSov to "turn on" what was never built.

---

## 3. Allowed Operator Actions

What the operator legitimately can do, and the constraints on each:

### 3.1 Reject a connection from a known-malicious actor
**Allowed.** The operator may refuse TCP/QUIC accepts, refuse Noise handshakes, or refuse to enter a relay subscription with a specific peer NodeId. Rejection is by **peer identity** or **transport-level signal** (IP rate, malformed handshake), never by message content (which is opaque). A rejected peer can freely connect to a different operator, run their own node, or join a Tier-1 mesh — rejection is local to this operator's relay, not a network-wide ban.

### 3.2 Rate-limit a peer flooding the mesh
**Allowed.** The operator may apply per-peer rate limits on:
- Connection attempts
- Frame relay requests
- Bandwidth consumption
- Storage of pending undelivered frames

Rate limits are based on observable metadata (frame count, byte count, connection frequency) — not on content. Limits must be published in the operator's service terms, so users know the parameters of the relay they are paying for.

### 3.3 Charge for the relay service
**Allowed.** The operator may charge a Lightning subscription (recurring) or per-frame (metered) for the relay service. The charge is denominated in sats, paid over Lightning, and recorded in the operator's local hosting-contract ledger (`OperatorHostingContract`, `OperatorHostingPayment` — see `EncryptedStorage` for the storage shape). Pricing must be disclosed in advance; no surprise charges.

### 3.4 Terminate the relay relationship with a specific user
**Allowed, with constraints.**
- **Notice period:** Minimum 30 days notice for routine termination (capacity, business decision, no fault). Minimum 7 days notice for stated cause (abuse pattern, non-payment, terms violation). Zero notice is permitted only for emergency response to active network attack (DDoS amplification, mass spam) and must be followed by a written explanation within 72 hours.
- **Migration assistance:** The operator must, on request, hand the departing user the bundle of frames currently held in their pending-delivery queue and a signed attestation of frames relayed in the last 30 days (so the user can reconcile with their counterparties). The operator cannot withhold a user's queued messages as a termination penalty.
- **No identity destruction:** Termination ends the *relay subscription*. The user's identity, channels, history, and federation trust are unaffected (§4.1).

### 3.5 Refuse to onboard a new user
**Allowed.** An operator at capacity, in a regulated jurisdiction with KYC obligations they will not meet for a particular jurisdiction's residents, or with a closed-cohort business model (e.g., "this relay serves only members of cooperative X") may refuse onboarding. Refusal must state a reason from a published list, not an arbitrary case-by-case judgment.

### 3.6 Decommission a relay entirely
**Allowed, with the same notice constraints as §3.4 applied to all subscribers.** A decommission notice must include:
- A list of recommended alternative operators (or the statement "we recommend self-hosting Tier-1")
- A migration window of at least 30 days during which the relay continues to operate
- An offer to hand each subscriber their queued frames and 30-day attestation

### 3.7 Cooperate with lawful process regarding metadata it legitimately sees
**Allowed and unavoidable.** An operator served with valid legal process in its jurisdiction may surrender:
- The ciphertext blobs it holds (uselessly opaque to the requester)
- The routing metadata it has logged (NodeId pairs, timestamps, sizes)
- The operator's own Lightning subscription payment records

The operator **cannot** surrender what it does not have: plaintext content, private keys, mnemonics, or content-derived data. The operator must publish a transparency report (§4.4) enumerating the legal processes it received and the categories of data surrendered, redacted to comply with gag orders but with the **count** always reported.

### 3.8 Monitor service health
**Allowed.** Connection counts, queue depths, disk usage of held ciphertext, latency, payment-routing revenue, error rates, uptime — all permitted. These are the metabolic vital signs of the operator's own cell, not signals from the user's cell.

### 3.9 Detect abuse patterns from metadata
**Allowed.** Anomaly detection on connection frequency, frame rate, byte rate, error rate, and pending-queue saturation is permitted. The operator may act on metadata signals (rate limit, throttle, terminate per §3.4) without inspecting content.

---

## 4. User Protections (Inalienable)

A user binding to a Tier-2 relay does not surrender any of the following, regardless of operator policy:

### 4.1 Exit the operator relationship
The user can at any time, without operator consent:
- Migrate to a different Tier-2 operator
- Run their own Tier-1 light node
- Run a Tier-Full sovereign node
- Disable Tier-2 entirely and operate purely peer-to-peer

What survives migration:
- **Identity** — the BIP-39 mnemonic and derived Ed25519 / Bitcoin keys
- **Lightning channels** — channel state is on-chain; the operator was never a custodian
- **Federation trust** — whitelist entries the user has authorized
- **Conversation history** — held on the user's own device(s), not on the operator's relay
- **Counterparty relationships** — peers identified by NodeId, portable across operators

What does not survive:
- The hosting subscription (it was a contract with that specific operator and ends at migration)
- Queued frames the operator was holding for the user (§3.4 requires the operator to hand these over on termination)

### 4.2 Run multiple relays simultaneously
A user can subscribe to multiple Tier-2 operators concurrently for redundancy. The protocol does not bind a user to a single operator. Failover between relays is automatic. No operator can prevent this.

### 4.3 Inspect what the operator sees
The operator must expose a signed transparency endpoint that, on user request, returns:
- The list of frames currently queued for the user (count, sender NodeId, size, age — **never content**)
- The 30-day rolling log of frames relayed for the user (same fields, redacted to recent counterparties)
- The current subscription state (paid through date, last payment hash)

This endpoint is rate-limited but always available to the authenticated subscriber. It is the user's right to audit what their operator is observing about them.

### 4.4 Audit the relay's behavior against this charter
- The operator must publish a quarterly transparency report enumerating:
  - Legal process count (received, complied, refused on grounds of illegality)
  - Categories of data surrendered (always: ciphertext + metadata; never: plaintext or keys)
  - Termination count and reason categories
  - Onboarding refusal count
- The operator must publish a **warrant canary** that affirms (via signed timestamped statement) the absence of secret legal compulsion. Disappearance of the canary is a public signal.
- The open-source codebase is the ground truth for what the operator *can* do. Anyone can read `crates/konsensus-storage/src/encrypted.rs` and verify the operator cannot decrypt.

### 4.5 Run a Tier-1 light node alongside a Tier-2 subscription
A user can keep their identity rooted on a personal Tier-1 node and use Tier-2 relays only for store-and-forward when their personal node is offline. This is the recommended posture for users who want maximum sovereignty without 24/7 uptime obligations. The architecture supports it natively.

---

## 5. The Differentiation Moment (Marketing-Honest)

This section evaluates the public claims a BitSov user is entitled to make, and the architectural conditions under which each is true. Claims marked **TRUE** are statements a user can make about BitSov that they cannot honestly make about Signal, iMessage, WhatsApp, or Telegram.

### 5.1 "Even if BitSov-the-operator wanted to read my messages, they architecturally cannot."
**TRUE.** E2EE (§2.1) plus AES-256-GCM at-rest re-encryption (§2.1) means the operator's storage and runtime hold ciphertext-only. A change to this would require shipping a wire-incompatible protocol that every recipient node would reject. Compare: Signal *won't* but their server software could be modified to log plaintext from sealed-sender failures or to MITM key changes; iMessage's iCloud backup default exposes plaintext to Apple.

### 5.2 "If BitSov-the-operator gets subpoenaed, they have nothing decryptable to surrender."
**TRUE.** §2.9. The operator can surrender ciphertext and metadata. Compare: Signal can surrender phone number + last-connect timestamp (famously little, but non-zero); iMessage can surrender iCloud-backed plaintext when iCloud Backup is on, which is the default; WhatsApp surrenders metadata extensively and on-by-default cloud backups expose content; Telegram default chats are server-readable.

### 5.3 "If BitSov-the-operator deplatforms me, my identity, channels, and history are intact and I can take them to a different operator."
**TRUE.** §4.1 enumerates what survives. The operator cannot revoke the user's keys, freeze their Lightning channels (which are on-chain bilateral contracts the operator was never a party to), or hold their conversation history hostage (which is on the user's device). Compare: Signal deplatforming is rare but irreversible at the protocol level (your Signal identity is your phone number, which Signal controls registration of); iMessage deplatforming via Apple ID loss is catastrophic; WhatsApp number bans destroy the account.

### 5.4 "I never have to trust BitSov-the-operator with anything more than 'please hold this encrypted blob for the recipient.'"
**TRUE.** The trust surface to the operator is: relay encrypted blobs, settle Lightning subscription. Compare: Signal trust surface is sealed-sender correctness + key-transparency honesty + server software fidelity; iMessage trust surface is the entire Apple ID stack.

### 5.5 "BitSov-the-company cannot ship a Tier-3 custodial product next quarter under financial pressure."
**TRUE** under the governance encoding of §6. The codebase contains no key-escrow primitive, no operator-held user-key path, no decryptable-by-operator storage. Adding these would require a fork-the-project trigger that the charter encodes as a public commitment (§6). Compare: every centralized messenger could pivot to broader data collection with a software update; BitSov cannot, because the architectural primitives that would enable Tier-3 are absent and their introduction is governance-blocked.

### 5.6 Claims **NOT** made — honest limits

Statements a BitSov user **should not** make, because they are not architecturally guaranteed at Tier-2:

- "My operator does not know who I'm talking to." **FALSE.** The Tier-2 operator sees routing metadata: NodeId pairs and timestamps for frames it relays. This is unavoidable at Tier-2 — the operator must read the recipient NodeId to route the frame. Mitigation: run Tier-1 yourself for maximum metadata privacy, or layer Tor as a transport (planned).
- "My operator cannot tell when I am online." **FALSE.** Subscription heartbeat and connection state are observable. Mitigation: same as above.
- "My messages are guaranteed delivered even if my operator goes offline." **FALSE.** A single-operator subscription has a single point of failure. Mitigation: subscribe to multiple operators (§4.2) or run Tier-1.

The charter's strength is that the honest limits are narrow, well-specified, and operator-neutral. The dishonest claims that Signal/iMessage/WhatsApp can be quietly forced to make (because the architecture permits the abuse) are claims BitSov is permanently spared from.

---

## 6. The Hard-Line Commitment: No Tier-3 Custodial Hosting, Ever

BitSov will **never** offer a "Tier-3" product in which the operator holds the user's identity keys, mnemonic, or decryption keys. This commitment is not a marketing pledge. It is encoded at four levels, each more pressure-resistant than the last:

### 6.1 Architectural encoding
- The `NodeTier` enum in `crates/konsensus-node/src/config.rs` admits only `Cloud`, `Light`, `Full`. There is no `Custodial` variant. Adding one is a breaking codebase change, not a configuration flip.
- `IdentityConfig::mnemonic_file` is read by the local node process only. There is no API endpoint, no protocol message, no storage primitive that accepts a user's mnemonic from a remote source. An operator wanting to ingest user mnemonics would have to write that code from scratch and ship it in a fork.
- `EncryptedStorage` derives its AES key from the **node's** identity (`NodeIdentity::aes_key()`). There is no key-derivation path that produces an operator-readable user-specific key.

### 6.2 Open-source auditability
- The repository is public. Anyone can read the codebase and verify the absence of custodial primitives. A pull request that introduces a custodial primitive is a publicly visible signal of charter violation.
- CI checks (to be added as governance hook): any PR that adds a method matching the signature pattern `fn .*operator.*decrypt.*` or `fn .*custody.*key.*` requires explicit charter-board review and a public RFC.

### 6.3 Governance / constitutional encoding
- This charter is a load-bearing project document. Modification requires:
  - A public RFC with minimum 30-day comment period
  - Approval by a charter board that includes at least one founder, one independent technical reviewer with no employment relationship to the project, and one user representative selected from active subscribers
  - A signed commit referencing the RFC in the merge message
- The charter is published with a cryptographic hash in node release notes. Nodes can verify they are running a charter-compliant release by checking the hash against the published canonical document.

### 6.4 Fork-the-project trigger
- If BitSov-the-company (current or future incarnation) ships, attempts to ship, or is credibly reported to ship a custodial Tier-3 product in violation of this charter:
  - The project's MIT/Apache license permits any user, employee, or third party to fork the codebase, publish it under the BitSov-Sovereign name, and route the existing federation whitelist to the fork.
  - The Five Immutable Principles are public; the fork inherits them.
  - The charter board is empowered (and morally obligated) to publish a "successor project" designation that the existing user base can migrate to.
- This is the ultimate pressure-resistance: if BitSov-the-company is acquired by a hostile entity, regulated into compliance, or financially coerced into custody, the user base and the technical community can move to a fork that honors the charter, taking their identities and channels with them (per §4.1). The brand can be captured; the protocol cannot.

The four layers operate in series. A hostile actor who wants to deliver custodial BitSov must defeat: the absence of code primitives, the visibility of open source, the governance veto, and the fork option. Defeating all four is harder than building a new product from scratch — which is the point.

---

## 7. Operational Implications (Day in the Life of an Operator)

What the operator's monitoring dashboard looks like, what their support inbox looks like, what their abuse handling looks like.

### 7.1 What the operator CAN monitor
- Total connections, per-peer connection rate, transport-level handshake failures
- Frame relay throughput (count, bytes), pending-queue depth per recipient
- Disk usage of `EncryptedStorage` (ciphertext, growing over time)
- Lightning subscription revenue, churn rate, payment failures
- Service latency: median, p95, p99 for frame relay
- Federation health: which peers are reachable, signature verification failures
- Per-tier counts: how many Light vs Full subscribers
- Bitcoin chain health: `ChainProvider` query latency, fee rate (used by chain-aware pricing)

### 7.2 What the operator CAN'T monitor
- Message content (any kind, ever)
- File content, file names (encrypted at rest per `encrypt_file_record`), MIME types
- Calendar event titles, attendee identities (encrypted at rest per `CalendarEventRecord` pass-through layered with E2EE)
- Room names beyond those for rooms the operator's node is itself a member of (`encrypt_room`)
- Peer display names of subscribers' counterparties (`encrypt_peer`)
- Full conversation graph — only the subset of NodeId pairs whose frames pass through this operator's relay
- Cross-relay correlation — the operator cannot learn what their subscriber does with other relays

### 7.3 Abuse handling without content access
The operator's abuse model is **pattern-on-metadata, never-content**:
- **Spam detection:** Sustained high frame rate to many distinct recipients from a single sender NodeId. Action: rate limit, then terminate per §3.4 with stated cause.
- **DDoS amplification:** Bursts of identical-size frames or connection storms. Action: transport-level block, then identity-level termination.
- **Non-payment:** Subscription lapsed past grace period. Action: standard termination per §3.4 routine path.
- **Reported abuse from a counterparty:** A counterparty reports "user X is harassing me." The operator **cannot verify the content of the alleged harassment.** The operator's response options are:
  1. Provide the reporter with the BitSov-protocol-native blocking mechanism (the reporter removes user X from their federation whitelist; user X's frames stop reaching them). This is the **preferred response** because it does not require the operator to act as judge.
  2. If the report is corroborated by metadata signals (sustained one-way frame flow despite block, repeated subscription churn to evade), the operator may apply §3.4 termination with stated cause.
  3. The operator does **not** investigate content, request screenshots, or arbitrate disputes. This is unfamiliar to operators trained on centralized-platform moderation, and it is correct.

### 7.4 The "I forgot my mnemonic" support case
The hardest user conversation an operator has. Script:

> User: "I've lost my mnemonic. Can you help me recover my account?"
>
> Operator: "I'm sorry — no. Your BitSov identity is generated and held only on your device. We never had a copy of your mnemonic. There is no recovery channel because there is no place we could have stored it. This is the cost of sovereignty: we cannot read your messages, surveil your contacts, or surrender your identity to a subpoena, *and* we cannot recover your account. If you have a paper or steel backup, retrieve it now. If you do not, your previous identity is unrecoverable. You can generate a new identity, but you will need to re-establish federation trust with your counterparties from scratch."

This is brutal. It is also the only honest answer compatible with the rest of the charter. Every recovery mechanism we could offer is a backdoor we would have to defend against subpoenas, hostile employees, and acquisition pressure. The user retains sole custody; we retain none.

Operators should publish a strongly-worded **backup-your-mnemonic** onboarding flow with multiple touchpoints (write it down, photograph the steel backup, verify the words by re-entry) before the user starts depositing real value. The cost of one lost-mnemonic conversation justifies an aggressive backup UX.

### 7.5 What the support inbox looks like
| Common ticket | Operator response |
|---|---|
| "My messages aren't delivering." | Check peer reachability, subscription state, federation whitelist — all visible at metadata level. |
| "How do I add a contact?" | Walk through invite/whitelist flow. No operator action required. |
| "Can you tell me what user X said?" | "No. We do not have access to message content. This applies to all messages, all users, all subpoenas." |
| "Can you ban user X for me?" | "Use your federation block. If they're abusing the relay as a whole, file an abuse report with metadata evidence — repeated unsolicited frames, etc." |
| "I forgot my mnemonic." | See §7.4. |
| "I want to leave this relay." | Walk through migration: confirm 30-day notice equivalent is not needed (user-initiated exits are immediate), hand over queued frames, sign 30-day attestation, void remaining subscription pro-rata. |
| "I want to switch from Light to Full tier." | The user runs `konsensus migrate --tier full` locally; the operator's role is to gracefully terminate the subscription when the user no longer needs it. Identity, channels, history are unaffected. |

---

## 8. Scale Invariance

This charter applies identically at every operator scale. A solo operator running one Tier-2 relay for friends is bound by §2 architectural prohibitions, §3 allowed actions, §4 user protections, §5 honest claims, §6 the hard-line commitment, and §7 operational discipline. A BitSov-the-company running 1,000 relays is bound by the **same** sections, with the same words.

What scales:
- Operational tooling (one operator = manual; 1,000 = automation)
- Legal exposure (one jurisdiction = simple; 50 = compliance staff)
- Transparency report effort (small subscriber base = single page; large = structured publication)

What does **not** scale and does **not** change:
- Architectural prohibitions
- User protections
- Charter modification process

A charter that softened at scale would become a marketing artifact rather than a sovereignty guarantee. The charter does not soften. It is the same on the wall of the solo operator's home office as it is on the wall of the boardroom of any future BitSov entity.

---

## 9. Signatures and Adoption

This charter takes effect upon merge to `main` of `docs/v2/OPERATOR_SOVEREIGNTY_CHARTER.md`. Every operator running a Tier-2 BitSov relay is expected to publish a link to this canonical document and a signed statement of adoption. The signed statement attests:

1. The operator has read the charter.
2. The operator's deployment matches the charter (architectural prohibitions are in force because the operator is running unmodified open-source `konsensus` binaries at a release hash listed in §6.3).
3. The operator agrees to the policy commitments (§2.10 metadata non-sale, §3 notice periods, §4 user protections, §7 abuse handling discipline).
4. The operator commits to publishing a quarterly transparency report (§4.4) and maintaining a warrant canary.

Failure to adopt is not enforced by code — the protocol federates regardless. Failure to adopt **is** enforced by the user base: a non-adopting operator publishes by its silence that it does not bind itself to these constraints, and users can choose accordingly.

---

## Appendix A — Receptor Inventory

Quick reference: every receptor the user-node-cell exposes to the operator-cell, with the file that defines it.

| Receptor | Definition | Cell-test verdict |
|---|---|---|
| Ciphertext relay (`UkmEnvelope.ciphertext`) | `crates/konsensus-core/src/...` (UKM envelope) | Permitted — opaque payload |
| Recipient routing (`UkmEnvelope.recipient`) | Same | Permitted — minimum-required routing info |
| Payment proof (`UkmEnvelope.payment_proof`) | Same | Permitted — economic gate enforcement |
| Hosting subscription state | `OperatorHostingContract` / `OperatorHostingPayment` in `crates/konsensus-core/` | Permitted — operator's own ledger |
| At-rest blob storage | `crates/konsensus-storage/src/encrypted.rs` `Storage::store_message` | Permitted — operator stores ciphertext |
| Per-peer pending queue | `queue_pending_delivery` in same file | Permitted — store-and-forward primitive |
| Message plaintext | — | **No receptor exists. Architecturally excluded.** |
| Mnemonic / identity key | — | **No receptor exists. Architecturally excluded.** |
| Cross-relay correlation | — | **No receptor exists. Architecturally excluded.** |

---

## Appendix B — Verification Checklist for a New Operator

Before going live:

- [ ] Running an unmodified `konsensus` binary from a release hash listed in the charter's compatible-version manifest.
- [ ] `StorageConfig.encrypted = true` for Tier-2 deployment.
- [ ] `NodeTier` in config is `Cloud`, `Light`, or `Full`. (There is no Tier-3 variant; if a fork has added one, the operator is no longer charter-compliant.)
- [ ] Transparency endpoint (§4.3) is reachable and tested.
- [ ] Warrant canary published with the operator's identity signature.
- [ ] Termination notice templates aligned with §3.4 minimums.
- [ ] Onboarding flow includes mandatory mnemonic-backup verification (§7.4).
- [ ] Support staff trained on §7 abuse handling — pattern-on-metadata, never-content.
- [ ] Charter adoption statement signed and published.

---

*This document is the wall-tape charter. If a future decision drifts from it, the document does not bend; the decision is wrong and must be revised. The charter holds at one operator and at one thousand. The charter holds under pressure. The charter holds.*
