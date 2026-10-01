# BitSov design reasoning

Status: conceptual anchor, 1 Oct 2026. It argues *why* the system is shaped as it is. The specs say *how*. Nothing here is a spec, and nothing here is marketing.

## 0. How to use this doc

Read it before touching BitSov. Order of authority: whitepaper (WP) → this doc → specs (`docs/protocol/`, `docs/v2/`, ADRs) → code. The lower layer may add detail; it may never contradict the higher one.
When two layers disagree, or a task needs what §5 refuses: stop, write the conflict down (PR or issue), and flag it. Do not build around it.
Sources: WP = `Konsensus_v02/docs/v2/whitepaper/BitSov_Whitepaper_DRAFT.tex`; V/BIO = `Konsensus_v02/docs/vision/`; OSC = `Konsensus_v02/docs/v2/OPERATOR_SOVEREIGNTY_CHARTER.md`; ADR-032/034/036 = `Konsensus_v02/docs/v2/`; NS/DEC/RL = `MindLink-Private/pm/` (BITSOV-NORTHSTAR, DECISIONS, research/RELATION-LADDER-AND-DEVICE-KEYS). Status words: BUILT / PROPOSAL / RESERVED, checked against `origin/main` a1c1b74 where `git grep` can tell.

## 1. First premises

- **P1. "Free" means selling the user.** When sending costs nothing, the network cannot be funded by senders, so it is funded by selling the receiver. The same asymmetry makes spam, Sybil floods and deplatforming possible. (WP §1, NS, BROWSE.md §3)
- **P2. Payment is the connection.** No service without settlement. Admission is a settled, recipient-bound, single-use payment, re-proven per act. The rule is not "no byte without sats": the bytes that carry a proof must arrive first. (WP §2, NS)
- **P3. Bitcoin anchors energy and admission, never identity or the social graph.** The timechain is truth for one thing: the irreversible movement of value. A registry or graph on it is "the surveillance trap". (WP §3, ACCOUNT-LAYER.md intro)
- **P4. BTC is ATP.** Work costs energy; identity is not stored in the energy. The signal costs ATP; the neuron is not made of it. (WP §3, BIO-ATP §1.1)
- **P5. Keys are identity and truth.** No account, no registration, no namespace authority. A lost seed is a lost identity: "peers restore memory, never identity". (WP §4-5, V01 principle 1)
- **P6. The node is the sovereign unit** and the backend of your digital life. The node, not a platform, holds every relationship. (WP abstract, NS, V01 §1.3)
- **P7. "Can't", not "won't".** A guarantee is architectural or it is not a guarantee. Policy decays under pressure; code that lacks the capability does not. (OSC §0, §2)
- **P8. Honesty and claim discipline.** Never claim location privacy, relay or scale as shipped. "Architecture-novel, not primitive-novel." No absolutes. (NS, WP header, WP §6-8)

## 2. Derived principles

- **No persistent admission object** (P2). Authorization is a continuously re-proven economic event, not a durable grant that can be seized, sold or administered. (WP §8)
- **"Paid once, therefore related forever" is rejected** (P2, P3). A relationship is the flux of settlements that sustain it, like a synapse. (WP §8)
- **"Whitelist" is split six ways** (P2, P5): keys (identity), contacts (private knowledge), invite-only (local policy), admission proof, scoped capability, Lightning channel. None may collapse into one list. (WP §4.3, NS)
- **Three-line acceptance test** (P2): anyone may know an endpoint; anyone may offer payment; work happens only against settlement. (WP §2)
- **Payment caps spam and pays the victim** (P1, P2). A flood is self-defeating because its cost lands in the target's wallet. (WP §2, BROWSE.md §3, ADR-036 §1)
- **Energy-proportional contact** (P4): the synaptic tier (Lightning, built) for ordinary work; the genomic tier (on-chain, not built) for high-finality commitments. (WP §3)
- **No global graph** (P3): no registry, DHT or compiled-in bootstrap list; channels unannounced. (WP §6.1)
- **A bounded doorway, not a wall** (P2, P8). Pre-payment DoS cannot be eliminated; the free surface shrinks to an unprivileged quarantine. (WP §6.2)
- **Abuse is signed local evidence, never a global blacklist** (P3, P5). The moment reports become global truth, platform moderation is rebuilt. (WP §7)
- **Relationship data lives in local vaults** (P1, P6). Central aggregation is data brokerage. (WP §7)
- **Identity and money share a backup; never say "ID is money"** (P3, P5). Keys are domain-separated from one seed. (ACCOUNT-LAYER.md §1, RL)
- **Every act is paid, human or AI** (P2). Paid bootstrap and paid sessions were rejected. (DEC 28 Sep)
- **The node is the authority; every AI is an untrusted client** (P6). "No purchase buys better node treatment." (DEC 25 Sep)
- **Retail sovereignty first** (P6, P8). A normal person needs a sovereignty floor, not a frontier model; safe presets beat per-request approvals. (DEC 25 Sep, NS)

## 3. The protocol, unpacked

Each item: Decision → Why → Rejected → Spec → Biology → Status.

### 3.1 Identity and keys
- Decision: one BIP-39 seed; blake3 domain-separated keys (node id Ed25519, transport X25519, storage AES, LN/on-chain, owner-approval from seed + typed password). NodeId is the mesh identity; IP is reachability only. Apps are paired devices with Secure Enclave keys registered by an owner-approval signature. The public profile is a signed front-door card; names are local petnames.
- Why: P5 (keys are identity), P3 (no registry). The owner key needs the password because a same-user process that reads a plaintext seed could otherwise forge device records.
- Rejected: accounts and passwords; IP as login; a global name registry (Zooko); "seed = ID = money"; social-recovery quorums ("identity-theft surface", WP §5); trusting a "biometric passed" flag; pairing rooted in reading `data_dir` (still a GAP).
- Spec: `docs/protocol/ACCOUNT-LAYER.md`, `docs/security/device-keys.md`, `docs/security/pairing.md`.
- Biology: the key pair is the membrane; the private key is selective permeability (BIO-MEM §2.1).
- Status: BUILT (keys, device keys, card). Node-key rotation and pairwise LN identities: PROPOSAL.

### 3.2 Admission and payment per act
- Decision: the gate checks integrity → freshness → signature → nonce → price → optional list ("not the authority") → recipient-bound settlement → payment-hash replay, fail-closed. First contact (F1) is a narrow, stateless, signed, 60 s quote plus invoice for strangers. Budgets authorize spending; every act is still paid. Quoted re-admission at most once per connection generation.
- Why: P2. Settlement, not stored state, is the authority, re-derived per unit of work.
- Rejected: free control messages (typing, receipts); paid sessions or bootstrap; external invoicing gateways; a stateful invoice fallback for strangers; the allow-list as authority.
- Spec: WP §4.2; `docs/v2/F1-CAPPED-FIRST-CONTACT.md`; `docs/v2/ALL-IN-FEE-CAPS.md`; `docs/SPEND_BUDGET_GRANTS.md`; `docs/v2/UNIFIED_PROTOCOL.md` "Exceptions to Payment".
- Biology: the ATP-powered energy gate; anyone with the right key-shape who spends the energy crosses (ADR-036).
- Status: BUILT (gate, F1 `stateless_quote_unsupported`, caps). Quoted re-admission (#111): PROPOSAL, revived 29 Sep.

### 3.3 Relations: ladder and plasticity
- Decision: four rungs, Knock / Contact / Close / Anchored, on rails routed → routed → direct private channel → on-chain. One signed `RelationIntent` per relation, with `level` fixed now. Plasticity: potentiation and decay from energy and traffic, computed locally, never published.
- Why: P2 and P3. Trust is earned by paid history; closeness is a private, local fact.
- Rejected: "the social graph and the liquidity graph become one" (withdrawn, RL); a public trust graph; gossiped Close channels; global blocking; whitelist-as-trust. Plasticity is a routing and price signal, never legal trust or KYC; agreements may read it, outcomes never write back (ADR-028).
- Spec: RL; `docs/protocol/ACCOUNT-LAYER.md` §4; `Konsensus_v02/docs/v2/ADR-028-agreements-layer.md`.
- Biology: a relation is a synapse; plasticity is synaptic-weight homeostasis, with a 50 % discount cap.
- Status: BUILT (`level` in RelationIntent; `SynapticWeight` discount in `konsensus-pricing`). Close/Anchored rails and ladder movement: PROPOSAL.

### 3.4 Transport and relay (store-and-forward)
- Decision: one envelope format (UKM) over Noise; the `kind` is the receptor. A ciphertext-only relay tier is a proposal; the engine is inert and off by default. An operator may refuse by peer identity, never by content, and a user exits with identity, channels and history intact.
- Why: P6, P7, P8. A relay leaks twelve metadata classes, the social graph loudest, so it stays a proposal until padding, multi-relay fan-out, a 24 h retention ceiling and no FCM/APNS in core exist.
- Rejected: legacy protocols in core (bridges live edge-only); a full Sphinx mixnet (latency); the operator as the user's only LN hop; contractual rather than cryptographic prohibitions.
- Spec: `docs/v2/UNIFIED_PROTOCOL.md`; `docs/v2/RELAY_PROTOCOL.md`; `docs/v2/THREAT_MODEL_TIER2_RELAY.md`; OSC §3-4.
- Biology: the relay is a phagocyte, not the cell; it "leaks 11 metadata classes a cell does not".
- Status: transport BUILT. Relay PROPOSAL; `RelayEngine` exists with `RelayPolicy::inert_default()`, advertisement OFF by default.

### 3.5 Pricing (ADR-027's three names)
- Decision: three names, never bare "timechain pricing": *chain-aware message pricing* (core, per-kind msat adjusted to fee rate); *timechain contract pricing* (outside core, `konsensus-agreements`); *ChainBridge Flywheel* (business, never in core). Floors: 1 sat per act (`htlc_minimum_msat`), routing-fee ceiling min(max(5,000 msat, 1 %), 10,000 msat).
- Why: P4. Contract pricing "has no clean biological anchor" and belongs outside the cell membrane. Routing fees and dust, not protocol design, set the real floor (WP §6.3).
- Rejected: one conflated pricing engine; sub-floor prices presented as solved.
- Spec: `docs/v2/ADR-027-pricing-terminology.md`; `docs/v2/ALL-IN-FEE-CAPS.md`; BROWSE.md §3.
- Biology: fee rate is ambient ATP availability; per-message msat is ATP per operation.
- Status: message pricing and fee caps BUILT. Agreements layer RESERVED (ADR-028, deferred).

### 3.6 Chain source tiers
- Decision: the user chooses per node: Neutrino (compact block filters), Electrum (headers verified locally), or Bitcoin Core (pruned or full). Hosted VMs run pruned Core. The chain source is local and does not affect node-to-node connectivity.
- Why: P3. A public Esplora sees which outputs a node watches, including private channel funding, tied to its IP: it leaks the channel graph.
- Rejected: public Esplora as the default (kept for dev only, labelled "third-party chain view"); paying a friend's node per query (payment buys admission, not privacy).
- Spec: `docs/v2/ARCHITECTURE.md` §2.1; DEC 1 Oct.
- Biology: a cell does not let a neighbour count its ATP transactions.
- Status: PROPOSAL. `origin/main` has only `esplora` and `mock`; Neutrino and Electrum are marked "planned".

### 3.7 Calls and meetings
- Decision: media is direct WebRTC between apps (STUN only, no TURN); signalling is four paid UKM kinds 400-403; the offer is the per-call admission at the callee's `call_msat`; nothing in a call is pre-authorized. A meeting is ordinary 1:1 calls with a `meeting` field.
- Why: P2 (every act paid), P6 (media never touches a third party). The unpaid signalling lane was a gate bypass and is closed.
- Rejected: a free signalling frame family (legacy `Call*` frames are dropped); per-minute billing for direct media; relayed media.
- Spec: `docs/v2/CALLS-PROTOTYPE.md`.
- Biology: electrical signalling (action potentials) is the one modality that is physically different from chemical signalling (UNIFIED_PROTOCOL §2).
- Status: BUILT as a prototype, regtest only; mainnet after review.

### 3.8 Rooms
- Decision: a fixed roster of 2-4 nodes, no new wire kinds, a room binding inside the ordinary E2EE chat plaintext, the id commits to the roster, the sender pays each member via the 1:1 path, pairwise ratchets. A room never pays a first contact.
- Why: P2, P3, P5. A creator-signed roster is a back-door authority; epochs create partitions and disclosure bugs; observers see paid 1:1 chats, not a room.
- Rejected: the #152 design (epochs, signed rosters, kinds 910-914, kick, scribe); MLS; history sync; room links.
- Spec: `docs/protocol/ROOMS.md` on `feat/rooms-mvp` (a915182); `MindLink-Private/pm/projects/bitsov/research/ROOMS-MVP-SYNTHESIS.md`.
- Biology: a tissue is a bounded group of cells with shared recognition, not a new organ.
- Status: PROPOSAL. Not on `origin/main`; main still carries a legacy rooms path (`Recipient::Room` compose, admin-only REST) that the MVP says to remove or keep as a local cache only.

### 3.9 Browse
- Decision: doorstep (the signed card) is free; porch reads cost 1 sat each, settled before the answer; the house is at normal prices. A node id resolves only from a saved contact or a card you hold.
- Why: P1, P2. A free read is "a wall with a hole in it"; node ids are free to mint, so only payment limits a Sybil; free reads recreate scraping, which is "free = sell the user".
- Rejected: free reads; per-IP limits (punish NAT and Tor); DHT, directory, gossip or name registry; remote HTML or scripts; stranger reads without a Knock (needs an ADR).
- Spec: `docs/protocol/BROWSE.md`.
- Biology: the card travels free because it costs the cell nothing; a read makes the cell work, so it costs ATP.
- Status: BUILT v1 (`porch_read_v1`). Media, card relay, persistent cache, app view: GAP.

### 3.10 Remote access and remote signer
- Decision: remote access is a Noise_XX tunnel to the existing API, closed by default, pinned node keys, plaintext HTTP never non-loopback, `/auth/local` unmounted. It adds "no TLS, relay, remote signer, new auth system". The remote signer keeps seed and owner keys on owner hardware; the node asks it for every signature that moves money or speaks for the owner. Lightning signing goes through VLS, not a home-grown policy engine.
- Why: P5, P7. "A node that holds its own seed can spend… Whoever controls the machine… can do the same."
- Rejected: "encrypted on the VM" as a third option (the operator can read memory); a home-grown signing policy engine; handing the seed to the VM operator as an offline workaround.
- Spec: `docs/protocol/REMOTE-ACCESS.md`; `docs/protocol/REMOTE-SIGNER.md` §3-5.
- Biology: the membrane control (private key) must stay inside the cell that owns it.
- Status: remote access BUILT (v1). Signer protocol RESERVED; `no_config_claims_a_remote_signer` is a test on main.

### 3.11 Custody tiers
- Decision: the node reports one `custody_mode`: `local_seed`, `encrypted_seed`, `hosted_custody`, `money_signer`, `remote_signer`. The app shows it as a badge and may only strengthen the label; a loopback URL is not proof of local provenance. The charter forbids any product where an operator holds a mnemonic, identity, device, spend or decryption keys: "reject or fork".
- Why: P7, P8. The Cloud tier promise ("must not hold user keys") is false until a signer exists, so the label makes it visibly not true.
- Rejected: operator-decrypts-mnemonic provisioning (ADR-032, charter-rejected); shared wallets with sub-balances; a paid entitlement that revokes identity, export or self-host.
- Spec: `CHARTER.md`; `docs/protocol/REMOTE-SIGNER.md` §2, §6; `Konsensus_v02/docs/v2/ADR-034*.md`; `docs/v2/TIER_MIGRATION_PROTOCOL.md`.
- Biology: the Cell Test: an operator is another cell bound by receptors; no cytoplasm exchange.
- Status: labels BUILT (`custody_mode` in `/status`). Signer modes RESERVED. See T1.

### 3.12 Recovery and backups
- Decision: keys are truth; the seed recovers identity and money, a separate user-owned export key recovers contacts and settings, and peers may rebuild shared context around a new key, never identity. Channel-state (SCB) export exists; restore force-closes from a snapshot.
- Why: P5. The #157 lesson: a channel snapshot older than the channel is a revoked-state weapon pointed at yourself. **Never broadcast state from a possibly stale backup.**
- Rejected: social-recovery quorums; custodial recovery; "back up channel state with a friend, paid per KB-day" (remote copies are always behind, so it makes #157 worse).
- Spec: `docs/v2/RECOVERY.md`; WP §5; `MindLink-Private/pm/projects/bitsov/research/umbrel/FOOL-DIALECTIC-01OCT.md` C3.
- Biology: peers restore memory, never identity; the genome is not reconstructed from a neighbour.
- Status: SCB export BUILT; restore is CLI-only and documents "step back". **Pending decision (OPEN):** prefer a static backup (peer ids, addresses, channel points; safe at any age) plus peer-assisted cooperative close over snapshot restore.

## 4. The application

- **A control center, not a wallet or messenger clone.** The interface of the next decade is conversation: one seat, chat tracks with peers and AI, inline artifacts. A wallet holds keys and depends on others to verify; a node verifies and enforces (V01 §1.3). Umbrel patterns may be learned, never its code (PolyForm-NC), and BitSov is a protocol node, not a home-server OS. (NS; umbrel/SYNTHESIS.md, FOOL-DIALECTIC C1)
- **Four pillars in one surface:** Channels (peers, paid admission visible), AI (brokered by *your* app), Node (health, identity, peers, freshness), Wallet (on-chain + Lightning, funding the node). (NS)
- **Onboarding and device login.** An app is a paired device, not a login. A Secure Enclave key, unlocked by Touch ID for one signature, is registered once by an owner-approval signature. No passwords. Three-screen first run: Touch ID or restore → "your node is ready" → home. The weaker file-key tier must be labelled (GAP: not built). (ACCOUNT-LAYER.md §3-4; RL; SYNTHESIS §3)
- **The AI boundary.** The app brokers AI; the node never talks to cloud AI. Every AI, local or cloud, is an untrusted client of a small versioned interface. Default: deny spend to any AI; an endpoint badge Own / Shared open / Frontier says who gets paid and what data leaves the node. MindLink may be one paid vendor on the mesh, with no better node treatment. (DEC 25 Sep, DEC 29 Sep; status of the badge: PROPOSAL, app repo not verified here)
- **Honesty in the UI.** No claim without a capability: the app offers a paid read only to a node that advertises `porch_read_v1`, a room only to members advertising the binding, and never implies cross-node fetch before it exists. A sat cost is visible before every paid act ("Send · 12 sats", all-in totals from `quote.max_routing_fee_msat`). Custody and chain-view labels are information, like the balance, never hidden by a setting. Say that the owner sees who read what, that Close channels are visible on-chain, and that the fee reserve and locked funds exist. (BROWSE.md §8-9; REMOTE-SIGNER.md §6; DEC 28 Sep; SYNTHESIS §2.7)
- **Retail sovereignty.** Safe presets that only narrow, not per-request approval fatigue: retail users rubber-stamp prompts. Cheap shared or open models by default; frontier is an add-on. (DEC 25 Sep, NS)

## 5. What we refuse to build

- A whitelist as admission authority: "bootstrap crutch… not the destination". (WP §4.3, ADR-036)
- A global censor or blacklist: abuse reports are evidence, never mandatory law. (WP §7)
- A content-moderation backend, lawful intercept or master key: no plaintext exists to act on. (OSC §2.11-2.12)
- Custodial hosting: mnemonic upload, key escrow, operator decryption, custodial recovery. "Reject or fork." (CHARTER.md)
- A DHT, directory, registry or compiled-in bootstrap list; a register may exist only as "convenience CACHE, never the authority". (WP §6.1, BROWSE.md §2, ADR-036 §3)
- Identity, relationships or a graph on-chain; a card `seq` "is a counter, not a block height". (WP §3, BROWSE.md §5)
- Legacy protocols in core; bridges are edge-only and feature-gated. (UNIFIED_PROTOCOL.md)
- Free reads or free control messages: no unpaid lane, no exceptions. (BROWSE.md §3, UNIFIED_PROTOCOL.md)
- A public trust graph or gossiped Close channels. (RL)
- Admin scope grantable to a pairing; the app never holds the owner credential. (DEC 28 Sep)
- Admission-by-price without relay-fronting: it "trades a chokepoint for a panopticon". (ADR-036 §4)
- Claims we do not make: voting or elections (payment linkage is "toxic" to ballot secrecy); "surveillance-proof" or "unhackable"; reader anonymity; owner location privacy. (WP §7-8, BROWSE.md §8)
- A paid entitlement that revokes identity, export or self-host. (HOSTED-NODE-BUSINESS-CASE.md §1)

## 6. Open tensions (status: OPEN, needs Rasmus)

- **T1. Charter vs hosted nodes.** `CHARTER.md` says never ship a product where an operator holds a mnemonic or can decrypt content. NS, V04, V06, DEC 30 Sep and RL all describe a hosted VM people "sign up for" and later move home; `REMOTE-SIGNER.md` §6 keeps "honest hosted custody" as a sanctioned fallback and names the pilot VMs as hosted custody today. A badge is policy, not "can't" (OSC §0, §2). Even `remote_signer` leaves content readable: it "protects money and… the identity root, not content" (REMOTE-SIGNER.md §7), while OSC §2.1 calls reading content ARCHITECTURALLY EXCLUDED. `money_signer` leaves the identity root on the VM. Options, stated plainly: (a) the owner operates the VM (customer-owned VPS: charter-clean, MindLink holds no credentials); (b) ADR-034 thin client + relay (keys and decryption on the user's device; the only charter-clean *hosted* design); (c) amend the charter to allow labelled hosted custody, by its own RFC process. Also: `OPERATOR_SOVEREIGNTY_CHARTER.md` is pinned by `CHARTER.md` (sha 81237a48…) but is missing from this repo. Proposed resolution: pilot under (a) only; keep (b) as the hosted product path; do not choose (c) silently. **OPEN: needs Rasmus.**
- **T2. Whitelist as core vs crutch.** V01, BIO-IMM, BIO-TIS, BIO-NERV, OSC and ADR-032 treat federation as whitelist-only ("self = whitelisted"); WP §4.3, NS and ADR-036 call it a bootstrap crutch. Proposed: adopt the six-way split (§2); add a header note to the vision and biology docs that "whitelist" there means local invite-only policy. **OPEN: needs Rasmus.**
- **T3. What the nucleus is.** BIO-ATP makes the ledger the "single reference for clearance, identity, and truth"; WP §3 says the chain is "not a registry of identity"; NS says "Nucleus = keys", BIO-ATP and ADR-036 say nucleus = timechain/DNA. Proposed: nucleus = the timechain as clock and value reference; identity derives from keys, never from the ledger; fix the NS line. **OPEN: needs Rasmus.**
- **T4. Relays.** V01 principle 3 "Zero reliance on third-party relays" and V01 "no cloud backup" vs the Tier-2 relay (OSC, ADR-034), WP relay-fronting and ADR-036 "MindLink… runs relays". Proposed: relays are optional, paid, ciphertext-only and exit-able; principle 3 is reworded to "no relay may become the cell". **OPEN: needs Rasmus.**
- **T5. Discovery.** WP and BROWSE.md: no DHT; ARCHITECTURE.md §DHT and `dht_bootstrap = true`, ADR-036 gossip diffusion, ADR-029 "requires bootstrap discovery (DHT or curated list)". Proposed: strike the DHT section from ARCHITECTURE.md; discovery is cards out of band, then paid diffusion only under ADR-036's cache-never-authority rule. **OPEN: needs Rasmus.**
- **T6. The pre-payment floor.** WP §2 lists "invoice" among things not given before settlement; F1 issues a stranger a signed 60 s invoice as an "explicit protocol clarification"; the whitepaper amendment is proposed, not merged. Proposed: merge the amendment so the floor reads "a bounded, stateless payment-preparation quote". **OPEN: needs Rasmus.**
- **T7. Slogans.** "No payment → no packet" (V01, BROWSE.md §3) vs WP "never 'no byte without sats'". "Seed = identity + money" (DEC 30 Sep) vs "never say 'ID is money'" (RL, ACCOUNT-LAYER.md). Proposed: canonical forms are "no service without settlement" and "identity and money share a backup"; retire the others. **OPEN: needs Rasmus.**
- **T8. Crypto and groups.** WP: X3DH and Double Ratchet as-is; OSC and the relay threat model: PQXDH and MLS for groups; Rooms MVP: no MLS. Proposed: state X3DH + Double Ratchet as built, PQXDH as a roadmap item, MLS as not planned; correct OSC §2.1 wording. **OPEN: needs Rasmus.**
- **T9. "Tier" means five things.** See §7. Proposed: adopt the glossary names in all new text; rename in specs opportunistically. **OPEN: needs Rasmus.**
- **T10. Pricing in Principle 5.** V01 and V03 make timechain contract pricing part of Principle 5; ADR-027 removes it from core. Proposed: Principle 5 in core means chain-aware message pricing only; contract pricing is the agreements layer. **OPEN: needs Rasmus.**

## 7. Glossary: the five meanings of "tier"

Use these names from now on; do not write bare "tier" in new text.

| Was called | Use instead | Values | Where |
|---|---|---|---|
| ARCHITECTURE T1-T4 | **resource profile** | Light, Standard, Full, Infrastructure | `docs/v2/ARCHITECTURE.md` |
| Charter Tier-1 / Tier-2 / Tier-3 | **operator role** | self-run, relay operator, custodial (excluded) | `CHARTER.md`, OSC |
| `NodeTier` Cloud / Light / Full | **onboarding mode** (config `tier`) | cloud, light, full | `crates/konsensus-node/src/config.rs` |
| Chain-source T1-T3 | **chain view** | neutrino, electrum, core | `docs/v2/ARCHITECTURE.md` §2.1, DEC 1 Oct |
| Relation-ladder levels 0-3 | **rung** | Knock, Contact, Close, Anchored | RL, `docs/protocol/ACCOUNT-LAYER.md` §4 |

Two more uses to avoid: `ACCOUNT-LAYER.md` §3 "spend authority tiers" (say **spend authority**: device key, console grant, none) and §4 "device-key tiers" (say **device-key grade**: Secure Enclave, file key, console only).
