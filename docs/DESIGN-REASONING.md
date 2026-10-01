# BitSov design reasoning

Status: conceptual anchor, 1 Oct 2026, revision 2. It argues *why* the system is shaped as it is. The specs say *how*. Nothing here is a spec, and nothing here is marketing.

## 0. How to use this doc

Read it before touching BitSov. Order of authority: whitepaper (WP) → `CHARTER.md` (and `OPERATOR_SOVEREIGNTY_CHARTER.md`, once it is in-tree) → this doc → specs (`docs/protocol/`, `docs/v2/`, in-tree ADRs) → code. A lower layer may add detail; it may never contradict a higher one.
When two layers disagree, or a task needs what §5 refuses: stop, write the conflict down (PR or issue), and flag it. Do not build around it.
Paths without a prefix are in this repo. Paths marked **external** are not in this tree: WP = `Konsensus_v02/docs/v2/whitepaper/BitSov_Whitepaper_DRAFT.tex`; V/BIO = `Konsensus_v02/docs/vision/`; OSC = `Konsensus_v02/docs/v2/OPERATOR_SOVEREIGNTY_CHARTER.md`; ADR-032/034/036 = `Konsensus_v02/docs/v2/`; NS, DEC, RL and `research/` = `MindLink-Private/pm/`. Status words BUILT / PROPOSAL / RESERVED were checked against `origin/main` a1c1b74 with `git grep`; app-side claims could not be checked here (no app source in this tree).

## 1. First premises

- **P1. "Free" means selling the user.** When sending costs nothing, the network cannot be funded by senders, so it is funded by selling the receiver. The same asymmetry makes spam, Sybil floods and deplatforming possible. (WP §1, NS, `docs/protocol/BROWSE.md` §3)
- **P2. Payment is the connection.** No service without settlement. Admission is a settled, recipient-bound, single-use payment, re-proven per act. The exact rule is not "no byte without sats": the bytes that carry a proof must arrive first. (WP §2, NS)
- **P3. Bitcoin anchors energy and admission, never identity or the social graph.** The timechain is truth for one thing: the irreversible movement of value. A registry or graph on it is "the surveillance trap". (WP §3, `docs/protocol/ACCOUNT-LAYER.md` intro)
- **P4. BTC is ATP.** Work costs energy; identity is not stored in the energy. (WP §3, external BIO-ATP §1.1)
- **P5. Keys are identity and truth.** No account, no registration, no namespace authority. A lost seed is a lost identity: "peers restore memory, never identity". (WP §4-5, external V01 principle 1)
- **P6. The node is the sovereign unit** and the backend of your digital life. The node, not a platform, holds every relationship. (WP abstract, NS, external V01 §1.3)
- **P7. "Can't", not "won't".** A guarantee is architectural or it is not a guarantee. Policy decays under pressure; code that lacks the capability does not. (external OSC §0, §2)
- **P8. Honesty and claim discipline.** Never claim location privacy, relay or scale as shipped. "Architecture-novel, not primitive-novel." No absolutes. (NS, WP header, WP §6-8)

## 2. Derived principles

- **No persistent admission object** (P2). Authorization is a continuously re-proven economic event, not a durable grant that can be seized, sold or administered. (WP §8)
- **"Paid once, therefore related forever" is rejected** (P2, P3). A relationship is the flux of settlements that sustain it, like a synapse. (WP §8)
- **"Whitelist" is split six ways** (P2, P5): keys (identity), contacts (private knowledge), invite-only (local policy), admission proof, scoped capability, Lightning channel. None may collapse into one list. (WP §4.3, NS)
- **Three-line acceptance test** (P2): anyone may know an endpoint; anyone may offer payment; work happens only against settlement. (WP §2)
- **Payment caps spam and pays the victim** (P1, P2). A flood is self-defeating because its cost lands in the target's wallet. (WP §2, BROWSE.md §3, external ADR-036 §1)
- **Energy-proportional contact** (P4): the synaptic tier (Lightning, built) for ordinary work; the genomic tier (on-chain, not built) for high-finality commitments. (WP §3)
- **No global graph** (P3): no registry, DHT or compiled-in bootstrap list. Channels are unannounced **by default**; the open-channel API accepts `announce=true` and LDK honours it, so this is a default, not an enforced invariant (`crates/konsensus-api/src/handlers/payments.rs`). (WP §6.1)
- **A bounded doorway, not a wall** (P2, P8). Pre-payment DoS cannot be eliminated; the free surface shrinks to an unprivileged quarantine. (WP §6.2)
- **Abuse is signed local evidence, never a global blacklist** (P3, P5). The moment reports become global truth, platform moderation is rebuilt. (WP §7)
- **Relationship data lives in local vaults** (P1, P6). Central aggregation is data brokerage. (WP §7)
- **Identity and money share a backup; never say "ID is money"** (P3, P5). Keys are domain-separated from one seed. (ACCOUNT-LAYER.md §1, external RL)
- **Every act is paid, human or AI** (P2). Paid bootstrap and paid sessions were rejected. (external DEC 28 Sep)
- **The node is the authority; every AI is an untrusted client** (P6). "No purchase buys better node treatment." (external DEC 25 Sep)
- **Retail sovereignty first** (P6, P8). A normal person needs a sovereignty floor, not a frontier model; safe presets beat per-request approvals. (external DEC 25 Sep, NS)
- **Prices trend down** (P1, P4). A tiny price per message, "trending toward fractions of a cent", is the removal of the hidden tax, not a tax on speech. (WP §2)

### Admitted gaps (the whitepaper names them; this doc must too)

- **Paid-open finishes the handshake before payment.** As shipped, a stranger completes the Noise handshake before any sats move; that pre-payment surface is "not yet closed". (WP §6.3)
- **A shared liquidity provider sees the payment graph.** "Pay anyone" is an all-pairs routing problem; the path of least resistance is one provider that observes the payment plane even while envelopes stay sealed. Mitigations (multi-provider fan-out, blinded paths) are not built. (WP §6.3)
- **"One settled sat" is a mental model, not a viable tariff.** Routing fees and the dust limit set the real floor; a sat can cost about as much again to route. The whitepaper calls this "a live tension, not a solved problem", and so does this doc. (WP §6.3)

## 3. The protocol, unpacked

Each item: Decision → Why → Rejected → Spec → Biology → Status.

### 3.1 Identity and keys
- Decision: one BIP-39 seed; blake3 domain-separated keys (node id Ed25519, transport X25519, storage AES, LN/on-chain, owner-approval from seed + typed password). NodeId is the mesh identity; IP is reachability only. Apps are paired devices with Secure Enclave keys registered by an owner-approval signature. The public profile is a signed front-door card; names are local petnames.
- Why: P5 (keys are identity), P3 (no registry). The owner key needs the password because a same-user process that reads a plaintext seed could otherwise forge device records.
- Rejected: accounts and passwords; IP as login; a global name registry (Zooko); "seed = ID = money"; social-recovery quorums ("identity-theft surface", WP §5); trusting a "biometric passed" flag; pairing rooted in reading `data_dir` (still a GAP).
- Spec: `docs/protocol/ACCOUNT-LAYER.md`, `docs/security/device-keys.md`, `docs/security/pairing.md`.
- Biology: the key pair is the membrane; the private key is selective permeability (external BIO-MEM §2.1).
- Status: BUILT (keys, owner-approved device keys, signed card). Node-key rotation and pairwise LN identities: PROPOSAL. See T14 (NodeId vs "Bitcoin keypair") and T15 (Touch ID vendor dependency).

### 3.2 Admission and payment per act
- Decision: a per-envelope gate, fail-closed. In code the order is integrity → optional whitelist → freshness → signature → price (with the plasticity discount and `min_admission_cost_msat`) → recipient-bound settlement → nonce and payment-hash replay, checked and stored atomically (`crates/konsensus-core/src/gate.rs`). The whitepaper lists the optional list *after* price ("a local preference, not the authority"); the code checks it earlier. That is a spec/code disagreement already noted as drift by external ADR-036; it is flagged, not resolved here. First contact (F1) is a narrow, stateless, signed, 60 s quote plus invoice for strangers. Budgets authorize spending; every act is still paid.
- Why: P2. Settlement, not stored state, is the authority, re-derived per unit of work.
- Rejected: free control messages (typing, receipts); paid sessions or bootstrap; external invoicing gateways; a stateful invoice fallback for strangers; the allow-list as authority.
- Spec: WP §4.2; `docs/v2/F1-CAPPED-FIRST-CONTACT.md`; `docs/v2/ALL-IN-FEE-CAPS.md`; `docs/SPEND_BUDGET_GRANTS.md`; `docs/v2/UNIFIED_PROTOCOL.md` "Exceptions to Payment".
- Biology: the ATP-powered energy gate; anyone with the right key-shape who spends the energy crosses (external ADR-036).
- Status: BUILT (gate, F1 with `stateless_quote_unsupported`, all-in caps). Quoted re-admission: BUILT for capped single-recipient chat only (`readmit_then_pay`, capability `quoted_readmission_v1`); rooms and other kinds still refuse capped re-admission. See T6 (the pre-settlement quote) and T12 (F1's per-IP quota).

### 3.3 Relations: ladder and plasticity
- Decision: four rungs, Knock / Contact / Close / Anchored, on rails routed → routed → direct private channel → on-chain. One signed `RelationIntent` per relation, with `level` fixed now. Plasticity (potentiation and decay from energy and traffic) is computed locally from the node's own history. One signal is exported: the discount in the price table a node sends its peer (`discount = 0.5 × weight`, `Frame::PriceTable`), so a peer can read its own weight. No graph is published.
- Why: P2 and P3. Trust is earned by paid history; closeness is a private, local fact; the one exported signal is disclosed, not hidden (ACCOUNT-LAYER.md §5).
- Rejected: "the social graph and the liquidity graph become one" (withdrawn, external RL); a public trust graph; gossiped Close channels; global blocking; whitelist-as-trust. Plasticity is a routing and price signal, never legal trust or KYC; agreements may read it, outcomes never write back.
- Spec: external RL; `docs/protocol/ACCOUNT-LAYER.md` §4-5; `docs/v2/ADR-028-agreements-layer.md`.
- Biology: a relation is a synapse; plasticity is synaptic-weight homeostasis, with a 50 % discount cap.
- Status: BUILT (`level` in RelationIntent; `SynapticWeight` discount in `konsensus-pricing`). Close/Anchored rails and automatic ladder movement: PROPOSAL.

### 3.4 Transport and relay (store-and-forward)
- Decision: one envelope format (UKM) over Noise; the `kind` is the receptor. A ciphertext-only relay tier exists in code and ships when an operator enables it (register, deposit, drain, unregister are paid operations); it is off by default, not advertised by default, and its policy is `RelayPolicy::inert_default()` (7-day TTL cap, quotas). The privacy design it needs before promotion (padding, multi-relay fan-out, 24 h retention ceiling, no FCM/APNS in core) is a proposal. An operator may refuse by peer identity, never by content, and a user exits with identity, channels and history intact.
- Why: P6, P7, P8. A relay leaks twelve metadata classes, the social graph loudest, so the tier stays unpromoted until those mitigations exist.
- Rejected: legacy protocols in core (bridges live edge-only); a full Sphinx mixnet (latency); the operator as the user's only LN hop; contractual rather than cryptographic prohibitions.
- Spec: `docs/v2/UNIFIED_PROTOCOL.md`; `docs/v2/RELAY_PROTOCOL.md`; `docs/v2/THREAT_MODEL_TIER2_RELAY.md`; external OSC §3-4.
- Biology: the relay is a phagocyte, not the cell; it "leaks 11 metadata classes a cell does not".
- Status: transport BUILT. Relay engine BUILT, default-off (`crates/konsensus-node/src/relay/`); relay privacy design PROPOSAL; whitepaper status "inert, default-off" (WP §9). See T4.

### 3.5 Pricing (ADR-027's three names)
- Decision: three names, never bare "timechain pricing": *chain-aware message pricing* (core, per-kind msat adjusted to fee rate); *timechain contract pricing* (outside core, a future `konsensus-agreements`); *ChainBridge Flywheel* (business, never in core). Floors: the sender rounds every invoice up to `MIN_INVOICE_AMOUNT_MSAT` = 1,000; the receiving gate permits sub-sat tariffs and applies its own `min_admission_cost_msat` (default 0); the routing-fee ceiling is min(max(5,000 msat, 1 %), 10,000 msat), configurable.
- Why: P4. Contract pricing "has no clean biological anchor" and belongs outside the cell membrane. Routing fees and dust, not protocol design, set the real floor (§2 admitted gaps).
- Rejected: one conflated pricing engine; sub-floor prices presented as solved.
- Spec: `docs/v2/ADR-027-pricing-terminology.md`; `docs/v2/ALL-IN-FEE-CAPS.md`; BROWSE.md §3.
- Biology: fee rate is ambient ATP availability; per-message msat is ATP per operation.
- Status: message pricing and fee caps BUILT. Agreements layer RESERVED (ADR-028, deferred). See T10.

### 3.6 Chain source tiers
- Decision: the user is to choose per node: Neutrino (compact block filters), Electrum (headers verified locally), or Bitcoin Core (pruned or full). Hosted VMs are to run pruned Core. The chain source is local and does not affect node-to-node connectivity.
- Why: P3. A public Esplora sees which outputs a node watches, including private channel funding, tied to its IP: it leaks the channel graph.
- Rejected: public Esplora as the default (kept for dev only, labelled "third-party chain view"); paying a friend's node per query (payment buys admission, not privacy).
- Spec: `docs/v2/ARCHITECTURE.md` §2.1; external DEC 1 Oct.
- Biology: a cell does not let a neighbour count its ATP transactions.
- Status: PROPOSAL. `origin/main` has only `esplora` and `mock` (`crates/konsensus-chain/`); Neutrino and Electrum are named "planned".

### 3.7 Calls and meetings
- Decision: media is direct WebRTC between apps (STUN only, no TURN); signalling is four paid UKM kinds 400-403; the offer is the per-call admission at the callee's `call_msat`; answer, ICE and hangup are each a small paid act. A meeting is ordinary 1:1 calls with a `meeting` field.
- Why: P2 (every act paid), P6 (media never passes a third party's server). The unpaid signalling lane was a gate bypass and is closed.
- Rejected: a free signalling frame family (legacy `Call*` frames are dropped); per-minute billing for direct media; relayed media.
- Spec: `docs/v2/CALLS-PROTOTYPE.md`.
- Biology: electrical signalling (action potentials) is the one modality physically different from chemical signalling (UNIFIED_PROTOCOL §2).
- Status: BUILT as a prototype, "behind no flag", proven on regtest only; there is no runtime network restriction, so mainnet is held by release policy, not code. STUN reveals both endpoints' addresses; no location privacy is claimed. See T11.

### 3.8 Rooms
- Decision (MVP): a fixed roster of 2-4 nodes, no new wire kinds, a room binding inside the ordinary E2EE chat plaintext, the id commits to the roster, the sender pays each member via the 1:1 path, pairwise ratchets. A room never pays a first contact.
- Why: P2, P3, P5. A creator-signed roster is a back-door authority; epochs create partitions and disclosure bugs; observers see paid 1:1 chats, not a room.
- Rejected: the #152 design (epochs, signed rosters, kinds 910-914, kick, scribe); MLS; history sync; room links.
- Spec: **not in this tree.** `docs/protocol/ROOMS.md` exists only on branch `feat/rooms-mvp` (a915182); rationale in external `research/ROOMS-MVP-SYNTHESIS.md`.
- Biology: a tissue is a bounded group of cells with shared recognition, not a new organ.
- Status: PROPOSAL. `origin/main` carries a legacy rooms path (`Recipient::Room` compose; REST reads under `read` scope, mutations under `admin`) that the MVP says to remove or keep as a local cache only.

### 3.9 Browse
- Decision: doorstep (the signed card) is free; a porch read is a paid act settled before the answer, at the owner's `web_content_msat`, whose default and floor is 1 sat (the owner may charge more and chain-aware pricing may raise it); the house is at normal prices. A node id resolves only from a saved contact or a card you hold.
- Why: P1, P2. A free read is "a wall with a hole in it"; node ids are free to mint, so only payment limits a Sybil; free reads recreate scraping, which is "free = sell the user".
- Rejected: free reads; per-IP limits (punish NAT and Tor); DHT, directory, gossip or name registry; remote HTML or scripts; stranger reads without a Knock (needs an ADR).
- Spec: `docs/protocol/BROWSE.md`.
- Biology: the card travels free because it costs the cell nothing; a read makes the cell work, so it costs ATP.
- Status: BUILT v1 (`porch_read_v1`). Media, card relay, persistent cache, app view: GAP.

### 3.10 Remote access and remote signer
- Decision: remote access is a Noise_XX tunnel to the existing API, closed by default, pinned node keys, plaintext HTTP never non-loopback, `/auth/local` unmounted. It adds "no TLS, relay, remote signer, new auth system". The remote signer design keeps seed and owner keys on owner hardware; the node asks it for every signature that moves money or speaks for the owner. Lightning signing would go through VLS, not a home-grown policy engine.
- Why: P5, P7. "A node that holds its own seed can spend… Whoever controls the machine… can do the same."
- Rejected: "encrypted on the VM" as a third option (the operator can read memory); a home-grown signing policy engine; handing the seed to the VM operator as an offline workaround.
- Spec: `docs/protocol/REMOTE-ACCESS.md`; `docs/protocol/REMOTE-SIGNER.md` §3-5.
- Biology: membrane control (the private key) must stay inside the cell that owns it.
- Status: remote access BUILT (v1). Signer protocol RESERVED; `no_config_claims_a_remote_signer` is a test on main.

### 3.11 Custody tiers
- Decision: the node reports one `custody_mode`: `local_seed`, `encrypted_seed`, `hosted_custody`, `money_signer`, `remote_signer`. The app shows it as a badge and may only strengthen the label; a loopback URL is not proof of local provenance. The charter forbids any product where an operator holds a mnemonic, identity, device, spend or decryption keys: "reject or fork".
- Why: P7, P8. The Cloud tier promise ("must not hold user keys") is false until a signer exists. The label is disclosure, which is honesty (P8); it is not a guarantee (P7): a badge is policy, not "can't".
- Rejected: operator-decrypts-mnemonic provisioning (external ADR-032, charter-rejected); shared wallets with sub-balances; a paid entitlement that revokes identity, export or self-host.
- Spec: `CHARTER.md`; `docs/protocol/REMOTE-SIGNER.md` §2, §6; `docs/v2/TIER_MIGRATION_PROTOCOL.md`; external ADR-034.
- Biology: the Cell Test: an operator is another cell bound by receptors; no cytoplasm exchange.
- Status: labels BUILT (`custody_mode` in `/status`). Signer modes RESERVED. The pilot VMs are hosted custody today. See T1.

### 3.12 Recovery and backups
- Decision (whitepaper design): keys are truth; the seed recovers identity and money; a user-owned export key, independent of the seed, is to recover contacts and settings; peers may rebuild shared context around a new key, never identity. Today the exit bundle (SCB + peer whitelist) is encrypted with a key derived from the mnemonic, and SCB restore force-closes from a snapshot.
- Why: P5. The #157 lesson: a channel snapshot older than the channel is a revoked-state weapon pointed at yourself. **Never broadcast state from a possibly stale backup.**
- Rejected: social-recovery quorums; custodial recovery; "back up channel state with a friend, paid per KB-day" (remote copies are always behind, so it makes #157 worse).
- Spec: `docs/v2/RECOVERY.md`; `crates/konsensus-api/src/handlers/export.rs`; WP §5; external `research/umbrel/FOOL-DIALECTIC-01OCT.md` C3.
- Biology: peers restore memory, never identity; the genome is not reconstructed from a neighbour.
- Status: SCB + whitelist export BUILT (mnemonic-derived key). Separate export key: PROPOSAL. Peer-assisted reconstruction: "a design for a future capability, not a shipped feature" (WP §5). Restore is CLI-only and documents "step back". **Pending decision (OPEN):** prefer a static backup (peer ids, addresses, channel points; safe at any age) plus peer-assisted cooperative close over snapshot restore.

## 4. The application

- **A control center, not a wallet or messenger clone.** The interface of the next decade is conversation: one seat, chat tracks with peers and AI, inline artifacts. A wallet holds keys and depends on others to verify; a node verifies and enforces (external V01 §1.3). Umbrel patterns may be learned, never its code (PolyForm-NC); BitSov is a protocol node, not a home-server OS. (NS; external `research/umbrel/SYNTHESIS.md`, FOOL-DIALECTIC C1)
- **Four pillars in one surface:** Channels (peers, paid admission visible), AI (brokered by *your* app), Node (health, identity, peers, freshness), Wallet (on-chain + Lightning, funding the node). (NS)
- **Onboarding and device login.** An app is a paired device, not a login. A Secure Enclave key, unlocked by Touch ID for one signature, is registered once by an owner-approval signature. No passwords. Proposed first run: Touch ID or restore → "your node is ready" → home. The weaker file-key tier must be labelled (GAP: not built). The platform vendor's enclave is a dependency at the door: see T15. (ACCOUNT-LAYER.md §3-4; external RL, SYNTHESIS §3)
- **The AI boundary.** The app brokers AI; the node never talks to cloud AI. Every AI, local or cloud, is an untrusted client of a small versioned interface. Default: deny spend to any AI; an endpoint badge Own / Shared open / Frontier says who gets paid and what data leaves the node. MindLink may be one paid vendor on the mesh, with no better node treatment. An AI agent with its own key and node is a peer, not a client: see T13. (external DEC 25 Sep, DEC 29 Sep; badge status PROPOSAL, app repo not checked here)
- **Honesty in the UI.** No claim without a capability: the app offers a paid read only to a node advertising `porch_read_v1`, a room only to members advertising the binding, and never implies cross-node fetch before it exists. A sat cost is visible before every paid act ("Send · 12 sats", all-in totals from `quote.max_routing_fee_msat`). Custody and chain-view labels are information, like the balance, never hidden by a setting. Say that the owner sees who read what, that Close channels are visible on-chain, and that the fee reserve and locked funds exist. (BROWSE.md §8-9; REMOTE-SIGNER.md §6; external DEC 28 Sep, SYNTHESIS §2.7)
- **Retail sovereignty.** Safe presets that only narrow, not per-request approval fatigue: retail users rubber-stamp prompts. Cheap shared or open models by default; frontier is an add-on. (external DEC 25 Sep, NS)

## 5. What we refuse to build

- A whitelist as admission authority: "bootstrap crutch… not the destination". (WP §4.3, external ADR-036)
- A global censor or blacklist: abuse reports are evidence, never mandatory law. (WP §7)
- A content-moderation backend, lawful intercept or master key: no plaintext exists to act on. (external OSC §2.11-2.12)
- Custodial hosting: mnemonic upload, key escrow, operator decryption, custodial recovery. "Reject or fork." (`CHARTER.md`)
- A DHT, directory, registry or compiled-in bootstrap list; a register may exist only as "convenience CACHE, never the authority". (WP §6.1, BROWSE.md §2, external ADR-036 §3)
- Identity, relationships or a graph on-chain; a card `seq` "is a counter, not a block height". (WP §3, BROWSE.md §5)
- Legacy protocols in core; bridges are edge-only and feature-gated. (UNIFIED_PROTOCOL.md)
- Free reads or free control messages: no unpaid *service* lane beyond the irreducible floor (one inbound paid contact must be decoded before its proof can be checked). (BROWSE.md §3, UNIFIED_PROTOCOL.md, WP §2)
- A public trust graph or gossiped Close channels. (external RL)
- Admin scope grantable to a pairing; the app never holds the owner credential. (external DEC 28 Sep)
- Admission-by-price without relay-fronting: it "trades a chokepoint for a panopticon". (external ADR-036 §4)
- Claims we do not make: voting or elections (payment linkage is "toxic" to ballot secrecy); "surveillance-proof" or "unhackable"; reader anonymity; owner location privacy. (WP §7-8, BROWSE.md §8)
- A paid entitlement that revokes identity, export or self-host. (external `research/HOSTED-NODE-BUSINESS-CASE.md` §1)

## 6. Open tensions (every one: OPEN, needs Rasmus)

For each: the tension, then options with the premise-preserving one first. No option is chosen here.

- **T1. Charter vs hosted nodes.** `CHARTER.md` says never ship a product where an operator holds a mnemonic or can decrypt content. NS, external V04, V06, DEC 30 Sep and RL describe a hosted VM people "sign up for" and later move home; `docs/protocol/REMOTE-SIGNER.md` §6 keeps "honest hosted custody" as a fallback and names the pilot VMs as hosted custody today. A badge is policy, not "can't" (external OSC §0, §2). Even `remote_signer` leaves content readable: it "protects money and… the identity root, not content" (REMOTE-SIGNER.md §7), while OSC §2.1 calls reading content ARCHITECTURALLY EXCLUDED. `money_signer` leaves the identity root on the VM. `OPERATOR_SOVEREIGNTY_CHARTER.md` is pinned by `CHARTER.md` (sha 81237a48…) but missing from this repo. Options: (a) **premise-preserving:** the owner operates the node (home box, or a VPS in the owner's own account; MindLink holds no credentials). (b) External ADR-034 thin client + operator relay: keys and decryption on the user's device, but a third-party relay and an operator-funded channel, which bends external V01 principle 3 and §3.4's "operator as only LN hop" rejection. (c) Amend the charter by its own RFC process to allow labelled hosted custody. **OPEN: needs Rasmus.**
- **T2. Whitelist as core vs crutch.** External V01, BIO-IMM, BIO-TIS, BIO-NERV, OSC and ADR-032 treat federation as whitelist-only ("self = whitelisted"); WP §4.3, NS and external ADR-036 call it a bootstrap crutch. Options: (a) **premise-preserving:** self/non-self recognition stays, but as cryptographic identity plus the energy gate (ADR-036 §1), with the six-way split of §2; the vision and biology docs get a note that their "whitelist" is the local invite-only policy. (b) Keep the whitelist as a gate check and accept admission-by-authority. **OPEN: needs Rasmus.**
- **T3. What the nucleus is.** External BIO-ATP §1.2 makes the ledger the "single reference for clearance, identity, and truth"; WP §3 says the chain is "not a registry of identity"; NS says "Nucleus = keys"; BIO-ATP and ADR-036 say nucleus = timechain/DNA. Options: (a) **premise-preserving (P3):** nucleus = the timechain as clock and value reference; identity derives from keys, never from the ledger; correct both the NS line and BIO-ATP §1.2's "identity" word. (b) Keep "Nucleus = keys" as a separate app-level metaphor. **OPEN: needs Rasmus.**
- **T4. Relays.** External V01 principle 3, "Zero reliance on third-party relays", and "no cloud backup" vs the Tier-2 relay (OSC, ADR-034), WP relay-fronting and ADR-036 "MindLink… runs relays". The relay engine exists in code, default-off. Options: (a) **premise-preserving:** principle 3 stands; the default node uses no relay; a relay is an opt-in, paid, ciphertext-only, exit-able exception that is labelled and never required for reachability. (b) Promote the relay to architecture and reword principle 3. **OPEN: needs Rasmus.**
- **T5. Discovery.** WP and BROWSE.md: no DHT; `docs/v2/ARCHITECTURE.md` §DHT and `dht_bootstrap = true`; ADR-036 gossip diffusion; ADR-029 "requires bootstrap discovery (DHT or curated list)". Options: (a) **premise-preserving:** strike the DHT section; discovery is cards out of band, nothing else. (b) Paid diffusion under ADR-036's cache-never-authority rule. **OPEN: needs Rasmus.**
- **T6. The pre-settlement quote.** WP §2 lists "invoice" among things not given before settlement; F1 issues a stranger a signed 60 s invoice as an "explicit protocol clarification"; the whitepaper amendment is proposed, not merged. Options: (a) **premise-preserving:** keep WP §2 as written; F1's quote is a documented, bounded, stateless exception flagged against it; no further pre-settlement service is added. (b) Replace F1 with payer-push keysend (no invoice) so the floor holds literally. (c) Amend the whitepaper. **OPEN: needs Rasmus.**
- **T7. Slogans.** "No payment → no packet" (external V01 principle 2, BIO-IMM, BROWSE.md §3) vs WP §2 "never 'no byte without sats'". "Seed = identity + money" (external DEC 30 Sep) vs "never say 'ID is money'" (RL, ACCOUNT-LAYER.md §1). Options: (a) **premise-preserving:** both hold at their layers: the short form for service ("no payment → no packet *delivered*"), the exact form for the wire (WP §2); "identity and money share a backup" is the exact form of the seed line. (b) Retire the short forms. **OPEN: needs Rasmus.**
- **T8. Crypto and groups.** WP: X3DH and Double Ratchet as-is; external OSC §2.1 and the relay threat model: PQXDH and MLS for groups; Rooms MVP: no MLS. The tree has `x3dh.rs` and `double_ratchet.rs`, no PQXDH, no MLS. Options: (a) **premise-preserving (P7 and P8 together):** the charter's "can't" must name what is built; either build PQXDH (and MLS if groups need it) or correct OSC §2.1 to the classical ratchet with PQXDH as roadmap. A charter that names an unbuilt primitive is a "won't". (b) Leave OSC as aspiration. **OPEN: needs Rasmus.**
- **T9. "Tier" means five things.** See §7. Options: (a) adopt the glossary names in all new text and rename in specs opportunistically. (b) Keep "tier" with a mandatory qualifier. **OPEN: needs Rasmus.**
- **T10. Pricing and the flywheel vs P1.** External V01 principle 5 ("Timechain Pricing & ChainBridge Flywheel") is "non-negotiable"; V03 defines contract pricing as pay once, then free at an end block; BIO-IMM calls the flywheel regeneration. ADR-027 moves contract pricing out of core and the flywheel into business docs. External V04 and V06 fund growth with fiat SaaS, a $49/mo managed node and free nodes bound to BitSov, which is close to the receiver-funded shape P1 refuses. Options: (a) **premise-preserving:** core = chain-aware message pricing only; contract pricing lives in the agreements layer; the flywheel may fund nodes only if no entitlement touches identity, export, self-host or another node's admission gate (`research/HOSTED-NODE-BUSINESS-CASE.md`). (b) Return contract pricing to core as V01 reads. **OPEN: needs Rasmus.**
- **T11. Calls: one payment, then a live session.** The offer is paid once and `call_state` stays live for up to 4 h; media minutes are not re-paid, and §2 says paid sessions were rejected. Options: (a) **premise-preserving:** treat the call as one act (the offer) whose work is the signalling, not the minutes, and say so; media is peer-to-peer and costs the callee's node nothing. (b) Re-prove per interval (a paid heartbeat). **OPEN: needs Rasmus.**
- **T12. F1 quotas by source IP.** §3.9 rejects per-IP limits (they punish NAT and Tor); F1 limits stranger quotes to one per TCP source IP per 10 s and 16 globally. Options: (a) **premise-preserving:** state it plainly as a pre-payment doorway defence (WP §6.2 allows "per-source rate limits" there), never as an admission rule, and keep it out of the paid path. (b) Replace with a stateless cookie or proof-of-work before the quote. **OPEN: needs Rasmus.**
- **T13. AI as untrusted client vs AI as sovereign node.** §4 makes every AI an untrusted client the app brokers; WP §6.4 names machine-to-machine paid communication the standout, and external DEFLATION_AI_LENS says an agent "has its own key, pays its own admission, runs its own membrane". Options: (a) **premise-preserving:** both: an AI *using your node* is a client under your spend policy; an AI *with its own node* is a peer admitted by settlement like anyone. Write both roles into the AI boundary. (b) Pick one. **OPEN: needs Rasmus.**
- **T14. NodeId vs "the Bitcoin keypair is the user".** External V01 principle 1 makes the Bitcoin keypair the user; the mesh identity is an Ed25519 NodeId, domain-separated from the LN and on-chain keys (ACCOUNT-LAYER.md §1); WP §4.1 allows the split. Options: (a) **premise-preserving (P3, P5):** keep the split; reword V01 to "the seed-rooted keypair on the node is the user". (b) Bind NodeId to the LN key. **OPEN: needs Rasmus.**
- **T15. Touch ID and the Secure Enclave at the door.** Device login depends on a platform vendor's enclave and biometrics. §3.1 rejects trusting a "biometric passed" flag, and the node verifies a signature, not the biometric; still, the vendor sits in the login path, and there is no attestation outside the App Store (ACCOUNT-LAYER.md §4 GAP). Options: (a) **premise-preserving:** the enclave is one labelled device-key grade; the owner-approval key and the seed, not the vendor, are the root; a non-enclave grade (file key, hardware key) must exist and be labelled. (b) Require the enclave. **OPEN: needs Rasmus.**

## 7. Glossary: the five meanings of "tier"

Use these names from now on; do not write bare "tier" in new text.

| Was called | Use instead | Values | Where |
|---|---|---|---|
| ARCHITECTURE T1-T4 | **resource profile** | Light, Standard, Full, Infrastructure | `docs/v2/ARCHITECTURE.md` |
| Charter Tier-1 / Tier-2 / Tier-3 | **operator role** | self-run; relay operator; custodial, which is forbidden by the charter and currently breached by the pilot VMs (T1) | `CHARTER.md`, external OSC |
| `NodeTier` Cloud / Light / Full | **onboarding mode** (config `tier`) | cloud, light, full | `crates/konsensus-node/src/config.rs` |
| Chain-source T1-T3 | **chain view** | neutrino, electrum, core | `docs/v2/ARCHITECTURE.md` §2.1, external DEC 1 Oct |
| Relation-ladder levels 0-3 | **rung** | Knock, Contact, Close, Anchored | external RL, `docs/protocol/ACCOUNT-LAYER.md` §4 |

Two more uses to avoid: `ACCOUNT-LAYER.md` §3 "spend authority tiers" (say **spend authority**: device key, console grant, none) and §4 "device-key tiers" (say **device-key grade**: Secure Enclave, file key, console only).
