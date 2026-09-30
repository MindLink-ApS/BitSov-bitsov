# Account layer (normative)

Status: normative for M1. Source of direction: identity model v2
(`MindLink-Private/pm/projects/bitsov/research/RELATION-LADDER-AND-DEVICE-KEYS.md`).
Every **GAP** marks where the code does not yet meet this spec.

BitSov has no accounts and no passwords. There is one seed per person-node,
a node key that is who you are on the mesh, and device keys that are how an
app logs in. Bitcoin anchors energy and admission, **never identity or the
social graph**.

## 1. Seed and key separation

The root is a BIP-39 mnemonic plus an optional passphrase, giving a 64-byte
seed (`konsensus-core/src/identity.rs`). Every key is derived with the blake3
KDF under its own context string. No key can be computed from another, and
keys cannot be linked except through the seed. Say "identity and money share
a backup", never "ID is money".

| Key | Context | Use | Held by |
|---|---|---|---|
| Node identity (Ed25519) | `konsensus-v2 ed25519 signing key` | NodeId; signs the profile card and auth challenges | node |
| Transport (X25519) | `konsensus-v2 x25519 key exchange` | Noise_XX static key | node |
| Storage (AES-256) | `konsensus-v2 aes256 storage key` | at-rest encryption; JWT secret derived from it | node |
| Lightning + on-chain wallet | `konsensus-v2 ldk-lightning` (64-byte LDK entropy, `konsensus-lightning/src/ldk.rs`) | LN node key, channel keys, the LDK on-chain wallet | node (LDK) |
| **Owner approval (Ed25519)** | `konsensus-v2 ed25519 owner-approval key` | signs owner decisions (§4) | owner CLI, which signs with it. The node derives it at startup from the seed it already holds, keeps only the public half (`NodeIdentity::owner_approval_public`), and never retains the private half |

- **GAP (cleanup).** `NodeIdentity` also derives a secp256k1 key (`konsensus-v2 secp256k1 bitcoin key`) that no production path uses. The wallet lives inside the LDK entropy. The key should be removed, or reserved for pairwise LN identities.
- **GAP.** Pairwise LN identities (one per relation) are not implemented. One LN node key exists per seed.

## 2. The node key is the mesh identity

- A node is its **NodeId**, the Ed25519 public key. Peers authenticate it over Noise_XX with the X25519 static key. An IP address or endpoint is only reachability; it never logs anyone in.
- The **identity fingerprint** is the first 16 bytes of `blake3::keyed_hash(blake3("bitsov-identity-fingerprint-v1"), node_id_hex)` (`pairing::identity_fingerprint`). It is bound into every token, grant and device signature, so a grant made against one identity is refused by another.

## 3. How an app gets and holds access to a node

An app is a **paired client**. It never holds the seed or any node key.

1. **Pairing ceremony** (`handlers/pairing_routes.rs`).
   - The app generates an Ed25519 client key and calls `POST /api/v1/pair/request`. The node writes a 32-byte challenge to a `0600` file under `data_dir/pairing/`.
   - The app signs the challenge and calls `POST /api/v1/pair/confirm`. The pairing is `(client_id = H(client_pubkey), epoch, scopes = read+receive)`.
   - A pairing window must be open. The first pairing on a fresh node needs none.
2. **Tokens.**
   - The app calls `GET /api/v1/pair/challenge`, signs the challenge, and calls `POST /api/v1/pair/token`.
   - It receives a 10-minute JWT bound to `(client_id, epoch, identity fingerprint)`.
   - Every request recomputes the effective scopes, so revocations bite on the next call.
3. **Spend authority** comes in three tiers, from strongest to recovery:
   - **Device key** (§4): once registered, the app signs a per-peer `RelationIntent` (`POST /api/v1/pair/relation-intent`) with the device key. The node opens a recipient-bound envelope.
   - **Console grant** (recovery): `POST /api/v1/pair/elevation-request`, then the owner runs `konsensus grant --op … --config …` and types the short code shown only on the node's terminal.
   - **None**: a packaged sidecar (no `--owner-control`) is read+receive only.
4. **Revocation.**
   - `konsensus pair-revoke` deletes the pairing, or bumps the epoch with `--keep-pairing`. Either retires the pairing's tokens, grants and device keys.
   - Key rotation (`/pair/rotate`) retires the old id's device keys.
   - `konsensus device revoke` and `konsensus grant-revoke` stop spend.

- **GAP (v2 root of trust).** The pairing itself is still rooted in *read access to `data_dir`* (the challenge file). v2 requires the owner-approval key to sign `client_pubkey || epoch` for every pairing. That is implemented for **device-key registration** (§4), not yet for the pairing ceremony. Until it is, anything that can read `data_dir` can pair a read+receive client, but it cannot register a device key or obtain spend **through the API**.
- **GAP (durable state is unsigned).** `pairing/clients.json` is loaded without authentication. Client records, spend grants and front-door grants carry no owner signature. A process that can **write** `data_dir` and restart the node can therefore forge a pairing with a grant and spend. Only device-key records are owner-signed (§4). The fix is to owner-sign or MAC every authority record with a key that is not in `data_dir`. Note that a same-user process can also read a plaintext mnemonic, so this matters once the mnemonic is encrypted or remote.
- **GAP (v2 merge).** v2 makes the device key *be* the login key. Today an app holds two keys: the Ed25519 pairing key, which is a file in the app's store, and the P-256 Secure Enclave device key. The next step is pairing with the Secure Enclave key directly, with the file key as the labelled weaker tier (§4).

## 4. Device keys are login

- A device key is a P-256 key created by the app in the device's secure hardware: the Secure Enclave on macOS, later StrongBox or the iOS Secure Enclave. Biometrics (Touch ID) unlock it for **one** signature.
- On macOS it is CryptoKit `SecureEnclave.P256.Signing.PrivateKey` with `[.privateKeyUsage, .biometryCurrentSet]`, persisted as its device-bound `dataRepresentation`. It is not a keychain item, so no entitlement is needed.

**Registration (once per device):**
1. The app sends `POST /api/v1/pair/device-key {public_key, name, proof}`. `proof` is the device key's signature over:

   ```
   bitsov-device-register-v1\nnode:{fp}\nclient:{client_id}\npublic_key:{hex}
   ```
2. The owner runs `konsensus device approve --op <id> --config <path>`. The control socket is **not trusted** to say what is being signed: the CLI computes the device fingerprint, the pairing key and the epoch itself, from the exact bytes it will sign, and the owner compares that fingerprint with the app's screen. The CLI then asks for the short code the node printed on its own terminal, and derives the **owner-approval key** from the seed. It refuses if the node on the socket isn't the identity that seed derives. It then signs:

   ```
   bitsov-owner-approval-v1\npurpose:device-key\nnode:{fp}\nclient_pubkey:{hex}\nepoch:{n}\ndevice_key:{hex}
   ```

   That is the v2 `client_pubkey || epoch`, bound to this node and to the one device key.
3. The node checks the owner signature first, so a bad signature spends no code attempt. It then checks the code and stores the key **with the owner signature**.
4. On **every** use the node re-verifies that signature against the owner-approval public key derived from its own seed, against the current `client_pubkey` and `epoch`. A device-key record written into `data_dir` without the owner's signature authorizes nothing. That covers device-key records only; see the unsigned-state GAP in §3.

**Use.** A `RelationIntent`:

```
bitsov-relation-intent-v1\nnode:{fp}\nclient:{client_id}\ndevice:{key_id}\npeer:{hex}\nlevel:{n}\nbudget_msat:{n}\nper_act_max_msat:{n}\nwindow_secs:{n}\nissued_at:{t}\nnonce:{hex}
```

- `level` is the relation-ladder rung: 0 Knock, 1 Contact, 2 Close, 3 Anchored. Only 1 is accepted until first contact (step 4). The field is fixed now so that plasticity can move relations later.
- Enforcement, limits and residual risks are in `docs/security/device-keys.md`.

**Tiers, labelled in the app:**
- **Secure Enclave + Touch ID**: the default where available.
- **File key (weaker)**: a software key readable by the OS user. The app must label it as weaker wherever it is used.
- **Console only**: no device key.

**Gaps:**
- **GAP (revocation).** Revoking a device key deletes its record, but the owner signature stays valid for (node, client_pubkey, epoch, device key). A `data_dir` writer could restore a revoked key. Epoch bumps and pairing revocation are durable. Per-key revocation needs a signed revocation list or a per-registration nonce.
- **GAP (socket).** `control.sock` lives in `data_dir`, so a same-user `data_dir` writer could replace it and phish a signature. The CLI's own fingerprint display and the owner's comparison are the defence. The signature is not bound to the console code.
- **GAP.** No hardware attestation on macOS outside the App Store: the node cannot prove a key is in the Secure Enclave. The owner's approval is the root.
- **GAP.** The owner-approval private key is derived from the mnemonic on the node's machine. With a plaintext `mnemonic.txt`, a process that can read it can derive the key. The BIP-39 `identity.passphrase` is also plaintext in `konsensus.toml`. An encrypted mnemonic (`.enc`) or a remote signer (§7) closes this.
- **GAP.** The file-key tier and its label are not built. Today a Mac without a usable Touch ID falls back to the console grant.

## 5. The profile card is the public profile

- The **front-door card** (`konsensus-core/src/front_door.rs`, `FrontDoorCard`) is the only public profile. Its fields:
  - `v`, `network`, `node_id`, `endpoint` and `reach`;
  - `seq`, `issued_at` and `expires_at`;
  - `prices`;
  - `profile`, which holds the display name;
  - the optional `cv`, `media`, `site` and `links`.
- It is signed by the node identity key over `BLAKE3(domain || canonical JSON)`. It is self-distributed as a link or QR code. A higher `seq` replaces a lower one, and an expired card is shown as stale.
- There is no global directory and no name registry (Zooko's triangle: names are local, §6).
- A paired app may publish the card only under an owner `front_door` grant.
- **Disclosure:** the trust discount in the card's price table is the one closeness signal a node exports. The opening and closing of Close channels is visible on-chain. The UI must say so.
- **GAP.** That disclosure is not in the app yet.

## 6. Petnames and fingerprints

- A **petname** is the name *you* give a contact. It is local, never published, and never taken from the other side as truth.
- A contact is verified by comparing its **fingerprint**, derived from its NodeId (scan a QR in person, or read it aloud).
- **GAP.** Peers carry a `label`, which an invite token can pre-fill from the inviter's own label (`handlers/invite.rs`). That is a remote-supplied name. The app must treat it as a *suggestion*, keep the owner's petname separate, and show a "verified" state only after a fingerprint check. Not built (M1.4).

## 7. Hosted nodes: remote signer versus custody

- A node may run on a cloud VM **only** if the seed stays on owner hardware. The node then asks a **remote signer**, the owner's device or a hardware key, for owner approvals and, eventually, for LN signing.
- Otherwise the app's badge must say **"hosted custody"**: whoever runs the VM can spend.
- The owner-approval key is the first key built this way: the node needs only its public half, so moving the private half to a remote signer changes no verifier.
- **GAP.** No remote signer exists. LDK signs in-process from the on-node seed, and the badge is not built.

## 8. Node-key rotation

- A rotation record, signed by the root (the owner-approval key) and by the old node key, names the new NodeId. Contacts that hold the old fingerprint follow it. Petnames and relations carry over, and the old key's card is retired.
- **GAP.** Not implemented (M1.5, after Mexico). Today a new node key is a new identity, and contacts must re-verify.

## 9. Invariants (tested)

- No HTTP route writes an owner approval, a console grant or a device registration. Guard tests: `pairing_routes.rs`, `device_routes.rs`.
- Over the API, a paired token alone never carries spend. Spend requires a console grant, or a registered key's signature over exact terms. Direct writes to `data_dir` are outside this invariant; see §3.
- The running node never **retains** the owner-approval private key. It derives the key once at startup from the seed it holds and keeps only the public half (`NodeIdentity::owner_approval_public`).
- A device-key record without a valid owner signature for the current pairing key and epoch is refused on every use (`device_key_tests::a_device_key_written_into_data_dir_authorizes_nothing`).
- Every key is domain-separated from the seed (`identity::tests::owner_approval_key_is_domain_separated_and_public_only_on_the_node`).
