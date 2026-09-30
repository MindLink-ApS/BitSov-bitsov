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
| **Owner approval (Ed25519)** | `konsensus-v2 ed25519 owner-approval key v2 (seed+owner secret)`, over seed ‖ **owner secret** (argon2id of the recovery-phrase password, salted per node) | signs owner decisions (§4) | owner CLI, which signs with it. The node derives only the public half, at a start from the encrypted seed with the password typed (§4) |

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
2. The owner runs `konsensus device approve --op <id> --config <path>`.
   - **Owner-secret boundary (enforced, fail closed).** The CLI signs only if the recovery phrase is **encrypted**: a `.enc` file created by `konsensus init --encrypt` or `konsensus restore --encrypt`, with no plaintext `mnemonic.txt` beside it. The encryption password is typed at the CLI's prompt. There is no flag, environment variable or config field for it. Otherwise the CLI refuses before showing or asking anything, because a same-user app that can read a plaintext phrase could derive the owner-approval key and approve devices itself.
   - The BIP-39 `identity.passphrase` in the config is a derivation input shared with the node. It is not the protection.
   - The control socket is **not trusted**. Nothing it sends is printed in this flow; other owner commands print its text with control, bidi and invisible characters escaped. The CLI computes the device fingerprint, the pairing key and the epoch itself, from the exact bytes it will sign, and the owner compares that fingerprint with the app's screen.
   - The CLI then asks for the short code the node printed on its own terminal, prompts for the password, and derives the **owner-approval key** from the seed. It refuses if the node on the socket isn't the identity that seed derives. It then signs:

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

**Node-wide gate (the authority boundary).** Device-key registration, owner approval of a device and relation intents all run only if the node **started from an encrypted recovery phrase whose password was typed at that start**. Otherwise the node refuses them with HTTP 403 and a stable `reason`. `GET /api/v1/pair/device-keys` reports the same value as `device_approvals`, so the app can say why before the owner tries.

| `reason` | when | the app shows |
|---|---|---|
| `seed_not_encrypted` | plaintext `mnemonic.txt`, or a plaintext copy beside the `.enc` | "Encrypt your recovery phrase to enable Touch ID approvals." |
| `seed_password_not_typed` | started with `--password` or `--password-file` | "Restart the node and type the password to enable Touch ID approvals." |
| `owner_key_unavailable` | no owner key at start (for example a wrong password) | "Touch ID approvals are off on this node." |

Why the gate lives in the node, and why the key needs the password:
- A same-user program that can read a plaintext seed could derive a seed-only owner key and write a correctly signed device record. Refusing in the CLI can't stop that, because the program never runs the CLI.
- So the node enables device authority only when it can derive an owner key that such a program can't: the key is derived from the seed **and** the typed password (argon2id, the same cost as the file encryption).
- An old copy of `mnemonic.txt`, taken before the phrase was encrypted, therefore does not yield the owner key.
- Changing the password changes the owner key. Devices must then be registered again (fail closed).

**Tiers, labelled in the app:**
- **Secure Enclave + Touch ID**: the default where available.
- **File key (weaker)**: a software key readable by the OS user. The app must label it as weaker wherever it is used.
- **Console only**: no device key.

**Gaps:**
- **GAP (revocation).** Revoking a device key deletes its record, but the owner signature stays valid for (node, client_pubkey, epoch, device key). A `data_dir` writer could restore a revoked key. Epoch bumps and pairing revocation are durable. Per-key revocation needs a signed revocation list or a per-registration nonce.
- **GAP (socket).** `control.sock` lives in `data_dir`, so a same-user `data_dir` writer could replace it and phish a signature. The CLI's own fingerprint display and the owner's comparison are the defence. The signature is not bound to the console code.
- **GAP.** No hardware attestation on macOS outside the App Store: the node cannot prove a key is in the Secure Enclave. The owner's approval is the root.
- **Boundary.** The owner-approval key is protected by the encryption password, which is required for signing (step 2). What is left:
  - a same-user process that captures the typed password, for example with a keylogger, or reads the owner CLI's memory while it signs, is out of scope for this tier;
  - a node started from an encrypted phrase holds the decrypted seed in memory, so a same-user process that can read the node's memory can derive the key;
  - the BIP-39 `identity.passphrase` is plaintext in `konsensus.toml`.
  A remote signer (§7) is the real fix.
- **Enabling Touch ID approvals on an existing node (the pilot path):**
  1. Stop the node (quit the app).
  2. Run `konsensus seed encrypt --config <absolute path>` once.
  3. Start the node again from a terminal and **type** the password when asked.

  The node then reports `device_approvals: "enabled"`, and the app's "Set up Touch ID approvals" works. Nothing else is needed.

- **Migration.** `konsensus seed encrypt --config <path>` (node stopped) encrypts an existing plaintext `mnemonic.txt` in place.

  It refuses first, with nothing changed, when any of these holds:
  - `mnemonic_file` is a relative path;
  - the plaintext is not a regular file, or has more than one hard link;
  - another run holds the lock;
  - any `mnemonic.enc` exists, including a symlink.

  Otherwise:
  1. it asks for a new password twice, on the terminal only (at least 10 characters);
  2. it writes `mnemonic.enc` (0600) and flushes it;
  3. it reads the file back and checks that it derives the **same node identity**;
  4. it points the config at the new file and checks that the config reloads that way;
  5. only then does it overwrite the plaintext with zeros, delete it, and flush the directory.

  The `.enc` is created exclusively (`O_EXCL`, 0600). If the config update fails, the config is restored and the new file is removed only once the config is proven to point back at the plaintext; otherwise **both** files are kept and the message says where the config points.

  The running-node check can only see an owner-run node (its control socket), so stop the node yourself first. On SSDs, APFS snapshots and Time Machine, older copies of the plaintext can persist; they hold the same words as the owner's written backup, which stays the recovery.
- **Starting an encrypted node.** `konsensus start` prompts for the password on the terminal. That includes a dev node the app launches: the prompt appears in the terminal that started the app.
- **Password file (opt-in).** `--password-file <path>` reads the password from a file instead. It must be a regular file owned by the current user, with no group or other permissions. Symlinks are refused, and the opened file is checked against the one inspected. Starting this way leaves **Touch ID approvals off** (`seed_password_not_typed`), because the password was not typed. The node warns that any program running as this user, including a paired app, can read it. With it, the owner key is protected from **other OS users only**, the same as a plaintext seed against a same-user app. `konsensus device approve` never reads it; it always prompts.
- **GAP.** An app launched from Finder has no terminal to prompt on. It would need the password file, with the weaker boundary above, or a remote signer (§7). An encrypted mnemonic (`.enc`) or a remote signer (§7) closes this.
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
- The running node never **retains** the owner-approval private key, and derives its public half only when started from an encrypted seed with the password typed. Otherwise every device-key path refuses node-wide (`device_key_tests::a_node_running_from_a_plaintext_seed_disables_device_authority_node_wide`, `owner_key_startup_tests`).
- A copy of the seed without the recovery-phrase password does not yield the owner key (`owner_key_startup_tests::an_old_plaintext_copy_of_the_seed_does_not_yield_the_owner_key`).
- A device-key record without a valid owner signature for the current pairing key and epoch is refused on every use (`device_key_tests::a_device_key_written_into_data_dir_authorizes_nothing`).
- Every key is domain-separated from the seed (`identity::tests::owner_approval_key_is_domain_separated_and_public_only_on_the_node`).
