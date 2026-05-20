# BitSov Charter

Status: Load-bearing commitment
Ratified: 2026-05-19

## No Tier-3 Custodial Hosting

BitSov will never ship a product in which an operator holds a user's mnemonic,
identity keys, device signing keys, Lightning spend keys, or message decryption
keys.

This is not a marketing pledge. It is an architectural boundary:

- The operator may relay ciphertext.
- The operator may sell paid reachability, store-and-forward, and routing
  services.
- The operator may see the routing metadata required to provide those services.
- The operator must never receive the user's mnemonic or a decryptable runtime
  substitute for it.
- The operator must never be able to decrypt user content, impersonate a user, or
  issue payment proofs for a user.

The canonical charter is:

- `docs/v2/OPERATOR_SOVEREIGNTY_CHARTER.md`
- SHA-256:
  `81237a48fd7565cb64b2bc05504daa3fdd85cacdb46f6e56712d77d1c7064429`

Any future pull request that introduces operator-held user keys, mnemonic upload,
key escrow, operator decryption, custodial recovery, or a Tier-3 hosted-node
product is a charter violation. The correct response is not "review carefully";
the correct response is "reject or fork."
