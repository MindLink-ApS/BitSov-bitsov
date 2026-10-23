# Legacy mnemonic fixture

`mnemonic-v1.enc` was generated before enabling zeroization, using an isolated
crate with aes-gcm 0.10.3 and argon2 0.5.3 (default features only), matching
`eb53792e`'s algorithm and v1 layout. It contains public test data only.

- Plaintext: the BIP-39 test phrase `abandon` repeated 11 times, then `about`.
- Password: `  legacy-fixture-password  ` (two ASCII spaces at each end).
- Argon2id v0x13: m=65536 KiB, t=3, p=1, output=32 bytes.
- Salt: sixteen `07` bytes. Nonce: twelve `09` bytes.
- Bytes: version `01`, salt, nonce, AES-256-GCM ciphertext and 16-byte tag;
  empty associated data.

Keep this binary fixed: regenerating it with the implementation under test
would hide changes to the KDF, password handling, or encrypted-file format.
