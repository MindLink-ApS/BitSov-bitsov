Public, test-only ECDSA P-256 certificate/key fixtures for the local rustls server.
Never deploy this key. The CA private keys were discarded after generation.

- `ca.pem` signs `server.der`; server SAN is DNS `localhost` only.
- `server-key.der` is unencrypted PKCS#8 test material.
- `wrong-ca.pem` is an unrelated CA used to verify trust rejection.
- Certificates are valid from 2020-01-01 through 2045-01-01.

Generated with Python cryptography, SHA-256 signatures, BasicConstraints CA=true
for roots and CA=false for the server. Tests intentionally use an IP URL to
exercise hostname rejection separately from CA rejection.
