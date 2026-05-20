-- Migration 005: Add encrypted plaintext cache for decrypted messages.
-- The node decrypts incoming E2EE messages and caches the plaintext (AES-encrypted
-- at rest) so the local REST API can return it. This enables the sovereign browser
-- and other features that need to poll for decrypted content.
-- The plaintext_enc column stores AES-256-GCM encrypted data, never raw plaintext.

ALTER TABLE messages ADD COLUMN plaintext_enc BLOB;
