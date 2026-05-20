-- Track ON-B (Tier-2 onboarding) — invites this node has accepted as invitee.
--
-- One row per redeemed BitSovInvite, indexed by the invite's nonce.
-- ONB3's POST /api/v1/invites/accept handler inserts a row before adding
-- the inviter to the whitelist; a second presentation of the same invite
-- hits the PRIMARY KEY constraint and is rejected with HTTP 409.
--
-- This is the replay-protection surface called out in BitSovInvite::verify()
-- docstring: "Replay protection (nonce single-use) is the caller's
-- responsibility; this function intentionally has no state."
--
-- ADR: docs/v2/ADR-029-invite-token-scheme.md "Single-use enforcement".

CREATE TABLE IF NOT EXISTS accepted_invites (
    -- 16-byte nonce from the redeemed BitSovInvite (BLOB).
    -- PRIMARY KEY → second redemption of the same invite is rejected.
    nonce               BLOB    PRIMARY KEY,

    -- Inviter's Ed25519 pubkey (32 bytes raw) — recorded so operator
    -- audits can answer "who invited me?" without parsing the original token.
    inviter_pubkey      BLOB    NOT NULL,

    -- Original expiry timestamp (Unix seconds) — for audit trail; verify()
    -- already rejected expired invites at acceptance time.
    expiry_unix         INTEGER NOT NULL,

    -- When the invitee accepted (Unix seconds).
    accepted_at         INTEGER NOT NULL
);

-- Audit lookup by inviter (useful when revoking a relationship).
CREATE INDEX IF NOT EXISTS idx_accepted_invites_inviter
    ON accepted_invites(inviter_pubkey);
