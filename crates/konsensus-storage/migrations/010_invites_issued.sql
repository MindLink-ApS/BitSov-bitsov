-- Track ON-B (Tier-2 onboarding) — invites the inviter has issued.
--
-- Each row represents a BitSovInvite produced by this node's
-- POST /api/v1/invites endpoint (ONB2). The runner stamps state='pending'
-- on issuance; the invitee's first Noise_XX handshake flips it to 'accepted'
-- via the auto-channel-open trigger (ONB5). Operator can revoke a pending
-- invite via DELETE /api/v1/invites/:id.
--
-- ADR: docs/v2/ADR-029-invite-token-scheme.md.
-- Code surface: crates/konsensus-core/src/invite.rs (BitSovInvite type),
-- crates/konsensus-api/src/handlers/invites.rs (handlers, ONB2/ONB4/ONB5).

CREATE TABLE IF NOT EXISTS invites_issued (
    -- UUID v4 in canonical 16-byte form (BLOB) for compact storage.
    id                          BLOB    PRIMARY KEY,

    -- The recipient pubkey this invite is bound to (Ed25519, 32 bytes raw).
    invitee_pubkey              BLOB    NOT NULL,

    -- Unix seconds after which the invite is invalid (verify() rejects).
    expiry_unix                 INTEGER NOT NULL,

    -- Inviter's hint for channel capacity if invitee chose Light tier.
    -- NULL = use operator default (currently 50_000 sats per ADR-029).
    channel_size_hint_sats      INTEGER,

    -- Per-invite 16-byte random nonce (BLOB) included in signed canonical
    -- bytes. Ensures unique signatures across re-issues to the same pubkey.
    nonce                       BLOB    NOT NULL,

    -- Lifecycle: 'pending' (issued, not yet redeemed)
    --           | 'accepted' (invitee connected, ON-B5 auto-channel-open fired)
    --           | 'revoked' (operator deleted before acceptance).
    state                       TEXT    NOT NULL DEFAULT 'pending'
                                          CHECK(state IN ('pending','accepted','revoked')),

    created_at                  INTEGER NOT NULL,
    accepted_at                 INTEGER,
    revoked_at                  INTEGER
);

-- Fast lookup by invitee_pubkey when the invitee comes online (ONB5).
CREATE INDEX IF NOT EXISTS idx_invites_issued_invitee
    ON invites_issued(invitee_pubkey);

-- Fast lookup by state for the operator's invite-management panel (ONB10).
CREATE INDEX IF NOT EXISTS idx_invites_issued_state
    ON invites_issued(state);
