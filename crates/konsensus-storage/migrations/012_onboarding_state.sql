-- Track ON-B (Tier-2 onboarding) — single-row state machine for the
-- invitee-side onboarding flow.
--
-- ONB6's funding-poll service writes this row when the invitee chooses
-- Full tier; the frontend's OnboardingView (ONB7+) polls GET
-- /api/v1/onboarding/state for ceremony progress updates.
--
-- Single row enforced via PRIMARY KEY CHECK(id=1) — there is only one
-- ongoing onboarding per node.
--
-- ADR: docs/v2/ADR-029-invite-token-scheme.md "Funding ceremony".

CREATE TABLE IF NOT EXISTS onboarding_state (
    -- Always 1 — enforced single-row.
    id                              INTEGER PRIMARY KEY CHECK(id = 1),

    -- Steps: 'paste-invite' (invitee about to paste a token)
    --       | 'accepting' (token parsed, signature verified, whitelist added)
    --       | 'funding' (Full-tier: awaiting on-chain funding)
    --       | 'funding-confirmed' (1+ confirmations received)
    --       | 'connecting' (Noise_XX handshake to inviter in progress)
    --       | 'first-message' (channel open, send-first-message wizard)
    --       | 'complete' (done; frontend transitions to ChatView).
    current_step                    TEXT    NOT NULL DEFAULT 'paste-invite',

    -- Full-tier funding ceremony (NULL for Light tier).
    funding_address                 TEXT,
    funding_amount_sats_required    INTEGER,
    funding_amount_sats_received    INTEGER NOT NULL DEFAULT 0,

    -- Last time the chain-poll task checked the funding address (Unix seconds).
    -- NULL until the first poll completes.
    last_poll_at                    INTEGER
);

-- Seed the single row so handlers can UPDATE rather than INSERT-on-first-use.
INSERT INTO onboarding_state (id, current_step) VALUES (1, 'paste-invite')
    ON CONFLICT(id) DO NOTHING;
