-- ONB5: add explicit terminal state for channel-open intents that expired
-- before the invitee came online.

CREATE TABLE invites_issued_onb5_new (
    id                                  BLOB    PRIMARY KEY,
    invitee_pubkey                      BLOB    NOT NULL,
    expiry_unix                         INTEGER NOT NULL,
    channel_size_hint_sats              INTEGER,
    addr                                TEXT    NOT NULL DEFAULT '',
    max_fee_rate_sat_per_vb             INTEGER,
    channel_open_intent_expiry_unix     INTEGER,
    nonce                               BLOB    NOT NULL,
    state                               TEXT    NOT NULL DEFAULT 'pending'
                                                  CHECK(state IN ('pending','accepted','revoked','expired')),
    created_at                          INTEGER NOT NULL,
    accepted_at                         INTEGER,
    revoked_at                          INTEGER
);

INSERT INTO invites_issued_onb5_new (
    id,
    invitee_pubkey,
    expiry_unix,
    channel_size_hint_sats,
    addr,
    max_fee_rate_sat_per_vb,
    channel_open_intent_expiry_unix,
    nonce,
    state,
    created_at,
    accepted_at,
    revoked_at
)
SELECT
    id,
    invitee_pubkey,
    expiry_unix,
    channel_size_hint_sats,
    addr,
    max_fee_rate_sat_per_vb,
    channel_open_intent_expiry_unix,
    nonce,
    state,
    created_at,
    accepted_at,
    revoked_at
FROM invites_issued;

DROP TABLE invites_issued;
ALTER TABLE invites_issued_onb5_new RENAME TO invites_issued;

CREATE INDEX IF NOT EXISTS idx_invites_issued_invitee
    ON invites_issued(invitee_pubkey);

CREATE INDEX IF NOT EXISTS idx_invites_issued_state
    ON invites_issued(state);
