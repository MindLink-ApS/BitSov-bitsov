-- ONB5f replayable progress scoping:
-- track which invite/peer the single-row onboarding state belongs to so
-- normal mesh reconnects cannot regress or advance an unrelated flow.

ALTER TABLE onboarding_state
    ADD COLUMN invite_id TEXT;

ALTER TABLE onboarding_state
    ADD COLUMN inviter_pubkey BLOB;

ALTER TABLE onboarding_state
    ADD COLUMN inviter_ln_pubkey TEXT;
