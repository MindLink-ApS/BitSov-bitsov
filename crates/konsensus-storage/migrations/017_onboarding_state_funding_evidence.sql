-- ONB6 onboarding-state compatibility migration:
-- add tier/evidence fields and keep funding progress columns explicit.

ALTER TABLE onboarding_state
    ADD COLUMN tier TEXT;

ALTER TABLE onboarding_state
    ADD COLUMN funding_evidence TEXT;
