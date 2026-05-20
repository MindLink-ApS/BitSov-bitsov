-- ONB5a: BitSovInvite v2 signed dial target and channel-open bounds.
--
-- Existing rows were issued as v1 invites; defaults preserve backward
-- compatibility while new v2 rows populate all three fields.

ALTER TABLE invites_issued
    ADD COLUMN addr TEXT NOT NULL DEFAULT '';

ALTER TABLE invites_issued
    ADD COLUMN max_fee_rate_sat_per_vb INTEGER;

ALTER TABLE invites_issued
    ADD COLUMN channel_open_intent_expiry_unix INTEGER;
