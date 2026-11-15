-- The caller's current paid offer (envelope id) for a call row, so a delayed
-- refusal of an earlier offer can never end a later lifecycle of the same id.
ALTER TABLE call_state ADD COLUMN offer_id TEXT;
