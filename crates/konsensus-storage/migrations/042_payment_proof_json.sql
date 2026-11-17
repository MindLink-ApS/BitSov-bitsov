-- Multi-path UKM gate payment proofs (paths 2–3) alongside legacy Lightning columns.

ALTER TABLE messages ADD COLUMN payment_proof_json TEXT;
