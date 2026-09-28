ALTER TABLE pending_deliveries ADD COLUMN state TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE pending_deliveries ADD COLUMN dispatched INTEGER NOT NULL DEFAULT 0;
-- Existing rows were queued by a previous send attempt.
UPDATE pending_deliveries SET dispatched = 1;
