-- Only invoices issued after the callee's stop-early check may buy call blocks.
-- Keep this binding independent of call rows and receipts; no preimages or SDP.
CREATE TABLE IF NOT EXISTS call_block_invoices (
    payment_hash TEXT PRIMARY KEY,
    peer TEXT NOT NULL,
    call_id TEXT NOT NULL,
    seq BIGINT NOT NULL,
    retain_until_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_call_block_invoices_retention
    ON call_block_invoices(retain_until_ms);
