-- Durable receipts of the free call replies (answer or decline) that moved a
-- call, written with the transition itself. NULL: none, as for every row
-- written before receipts existed.
ALTER TABLE call_state ADD COLUMN free_reply_receipts TEXT;
