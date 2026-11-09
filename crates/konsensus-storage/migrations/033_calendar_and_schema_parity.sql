-- Calendar events and RSVPs, plus onboarding_state columns that Postgres
-- migration 12 already created (funding_amount_sats, funding_txid,
-- confirmations, updated_at). Adding them here keeps a fresh SQLite catalog
-- aligned with Postgres without dropping anything Postgres already stored.
--
-- CREATE TABLE IF NOT EXISTS keeps rows in a hand-built calendar table.
-- The bundled SQLite (3.45) rejects ADD COLUMN IF NOT EXISTS, so calendar
-- columns are not altered after create: a hand-built table must already have
-- the columns the storage API reads. The onboarding columns below are new on
-- SQLite, so a plain ADD COLUMN is the upgrade.

CREATE TABLE IF NOT EXISTS calendar_events (
    id              TEXT PRIMARY KEY,
    message_id      TEXT,
    organizer       TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT,
    start_ms        INTEGER NOT NULL,
    end_ms          INTEGER NOT NULL,
    tz              TEXT NOT NULL,
    location        TEXT,
    attendees_json  TEXT NOT NULL,
    recurrence_json TEXT,
    color           TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    parent_id       TEXT
);

CREATE INDEX IF NOT EXISTS idx_calendar_events_start
    ON calendar_events (start_ms);

CREATE TABLE IF NOT EXISTS calendar_rsvps (
    id         TEXT PRIMARY KEY,
    event_id   TEXT NOT NULL,
    responder  TEXT NOT NULL,
    response   TEXT NOT NULL,
    comment    TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (event_id, responder)
);

CREATE INDEX IF NOT EXISTS idx_calendar_rsvps_event
    ON calendar_rsvps (event_id);

-- Covers a hand-built RSVP table that omitted UNIQUE(event_id, responder).
-- A second unique index is harmless on SQLite: ON CONFLICT still matches.
CREATE UNIQUE INDEX IF NOT EXISTS calendar_rsvps_event_responder_key
    ON calendar_rsvps (event_id, responder);

ALTER TABLE onboarding_state ADD COLUMN funding_amount_sats INTEGER;
ALTER TABLE onboarding_state ADD COLUMN funding_txid TEXT;
ALTER TABLE onboarding_state ADD COLUMN confirmations INTEGER NOT NULL DEFAULT 0;
ALTER TABLE onboarding_state ADD COLUMN updated_at INTEGER;
