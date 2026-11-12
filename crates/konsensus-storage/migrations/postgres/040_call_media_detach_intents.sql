-- Attachment publication arms recovery before a socket can be exposed.
-- Later detach and completion records retain the full intent history.
CREATE TABLE call_media_detach_intents (
    id BIGSERIAL PRIMARY KEY,
    peer TEXT NOT NULL,
    call_id TEXT NOT NULL,
    generation BIGINT,
    event TEXT NOT NULL CHECK (event IN ('attached', 'detach', 'complete')),
    only_unpaid INTEGER NOT NULL CHECK (only_unpaid IN (0, 1)),
    may_hangup_live INTEGER NOT NULL CHECK (may_hangup_live IN (0, 1)),
    CHECK ((event = 'attached' AND generation IS NULL) OR
           (event <> 'attached' AND generation IS NOT NULL AND generation > 0))
);
CREATE INDEX call_media_attachment_current ON call_media_detach_intents(peer, call_id, event, id);
CREATE INDEX call_media_detach_generation ON call_media_detach_intents(generation, id);

-- The current head is a derived index; intent history above remains append-only.
CREATE TABLE call_media_heads (
    peer TEXT NOT NULL,
    call_id TEXT NOT NULL,
    generation BIGINT NOT NULL UNIQUE REFERENCES call_media_detach_intents(id),
    latest_event BIGINT NOT NULL REFERENCES call_media_detach_intents(id),
    completed INTEGER NOT NULL CHECK (completed IN (0, 1)),
    PRIMARY KEY (peer, call_id)
);
CREATE INDEX call_media_heads_pending ON call_media_heads(completed, generation);
