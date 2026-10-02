# Unreadable at-rest rows

Owner list reads skip rows whose at-rest fields cannot be decrypted. They keep
readable rows in query order and never delete, rewrite, or re-encrypt stored rows.
Database/query failures still return errors. Single-item reads remain strict:
an existing unreadable item returns an error, not a 404.

## Backward-compatible API diagnostics

Response bodies retain their original JSON shapes. Existing clients continue to
read bare arrays. Server-side refilling reaches older readable rows automatically;
clients must honor continuation headers to continue beyond a hard scan bound.
`storage_list_diagnostics_v1` in owner `/api/v1/status.api_capabilities` advertises
the optional response headers and owner status diagnostics.

| Route | Unchanged response body |
| --- | --- |
| `GET /api/v1/messages` (including `peer` conversations and `room` filters) | Bare array |
| `GET /api/v1/messages/search` | Bare array |
| `GET /api/v1/rooms` | Bare array |
| `GET /api/v1/files` | Bare array |
| `GET /api/v1/peers` | Bare array |
| `POST /api/v1/messages/resync` (discover) | Existing discovery object |
| `POST /api/v1/messages/resync` (fulfill) | Existing fulfillment object |

Successful list reads and resync discovery expose per-scan diagnostics in headers:

- `X-BitSov-Unreadable-Count: <count>` appears only when the count is greater than 0.
- `X-BitSov-Storage-Key-Mismatch: true` appears only when the scan sets the warning.
- `X-BitSov-Oldest-Scanned-Timestamp` and `X-BitSov-Oldest-Scanned-Id` appear when
  the raw scan budget is reached before filling the readable page. They identify
  the last processed raw row, including an unreadable row. A short/empty body
  with these headers does **not** mean history has ended.
- `X-BitSov-Next-Before` and `X-BitSov-Next-Before-Id` provide the next request's
  safe cursor for messages, search, files and resync. Normally this is the raw
  scan boundary. Search truncation or staged-file merging can put it earlier so
  following it cannot skip readable rows that have not been returned. These
  headers also appear on full file pages (preserving timestamp precision) and
  truncated healthy search pages.

For example, an all-unreadable message list can return:

```http
HTTP/1.1 200 OK
Content-Type: application/json
X-BitSov-Unreadable-Count: 2
X-BitSov-Storage-Key-Mismatch: true

[]
```

Healthy exhausted scans omit diagnostic and continuation headers. A scan below
the mismatch threshold sends the unreadable count without a mismatch warning.
No diagnostic or cursor is added to JSON bodies, including resync discovery;
fulfillment does not scan a list and sends none of these headers.
Like the data freshness headers, these are read by the app's host-side broker;
they are not added to `Access-Control-Expose-Headers` for webview JavaScript.
Outbox list methods have the same diagnostics in storage; there is no outbox list
HTTP route.
Unreadable outbox operations are excluded from recovery and compaction, and stay
on disk unchanged. Whitelist backup/export collection remains strict: unreadable
peers refuse collection before an existing complete backup can be replaced. No payment or retry is attempted for an omitted operation.

Counts belong to the particular storage scan, not a global counter difference.
They count each omitted row once, even when several encrypted fields are corrupt.
Paged message and file limits apply to **readable** rows. The encrypted wrapper
fetches successively older raw batches, using `(timestamp DESC, id DESC)` keysets,
until the readable limit is filled, the source is exhausted, or it has processed
`min(10 × limit, 5000)` raw rows. Timestamp ties cannot strand readable rows.
A zero limit scans nothing. Counts and mismatch thresholds cover the entire
processed scan, not individual refill batches. A budget-sized exhausted source
can conservatively produce a cursor; the next request then reports exhaustion.

Search and room threads still select up to 1,000 readable source messages;
resync discovery selects up to 1,000 readable conversation messages. Each can
scan up to 5,000 raw rows. Search matching, logical room grouping, resync's lower
time bound, and staged-file merging happen after the scan. Consequently their
final body can be shorter than the requested limit independently of corruption;
unreadable counts describe source rows, not only matches of the final filter.

### Continuing bounded scans (#188 / Fable F1)

For messages and search, pass `X-BitSov-Next-Before` as `before` and
`X-BitSov-Next-Before-Id` as `before_id`, preserving other filters. Timestamps are
milliseconds since epoch. A timestamp alone retains the existing exclusive
`before` behavior; the ID pair resumes within ties. For files use the same query
parameters, URL-encoding the file timestamp string and ID. PostgreSQL cursors
retain microseconds separately from the unchanged millisecond response metadata.
For resync discovery, add `before` and `before_id` to the JSON request and retain
`peer_id`, `from_ms` and `to_ms`. Discovery's `total_count` remains the count of
entries in that response, not a claim that all history has been discovered.

Room threads keep their existing logical `before` pagination, aggregating from
the top of the source scan. Drain those logical pages before advancing the raw
source checkpoint: pass `Oldest-Scanned-Timestamp/Id` as `scan_before` and
`scan_before_id`, clear logical `before`, then paginate within that chunk with
the **same** scan parameters. Raw source continuation is an explicit opt-in mode:
per-member copies of a sent message can straddle chunks. Consumers must merge by
`room_msg` and deduplicate `copies` by message ID across chunks; full copy sets
cannot be guaranteed within one bounded source scan. Room responses deliberately
omit `Next-Before` headers so a raw timestamp cannot be confused with a logical
page boundary. Existing requests without scan parameters keep their grouping.

This closes the pre-decryption LIMIT gap from #188: readable t=10 behind
unreadable t=20 is returned for `limit=1`, unreadable blocks are traversed without
client intervention, and scan-bound responses advertise an explicit checkpoint
instead of silently presenting exhaustion. Header-unaware clients can still stop
at a scan bound; the host-side broker must follow the continuation contract.
Peer responses retain live registry/transport data, and additionally scan stored
peers to disclose unreadable persisted rows; that scan does not refresh the registry.

`X-BitSov-Storage-Key-Mismatch: true` warns that at least 50% of the scanned rows failed
(and at least one failed). It means **possible wrong key/passphrase or corrupt
rows**, not proof that the key is wrong. An empty scan does not trigger it.

## Owner status and logs

Owner `/api/v1/status` includes:

- `storage_unreadable_rows`: cumulative failed row reads since storage wrapper
  creation (normally node startup). Re-reading the same bad row increments it
  again; it is not the number of distinct corrupt rows in the database.
- `storage_key_mismatch`: a warning latched when any list reaches the threshold.
  It stays true until restart so a healthy/empty background scan cannot hide it.

These fields are absent from public `/api/v1/health`. No identities, content, or
keys are added to public diagnostics. Each omitted row logs a fixed warning with
only its row ID; the first threshold breach logs one fixed ERROR per wrapper
lifetime, without row content, error text, or keys.

Check the configured storage key/passphrase, storage-encryption history and
backup provenance before taking operator-directed repair action. The node does
not infer a new key or mutate unreadable data.

Doctrine: 1 holds (admission/payment paths unchanged; unreadable outbox work is
not retried); 2–4 hold (owner-local diagnostics, no directory or identity change);
5 holds (no custody change); 6 holds (partial data and possible mismatch are
explicitly reported, without claiming a diagnosis or automatic repair).
