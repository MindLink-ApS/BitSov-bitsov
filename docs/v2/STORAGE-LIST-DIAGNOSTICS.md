# Unreadable at-rest rows

Owner list reads skip rows whose at-rest fields cannot be decrypted. They keep
readable rows in query order and never delete, rewrite, or re-encrypt stored rows.
Database/query failures still return errors. Single-item reads remain strict:
an existing unreadable item returns an error, not a 404.

## Backward-compatible API diagnostics

Response bodies retain their original JSON shapes. No client migration is needed:
the shipped bitsov-app continues to read lists as bare arrays, unchanged.
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

For example, an all-unreadable message list can return:

```http
HTTP/1.1 200 OK
Content-Type: application/json
X-BitSov-Unreadable-Count: 2
X-BitSov-Storage-Key-Mismatch: true

[]
```

Healthy/empty scans omit both headers. A scan below the mismatch threshold sends
only the unreadable count. Neither diagnostic is added to JSON bodies, including
resync discovery; fulfillment does not scan a list and sends neither header.
Like the data freshness headers, these are read by the app's host-side broker;
they are not added to `Access-Control-Expose-Headers` for webview JavaScript.
Outbox list methods have the same diagnostics in storage; there is no outbox list
HTTP route.
Unreadable outbox operations are excluded from recovery and compaction, and stay
on disk unchanged. Whitelist backup/export collection remains strict: unreadable
peers refuse collection before an existing complete backup can be replaced. No payment or retry is attempted for an omitted operation.

Counts belong to the particular storage scan, not a global counter difference.
They count each omitted row once, even when several encrypted fields are corrupt.
Limits apply to scanned rows; a partial or all-unreadable page may contain fewer
readable items than requested. Search, room-thread filtering, resync windows, and
staged-file merging happen after this scan, so the count describes its source rows,
not only items matching the final filter. No extra page is fetched automatically.
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
