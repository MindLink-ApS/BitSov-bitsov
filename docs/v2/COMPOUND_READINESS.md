# Compound readiness discovery

`GET /api/v1/status?compound_readiness=true&generation=7&request_id=read-1`
adds `compound_readiness: { envelope, readiness }` to authenticated status.
The ordinary status response and public health response retain their existing
shape. The existing read-scope, selected-node and remote transport checks apply.
Correlation requires an unsigned connection generation and a request identifier
of 1–64 ASCII letters, digits, dots, underscores or hyphens. Neither field grants
permission. A caller must discard a response if its current node, connection,
client or operation context differs from the captured binding.

The envelope uses `schema: { name: "compound_readiness", major: 1, minor: 0 }`.
The schema version describes discovery, independently of the product release.
No required extensions are defined. Additive minor diagnostics belong only in
`optional_diagnostics`, an explicitly non-authoritative object. Unknown required
extensions, major versions, enums, unmarked fields, absent required data and
duplicate semantic keys, positional arrays in place of named objects, and
payloads over 32 KiB refuse evaluation. Correlation and contextual fields are
part of the authenticated observation. Context includes the requested stage and
operation identity; changing either invalidates an outstanding observation.

`named_contact_compound` revision 1 describes a candidate manifest. Its required
semantic revision is 1 for each of: owner setup, authority/consent, receiving and
reply, aggregate history, aggregate enforcement, exact hold, durable compound
records, introduction sequencing, callee signals, lifecycle/recovery and
platform/connection. A route, table, release string or quote alone establishes
none of these complete enforcement groups. The runtime manifest is unfinalized,
the new groups are unsupported, and owner selections are unresolved. This change
adds no activation setting or consumer of readiness as authority.

The evaluator separates implemented capability from per-stage observations for
setup, introduction, ordinary reply, caller call and callee answer. Setup does
not depend on a future paid outcome. Call preparation requires confirmed bound
introduction evidence. Reply and answer have separate prerequisites and actors.
Message outcomes distinguish explicit `not_attempted` from pending, unknown,
confirmed and refused. Only explicit not-attempted evidence can make a message
stage attempt-eligible; unresolved or resolved attempts keep their references
and cannot offer another attempt under the same operation.

Pending, refused, needs-owner and unknown states carry bounded reason and
next-action codes. A paired reader is not an enrolled owner. Warm context keeps
its provenance; it is not evidence of a fresh onboarding journey.

The snapshot describes observed settings and components, not OS permission,
peer admission, spend authority or physical-device acceptance. Unknown aggregate
history and unresolved obligations require reconciliation. Changed context,
terminal operations, revocation, unknown time validity and expiry block dependent
new stages. Expiring enrollment, ring and callee authority require known effective deadlines.
Parent and child expiries use the earlier actual boundary, with no
grace or extension from refresh. Missing peer trust blocks the affected stage;
no new trust channel is created.

`ReadContext` supplies the authenticated expected binding, receipt-local age and
known authoritative time validity. The evaluator compares the full context and
uses `valid_for_ms` only with that receipt-local age. This implementation defines
no runtime snapshot validity window: it reports `null`, so advancement remains
unavailable. Wall-clock timestamps alone never prove freshness.

`can_prepare` describes proposal eligibility. `can_request_approval` also requires
the matching requested stage and, outside setup, an operation identity.
`can_attempt_stage` only describes eligibility to submit a separately authorized
request, with a current authority reference, effective expiry and mandatory
revalidation at the authoritative boundary. `authorizes_dispatch` is always
false and `revalidation_required` always true. No discovery result enrolls,
changes settings, mints grants, reserves funds, sends messages or starts calls.
Opaque authority references are not bearer material. Safe existing outcome
references and accounting uncertainty survive a capability downgrade; discovery
does not cancel, refund or erase an already authorized operation. The status
route exposes no unrelated contact data, and accepts no capability claims from
its query parameters.
