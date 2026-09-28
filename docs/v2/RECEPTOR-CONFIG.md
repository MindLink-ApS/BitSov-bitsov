# Receptor configuration (RECEPTOR-1)

**Do not merge the implementation before doctrine PR #93 (ADR-042).**

The existing F1 `RequestInvoice` path can quote any explicitly enabled `u16`
act kind. The default enables only `KIND_CHAT` (0). Human and agent requesters
use the same Noise request, pricing lookup, source caps, replay guard and
refusals; there is no requester-class exemption. This does not add an HTTP or
x402 door or enable execution of any new service.

Example opt-in configuration:

```toml
[receptor]
route_hints = "none"

[[receptor.acts]]
kind = 0
enabled = true

[[receptor.acts]]
kind = 200 # KIND_FILE_REF; quote preparation only
enabled = true
window_secs = 10
per_source = 1
global = 16
```

An explicit `acts` list replaces the default list; include chat to retain it.
An omitted `enabled` is false. Omitted caps use F1's defaults above. Duplicate
kinds and zero caps/windows are rejected. An empty list disables all receptors.
Disabled/absent acts receive the existing fixed `konsensus:admission_required`
refusal; replay and exhausted caps receive `konsensus:admission_rate_limited`.
Refusals themselves retain the existing source and global rate limits.
Unsupported backends return `stateless_quote_unsupported` without an invoice RPC.
Other pricing/backend/validation failures remain fail-closed, as in F1.

Send `purpose = "konsensus:admission:<kind>"`, using canonical decimal digits.
The existing `admission_quote::request_id` binds sender, recipient, issue second
and a fresh random nonce. One ID can mint at most one invoice across *all*
acts. A retry needs a fresh ID; rotating identity does not reset the source-IP
cap. IPv4-mapped IPv6 shares its IPv4 bucket. Caps are independent per act;
volatile source guards and request-ID digests also have shared hard bounds of
1,024 each. Exhaustion refuses work rather than evicting live guards. Restart
retains F1's startup quarantine, so pre-start attempts cannot reopen.

Chat preserves F1's amount and `konsensus:<id>:message=<price>` description,
including its existing first-contact pricing rule. Other kinds quote only their
own payable price in `konsensus:<id>:act=<kind>:price=<msat>`; the amount is at
least the backend's 1,000-msat minimum. The caller's amount hint is ignored.
No price table, prekeys, peer record, session or service is returned. The
recipient's Lightning key signs the BOLT11 request binding, price and expiry.
The invoice expires within the request's 60-second lifetime, including the
backend timeout budget. Settlement and the payment gate remain required for
service.

Production quotes still use the LDK `create_inbound_payment` path, retaining
no pending payment or application record. Only bounded volatile counters and
request-ID digests exist before settlement. LND/LNbits remain unsupported.

`route_hints = "none"` is the only currently accepted policy and the default.
The LDK adapter removes private route hints before signing stateless invoices;
the receptor also rejects any backend invoice containing hints. Ordinary paid
invoice creation is unaffected. A single-LSP-hint option awaits Rasmus's
ADR-042 decision and cannot be enabled through this implementation. This may
make a recipient reachable only through private channels unpayable until the
payer knows a route separately.
