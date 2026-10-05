# Porch walkthrough ticket 2

The checkout's default is already **1,000 msat = 1 sat**, not 1,000 sats.
Retained deliberately: the original 50-msat tariff is below the existing
sender and receiving-gate 1-sat floor. The supplied `mesh-browse.md` also calls
for a “one sat-class” refresh and a “1 sat floor.” Lowering a config number to
50 without changing those floors would only misrepresent the actual charge.
No global payment floor or operator-selected price is changed by this fix.
With the default fee policy, the preview is 1 sat principal plus **up to** 5
sats routing allowance (6 sats maximum), not 1,006 sats. Actual fees may be lower.

## Price trace

- `crates/konsensus-node/src/config.rs:720`: `[pricing].web_content_msat`;
  defaults at `:1829`, validation at `:1358` requires at least 1,000 msat.
- `crates/konsensus-node/src/node.rs:316`: configuration feeds the pricing
  engine. Chain-aware mode can adjust the base price.
- `crates/konsensus-pricing/src/static_pricing.rs:70`: static default 1,000
  msat. Kind 500 is in the web-content category.
- `crates/konsensus-core/src/gate.rs:33`: receiving price includes both the
  configured admission-cost floor and non-discountable 1,000-msat Porch floor.
- `crates/konsensus-api/src/handlers/messages/caps.rs:16`: sender floors any
  positive paid act at 1,000 msat; routing allowance is additional.
- `crates/konsensus-node/src/config.rs:1055`: `[web].page_price_msat` also
  defaults to 1,000 msat, but is legacy metadata, not the payment authority.
  Card and manifest prices now derive from pricing plus gate floors through
  `handlers/front_door.rs::porch_page_price` and `msg_handler.rs::priced_manifest`.
- Previously, `handlers/messages/compose.rs::quoted_price` selected a fresh
  discounted cached peer price, or the **reader's own price** if none was
  available. This fix bypasses that fallback for single-peer kind-500 reads:
  `browse.rs::page_price` gets the recipient's fresh path quote instead.

## Reading-app evidence (read only; no app changes)

Inspected sibling checkout `../pa-walk`, which contains the walkthrough app:

- `../pa-walk/src-tauri/src/main.rs:4870-4884`: `read_porch_quote` reads local
  `/pricing/500` and `/pricing/peers`; it has no path and never checks existence.
- `../pa-walk/src-tauri/src/porch.rs:65-70`: `read_price` uses the peer's cached
  web-content category or falls back to the reader's own price, with a 1-sat
  floor. There is no hardcoded 1,000-sat Porch tariff here.
- `../pa-walk/src-tauri/src/act.rs:70-71`: the app adds a routing **ceiling** of
  5–10 sats to the principal; `:106-110` constructs the displayed total.
- `../pa-walk/src-tauri/src/main.rs:5009-5020`: successful Porch accounting
  retains the confirmed all-in ceiling (`max_msat`) even when the response
  reports a smaller principal. `porch.rs:279-280` exposes both principal and
  that accounted total. The displayed total is not evidence of actual fees.

The recording alone cannot establish whether ~1,006 sats came from the deployed
recipient config, the reader's fallback config, a cached price, or display /
allowance accounting. No deployed config or settled invoice from that read is
in this checkout. Do not claim the node default explains the observed amount.
The app controls the preview and ceiling; the node controls the actual payment.

App follow-up: call `/browse/quote` with the chosen path; display msat/sat units
correctly and separate principal from maximum fees. Recognize the new explicit
prepayment refusal reasons so the app releases its pending spend reservation.
Use `porch_quote_v1` for compatibility checks. This task changes only the node.

## Node behavior and limits

Free metadata is available only to contacts the recipient already admits by
payment or explicit whitelist. No card or page
body leaves on the quote channel. Missing, disabled, empty, unsafe or oversized
pages cannot trigger a normal paid fetch. Quotes are peer/request/path-bound,
rate-limited, timeout-bounded, and contain the recipient's public tariff plus
floors. Spend caps and the paid gate remain in force. The existing content
reply proof is still bound to one settled request and consumed once.

A quote is an availability check, not a reservation. Fetch rechecks after a
preview, but a page can disappear after its final preflight, or the peer can
fail after payment. This change does not promise atomic delivery or refunds.
Those outcomes remain paid failures, with no automatic retry.

## Verification

- `cargo fmt --all` ran; unrelated pre-existing formatting churn was excluded
  from this focused patch. The main changed Porch/content files also pass a
  scoped `rustfmt --check`.
- `cargo clippy --workspace --all-targets -- -D warnings` passed. Cargo still
  reports the existing future-incompatibility notice for sqlx-postgres 0.8.0.
- `cargo test --workspace`: 4,124 unit/integration tests passed, five ignored.
  The initial combined run reached an E0463 Rustdoc dependency-artifact error
  for `konsensus_api` while another build overlapped. A subsequent serial
  `cargo test --workspace --doc` passed (two runnable doc tests).
- After the final compatibility changes, `cargo test --workspace porch_`
  passed all 31 matching tests, and `cargo test --workspace --lib
  quote_correlation` passed the response binding/replay regression.
- The new quote endpoint, oversized wire-field rejection, and whitelisted
  contact regression were each observed failing before their fixes.
- Independent review found wire-size and whitelist compatibility concerns;
  both were fixed and the follow-up review found no remaining issues.
