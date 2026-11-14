# In-app spend approval and unaided recovery

Design proposal v3 · 10 November 2026

**Status:** Proposed design, not implementation or release approval. Current-source findings and remaining runtime uncertainties are distinguished below. Existing implementation is not evidence of a completed unaided recovery journey. No live node, credential, payment, signing, deployment, or recovery action has been performed. This document does not authorize those actions.

## 1. Outcome and recommended first slice

An ordinary older owner should be able to understand and approve a bounded spending request in the app, and recover from routine node restart, pairing loss, and app lockout without a terminal or a hidden helper. The interface must distinguish authority, connectivity, chain readiness, backend readiness, and payment outcome. A healthy connection does not establish permission to spend. A current chain tip does not establish a usable payment backend.

Start with an already-enrolled second owner device approving a different requesting client. The inspected node enforces separation between pairing client IDs, not between physical devices or people. An app install must never hold both the requesting pairing and an approving owner key for the same node. A second pairing on that install is the same-device case (Option B), not independent approval. This includes an AI requester pairing on the approver's device. Do not enable a one-device journey by deleting the same-pairing prohibition or relabeling a second pairing as a second device. First-owner enrollment, same-device approval, and loss of the last owner authority require separate reviewed security designs.

The first slice is intentionally narrower than complete empty-hardware onboarding. It must disclose its enrolled-owner prerequisite. Successful testing with provisioned devices does not prove that a new owner can provision the system unaided.

## 2. Current-source evidence and uncertainty

Node source originally inspected at `fac9245b01fecb4f1dea24cfc95184a1d040a034`; the relevant pairing, approval and spend-budget files were rechecked as unchanged through `d99252f11e7feeca7888d50a232633c589e5f2d7`. This is source evidence, not installed-box or released-binary verification. The protocol reference is `docs/v2/OWNER-APPROVALS.md`.

- Approval requests expire after 300 seconds. Approved first-contact authority lasts at most 120 seconds from approval and never beyond its underlying spend grant (pairing/approval.rs:19,482,681; OWNER-APPROVALS.md:196,204,238).
- Pending requests and attempt limits are process-local. Signed spend-grant receipts persist; first-contact authority and its receipt are memory-only. An approval receipt is not proof of payment settlement.
- Pending discovery excludes the requester's own pairing. Approval independently prohibits the same client, requires a current eligible enrolled owner key, and requires a matching authenticated Noise context. Read/AI pairing scope can request but cannot alone approve.
- Signed operation bytes bind node, requester, epoch, grant, recipient, limits, operation, nonce and expiry. Owner-key binding comes through verification with the selected eligible key and its attested receipt; there is no additional owner-key-ID wire field to invent.
- No decline/cancel endpoint exists in the inspected approval routes. Other cancellation APIs concern different operations.
- Breaker reset IS implemented as the additive owner_device_approval_breaker_reset_v1 capability, separate from owner_device_approval_v1. It requires another enrolled owner pairing, a current live grant and unchanged signed accounting snapshot, preserves the grant's accounting, and allows at most three successful device resets per rolling day per grant (pairing/approval.rs:16,596-630; OWNER-APPROVALS.md:275).
- These capability strings do not prove enabled owner mode, available keys or successful enrollment. The actual service mode and transport still gate access.

Approval UI and host commands already exist in the previously inspected application snapshot from November 6. That snapshot is not asserted to be the latest app or installed build. This proposal concerns integration, recovery and acceptance gaps, not rebuilding absent endpoints. Revalidate application behavior against the selected implementation build.

Older same-device/biometric designs must not override the implemented separate-owner rule. Current spend-grant approval is messaging authority, not blanket explicit-payment authorization. Explicit payments require their own authorization path.

Before implementation, verify target app/node versions, feature flags, owner enrollment, platform key protection, token refresh and reconciliation support. Existing held work remains held unless separately released by its owner. Source-inspected tests are not new runtime test results.

## 3. Options and costs

### A. Already-enrolled second owner device — recommended first slice

Benefits: preserves requester/approver separation and offers the clearest fit with the inspected implementation.

Costs: requires another available enrolled device, enrollment and key lifecycle management, understandable device labels, and an explicit recovery policy if that device is unavailable or lost. It cannot honestly be described as a one-phone setup. Hardware availability and platform support must be confirmed; no purchase is assumed.

### B. Same-device owner ceremony — separate security design

Benefits: potentially lower everyday friction and no second-device availability dependency.

Costs: requires a reviewed authority boundary that survives compromise of the requesting app/session, platform-specific key protection and user-presence semantics, and a decision about what biometrics actually authorize. Biometrics alone are not a substitute for server-side owner authorization. Do not weaken the current prohibition to implement this option.

### C. Physical or offline owner-held recovery — separate design

Benefits: may provide recovery after loss of ordinary app access without a hosted administrator.

Costs: provisioning, secure storage, theft/loss handling, revocation and replacement, proof of possession, and precise limits on what wallet/channel/history state can be recovered. Recovery material must be understandable and actually held by the owner. It must not silently become a bypass for spend limits or existing liabilities.

### D. Helper or hosted broker — reject as default

A helper-operated console or centrally held recovery authority does not satisfy unaided, exclusive owner control. It introduces availability, trust, privacy, and support costs. If offered later as an explicit assisted mode, label it honestly and define its authority; do not count it as passing the independent-owner gate.

No currency amounts, implementation duration, or hardware requirements are asserted without measured evidence and owner selection.

## 4. Approval journey and authority invariants

### Separate-device requirement

For the same node, the supported app must refuse creation, import or restoration of a requesting pairing alongside an approving owner key. On enrollment, role change, restore and before signing, reconcile all locally held pairings and owner keys for that node. A conflicting second pairing, including a Read/AI requester, blocks approval; hiding it in another account or screen does not make it independent. Do not silently delete or revoke an existing key to resolve the conflict. Show an explicit owner-reviewed role or separate-device setup path. The approver role must not create a spending request that it can approve through another local pairing.

The current node's distinct-client-ID check is necessary but insufficient. The implementation plan must specify enforceable enrollment/role controls, migration of existing mixed-role installs, and the evidence supporting the distinct-device prerequisite. Local checks alone cannot prove that another install or a modified client is on different hardware. Do not claim cryptographic device separation from a device label, a local-only check or a new client ID. If the selected platform cannot meet the reviewed boundary, keep that journey unavailable and retain Option B as a separate design. No new device-attestation field or endpoint is asserted here.

### Request and approval

1. The requesting client creates a bounded request. Creating a request is not payment and is not grant approval.
2. An eligible owner app obtains the request through an authenticated, pinned-node connection. A notification or link is a navigation hint, not authority.
3. The app displays the requesting device, intended recipient or action, total limit, time window, and consequences. Device and recipient labels require a verified mapping; attractive names alone are not identity evidence. A time-window budget must not be described as a recurring daily allowance unless that is the actual contract.
4. The owner signs the exact bound terms using an eligible owner key after the separate-device/role checks above. Local biometric success does not replace node-side authorization, key eligibility, current epoch, or requester separation checks.
5. The node validates and consumes the approval atomically, persists the outcome, and returns an authoritative result. Concurrent submissions and retries must not create duplicate grants or reset a budget.
6. The app obtains any required updated authorization and resumes only the original operation within the approved limits. It must not silently expand the recipient, duration, or scope.

Bind node identity, requester/client and pairing epoch, operation, grant, recipient, limits, nonce, and expiry in the protocol-defined bytes. Verify with the eligible enrolled owner key and retain its attested receipt; do not add a new owner-key-ID wire field merely to implement this design. Any changed term requires a fresh review and signature. Display text must correspond to the signed payload.

If an approval response is lost, show an uncertain state and reconcile requests, grants, and operation/payment records. A missing request after restart is not proof that no approval or payment occurred. Card dismissal is not decline or cancellation when no such endpoint exists. Never tell the owner an operation was cancelled merely because a local card disappeared.

## 5. Revocation, limits, and breakers

Distinguish revoking a grant, an owner key, a pairing, and an identity. Each has a different effect. The app must describe the exact target and the resulting loss of access.

Routine reconnect, pairing recovery, unlock and restart must not silently issue new spending authority. A deliberate independently owner-approved fresh grant is a distinct budget, not automatic recovery. Current code creates a new meter and clears the old meter: old reservations cannot dispatch against, debit or refund the replacement grant. Previously submitted payments may still settle; replacement is not payment cancellation.

Open owner/reviewer decision: retain this explicit fresh-budget model with clear disclosure of earlier unknown payments, or require cross-grant continuity as a separately designed change. The current endpoints do not establish the latter. No exploit is claimed by this distinction. Old payment history and unresolved outcomes must remain accurately visible independently of the latest grant meter. Cross-pairing idempotency continuity must be specified before recovery can resume an old operation.

Revoke-versus-in-flight ordering needs a specified node-side result. Revoking an approving key does not retroactively revoke an already-issued grant for another pairing; the relevant requesting pairing/grant must be revoked to end that authority. Already-dispatched payments cannot be promised recalled.

Use the existing separately advertised breaker-reset operation only when its sub-capability and runtime authority are available. The requester cannot approve its own reset. Require current signed meter digest and grant snapshot, durable reset quota, preserved budget/deadline and pending accounting, and refusal of changed or expired state. Base approval capability alone is insufficient. If reset is unavailable, explain that accurately.

## 6. Recovery journeys

### Node restart

Separate starting, locked, authenticated, chain-source health, payment-backend health, and ready states. An app that recognizes a previously paired node must not silently trust a replacement identity at the old address. Use the pinned identity and an approved unlock route; do not substitute trust-on-first-use during recovery.

A restarted node can lose pending approval requests while retaining receipts. Reconcile before reissuing an operation. A fresh request must not imply that an earlier payment is known to have failed.

Core cookie rotation is a specific split-health case: the chain provider may reread credentials while the payment backend may require restart or reinitialization. Determine actual version behavior. Do not display overall readiness because only one component recovered. The accepted app lifecycle recovery must work without a hidden console helper.

### Pairing loss with surviving owner authority

Treat reenrollment as a new, untrusted requester until an eligible surviving owner approves it. Make old-device loss and possible theft explicit. Revoking an old pairing is an owner action with consequences, not an automatic inference from a connection failure.

Do not transfer grants, issue a fresh budget, or erase unknown payment outcomes simply because the replacement device belongs to the same person. Define continuity and reconciliation before enabling this journey. Any independently approved new budget must be presented as a new spending decision, not a recovery side effect.

### App lockout

Distinguish failed biometrics, an expired session, revoked authority, rate limiting, node outage, and loss of the owner key. These states need different remedies.

Warn before app reset, reinstall, or local-data clearing can destroy the only owner key. Do not weaken authentication or counters to make the screen recover. Legitimate recovery must remain available under request flooding, without allowing a requester to bypass rate limits or authority checks.

### Last owner authority lost

Until an owner-held recovery ceremony is specified and tested, state that this case is unsupported. An address, support claim, device name, or knowledge of personal details is not owner authority.

Do not promise that a wallet seed restores channel state, operation history, pending liabilities, or all node identity and authorization state. Define exactly which backups restore which assets and metadata. Never silently replace the node identity or create a new trust relationship under the label of recovery.

## 7. Decisions required before implementation

| Decision | Recommended choice | Cost or consequence |
|---|---|---|
| 1. Initial approval subset | Start with an already-enrolled separate owner device, with the enforceable role boundary in section 4. Keep the one-device ceremony separate | Requires another available device and verified enrollment. A second pairing on one install does not qualify |
| 2. First owner and last authority lost | Keep existing enrollment as an explicit prerequisite for the first slice. Design owner-held, non-hosted recovery separately before promising empty-hardware onboarding or last-authority recovery | First-owner provisioning may still need help, and losing the last authority remains unsupported. A recovery design must identify who holds authority and what cannot be recovered |
| 3. Grant policy and replacement | Use the actual node-enforced, owner-selected bounded terms and expiry. Retain the current explicit fresh-grant model for the initial slice, with independent approval and disclosure of unresolved older payments; defer cross-grant carryover to a separate design | A deliberately approved replacement creates a new meter, not recovery of the old allowance. Unknown liabilities remain visible and must be reconciled. Owner approval of this policy and actual defaults is still required; do not invent numerical UI limits |
| 4. Cancel, decline, revocation and breakers | Make dismissal local-only and expiry truthful while no decline/cancel API exists. Expose revocation only with verified target and in-flight semantics. Integrate breaker reset only with its advertised sub-capability and independent approval | The first slice cannot promise immediate server-side cancellation. Unsupported revoke paths remain unavailable. Reset quota and budget accounting stay unchanged |
| 5. Platforms and key protection | Support only platform pairs whose enrolled-owner key protection, user-presence behavior, role controls and recovery route are verified on the exact app/node build. Publish that tested support matrix before release | Narrows initial reach and requires platform-specific tests. No platform is approved or declared supported merely by this proposal |
| 6. Release failure gates | Make every listed safety and unaided-use gate mandatory: no false paid/unpaid result, no false readiness, no hidden helper, no same-requester or same-install self-approval, and no authority/budget bypass through recovery or replacement | A failed or untested gate blocks the corresponding completion claim and release slice; accurate unavailable states are preferable to apparent success |

Each row is a recommendation for owner and security review, not a recorded decision or risk acceptance.

These are product and security choices, not permission for live financial or credential actions.

## 8. Testable acceptance cases

Run future engineering tests on isolated approved regtest/signet fixtures, not live funds. Record exact versions, feature flags, initial state, action, persisted result, and visible result. No test execution is claimed by this document.

- **B1 Eligible owner:** A different enrolled owner can approve an unchanged bounded request; only its intended operation receives the resulting authority.
- **B2 Ineligible approver and device-role conflict:** Same-pairing, Read/AI-only and revoked-owner attempts fail without grant creation or budget change. Also refuse same install with a second pairing and an AI requester pairing on the approver's device, including import, restore and role-change paths. Test direct requests that bypass the UI against the reviewed enforcement boundary. A different client ID alone is not acceptance evidence; unsupported physical-device separation remains a release blocker for that claim.
- **B3 Bound terms:** Mutating node, requester, epoch, recipient, amount, window, nonce, or operation invalidates the approval. Displayed and signed terms agree.
- **B4 Replay and concurrency:** Duplicate signatures, retries, and racing submissions produce at most one effective grant/outcome, without budget reset.
- **B5 Restart:** Lost pending requests are shown as requiring reconciliation, not as evidence that no payment occurred. Persisted receipts remain authoritative within their documented scope.
- **B6 Dismissal:** Dismissing a card never claims a server-side decline/cancel unless that operation actually exists and succeeds.
- **B7 Replacement:** Recovery alone issues no fresh grant. Deliberate independent-owner approval of a new budget is explicit. Old reservations cannot dispatch against, debit or refund the new grant. Test replacement before dispatch, after wallet submission, during late settlement and across restart; preserve truthful old-payment outcomes and prevent duplicate payment. Cross-grant carryover, if selected, needs separate acceptance evidence.
- **B8 Revocation:** Grant, key, and pairing revocation affect only their specified targets, with explicit consequences and tested in-flight ordering.
- **B9 Breaker:** The base capability alone offers no reset. With the reset sub-capability, require an independent eligible owner, unchanged meter digest/live grant, durable rolling quota and preservation of budget, deadline and unresolved accounting. Self, stale, expired, over-quota and persistence-failure cases fail without clearing the breaker.
- **B10 Locked reboot:** A known locked node remains pinned. Recovery does not trust a replacement node merely at the previous address.
- **B11 Cookie rotation:** Chain-source recovery alone does not mark the payment backend ready. The supported recovery path requires no console helper.
- **B12 Lost pairing:** A replacement requester needs valid surviving-owner approval; old grants and liabilities are not silently transferred or cleared.
- **B13 Biometric failure:** Failure grants no authority; the legitimate supported recovery path does not weaken authentication.
- **B14 Lost key/reset:** Before destructive app reset, the owner is warned about loss of the sole key. Unsupported last-authority recovery is not presented as available.
- **B15 Request flooding:** Untrusted requests cannot authorize themselves or make legitimate recovery permanently unavailable; rate and queue behavior is specified and tested.
- **B16 Lost send response:** Reconciliation of an uncertain operation does not send a duplicate payment or assert a false unpaid state.
- **B17 Disabled capability:** An older or feature-disabled node receives an accurate unavailable state, not a broken approval promise.
- **B18 Revocation race:** Revocation during approval has a deterministic, documented persisted outcome and matching app state.
- **B19 Privacy:** Logs, screenshots, and test reports contain no secrets, recovery material, or unnecessary personal data.
- **B20 Crash consistency:** Crashes at approval consumption, persistence, acknowledgment, and token refresh cannot produce duplicate authority, reset limits, or false success.

- **B21 Request deadline:** Submit an unchanged, correctly signed operation exactly at and after its deadline. Independently expire wall time and monotonic elapsed time in deterministic fixtures. Refuse with no new authority or budget mutation; distinguish expired from unknown-after-restart. Signature validity does not extend time.
- **B22 Grant snapshot deadline/replacement:** Expire or replace the referenced live grant after request creation but before approval. Correct signatures must still fail. No authority or budget mutation; the app requests fresh review rather than silently substituting new terms.
- **B23 Issued first-contact expiry:** Test the earlier of approval+120 seconds and underlying grant expiry, including the boundary. Refuse new dispatch after expiry without renewing automatically; preserve an already-submitted payment as unknown or settled according to evidence, never infer unpaid from elapsed time.
- **B24 Grant expiry mid-operation:** Pause before first wallet poll, expire the grant, and assert no dispatch. Separately expire it after a poll that may have submitted money: stop further unauthorized dispatch and reconcile the existing operation without duplicate payment or false unpaid state. Repeat across restart with authoritative operation history.

Require exact-head review and regression tests for the authority boundaries. Mutation or negative tests should demonstrate that removing a binding or eligibility check causes test failure. Passing UI screenshots alone is insufficient.

## 9. Older-user acceptance gate

Recruit at least three consenting ordinary device users aged 65 or older, not developers or administrators of this system. Collect only minimal necessary demographic information. This small acceptance exercise is not a statistical claim about all older users.

Freeze and record the exact build, setup, supplied materials, supported platforms, and enrolled-device prerequisites. Second-device enrollment is outside the five-decision count only for a scenario explicitly starting with that device already enrolled. Record it separately as helper provisioning, including all preparation and any terminal or expert work. That result is approval or recovery with provisioned devices, not unaided onboarding.

If enrollment, reenrollment or a role change is required during a scored scenario, its authority and recovery decisions count toward the same five-decision limit, and any helper intervention fails the unaided score. An end-to-end onboarding test must include second-device enrollment and cannot reuse the provisioned-device exemption. Participants perform approval, node restart recovery, pairing-loss recovery with surviving authority, and app-lockout scenarios using only the stated materials.

For each supported scenario, require no more than five user decisions, zero hints, no terminal, and no hidden settings or off-screen helper actions. Count every authority choice, recovery choice, and retry rather than excluding inconvenient steps from the total. Report each participant and each scenario separately, not only an average.

Afterward, verify comprehension of four points: whose authority was used; what limit and duration were approved; whether payment is complete, failed, or still unknown; and what unresolved danger or unavailable recovery remains. False unpaid or ready interpretations fail the gate even if the participant reached the final screen.

An unsupported last-authority-loss scenario must be described honestly and must not be scored as successful recovery. Provisioned-device success does not establish complete unaided onboarding from empty hardware.

## 10. Handoff and implementation boundary

The next engineering step is a version-specific contract inventory and owner decision record, followed by a reviewed implementation plan for the selected subset. Do not duplicate held work, silently broaden recovery authority, add a public fallback, or change live node configuration.

This is a design deliverable only. Identified existing source features are explicitly revision-scoped. It makes no claim of newly implemented features, newly passing tests, accepted risk, release readiness, or completed household recovery.
