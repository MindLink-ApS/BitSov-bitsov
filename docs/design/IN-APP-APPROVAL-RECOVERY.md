# In-app spend approval and unaided recovery

Q10 design-only draft · 9 November 2026

**Status:** Proposed design, not implementation or release approval. Historical contract evidence below is not verified against the current implementation. No live node, credential, payment, signing, deployment, or recovery action has been performed. This document does not authorize those actions.

## 1. Outcome and recommended first slice

An ordinary older owner should be able to understand and approve a bounded spending request in the app, and recover from routine node restart, pairing loss, and app lockout without a terminal or a hidden helper. The interface must distinguish authority, connectivity, chain readiness, backend readiness, and payment outcome. A healthy connection does not establish permission to spend. A current chain tip does not establish a usable payment backend.

Start with an already-enrolled second owner device approving a different requesting client. This follows the historical contract's separation between requester and approver. Do not enable a one-device journey by deleting the same-pairing prohibition. First-owner enrollment, same-device approval, and loss of the last owner authority require separate reviewed security designs.

The first slice is intentionally narrower than complete empty-hardware onboarding. It must disclose its enrolled-owner prerequisite. Successful testing with provisioned devices does not prove that a new owner can provision the system unaided.

## 2. Evidence and uncertainty

The research reviewed the owner-approval v1 contract, older owner-device approval design, home-node unlock and pairing contract, local-owner ceremony contract, phone walkthrough, and premise red-team findings. These are design and historical project evidence, not proof of current runtime capability.

The historical v1 contract described:

- Requests for spend grants and first contact; request TTL 300 seconds, with first-contact requests limited to 120 seconds.
- Pending approval operations lost on restart, while spend receipts persist.
- A remote-owner pending list that excludes the requester's own pairing.
- A prohibition on same-pairing approval. An already-enrolled second owner is required by that contract.
- Paired Read/AI tokens able to request but not approve. Approval requires a current enrolled owner-device key and matching authenticated Noise context.
- Signed binding to node, client, owner key, epoch, grant, recipient, limits, operation, nonce, and expiry.
- No decline/cancel endpoint and no implemented breaker-reset operation in that contract.

An older design proposed same-device approval with biometrics and breaker reset. Those proposals must not be presented as implemented v1 behavior. Likewise, advertised capability does not establish that the feature is enabled or usable in the installed version.

Before implementation, inventory exact app/node versions, exposed endpoints, feature flags, persistence and restart behavior, owner enrollment, revocation, token refresh, and reconciliation support. Resolve any disagreement with the historical contract before writing UI copy or tests that assume it. Existing held implementation work remains held unless separately released by its owner.

## 3. Options and costs

### A. Already-enrolled second owner device — recommended first slice

Benefits: preserves requester/approver separation and offers the clearest fit with the historical contract.

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

1. The requesting client creates a bounded request. Creating a request is not payment and is not grant approval.
2. An eligible owner app obtains the request through an authenticated, pinned-node connection. A notification or link is a navigation hint, not authority.
3. The app displays the requesting device, intended recipient or action, total limit, time window, and consequences. Device and recipient labels require a verified mapping; attractive names alone are not identity evidence. A time-window budget must not be described as a recurring daily allowance unless that is the actual contract.
4. The owner signs the exact bound terms using an eligible owner key. Local biometric success does not replace node-side authorization, key eligibility, current epoch, or requester separation checks.
5. The node validates and consumes the approval atomically, persists the outcome, and returns an authoritative result. Concurrent submissions and retries must not create duplicate grants or reset a budget.
6. The app obtains any required updated authorization and resumes only the original operation within the approved limits. It must not silently expand the recipient, duration, or scope.

Bind node identity, requester/client and pairing epoch, owner key, operation, grant, recipient, limits, nonce, and expiry. Any changed term requires a fresh review and signature. Display text must correspond to the signed payload.

If an approval response is lost, show an uncertain state and reconcile requests, grants, and operation/payment records. A missing request after restart is not proof that no approval or payment occurred. Card dismissal is not decline or cancellation when no such endpoint exists. Never tell the owner an operation was cancelled merely because a local card disappeared.

## 5. Revocation, limits, and breakers

Distinguish revoking a grant, an owner key, a pairing, and an identity. Each has a different effect. The app must describe the exact target and the resulting loss of access.

Replacement must preserve spent amounts, pending liabilities, and other applicable budget history. It must not provide a way to reset limits by reenrolling, changing a pairing, or requesting a new grant. Revoke-versus-in-flight ordering needs a specified node-side result, not only a UI animation.

Breaker reset requires independent owner authority and a separately specified operation. Do not let a requester reset its own safety breaker, and do not invent a reset endpoint because an older design mentioned it. If reset is unavailable, explain the blocked state accurately.

## 6. Recovery journeys

### Node restart

Separate starting, locked, authenticated, chain-source health, payment-backend health, and ready states. An app that recognizes a previously paired node must not silently trust a replacement identity at the old address. Use the pinned identity and an approved unlock route; do not substitute trust-on-first-use during recovery.

A restarted node can lose pending approval requests while retaining receipts. Reconcile before reissuing an operation. A fresh request must not imply that an earlier payment is known to have failed.

Core cookie rotation is a specific split-health case: the chain provider may reread credentials while the payment backend may require restart or reinitialization. Determine actual version behavior. Do not display overall readiness because only one component recovered. The accepted app lifecycle recovery must work without a hidden console helper.

### Pairing loss with surviving owner authority

Treat reenrollment as a new, untrusted requester until an eligible surviving owner approves it. Make old-device loss and possible theft explicit. Revoking an old pairing is an owner action with consequences, not an automatic inference from a connection failure.

Do not transfer grants, reset budgets, or waive pending liabilities simply because the replacement device belongs to the same person. Define continuity and reconciliation before enabling this journey.

### App lockout

Distinguish failed biometrics, an expired session, revoked authority, rate limiting, node outage, and loss of the owner key. These states need different remedies.

Warn before app reset, reinstall, or local-data clearing can destroy the only owner key. Do not weaken authentication or counters to make the screen recover. Legitimate recovery must remain available under request flooding, without allowing a requester to bypass rate limits or authority checks.

### Last owner authority lost

Until an owner-held recovery ceremony is specified and tested, state that this case is unsupported. An address, support claim, device name, or knowledge of personal details is not owner authority.

Do not promise that a wallet seed restores channel state, operation history, pending liabilities, or all node identity and authorization state. Define exactly which backups restore which assets and metadata. Never silently replace the node identity or create a new trust relationship under the label of recovery.

## 7. Decisions required before implementation

1. Approve the already-enrolled second-device subset as the initial deliverable, or require a separately designed one-device ceremony first.
2. Select the intended first-owner and last-authority-loss recovery model, including who holds recovery authority and what remains unrecoverable.
3. Define grant defaults, maximum scope, expiry, replacement semantics, and treatment of pending liabilities. Do not invent numerical limits in the UI.
4. Decide the required cancel, decline, revoke, and breaker-reset behaviors; distinguish release requirements from later work where APIs are absent.
5. Select supported app/device platforms and confirm the available key-protection and user-presence capabilities on each.
6. Approve explicit release failure gates: no false paid/unpaid result, no false readiness, no hidden helper, no same-requester self-approval, and no bypass through recovery or replacement.

These are product and security choices, not permission for live financial or credential actions.

## 8. Testable acceptance cases

Run future engineering tests on isolated approved regtest/signet fixtures, not live funds. Record exact versions, feature flags, initial state, action, persisted result, and visible result. No test execution is claimed by this document.

- **B1 Eligible owner:** A different enrolled owner can approve an unchanged bounded request; only its intended operation receives the resulting authority.
- **B2 Ineligible approver:** Same-pairing, Read/AI-only, and revoked-owner attempts fail without grant creation or budget change.
- **B3 Bound terms:** Mutating node, requester, epoch, recipient, amount, window, nonce, or operation invalidates the approval. Displayed and signed terms agree.
- **B4 Replay and concurrency:** Duplicate signatures, retries, and racing submissions produce at most one effective grant/outcome, without budget reset.
- **B5 Restart:** Lost pending requests are shown as requiring reconciliation, not as evidence that no payment occurred. Persisted receipts remain authoritative within their documented scope.
- **B6 Dismissal:** Dismissing a card never claims a server-side decline/cancel unless that operation actually exists and succeeds.
- **B7 Replacement:** Reenrollment and replacement grants retain applicable spent amounts and pending liabilities; no reset path appears.
- **B8 Revocation:** Grant, key, and pairing revocation affect only their specified targets, with explicit consequences and tested in-flight ordering.
- **B9 Breaker:** The requester cannot reset its own safety breaker; unavailable reset is accurately reported.
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

Require exact-head review and regression tests for the authority boundaries. Mutation or negative tests should demonstrate that removing a binding or eligibility check causes test failure. Passing UI screenshots alone is insufficient.

## 9. Older-user acceptance gate

Recruit at least three consenting ordinary device users aged 65 or older, not developers or administrators of this system. Collect only minimal necessary demographic information. This small acceptance exercise is not a statistical claim about all older users.

Freeze and record the exact build, setup, supplied materials, supported platforms, and enrolled-device prerequisites. Disclose all helper provisioning. Participants perform approval, node restart recovery, pairing-loss recovery with surviving authority, and app-lockout scenarios using only the stated materials.

For each supported scenario, require no more than five user decisions, zero hints, no terminal, and no hidden settings or off-screen helper actions. Count every authority choice, recovery choice, and retry rather than excluding inconvenient steps from the total. Report each participant and each scenario separately, not only an average.

Afterward, verify comprehension of four points: whose authority was used; what limit and duration were approved; whether payment is complete, failed, or still unknown; and what unresolved danger or unavailable recovery remains. False unpaid or ready interpretations fail the gate even if the participant reached the final screen.

An unsupported last-authority-loss scenario must be described honestly and must not be scored as successful recovery. Provisioned-device success does not establish complete unaided onboarding from empty hardware.

## 10. Handoff and implementation boundary

The next engineering step is a version-specific contract inventory and owner decision record, followed by a reviewed implementation plan for the selected subset. Do not duplicate held work, silently broaden recovery authority, add a public fallback, or change live node configuration.

This is a design deliverable only. It contains no claim of implemented features, passing tests, accepted risk, released software, or verified delivery into another environment.
