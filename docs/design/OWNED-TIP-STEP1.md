# Owned tip onboarding Step 1

Status: design proposal v3 for owner review, 10 November 2026. No implementation or deployment is approved by this document.

## Recommendation

Connect an existing owner-controlled Bitcoin Core or Electrum service first. Defer installing, upgrading or exposing a chain service to a separately approved project. Provide an explicit, owner-driven transition for existing nodes, with validation before activation and no silent public fallback.

This step closes the onboarding design gap between choosing an owned chain source and operating against it safely. It does not complete timechain phase or entrainment, prove independent validation merely by selecting an endpoint, or make the entire application ready for unaided household use.

## Intended outcome and scope

A household owner can connect a supported, already-running chain service through the application without editing configuration or opening a terminal. The application explains what has been verified and what still prevents messaging or payments.

The target audience includes an older adult setting up without a helper. The design covers both a new node and an existing node using an explorer. The supported evaluation networks are signet and regtest. A real deployment, new persistent access, source installation, or network/security change requires separate owner authorization.

The following are outside Step 1:

- Automatic Bitcoin Core or Electrum installation, initial infrastructure provisioning and firewall changes.
- A generic configuration editor, wallet migration, seed import or recovery-phrase handling.
- Mainnet rollout, liquidity purchases, channel operations and changes to spend policy.
- Silent upgrades or rewrites of existing configurations.
- AI grants, inference, social-graph publication, and phase/entrainment algorithms.
- Publication, release signing, or a claim that unaided onboarding is already shipped.

## Evidence boundary

Existing recorded building blocks are the network gate from #535, fail-closed tip handling from #541 and the read-only explorer warning from #544. The general source switcher from #537 was parked. Those components do not establish that an application-based source transition exists.

This proposal relies on documented requirements and recorded change evidence. Their integration must be rechecked against the implementation base and deployed release before coding or testing. A merge on the development branch does not put that behavior on an installed household box. Endpoint contracts, supported authentication forms and runtime restart requirements are implementation discovery items, not capabilities asserted here.

## Architecture and trust boundaries

The application is the owner's control surface. The owner's BitSov node validates and uses the configured chain source. Both the BitSov chain reader and embedded Lightning backend must use the selected compatible source; choosing a source in the UI is insufficient if one backend silently continues using another.

Connection configuration contains a source type, address, network expectation and a reference to approved authentication material. Secrets must remain outside ordinary configuration previews, telemetry, support exports and error text. Do not copy a remote service's cookie file into chat or use the application to browse seed directories.

Changing the active chain source is an authority change, including switching to a reachable, fresh Core service on the correct network. Such a service could still be attacker-controlled and hide chain events. Network and freshness checks do not authorize the change.

Activation requires an eligible enrolled owner key, with the requester/approver separation required for spending approval. A Read/AI pairing or a mere authenticated session cannot propose and activate its own change. An app install must never hold both the requesting pairing and an approving owner key for the same node; adding a second pairing on that install is the same-device case, not independent approval. The first supported route requires a separately enrolled owner device. Missing owner authority leaves setup incomplete; first-owner enrollment and last-owner recovery are separate designs.

The owner must review and authorize the exact node identity, current configuration revision, source type and endpoint, expected network, transport/trust mode, any certificate fingerprint, approved authentication reference, and affected backends. Bind these non-secret terms, operation identity, nonce and expiry to a narrowly scoped source-change authorization. Recheck eligible owner authority and unchanged terms at activation. A changed endpoint, pin, authentication reference or configuration revision requires fresh review. Returning to an earlier source uses the same rule.

Existing spend approvals do not authorize configuration changes. The implementation needs a separately reviewed typed source-change operation; inventory existing APIs and enrollment capabilities before specifying it. The present node checks distinct pairing client IDs, not distinct physical devices. The implementation plan must specify how role conflicts are refused and what independently verifies the supported separate-device prerequisite. A UI label or another client ID is not proof. This proposal does not declare that stronger enforcement, a source-change endpoint or a new authorization mechanism is implemented.

### Keep these facts separate

| Fact | Meaning | What it does not establish |
|---|---|---|
| Ownership | The owner controls the selected service and its administration | A reachable address or a checkbox does not prove control |
| Network | Reported chain identity matches the selected test network | Matching a network does not establish freshness or validation |
| Freshness | Tip observations meet the existing network-specific freshness policy | A recent timestamp or height does not prove independent validation |
| Validation backing | The selected service is backed by a known validating node under the stated control model | An Electrum server label alone does not prove this |
| Chain readiness | The selected source is usable under the network, sync and freshness rules | It does not mean Lightning, channels or grants are ready |
| Payment readiness | Existing payment gates and required permissions are satisfied | It does not mean every intended contact or call can succeed |

Owner-controlled Electrum is a supported alternative interface. Its backing node, validation behavior and operator control must be established or shown as unverified. Do not call an unknown Electrum service equivalent to an independently validating Core node. Protocol observations alone cannot prove who administers a server. State the evidence and trust assumption honestly.

## Options and costs

| Option | Benefit | Costs and dependencies | Recommendation |
|---|---|---|---|
| Connect existing owned Core | Reuses a validating service already operated by the owner | Authentication setup, uptime, transport protection and network compatibility; remote access may require separately approved setup | First supported route where compatible |
| Connect existing owned Electrum | Reuses an existing indexed interface and can avoid operating another instance | Verify backing validator and ownership; existing index/storage and maintenance remain operator costs | Equal first-step alternative with precise trust disclosure |
| Install a new owned service | Removes dependency on an unavailable existing service | Software lifecycle, storage, initial synchronization, bandwidth, power, indexing if selected, backups and recovery UX | Later separate design and authorization |
| Explicit external explorer mode | Preserves a deliberately chosen external dependency where allowed | Availability, metadata exposure and provider trust; does not meet the owned-source goal | Never automatic; not the successful owned-tip route |

No prices, hardware minimums or synchronization durations have been measured for this design. Connecting an existing service is not cost-free: incremental load, administration and uptime matter. Before recommending new hardware, measure the chosen network, storage mode, available disk, RPC/index load, steady-state bandwidth and recovery time. Do not turn generic estimates into a budget commitment.

An already-running source may still require secure authentication provisioning. If that requires terminal work today, show it as an unmet precondition rather than calling the whole journey zero-terminal.

## Proposed new-node journey

1. **Choose the existing source.** Offer an owned Core or owned Electrum connection with a short explanation. Do not scan arbitrary networks or promise automatic discovery. A future discovery method needs its own verified threat model and consent behavior.
2. **Provide approved connection details.** Use the supported secure local setup mechanism. Present the expected test network and the selected source without displaying secrets. If access is not provisioned, stop with one clear next action.
3. **Check before saving.** Probe the candidate read-only using bounded requests. Check syntax, allowed destination, transport/authentication policy, network identity, sync state and freshness. Record backing-validation evidence separately. Electrum must use CA-valid TLS with hostname validation, an explicitly approved local TCP route, or a reviewed certificate-pinning route using an owner-confirmed fingerprint delivered with the connection material through an independently trusted channel. No silent trust on first use, first-seen pinning, or disabling certificate verification. A fingerprint read only from the candidate connection is not independent evidence. A pinned fingerprint mismatch or change fails closed; replacement needs fresh owner approval from trusted connection material. Local TCP remains limited to the implementation's allowed local destinations and has no TLS server-identity guarantee; disclose that trust assumption. Pinning is a proposed route, not a present capability: until both backends support and enforce the same approved pin, a self-signed server needing that route is unsupported. A test probe does not fund, send, create a channel or grant persistent access implicitly.
4. **Owner confirms activation.** Show the source type, network, control/trust description and whether a restart is required. Obtain the independent eligible owner-key authorization described above for the exact change. A local confirmation button alone is insufficient. No source switch occurs from pressing Back, Retry or Cancel.
5. **Activate and report state.** Confirm both backends use the same approved source and apply existing payment gates. Show a precise state such as “Bitcoin source connected; waiting for synchronization” or “Source ready; spending approval still needed.” Never present source success as completed messaging setup.

For a new node without an existing service, offer “Set up a source later” and preserve safe incomplete setup. Do not write public explorer URLs or silently choose mainnet to make progress appear complete. The implementation must reconcile this with the current fresh-init path before it is enabled.

## Proposed existing-node journey

An existing explorer-backed node first receives an informational warning with the current source category and consequences. Opening the screen must not rewrite config, change file permissions, read recovery material or restart anything.

1. Owner chooses “Change Bitcoin source.” Capture the active configuration revision and safe non-secret source summary.
2. Validate a candidate using the same read-only checks as a new node. Active operation continues only under its existing policy; candidate checks never assert that the existing source is healthier than it is.
3. Present a before/after summary, compatibility result, expected interruption and explicit trust changes. Do not silently narrow or enlarge payment permissions.
4. Before activation, the implementation must determine whether outstanding payment/session operations require deferral. Do not cancel or retry money operations as a source-switch side effect. If quiescence cannot be proved, defer activation and explain why.
5. On explicit independent owner-key confirmation, recheck the active configuration revision, candidate health and the complete authorized terms, including transport trust and current key eligibility. A concurrent edit invalidates the proposal and requires a fresh preview and approval; do not overwrite another writer's changes.
6. Commit only the approved source fields through a separately reviewed, crash-safe configuration transaction. Preserve unrelated fields and all legacy omitted-URL semantics outside the explicitly approved transition. The exact persistence mechanism requires implementation review; do not reuse the parked general switcher without resolving its findings.
7. Reinitialize or restart only through the approved node lifecycle path if required. Validate the effective source for both backends and persist enough non-secret state to explain an interrupted transition.
8. Report activated, activation failed, or recovery needed. Fail closed on an invalid/unknown effective source. No automatic explorer fallback, even if the previous source was an explorer.

### Failure and rollback policy

Before the commit boundary, Cancel or validation failure leaves the active configuration unchanged. After a committed but unsuccessful activation, keep spending closed and offer an explicit owner-reviewed recovery action. Restoring a previous source must be separately visible and confirmed, must pass current checks, and must not alter wallet/database versions. Returning to an external source is a disclosed external-dependency choice, never a hidden rollback.

If the application cannot recover unaided after a crash, restart or lockout, mark the journey incomplete. A console helper procedure may be documented as a limitation; it does not satisfy the zero-terminal acceptance bar.

## Current fallback and transport inventory

Source locations below were checked at node revision `d99252f11e7feeca7888d50a232633c589e5f2d7`. Recheck the implementation base before coding. These are existing paths to close for an explicitly selected owned source, not proof that a transition is implemented.

| Existing path | Current behavior | Required Step 1 treatment |
|---|---|---|
| `crates/konsensus-lightning/src/ldk.rs:85-89`, with startup handling from `:783` | `[lightning] esplora_url_fallback` can supply another explorer when the primary fails at startup | Owned-source activation must exclude both Esplora primary and fallback from the effective Lightning path, including startup, reinitialization and error handling. Dormant explorer fields and their credential references must not be read or used to select or initialize that backend |
| `crates/konsensus-node/src/config.rs:1039-1056`, `ChainConfig::esplora_fallbacks` | An Esplora chain reader without an explicit fallback reuses the Lightning primary/fallback URLs | Both backends must select the approved owned-source mode. No chain-reader URL inheritance or fallback to the Lightning explorer URLs after transition |
| `crates/konsensus-node/src/config.rs:1076`, `:2269`, `:2417-2423` | Fresh construction writes public explorer primary/fallback defaults for chain and Lightning | The new owned-source journey must not invoke these defaults to fill an incomplete selection or after recovery. No source means incomplete setup. Preserve legacy omitted-field interpretation outside an explicitly authorized transition; do not silently rewrite other existing nodes |

After an owned-source transition, no Esplora primary/fallback field is read by either backend for source construction, selection, authentication or recovery, and no request is sent to one. Parsing or retaining inert legacy configuration for compatibility is not permission to use it. A required source field that is absent or incompatible fails closed rather than re-entering a default construction path. Test effective configuration and captured network traffic across restart and failure, not only the selected UI option.

`crates/konsensus-chain/src/electrum.rs` currently accepts `ssl://` or allowed local `tcp://` endpoints and has no owner-confirmed certificate-fingerprint field. The Lightning backend configures its own Electrum client in `crates/konsensus-lightning/src/ldk.rs:973`. A custom pin must be enforced on both actual client connections, not merely on a successful preliminary probe. Never disable verification to fit a self-signed server into the existing interface.

FreshTip in `crates/konsensus-node/src/node.rs:858-866` bounds the BitSov chain reader. It is not evidence that Lightning's own synchronization is healthy. Preserve separate backend health and the acceptance checks below.

## Proposed state and error presentation

| State | Meaning | Primary next action |
|---|---|---|
| No source selected | Setup has not chosen a usable source | Choose source |
| Access unavailable | Address, authentication or approved transport cannot be used | Review connection |
| Wrong network | Source identity differs from configured network | Choose a matching source |
| Source synchronizing | Source reachable, but not ready under existing sync policy | Check progress |
| Tip stale or unknown | Freshness cannot be established | Check source |
| Source ready | Chain-source checks pass; other gates are evaluated separately | Continue setup |
| Activation interrupted | Effective configuration is unresolved or activation failed | Review recovery |
| Spending approval missing | Source can work, but app lacks required authority | Review approval |

Copy is illustrative, not implemented localization. Each screen has one primary recovery action; supporting detail may remain available. Do not expose raw RPC errors or credentials. Repeated clicks must be idempotent, not create multiple transitions. App restart, Back, Cancel and reopening setup must show the effective state, not a stale success screen.

Budget copy must describe the actual grant: a total amount for a specified window of up to 24 hours where applicable. Do not describe it as a recurring daily allowance or imply a restart replenishes it.

## Open dependencies

- Owner-device spending approval is separate from source selection. Existing console-based grants do not satisfy the unaided path.
- A usable owner-controlled authentication mechanism for both local and remote sources needs verification. New persistent credentials or broader access require explicit authorization.
- Unaided recovery from pairing loss, source-switch failure, app lockout and node restart remains an independent requirement.
- Distribution, signed installation, contacts, liquidity, reachability and real call/payment evidence are not delivered by this design.
- Existing-node read-only warning is useful but is not a source migration implementation.
- Household Core availability and correct network must be checked under separate permission; this proposal assumes neither.

## Owner decisions

| Decision | Recommended choice | Cost or consequence |
|---|---|---|
| Step 1 audience | Owners with an already-running compatible Core or Electrum service | Smaller scope; users without one need a clearly incomplete path |
| Installation scope | Defer automated installation | Avoids unmeasured disk, bandwidth and maintenance commitments; does not solve all new households |
| Existing-node activation | Explicit preview, validation and independent owner-key authorization | Requires an enrolled separate owner device; protects against an unauthorized same-network source switch |
| Remote source access | Use an approved protected route; no new public exposure by default | May require separate authentication/transport setup and owner action |
| External explorer option | Explicit, labelled exception only if owner retains it | Accepts provider dependency; cannot count as owned-tip completion |
| Full household completion claim | Block until approvals and recovery work unaided | Source setup may finish before the product journey does |
| Test-network/default policy | Keep this step signet/regtest; decide public-build behavior separately | Requires explicit compatibility validation; no mainnet enablement here |

The connect-existing-first direction is the design brief. Remaining choices above are recommendations for review, not recorded approvals of implementation or live changes.

## Acceptance and regression plan

No tests were run for this design. These are required future checks, not completed evidence.

| ID | Scenario | Required result |
|---|---|---|
| A1 | New node with owned Core on matching signet/regtest | Source, sync/freshness and payment readiness shown separately; no external fallback |
| A2 | Owned Electrum with known validating backing node | Interface, backing validation and ownership evidence recorded distinctly |
| A3 | Electrum backing validation unknown | No “independently validated” or fully sovereign success claim |
| A4 | Wrong network, including partial chain/Lightning config mismatch | Candidate refused before activation; money paths remain gated |
| A5 | Unreachable, stale, unknown or synchronizing candidate | No source success claim, invoice or payment caused by setup |
| A6 | Candidate validation cancelled | Existing config bytes and unrelated file permissions unchanged |
| A7 | Existing omitted URL fields before explicit transition | Legacy interpretation unchanged; warning does not migrate |
| A8 | Successful explicit transition, then source failure and restart | Both backends use the selected source; no Esplora primary/fallback field is read by either backend for operation. Exercise Lightning startup fallback, chain-reader inheritance and fresh-default recovery paths with trap endpoints; capture zero explorer requests. Missing owned-source fields fail closed |
| A9 | Concurrent edit after preview | Activation refuses stale revision; new preview required |
| A10 | Crash before commit, during commit and after commit | Defined recoverable state; no half-written config or fabricated readiness |
| A11 | Repeated confirmation, Back/Cancel and app restart | One transition at most; UI matches effective state |
| A12 | Unresolved money operation during transition | Defer safely; no implicit retry, cancellation, payment or grant expansion |
| A13 | Activation fails and previous source is external | No automatic fallback; any restore is explicit and revalidated |
| A14 | Source loss after activation | Existing fail-closed gates apply; UI withdraws readiness without inventing a new timeout policy |
| A15 | Secret-bearing errors and diagnostic exports | No credentials, recovery material or secret-bearing URLs disclosed |
| A16 | Source ready but app approval/recovery missing | “Setup incomplete”; does not pass the household test |
| A17 | Persistence path substitution, symlink and unsafe backup cases | Reviewed fail-closed behavior; no unrelated or recovery-file writes |
| A18 | After activation, restart Core and rotate its authentication cookie in an isolated fixture | Show chain-reader and Lightning health separately; retain existing payment gates while either required backend is unavailable; no external fallback, leaked credentials or implicit privilege expansion; recover through the approved app/lifecycle route, then recheck both backends. Terminal/helper recovery means the unaided result fails |
| A19 | Fresh, correct-network attacker-controlled candidate; Read/AI/session-only caller; same install with second pairing | Candidate health never supplies authority. Activation needs a distinct eligible owner key and the reviewed separate-device/role boundary; refuse self-approval, stale authority, altered terms and stale configuration without source or budget changes |
| A20 | Electrum TLS and pinning cases | CA-valid matching-host TLS works only through supported clients; invalid CA/hostname and unsupported self-signed routes fail. An independently supplied owner-approved pin, if implemented, must be enforced by both clients. Missing/untrusted first-seen pin, changed pin and probe/runtime certificate substitution fail closed without a fallback or silent verification bypass |

For security/payment-related implementation, include tests that fail against the pre-change behavior and mutation checks of the actual guards. Bound probes, retries and response sizes. Use isolated fixtures; no production-node contact is needed to prove most rejection cases.

### Unaided household test

Run formative sessions with at least three consenting owners aged 65 or older who use everyday phone/computer applications but do not administer Bitcoin services or develop this product. This proposed sample is a minimum usability gate, not a statistical claim about all older adults. Record age band and relevant experience only, without unnecessary personal data. A developer/operator demonstration cannot substitute for these sessions.

Before each session, record the exact app/node build, device and supported test network, and provision a compatible owned source with the selected supported authentication method. Supply only the application, a neutral task card (connect your existing Bitcoin source), and the exact user-facing connection material: source type, owner-chosen service label, network and a supported address/code/QR or secure enrollment handoff. Use only formats the implementation actually supports. Do not supply raw secrets in the test record, custom terminal commands or an unstated preconfigured shortcut. Document what setup the facilitator performed beforehand, including separate owner-device enrollment. That enrollment is outside the five-decision connection score only when completed before the scenario and explicitly reported as helper provisioning. If enrollment or reenrollment is needed during the scenario, count its decisions and any help; do not omit them to achieve a pass. Any end-to-end onboarding claim must include enrollment. If obtaining that material requires an expert or terminal, the result establishes connection of a provisioned source only, not end-to-end household onboarding.

Count each user choice that changes configuration, trust, authority or workflow as one decision, including the final activation and any required recovery choice. Repeated attempts at the same choice count again and are also recorded as retries. Reading, typing a supplied value and selecting Continue without another choice are interactions, not additional decisions; log them separately. Record hesitations over ten seconds, errors, elapsed active time and any abandoned or repeated step. Never hide permission prompts or recovery choices from the count.

Pass the source-connection scenario only if every participant completes it with at most five decisions, zero terminal steps, zero hidden settings, zero hints, zero helper intervention and no unsafe success claim. If a facilitator must help, stop the unaided score at that point; a guided continuation is useful diagnosis, not a pass. Include Cancel/reopen and a recoverable failure scenario, including Core restart/cookie rotation where that authentication mode is supported. Score each recovery scenario separately against the same zero-helper/zero-terminal requirements and five-decision limit rather than combining multiple scenarios into one favorable average.

After connection and after recovery, ask each participant, without leading hints: whose Bitcoin service is in use; what validation or ownership fact is still unverified; whether the source and the payment service are ready; and whether spending still needs approval. Compare the answers with the fixture's actual state. All four must be correct in plain language. Treat claiming readiness when a required backend or approval is missing as failure even when the clicks completed successfully. Report participant-level outcomes, not just a pooled success count.

Core authentication recovery needs particular attention: existing integration evidence indicates that the chain reader can reread credentials while the Lightning backend receives them during construction. Recheck this behavior on the tested release. A successful chain query after cookie rotation therefore cannot prove Lightning recovered. The approved lifecycle path may require restarting BitSov; demonstrate that action through the app without silently changing source, permissions or credentials. If unavailable, preserve fail-closed behavior and mark unaided recovery incomplete.

Measure initial source connection separately from blockchain synchronization. Do not promise a synchronization duration or hide it inside a nominal setup-time target. A full “ready” claim additionally requires first message, reply and call, correct spending approval, and recovery after restart. If those dependencies remain open, record the source-onboarding result separately and keep the full household result failed or not run.

## Review exit criteria

The design can advance to implementation planning when the owner accepts scope and costs, reviewers agree on the trust/readiness distinctions, and current APIs plus lifecycle constraints are inventoried. Implementation work must have an isolated ownership claim and preserve other active work.

Reject this design or its implementation if it silently adds a public chain dependency, treats Electrum selection as proof of validation, changes a source without independent owner-key authorization, accepts a self-signed server through first-seen trust or disabled verification, claims terminal-free success with a helper step, or uses source readiness to bypass payment gates.

Phase and entrainment remain a later design stage built on this floor. Their success criteria are not invented or declared achieved here.
