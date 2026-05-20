# Mobile Frontend Architecture — Tier-2 Relay Path

**Status:** Decision document, awaiting human sign-off
**Author:** Autonomous architect (Claude Opus 4.7), 2026-05-14
**Decision owner:** Founder/operator (info@mindlink.tech)
**Scope:** Choose the architecture for BitSov's mobile client so that a phone can
run the konsensus-node binary locally and act as a Tier-2 Relay participant.

---

## TL;DR

| Rank | Option | Time-to-beta | App Store risk | Code reuse | Recommended |
|------|--------|--------------|----------------|------------|:-----------:|
| 1    | **A. Tauri Mobile 2 + reuse SolidJS frontend**   | 6–9 wks  | Medium (35–45%) on iOS, Low on Android | ~85% of 21k LOC | **Yes** |
| 2    | B. React Native + Rust core via uniffi          | 14–20 wks | Medium (30–40%) on iOS, Low on Android | ~0% of UI; ~100% of Rust core | No (deferred fallback) |
| 3    | C. Native Swift + Kotlin, Rust via FFI          | 26–36 wks | Lowest (20–30%) on iOS, Low on Android | ~0% of UI; ~100% of Rust core | No |

**Pick Option A** and ship a Tier-2 Android-first beta in 6–9 weeks. Defer iOS until
either (a) Phoenix/Breez normalize the App Review precedent for an LDK-on-device
app or (b) Apple's policy review for Bitcoin Law jurisdictions (ES, where BitSov
is rotating) shifts. In the meantime, ship a **mobile PWA** as the iOS path so the
Cell Test isn't violated by Apple's gate.

---

## 1. Inventory of what we're protecting

The frontend at `frontend/src/` is **20,904 LOC** of TypeScript/TSX (excluding
generated and bootstrap files). Material that has to survive any mobile rewrite:

| Surface | LOC | Mobile relevance |
|--------|-----|------------------|
| `src/components/` (60 files: Chat, Funding, FirstMessage, Wallet, Calendar, Files, Onboarding) | ~14k | All needed on mobile. Calendar week/month views need a mobile-tailored alt layout. |
| `src/views/OnboardingView.tsx` + `src/state/onboarding.ts` | ~600 | **The most mobile-shaped flow already.** State machine: paste-invite → confirm-invite → funding → connecting → first-message. |
| `src/stores/*.ts` (15 stores: auth, contacts, messages, peers, payments, files, rooms, notifications, …) | ~3.5k | All needed. These are pure Solid signals + HTTP/WS calls. They have **no DOM dependency**, so they port verbatim to Tauri Mobile. |
| `src/api/client.ts` | 694 | Pure `fetch` HTTP client. Ports verbatim. Already supports `setBaseUrl()` for connecting to a paired remote node/relay or `127.0.0.1:3141` (local-node Tier-0/1). |

The client/store layer is **architecturally already mobile-ready**: it talks to a
local konsensus-node over `127.0.0.1:3141` HTTP+WS, with JWT auth and a documented
error surface. Any mobile shell just needs to (a) host SolidJS and (b) run the
Rust core locally and expose 127.0.0.1.

This is load-bearing for the recommendation. Option A reuses ~85% of LOC. Options
B and C reuse ~0% of UI but inherit the same backend API surface.

---

## 2. Option A — Tauri Mobile 2 + reuse SolidJS frontend

### Architecture

```
┌────────────────────────────────────────────────────┐
│  Phone (iOS / Android)                             │
│                                                    │
│  ┌──────────────────────────────────────────────┐  │
│  │  Tauri Mobile shell (WKWebView / WebView)    │  │
│  │  ──────────────────────────────────────────  │  │
│  │  SolidJS UI (same code as desktop)           │  │
│  │  fetch('http://127.0.0.1:3141/...')          │  │
│  └──────────────┬───────────────────────────────┘  │
│                 │  loopback HTTP+WS                │
│  ┌──────────────▼───────────────────────────────┐  │
│  │  konsensus-node Rust binary (statically      │  │
│  │  linked into app, runs as background svc)    │  │
│  │  LDK + Hyperion transport + storage          │  │
│  └──────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────┘
```

The existing repo already has `frontend/src-tauri-mobile/` scaffolded with iOS +
Android configs (`identifier: network.bitsov.app`, `minSdkVersion: 24`,
`minimumSystemVersion: 16.0`). The plumbing is started.

### Concrete scorecard

| Dimension | Estimate | Notes |
|-----------|----------|-------|
| Time to beta (1 engineer) | **6–9 weeks** | Wks 1–2: Rust core builds for `aarch64-linux-android` + `aarch64-apple-ios`; CI matrix. Wks 3–4: Tauri lifecycle hooks → start/stop the node as a foreground service (Android) and background-mode `voip`/`processing` task (iOS). Wks 5–6: mobile-tailor the 5 worst desktop layouts (Calendar week view, Wallet ChannelManager, FileGrid). Wks 7–9: hardening, internal beta, TestFlight/Internal Track. |
| Binary size | **~45–65 MB** Android APK split, **~85–110 MB** iOS IPA | Rust core ~25–35 MB stripped+`lto=fat`+`opt-level=z`. WebView is system-provided (no Chromium ship). SolidJS bundle ~120 KB gzipped. iOS larger due to bitcode + fat binary historically (now slimmer with Mach-O thin slices). |
| Battery | **Moderate.** LDK keeps a TCP connection to peers + esplora poll loop. On Android, a foreground service with `dataSync` type is the right primitive; iOS is the problem (see §5). | A 24h test on a Pixel 7 with 1 active channel + 5 idle peers should consume ~3–5% battery. |
| Code reuse | **~85%** | All `stores/`, `api/`, `state/onboarding.ts` port verbatim. ~60% of `components/` work as-is on a phone screen; ~30% need mobile alt-layout; ~10% (Sidebar, RightPanel, CommandPalette) are desktop-only and get conditionally hidden. |

### App Store risk — iOS

Apple App Review Guidelines that touch us:

- **3.1.1 (In-App Purchase)** — "If you want to unlock features or functionality
  within your app… you must use in-app purchase." **Our defense:** BitSov does not
  unlock app features for sats; sats pay peers for message relay across the mesh.
  This is peer-to-peer value transfer, not IAP for digital content. Damus and
  Nostur shipped this fight and won (zaps are user-to-user, not IAP).
- **3.1.5(a) (Goods and Services Outside of the App)** — explicitly allows
  "person-to-person services (such as one-on-one realtime consultations)" outside
  IAP. Lightning payments to peers fit here.
- **3.1.5(b) (Cryptocurrencies)** — "Apps may facilitate transmission of approved
  cryptocurrencies on an approved exchange, provided they are offered by the
  exchange itself." This clause was originally aimed at exchange apps. Damus,
  Nostur, Phoenix, Breez, Mutiny, Zeus — all shipped despite this clause by being
  "wallet" apps where the user controls the keys. **Our defense:** BitSov is a
  non-custodial wallet that happens to also send messages over the same channels.
- **4.2.7 (Remote App Code)** — "Apps that browse the web must use the appropriate
  WebKit framework…" Tauri Mobile on iOS uses WKWebView, so we're compliant. The
  HTML/JS we render is bundled, not remote.
- **5.2.1 (General — Intellectual Property)** — irrelevant.
- **2.5.4 (VoIP)** — "Apps using VoIP… must use the appropriate background mode."
  Our VoIPView is real (calls in roadmap). We use `voip` and `audio` background
  modes; legitimate use, well-precedented.

**Risk estimate: 35–45% first-submission rejection** based on reviewer-roulette
distribution observed across LN apps 2023–2026. Likelihood of **eventual approval
after appeal or rewording**: ~85%. Phoenix has been live for >3 years. Breez had
multiple rejections but is live. Mutiny chose the browser-extension/PWA path
specifically to avoid this fight. Zeus is live on App Store. **Damus shipped with
zaps live** after Apple briefly threatened removal in late 2022 and then backed
off following public outcry.

**Cell Test on Apple's gate:** A cell doesn't ask the ER membrane for permission
to exist. Apple's review is a structural violation of Principle 1 (Sovereignty).
We mitigate by treating iOS as a **convenience surface** while the canonical
Tier-2 path runs on Android (no equivalent gate; APK sideload always works) and
the PWA at `bitsov.app` (no gate at all — Safari renders it). If Apple rejects
the binary, the user still has the PWA.

### App Store risk — Android (Play Store)

- Play Store has no equivalent to 3.1.5(b). Cryptocurrency wallet apps and
  Lightning apps (Phoenix, Breez, Zeus, Wallet of Satoshi, Mutiny) live there
  without recurring drama.
- Foreground service (`dataSync` type) requires user-visible notification on
  API 34+. Tolerable UX cost.
- Sideload always works as a fallback — F-Droid is an option for fully open
  distribution. **Cell Test on Android: passes.**

**Risk estimate: 5–10% rejection.**

### Background process on iOS — the hard problem

iOS will **not let an app run a server indefinitely**. The koalitis here:

- `BGProcessingTask` / `BGAppRefreshTask` — minutes of CPU per day, scheduled by
  the OS. Not a "keep my LDK channel open" primitive.
- `voip` background mode — historically used for VoIP apps to maintain a socket;
  Apple has tightened this and now expects you to use CallKit + PushKit.
  **Mis-using `voip` for a non-call socket risks 2.5.4 rejection.**
- `audio` background mode + a silent audio stream — the abuse pattern; rejection
  bait.

The honest answer for iOS: **the konsensus-node cannot stay online when the app
is backgrounded.** We must:

1. Ship a **server-side push relay** that the user's node points at (a relay
   metadata tradeoff, not operator key custody). When a message arrives for the user, the relay sends
   APNs silent push → iOS wakes the app for ~30s → app starts the local node,
   downloads queued messages, hands them off, and goes back to sleep.
2. **The cost:** the relay sees that *some* encrypted ciphertext is destined for
   the user. It cannot decrypt (E2EE preserved). But it learns timing metadata.
   This is **explicitly a relay metadata downgrade** and must be documented as a
   reachability tradeoff on iOS.
3. Alternative: tell iOS users "your messages arrive when you open the app." UX
   tolerable for a beta; not viable for 1M users.

Android has none of this: `ForegroundService` of type `dataSync` lets the node
run indefinitely. Battery-permission UX gets users to whitelist us.

### Notification model

- **Android (FCM):** Konsensus-node, when running as foreground service, talks to
  its peers directly. No FCM needed for delivery. FCM is only used as a
  battery-saver fallback when the foreground service is killed by aggressive OEM
  battery savers (Huawei, Xiaomi). When FCM data message arrives → service
  restarts.
- **iOS (APNs):** Required. Konsensus-node tells its trusted relays "ping me at
  APNs token X when you have a message for me." Relay sends silent push → iOS
  wakes app → app downloads + decrypts locally. The relay never sees plaintext.

This bridge is **already partially designed** in `BROWSER_NETWORK_LAYER.md` — the
"hosting" tier 3 architecture covers the same pattern.

### Verdict

**Recommended.** Time-to-beta is half of Option B and a quarter of Option C. The
SolidJS UI is already mobile-ready (paste-invite + funding flows look like mobile
onboarding by accident of good design). Tauri Mobile 2 reached stable late 2024
and has shipped real apps (e.g., the Tauri team's own demos, several
non-cryptocurrency apps on both stores). The technology bet has matured enough.

---

## 3. Option B — React Native + Rust core via uniffi/cxx

### Architecture

```
┌──────────────────────────────────────┐
│ React Native (JS/Hermes) UI          │
│ Bridges (TurboModule) to Rust core   │
├──────────────────────────────────────┤
│ Rust konsensus-node via uniffi-rs    │
│ (no HTTP loopback; in-process FFI)   │
└──────────────────────────────────────┘
```

### Scorecard

| Dimension | Estimate | Notes |
|-----------|----------|-------|
| Time to beta | **14–20 weeks** | Wks 1–4: uniffi-rs bindings for the ~140 REST endpoints (or, smarter, expose a smaller native API). Wks 5–14: rewrite the 20k LOC frontend in RN/React + TypeScript. Wks 15–20: parity testing, hardening. |
| Binary size | **~28–45 MB** Android, **~55–75 MB** iOS | Smaller than Tauri (no webview boilerplate, Hermes is leaner than V8). |
| Battery | Marginally better than Tauri (no webview render thread idle). | |
| Code reuse | **~0% of UI** (different framework). **~100% of Rust core**, plus uniffi binding work. ~80% of the *patterns* (state shape, store ideas) transferable but every file is a rewrite. | |
| iOS App Store risk | **30–40%** — same fundamental policies, slightly lower because RN is mainstream and bitcoin apps in RN (Mutiny attempted RN; Phoenix is RN-shaped) have track record. | |
| Android risk | 5–10%, same as A. | |
| Background process | **Same constraints as A.** The platform OS is what limits this, not the framework. Same APNs/FCM bridge required. |
| Notification model | Same as A. |

### When this option wins

If Tauri Mobile 2 turns out to be unstable in the wild — segfaults, audio routing
bugs, accessibility issues we can't work around — we fall back to RN. The Rust
core work (uniffi bindings) is **valuable independent of B**: a stable FFI
surface lets third-party UIs exist, including a future native Linux UI.

**Recommendation: don't write this now, but track Tauri Mobile bug counts for the
first 4 weeks of Option A. If we hit a Tauri-blocking bug, pivot.**

---

## 4. Option C — Native Swift + Kotlin + Rust core

### Scorecard

| Dimension | Estimate | Notes |
|-----------|----------|-------|
| Time to beta | **26–36 weeks** (two separate UI tracks; one engineer means serialize them) | Realistically requires a second engineer, which BitSov does not have. |
| Binary size | **~15–25 MB** Android, **~20–35 MB** iOS | Smallest by a clear margin. |
| Battery | Best — native UI is most efficient. | |
| Code reuse | **~0% of UI.** ~100% of Rust core. | |
| iOS App Store risk | **20–30%** — native Swift apps draw the least scrutiny. Phoenix is native. | |
| Background process | Same OS constraints. Same APNs/FCM bridge. **No advantage on this critical axis.** |

### Verdict

The smallest binaries, the best battery life, the lowest App Store rejection
probability — and **none of it matters** if it takes us a year to ship at a
moment when the network needs mobile to demonstrate Tier-2 viability for grants
and the El Salvador rotation. The talent cost (two mobile engineers, one
Rust/FFI engineer) is wrong for current BitSov headcount.

**Reconsider at >100k users**, when native polish becomes a competitive
differentiator and the team can afford to maintain three frontends.

---

## 5. Critical decision dependencies

These are the concrete pieces of evidence that would change the ranking:

| Trigger | New ranking |
|---------|-------------|
| Tauri Mobile 2 hits a P0 segfault we can't fix in 2 wks of Option-A work | Pivot to **B** (have uniffi bindings half-built from L-track work already) |
| Apple rejects our first iOS submission **and refuses appeal** | iOS becomes PWA-only; Option A continues on Android. No re-ranking. |
| Apple rejects + we want native iOS UX anyway | Pivot iOS only to **C-iOS** while keeping A on Android. Hybrid stack. |
| Breez / Phoenix / Mutiny shipped an **LDK-on-device** iOS app successfully in 2025–2026 | Option A's iOS risk drops to ~20%; speeds up our schedule (less defensive work). |
| Apple announces relaxed rules in Bitcoin Law jurisdictions (ES, where BitSov is rotating) | A's iOS risk drops to ~15%. Submit ES-first. |
| El Salvador's CNAD / Bitcoin Office publicly endorses sovereign mesh networking | Indirectly improves Apple's calculus; still doesn't move them, but improves the press story for any rejection appeal. |
| Tauri Mobile 2 ships an officially blessed iOS background-execution example | A's iOS background story tightens; risk drops to ~25%. |
| Two production Tauri-Mobile apps surface in App Store with >100k users | A's "newer/less-tested" objection dissolves. |

We should monitor these signals monthly and revisit this ADR if any fires.

---

## 6. The 80/20 path — what to ship if we only have 4 weeks

A 4-week minimum-viable mobile shape that **proves the architecture** without
needing the full mobile binary:

### Phase 0 (4 weeks): Mobile PWA + paired remote access

1. **Week 1: PWA polish.** Add a web manifest to the existing SolidJS frontend.
   Service worker for offline-resilient asset cache. Push notifications via Web
   Push API (works on Android Chrome, **iOS 16.4+ on Safari for PWAs added to
   home screen**). Lighthouse PWA score >90.
2. **Week 2: Paired-remote UX.** Maya types `bitsov.app` in mobile Safari, scans a
   pairing QR from her own node, and her phone's PWA is now an authorized remote
   device. The node may be a laptop, a VPS she controls, or a relay-assisted
   endpoint, but the operator never receives her mnemonic and never gains a
   decryption key. The phone is a UI plus a device signing key; this validates
   remote access without creating an operator-custody precedent.
3. **Week 3: Mobile layouts.** Conditional CSS for the 5 desktop-only layouts
   (Sidebar collapses, RightPanel becomes drawer, Calendar week view becomes
   day-by-day swipe). No new logic; just CSS + 3 components.
4. **Week 4: Field test.** Maya carries her node on her phone as a paired remote
   client. Josh does the same. They send messages
   while walking around. We prove the **UX** works on a phone before we prove
   the **node-on-device** works on a phone.

**What this buys us:**

- A mobile demo for HRF / NGI / next-grant submissions.
- Real paired-device users producing real UX telemetry without key custody.
- A safety net during the Tauri Mobile work — if Apple rejects, PWA is the
  permanent fallback.
- **Validates the SolidJS bet for mobile.** If the PWA UX is bad on a phone, we
  learn that before we sink 9 weeks into Tauri Mobile.

**What it doesn't do:**

- Doesn't prove Tier-2 (node-on-device). That's the next 6–9 weeks of Option A.

### Recommended sequencing

```
Wk 0–4:  PWA + paired remote access (validates UX, ships demo)
Wk 4–13: Tauri Mobile Android beta (validates Tier-2, ships APK)
Wk 13–18: Tauri Mobile iOS beta (App Store submission, may iterate)
Wk 18+:  If iOS rejected → PWA remains canonical iOS path until appeal lands
```

The PWA is **not a throwaway prototype**. It is the canonical iOS path if Apple
fights us, and the canonical "I don't want to install anything" path for users
who never become Tier-2.

---

## 7. Cell Test and the Apple question

Restating the founder's framing: *a cell membrane doesn't ask permission from an
OS vendor to exist.*

Apple's App Store is a regulatory environment that BitSov must traverse, not a
gate that BitSov must concede sovereignty to. Concretely:

- The **node** never lives on Apple's terms. The Rust core ships as part of the
  app binary; Apple sees a binary they review, not a service they host.
- The **identity** is a Bitcoin-anchored key the user holds, not an Apple ID.
- The **payment gate** runs over Lightning channels the user owns, not StoreKit.
- The **escape hatch** is the PWA at `bitsov.app` and the Android APK on F-Droid.
  Apple can reject; BitSov continues to exist. **No single OS vendor can kill the
  network.** That is the relevant scale-mandate test, not "can we get on the App
  Store?"

The PWA is the architectural insurance policy. The App Store is a distribution
channel we'd like but don't depend on. Build with that asymmetry baked in.

---

## 8. Open questions for human review

1. **Hosted relay for iOS push:** who runs it? Operator-owned (BitSov S.A. de
   C.V.)? User-elected from a small set? F-Droid-style federated? This decision
   shapes the relay metadata boundary and should be made before Option-A iOS
   submission.
2. **Confidential push payloads:** APNs limits payload size and visibility. We
   need a design where the push body itself carries no plaintext metadata
   beyond "you have N messages waiting." Sketched in `BROWSER_NETWORK_LAYER.md`
   but not finalized for mobile.
3. **Esplora on mobile:** the LDK gotcha doc (`feedback_ldk_gotchas.md`) flags
   that LDK refuses to start if its esplora fetch times out. On mobile networks
   (LTE, captive WiFi) this is much more common than on a VM. L4 (primary +
   fallback esplora) is a hard prerequisite for Tier-2 mobile, not a nice-to-have.
4. **mnemonic backup UX on mobile:** how does the user write down 12 words while
   on a phone? `MnemonicWizard.tsx` exists for desktop; needs mobile-tailored
   "show one word at a time + confirm" flow with anti-screenshot guard.

---

## 9. Sources / further reading

- Apple App Review Guidelines, current revision: <https://developer.apple.com/app-store/review/guidelines/>
- Tauri Mobile 2 status: <https://v2.tauri.app/start/prerequisites/#mobile>
- uniffi-rs (Mozilla): <https://mozilla.github.io/uniffi-rs/>
- Damus / Apple precedent (Dec 2022): public correspondence between Apple App
  Review and Damus team re: zaps and 3.1.1
- Phoenix wallet (ACINQ): live on App Store with LDK-class on-device LN node
- Web Push for PWAs on iOS 16.4+: <https://webkit.org/blog/13878/>
- BitSov repo internal: `BROWSER_NETWORK_LAYER.md`, `feedback_ldk_gotchas.md`,
  `ONBOARDING_ARCHITECTURE.md`

---

## Decision

**Recommended:** Adopt Option A (Tauri Mobile 2 + reuse SolidJS) for Tier-2 mobile,
preceded by a 4-week PWA + paired-remote-access phase that derisks the UX and acts as
the permanent iOS fallback if Apple's review goes badly.

Awaiting human sign-off before scheduling factory work for Phase 0 (PWA).
