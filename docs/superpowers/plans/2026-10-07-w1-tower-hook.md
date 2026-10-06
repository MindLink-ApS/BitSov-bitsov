# W1 tower hook implementation plan

**Goal:** Implement only W1 from the supplied watchtower design contract.
**Spec:** `../pa-w1-contract.md`, §§ F3–F9, 3.3–3.4, 7.
**Architecture:** An optional TowerPersister delegates all monitor persistence to the existing Persister. A configured TowerClient is a durable local candidate queue (no transport). Pending unsigned ladders and a per-channel wallet destination survive restarts; signed candidates remain available for W2.

## Constraints and review focus

- Offline only; no regtest/e2e, daemons, RPC, or 127.0.0.1:3141. Never push.
- Preserve disabled persistence calls, bytes, statuses, completed updates and archive behavior.
- Persist pending data before monitor acknowledgement; retain signed data before removing pending data. Never acknowledge tower storage errors as Completed.
- Retry secret-not-known on subsequent updates and startup; deduplicate replay; reject corrupt storage.
- Three fee tiers max(253, one-block estimate), 4x, 16x; fee at most half the protected output; exclude dust outputs.
- W2 crypto, networking, payment, configuration and acknowledgement/pruning are out of scope. Same-SHA Fable/Grok approval remains a separate money-path merge gate.

## Tasks

- [ ] Add offline functional regressions using LDK's in-memory harness: initial/later commitments, script-valid signed ladder, below dust, restart mid-queue, disabled delegate parity, storage failure and fee caps. Observe failure before implementing.
- [ ] Implement `tower_hook.rs`: serializable JusticeCandidate and pending channel record, durable local TowerClient, generic TowerPersister with optional fee/destination providers. Run hook tests and commit.
- [ ] Wire explicit Builder opt-in, ChainMonitor type, module export; default remains off. Document every delta in BITSOV-PATCH.md. Check workspace and vendor clippy offline; commit.
- [ ] Review final diff and report exact validation commands, results, commits and outstanding W2/review work.
