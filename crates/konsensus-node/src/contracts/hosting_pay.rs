//! Daily Lightning payment task for operator-hosted cloud nodes.

use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio::sync::{broadcast, watch};
use tracing::{debug, info, warn};
use uuid::Uuid;

use konsensus_api::state::WsDeliveryStatus;
// NodeId is referenced in #[cfg(test)] code that local
// `cargo test -p konsensus-node contracts::hosting_pay` does not compile
// but the broader CI test matrix does. Re-added 2026-05-12 after clippy
// nudged removal and CI flagged the regression.
#[allow(unused_imports)]
use konsensus_core::{
    HostingContractError, HostingContractState, LightningError, LightningProvider, NodeId,
    OperatorHostingContract, OperatorHostingPayment, OperatorHostingPaymentDirection,
    PaymentDirection, PaymentStatus,
};
use konsensus_storage::{Storage, StorageError};

const OPERATOR_HOSTING_MEMO_PREFIX: &str = "operator-hosting:";
const DAILY_PAYMENT_INTERVAL: Duration = Duration::from_secs(86_400);
const DAY_SECS: u64 = 86_400; // hardened duplicate of core::contracts::hosting DAY_SECS for threshold calcs (scale-ready daily loop)
pub const HOSTING_CONTRACTS_ENV: &str = "KONSENSUS_HOSTING_CONTRACTS_ENABLED";

/// Pure predicate for the operator-hosting feature gate (see the API-side twin
/// in `handlers/hosting.rs`). Factored out so the default-OFF / opt-in semantics
/// are deterministically unit-testable without mutating process env. The daily
/// payment task early-returns when this is false, so a public/reference node
/// never runs the keysend billing loop unless the operator opts in.
fn hosting_flag_enabled(raw: Option<&str>) -> bool {
    matches!(
        raw,
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

pub fn hosting_contracts_enabled() -> bool {
    hosting_flag_enabled(std::env::var(HOSTING_CONTRACTS_ENV).ok().as_deref())
}

/// Dependencies for the long-running daily payment task.
pub struct HostingPaymentTaskDeps {
    /// Local storage with hosting contracts and payment ledger tables.
    pub storage: Arc<dyn Storage>,
    /// Lightning backend used for tenant keysend payments and operator scans.
    pub lightning: Arc<dyn LightningProvider>,
    /// Existing WebSocket event channel. The event type discriminates hosting events.
    pub ws_delivery_tx: broadcast::Sender<Arc<WsDeliveryStatus>>,
    /// Node shutdown signal.
    pub shutdown_rx: watch::Receiver<bool>,
}

/// Summary for one scheduler pass.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HostingPaymentRunStats {
    /// Contracts loaded from storage.
    pub contracts_checked: usize,
    /// Successful outgoing tenant payments.
    pub payments_sent: usize,
    /// Failed outgoing tenant payment attempts.
    pub payments_failed: usize,
    /// Incoming operator payments recorded from Lightning history.
    pub incoming_payments_recorded: usize,
    /// Contract state updates written without a successful payment.
    pub state_updates: usize,
    /// UI overdue events emitted.
    pub overdue_events: usize,
}

/// Errors from hosting payment scheduling.
#[derive(Debug, Error)]
pub enum HostingPaymentError {
    /// Storage operation failed.
    #[error("storage: {0}")]
    Storage(#[from] StorageError),
    /// Lightning operation failed outside a per-contract payment attempt.
    #[error("lightning: {0}")]
    Lightning(#[from] LightningError),
    /// Contract validation or state calculation failed.
    #[error("contract: {0}")]
    Contract(#[from] HostingContractError),
    /// Incoming keysend memo could not be parsed.
    #[error("invalid operator hosting memo: {0}")]
    InvalidMemo(String),
}

/// Run the hosting payment task until shutdown.
pub async fn run_daily_payment_task(mut deps: HostingPaymentTaskDeps) {
    if !hosting_contracts_enabled() {
        info!(
            env = HOSTING_CONTRACTS_ENV,
            "operator hosting payment task disabled"
        );
        return;
    }

    if let Err(e) = run_once(
        Arc::clone(&deps.storage),
        Arc::clone(&deps.lightning),
        deps.ws_delivery_tx.clone(),
        now_unix(),
    )
    .await
    {
        warn!(error = %e, "operator hosting payment startup pass failed");
    }

    let mut interval = tokio::time::interval(DAILY_PAYMENT_INTERVAL);
    interval.tick().await;

    loop {
        tokio::select! {
            _ = interval.tick() => {
                match run_once(
                    Arc::clone(&deps.storage),
                    Arc::clone(&deps.lightning),
                    deps.ws_delivery_tx.clone(),
                    now_unix(),
                ).await {
                    Ok(stats) => {
                        debug!(
                            contracts = stats.contracts_checked,
                            sent = stats.payments_sent,
                            failed = stats.payments_failed,
                            incoming = stats.incoming_payments_recorded,
                            overdue = stats.overdue_events,
                            "operator hosting payment pass complete"
                        );
                    }
                    Err(e) => warn!(error = %e, "operator hosting payment pass failed"),
                }
            }
            changed = deps.shutdown_rx.changed() => {
                if changed.is_err() || *deps.shutdown_rx.borrow() {
                    info!("operator hosting payment task shutting down");
                    break;
                }
            }
        }
    }
}

/// Run both operator-side incoming scan and tenant-side due payment pass once.
pub async fn run_once(
    storage: Arc<dyn Storage>,
    lightning: Arc<dyn LightningProvider>,
    ws_delivery_tx: broadcast::Sender<Arc<WsDeliveryStatus>>,
    now: u64,
) -> Result<HostingPaymentRunStats, HostingPaymentError> {
    let mut stats =
        record_incoming_operator_payments_once(Arc::clone(&storage), Arc::clone(&lightning))
            .await?;
    let tenant_stats = pay_due_contracts_once(storage, lightning, ws_delivery_tx, now).await?;

    stats.contracts_checked += tenant_stats.contracts_checked;
    stats.payments_sent += tenant_stats.payments_sent;
    stats.payments_failed += tenant_stats.payments_failed;
    stats.state_updates += tenant_stats.state_updates;
    stats.overdue_events += tenant_stats.overdue_events;
    Ok(stats)
}

/// Send due tenant payments once.
pub async fn pay_due_contracts_once(
    storage: Arc<dyn Storage>,
    lightning: Arc<dyn LightningProvider>,
    ws_delivery_tx: broadcast::Sender<Arc<WsDeliveryStatus>>,
    now: u64,
) -> Result<HostingPaymentRunStats, HostingPaymentError> {
    let contracts = storage.list_operator_hosting_contracts().await?;
    let mut stats = HostingPaymentRunStats {
        contracts_checked: contracts.len(),
        ..HostingPaymentRunStats::default()
    };

    // Perspective guard: this node only PAYS contracts where it is the TENANT.
    // A contract whose `operator_pubkey` is OUR own pubkey is one where we are
    // the operator/payee (e.g. registered via the hosting REST API) — paying it
    // would be a keysend to ourselves. The incoming-scan side records those
    // rows; the pay-due pass must skip them (otherwise we attempt a daily
    // self-keysend and, when it fails, fire false `overdue` events for a
    // contract where we are the recipient).
    let our_pubkey = lightning.get_node_pubkey().await;

    for contract in contracts {
        if let Some(ref ours) = our_pubkey {
            if &contract.operator_pubkey == ours {
                continue;
            }
        }
        let implied_state = contract.state_at(now)?;
        if !contract.payment_due_at(now)? {
            if implied_state != contract.state {
                storage
                    .update_operator_hosting_contract_state(&contract.id, implied_state, now)
                    .await?;
                stats.state_updates += 1;
            }
            continue;
        }

        // DOUBLE-PAY GUARD: before issuing the keysend, scan recent outgoing
        // Lightning payments for this contract's memo. If we find a settled
        // payment within the last DAY_SECS, we already paid today — skip.
        // This closes the AI-review-flagged crash window where the keysend
        // settles but mark_operator_hosting_contract_paid hasn't yet been
        // written, leaving the next scheduler tick to keysend a second time.
        // See PR #88 review finding #1.
        let expected_memo = contract.keysend_memo();
        // 24 hours — same DAY_SECS as konsensus-core's hosting contract module (harden: use const).
        let recent_threshold = now.saturating_sub(DAY_SECS); // DAILY_PAYMENT_INTERVAL equiv in secs for history scan (no drift)

        if has_recent_outgoing_for_memo(Arc::clone(&lightning), &expected_memo, recent_threshold)
            .await?
        {
            // Already paid today via Lightning history; just sync our local
            // last_paid_at marker so the next scheduler tick knows.
            storage
                .mark_operator_hosting_contract_paid(&contract.id, now, now)
                .await?;
            stats.state_updates += 1;
            continue;
        }

        match send_hosting_keysend(&contract, Arc::clone(&lightning)).await {
            Ok(payment) => {
                storage.record_operator_hosting_payment(&payment).await?;
                storage
                    .mark_operator_hosting_contract_paid(&contract.id, payment.paid_at, now)
                    .await?;
                stats.payments_sent += 1;
            }
            Err(e) => {
                stats.payments_failed += 1;
                warn!(
                    contract_id = %contract.id,
                    tenant = %contract.tenant_pubkey,
                    error = %e,
                    "operator hosting payment failed"
                );
                if implied_state != contract.state {
                    storage
                        .update_operator_hosting_contract_state(&contract.id, implied_state, now)
                        .await?;
                    stats.state_updates += 1;
                }
                if matches!(
                    implied_state,
                    HostingContractState::Overdue | HostingContractState::Paused
                ) {
                    emit_overdue_event(&ws_delivery_tx, &contract, implied_state, now)?;
                    stats.overdue_events += 1;
                }
            }
        }
    }

    Ok(stats)
}

/// Scan settled incoming keysends and record operator-side ledger entries.
pub async fn record_incoming_operator_payments_once(
    storage: Arc<dyn Storage>,
    lightning: Arc<dyn LightningProvider>,
) -> Result<HostingPaymentRunStats, HostingPaymentError> {
    let mut stats = HostingPaymentRunStats::default();
    let payments = lightning.list_payments(500).await?;
    let operator_pubkey = lightning.get_node_pubkey().await.unwrap_or_default();
    let contracts = storage.list_operator_hosting_contracts().await?;

    for payment in payments {
        if payment.direction != PaymentDirection::Incoming
            || payment.status != PaymentStatus::Settled
        {
            continue;
        }

        let Some(memo) = payment.memo.as_deref() else {
            continue;
        };
        if !memo.starts_with(OPERATOR_HOSTING_MEMO_PREFIX) {
            continue;
        }

        let contract_id = parse_hosting_memo(memo)?;
        let Some(contract) = contracts.iter().find(|c| c.id == contract_id) else {
            // Unknown contract id — surface as warn so operator notices forged
            // or stale memos (AI review on PR #88 asked for this).
            warn!(
                %contract_id,
                "skipping incoming operator hosting payment for unknown contract"
            );
            continue;
        };
        // SECURITY: use the contract's authoritative tenant_pubkey, NOT a
        // value derived from the (potentially forged) wire memo. The
        // legacy v1 memo format placed tenant_pubkey in the wire payload,
        // which let any Lightning sender claim arbitrary tenant identity.
        // See AI review on PR #88 #2 (memo-derived tenant_pubkey forgery).
        let record = OperatorHostingPayment {
            payment_hash: payment.payment_hash,
            contract_id,
            tenant_pubkey: contract.tenant_pubkey,
            operator_pubkey: if operator_pubkey.is_empty() {
                contract.operator_pubkey.clone()
            } else {
                operator_pubkey.clone()
            },
            amount_msat: payment.amount_msat,
            paid_at: payment.timestamp,
            direction: OperatorHostingPaymentDirection::Incoming,
            preimage: payment.preimage,
            memo: Some(memo.to_string()),
        };
        if storage.record_operator_hosting_payment(&record).await? {
            stats.incoming_payments_recorded += 1;
        }
    }

    Ok(stats)
}

/// Returns true if a settled outgoing Lightning payment with the given memo
/// has been observed since `threshold_unix`. Used by the daily-payment task to
/// avoid double-paying after a crash window between keysend settlement and
/// the local mark_operator_hosting_contract_paid write.
///
/// This treats the Lightning provider's outgoing payment history as the
/// canonical idempotency record. The local storage row is a cache; the
/// Lightning ledger is the source of truth for "did money actually leave."
async fn has_recent_outgoing_for_memo(
    lightning: Arc<dyn LightningProvider>,
    memo: &str,
    threshold_unix: u64,
) -> Result<bool, HostingPaymentError> {
    let payments = lightning.list_payments(500).await?;
    for payment in payments {
        if payment.direction != PaymentDirection::Outgoing {
            continue;
        }
        if payment.status != PaymentStatus::Settled {
            continue;
        }
        if payment.timestamp < threshold_unix {
            continue;
        }
        if payment.memo.as_deref() == Some(memo) {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn send_hosting_keysend(
    contract: &OperatorHostingContract,
    lightning: Arc<dyn LightningProvider>,
) -> Result<OperatorHostingPayment, HostingPaymentError> {
    let amount_msat = contract.daily_amount_msat()?;
    let memo = contract.keysend_memo();
    let payment = lightning
        .keysend(&contract.operator_pubkey, amount_msat, Some(&memo))
        .await?;

    if payment.status != PaymentStatus::Settled {
        return Err(HostingPaymentError::Lightning(
            LightningError::PaymentFailed(format!(
                "operator hosting keysend not settled: {:?}",
                payment.status
            )),
        ));
    }

    Ok(OperatorHostingPayment {
        payment_hash: payment.payment_hash,
        contract_id: contract.id,
        tenant_pubkey: contract.tenant_pubkey,
        operator_pubkey: contract.operator_pubkey.clone(),
        amount_msat: payment.amount_msat,
        paid_at: payment.timestamp,
        direction: OperatorHostingPaymentDirection::Outgoing,
        preimage: payment.preimage,
        memo: payment.memo,
    })
}

fn emit_overdue_event(
    ws_delivery_tx: &broadcast::Sender<Arc<WsDeliveryStatus>>,
    contract: &OperatorHostingContract,
    state: HostingContractState,
    now: u64,
) -> Result<(), HostingPaymentError> {
    let days_unpaid = contract.days_unpaid_at(now)?;
    let reason = format!(
        "{} days unpaid; fund your node to continue hosted outbound service",
        days_unpaid
    );
    let _ = ws_delivery_tx.send(Arc::new(WsDeliveryStatus {
        event_type: "operator_hosting_overdue",
        message_id: contract.id.to_string(),
        status: state.as_str().to_string(),
        reason: Some(reason),
    }));
    Ok(())
}

/// Parse a hosting-memo string of the form `operator-hosting:<contract_id>`.
///
/// The v1 memo also embedded `tenant_pubkey` for self-validation. That field
/// was a Principle 4 metadata leak (visible to last-hop Lightning nodes via
/// keysend TLV) and also a forgery vector: any sender could put an arbitrary
/// node_id in the memo and have it recorded as that tenant's payment.
/// Per AI review on PR #88, the tenant identity is now derived from the
/// matched contract row, not from the memo.
fn parse_hosting_memo(memo: &str) -> Result<Uuid, HostingPaymentError> {
    let rest = memo
        .strip_prefix(OPERATOR_HOSTING_MEMO_PREFIX)
        .ok_or_else(|| HostingPaymentError::InvalidMemo(memo.to_string()))?;
    // Accept both legacy `<id>:<tenant>` and current `<id>` shapes during
    // the migration window. Only the contract_id is authoritative.
    let id_part = rest.split(':').next().unwrap_or(rest);
    let contract_id =
        Uuid::parse_str(id_part).map_err(|e| HostingPaymentError::InvalidMemo(e.to_string()))?;
    Ok(contract_id)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use konsensus_lightning::{MockLightningConfig, MockLightningProvider};
    use konsensus_storage::SqliteStorage;

    /// The hosting payment loop is gated OFF by default: `run_daily_payment_task`
    /// begins with `if !hosting_contracts_enabled() { return }`, so unless the
    /// operator sets the flag, no keysend billing runs. This pins the predicate
    /// that guard reads (default-OFF, explicit truthy opt-in only).
    #[test]
    fn hosting_payment_gate_is_off_by_default_and_opts_in_explicitly() {
        assert!(!hosting_flag_enabled(None), "absent flag must be OFF");
        assert!(!hosting_flag_enabled(Some("")), "empty flag must be OFF");
        assert!(!hosting_flag_enabled(Some("0")), "0 must be OFF");
        assert!(!hosting_flag_enabled(Some("false")), "false must be OFF");
        assert!(!hosting_flag_enabled(Some("no")), "no must be OFF");
        for on in ["1", "true", "TRUE", "yes", "YES"] {
            assert!(hosting_flag_enabled(Some(on)), "{on} must enable the task");
        }
    }

    /// Money-adjacent disabled-path guard (#326): with the env flag OFF (default),
    /// `run_daily_payment_task` must return BEFORE the keysend billing loop and bill
    /// NOTHING — even with a DUE contract present. This pins the actual call-site
    /// guard, not just the predicate: if the guard is ever removed while the
    /// predicate test stays green, a public/reference node would silently bill.
    #[tokio::test]
    async fn disabled_task_returns_without_billing_a_due_contract() {
        std::env::remove_var(HOSTING_CONTRACTS_ENV); // ensure OFF (the default)

        let now = 1_700_086_401;
        let sqlite = Arc::new(SqliteStorage::in_memory().await.unwrap());
        // A contract that IS due (started > 1 day ago, never paid).
        sqlite
            .upsert_operator_hosting_contract(&contract(now - 86_400))
            .await
            .unwrap();
        let storage: Arc<dyn Storage> = sqlite.clone();
        let lightning: Arc<dyn LightningProvider> =
            Arc::new(MockLightningProvider::with_config(MockLightningConfig {
                initial_balance_msat: 50_000_000,
            }));
        let (ws_tx, _ws_rx) = broadcast::channel::<Arc<WsDeliveryStatus>>(4);
        let (_sd_tx, shutdown_rx) = watch::channel(false);

        let deps = HostingPaymentTaskDeps {
            storage: Arc::clone(&storage),
            lightning,
            ws_delivery_tx: ws_tx,
            shutdown_rx,
        };

        // Flag OFF => the task must return promptly (before the billing loop), so a
        // generous timeout that is NOT reached proves it did not enter the loop.
        tokio::time::timeout(Duration::from_secs(5), run_daily_payment_task(deps))
            .await
            .expect("disabled hosting task must return promptly, not enter the billing loop");

        // And it must have billed NOTHING for the due contract.
        let payments = storage
            .list_operator_hosting_payments(&Uuid::nil())
            .await
            .unwrap();
        assert!(
            payments.is_empty(),
            "disabled task must record ZERO payments (found {})",
            payments.len()
        );
        let contracts = storage.list_operator_hosting_contracts().await.unwrap();
        assert!(
            contracts[0].last_paid_at.is_none(),
            "disabled task must not mark the due contract paid"
        );
    }

    fn tenant() -> NodeId {
        NodeId::from_bytes([9u8; 32])
    }

    fn operator_pubkey() -> String {
        format!("02{}", "22".repeat(32))
    }

    fn contract(started_at: u64) -> OperatorHostingContract {
        OperatorHostingContract::new(Uuid::nil(), tenant(), operator_pubkey(), 20_000, started_at)
            .expect("valid hosting contract")
    }

    #[tokio::test]
    async fn due_contract_sends_keysend_and_records_payment() {
        let now = 1_700_086_401;
        let sqlite = Arc::new(SqliteStorage::in_memory().await.unwrap());
        sqlite
            .upsert_operator_hosting_contract(&contract(now - 86_400))
            .await
            .unwrap();
        let storage: Arc<dyn Storage> = sqlite.clone();
        let lightning: Arc<dyn LightningProvider> =
            Arc::new(MockLightningProvider::with_config(MockLightningConfig {
                initial_balance_msat: 50_000_000,
            }));
        let (tx, _rx) = broadcast::channel(4);

        let stats = pay_due_contracts_once(Arc::clone(&storage), lightning, tx, now)
            .await
            .unwrap();

        assert_eq!(stats.contracts_checked, 1);
        assert_eq!(stats.payments_sent, 1);
        assert_eq!(stats.payments_failed, 0);

        let contracts = storage.list_operator_hosting_contracts().await.unwrap();
        assert_eq!(contracts[0].state, HostingContractState::Active);
        assert!(contracts[0].last_paid_at.is_some());

        let payments = storage
            .list_operator_hosting_payments(&Uuid::nil())
            .await
            .unwrap();
        assert_eq!(payments.len(), 1);
        assert_eq!(
            payments[0].direction,
            OperatorHostingPaymentDirection::Outgoing
        );
        assert_eq!(payments[0].amount_msat, 20_000_000);
    }

    /// Perspective guard: a contract whose `operator_pubkey` is THIS node's own
    /// pubkey (an operator-side row, e.g. created via the hosting REST API) is
    /// skipped by the pay-due pass — the node never keysends itself.
    #[tokio::test]
    async fn operator_perspective_contract_is_not_self_paid() {
        let now = 1_700_086_401;
        let sqlite = Arc::new(SqliteStorage::in_memory().await.unwrap());
        // operator_pubkey == the MockLightningProvider's own node pubkey.
        let own = format!("02{}", "aa".repeat(32));
        let c = OperatorHostingContract::new(Uuid::nil(), tenant(), own, 20_000, now - 86_400)
            .expect("valid hosting contract");
        sqlite.upsert_operator_hosting_contract(&c).await.unwrap();
        let storage: Arc<dyn Storage> = sqlite.clone();
        let lightning: Arc<dyn LightningProvider> =
            Arc::new(MockLightningProvider::with_config(MockLightningConfig {
                initial_balance_msat: 50_000_000,
            }));
        let (tx, _rx) = broadcast::channel(4);

        let stats = pay_due_contracts_once(Arc::clone(&storage), lightning, tx, now)
            .await
            .unwrap();

        assert_eq!(stats.payments_sent, 0, "must not self-keysend");
        assert_eq!(stats.payments_failed, 0, "skipped, not failed");
        let payments = storage
            .list_operator_hosting_payments(&Uuid::nil())
            .await
            .unwrap();
        assert_eq!(payments.len(), 0, "no self-payment recorded");
    }

    #[tokio::test]
    async fn unpaid_contract_emits_overdue_event_after_grace() {
        let now = 1_700_086_400;
        let sqlite = Arc::new(SqliteStorage::in_memory().await.unwrap());
        sqlite
            .upsert_operator_hosting_contract(&contract(now - 8 * 86_400))
            .await
            .unwrap();
        let storage: Arc<dyn Storage> = sqlite.clone();
        let lightning: Arc<dyn LightningProvider> =
            Arc::new(MockLightningProvider::with_config(MockLightningConfig {
                initial_balance_msat: 0,
            }));
        let (tx, mut rx) = broadcast::channel(4);

        let stats = pay_due_contracts_once(Arc::clone(&storage), lightning, tx, now)
            .await
            .unwrap();

        assert_eq!(stats.payments_sent, 0);
        assert_eq!(stats.payments_failed, 1);
        assert_eq!(stats.overdue_events, 1);

        let event = rx.recv().await.unwrap();
        assert_eq!(event.event_type, "operator_hosting_overdue");
        assert_eq!(event.status, "overdue");
        assert_eq!(event.message_id, Uuid::nil().to_string());

        let contracts = storage.list_operator_hosting_contracts().await.unwrap();
        assert_eq!(contracts[0].state, HostingContractState::Overdue);
    }

    #[test]
    fn hosting_memo_round_trips_contract_id_only() {
        let memo = contract(1_700_000_000).keysend_memo();
        // Memo intentionally encodes only the contract_id (Principle 4
        // metadata-leak fix per PR #88 AI review). Tenant identity is
        // derived from the matched contract row, not the wire memo.
        let contract_id = parse_hosting_memo(&memo).unwrap();
        assert_eq!(contract_id, Uuid::nil());
    }

    #[test]
    fn hosting_memo_legacy_with_tenant_field_still_parses() {
        // Backwards-compatibility check: during the migration window the
        // operator may receive payments minted by tenants on older binaries
        // that still include the tenant_pubkey field in the memo. Those
        // memos must parse to the same contract_id; the operator ignores
        // the (forgeable) trailing tenant field.
        let memo = format!("operator-hosting:{}:{}", Uuid::nil(), tenant().to_hex());
        let contract_id = parse_hosting_memo(&memo).unwrap();
        assert_eq!(contract_id, Uuid::nil());
    }

    #[test]
    fn hosting_memo_forged_tenant_field_does_not_affect_record() {
        // SECURITY: even if a sender forges the tenant field in the memo,
        // the parsed contract_id is unaffected — and downstream code uses
        // contract.tenant_pubkey (the authoritative value), not the memo.
        let memo = format!(
            "operator-hosting:{}:{}",
            Uuid::nil(),
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
        let contract_id = parse_hosting_memo(&memo).unwrap();
        assert_eq!(contract_id, Uuid::nil());
    }
}
