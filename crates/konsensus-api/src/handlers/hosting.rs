//! Operator hosting REST surface (H1 / the M5 Node-as-a-Service core seam).
//!
//! Exposes the operator's hosting-billing over the EXISTING
//! [`OperatorHostingContract`] core + storage (the daily keysend settlement loop
//! already runs in the node — `crates/konsensus-node/src/contracts/hosting_pay.rs`).
//! Three authenticated endpoints:
//! - `POST /api/v1/hosting/contracts` — create a contract billing a tenant
//!   `sats_per_day` (the operator pubkey is THIS node's Lightning pubkey, never
//!   caller-supplied).
//! - `GET  /api/v1/hosting/contracts` — list contracts with their LIVE state
//!   (`state_at(now)`) + `days_unpaid`.
//! - `GET  /api/v1/hosting/contracts/:id/ledger` — that contract's payments.
//!
//! **Charter scope (self-host / relay COGS billing — NOT a key-holding cloud
//! node).** This bills *compute* for hosting a tenant's own node or a
//! ciphertext relay: a SEPARATE Lightning flow (`OperatorHostingPayment`, memo
//! `operator-hosting:<id>`) that bypasses the energy gate. It never touches the
//! tenant's keys or plaintext — it only records who pays the operator how much
//! per day. It is not, and must not be marketed as, "a node we run that holds
//! your keys."
//!
//! All routes are gated behind [`AuthUser`] (the node owner / operator).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use konsensus_core::types::NodeId;
use konsensus_core::{HostingContractState, OperatorHostingContract, OperatorHostingPayment};

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::AppState;

pub const HOSTING_CONTRACTS_ENV: &str = "KONSENSUS_HOSTING_CONTRACTS_ENABLED";

/// Pure predicate for the operator-hosting feature gate: whether the raw env
/// value opts the feature IN. Factored out of [`hosting_contracts_enabled`] so
/// the accept/reject semantics (default-OFF, accepted truthy tokens) are
/// deterministically unit-testable without mutating process env.
fn hosting_flag_enabled(raw: Option<&str>) -> bool {
    matches!(
        raw,
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

pub fn hosting_contracts_enabled() -> bool {
    hosting_flag_enabled(std::env::var(HOSTING_CONTRACTS_ENV).ok().as_deref())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Request body for `POST /api/v1/hosting/contracts`.
#[derive(Debug, Deserialize)]
struct CreateContractRequest {
    /// Tenant node identity (64-hex). The party being hosted + billed.
    tenant_pubkey: String,
    /// Daily price in sats. Must be > 0.
    sats_per_day: u64,
}

/// A hosting contract with its LIVE (computed-at-request-time) lifecycle state.
#[derive(Debug, Serialize)]
struct ContractView {
    id: String,
    tenant_pubkey: String,
    operator_pubkey: String,
    sats_per_day: u64,
    started_at: u64,
    last_paid_at: Option<u64>,
    /// Live state: `active` | `overdue` (>7d) | `paused` (>14d) | `stopped`.
    state: String,
    /// Whole days since the last payment (0 if never charged yet / current).
    days_unpaid: u64,
}

/// Whether a live (non-`Stopped`) hosting contract already exists for this
/// `(tenant, operator)` pair. Each contract is an independent daily-keysend
/// relationship, so a duplicate would double-bill the tenant — creation refuses
/// one rather than minting a second payable row.
fn has_active_contract_for(
    contracts: &[OperatorHostingContract],
    tenant: &NodeId,
    operator_pubkey: &str,
) -> bool {
    contracts.iter().any(|c| {
        &c.tenant_pubkey == tenant
            && c.operator_pubkey == operator_pubkey
            && c.state != HostingContractState::Stopped
    })
}

fn contract_view(c: &OperatorHostingContract, now: u64) -> Result<ContractView, ApiError> {
    let state = c
        .state_at(now)
        .map_err(|e| ApiError::Internal(format!("hosting state: {e}")))?;
    let days_unpaid = c
        .days_unpaid_at(now)
        .map_err(|e| ApiError::Internal(format!("hosting days_unpaid: {e}")))?;
    Ok(ContractView {
        id: c.id.to_string(),
        tenant_pubkey: c.tenant_pubkey.to_hex(),
        operator_pubkey: c.operator_pubkey.clone(),
        sats_per_day: c.sats_per_day,
        started_at: c.started_at,
        last_paid_at: c.last_paid_at,
        state: state.as_str().to_string(),
        days_unpaid,
    })
}

/// `POST /api/v1/hosting/contracts` — operator creates a hosting contract.
async fn create_contract(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateContractRequest>,
) -> Result<Json<ContractView>, ApiError> {
    // Cheap up-front guard (the core `validate()` also rejects this) so the
    // caller gets a clear 400 rather than a generic contract error.
    if req.sats_per_day == 0 {
        return Err(ApiError::BadRequest("sats_per_day must be > 0".into()));
    }
    let tenant = NodeId::from_hex(req.tenant_pubkey.trim())
        .map_err(|e| ApiError::BadRequest(format!("invalid tenant_pubkey hex: {e}")))?;

    // The operator is THIS node — never trust a caller-supplied operator key.
    let operator_pubkey = state.lightning.get_node_pubkey().await.ok_or_else(|| {
        ApiError::Lightning(
            "node Lightning pubkey unavailable — cannot create a hosting contract".into(),
        )
    })?;

    // Idempotency / anti-double-billing: refuse a second live contract for the
    // same (tenant, operator). Each row is its own daily-keysend relationship,
    // so a duplicate (a retried POST, a double-click) would silently double the
    // tenant's bill. Stop the existing contract first to re-host.
    let existing = state
        .storage
        .list_operator_hosting_contracts()
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;
    if has_active_contract_for(&existing, &tenant, &operator_pubkey) {
        return Err(ApiError::Conflict(format!(
            "an active hosting contract already exists for tenant {} — stop it before creating a new one",
            tenant.to_hex()
        )));
    }

    let now = unix_now();
    let contract = OperatorHostingContract::new(
        Uuid::new_v4(),
        tenant,
        operator_pubkey,
        req.sats_per_day,
        now,
    )
    .map_err(|e| ApiError::BadRequest(format!("invalid hosting contract: {e}")))?;

    state
        .storage
        .upsert_operator_hosting_contract(&contract)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    Ok(Json(contract_view(&contract, now)?))
}

/// `GET /api/v1/hosting/contracts` — list contracts with live state.
async fn list_contracts(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ContractView>>, ApiError> {
    let now = unix_now();
    let contracts = state
        .storage
        .list_operator_hosting_contracts()
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;
    let views = contracts
        .iter()
        .map(|c| contract_view(c, now))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(views))
}

/// `GET /api/v1/hosting/contracts/:id/ledger` — that contract's payment ledger.
async fn contract_ledger(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Vec<OperatorHostingPayment>>, ApiError> {
    let contract_id = Uuid::parse_str(id.trim())
        .map_err(|e| ApiError::BadRequest(format!("invalid contract id: {e}")))?;
    let payments = state
        .storage
        .list_operator_hosting_payments(&contract_id)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;
    Ok(Json(payments))
}

/// Mounts the operator-hosting routes (all [`AuthUser`]-gated).
pub fn routes() -> Router<Arc<AppState>> {
    if !hosting_contracts_enabled() {
        return Router::new();
    }

    Router::new()
        .route(
            "/api/v1/hosting/contracts",
            post(create_contract).get(list_contracts),
        )
        .route("/api/v1/hosting/contracts/:id/ledger", get(contract_ledger))
}

#[cfg(test)]
mod tests {
    use super::*;
    use konsensus_storage::{SqliteStorage, Storage};

    /// The operator-hosting feature gate is OFF by default and opts in only on
    /// explicit truthy tokens. This is the predicate both the payment task and
    /// the `routes()` mount guard read, so a public/reference node never
    /// auto-charges or exposes the hosting API unless the operator sets the flag.
    #[test]
    fn hosting_gate_is_off_by_default_and_opts_in_explicitly() {
        // Default OFF: absent env, empty, and non-truthy values.
        assert!(!hosting_flag_enabled(None), "absent flag must be OFF");
        assert!(!hosting_flag_enabled(Some("")), "empty flag must be OFF");
        assert!(!hosting_flag_enabled(Some("0")), "0 must be OFF");
        assert!(!hosting_flag_enabled(Some("false")), "false must be OFF");
        assert!(!hosting_flag_enabled(Some("no")), "no must be OFF");
        assert!(!hosting_flag_enabled(Some("enabled")), "arbitrary must be OFF");
        // Opt IN only on the accepted truthy tokens.
        for on in ["1", "true", "TRUE", "yes", "YES"] {
            assert!(hosting_flag_enabled(Some(on)), "{on} must enable hosting");
        }
    }

    // NOTE on the mount + task guards: both `routes()` (this file, above) and
    // `run_daily_payment_task` (konsensus-node hosting_pay.rs) are a single
    // `if !hosting_contracts_enabled() { early-return }` over the predicate
    // exercised in the test above. They are not asserted with a live request
    // here because that requires a fully-constructed `AppState`; the gate they
    // depend on is deterministically pinned by `hosting_gate_is_off_by_default_*`.

    fn tenant_hex() -> String {
        "11".repeat(32)
    }

    /// A validly-formatted compressed LN pubkey (66 hex, `02`-prefixed). In
    /// production the operator pubkey comes from `get_node_pubkey()`.
    fn op_pubkey() -> String {
        format!("02{}", "ab".repeat(32))
    }

    /// Create → persist → list round-trip: a fresh contract is `active` with
    /// 0 days unpaid, and reads back through the live-state list view.
    #[tokio::test]
    async fn create_then_list_contract_roundtrip() {
        let storage = SqliteStorage::in_memory().await.unwrap();
        let now = 1_700_000_000;
        let tenant = NodeId::from_hex(&tenant_hex()).unwrap();
        let contract =
            OperatorHostingContract::new(Uuid::new_v4(), tenant, op_pubkey(), 20_000, now).unwrap();
        storage
            .upsert_operator_hosting_contract(&contract)
            .await
            .unwrap();

        let listed = storage.list_operator_hosting_contracts().await.unwrap();
        assert_eq!(listed.len(), 1);
        let view = contract_view(&listed[0], now).unwrap();
        assert_eq!(view.state, "active");
        assert_eq!(view.days_unpaid, 0);
        assert_eq!(view.sats_per_day, 20_000);
        assert_eq!(view.tenant_pubkey, tenant_hex());
    }

    /// An unpaid contract crosses into `overdue` after the 7-day grace.
    #[tokio::test]
    async fn contract_view_reports_overdue_after_grace() {
        let start = 1_700_000_000u64;
        let tenant = NodeId::from_hex(&tenant_hex()).unwrap();
        let contract =
            OperatorHostingContract::new(Uuid::new_v4(), tenant, op_pubkey(), 10_000, start)
                .unwrap();
        // 8 days later, never paid.
        let now = start + 8 * 86_400;
        let view = contract_view(&contract, now).unwrap();
        assert_eq!(view.state, "overdue");
        assert!(view.days_unpaid >= 7);
    }

    /// A second live contract for the same tenant is detected as a duplicate
    /// (the handler turns this into a 409 instead of a second payable row).
    #[test]
    fn duplicate_active_contract_is_detected() {
        let tenant = NodeId::from_hex(&tenant_hex()).unwrap();
        let op = op_pubkey();
        let c =
            OperatorHostingContract::new(Uuid::new_v4(), tenant, op.clone(), 20_000, 1_700_000_000)
                .unwrap();
        let contracts = vec![c];
        assert!(has_active_contract_for(&contracts, &tenant, &op));
        // A different tenant is not a duplicate.
        let other = NodeId::from_hex(&"22".repeat(32)).unwrap();
        assert!(!has_active_contract_for(&contracts, &other, &op));
    }

    /// `sats_per_day = 0` is rejected by the core constructor (mirrored by the
    /// handler's 400 guard).
    #[test]
    fn zero_price_contract_is_rejected() {
        let tenant = NodeId::from_hex(&tenant_hex()).unwrap();
        let res =
            OperatorHostingContract::new(Uuid::new_v4(), tenant, op_pubkey(), 0, 1_700_000_000);
        assert!(res.is_err());
    }
}
