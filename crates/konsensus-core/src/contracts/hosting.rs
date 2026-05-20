//! Operator hosting contract for cloud-tier node sustainability.

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::types::NodeId;

const DAY_SECS: u64 = 86_400;
const OVERDUE_GRACE_DAYS: u64 = 7;
const PAUSE_GRACE_DAYS: u64 = 14;

/// Lifecycle state for an operator-hosted cloud node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostingContractState {
    /// Daily payments are current or still inside the grace window.
    Active,
    /// No successful payment for at least seven days.
    Overdue,
    /// No successful payment for at least fourteen days; outbound service may pause.
    Paused,
    /// Operator stopped the hosted VM while retaining the user's exit path.
    Stopped,
}

impl HostingContractState {
    /// Stable database representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Overdue => "overdue",
            Self::Paused => "paused",
            Self::Stopped => "stopped",
        }
    }
}

impl FromStr for HostingContractState {
    type Err = HostingContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "active" => Ok(Self::Active),
            "overdue" => Ok(Self::Overdue),
            "paused" => Ok(Self::Paused),
            "stopped" => Ok(Self::Stopped),
            other => Err(HostingContractError::InvalidState(other.to_string())),
        }
    }
}

/// Direction of a recorded operator hosting payment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorHostingPaymentDirection {
    /// Tenant node sent the payment.
    Outgoing,
    /// Operator node received the payment.
    Incoming,
}

impl OperatorHostingPaymentDirection {
    /// Stable database representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Outgoing => "outgoing",
            Self::Incoming => "incoming",
        }
    }
}

impl FromStr for OperatorHostingPaymentDirection {
    type Err = HostingContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "outgoing" => Ok(Self::Outgoing),
            "incoming" => Ok(Self::Incoming),
            other => Err(HostingContractError::InvalidPaymentDirection(
                other.to_string(),
            )),
        }
    }
}

/// Errors from validating or advancing an operator hosting contract.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HostingContractError {
    /// A fixed sat/day price must be non-zero.
    #[error("sats_per_day must be greater than zero")]
    ZeroDailyPrice,

    /// Sats to msat conversion overflowed.
    #[error("sats_per_day overflows millisatoshi conversion")]
    AmountOverflow,

    /// Operator Lightning pubkey is not a compressed secp256k1 pubkey in hex.
    #[error("operator_pubkey must be 66 hex characters")]
    InvalidOperatorPubkey,

    /// A timestamp went backwards relative to the contract start.
    #[error("timestamp precedes contract start")]
    TimestampBeforeStart,

    /// Storage contained an unknown state.
    #[error("invalid hosting contract state: {0}")]
    InvalidState(String),

    /// Storage contained an unknown payment direction.
    #[error("invalid hosting payment direction: {0}")]
    InvalidPaymentDirection(String),

    /// New payment timestamp is earlier than the previous one — refused to
    /// avoid time-rewind double-pay attacks.
    #[error("paid_at {new} would rewind last_paid_at {prev}")]
    TimestampMonotonicity { prev: u64, new: u64 },
}

/// Contract declaring that a cloud-tier tenant pays an operator for VM hosting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorHostingContract {
    /// Stable contract id.
    pub id: Uuid,
    /// Tenant BitSov node identity.
    pub tenant_pubkey: NodeId,
    /// Operator Lightning node pubkey that receives daily keysends.
    pub operator_pubkey: String,
    /// Fixed daily hosting price in sats.
    pub sats_per_day: u64,
    /// Unix timestamp when hosting started.
    pub started_at: u64,
    /// Unix timestamp of the last successful hosting payment.
    pub last_paid_at: Option<u64>,
    /// Current lifecycle state.
    pub state: HostingContractState,
}

impl OperatorHostingContract {
    /// Create and validate a new active hosting contract.
    pub fn new(
        id: Uuid,
        tenant_pubkey: NodeId,
        operator_pubkey: String,
        sats_per_day: u64,
        started_at: u64,
    ) -> Result<Self, HostingContractError> {
        let contract = Self {
            id,
            tenant_pubkey,
            operator_pubkey,
            sats_per_day,
            started_at,
            last_paid_at: None,
            state: HostingContractState::Active,
        };
        contract.validate()?;
        Ok(contract)
    }

    /// Validate fields that must hold before the contract is actionable.
    pub fn validate(&self) -> Result<(), HostingContractError> {
        if self.sats_per_day == 0 {
            return Err(HostingContractError::ZeroDailyPrice);
        }
        self.daily_amount_msat()?;
        if !is_compressed_pubkey_hex(&self.operator_pubkey) {
            return Err(HostingContractError::InvalidOperatorPubkey);
        }
        if let Some(last_paid_at) = self.last_paid_at {
            if last_paid_at < self.started_at {
                return Err(HostingContractError::TimestampBeforeStart);
            }
        }
        Ok(())
    }

    /// Daily payment amount in millisatoshis.
    pub fn daily_amount_msat(&self) -> Result<u64, HostingContractError> {
        self.sats_per_day
            .checked_mul(1_000)
            .ok_or(HostingContractError::AmountOverflow)
    }

    /// Timestamp that determines unpaid age.
    pub fn paid_through_at(&self) -> u64 {
        self.last_paid_at.unwrap_or(self.started_at)
    }

    /// Whole unpaid days at `now`.
    pub fn days_unpaid_at(&self, now: u64) -> Result<u64, HostingContractError> {
        if now < self.started_at {
            return Err(HostingContractError::TimestampBeforeStart);
        }
        Ok(now.saturating_sub(self.paid_through_at()) / DAY_SECS)
    }

    /// Whether another daily payment should be attempted at `now`.
    pub fn payment_due_at(&self, now: u64) -> Result<bool, HostingContractError> {
        if matches!(self.state, HostingContractState::Stopped) {
            return Ok(false);
        }
        if now < self.started_at {
            return Err(HostingContractError::TimestampBeforeStart);
        }
        Ok(now.saturating_sub(self.paid_through_at()) >= DAY_SECS)
    }

    /// State implied by unpaid age at `now`.
    pub fn state_at(&self, now: u64) -> Result<HostingContractState, HostingContractError> {
        if self.state == HostingContractState::Stopped {
            return Ok(HostingContractState::Stopped);
        }
        let days = self.days_unpaid_at(now)?;
        if days >= PAUSE_GRACE_DAYS {
            Ok(HostingContractState::Paused)
        } else if days >= OVERDUE_GRACE_DAYS {
            Ok(HostingContractState::Overdue)
        } else {
            Ok(HostingContractState::Active)
        }
    }

    /// Return a copy advanced after a successful payment.
    ///
    /// Enforces monotonicity: `paid_at` must not be earlier than the previous
    /// `last_paid_at` (if any) and must not be earlier than `started_at`. This
    /// closes the AI-review-flagged time-rewind attack where a stale or
    /// out-of-order timestamp (clock skew, replayed scan, restored backup)
    /// would move `last_paid_at` backward and immediately re-trigger
    /// `payment_due_at` — causing a double payment.
    pub fn mark_paid_at(&self, paid_at: u64) -> Result<Self, HostingContractError> {
        if paid_at < self.started_at {
            return Err(HostingContractError::TimestampBeforeStart);
        }
        if let Some(prev) = self.last_paid_at {
            if paid_at < prev {
                return Err(HostingContractError::TimestampMonotonicity {
                    prev,
                    new: paid_at,
                });
            }
        }
        let mut updated = self.clone();
        updated.last_paid_at = Some(paid_at);
        updated.state = HostingContractState::Active;
        Ok(updated)
    }

    /// Memo used by the tenant keysend and operator-side payment scanner.
    ///
    /// Form: `operator-hosting:<contract_id>`. The tenant_pubkey is
    /// deliberately NOT included — it is redundant (the operator already
    /// looks up the tenant via `contract_id`) and was a Principle 4
    /// metadata leak in v1 (visible to last-hop Lightning nodes per
    /// keysend TLV semantics).
    pub fn keysend_memo(&self) -> String {
        format!("operator-hosting:{}", self.id)
    }
}

/// Recorded Lightning payment for an operator hosting contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorHostingPayment {
    /// Lightning payment hash.
    pub payment_hash: String,
    /// Contract this payment belongs to.
    pub contract_id: Uuid,
    /// Tenant BitSov node identity.
    pub tenant_pubkey: NodeId,
    /// Operator Lightning pubkey that received or should receive payment.
    pub operator_pubkey: String,
    /// Paid amount in millisatoshis.
    pub amount_msat: u64,
    /// Unix timestamp when the payment settled.
    pub paid_at: u64,
    /// Incoming or outgoing from this node's perspective.
    pub direction: OperatorHostingPaymentDirection,
    /// Optional settled preimage.
    pub preimage: Option<String>,
    /// Optional memo attached to the payment.
    pub memo: Option<String>,
}

fn is_compressed_pubkey_hex(value: &str) -> bool {
    value.len() == 66 && hex::decode(value).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant() -> NodeId {
        NodeId::from_bytes([7u8; 32])
    }

    fn operator_pubkey() -> String {
        format!("02{}", "11".repeat(32))
    }

    #[test]
    fn contract_validates_and_converts_sats_to_msat() {
        let contract = OperatorHostingContract::new(
            Uuid::nil(),
            tenant(),
            operator_pubkey(),
            20_000,
            1_700_000_000,
        )
        .expect("valid contract");

        assert_eq!(contract.daily_amount_msat().unwrap(), 20_000_000);
        assert_eq!(contract.state, HostingContractState::Active);
    }

    #[test]
    fn zero_daily_price_is_rejected() {
        let err = OperatorHostingContract::new(
            Uuid::nil(),
            tenant(),
            operator_pubkey(),
            0,
            1_700_000_000,
        )
        .unwrap_err();

        assert_eq!(err, HostingContractError::ZeroDailyPrice);
    }

    #[test]
    fn invalid_operator_pubkey_is_rejected() {
        let err = OperatorHostingContract::new(
            Uuid::nil(),
            tenant(),
            "not-a-pubkey".to_string(),
            1,
            1_700_000_000,
        )
        .unwrap_err();

        assert_eq!(err, HostingContractError::InvalidOperatorPubkey);
    }

    #[test]
    fn overdue_and_pause_thresholds_are_day_based() {
        let started = 1_700_000_000;
        let contract =
            OperatorHostingContract::new(Uuid::nil(), tenant(), operator_pubkey(), 1, started)
                .expect("valid contract");

        assert_eq!(
            contract.state_at(started + 6 * DAY_SECS).unwrap(),
            HostingContractState::Active
        );
        assert_eq!(
            contract.state_at(started + 7 * DAY_SECS).unwrap(),
            HostingContractState::Overdue
        );
        assert_eq!(
            contract.state_at(started + 14 * DAY_SECS).unwrap(),
            HostingContractState::Paused
        );
    }

    #[test]
    fn successful_payment_resets_state_and_due_clock() {
        let started = 1_700_000_000;
        let contract =
            OperatorHostingContract::new(Uuid::nil(), tenant(), operator_pubkey(), 1, started)
                .expect("valid contract");

        let paid = contract.mark_paid_at(started + 8 * DAY_SECS).unwrap();
        assert_eq!(paid.last_paid_at, Some(started + 8 * DAY_SECS));
        assert_eq!(paid.state, HostingContractState::Active);
        assert!(!paid.payment_due_at(started + 8 * DAY_SECS + 60).unwrap());
        assert!(paid.payment_due_at(started + 9 * DAY_SECS + 1).unwrap());
    }

    #[test]
    fn memo_contains_contract_and_tenant() {
        let contract = OperatorHostingContract::new(
            Uuid::nil(),
            tenant(),
            operator_pubkey(),
            1,
            1_700_000_000,
        )
        .expect("valid contract");

        // Memo intentionally does NOT include tenant_pubkey (Principle 4
        // metadata-leak fix per PR #88 AI review). Operator looks up tenant
        // via contract_id, not the wire memo.
        assert_eq!(
            contract.keysend_memo(),
            format!("operator-hosting:{}", Uuid::nil())
        );
    }

    #[test]
    fn mark_paid_at_rejects_time_rewind() {
        let started = 1_700_000_000;
        let contract = OperatorHostingContract::new(
            Uuid::nil(),
            tenant(),
            operator_pubkey(),
            1,
            started,
        )
        .expect("valid contract");

        let paid_first = contract
            .mark_paid_at(started + 2 * DAY_SECS)
            .expect("forward payment ok");
        assert_eq!(paid_first.last_paid_at, Some(started + 2 * DAY_SECS));

        // Attempting to mark an EARLIER paid_at must be rejected — this is
        // the time-rewind attack the AI review on PR #88 flagged.
        let err = paid_first
            .mark_paid_at(started + DAY_SECS)
            .expect_err("must reject rewind");
        assert!(matches!(
            err,
            HostingContractError::TimestampMonotonicity { .. }
        ));
    }
}
