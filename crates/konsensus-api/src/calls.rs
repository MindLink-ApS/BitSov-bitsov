//! This node's 1:1 call state (kinds 400-403), shared by the compose path
//! (outgoing) and the receive path (incoming). See
//! [`konsensus_core::payloads::call`] for the rules.
//!
//! Process-wide, like the admission ledger: a `std` mutex never held across
//! `await`, recovered from poison so a panic elsewhere cannot block calls.

use std::sync::{Mutex, MutexGuard, OnceLock};

use konsensus_core::payloads::call::{CallRefusal, CallRegistry, CallSignal, Direction};
use konsensus_core::types::NodeId;

use crate::error::ApiError;
use crate::state::AppState;

/// How long to wait for the callee's own answer to a call price query.
const PRICE_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// A cached table older than this is not a quote.
const MAX_PRICE_AGE: std::time::Duration = std::time::Duration::from_secs(3600);

/// The callee's current call-offer price (trust discount applied), asked of
/// the callee itself just now: a `PriceQuery` for kind 400 and its
/// `PriceResponse`. A sender never falls back to its own tariff for a call
/// offer: with no fresh answer, nothing is paid.
pub async fn peer_call_price(state: &AppState, peer: &NodeId) -> Result<u64, ApiError> {
    let kind = konsensus_core::kind::KIND_CALL_INVITE;
    let asked = std::time::Instant::now();
    let frame = konsensus_message::Frame::PriceQuery { kind }
        .to_bytes()
        .map_err(|e| ApiError::Internal(format!("frame serialization error: {e}")))?;
    let unknown = || {
        ApiError::BadRequest("their node did not answer with a call price; nothing was paid".into())
            .with_reason("call_price_unknown")
    };
    state.transport.send_raw_frame(peer, &frame).await.map_err(|_| unknown())?;
    let key = konsensus_pricing::peer_prices::kind_key(kind);
    tokio::time::timeout(PRICE_QUERY_TIMEOUT, async {
        loop {
            let fresh = state.peer_prices.get_peer_entry(peer).await
                .is_some_and(|e| e.received_at >= asked && e.prices.contains_key(&key));
            if fresh {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| unknown())?;
    let height = state.chain.get_block_height().await.unwrap_or(0);
    state.peer_prices.get_fresh_discounted_peer_price(peer, kind, height, MAX_PRICE_AGE).await.ok_or_else(unknown)
}

fn registry() -> MutexGuard<'static, CallRegistry> {
    static CALLS: OnceLock<Mutex<CallRegistry>> = OnceLock::new();
    CALLS.get_or_init(|| Mutex::new(CallRegistry::new())).lock().unwrap_or_else(|p| p.into_inner())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Whether `kind` is 1:1 call signalling (400-403).
pub fn is_call_kind(kind: u16) -> bool {
    (konsensus_core::kind::KIND_CALL_INVITE..=konsensus_core::kind::KIND_CALL_HANGUP).contains(&kind)
}

/// Admit a signal this node received (after the payment gate). A refusal
/// means it must not reach the app.
pub fn admit_incoming(peer: &NodeId, kind: u16, plaintext: Option<&str>) -> Result<CallSignal, CallRefusal> {
    let signal = CallSignal::parse(kind, plaintext.ok_or(CallRefusal::Invalid("undecryptable"))?)?;
    registry().admit(Direction::Incoming, peer, kind, &signal, now_ms())?;
    Ok(signal)
}

/// Admit a signal this node is about to pay for and send. Refused before
/// any price is quoted or any payment starts.
pub fn admit_outgoing(peer: &NodeId, kind: u16, plaintext: &str) -> Result<(), ApiError> {
    let refused = |e: CallRefusal, reason: &'static str| ApiError::BadRequest(e.to_string()).with_reason(reason);
    let signal = CallSignal::parse(kind, plaintext).map_err(|e| refused(e, "call_signal_invalid"))?;
    registry().admit(Direction::Outgoing, peer, kind, &signal, now_ms()).map_err(|e| {
        let reason = match e {
            CallRefusal::Replayed => "call_id_used",
            CallRefusal::Full => "call_busy",
            _ => "call_not_live",
        };
        refused(e, reason)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outgoing_refusals_are_named_before_any_payment() {
        let peer = NodeId::from_bytes([7; 32]);
        let id = format!("{:032x}", 0xca11_u128 + u128::from(std::process::id()));
        let offer = format!(r#"{{"v":1,"call_id":"{id}","media":"audio","sdp":"v=0"}}"#);
        admit_outgoing(&peer, 400, &offer).unwrap();
        let again = admit_outgoing(&peer, 400, &offer).unwrap_err();
        assert!(matches!(&again, ApiError::Reasoned { reason: "call_id_used", .. }), "{again:?}");
        let ice = format!(r#"{{"v":1,"call_id":"{:032x}","candidate":"c"}}"#, 1);
        assert!(matches!(admit_outgoing(&peer, 402, &ice).unwrap_err(), ApiError::Reasoned { reason: "call_not_live", .. }));
        assert!(matches!(admit_outgoing(&peer, 400, "hi").unwrap_err(), ApiError::Reasoned { reason: "call_signal_invalid", .. }));
        assert!(is_call_kind(403) && !is_call_kind(404) && !is_call_kind(0));
    }
}
