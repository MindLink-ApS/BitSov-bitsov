//! Explicit invoice refusals: the reasons a recipient states when it will not
//! issue an invoice, and the binding that routes a refusal to the request that
//! asked.
//!
//! A recipient never ignores a payment request in silence. When it refuses one,
//! it answers with `Frame::InvoiceError` and one of the reasons below, so the
//! sender learns at once what to do instead of timing out.
//!
//! The sender binds each outgoing invoice request to the peer it was sent to.
//! A refusal counts only when it comes from that peer. So a refusal from a peer
//! we have not paid can only end a request we sent to that same peer, which the
//! peer could equally do by never answering.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, OnceLock};

use konsensus_core::NodeId;

/// The recipient does not hold this connection as paid, so it will not issue a
/// paid invoice on it. Every connection is admitted afresh: a reconnect starts
/// unprivileged, and there is no durable admission to carry over. The sender
/// pays admission again (the normal first-contact path) and then asks again.
pub const ADMISSION_REQUIRED: &str = "konsensus:admission_required";

/// The recipient refused an admission invoice because this peer asked for one
/// too recently (the unpaid admission path is rate-limited per peer).
pub const ADMISSION_RATE_LIMITED: &str = "konsensus:admission_rate_limited";

/// Bound on requests tracked at once. The compose paths cap their own pending
/// requests far below this; past it, new requests go unbound (a refusal then
/// times out as before) instead of growing the map.
const MAX_BOUND_REQUESTS: usize = 1024;

struct Binding {
    peer: NodeId,
    refusal: Option<String>,
}

fn bindings() -> MutexGuard<'static, HashMap<String, Binding>> {
    static BINDINGS: OnceLock<Mutex<HashMap<String, Binding>>> = OnceLock::new();
    BINDINGS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Bind an outgoing invoice request to the peer it is sent to. Unbind it with
/// [`RequestBinding::finish`] (or by dropping it) once the request is over.
pub fn bind(request_id: &str, peer: NodeId) -> RequestBinding {
    let mut map = bindings();
    let bound = map.len() < MAX_BOUND_REQUESTS;
    if bound {
        map.insert(request_id.to_string(), Binding { peer, refusal: None });
    }
    RequestBinding {
        request_id: request_id.to_string(),
        bound,
    }
}

/// Record `peer`'s refusal of `request_id`. Returns `true` only when that
/// request is pending and was sent to `peer`; the caller then fails the
/// request, and the compose that sent it reads the reason.
pub fn record(request_id: &str, peer: &NodeId, reason: &str) -> bool {
    match bindings().get_mut(request_id) {
        Some(binding) if binding.peer == *peer => {
            binding.refusal = Some(reason.to_string());
            true
        }
        _ => false,
    }
}

/// An outgoing invoice request's binding. Dropping it unbinds the request.
pub struct RequestBinding {
    request_id: String,
    bound: bool,
}

impl RequestBinding {
    /// Unbind the request and return the peer's refusal reason, if it refused.
    pub fn finish(mut self) -> Option<String> {
        self.take()
    }

    fn take(&mut self) -> Option<String> {
        if !std::mem::take(&mut self.bound) {
            return None;
        }
        bindings().remove(&self.request_id).and_then(|b| b.refusal)
    }
}

impl Drop for RequestBinding {
    fn drop(&mut self) {
        self.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    #[test]
    fn refusal_reaches_the_request_only_from_its_own_peer() {
        let request = uuid::Uuid::new_v4().to_string();
        let binding = bind(&request, node(1));
        assert!(!record(&request, &node(2), ADMISSION_REQUIRED), "another peer cannot refuse it");
        assert!(record(&request, &node(1), ADMISSION_REQUIRED));
        assert_eq!(binding.finish().as_deref(), Some(ADMISSION_REQUIRED));
        assert!(!record(&request, &node(1), ADMISSION_REQUIRED), "finished requests are unbound");
    }

    #[test]
    fn unknown_or_dropped_requests_do_not_bind() {
        let request = uuid::Uuid::new_v4().to_string();
        assert!(!record(&request, &node(1), ADMISSION_REQUIRED));
        drop(bind(&request, node(1)));
        assert!(!record(&request, &node(1), ADMISSION_REQUIRED));
    }
}
