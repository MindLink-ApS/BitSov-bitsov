//! API error types — maps internal errors to HTTP responses.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use thiserror::Error;

/// API errors — converted to appropriate HTTP status codes.
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Lightning is offline or synchronizing; retry when money_ready is true")]
    NotReady,

    #[error("{source}")]
    RoutingFee { source: Box<ApiError>, max_routing_fee_msat: u64 },
    /// The backend positively refused the operation before any dispatch.
    #[error("not dispatched: {0}")]
    NotDispatched(String),
    #[error("recipient backend does not support stateless first-contact quotes")]
    StatelessQuoteUnsupported,

    #[error("price cap exceeded: {0}")]
    PriceCapExceeded(String),

    /// A paired client's budget grant refused the debit (G1). Nothing was
    /// reserved and no invoice was requested or paid.
    #[error("budget exceeded: {0}")]
    BudgetExceeded(crate::spend_budget::BudgetRefusal),

    /// A dispatch may have happened, but no terminal payment evidence is available.
    #[error("payment outcome unknown: {0}")]
    PaymentUnresolved(String),
    /// Payment settled, but an envelope proof could not be constructed.
    #[error("payment settled but proof unavailable: {reason}")]
    PaymentProofUnavailable { amount_msat: u64, reason: String },

    /// Resource not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Bad request (invalid input).
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Conflict (resource state prevents operation).
    #[error("conflict: {0}")]
    Conflict(String),

    /// Authentication failed.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// Authenticated, but the token does not carry the scope this operation needs.
    ///
    /// Distinct from [`ApiError::Unauthorized`] on purpose (#72): the caller proved who
    /// it is and simply may not do this. Answering 401 would invite a client to
    /// re-authenticate in a loop for authority its issuer can never grant. Mirrors the
    /// 403 that `ScopedAuth` returns, for the cases where the required scope depends on
    /// the request body and cannot be stated in the extractor.
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// Payment gate rejected the message.
    #[error("payment required: {0}")]
    PaymentRequired(String),

    /// Storage error.
    #[error("storage error: {0}")]
    Storage(String),

    /// Transport error.
    #[error("transport error: {0}")]
    Transport(String),

    /// Lightning error.
    #[error("lightning error: {0}")]
    Lightning(String),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),

    /// Rate limit exceeded.
    #[error("too many requests: {0}")]
    TooManyRequests(String),
}

/// JSON error response body.
#[derive(Serialize)]
struct ErrorBody {
    error: String,
    code: u16,
}

impl ApiError {
    pub(crate) fn with_routing_fee(self, max_routing_fee_msat: u64) -> Self {
        Self::RoutingFee { source: Box::new(self), max_routing_fee_msat }
    }
    fn response_parts(&self) -> (StatusCode, serde_json::Value) {
        if matches!(self, Self::NotReady) {
            return (StatusCode::SERVICE_UNAVAILABLE, serde_json::json!({
                "error": self.to_string(), "code": "not_ready", "money_ready": false
            }));
        }
        if let Self::RoutingFee { source, max_routing_fee_msat } = self {
            let (status, mut body) = source.response_parts();
            body["max_routing_fee_msat"] = (*max_routing_fee_msat).into();
            return (status, body);
        }
        if let Self::NotDispatched(reason) = self {
            return (StatusCode::BAD_REQUEST, serde_json::json!({
                "error": reason, "code": "not_dispatched"
            }));
        }
        if matches!(self, ApiError::StatelessQuoteUnsupported) {
            return (StatusCode::SERVICE_UNAVAILABLE, serde_json::json!({
                "error": self.to_string(), "code": "stateless_quote_unsupported"
            }));
        }
        if let ApiError::PriceCapExceeded(message) = &self {
            return (StatusCode::CONFLICT, serde_json::json!({
                "error": message, "code": "price_cap_exceeded"
            }));
        }
        if let ApiError::PaymentProofUnavailable { amount_msat, reason } = &self {
            return (StatusCode::BAD_GATEWAY, serde_json::json!({
                "error": reason, "code": "payment_settled_send_incomplete", "amount_msat": amount_msat
            }));
        }
        if let ApiError::BudgetExceeded(refusal) = &self {
            let remaining = match refusal {
                crate::spend_budget::BudgetRefusal::Total { remaining_msat }
                | crate::spend_budget::BudgetRefusal::Recipient { remaining_msat, .. } => {
                    Some(*remaining_msat)
                }
                _ => None,
            };
            return (StatusCode::CONFLICT, serde_json::json!({
                "error": refusal.to_string(),
                "code": "budget_exceeded",
                "reason": refusal.reason(),
                "remaining_msat": remaining,
            }));
        }
        let (status, message) = match &self {
            ApiError::NotReady | ApiError::RoutingFee { .. } | ApiError::NotDispatched(_) | ApiError::PriceCapExceeded(_) | ApiError::BudgetExceeded(_) | ApiError::StatelessQuoteUnsupported => unreachable!(),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            ApiError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            ApiError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            ApiError::PaymentRequired(msg) => (StatusCode::PAYMENT_REQUIRED, msg.clone()),
            ApiError::Storage(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
            ApiError::Transport(msg) => (StatusCode::BAD_GATEWAY, msg.clone()),
            ApiError::PaymentUnresolved(msg) => (StatusCode::BAD_GATEWAY, msg.clone()),
            ApiError::PaymentProofUnavailable { reason, .. } => (StatusCode::BAD_GATEWAY, reason.clone()),
            ApiError::Lightning(msg) => (StatusCode::BAD_GATEWAY, msg.clone()),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
            ApiError::TooManyRequests(msg) => (StatusCode::TOO_MANY_REQUESTS, msg.clone()),
        };

        let body = ErrorBody {
            error: message,
            code: status.as_u16(),
        };

        (status, serde_json::to_value(body).expect("error body serializes"))
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, body) = self.response_parts();
        (status, Json(body)).into_response()
    }
}

/// Check before parsing payment details, consuming grants, or issuing invoices.
pub(crate) async fn require_money_ready(state: &crate::state::AppState) -> Result<(), ApiError> {
    if state.lightning.money_ready().await { Ok(()) } else { Err(ApiError::NotReady) }
}

impl From<konsensus_core::traits::lightning::LightningError> for ApiError {
    fn from(error: konsensus_core::traits::lightning::LightningError) -> Self {
        match error {
            konsensus_core::traits::lightning::LightningError::NotReady => Self::NotReady,
            other => Self::Lightning(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse the JSON body from an ApiError response.
    async fn error_body(err: ApiError) -> (StatusCode, serde_json::Value) {
        let resp = err.into_response();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (status, json)
    }

    #[tokio::test]
    async fn not_dispatched_keeps_400_and_code_when_wrapped_with_routing_fee() {
        for ceiling in [0, 5_000] {
            let (status, body) = error_body(
                ApiError::NotDispatched("announce_unavailable".into()).with_routing_fee(ceiling),
            ).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body["code"], "not_dispatched");
            assert_eq!(body["error"], "announce_unavailable");
            assert_eq!(body["max_routing_fee_msat"], ceiling);
        }
    }

    #[tokio::test]
    async fn not_found_returns_404() {
        let (status, json) = error_body(ApiError::NotFound("room not found".into())).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(json["code"], 404);
        assert_eq!(json["error"], "room not found");
    }

    #[tokio::test]
    async fn bad_request_returns_400() {
        let (status, json) = error_body(ApiError::BadRequest("invalid input".into())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["code"], 400);
        assert_eq!(json["error"], "invalid input");
    }

    #[tokio::test]
    async fn unauthorized_returns_401() {
        let (status, json) = error_body(ApiError::Unauthorized("bad token".into())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(json["code"], 401);
    }

    #[tokio::test]
    async fn conflict_returns_409() {
        let (status, json) = error_body(ApiError::Conflict("already accepted".into())).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(json["code"], 409);
        assert_eq!(json["error"], "already accepted");
    }

    #[tokio::test]
    async fn payment_required_returns_402() {
        let (status, json) = error_body(ApiError::PaymentRequired("insufficient".into())).await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        assert_eq!(json["code"], 402);
    }

    #[tokio::test]
    async fn storage_error_returns_500() {
        let (status, json) = error_body(ApiError::Storage("db failed".into())).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["code"], 500);
    }

    #[tokio::test]
    async fn transport_error_returns_502() {
        let (status, json) = error_body(ApiError::Transport("peer unreachable".into())).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(json["code"], 502);
    }

    #[tokio::test]
    async fn lightning_error_returns_502() {
        let (status, json) = error_body(ApiError::Lightning("lnbits down".into())).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(json["code"], 502);
    }

    #[tokio::test]
    async fn internal_error_returns_500() {
        let (status, json) = error_body(ApiError::Internal("unexpected".into())).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["code"], 500);
    }

    #[test]
    fn error_display_messages() {
        assert_eq!(
            ApiError::NotFound("x".into()).to_string(),
            "not found: x"
        );
        assert_eq!(
            ApiError::BadRequest("y".into()).to_string(),
            "bad request: y"
        );
        assert_eq!(
            ApiError::Conflict("c".into()).to_string(),
            "conflict: c"
        );
        assert_eq!(
            ApiError::Unauthorized("z".into()).to_string(),
            "unauthorized: z"
        );
        assert_eq!(
            ApiError::PaymentRequired("p".into()).to_string(),
            "payment required: p"
        );
        assert_eq!(
            ApiError::Storage("s".into()).to_string(),
            "storage error: s"
        );
        assert_eq!(
            ApiError::Transport("t".into()).to_string(),
            "transport error: t"
        );
        assert_eq!(
            ApiError::Lightning("l".into()).to_string(),
            "lightning error: l"
        );
        assert_eq!(
            ApiError::Internal("i".into()).to_string(),
            "internal error: i"
        );
    }

    #[tokio::test]
    async fn error_body_has_correct_json_structure() {
        let (_, json) = error_body(ApiError::NotFound("test".into())).await;
        // Should have exactly "error" and "code" fields
        let obj = json.as_object().unwrap();
        assert_eq!(obj.len(), 2);
        assert!(obj.contains_key("error"));
        assert!(obj.contains_key("code"));
    }

    #[tokio::test]
    async fn empty_error_message_still_valid() {
        let (status, json) = error_body(ApiError::NotFound(String::new())).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(json["error"], "");
        assert_eq!(json["code"], 404);
    }

    #[tokio::test]
    async fn unicode_error_message_preserved() {
        let msg = "unicod\u{00e9} err\u{00f6}r m\u{00e8}ssage";
        let (_, json) = error_body(ApiError::BadRequest(msg.into())).await;
        assert_eq!(json["error"], msg);
    }
}
