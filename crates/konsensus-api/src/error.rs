//! API error types — maps internal errors to HTTP responses.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use thiserror::Error;

/// API errors — converted to appropriate HTTP status codes.
#[derive(Debug, Error)]
pub enum ApiError {
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

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            ApiError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            ApiError::PaymentRequired(msg) => (StatusCode::PAYMENT_REQUIRED, msg.clone()),
            ApiError::Storage(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
            ApiError::Transport(msg) => (StatusCode::BAD_GATEWAY, msg.clone()),
            ApiError::Lightning(msg) => (StatusCode::BAD_GATEWAY, msg.clone()),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
            ApiError::TooManyRequests(msg) => (StatusCode::TOO_MANY_REQUESTS, msg.clone()),
        };

        let body = ErrorBody {
            error: message,
            code: status.as_u16(),
        };

        (status, Json(body)).into_response()
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
