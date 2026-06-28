//! Stable gateway error envelope.

use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;

/// Gateway error type.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    /// Request authentication failed.
    #[error("authentication failed")]
    Authentication,
    /// Request authorization failed.
    #[error("authorization denied: {reason}")]
    Authorization {
        /// Safe denial reason.
        reason: &'static str,
    },
    /// Request body or route validation failed.
    #[error("bad request: {message}")]
    BadRequest {
        /// Safe error message.
        message: String,
    },
    /// Requested resource was not found.
    #[error("not found: {resource}")]
    NotFound {
        /// Safe resource label.
        resource: String,
    },
    /// No eligible route is available.
    #[error("no route available: {reason}")]
    NoRoute {
        /// Safe no-route reason.
        reason: &'static str,
    },
    /// Runtime budget policy rejected the request.
    #[error("budget exceeded: {reason}")]
    BudgetExceeded {
        /// Safe budget denial reason.
        reason: &'static str,
    },
    /// Runtime quota policy rejected the request.
    #[error("quota exceeded: {reason}")]
    QuotaExceeded {
        /// Safe quota denial reason.
        reason: &'static str,
    },
    /// Request handling exceeded the configured inbound timeout.
    #[error("request timed out")]
    RequestTimeout,
    /// Service is not ready.
    #[error("service not ready")]
    NotReady,
    /// Upstream provider execution failed.
    #[error("upstream provider failed: {reason}")]
    Upstream {
        /// Safe upstream failure reason.
        reason: &'static str,
    },
    /// Internal service error.
    #[error("internal error: {message}")]
    Internal {
        /// Safe error message.
        message: String,
    },
}

impl GatewayError {
    /// Returns a stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Authentication => "gateway.auth.authentication_failed",
            Self::Authorization { .. } => "gateway.auth.authorization_denied",
            Self::BadRequest { .. } => "gateway.request.invalid",
            Self::NotFound { .. } => "gateway.resource.not_found",
            Self::NoRoute { .. } => "gateway.route.no_route",
            Self::BudgetExceeded { .. } => "gateway.budget.exceeded",
            Self::QuotaExceeded { .. } => "gateway.quota.exceeded",
            Self::RequestTimeout => "gateway.request.timeout",
            Self::NotReady => "gateway.runtime.not_ready",
            Self::Upstream { .. } => "gateway.upstream.failed",
            Self::Internal { .. } => "gateway.internal",
        }
    }

    /// Returns the HTTP status code for this error.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::Authentication => StatusCode::UNAUTHORIZED,
            Self::Authorization { .. } => StatusCode::FORBIDDEN,
            Self::BadRequest { .. } => StatusCode::BAD_REQUEST,
            Self::NotFound { .. } => StatusCode::NOT_FOUND,
            Self::RequestTimeout => StatusCode::REQUEST_TIMEOUT,
            Self::NoRoute { .. } | Self::NotReady => StatusCode::SERVICE_UNAVAILABLE,
            Self::Upstream { .. } => StatusCode::BAD_GATEWAY,
            Self::BudgetExceeded { .. } | Self::QuotaExceeded { .. } => {
                StatusCode::TOO_MANY_REQUESTS
            }
            Self::Internal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// Stable gateway error response envelope.
#[derive(Debug, Serialize)]
pub struct ErrorEnvelope {
    /// Schema id.
    pub schema: &'static str,
    /// Error payload.
    pub error: ErrorBody,
}

/// Stable gateway error body.
#[derive(Debug, Serialize)]
pub struct ErrorBody {
    /// Machine-readable code.
    pub code: &'static str,
    /// Safe message.
    pub message: String,
    /// Whether retry might succeed.
    pub retryable: bool,
    /// Request id when available.
    pub request_id: Option<String>,
}

impl ErrorEnvelope {
    /// Creates an envelope from a gateway error.
    #[must_use]
    pub fn from_error(error: &GatewayError, request_id: Option<String>) -> Self {
        Self {
            schema: "gateway.error.v1",
            error: ErrorBody {
                code: error.code(),
                message: error.to_string(),
                retryable: matches!(
                    error,
                    GatewayError::NoRoute { .. }
                        | GatewayError::RequestTimeout
                        | GatewayError::NotReady
                        | GatewayError::Upstream { .. }
                        | GatewayError::QuotaExceeded { .. }
                        | GatewayError::Internal { .. }
                ),
                request_id,
            },
        }
    }
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> axum::response::Response {
        let status = self.status();
        let body = ErrorEnvelope::from_error(&self, None);
        (status, Json(body)).into_response()
    }
}

/// Gateway result type.
pub type Result<T> = std::result::Result<T, GatewayError>;
