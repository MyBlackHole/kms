use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    pub request_id: Option<String>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.code.as_str() {
            "KEY_NOT_FOUND" => StatusCode::NOT_FOUND,
            "KEY_DISABLED" => StatusCode::CONFLICT,
            "KEY_EXPIRED" => StatusCode::CONFLICT,
            "POLICY_DENIED" => StatusCode::FORBIDDEN,
            "INVALID_REQUEST" => StatusCode::BAD_REQUEST,
            "CRYPTO_ERROR" => StatusCode::INTERNAL_SERVER_ERROR,
            "HSM_ERROR" => StatusCode::INTERNAL_SERVER_ERROR,
            "UNAUTHORIZED" => StatusCode::UNAUTHORIZED,
            "AUDIT_ERROR" => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (status, axum::Json(self)).into_response()
    }
}

impl From<crate::Error> for ApiError {
    fn from(err: crate::Error) -> Self {
        let (code, _status) = match &err {
            crate::Error::KeyNotFound(_) => ("KEY_NOT_FOUND", StatusCode::NOT_FOUND),
            crate::Error::KeyDisabled(_) => ("KEY_DISABLED", StatusCode::CONFLICT),
            crate::Error::KeyExpired(_) => ("KEY_EXPIRED", StatusCode::CONFLICT),
            crate::Error::PolicyDenied(_) => ("POLICY_DENIED", StatusCode::FORBIDDEN),
            crate::Error::CryptoError(_) => ("CRYPTO_ERROR", StatusCode::INTERNAL_SERVER_ERROR),
            crate::Error::HsmError(_) => ("HSM_ERROR", StatusCode::INTERNAL_SERVER_ERROR),
            crate::Error::VerificationFailed(_) => ("VERIFICATION_FAILED", StatusCode::BAD_REQUEST),
            crate::Error::SerializationError(_) => ("INVALID_REQUEST", StatusCode::BAD_REQUEST),
            _ => ("INTERNAL_ERROR", StatusCode::INTERNAL_SERVER_ERROR),
        };

        Self {
            code: code.into(),
            message: err.to_string(),
            request_id: None,
        }
    }
}
