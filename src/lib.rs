pub mod api;
pub mod approval;
pub mod audit;
pub mod auth;
pub mod backup;
pub mod cli;
pub mod config;
pub mod crypto;
pub mod evidence;
pub mod hsm;
pub mod key;
pub mod monitor;
pub mod policy;
pub mod store;
pub mod trust;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("密钥未找到: {0}")]
    KeyNotFound(String),
    #[error("密钥已禁用: {0}")]
    KeyDisabled(String),
    #[error("密钥已过期: {0}")]
    KeyExpired(String),
    #[error("加密操作失败: {0}")]
    CryptoError(String),
    #[error("HSM 操作失败: {0}")]
    HsmError(String),
    #[error("策略拒绝: {0}")]
    PolicyDenied(String),
    #[error("验证失败: {0}")]
    VerificationFailed(String),
    #[error("序列化错误: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("数据库错误: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("IO 错误: {0}")]
    IoError(#[from] std::io::Error),
    #[error("内部错误: {0}")]
    Internal(String),
    #[error("API 错误 ({0}): {1}")]
    ApiError(u16, String),
    #[error("HTTP 请求失败: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("配置解析错误: {0}")]
    ConfigError(#[from] toml::de::Error),
}

impl axum::response::IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        let api_error: api::error::ApiError = self.into();
        api_error.into_response()
    }
}
