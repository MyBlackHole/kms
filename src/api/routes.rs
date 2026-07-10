use crate::Error;
use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use std::sync::Arc;
use std::time::Instant;

pub struct AppState {
    pub key_manager: crate::key::manager::KeyManager,
    pub envelope: crate::crypto::envelope::EnvelopeEncryption,
    pub kek_provider: Box<dyn crate::hsm::traits::KekProvider>,
    pub audit_logger: crate::audit::logger::AuditLogger,
    pub policy_engine: crate::policy::engine::PolicyEngine,
    pub session_manager: Arc<crate::auth::session::SessionManager>,
    pub totp_secret_issuer: String,
    pub pool: sqlx::SqlitePool,
    pub token_store: crate::auth::token::TokenStore,
    pub approval_store: crate::approval::SqliteApprovalStore,
    pub dep_store: crate::key::dependency::SqliteDependencyStore,
    pub blocklist: crate::monitor::blocklist::SharedBlocklist,
    pub tpm: Box<dyn crate::trust::tpm::TrustedPlatformModule>,
    pub started_at: Instant,
    pub totp_attempts: Arc<std::sync::Mutex<std::collections::HashMap<String, (u32, Instant)>>>,
    /// 安全等级（Level3 / Level4）
    pub security_level: crate::config::SecurityLevel,
    /// 抗抵赖模块开关
    pub anti_repudiation: bool,
    /// 运行安全画像
    pub security_profile: crate::config::SecurityProfile,
    /// 等保四级详细配置
    pub level4_config: crate::config::Level4Config,
    /// 二次鉴权管理器
    pub reauth_manager: Option<Arc<crate::auth::reauth::ReauthManager>>,
}

pub fn build_router(state: Arc<AppState>) -> Router {
    let mut router = Router::new()
        .route("/api/v1/health", get(health_check))
        // KMIP 2.1 端点（JSON-KMIP over HTTP）
        .route("/kmip/2_1", post(kmip_handler));

    if cfg!(feature = "monitoring") {
        router = router.route("/api/v1/metrics", get(metrics_handler));
    }

    router.with_state(state)
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub hsm_mode: String,
}

async fn metrics_handler(State(state): State<Arc<AppState>>) -> Result<String, crate::Error> {
    if cfg!(feature = "monitoring") {
        Ok(
            crate::monitor::metrics::MetricsCollector::generate(&state.pool, state.started_at)
                .await?,
        )
    } else {
        Err(crate::Error::Internal(
            "监控指标端点未启用（需要 monitoring feature）".into(),
        ))
    }
}

async fn health_check(State(state): State<Arc<AppState>>) -> Result<Json<HealthResponse>, Error> {
    Ok(Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        hsm_mode: state.kek_provider.name().into(),
    }))
}

// ─────────
// KMIP 2.1 JSON-KMIP over HTTP 端点
// ─────────

async fn kmip_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<crate::api::kmip::types::KmipNode>,
) -> Result<Json<crate::api::kmip::types::KmipNode>, Error> {
    let response = crate::api::kmip::dispatcher::dispatch(state, body).await;
    Ok(Json(response))
}
