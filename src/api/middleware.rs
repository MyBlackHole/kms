use crate::api::mtls::TlsIdentity;
use crate::auth::session::SessionManager;
use crate::auth::token::TokenStore;
use crate::policy::engine::PolicyEngine;
use crate::policy::label::SecurityLevel;
use crate::policy::roles::AdminRole;
use crate::policy::types::AuthContext;
use axum::{
    extract::{Request, State},
    http::{HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

pub struct Auth {
    admin_token: Option<String>,
}

impl Auth {
    pub fn new(admin_token: Option<String>) -> Self {
        Self { admin_token }
    }

    pub async fn validate_token(&self, token: &str, token_store: &TokenStore) -> bool {
        if self
            .admin_token
            .as_ref()
            .is_some_and(|valid| token == valid)
        {
            return true;
        }
        token_store
            .validate_token(token)
            .await
            .ok()
            .flatten()
            .is_some()
    }
}

#[derive(Clone)]
pub struct AuthMiddlewareState {
    pub auth: Arc<Auth>,
    pub policy: Arc<PolicyEngine>,
    pub session_manager: Arc<SessionManager>,
    pub token_store: Arc<TokenStore>,
    pub require_mtls: bool,
}

const SKIP_AUTH_PREFIXES: &[&str] = &["/api/v1/health", "/kmip/"];
const SKIP_TOTP_PREFIXES: &[&str] = &["/api/v1/health", "/kmip/"];

pub async fn auth_middleware(
    State(mw_state): State<AuthMiddlewareState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = request.uri().path().to_string();
    let method = request.method().to_string();
    let action = format!("{}:{}", method, path);

    let skip_auth = SKIP_AUTH_PREFIXES.iter().any(|p| path.starts_with(p));
    if !skip_auth {
        let auth_header = request
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(StatusCode::UNAUTHORIZED)?;

        if !mw_state
            .auth
            .validate_token(auth_header, &mw_state.token_store)
            .await
        {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    let source_ip = request
        .headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or("").trim().to_string());

    let mtls_identity = request.extensions().get::<TlsIdentity>().cloned();

    // 从请求头提取角色和安全级别
    let admin_role = request
        .headers()
        .get("X-Admin-Role")
        .and_then(|v| v.to_str().ok())
        .and_then(AdminRole::from_str);

    let security_level = request
        .headers()
        .get("X-Security-Level")
        .and_then(|v| v.to_str().ok())
        .and_then(SecurityLevel::from_str)
        .unwrap_or(SecurityLevel::Public);

    if mw_state.require_mtls && mtls_identity.is_none() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // mTLS 连接优先使用证书指纹作为 subject；否则退回到默认系统主体。
    let subject = mtls_identity
        .as_ref()
        .map(|id| id.subject.clone())
        .unwrap_or_else(|| "system".into());

    let ctx = AuthContext {
        subject,
        roles: vec!["admin".into()],
        admin_role,
        security_level,
        subject_categories: Vec::new(),
        source_ip,
        action: action.clone(),
        resource: path.clone(),
        request_time: chrono::Utc::now(),
    };

    if !mw_state.policy.evaluate(&ctx).unwrap_or(false) {
        return Err(StatusCode::FORBIDDEN);
    }

    // TOTP 双因子验证（跳过健康检查和 KMIP 路径）
    let needs_totp = !SKIP_TOTP_PREFIXES.iter().any(|p| path.starts_with(p));
    if needs_totp {
        let session_id = request
            .headers()
            .get("X-Session-Id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        match session_id {
            Some(ref sid) => {
                let session = mw_state
                    .session_manager
                    .validate_session(sid)
                    .ok_or(StatusCode::UNAUTHORIZED)?;
                if !session.totp_verified {
                    return Err(StatusCode::UNAUTHORIZED);
                } else {
                    // 刷新会话时间
                    mw_state.session_manager.mark_totp_verified(sid);
                }
            }
            None => {
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
    }

    request.extensions_mut().insert(ctx);
    Ok(next.run(request).await)
}

pub async fn request_tracking_middleware(mut request: Request, next: Next) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    request.extensions_mut().insert(request_id.clone());

    let mut response = next.run(request).await;
    response.headers_mut().insert(
        HeaderName::from_static("x-request-id"),
        HeaderValue::try_from(&request_id).unwrap(),
    );
    response
}
