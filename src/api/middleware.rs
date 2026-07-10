use crate::api::mtls::TlsIdentity;
use crate::auth::reauth::{is_sensitive_action, ReauthManager};
use crate::auth::session::SessionManager;
use crate::auth::token::TokenStore;
use crate::config::SecurityLevel;
use crate::policy::engine::PolicyEngine;
use crate::policy::label::SecurityLabel;
use crate::policy::label::SecurityLevel as MacLevel;
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
    pub security_level: SecurityLevel,
    /// 二次鉴权管理器（仅 level4 使用）
    pub reauth_manager: Option<Arc<ReauthManager>>,
    /// 敏感操作列表
    pub sensitive_operations: Vec<String>,
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
        .and_then(MacLevel::from_str)
        .unwrap_or(MacLevel::Public);

    if mw_state.require_mtls && mtls_identity.is_none() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // mTLS 连接优先使用证书指纹作为 subject
    let subject = mtls_identity
        .as_ref()
        .map(|id| id.subject.clone())
        .unwrap_or_else(|| "system".into());

    // 会话管理
    let session_id = request
        .headers()
        .get("X-Session-Id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // 检查二次鉴权状态
    let mut second_factor_verified = false;
    let is_level4 = mw_state.security_level == SecurityLevel::Level4;

    if is_level4 && !skip_auth {
        // Level4: 检查敏感操作是否需要二次鉴权
        if is_sensitive_action(&action, &mw_state.sensitive_operations) {
            let reauth_code = request
                .headers()
                .get("X-Reauth-TOTP")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            match reauth_code {
                Some(code) if !code.is_empty() => {
                    // 实际验证 TOTP 码值有效性，非空字符串不可绕过验证
                    if let Some(ref sid) = session_id {
                        let session = mw_state.session_manager.validate_session(sid);
                        if let Some(session_info) = session {
                            if let Some(ref totp_secret) = session_info.totp_secret {
                                match crate::auth::totp::TotpManager::validate_user_code(
                                    totp_secret,
                                    &code,
                                    "KMS",
                                    &session_info.username,
                                ) {
                                    Ok(true) => {
                                        second_factor_verified = true;
                                        mw_state.session_manager.mark_second_factor(sid);
                                    }
                                    _ => return Err(StatusCode::UNAUTHORIZED),
                                }
                            } else {
                                return Err(StatusCode::UNAUTHORIZED);
                            }
                        } else {
                            return Err(StatusCode::UNAUTHORIZED);
                        }
                    } else {
                        return Err(StatusCode::UNAUTHORIZED);
                    }
                }
                _ => {
                    // 检查 session 中是否有未过期的二次鉴权
                    if let Some(ref sid) = session_id {
                        if mw_state.session_manager.check_second_factor(sid) {
                            second_factor_verified = true;
                        } else {
                            return Err(StatusCode::UNAUTHORIZED);
                        }
                    } else {
                        return Err(StatusCode::UNAUTHORIZED);
                    }
                }
            }
        } else {
            // 非敏感操作，标记二次鉴权为已通过（如果有有效 session）
            if let Some(ref sid) = session_id {
                if mw_state.session_manager.validate_session(sid).is_some() {
                    second_factor_verified = true;
                }
            }
        }
    }

    // TOTP 双因子验证
    let needs_totp = !SKIP_TOTP_PREFIXES.iter().any(|p| path.starts_with(p));
    if needs_totp && !skip_auth {
        match session_id {
            Some(ref sid) => {
                let session = mw_state
                    .session_manager
                    .validate_session(sid)
                    .ok_or(StatusCode::UNAUTHORIZED)?;
                if !session.totp_verified {
                    return Err(StatusCode::UNAUTHORIZED);
                } else {
                    mw_state.session_manager.mark_totp_verified(sid);
                }
            }
            None => {
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
    }

    // 构建完整的主体安全标记
    let subject_label = SecurityLabel::new(security_level);

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
        session_id: session_id.clone(),
        second_factor_verified,
        mtls_authenticated: mtls_identity.is_some(),
        subject_label: Some(subject_label),
    };

    if !mw_state.policy.evaluate(&ctx).unwrap_or(false) {
        return Err(StatusCode::FORBIDDEN);
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
