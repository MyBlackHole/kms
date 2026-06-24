use super::codec::{build_authentication_block, extract_authentication};
use super::types::*;
use crate::config::SecurityLevel;

/// 安全标记等级（MAC 比较用）
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLabel {
    /// 公开（最低）
    Public,
    /// 内部
    Internal,
    /// 秘密
    Secret,
    /// 机密
    Confidential,
    /// 绝密
    TopSecret,
}

impl SecurityLabel {
    pub fn parse_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "public" => SecurityLabel::Public,
            "internal" => SecurityLabel::Internal,
            "secret" => SecurityLabel::Secret,
            "confidential" => SecurityLabel::Confidential,
            "topsecret" => SecurityLabel::TopSecret,
            _ => SecurityLabel::Internal, // 默认内部
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            SecurityLabel::Public => "Public",
            SecurityLabel::Internal => "Internal",
            SecurityLabel::Secret => "Secret",
            SecurityLabel::Confidential => "Confidential",
            SecurityLabel::TopSecret => "TopSecret",
        }
    }
}

/// 认证上下文（包含身份和安全标记）
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub username: String,
    pub authenticated: bool,
    pub security_label: SecurityLabel,
    pub session_id: Option<String>,
}

impl AuthContext {
    pub fn anonymous() -> Self {
        Self {
            username: "anonymous".into(),
            authenticated: false,
            security_label: SecurityLabel::Public,
            session_id: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Identity {
    pub username: String,
    pub authenticated: bool,
}

pub struct AuthBridge;

impl AuthBridge {
    /// 从 KMIP 请求中提取身份信息
    pub fn extract_identity(msg: &KmipNode) -> Identity {
        let auth_nodes = match extract_authentication(msg) {
            Some(nodes) => nodes,
            None => {
                return Identity {
                    username: "anonymous".into(),
                    authenticated: false,
                }
            }
        };

        for node in auth_nodes {
            if node.tag != KmipTag::Credential {
                continue;
            }
            let ct = match node.child(KmipTag::CredentialType) {
                Some(c) => c,
                None => continue,
            };
            let ct_name = match ct.enumeration_value() {
                Some(s) => s,
                None => continue,
            };
            let credential_type = match CredentialType::from_name(ct_name) {
                Some(t) => t,
                None => continue,
            };

            match credential_type {
                CredentialType::UsernameAndPassword => {
                    let cv = match node.child(KmipTag::CredentialValue) {
                        Some(c) => c,
                        None => continue,
                    };
                    let username = match cv.child(KmipTag::Username) {
                        Some(u) => u.text_value().unwrap_or("unknown"),
                        None => continue,
                    };
                    return Identity {
                        username: username.to_string(),
                        authenticated: true,
                    };
                }
                _ => continue,
            }
        }

        Identity {
            username: "anonymous".into(),
            authenticated: false,
        }
    }

    /// 从 KMIP 请求中提取完整的 AuthContext（含安全标记）
    ///
    /// Level4 模式下，必须验证会话存在且具有有效认证。
    /// CredentialValue 中 JSON 格式携带 session_id 和 username。
    pub fn authenticate(
        state: &crate::api::routes::AppState,
        request: &KmipNode,
        security_level: SecurityLevel,
    ) -> Result<AuthContext, KmipNode> {
        let identity = Self::extract_identity(request);

        // Level3 模式下不强制认证
        if security_level == SecurityLevel::Level3 {
            return Ok(AuthContext {
                username: identity.username,
                authenticated: identity.authenticated,
                security_label: SecurityLabel::Internal,
                session_id: None,
            });
        }

        // Level模式：必须通过 Credential 验证
        if !identity.authenticated {
            return Err(build_auth_error(
                "AUTH_FAILED",
                "Authentication required in Level4 mode",
            ));
        }

        // 尝试从 CredentialValue 的 JSON 中提取 session_id
        let auth_nodes = match extract_authentication(request) {
            Some(nodes) => nodes,
            None => {
                return Err(build_auth_error(
                    "AUTH_FAILED",
                    "Missing authentication block",
                ));
            }
        };

        let mut session_id: Option<String> = None;
        let mut username: Option<String> = None;

        for node in auth_nodes {
            if node.tag != KmipTag::Credential {
                continue;
            }
            let cv = match node.child(KmipTag::CredentialValue) {
                Some(c) => c,
                None => continue,
            };
            // Check for JSON credential (KMIPToken style with session_id)
            if let Some(json_str) = cv.text_value() {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(json_str) {
                    session_id = parsed
                        .get("session_id")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    username = parsed
                        .get("username")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                }
            }
            // Also check structured credential
            if username.is_none() {
                if let Some(u) = cv.child(KmipTag::Username) {
                    username = u.text_value().map(String::from);
                }
            }
        }

        let username = username.unwrap_or_else(|| identity.username.clone());
        let sid = session_id.clone().unwrap_or_default();

        // 验证会话
        if sid.is_empty() {
            return Err(build_auth_error(
                "AUTH_FAILED",
                "Missing session_id in Level4 mode",
            ));
        }

        let session = match state.session_manager.validate_session(&sid) {
            Some(s) => s,
            None => {
                return Err(build_auth_error(
                    "AUTH_FAILED",
                    "Invalid or expired session",
                ));
            }
        };

        // 检查 TOTP 已验证
        if !session.totp_verified {
            return Err(build_auth_error("AUTH_FAILED", "TOTP not verified"));
        }

        Ok(AuthContext {
            username,
            authenticated: true,
            security_label: SecurityLabel::Internal, // 默认内部标记，可根据用户角色细化
            session_id,
        })
    }

    /// 根据用户角色获取安全标记
    pub fn get_label_for_role(role: Option<&str>) -> SecurityLabel {
        match role {
            Some("SystemAdmin") | Some("SecurityAdmin") => SecurityLabel::Confidential,
            Some("AuditAdmin") => SecurityLabel::Secret,
            Some("Operator") => SecurityLabel::Internal,
            _ => SecurityLabel::Internal,
        }
    }

    pub fn build_auth_node(username: &str, password: Option<&str>) -> KmipNode {
        build_authentication_block(CredentialType::UsernameAndPassword, username, password)
    }
}

fn build_auth_error(reason: &str, message: &str) -> KmipNode {
    use super::codec::build_response_message;
    build_response_message(
        ResultStatus::OperationFailed,
        vec![
            KmipNode::enumeration(KmipTag::ResultReason, reason),
            KmipNode::text(KmipTag::ResultMessage, message),
        ],
    )
}
