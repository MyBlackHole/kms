use crate::auth::totp::TotpManager;
use crate::config::SecurityProfile;
use std::time::Duration;
use std::time::Instant;

/// 二次鉴权挑战状态
#[derive(Debug, Clone, PartialEq)]
pub enum ReauthChallenge {
    /// 需要 TOTP 二次鉴权
    TotpRequired,
    /// 需要口令重认证
    PasswordRequired,
    /// 鉴权通过
    Verified,
}

/// 二次鉴权管理器
pub struct ReauthManager {
    /// 敏感操作列表
    sensitive_operations: Vec<String>,
    /// 二次鉴权 TTL
    reauth_ttl: Duration,
    /// 安全画像
    profile: SecurityProfile,
}

impl ReauthManager {
    pub fn new(
        sensitive_operations: Vec<String>,
        reauth_ttl_seconds: u64,
        profile: SecurityProfile,
    ) -> Self {
        Self {
            sensitive_operations,
            reauth_ttl: Duration::from_secs(reauth_ttl_seconds),
            profile,
        }
    }

    /// 检查操作是否需要二次鉴权
    pub fn requires_reauth(&self, action: &str) -> bool {
        self.sensitive_operations
            .iter()
            .any(|op| action.to_uppercase().contains(op.as_str()))
    }

    /// 检查二次鉴权是否在有效期内
    pub fn is_reauth_valid(&self, verified_at: Option<Instant>) -> bool {
        match verified_at {
            Some(time) => time.elapsed() < self.reauth_ttl,
            None => false,
        }
    }

    /// 验证 TOTP 码完成二次鉴权
    pub fn verify_totp_reauth(
        &self,
        totp_code: &str,
        secret: &str,
        issuer: &str,
        username: &str,
    ) -> Result<(), ReauthError> {
        if totp_code.is_empty() {
            return Err(ReauthError::InvalidCode);
        }
        TotpManager::validate_user_code(secret, totp_code, issuer, username)
            .map_err(|_| ReauthError::InternalError)?;
        Ok(())
    }

    /// 判断二次鉴权是否在 Level4 下为必须
    pub fn reauth_required_for_level4(&self) -> bool {
        self.profile.is_production()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReauthError {
    #[error("二次鉴权码无效")]
    InvalidCode,
    #[error("二次鉴权已过期，请重新认证")]
    Expired,
    #[error("内部错误")]
    InternalError,
}

/// 敏感操作辅助函数：检查 action 是否在敏感操作列表中
pub fn is_sensitive_action(action: &str, sensitive_ops: &[String]) -> bool {
    let upper = action.to_uppercase();
    sensitive_ops.iter().any(|op| upper.contains(op.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensitive_action_detection() {
        let ops = vec!["DESTROY".into(), "DISABLE".into(), "EXPORT".into()];
        assert!(is_sensitive_action("POST:/api/v1/keys/test/destroy", &ops));
        assert!(is_sensitive_action("POST:/api/v1/keys/test/disable", &ops));
        assert!(is_sensitive_action("POST:/api/v1/keys/test/export", &ops));
        assert!(!is_sensitive_action("GET:/api/v1/keys", &ops));
        assert!(!is_sensitive_action("POST:/api/v1/keys/create", &ops));
    }

    #[test]
    fn test_reauth_required_production() {
        let mgr = ReauthManager::new(vec!["DESTROY".into()], 300, SecurityProfile::Production);
        assert!(mgr.requires_reauth("POST:/api/v1/keys/test/destroy"));
        assert!(!mgr.requires_reauth("GET:/api/v1/keys"));
        assert!(mgr.reauth_required_for_level4());
    }

    #[test]
    fn test_reauth_not_required_dev() {
        let mgr = ReauthManager::new(vec!["DESTROY".into()], 300, SecurityProfile::Dev);
        assert!(!mgr.reauth_required_for_level4());
    }

    #[test]
    fn test_reauth_ttl_expiry() {
        let mgr = ReauthManager::new(
            vec!["DESTROY".into()],
            1, // 1 second TTL
            SecurityProfile::Production,
        );
        let recent = Instant::now();
        assert!(mgr.is_reauth_valid(Some(recent)));
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(!mgr.is_reauth_valid(Some(recent)));
        assert!(!mgr.is_reauth_valid(None));
    }

    #[test]
    fn test_reauth_invalid_code() {
        let mgr = ReauthManager::new(vec!["DESTROY".into()], 300, SecurityProfile::Production);
        let result = mgr.verify_totp_reauth("", "secret", "KMS", "admin");
        assert!(result.is_err());
        match result {
            Err(ReauthError::InvalidCode) => {}
            _ => panic!("Expected InvalidCode error"),
        }
    }
}
