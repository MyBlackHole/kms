use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// 二次鉴权 TTL（5 分钟，可由 level4 配置覆盖）
const SECOND_FACTOR_TTL: Duration = Duration::from_secs(300);

/// 会话信息
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub username: String,
    pub totp_verified: bool,
    pub second_factor_verified_at: Option<Instant>,
    pub created_at: Instant,
    pub last_access: Instant,
    /// 会话标识符防劫持：客户端 IP（可选）
    pub client_ip: Option<String>,
    /// TOTP 密钥（用于二次鉴权验证）
    pub totp_secret: Option<String>,
}

impl SessionInfo {
    /// 检查二次鉴权是否在有效期内（使用 SessionManager 的 TTL）
    pub fn is_second_factor_valid_with_ttl(&self, ttl: Duration) -> bool {
        match self.second_factor_verified_at {
            Some(verified_at) => verified_at.elapsed() < ttl,
            None => false,
        }
    }

    /// 检查会话标识是否被劫持（IP 变化检测）
    pub fn check_session_hijack(&self, current_ip: Option<&str>) -> bool {
        match (&self.client_ip, current_ip) {
            (Some(expected), Some(actual)) => expected == actual,
            (None, _) => true, // 没有 IP 记录时不做劫持检测
            (_, None) => true,
        }
    }
}

/// 会话管理器
pub struct SessionManager {
    sessions: Arc<DashMap<String, SessionInfo>>,
    session_ttl: Duration,
    second_factor_ttl: Duration,
}

impl SessionManager {
    pub fn new(session_ttl_secs: u64) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            session_ttl: Duration::from_secs(session_ttl_secs),
            second_factor_ttl: SECOND_FACTOR_TTL,
        }
    }

    /// 使用可配置的二次鉴权 TTL（等保四级）
    pub fn with_second_factor_ttl(mut self, ttl_secs: u64) -> Self {
        self.second_factor_ttl = Duration::from_secs(ttl_secs);
        self
    }

    /// 获取二次鉴权 TTL
    pub fn second_factor_ttl(&self) -> Duration {
        self.second_factor_ttl
    }

    /// 设置二次鉴权 TTL
    pub fn set_second_factor_ttl(&mut self, ttl_secs: u64) {
        self.second_factor_ttl = Duration::from_secs(ttl_secs);
    }

    /// 创建新会话
    pub fn create_session(&self, session_id: String, username: String) {
        self.create_session_with_ip(session_id, username, None, None)
    }

    /// 创建新会话并记录客户端 IP 和 TOTP 密钥
    pub fn create_session_with_ip(
        &self,
        session_id: String,
        username: String,
        client_ip: Option<String>,
        totp_secret: Option<String>,
    ) {
        let now = Instant::now();
        self.sessions.insert(
            session_id,
            SessionInfo {
                username,
                totp_verified: false,
                second_factor_verified_at: None,
                created_at: now,
                last_access: now,
                client_ip,
                totp_secret,
            },
        );
    }

    /// 获取会话中存储的 TOTP 密钥
    pub fn get_totp_secret(&self, session_id: &str) -> Option<String> {
        self.sessions
            .get(session_id)
            .and_then(|entry| entry.totp_secret.clone())
    }

    /// 验证会话是否存在且未过期
    pub fn validate_session(&self, session_id: &str) -> Option<SessionInfo> {
        self.sessions.get(session_id).and_then(|entry| {
            if entry.last_access.elapsed() > self.session_ttl {
                // 会话过期
                drop(entry);
                self.sessions.remove(session_id);
                None
            } else {
                Some(entry.value().clone())
            }
        })
    }

    /// 标记会话已完成 TOTP 验证
    pub fn mark_totp_verified(&self, session_id: &str) {
        if let Some(mut entry) = self.sessions.get_mut(session_id) {
            entry.totp_verified = true;
            entry.last_access = Instant::now();
        }
    }

    /// 标记会话已完成二次鉴权（等保四级关键操作）
    pub fn mark_second_factor(&self, session_id: &str) {
        if let Some(mut entry) = self.sessions.get_mut(session_id) {
            entry.second_factor_verified_at = Some(Instant::now());
            entry.last_access = Instant::now();
        }
    }

    /// 检查会话的二次鉴权是否在有效期内
    pub fn check_second_factor(&self, session_id: &str) -> bool {
        self.sessions
            .get(session_id)
            .map(|entry| entry.is_second_factor_valid_with_ttl(self.second_factor_ttl))
            .unwrap_or(false)
    }

    /// 销毁会话
    pub fn destroy_session(&self, session_id: &str) {
        self.sessions.remove(session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_create_and_validate() {
        let manager = SessionManager::new(3600);
        manager.create_session("test-session".into(), "admin".into());

        let info = manager.validate_session("test-session");
        assert!(info.is_some());
        assert_eq!(info.unwrap().username, "admin");
    }

    #[test]
    fn test_session_totp_verification() {
        let manager = SessionManager::new(3600);
        manager.create_session("test-session".into(), "admin".into());

        let info = manager.validate_session("test-session").unwrap();
        assert!(!info.totp_verified);

        manager.mark_totp_verified("test-session");
        let info = manager.validate_session("test-session").unwrap();
        assert!(info.totp_verified);
    }

    #[test]
    fn test_session_destroy() {
        let manager = SessionManager::new(3600);
        manager.create_session("test-session".into(), "admin".into());
        manager.destroy_session("test-session");
        assert!(manager.validate_session("test-session").is_none());
    }

    #[test]
    fn test_second_factor_validation() {
        let manager = SessionManager::new(3600);
        manager.create_session("test-session".into(), "admin".into());

        // 初始状态：未验证
        assert!(!manager.check_second_factor("test-session"));

        // 标记二次鉴权后应在有效期内
        manager.mark_second_factor("test-session");
        assert!(manager.check_second_factor("test-session"));
    }

    #[test]
    fn test_session_hijack_detection() {
        let manager = SessionManager::new(3600);
        manager.create_session_with_ip(
            "test-session".into(),
            "admin".into(),
            Some("192.168.1.1".into()),
            None,
        );

        let info = manager.validate_session("test-session").unwrap();
        assert!(info.check_session_hijack(Some("192.168.1.1")));
        assert!(!info.check_session_hijack(Some("10.0.0.1")));
    }
}
