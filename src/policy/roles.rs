use serde::{Deserialize, Serialize};
use std::fmt;

/// 等保三级三权分立角色
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum AdminRole {
    /// 系统管理员 — 密钥管理、系统配置、用户管理
    SystemAdmin,
    /// 安全管理员 — 安全标记、策略配置
    SecurityAdmin,
    /// 审计管理员 — 审计日志查看（只读）
    AuditAdmin,
}

impl AdminRole {
    /// 从字符串解析角色
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "system" | "systemadmin" | "系统管理员" => Some(AdminRole::SystemAdmin),
            "security" | "securityadmin" | "安全管理员" => Some(AdminRole::SecurityAdmin),
            "audit" | "auditadmin" | "审计管理员" => Some(AdminRole::AuditAdmin),
            _ => None,
        }
    }

    /// 检查该角色是否有执行指定操作的权限
    pub fn can_perform(&self, action: &str, resource: &str) -> bool {
        match self {
            AdminRole::SystemAdmin => matches!(
                action,
                "CREATE"
                    | "READ"
                    | "UPDATE"
                    | "DELETE"
                    | "ROTATE"
                    | "ENABLE"
                    | "DISABLE"
                    | "ARCHIVE"
                    | "DESTROY"
                    | "GENERATE_DATADEK"
                    | "DECRYPT"
            ),
            AdminRole::SecurityAdmin => matches!(
                action,
                "READ" | "ATTACH_POLICY" | "DETACH_POLICY" | "SET_LABEL" | "GET_LABEL"
            ),
            AdminRole::AuditAdmin => {
                matches!(action, "READ" | "VERIFY_CHAIN") && resource.starts_with("audit:")
            }
        }
    }

    /// 返回所有角色
    pub fn all() -> Vec<AdminRole> {
        vec![
            AdminRole::SystemAdmin,
            AdminRole::SecurityAdmin,
            AdminRole::AuditAdmin,
        ]
    }
}

impl fmt::Display for AdminRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdminRole::SystemAdmin => write!(f, "SystemAdmin"),
            AdminRole::SecurityAdmin => write!(f, "SecurityAdmin"),
            AdminRole::AuditAdmin => write!(f, "AuditAdmin"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_admin_permissions() {
        let role = AdminRole::SystemAdmin;
        assert!(role.can_perform("CREATE", "key:test"));
        assert!(role.can_perform("DESTROY", "key:test"));
        assert!(role.can_perform("GENERATE_DATADEK", "key:test"));
        assert!(!role.can_perform("SET_LABEL", "key:test"));
        assert!(!role.can_perform("VERIFY_CHAIN", "audit:log"));
    }

    #[test]
    fn test_security_admin_permissions() {
        let role = AdminRole::SecurityAdmin;
        assert!(role.can_perform("SET_LABEL", "key:test"));
        assert!(role.can_perform("ATTACH_POLICY", "key:test"));
        assert!(!role.can_perform("CREATE", "key:test"));
        assert!(!role.can_perform("DESTROY", "key:test"));
    }

    #[test]
    fn test_audit_admin_permissions() {
        let role = AdminRole::AuditAdmin;
        assert!(role.can_perform("READ", "audit:log"));
        assert!(role.can_perform("VERIFY_CHAIN", "audit:chain"));
        assert!(!role.can_perform("CREATE", "key:test"));
        assert!(!role.can_perform("READ", "key:test"));
    }

    #[test]
    fn test_role_parsing() {
        assert_eq!(
            AdminRole::from_str("SystemAdmin"),
            Some(AdminRole::SystemAdmin)
        );
        assert_eq!(
            AdminRole::from_str("安全管理员"),
            Some(AdminRole::SecurityAdmin)
        );
        assert_eq!(AdminRole::from_str("unknown"), None);
    }
}
