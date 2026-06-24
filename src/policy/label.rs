use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;

/// 安全级别（从高到低）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum SecurityLevel {
    /// 绝密 — 最高级别
    TopSecret = 5,
    /// 机密
    Classified = 4,
    /// 秘密
    Secret = 3,
    /// 内部
    Internal = 2,
    /// 公开
    Public = 1,
}

impl SecurityLevel {
    /// 从字符串解析安全级别
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "topsecret" | "绝密" => Some(SecurityLevel::TopSecret),
            "classified" | "机密" => Some(SecurityLevel::Classified),
            "secret" | "秘密" => Some(SecurityLevel::Secret),
            "internal" | "内部" => Some(SecurityLevel::Internal),
            "public" | "公开" => Some(SecurityLevel::Public),
            _ => None,
        }
    }
}

impl PartialOrd for SecurityLevel {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SecurityLevel {
    fn cmp(&self, other: &Self) -> Ordering {
        (*self as u32).cmp(&(*other as u32))
    }
}

impl fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityLevel::TopSecret => write!(f, "TopSecret"),
            SecurityLevel::Classified => write!(f, "Classified"),
            SecurityLevel::Secret => write!(f, "Secret"),
            SecurityLevel::Internal => write!(f, "Internal"),
            SecurityLevel::Public => write!(f, "Public"),
        }
    }
}

/// 安全标记 —— 附加在主体（用户）和客体（资源）上的安全属性
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityLabel {
    pub level: SecurityLevel,
    pub categories: Vec<String>,
    pub compartments: Vec<String>,
}

impl SecurityLabel {
    pub fn new(level: SecurityLevel) -> Self {
        Self {
            level,
            categories: Vec::new(),
            compartments: Vec::new(),
        }
    }

    /// 判断主体是否可以读取具有此标记的客体
    /// 规则：主体级别 ≥ 客体级别
    pub fn can_read(&self, subject_level: SecurityLevel) -> bool {
        subject_level >= self.level
    }

    /// 判断主体是否可以写入具有此标记的客体
    /// 规则：主体级别 == 客体级别
    pub fn can_write(&self, subject_level: SecurityLevel) -> bool {
        subject_level == self.level
    }

    /// 判断主体是否具有此标记的分类访问权限
    pub fn can_access_category(&self, subject_categories: &[String]) -> bool {
        self.categories.is_empty()
            || self
                .categories
                .iter()
                .all(|c| subject_categories.contains(c))
    }
}

impl Default for SecurityLabel {
    fn default() -> Self {
        Self {
            level: SecurityLevel::Public,
            categories: Vec::new(),
            compartments: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_level_ordering() {
        assert!(SecurityLevel::TopSecret > SecurityLevel::Classified);
        assert!(SecurityLevel::Classified > SecurityLevel::Secret);
        assert!(SecurityLevel::Secret > SecurityLevel::Internal);
        assert!(SecurityLevel::Internal > SecurityLevel::Public);
    }

    #[test]
    fn test_mac_read_rule() {
        let label = SecurityLabel::new(SecurityLevel::Secret);
        assert!(label.can_read(SecurityLevel::TopSecret));
        assert!(label.can_read(SecurityLevel::Secret));
        assert!(!label.can_read(SecurityLevel::Internal));
    }

    #[test]
    fn test_mac_write_rule() {
        let label = SecurityLabel::new(SecurityLevel::Secret);
        assert!(label.can_write(SecurityLevel::Secret));
        assert!(!label.can_write(SecurityLevel::TopSecret));
        assert!(!label.can_write(SecurityLevel::Internal));
    }

    #[test]
    fn test_level_parsing() {
        assert_eq!(
            SecurityLevel::from_str("绝密"),
            Some(SecurityLevel::TopSecret)
        );
        assert_eq!(
            SecurityLevel::from_str("public"),
            Some(SecurityLevel::Public)
        );
        assert_eq!(SecurityLevel::from_str("invalid"), None);
    }
}
