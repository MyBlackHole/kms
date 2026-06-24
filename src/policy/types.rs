use crate::policy::label::SecurityLevel;
use crate::policy::roles::AdminRole;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub field: String,
    pub operator: ConditionOperator,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionOperator {
    StringEquals,
    StringNotEquals,
    StringLike,
    DateGreaterThan,
    DateLessThan,
    IpAddress,
    NotIpAddress,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyStatement {
    pub sid: Option<String>,
    pub effect: Effect,
    pub actions: Vec<String>,
    pub resources: Vec<String>,
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDocument {
    pub id: Option<String>,
    pub version: String,
    pub statements: Vec<PolicyStatement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    pub subject: String,
    pub roles: Vec<String>,
    pub admin_role: Option<AdminRole>,
    pub security_level: SecurityLevel,
    pub subject_categories: Vec<String>,
    pub source_ip: Option<String>,
    pub action: String,
    pub resource: String,
    pub request_time: chrono::DateTime<chrono::Utc>,
}

impl AuthContext {
    /// 创建一个新的认证上下文，默认安全级别为公开
    pub fn new(subject: &str, action: &str, resource: &str) -> Self {
        Self {
            subject: subject.to_string(),
            roles: vec!["admin".into()],
            admin_role: None,
            security_level: SecurityLevel::Public,
            subject_categories: Vec::new(),
            source_ip: None,
            action: action.to_string(),
            resource: resource.to_string(),
            request_time: chrono::Utc::now(),
        }
    }
}
