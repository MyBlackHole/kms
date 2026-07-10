use crate::policy::label::SecurityLabel;
use crate::policy::types::*;
use dashmap::DashMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct PolicyEngine {
    policies: Arc<DashMap<String, PolicyDocument>>,
    /// 资源安全标记缓存
    resource_labels: Arc<DashMap<String, SecurityLabel>>,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: Arc::new(DashMap::new()),
            resource_labels: Arc::new(DashMap::new()),
        }
    }

    pub fn attach_policy(&self, key_id: &str, policy: PolicyDocument) {
        self.policies.insert(key_id.to_string(), policy);
    }

    pub fn detach_policy(&self, key_id: &str) {
        self.policies.remove(key_id);
    }

    /// 设置资源的安全标记
    pub fn set_resource_label(&self, resource: &str, label: SecurityLabel) {
        self.resource_labels.insert(resource.to_string(), label);
    }

    /// 获取资源的安全标记
    pub fn get_resource_label(&self, resource: &str) -> Option<SecurityLabel> {
        self.resource_labels
            .get(resource)
            .map(|l| l.value().clone())
    }

    /// 检查密钥 ACL 权限
    pub fn check_key_acl(
        &self,
        key: &crate::key::types::Key,
        ctx: &AuthContext,
        required: crate::key::types::KeyPermission,
    ) -> bool {
        if key.acl.is_empty() {
            // ACL 为空则允许所有已认证的请求
            return true;
        }

        for entry in &key.acl {
            // 匹配主体
            if entry.subject != ctx.subject {
                continue;
            }
            // 匹配角色（如果指定了）
            if let Some(ref role) = entry.role {
                match &ctx.admin_role {
                    Some(admin_role) => {
                        if &admin_role.to_string() != role {
                            continue;
                        }
                    }
                    None => continue,
                }
            }
            // 检查权限等级
            let permitted = match required {
                crate::key::types::KeyPermission::Use => {
                    matches!(
                        entry.permission,
                        crate::key::types::KeyPermission::Use
                            | crate::key::types::KeyPermission::Admin
                            | crate::key::types::KeyPermission::Full
                    )
                }
                crate::key::types::KeyPermission::Admin => {
                    matches!(
                        entry.permission,
                        crate::key::types::KeyPermission::Admin
                            | crate::key::types::KeyPermission::Full
                    )
                }
                crate::key::types::KeyPermission::Full => {
                    matches!(entry.permission, crate::key::types::KeyPermission::Full)
                }
            };
            if permitted {
                return true;
            }
        }
        false
    }

    /// 完整评估：ABAC + MAC + 角色权限
    pub fn evaluate(&self, ctx: &AuthContext) -> Result<bool, String> {
        // 1. 角色权限检查（三权分立）
        if let Some(ref admin_role) = ctx.admin_role {
            let action_type = extract_action_type(&ctx.action);
            if !admin_role.can_perform(&action_type, &ctx.resource) {
                return Ok(false);
            }
        }

        // 2. MAC 强制访问控制检查
        if let Some(resource_label) = self.resource_labels.get(&ctx.resource) {
            let is_read = matches!(
                ctx.action.as_str(),
                "GET" | "READ" | "LIST" | "VERIFY_CHAIN"
            );
            let is_write = matches!(
                ctx.action.as_str(),
                "POST"
                    | "PUT"
                    | "PATCH"
                    | "DELETE"
                    | "CREATE"
                    | "UPDATE"
                    | "DESTROY"
                    | "ROTATE"
                    | "ENABLE"
                    | "DISABLE"
            );

            if is_read && !resource_label.can_read(ctx.security_level) {
                return Ok(false);
            }
            if is_write && !resource_label.can_write(ctx.security_level) {
                return Ok(false);
            }
            if !resource_label.can_access_category(&ctx.subject_categories) {
                return Ok(false);
            }
        }

        // 3. ABAC 策略评估
        let mut matched_deny = false;

        for entry in self.policies.iter() {
            let (_key_id, policy) = entry.pair();

            for statement in &policy.statements {
                if !self.match_action(&statement.actions, &ctx.action) {
                    continue;
                }
                if !self.match_resource(&statement.resources, &ctx.resource) {
                    continue;
                }
                if !self.match_conditions(&statement.conditions, ctx) {
                    continue;
                }

                match statement.effect {
                    Effect::Deny => {
                        matched_deny = true;
                    }
                    Effect::Allow => {
                        if !matched_deny {
                            return Ok(true);
                        }
                    }
                }
            }
        }

        // 如果没有策略匹配，默认拒绝（有角色/MAC时）
        if ctx.admin_role.is_some() {
            return Ok(false);
        }

        // 没有配置任何策略，默认允许（向后兼容）
        Ok(true)
    }

    fn match_action(&self, allowed_actions: &[String], action: &str) -> bool {
        allowed_actions.iter().any(|a| {
            if a == "*" {
                return true;
            }
            if a.ends_with('*') {
                let prefix = &a[..a.len() - 1];
                action.starts_with(prefix)
            } else {
                a == action
            }
        })
    }

    fn match_resource(&self, allowed_resources: &[String], resource: &str) -> bool {
        allowed_resources.iter().any(|r| {
            if r == "*" {
                return true;
            }
            if r.ends_with('*') {
                let prefix = &r[..r.len() - 1];
                resource.starts_with(prefix)
            } else {
                r == resource
            }
        })
    }

    fn match_conditions(&self, conditions: &[Condition], ctx: &AuthContext) -> bool {
        if conditions.is_empty() {
            return true;
        }
        conditions
            .iter()
            .all(|cond| self.evaluate_condition(cond, ctx))
    }

    fn evaluate_condition(&self, condition: &Condition, ctx: &AuthContext) -> bool {
        let ctx_value = match condition.field.as_str() {
            "source_ip" => ctx.source_ip.as_deref().unwrap_or(""),
            "action" => &ctx.action,
            "resource" => &ctx.resource,
            "subject" => &ctx.subject,
            &_ => return true,
        };

        let expected = condition.value.as_str().unwrap_or_default();

        match condition.operator {
            ConditionOperator::StringEquals => ctx_value == expected,
            ConditionOperator::StringNotEquals => ctx_value != expected,
            ConditionOperator::StringLike => {
                if let Some(prefix) = expected.strip_suffix('*') {
                    ctx_value.starts_with(prefix)
                } else {
                    ctx_value == expected
                }
            }
            _ => true,
        }
    }
}

/// 从 HTTP 方法字符串提取动作类型
fn extract_action_type(action: &str) -> String {
    let upper = action.to_uppercase();
    if upper.starts_with("GET") || upper.starts_with("LIST") {
        "READ".to_string()
    } else if upper.starts_with("POST") || upper.starts_with("PUT") || upper.starts_with("PATCH") {
        // 检查是否是特殊操作
        if upper.contains("ROTATE") {
            "ROTATE".to_string()
        } else if upper.contains("ENABLE") {
            "ENABLE".to_string()
        } else if upper.contains("DISABLE") {
            "DISABLE".to_string()
        } else if upper.contains("ARCHIVE") {
            "ARCHIVE".to_string()
        } else if upper.contains("DESTROY") {
            "DESTROY".to_string()
        } else if upper.contains("DATADEK") || upper.contains("DECRYPT") {
            "GENERATE_DATADEK".to_string()
        } else if upper.contains("SET_LABEL") {
            "SET_LABEL".to_string()
        } else if upper.contains("VERIFY_CHAIN") {
            "VERIFY_CHAIN".to_string()
        } else if upper.contains("ATTACH_POLICY") || upper.contains("DETACH_POLICY") {
            "ATTACH_POLICY".to_string()
        } else {
            "CREATE".to_string()
        }
    } else if upper.starts_with("DELETE") {
        "DELETE".to_string()
    } else {
        "READ".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::types::{
        Key, KeyAclEntry, KeyAlgorithm, KeyPermission, KeyPolicy, KeySpec, KeyUsage,
    };
    use crate::policy::label::SecurityLevel;

    fn test_key() -> Key {
        Key::new(
            "test",
            KeySpec {
                algorithm: KeyAlgorithm::Sm4,
                key_length: 128,
                usage: vec![KeyUsage::EncryptDecrypt],
                extractable: false,
            },
            KeyPolicy {
                rotation_days: None,
                expiration_days: None,
                max_versions: 3,
                require_mfa_to_disable: false,
                require_mfa_to_destroy: true,
                allowed_roles: vec![],
            },
        )
    }

    fn test_ctx(subject: &str) -> AuthContext {
        AuthContext {
            subject: subject.into(),
            roles: vec!["admin".into()],
            admin_role: None,
            security_level: SecurityLevel::Secret,
            subject_categories: vec![],
            source_ip: None,
            action: "encrypt".into(),
            resource: "key:test".into(),
            request_time: chrono::Utc::now(),
            session_id: None,
            second_factor_verified: true,
            mtls_authenticated: false,
            subject_label: None,
        }
    }

    #[test]
    fn test_empty_acl_allows_all() {
        let engine = PolicyEngine::new();
        let key = test_key();
        assert!(engine.check_key_acl(&key, &test_ctx("anyone"), KeyPermission::Use));
        assert!(engine.check_key_acl(&key, &test_ctx("anyone"), KeyPermission::Admin));
        assert!(engine.check_key_acl(&key, &test_ctx("anyone"), KeyPermission::Full));
    }

    #[test]
    fn test_acl_matching_subject() {
        let engine = PolicyEngine::new();
        let mut key = test_key();
        key.acl.push(KeyAclEntry {
            subject: "alice".into(),
            permission: KeyPermission::Use,
            role: None,
        });
        assert!(engine.check_key_acl(&key, &test_ctx("alice"), KeyPermission::Use));
        assert!(!engine.check_key_acl(&key, &test_ctx("bob"), KeyPermission::Use));
    }

    #[test]
    fn test_acl_permission_hierarchy() {
        let engine = PolicyEngine::new();
        let mut key = test_key();
        key.acl.push(KeyAclEntry {
            subject: "admin".into(),
            permission: KeyPermission::Admin,
            role: None,
        });
        assert!(engine.check_key_acl(&key, &test_ctx("admin"), KeyPermission::Use));
        assert!(engine.check_key_acl(&key, &test_ctx("admin"), KeyPermission::Admin));
        assert!(!engine.check_key_acl(&key, &test_ctx("admin"), KeyPermission::Full));
    }
}
