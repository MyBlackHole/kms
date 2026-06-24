use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyState {
    /// 启用——可正常使用
    Enabled,
    /// 禁用——不可用于加密新数据
    Disabled,
    /// 待归档——等待安全删除
    PendingArchive,
    /// 已归档——密钥材料已安全删除
    Archived,
    /// 已销毁——记录保留，密钥材料已不可恢复
    Destroyed,
}

impl KeyState {
    pub fn can_encrypt(&self) -> bool {
        matches!(self, KeyState::Enabled)
    }

    pub fn can_decrypt(&self) -> bool {
        matches!(self, KeyState::Enabled | KeyState::Disabled)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyVersion {
    pub version_number: u32,
    pub key_material_hash: String,
    pub key_material: Option<Vec<u8>>,
    pub hsm_key_id: Option<String>,
    pub state: KeyState,
    pub created_at: DateTime<Utc>,
    pub destroyed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySpec {
    pub algorithm: KeyAlgorithm,
    pub key_length: u32,
    pub usage: Vec<KeyUsage>,
    pub extractable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyAlgorithm {
    Sm4,
    Sm2,
    Aes256,
    Rsa2048,
}

impl KeyAlgorithm {
    pub fn name(&self) -> &str {
        match self {
            KeyAlgorithm::Sm4 => "SM4",
            KeyAlgorithm::Sm2 => "SM2",
            KeyAlgorithm::Aes256 => "AES256",
            KeyAlgorithm::Rsa2048 => "RSA2048",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "SM4" => Some(KeyAlgorithm::Sm4),
            "SM2" => Some(KeyAlgorithm::Sm2),
            "AES256" | "AES" => Some(KeyAlgorithm::Aes256),
            "RSA2048" | "RSA" => Some(KeyAlgorithm::Rsa2048),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyUsage {
    EncryptDecrypt,
    SignVerify,
    KeyWrap,
    DeriveKey,
}

/// 密钥 ACL 权限等级
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyPermission {
    /// 使用权限：可加密/解密/签名
    Use,
    /// 管理权限：可轮换/禁用/启用
    Admin,
    /// 完全控制：可销毁/修改ACL
    Full,
}

/// 密钥 ACL 条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyAclEntry {
    /// 授权主体（用户名或角色名）
    pub subject: String,
    /// 权限
    pub permission: KeyPermission,
    /// 可选：限定角色类型
    pub role: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPolicy {
    pub rotation_days: Option<u32>,
    pub expiration_days: Option<u32>,
    pub max_versions: u32,
    pub require_mfa_to_disable: bool,
    pub require_mfa_to_destroy: bool,
    pub allowed_roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Key {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub spec: KeySpec,
    pub policy: KeyPolicy,
    pub state: KeyState,
    pub versions: Vec<KeyVersion>,
    pub current_version: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub owner: Option<String>,
    pub tags: std::collections::HashMap<String, String>,
    pub acl: Vec<KeyAclEntry>,
}

impl Key {
    pub fn new(name: &str, spec: KeySpec, policy: KeyPolicy) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: None,
            spec,
            policy,
            state: KeyState::Enabled,
            versions: Vec::new(),
            current_version: 0,
            created_at: now,
            updated_at: now,
            owner: None,
            tags: std::collections::HashMap::new(),
            acl: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_new_defaults() {
        let key = Key::new(
            "test-key",
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
        );
        assert_eq!(key.name, "test-key");
        assert_eq!(key.state, KeyState::Enabled);
        assert!(key.acl.is_empty());
        assert_eq!(key.current_version, 0);
    }

    #[test]
    fn test_key_state_transitions() {
        let mut key = Key::new(
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
        );
        assert!(key.state.can_encrypt());
        assert!(key.state.can_decrypt());

        key.state = KeyState::Disabled;
        assert!(!key.state.can_encrypt(), "Disabled 不可加密");
        assert!(
            key.state.can_decrypt(),
            "Disabled 可解密（已有密文需要解密）"
        );

        key.state = KeyState::Archived;
        assert!(!key.state.can_encrypt());
        assert!(!key.state.can_decrypt());

        key.state = KeyState::Destroyed;
        assert!(!key.state.can_encrypt());
        assert!(!key.state.can_decrypt());
    }

    #[test]
    fn test_key_acl_entry_serde() {
        let entry = KeyAclEntry {
            subject: "user1".into(),
            permission: KeyPermission::Admin,
            role: Some("SystemAdmin".into()),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let d: KeyAclEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(d.subject, "user1");
        assert_eq!(d.permission, KeyPermission::Admin);
    }
}
