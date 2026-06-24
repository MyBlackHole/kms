pub mod tpm;

use crate::crypto::traits::HashEngine;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// 可信验证配置
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrustConfig {
    /// 预期的二进制 SM3 哈希（十六进制字符串）
    #[serde(default)]
    pub expected_binary_hash: Option<String>,
    /// 关键配置文件的预期哈希
    #[serde(default)]
    pub expected_config_hash: Option<String>,
}

/// 可信验证器
pub struct TrustVerifier;

impl TrustVerifier {
    /// 验证自身二进制文件的 SM3 哈希
    pub fn verify_binary(expected_hash: &str) -> bool {
        let binary_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("kms-server"));
        let binary_data = std::fs::read(&binary_path).unwrap_or_default();

        let hasher = crate::crypto::sm3_engine::Sm3Engine::new();
        let actual_hash = hex::encode(hasher.hash(&binary_data));

        let expected = expected_hash.trim().to_lowercase();
        let actual = actual_hash.trim().to_lowercase();

        if actual == expected {
            true
        } else {
            tracing::error!(
                "二进制哈希不匹配！预期: {}, 实际: {}",
                &expected[..16.min(expected.len())],
                &actual[..16.min(actual.len())]
            );
            false
        }
    }

    /// 验证配置文件完整性
    pub fn verify_config(config_data: &[u8], expected_hash: &str) -> bool {
        let hasher = crate::crypto::sm3_engine::Sm3Engine::new();
        let actual_hash = hex::encode(hasher.hash(config_data));
        let expected = expected_hash.trim().to_lowercase();

        if actual_hash == expected {
            true
        } else {
            tracing::error!("配置文件哈希不匹配");
            false
        }
    }

    /// 计算当前二进制哈希（用于 `hash-self` 命令）
    pub fn compute_self_hash() -> String {
        let binary_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("kms-server"));
        let binary_data = std::fs::read(&binary_path).unwrap_or_default();
        let hasher = crate::crypto::sm3_engine::Sm3Engine::new();
        hex::encode(hasher.hash(&binary_data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_self_hash() {
        let hash = TrustVerifier::compute_self_hash();
        assert_eq!(hash.len(), 64, "SM3 哈希应为 64 个十六进制字符");
    }

    #[test]
    fn test_config_verification() {
        let config_data = b"test config content";
        let hasher = crate::crypto::sm3_engine::Sm3Engine::new();
        let hash = hex::encode(hasher.hash(config_data));

        assert!(TrustVerifier::verify_config(config_data, &hash));
        assert!(!TrustVerifier::verify_config(config_data, "0000"));
    }
}
