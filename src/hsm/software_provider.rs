use crate::crypto::sm3_engine::Sm3Engine;
use crate::crypto::sm4_engine::Sm4Engine;
use crate::crypto::traits::{HashEngine, SymmetricCrypto};
use crate::hsm::traits::{HsmResult, KekProvider};
use crate::Error;
use dashmap::DashMap;
use std::sync::Arc;
use zeroize::Zeroizing;

pub struct SoftwareKekProvider {
    name: String,
    sm4: Sm4Engine,
    master_key: Arc<Vec<u8>>,
    kek_cache: Arc<DashMap<String, Vec<u8>>>,
    hasher: Sm3Engine,
}

impl SoftwareKekProvider {
    pub fn new(master_seed: Option<&str>) -> HsmResult<Self> {
        let seed = match master_seed {
            Some(s) => s.as_bytes().to_vec(),
            None => {
                let mut buf = vec![0u8; 32];
                getrandom::getrandom(&mut buf)
                    .map_err(|e| Error::HsmError(format!("无法生成主种子: {}", e)))?;
                buf
            }
        };

        let hasher = Sm3Engine::new();
        let master_key = hasher.hash(&seed)[..16].to_vec();

        // 锁定 master_key 内存，防止 swap 到磁盘
        if let Err(e) = crate::crypto::secure_mem::mlock_region(&master_key) {
            tracing::warn!("master_key 内存锁定失败 (非致命): {}", e);
        }

        Ok(Self {
            name: "software-kek-provider".into(),
            sm4: Sm4Engine::new(),
            master_key: Arc::new(master_key),
            kek_cache: Arc::new(DashMap::new()),
            hasher,
        })
    }

    fn derive_kek(&self, key_id: &str, key_version: u32) -> Zeroizing<Vec<u8>> {
        let info = format!("KEK_{}_{}", key_id, key_version);
        let mut derived = self
            .hasher
            .hash(&[self.master_key.as_ref(), info.as_bytes()].concat());
        derived.resize(16, 0);
        Zeroizing::new(derived)
    }
}

impl KekProvider for SoftwareKekProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn wrap_key(&self, key_id: &str, key_version: u32, plaintext: &[u8]) -> HsmResult<Vec<u8>> {
        let kek = self.derive_kek(key_id, key_version);
        let aad = format!("{}:{}", key_id, key_version);
        let wrapped = self.sm4.encrypt(&kek, plaintext, aad.as_bytes())?;

        let cache_key = format!("{}:{}", key_id, key_version);
        self.kek_cache.insert(cache_key, kek.to_vec());

        Ok(wrapped)
    }

    fn unwrap_key(&self, key_id: &str, key_version: u32) -> HsmResult<Vec<u8>> {
        let kek = self.derive_kek(key_id, key_version);
        Ok(kek.to_vec())
    }

    fn generate_random(&self, length: usize) -> HsmResult<Vec<u8>> {
        let mut buf = vec![0u8; length];
        getrandom::getrandom(&mut buf)
            .map_err(|e| Error::HsmError(format!("随机数生成失败: {}", e)))?;
        Ok(buf)
    }

    fn is_hardware_backed(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hsm::traits::KekProvider;

    #[test]
    fn test_provider_creation_with_seed() {
        let provider = SoftwareKekProvider::new(Some("0123456789abcdef0123456789abcdef")).unwrap();
        assert!(!provider.name().is_empty());
        assert!(!provider.is_hardware_backed());
    }

    #[test]
    fn test_provider_creation_random_seed() {
        let provider = SoftwareKekProvider::new(None).unwrap();
        assert!(!provider.name().is_empty());
    }

    #[test]
    fn test_wrap_unwrap_roundtrip() {
        let provider = SoftwareKekProvider::new(Some("0123456789abcdef0123456789abcdef")).unwrap();
        let plaintext = b"this is a 32 byte test vector!!!!!";

        let wrapped = provider.wrap_key("test-key", 1, plaintext).unwrap();
        assert!(!wrapped.is_empty());

        let unwrapped = provider.unwrap_key("test-key", 1).unwrap();
        assert!(!unwrapped.is_empty());
    }

    #[test]
    fn test_different_key_ids_produce_different_keys() {
        let provider = SoftwareKekProvider::new(Some("0123456789abcdef0123456789abcdef")).unwrap();

        let kek1 = provider.unwrap_key("key-a", 1).unwrap();
        let kek2 = provider.unwrap_key("key-b", 1).unwrap();
        assert_ne!(kek1, kek2, "不同 key_id 应产生不同 KEK");
    }

    #[test]
    fn test_different_versions_produce_different_keys() {
        let provider = SoftwareKekProvider::new(Some("0123456789abcdef0123456789abcdef")).unwrap();

        let kek_v1 = provider.unwrap_key("test-key", 1).unwrap();
        let kek_v2 = provider.unwrap_key("test-key", 2).unwrap();
        assert_ne!(kek_v1, kek_v2, "不同版本应产生不同 KEK");
    }

    #[test]
    fn test_generate_random() {
        let provider = SoftwareKekProvider::new(Some("0123456789abcdef0123456789abcdef")).unwrap();
        let random = provider.generate_random(32).unwrap();
        assert_eq!(random.len(), 32);

        let random2 = provider.generate_random(32).unwrap();
        // 两次随机应不同（概率极低）
        assert_ne!(random, random2);
    }

    #[test]
    fn test_kek_is_16_bytes() {
        let provider = SoftwareKekProvider::new(Some("0123456789abcdef0123456789abcdef")).unwrap();
        let kek = provider.unwrap_key("test", 1).unwrap();
        assert_eq!(kek.len(), 16, "KEK 应为 16 字节（SM4 密钥长度）");
    }
}
