use crate::crypto::traits::{CryptoResult, HashEngine};
use hmac::Mac;

pub struct Sha256Engine;

impl Default for Sha256Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256Engine {
    pub fn new() -> Self {
        Self
    }
}

impl HashEngine for Sha256Engine {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        sha2::Sha256::digest(data).to_vec()
    }

    fn hash_len(&self) -> usize {
        32
    }

    fn hmac(&self, key: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key)
            .map_err(|e| crate::Error::CryptoError(format!("HMAC-SHA256 初始化失败: {}", e)))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hash_len() {
        let engine = Sha256Engine::new();
        assert_eq!(engine.hash_len(), 32);
    }

    #[test]
    fn test_sha256_hash_deterministic() {
        let engine = Sha256Engine::new();
        let data = b"hello world";
        let h1 = engine.hash(data);
        let h2 = engine.hash(data);
        assert_eq!(h1, h2, "同一输入哈希应相同");
    }

    #[test]
    fn test_sha256_hash_different_data() {
        let engine = Sha256Engine::new();
        let h1 = engine.hash(b"hello");
        let h2 = engine.hash(b"world");
        assert_ne!(h1, h2, "不同输入哈希应不同");
    }

    #[test]
    fn test_sha256_known_vector() {
        let engine = Sha256Engine::new();
        let hash = engine.hash(b"abc");
        let expected =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap();
        assert_eq!(hash, expected, "SHA-256('abc') 应与 RFC 向量一致");
    }

    #[test]
    fn test_sha256_hmac_len() {
        let engine = Sha256Engine::new();
        let hmac = engine.hmac(b"key", b"data").unwrap();
        assert_eq!(hmac.len(), 32, "HMAC-SHA256 输出应为 32 字节");
    }

    #[test]
    fn test_sha256_hmac_deterministic() {
        let engine = Sha256Engine::new();
        let h1 = engine.hmac(b"key", b"data").unwrap();
        let h2 = engine.hmac(b"key", b"data").unwrap();
        assert_eq!(h1, h2, "同一 key+data HMAC 应相同");
    }

    #[test]
    fn test_sha256_hmac_different_key() {
        let engine = Sha256Engine::new();
        let h1 = engine.hmac(b"key1", b"data").unwrap();
        let h2 = engine.hmac(b"key2", b"data").unwrap();
        assert_ne!(h1, h2, "不同 key HMAC 应不同");
    }

    #[test]
    fn test_sha256_hmac_rfc4231_case2() {
        let engine = Sha256Engine::new();
        let key = hex::decode("4a656665").unwrap(); // "Jefe"
        let data = b"what do ya want for nothing?";
        let expected =
            hex::decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
                .unwrap();
        let result = engine.hmac(&key, data).unwrap();
        assert_eq!(result, expected, "HMAC-SHA256 RFC 4231 case 2 向量应匹配");
    }
}
