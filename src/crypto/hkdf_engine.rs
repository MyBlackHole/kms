use crate::crypto::traits::{CryptoResult, Kdf};
use crate::Error;

pub struct HkdfEngine;

impl Default for HkdfEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl HkdfEngine {
    pub fn new() -> Self {
        Self
    }
}

impl Kdf for HkdfEngine {
    fn derive_key(
        &self,
        seed: &[u8],
        salt: &[u8],
        info: &[u8],
        key_len: usize,
    ) -> CryptoResult<Vec<u8>> {
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), seed);
        let mut okm = vec![0u8; key_len];
        hk.expand(info, &mut okm)
            .map_err(|e| Error::CryptoError(format!("HKDF 扩展失败: {}", e)))?;
        Ok(okm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_output_length() {
        let engine = HkdfEngine::new();
        let key = engine.derive_key(b"seed", b"salt", b"info", 32).unwrap();
        assert_eq!(key.len(), 32, "HKDF 输出应为指定长度");
    }

    #[test]
    fn test_hkdf_deterministic() {
        let engine = HkdfEngine::new();
        let k1 = engine.derive_key(b"seed", b"salt", b"info", 16).unwrap();
        let k2 = engine.derive_key(b"seed", b"salt", b"info", 16).unwrap();
        assert_eq!(k1, k2, "同一 seed+salt+info 结果应相同");
    }

    #[test]
    fn test_hkdf_different_salt() {
        let engine = HkdfEngine::new();
        let k1 = engine.derive_key(b"seed", b"salt1", b"info", 16).unwrap();
        let k2 = engine.derive_key(b"seed", b"salt2", b"info", 16).unwrap();
        assert_ne!(k1, k2, "不同 salt 结果应不同");
    }

    #[test]
    fn test_hkdf_different_info() {
        let engine = HkdfEngine::new();
        let k1 = engine.derive_key(b"seed", b"salt", b"info1", 16).unwrap();
        let k2 = engine.derive_key(b"seed", b"salt", b"info2", 16).unwrap();
        assert_ne!(k1, k2, "不同 info 结果应不同");
    }

    #[test]
    fn test_hkdf_various_lengths() {
        let engine = HkdfEngine::new();
        for len in [1, 16, 32, 48, 64] {
            let key = engine.derive_key(b"seed", b"salt", b"info", len).unwrap();
            assert_eq!(key.len(), len, "HKDF 应支持输出 {} 字节", len);
        }
    }

    #[test]
    fn test_hkdf_zero_length() {
        let engine = HkdfEngine::new();
        let key = engine.derive_key(b"seed", b"salt", b"info", 0).unwrap();
        assert!(key.is_empty(), "HKDF 应支持 0 字节输出");
    }

    #[test]
    fn test_hkdf_empty_seed() {
        let engine = HkdfEngine::new();
        let key = engine.derive_key(b"", b"salt", b"info", 16).unwrap();
        assert_eq!(key.len(), 16, "空 seed 仍应输出正确长度");
    }
}
