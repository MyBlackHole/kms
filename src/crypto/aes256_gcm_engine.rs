use crate::crypto::traits::{CryptoResult, SymmetricCrypto};
use crate::Error;
use aes_gcm::aead::Nonce as AeadNonce;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key,
};

pub struct Aes256GcmEngine;

impl Default for Aes256GcmEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Aes256GcmEngine {
    pub fn new() -> Self {
        Self
    }
}

impl SymmetricCrypto for Aes256GcmEngine {
    fn key_len(&self) -> usize {
        32
    }

    fn nonce_len(&self) -> usize {
        12
    }

    fn tag_len(&self) -> usize {
        16
    }

    fn encrypt(&self, key: &[u8], plaintext: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
        if key.len() != 32 {
            return Err(Error::CryptoError(
                "AES-256-GCM 密钥长度必须为 32 字节".into(),
            ));
        }

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| Error::CryptoError(format!("无法生成随机数: {}", e)))?;
        let nonce = AeadNonce::<Aes256Gcm>::from_slice(&nonce_bytes);

        let payload = Payload {
            msg: plaintext,
            aad,
        };
        let mut encrypted = cipher
            .encrypt(nonce, payload)
            .map_err(|e| Error::CryptoError(format!("AES-256-GCM 加密失败: {}", e)))?;

        let mut result = Vec::with_capacity(12 + encrypted.len());
        result.extend_from_slice(&nonce_bytes);
        result.append(&mut encrypted);
        Ok(result)
    }

    fn decrypt(
        &self,
        key: &[u8],
        ciphertext_with_nonce: &[u8],
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        if ciphertext_with_nonce.len() < 28 {
            return Err(Error::CryptoError("AES-256-GCM 密文格式无效".into()));
        }

        let nonce = AeadNonce::<Aes256Gcm>::from_slice(&ciphertext_with_nonce[..12]);
        let encrypted = &ciphertext_with_nonce[12..];
        let payload = Payload {
            msg: encrypted,
            aad,
        };

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

        cipher
            .decrypt(nonce, payload)
            .map_err(|e| Error::CryptoError(format!("AES-256-GCM 解密失败: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_gcm_roundtrip() {
        let engine = Aes256GcmEngine::new();
        let key = hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap();
        let pt = b"Hello AES-256-GCM!";

        let ct = engine.encrypt(&key, pt, b"test-aad").unwrap();
        assert_ne!(ct, pt, "密文不应等于明文");

        let dec = engine.decrypt(&key, &ct, b"test-aad").unwrap();
        assert_eq!(dec, pt, "解密结果应与原文一致");
    }

    #[test]
    fn test_aes256_gcm_wrong_aad_fails() {
        let engine = Aes256GcmEngine::new();
        let key = hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap();
        let pt = b"secret data";

        let ct = engine.encrypt(&key, pt, b"correct-aad").unwrap();
        assert!(engine.decrypt(&key, &ct, b"wrong-aad").is_err());
    }

    #[test]
    fn test_aes256_gcm_different_keys_different_ciphertext() {
        let engine = Aes256GcmEngine::new();
        let key1 = [0u8; 32];
        let key2 = [1u8; 32];
        let pt = b"same data";

        let ct1 = engine.encrypt(&key1, pt, b"aad").unwrap();
        let ct2 = engine.encrypt(&key2, pt, b"aad").unwrap();
        assert_ne!(ct1, ct2, "不同密钥加密结果应不同");
    }

    #[test]
    fn test_aes256_gcm_wrong_key_fails() {
        let engine = Aes256GcmEngine::new();
        let key = [0u8; 32];
        let wrong_key = [1u8; 32];
        let pt = b"encrypt with one key";

        let ct = engine.encrypt(&key, pt, b"aad").unwrap();
        assert!(engine.decrypt(&wrong_key, &ct, b"aad").is_err());
    }

    #[test]
    fn test_aes256_gcm_key_len_validation() {
        let engine = Aes256GcmEngine::new();
        let short_key = [0u8; 16];
        let pt = b"test";

        let result = engine.encrypt(&short_key, pt, b"aad");
        assert!(result.is_err(), "16 字节密钥应被拒绝");
    }
}
