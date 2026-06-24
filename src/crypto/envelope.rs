use crate::crypto::aes256_gcm_engine::Aes256GcmEngine;
use crate::crypto::hkdf_engine::HkdfEngine;
use crate::crypto::sm4_engine::Sm4Engine;
use crate::crypto::traits::{CryptoResult, Kdf, KekProvider, SymmetricCrypto};
use crate::key::types::KeyAlgorithm;
use crate::Error;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedDataKey {
    pub ciphertext: Vec<u8>,
    pub key_id: String,
    pub algorithm: String,
    pub key_version: u32,
}

#[derive(Debug)]
pub struct DataKey {
    pub plaintext: Zeroizing<Vec<u8>>,
    pub encrypted: EncryptedDataKey,
}

pub struct EnvelopeEncryption {
    aes256: Aes256GcmEngine,
    sm4: Sm4Engine,
    hkdf: HkdfEngine,
}

impl Default for EnvelopeEncryption {
    fn default() -> Self {
        Self::new()
    }
}

impl EnvelopeEncryption {
    pub fn new() -> Self {
        Self {
            aes256: Aes256GcmEngine::new(),
            sm4: Sm4Engine::new(),
            hkdf: HkdfEngine::new(),
        }
    }

    fn algorithm_label(algo: KeyAlgorithm) -> CryptoResult<&'static str> {
        match algo {
            KeyAlgorithm::Sm4 => Ok("SM4-GCM"),
            KeyAlgorithm::Aes256 => Ok("AES-256-GCM"),
            _ => Err(Error::CryptoError(format!(
                "不支持的数据密钥算法: {:?}",
                algo
            ))),
        }
    }

    fn engine_for(&self, algorithm: &str) -> CryptoResult<&dyn SymmetricCrypto> {
        match algorithm {
            "SM4-GCM" => Ok(&self.sm4 as &dyn SymmetricCrypto),
            "AES-256-GCM" => Ok(&self.aes256 as &dyn SymmetricCrypto),
            other => Err(Error::CryptoError(format!("不支持的算法: {}", other))),
        }
    }

    fn adapt_kek_length(&self, kek: &[u8], target_len: usize) -> CryptoResult<Zeroizing<Vec<u8>>> {
        if kek.len() >= target_len {
            return Ok(Zeroizing::new(kek[..target_len].to_vec()));
        }
        let expanded = self.hkdf.derive_key(kek, b"KEK-ADAPT", b"", target_len)?;
        Ok(Zeroizing::new(expanded))
    }

    pub fn generate_data_key(
        &self,
        kek_provider: &dyn KekProvider,
        key_id: &str,
        key_version: u32,
        algorithm: KeyAlgorithm,
    ) -> CryptoResult<DataKey> {
        let algo_label = Self::algorithm_label(algorithm)?;
        let engine = self.engine_for(algo_label)?;
        let dek_len = engine.key_len();

        let mut plaintext_dek = Zeroizing::new(vec![0u8; dek_len]);
        getrandom::getrandom(&mut plaintext_dek)
            .map_err(|e| Error::CryptoError(format!("无法生成数据密钥: {}", e)))?;

        let raw_kek = kek_provider
            .unwrap_key(key_id, key_version)
            .map_err(|e| Error::CryptoError(format!("KEK 解包失败: {}", e)))?;
        let kek = self.adapt_kek_length(&raw_kek, engine.key_len())?;

        let aad = format!("{}:{}", key_id, key_version);
        let encrypted = engine.encrypt(&kek, &plaintext_dek, aad.as_bytes())?;

        Ok(DataKey {
            plaintext: plaintext_dek,
            encrypted: EncryptedDataKey {
                ciphertext: encrypted,
                key_id: key_id.to_string(),
                algorithm: algo_label.to_string(),
                key_version,
            },
        })
    }

    pub fn decrypt_data_key(
        &self,
        kek_provider: &dyn KekProvider,
        encrypted: &EncryptedDataKey,
    ) -> CryptoResult<Vec<u8>> {
        let engine = self.engine_for(&encrypted.algorithm)?;

        let raw_kek = kek_provider
            .unwrap_key(&encrypted.key_id, encrypted.key_version)
            .map_err(|e| Error::CryptoError(format!("KEK 解包失败: {}", e)))?;
        let kek = self.adapt_kek_length(&raw_kek, engine.key_len())?;

        let aad = format!("{}:{}", encrypted.key_id, encrypted.key_version);
        let plaintext = engine.decrypt(&kek, &encrypted.ciphertext, aad.as_bytes())?;

        Ok(plaintext)
    }

    pub fn encrypt_with_dek(
        &self,
        plaintext: &[u8],
        dek: &[u8],
        aad: &[u8],
        algorithm: &str,
    ) -> CryptoResult<Vec<u8>> {
        let engine = self.engine_for(algorithm)?;
        engine.encrypt(dek, plaintext, aad)
    }

    pub fn decrypt_with_dek(
        &self,
        ciphertext: &[u8],
        dek: &[u8],
        aad: &[u8],
        algorithm: &str,
    ) -> CryptoResult<Vec<u8>> {
        let engine = self.engine_for(algorithm)?;
        engine.decrypt(dek, ciphertext, aad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hsm::software_provider::SoftwareKekProvider;

    fn test_kek() -> SoftwareKekProvider {
        SoftwareKekProvider::new(Some("0123456789abcdef0123456789abcdef")).unwrap()
    }

    #[test]
    fn test_generate_sm4_data_key_roundtrip() {
        let envelope = EnvelopeEncryption::new();
        let kek = test_kek();

        let dk = envelope
            .generate_data_key(&kek, "test-key", 1, KeyAlgorithm::Sm4)
            .expect("生成 SM4 DEK 失败");
        assert_eq!(dk.plaintext.len(), 16, "SM4 DEK 应为 16 字节");
        assert_eq!(dk.encrypted.algorithm, "SM4-GCM");

        let pt = b"Hello KMS!";
        let ct = envelope
            .encrypt_with_dek(pt, &dk.plaintext, b"test-aad", "SM4-GCM")
            .expect("加密失败");
        assert_ne!(ct, pt);

        let dec = envelope
            .decrypt_with_dek(&ct, &dk.plaintext, b"test-aad", "SM4-GCM")
            .expect("解密失败");
        assert_eq!(dec, pt);
    }

    #[test]
    fn test_generate_aes256_data_key_roundtrip() {
        let envelope = EnvelopeEncryption::new();
        let kek = test_kek();

        let dk = envelope
            .generate_data_key(&kek, "test-key", 1, KeyAlgorithm::Aes256)
            .expect("生成 AES-256 DEK 失败");
        assert_eq!(dk.plaintext.len(), 32, "AES-256 DEK 应为 32 字节");
        assert_eq!(dk.encrypted.algorithm, "AES-256-GCM");

        let pt = b"Hello AES-256 KMS!";
        let ct = envelope
            .encrypt_with_dek(pt, &dk.plaintext, b"test-aad", "AES-256-GCM")
            .expect("加密失败");
        assert_ne!(ct, pt);

        let dec = envelope
            .decrypt_with_dek(&ct, &dk.plaintext, b"test-aad", "AES-256-GCM")
            .expect("解密失败");
        assert_eq!(dec, pt);
    }

    #[test]
    fn test_unwrap_sm4_data_key_roundtrip() {
        let envelope = EnvelopeEncryption::new();
        let kek = test_kek();

        let dk = envelope
            .generate_data_key(&kek, "test-key", 1, KeyAlgorithm::Sm4)
            .unwrap();
        let plaintext_dek = envelope
            .decrypt_data_key(&kek, &dk.encrypted)
            .expect("解密 SM4 DEK 失败");
        assert_eq!(plaintext_dek.len(), 16);
        assert_eq!(hex::encode(&plaintext_dek), hex::encode(&*dk.plaintext));
    }

    #[test]
    fn test_unwrap_aes256_data_key_roundtrip() {
        let envelope = EnvelopeEncryption::new();
        let kek = test_kek();

        let dk = envelope
            .generate_data_key(&kek, "test-key", 1, KeyAlgorithm::Aes256)
            .unwrap();
        let plaintext_dek = envelope
            .decrypt_data_key(&kek, &dk.encrypted)
            .expect("解密 AES-256 DEK 失败");
        assert_eq!(plaintext_dek.len(), 32);
        assert_eq!(hex::encode(&plaintext_dek), hex::encode(&*dk.plaintext));
    }

    #[test]
    fn test_different_keys_produce_different_ciphertext() {
        let envelope = EnvelopeEncryption::new();
        let kek1 = SoftwareKekProvider::new(Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")).unwrap();
        let kek2 = SoftwareKekProvider::new(Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")).unwrap();

        let dk1 = envelope
            .generate_data_key(&kek1, "k", 1, KeyAlgorithm::Sm4)
            .unwrap();
        let dk2 = envelope
            .generate_data_key(&kek2, "k", 1, KeyAlgorithm::Sm4)
            .unwrap();

        let pt = b"same plaintext";
        let ct1 = envelope
            .encrypt_with_dek(pt, &dk1.plaintext, b"aad", "SM4-GCM")
            .unwrap();
        let ct2 = envelope
            .encrypt_with_dek(pt, &dk2.plaintext, b"aad", "SM4-GCM")
            .unwrap();
        assert_ne!(ct1, ct2, "不同密钥加密结果应不同");
    }

    #[test]
    fn test_aes256_wrong_algorithm_on_decrypt_fails() {
        let envelope = EnvelopeEncryption::new();
        let kek = test_kek();

        let dk = envelope
            .generate_data_key(&kek, "test-key", 1, KeyAlgorithm::Aes256)
            .unwrap();
        let pt = b"test";
        let ct = envelope
            .encrypt_with_dek(pt, &dk.plaintext, b"aad", "AES-256-GCM")
            .unwrap();

        let result = envelope.decrypt_with_dek(&ct, &dk.plaintext, b"aad", "SM4-GCM");
        assert!(result.is_err(), "错误算法应解密失败");
    }

    #[test]
    fn test_unsupported_algorithm() {
        let envelope = EnvelopeEncryption::new();
        let result = envelope.engine_for("UNKNOWN");
        assert!(result.is_err());
    }
}
