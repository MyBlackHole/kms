use crate::crypto::traits::{CryptoResult, SymmetricCrypto};
use crate::Error;
use libsm::sm4::cipher_mode::{CipherMode, Sm4CipherMode};

pub struct Sm4Engine;

impl Default for Sm4Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Sm4Engine {
    pub fn new() -> Self {
        Self
    }

    fn generate_nonce() -> CryptoResult<[u8; 12]> {
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| Error::CryptoError(format!("无法生成随机数: {}", e)))?;
        Ok(nonce)
    }
}

impl SymmetricCrypto for Sm4Engine {
    fn key_len(&self) -> usize {
        16
    }

    fn nonce_len(&self) -> usize {
        12
    }

    fn tag_len(&self) -> usize {
        16
    }

    fn encrypt(&self, key: &[u8], plaintext: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
        if key.len() != 16 {
            return Err(Error::CryptoError("SM4 密钥长度必须为 16 字节".into()));
        }

        let nonce = Self::generate_nonce()?;

        let cipher = Sm4CipherMode::new(key, CipherMode::Gcm)
            .map_err(|e| Error::CryptoError(format!("SM4 初始化失败: {:?}", e)))?;

        let mut iv = [0u8; 16];
        iv[..12].copy_from_slice(&nonce);
        iv[12..].copy_from_slice(&[0, 0, 0, 1]);

        let encrypted = cipher
            .encrypt(aad, plaintext, &iv)
            .map_err(|e| Error::CryptoError(format!("SM4-GCM 加密失败: {:?}", e)))?;

        let mut result = Vec::with_capacity(12 + encrypted.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&encrypted);
        Ok(result)
    }

    fn decrypt(
        &self,
        key: &[u8],
        ciphertext_with_nonce: &[u8],
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        if ciphertext_with_nonce.len() < 28 {
            return Err(Error::CryptoError("SM4-GCM 密文格式无效".into()));
        }

        let nonce = &ciphertext_with_nonce[..12];
        let encrypted = &ciphertext_with_nonce[12..];

        let cipher = Sm4CipherMode::new(key, CipherMode::Gcm)
            .map_err(|e| Error::CryptoError(format!("SM4 初始化失败: {:?}", e)))?;

        let mut iv = [0u8; 16];
        iv[..12].copy_from_slice(nonce);
        iv[12..].copy_from_slice(&[0, 0, 0, 1]);

        let plaintext = cipher
            .decrypt(aad, encrypted, &iv)
            .map_err(|e| Error::CryptoError(format!("SM4-GCM 解密失败: {:?}", e)))?;

        Ok(plaintext)
    }
}
