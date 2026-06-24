use crate::crypto::envelope::EnvelopeEncryption;
use crate::crypto::traits::{HashEngine, KekProvider};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, TOTP};

pub struct TotpManager;

impl TotpManager {
    fn encrypt_secret(
        secret: &str,
        kek_provider: &dyn KekProvider,
        envelope: &EnvelopeEncryption,
    ) -> crate::Result<String> {
        let kek = kek_provider
            .unwrap_key("totp-system", 1)
            .map_err(|e| crate::Error::CryptoError(format!("TOTP KEK 派生失败: {}", e)))?;
        let encrypted = envelope
            .encrypt_with_dek(secret.as_bytes(), &kek, b"totp-secret", "SM4-GCM")
            .map_err(|e| crate::Error::CryptoError(format!("TOTP secret 加密失败: {}", e)))?;
        Ok(hex::encode(encrypted))
    }

    fn decrypt_secret(
        stored: &str,
        kek_provider: &dyn KekProvider,
        envelope: &EnvelopeEncryption,
    ) -> crate::Result<String> {
        let encrypted = hex::decode(stored)
            .map_err(|e| crate::Error::CryptoError(format!("TOTP secret hex 解码失败: {}", e)))?;
        let kek = kek_provider
            .unwrap_key("totp-system", 1)
            .map_err(|e| crate::Error::CryptoError(format!("TOTP KEK 派生失败: {}", e)))?;
        let plaintext = envelope
            .decrypt_with_dek(&encrypted, &kek, b"totp-secret", "SM4-GCM")
            .map_err(|e| crate::Error::CryptoError(format!("TOTP secret 解密失败: {}", e)))?;
        String::from_utf8(plaintext)
            .map_err(|e| crate::Error::CryptoError(format!("TOTP secret UTF-8 解码失败: {}", e)))
    }
}

impl TotpManager {
    pub fn generate_secret() -> String {
        let bytes: Vec<u8> = (0..20).map(|_| rand::random::<u8>()).collect();
        base32_encode(&bytes)
    }

    pub fn generate_qr_uri(secret: &str, issuer: &str, username: &str) -> crate::Result<String> {
        let totp = create_totp(secret, issuer, username)?;
        Ok(totp.get_url())
    }

    #[cfg(test)]
    pub fn validate_code(secret: &str, code: &str, issuer: &str) -> crate::Result<bool> {
        let totp = create_totp(secret, issuer, "kms")?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| crate::Error::Internal(format!("time error: {}", e)))?
            .as_secs();
        Ok(totp.check(code, timestamp))
    }

    pub fn validate_user_code(
        secret: &str,
        code: &str,
        issuer: &str,
        username: &str,
    ) -> crate::Result<bool> {
        let totp = create_totp(secret, issuer, username)?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| crate::Error::Internal(format!("time error: {}", e)))?
            .as_secs();
        Ok(totp.check(code, timestamp))
    }

    pub async fn get_or_create_user_secret(
        pool: &sqlx::SqlitePool,
        username: &str,
        kek_provider: &dyn KekProvider,
        envelope: &EnvelopeEncryption,
    ) -> crate::Result<(String, bool)> {
        if let Some(stored) = sqlx::query_scalar::<_, String>(
            "SELECT secret FROM user_totp_secrets WHERE username = ? AND enabled = 1",
        )
        .bind(username)
        .fetch_optional(pool)
        .await?
        {
            let secret = Self::decrypt_secret(&stored, kek_provider, envelope)?;
            return Ok((secret, false));
        }

        let secret = Self::generate_secret();
        let encrypted = Self::encrypt_secret(&secret, kek_provider, envelope)?;
        let result = sqlx::query(
            "INSERT OR IGNORE INTO user_totp_secrets (username, secret, enabled) VALUES (?, ?, 1)",
        )
        .bind(username)
        .bind(&encrypted)
        .execute(pool)
        .await?;

        if result.rows_affected() > 0 {
            return Ok((secret, true));
        }

        if let Some(stored) = sqlx::query_scalar::<_, String>(
            "SELECT secret FROM user_totp_secrets WHERE username = ? AND enabled = 1",
        )
        .bind(username)
        .fetch_optional(pool)
        .await?
        {
            let existing = Self::decrypt_secret(&stored, kek_provider, envelope)?;
            return Ok((existing, false));
        }

        Err(crate::Error::Internal(
            "TOTP secret provisioning failed".into(),
        ))
    }

    pub async fn get_user_secret(
        pool: &sqlx::SqlitePool,
        username: &str,
        kek_provider: &dyn KekProvider,
        envelope: &EnvelopeEncryption,
    ) -> crate::Result<Option<String>> {
        if let Some(stored) = sqlx::query_scalar::<_, String>(
            "SELECT secret FROM user_totp_secrets WHERE username = ? AND enabled = 1",
        )
        .bind(username)
        .fetch_optional(pool)
        .await?
        {
            let secret = Self::decrypt_secret(&stored, kek_provider, envelope)?;
            Ok(Some(secret))
        } else {
            Ok(None)
        }
    }
}

fn create_totp(secret_b32: &str, issuer: &str, username: &str) -> crate::Result<TOTP> {
    let secret_bytes = base32_decode(secret_b32)
        .ok_or_else(|| crate::Error::Internal("TOTP secret decode failed".into()))?;

    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some(issuer.to_string()),
        username.to_string(),
    )
    .map_err(|e| crate::Error::Internal(format!("TOTP create failed: {}", e)))
}

fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut buffer = 0u64;
    let mut bits = 0;

    for &b in bytes {
        buffer = (buffer << 8) | b as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1F) as usize;
            result.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
        result.push(ALPHABET[idx] as char);
    }
    while !result.len().is_multiple_of(8) {
        result.push('=');
    }
    result
}

fn base32_decode(input: &str) -> Option<Vec<u8>> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .filter(|c| *c != '=')
        .collect();

    let mut result = Vec::new();
    let mut buffer = 0u64;
    let mut bits = 0;

    for c in cleaned.chars() {
        let idx = match c {
            'A'..='Z' => (c as u8 - b'A') as u64,
            '2'..='7' => (c as u8 - b'2' + 26) as u64,
            _ => return None,
        };
        buffer = (buffer << 5) | idx;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(result)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TotpSecretEntry {
    pub username: String,
    pub secret: String,
    pub enabled: bool,
}

/// 生成一组恢复码（SM3 哈希存储，用于双因子无法使用时的后备认证）
impl TotpManager {
    /// 生成 N 个恢复码，返回 (明文列表, SM3 哈希列表)
    pub fn generate_recovery_codes(count: u32) -> (Vec<String>, Vec<String>) {
        let mut codes = Vec::with_capacity(count as usize);
        let mut hashes = Vec::with_capacity(count as usize);
        let hasher = crate::crypto::sm3_engine::Sm3Engine::new();
        for _ in 0..count {
            let code: String = (0..8)
                .map(|_| {
                    let idx = rand::random::<usize>() % 36;
                    if idx < 10 {
                        (b'0' + idx as u8) as char
                    } else {
                        (b'A' + (idx - 10) as u8) as char
                    }
                })
                .collect();
            let hash = hex::encode(hasher.hash(code.as_bytes()));
            codes.push(code);
            hashes.push(hash);
        }
        (codes, hashes)
    }

    /// 验证恢复码：用 SM3 哈希后与存储的哈希列表比对
    pub fn validate_recovery_code(code: &str, stored_hashes: &[String]) -> bool {
        let hasher = crate::crypto::sm3_engine::Sm3Engine::new();
        let code_hash = hex::encode(hasher.hash(code.as_bytes()));
        stored_hashes.iter().any(|h| h == &code_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base32_roundtrip() {
        let original = b"hello world";
        let encoded = base32_encode(original);
        let decoded = base32_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_generate_secret() {
        let secret = TotpManager::generate_secret();
        assert!(!secret.is_empty());
        let decoded = base32_decode(&secret);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap().len(), 20);
    }

    #[test]
    fn test_qr_uri() {
        let secret = TotpManager::generate_secret();
        let uri = TotpManager::generate_qr_uri(&secret, "KMS", "admin").unwrap();
        assert!(uri.starts_with("otpauth://"));
    }

    #[test]
    fn test_validate_user_code() {
        let secret = TotpManager::generate_secret();
        let totp = create_totp(&secret, "KMS", "admin").unwrap();
        let code = totp.generate_current().unwrap();
        assert!(TotpManager::validate_user_code(&secret, &code, "KMS", "admin").unwrap());
        assert!(!TotpManager::validate_user_code(&secret, "000000", "KMS", "admin").unwrap());
    }

    #[tokio::test]
    async fn test_totp_secret_provision_and_validation() {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:")
            .await
            .expect("无法创建内存数据库");
        crate::store::migrations::run_migrations(&pool)
            .await
            .expect("迁移失败");

        let kek_provider = crate::hsm::software_provider::SoftwareKekProvider::new(Some(
            "0123456789abcdef0123456789abcdef",
        ))
        .expect("KEK 提供程序创建失败");
        let envelope = crate::crypto::envelope::EnvelopeEncryption::new();

        let (secret, created) =
            TotpManager::get_or_create_user_secret(&pool, "admin", &kek_provider, &envelope)
                .await
                .expect("获取 TOTP secret 失败");
        assert!(created);

        let fetched = TotpManager::get_user_secret(&pool, "admin", &kek_provider, &envelope)
            .await
            .expect("查询 TOTP secret 失败");
        assert_eq!(fetched.as_deref(), Some(secret.as_str()));

        let totp = create_totp(&secret, "KMS", "admin").unwrap();
        let code = totp.generate_current().unwrap();
        assert!(TotpManager::validate_user_code(&secret, &code, "KMS", "admin").unwrap());
    }
}
