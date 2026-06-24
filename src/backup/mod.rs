use crate::crypto::HashEngine;
use crate::key;
use crate::key::store::KeyStore;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupHeader {
    pub version: u32,
    pub created_at: String,
    pub key_count: u32,
    pub checksum: String,
}

pub async fn export_keys(pool: &sqlx::SqlitePool, output_path: &Path) -> crate::Result<()> {
    let key_store = key::store::KeyStoreSqlite::new(pool.clone());
    let keys: Vec<key::types::Key> = key_store.list_keys().await?;

    let json = serde_json::to_string_pretty(&keys)?;
    std::fs::write(output_path, &json)?;
    Ok(())
}

pub async fn import_keys(pool: &sqlx::SqlitePool, input_path: &Path) -> crate::Result<u32> {
    let json = std::fs::read_to_string(input_path)?;
    let keys: Vec<key::types::Key> = serde_json::from_str(&json)?;

    let key_store = key::store::KeyStoreSqlite::new(pool.clone());
    let mut count = 0u32;
    for key in &keys {
        key_store.create_key(key).await?;
        count += 1;
    }
    Ok(count)
}

/// 导出密钥到 JSON 字符串（用于 API 调用）
pub async fn export_keys_to_string(pool: &sqlx::SqlitePool) -> crate::Result<String> {
    let key_store = key::store::KeyStoreSqlite::new(pool.clone());
    let keys: Vec<key::types::Key> = key_store.list_keys().await?;
    let json = serde_json::to_string_pretty(&keys)?;
    Ok(json)
}

/// 从 JSON 字符串导入密钥（用于 API 调用）
pub async fn import_keys_from_string(
    pool: &sqlx::SqlitePool,
    json_data: &str,
) -> crate::Result<u32> {
    let keys: Vec<key::types::Key> = serde_json::from_str(json_data)?;
    let key_store = key::store::KeyStoreSqlite::new(pool.clone());
    let mut count = 0u32;
    for key in &keys {
        key_store.create_key(key).await?;
        count += 1;
    }
    Ok(count)
}

pub async fn export_audit_logs(pool: &sqlx::SqlitePool, output_path: &Path) -> crate::Result<()> {
    let rows: Vec<String> = sqlx::query_scalar("SELECT event_data FROM audit_events ORDER BY id")
        .fetch_all(pool)
        .await?;

    let content = rows.join("\n");
    std::fs::write(output_path, &content)?;
    Ok(())
}

/// 导出 master seed（密钥种子），用于灾难恢复备份
///
/// 种子以明文形式保存，调用者需自行确保输出路径安全。
pub async fn export_master_seed(seed_path: &Path, output_path: &Path) -> crate::Result<()> {
    let seed_bytes = std::fs::read(seed_path).map_err(crate::Error::IoError)?;
    let checksum = hex::encode(crate::crypto::sm3_engine::Sm3Engine::new().hash(&seed_bytes));
    let header = BackupHeader {
        version: 2,
        created_at: chrono::Utc::now().to_rfc3339(),
        key_count: 1,
        checksum,
    };
    let mut export = serde_json::to_string(&header)?.into_bytes();
    export.push(b'\n');
    export.extend_from_slice(&seed_bytes);
    std::fs::write(output_path, &export)?;
    tracing::info!(
        "Master seed 已导出至: {} (SM3: {})",
        output_path.display(),
        &header.checksum[..16]
    );
    Ok(())
}

/// 导入 master seed，从备份恢复
pub fn import_master_seed(input_path: &Path, output_path: &Path) -> crate::Result<()> {
    let data = std::fs::read(input_path).map_err(crate::Error::IoError)?;

    // 找到第一个换行符，之前是 JSON header，之后是 raw seed
    let nl_pos = data
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(|| crate::Error::Internal("备份文件格式无效: 未找到头部".into()))?;

    let header_str = std::str::from_utf8(&data[..nl_pos])
        .map_err(|_| crate::Error::Internal("备份文件编码无效".into()))?;
    let _header: BackupHeader = serde_json::from_str(header_str)
        .map_err(|_| crate::Error::Internal("备份文件头部解析失败".into()))?;

    let seed_bytes = &data[nl_pos + 1..];

    let checksum = hex::encode(crate::crypto::sm3_engine::Sm3Engine::new().hash(seed_bytes));
    if _header.checksum != checksum {
        return Err(crate::Error::VerificationFailed(
            "种子校验和不匹配，文件可能已损坏".into(),
        ));
    }

    std::fs::write(output_path, seed_bytes).map_err(crate::Error::IoError)?;
    tracing::info!(
        "Master seed 已恢复至: {} (SM3: {})",
        output_path.display(),
        &checksum[..16]
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backup_header_serde() {
        let header = BackupHeader {
            version: 1,
            created_at: "2024-01-01T00:00:00Z".into(),
            key_count: 10,
            checksum: "abc123".into(),
        };
        let json = serde_json::to_string(&header).unwrap();
        let deserialized: BackupHeader = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.version, 1);
        assert_eq!(deserialized.key_count, 10);
    }
}
