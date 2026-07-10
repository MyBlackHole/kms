use crate::crypto::sm2_engine::Sm2Engine;
use crate::crypto::sm3_engine::Sm3Engine;
use crate::crypto::traits::{HashEngine, SignEngine};
use chrono::Utc;
use serde::{Deserialize, Serialize};

/// 抗抵赖证据类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EvidenceType {
    /// 数据原发证据（发送方签名）
    Origin,
    /// 数据接收证据（接收方确认签名）
    Receipt,
}

impl std::fmt::Display for EvidenceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceType::Origin => write!(f, "origin"),
            EvidenceType::Receipt => write!(f, "receipt"),
        }
    }
}

/// 抗抵赖证据记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonRepudiationEvidence {
    /// 证据唯一 ID
    pub evidence_id: String,
    /// 关联的审计事件 ID
    pub audit_event_id: String,
    /// 证据类型
    pub evidence_type: EvidenceType,
    /// 主体（操作者）
    pub subject: String,
    /// 操作
    pub action: String,
    /// 资源
    pub resource: String,
    /// 操作时间戳（纳秒精度）
    pub timestamp: i64,
    /// 操作内容的 SM3 哈希
    pub content_hash: String,
    /// SM2 签名（hex 编码）
    pub signature: String,
    /// 签名者公钥（hex 编码）
    pub signer_public_key: String,
    /// NTP 时间戳（可信时间源）
    pub ntp_timestamp: Option<i64>,
    /// 证据状态
    pub status: EvidenceStatus,
}

/// 证据状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EvidenceStatus {
    /// 有效
    Valid,
    /// 已撤销
    Revoked,
    /// 过期
    Expired,
}

impl std::fmt::Display for EvidenceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceStatus::Valid => write!(f, "valid"),
            EvidenceStatus::Revoked => write!(f, "revoked"),
            EvidenceStatus::Expired => write!(f, "expired"),
        }
    }
}

/// 抗抵赖证据管理器
pub struct NonRepudiationManager {
    signer: Sm2Engine,
    hasher: Sm3Engine,
    signer_private_key: Option<Vec<u8>>,
}

impl Default for NonRepudiationManager {
    fn default() -> Self {
        Self::new()
    }
}

impl NonRepudiationManager {
    pub fn new() -> Self {
        Self {
            signer: Sm2Engine::new(),
            hasher: Sm3Engine::new(),
            signer_private_key: None,
        }
    }

    /// 设置签名私钥
    pub fn set_signing_key(&mut self, key: Vec<u8>) {
        self.signer_private_key = Some(key);
    }

    /// 生成签名密钥对
    pub fn generate_keypair(&self) -> crate::Result<(Vec<u8>, Vec<u8>)> {
        self.signer
            .generate_keypair()
            .map_err(|e| crate::Error::CryptoError(format!("生成抗抵赖密钥对失败: {}", e)))
    }

    /// 从私钥派生公钥
    fn derive_public_key(&self, private_key: &[u8]) -> crate::Result<Vec<u8>> {
        use libsm::sm2::signature::SigCtx;
        let ctx = SigCtx::new();
        let sk = ctx
            .load_seckey(private_key)
            .map_err(|_| crate::Error::CryptoError("SM2 私钥加载失败".into()))?;
        let pk = ctx
            .pk_from_sk(&sk)
            .map_err(|_| crate::Error::CryptoError("SM2 公钥推导失败".into()))?;
        let pk_bytes = ctx
            .serialize_pubkey(&pk, false)
            .map_err(|e| crate::Error::CryptoError(format!("SM2 公钥序列化失败: {:?}", e)))?;
        Ok(pk_bytes)
    }

    /// 创建数据原发证据
    pub fn create_origin_evidence(
        &self,
        audit_event_id: &str,
        subject: &str,
        action: &str,
        resource: &str,
        content: &[u8],
    ) -> crate::Result<NonRepudiationEvidence> {
        let private_key = self
            .signer_private_key
            .as_ref()
            .ok_or_else(|| crate::Error::Internal("抗抵赖签名密钥未配置".into()))?;

        let public_key = self.derive_public_key(private_key)?;
        let content_hash = hex::encode(self.hasher.hash(content));
        let timestamp = Utc::now().timestamp_nanos_opt().unwrap_or(0);

        // 签名内容：content_hash + timestamp + action + resource
        let sign_data = format!("{}|{}|{}|{}", content_hash, timestamp, action, resource);
        let signature = self
            .signer
            .sign(private_key, sign_data.as_bytes())
            .map_err(|e| crate::Error::CryptoError(format!("抗抵赖签名失败: {}", e)))?;

        Ok(NonRepudiationEvidence {
            evidence_id: uuid::Uuid::new_v4().to_string(),
            audit_event_id: audit_event_id.to_string(),
            evidence_type: EvidenceType::Origin,
            subject: subject.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            timestamp,
            content_hash,
            signature: hex::encode(&signature),
            signer_public_key: hex::encode(&public_key),
            ntp_timestamp: None,
            status: EvidenceStatus::Valid,
        })
    }

    /// 创建数据接收证据
    pub fn create_receipt_evidence(
        &self,
        audit_event_id: &str,
        subject: &str,
        action: &str,
        resource: &str,
        origin_evidence_id: &str,
        content_hash: &str,
    ) -> crate::Result<NonRepudiationEvidence> {
        let private_key = self
            .signer_private_key
            .as_ref()
            .ok_or_else(|| crate::Error::Internal("抗抵赖签名密钥未配置".into()))?;

        let public_key = self.derive_public_key(private_key)?;
        let timestamp = Utc::now().timestamp_nanos_opt().unwrap_or(0);

        // 接收证据签名：包含原发证据 ID 和内容哈希
        let sign_data = format!(
            "RECEIPT|{}|{}|{}|{}",
            origin_evidence_id, content_hash, timestamp, subject
        );
        let signature = self
            .signer
            .sign(private_key, sign_data.as_bytes())
            .map_err(|e| crate::Error::CryptoError(format!("抗抵赖接收证据签名失败: {}", e)))?;

        Ok(NonRepudiationEvidence {
            evidence_id: uuid::Uuid::new_v4().to_string(),
            audit_event_id: audit_event_id.to_string(),
            evidence_type: EvidenceType::Receipt,
            subject: subject.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            timestamp,
            content_hash: content_hash.to_string(),
            signature: hex::encode(&signature),
            signer_public_key: hex::encode(&public_key),
            ntp_timestamp: None,
            status: EvidenceStatus::Valid,
        })
    }

    /// 验证证据签名
    pub fn verify_evidence(&self, evidence: &NonRepudiationEvidence) -> crate::Result<bool> {
        let public_key_bytes = hex::decode(&evidence.signer_public_key)
            .map_err(|e| crate::Error::CryptoError(format!("公钥解码失败: {}", e)))?;
        let signature_bytes = hex::decode(&evidence.signature)
            .map_err(|e| crate::Error::CryptoError(format!("签名解码失败: {}", e)))?;

        let sign_data = match evidence.evidence_type {
            EvidenceType::Origin => {
                format!(
                    "{}|{}|{}|{}",
                    evidence.content_hash, evidence.timestamp, evidence.action, evidence.resource
                )
            }
            EvidenceType::Receipt => {
                format!(
                    "RECEIPT|{}|{}|{}|{}",
                    evidence.audit_event_id,
                    evidence.content_hash,
                    evidence.timestamp,
                    evidence.subject
                )
            }
        };

        self.signer
            .verify(&public_key_bytes, sign_data.as_bytes(), &signature_bytes)
            .map_err(|e| crate::Error::CryptoError(format!("抗抵赖验证失败: {}", e)))
    }
}

/// 抗抵赖证据的数据库存储（使用 SQLite 追加写）
pub async fn store_evidence(
    pool: &sqlx::SqlitePool,
    evidence: &NonRepudiationEvidence,
) -> crate::Result<()> {
    // 创建表（如果不存在）
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS non_repudiation_evidence (
            evidence_id TEXT PRIMARY KEY,
            audit_event_id TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            subject TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            content_hash TEXT NOT NULL,
            signature TEXT NOT NULL,
            signer_public_key TEXT NOT NULL,
            ntp_timestamp INTEGER,
            status TEXT NOT NULL DEFAULT 'valid',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )"#,
    )
    .execute(pool)
    .await
    .map_err(crate::Error::DatabaseError)?;

    sqlx::query(
        r#"INSERT INTO non_repudiation_evidence
            (evidence_id, audit_event_id, evidence_type, subject, action, resource,
             timestamp, content_hash, signature, signer_public_key, ntp_timestamp, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
    )
    .bind(&evidence.evidence_id)
    .bind(&evidence.audit_event_id)
    .bind(evidence.evidence_type.to_string())
    .bind(&evidence.subject)
    .bind(&evidence.action)
    .bind(&evidence.resource)
    .bind(evidence.timestamp)
    .bind(&evidence.content_hash)
    .bind(&evidence.signature)
    .bind(&evidence.signer_public_key)
    .bind(evidence.ntp_timestamp)
    .bind(evidence.status.to_string())
    .execute(pool)
    .await
    .map_err(crate::Error::DatabaseError)?;

    Ok(())
}

/// 查询证据
pub async fn query_evidence(
    pool: &sqlx::SqlitePool,
    audit_event_id: &str,
) -> crate::Result<Vec<NonRepudiationEvidence>> {
    #[derive(Debug, sqlx::FromRow)]
    struct EvidenceRow {
        evidence_id: String,
        audit_event_id: String,
        evidence_type: String,
        subject: String,
        action: String,
        resource: String,
        timestamp: i64,
        content_hash: String,
        signature: String,
        signer_public_key: String,
        ntp_timestamp: Option<i64>,
        status: String,
    }

    let rows = sqlx::query_as::<_, EvidenceRow>(
        r#"SELECT evidence_id, audit_event_id, evidence_type, subject, action, resource,
                  timestamp, content_hash, signature, signer_public_key, ntp_timestamp, status
           FROM non_repudiation_evidence
           WHERE audit_event_id = ?
           ORDER BY timestamp ASC"#,
    )
    .bind(audit_event_id)
    .fetch_all(pool)
    .await
    .map_err(crate::Error::DatabaseError)?;

    let evidence_list = rows
        .into_iter()
        .map(|r| NonRepudiationEvidence {
            evidence_id: r.evidence_id,
            audit_event_id: r.audit_event_id,
            evidence_type: match r.evidence_type.as_str() {
                "origin" => EvidenceType::Origin,
                "receipt" => EvidenceType::Receipt,
                _ => EvidenceType::Origin,
            },
            subject: r.subject,
            action: r.action,
            resource: r.resource,
            timestamp: r.timestamp,
            content_hash: r.content_hash,
            signature: r.signature,
            signer_public_key: r.signer_public_key,
            ntp_timestamp: r.ntp_timestamp,
            status: match r.status.as_str() {
                "valid" => EvidenceStatus::Valid,
                "revoked" => EvidenceStatus::Revoked,
                "expired" => EvidenceStatus::Expired,
                _ => EvidenceStatus::Valid,
            },
        })
        .collect();

    Ok(evidence_list)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_manager() -> NonRepudiationManager {
        let mut mgr = NonRepudiationManager::new();
        let (sk, _pk) = mgr.generate_keypair().unwrap();
        mgr.set_signing_key(sk);
        mgr
    }

    #[test]
    fn test_origin_evidence_creation() {
        let mgr = setup_manager();
        let content = b"sensitive operation data";

        let evidence = mgr
            .create_origin_evidence("audit-001", "admin", "DESTROY", "key:test-1", content)
            .unwrap();

        assert_eq!(evidence.evidence_type, EvidenceType::Origin);
        assert_eq!(evidence.subject, "admin");
        assert_eq!(evidence.action, "DESTROY");
        assert_eq!(evidence.resource, "key:test-1");
        assert_eq!(evidence.status, EvidenceStatus::Valid);
        assert!(!evidence.signature.is_empty());
        assert!(!evidence.signer_public_key.is_empty());
    }

    #[test]
    fn test_receipt_evidence_creation() {
        let mgr = setup_manager();

        let evidence = mgr
            .create_receipt_evidence(
                "audit-002",
                "receiver",
                "RECEIVE_KEY",
                "key:test-1",
                "origin-evidence-001",
                "abc123hash",
            )
            .unwrap();

        assert_eq!(evidence.evidence_type, EvidenceType::Receipt);
        assert_eq!(evidence.subject, "receiver");
    }

    #[test]
    fn test_evidence_verification() {
        let mut mgr = NonRepudiationManager::new();
        let (sk, _pk) = mgr.generate_keypair().unwrap();
        mgr.set_signing_key(sk);

        let content = b"test data";
        let evidence = mgr
            .create_origin_evidence("audit-003", "admin", "ENCRYPT", "key:test-2", content)
            .unwrap();

        // 验证签名
        assert!(mgr.verify_evidence(&evidence).unwrap());

        // 篡改证据
        let mut tampered = evidence.clone();
        tampered.content_hash = "tampered".into();
        assert!(!mgr.verify_evidence(&tampered).unwrap());
    }

    #[test]
    fn test_keypair_generation() {
        let mgr = NonRepudiationManager::new();
        let (sk, pk) = mgr.generate_keypair().unwrap();
        assert!(!sk.is_empty());
        assert!(!pk.is_empty());
        assert_ne!(sk, pk);
    }

    #[tokio::test]
    async fn test_store_and_query_evidence() {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create in-memory database");

        let mut mgr = NonRepudiationManager::new();
        let (sk, _) = mgr.generate_keypair().unwrap();
        mgr.set_signing_key(sk);

        let content = b"test evidence storage";
        let evidence = mgr
            .create_origin_evidence("audit-store-001", "admin", "SIGN", "key:test-3", content)
            .unwrap();

        store_evidence(&pool, &evidence).await.unwrap();

        let results = query_evidence(&pool, "audit-store-001").await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].evidence_id, evidence.evidence_id);
        assert_eq!(results[0].status, EvidenceStatus::Valid);
    }
}
