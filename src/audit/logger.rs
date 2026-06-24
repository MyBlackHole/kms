use crate::config::SecurityLevel;
use crate::crypto::sm2_engine::Sm2Engine;
use crate::crypto::sm3_engine::Sm3Engine;
use crate::crypto::traits::{HashEngine, SignEngine};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: String,
    pub timestamp: i64,
    pub event_type: String,
    pub subject: String,
    pub action: String,
    pub resource: String,
    pub request_id: Option<String>,
    pub source_ip: Option<String>,
    pub result: String,
    pub detail: Option<String>,
    pub previous_hash: Option<String>,
    pub hash: Option<String>,
    pub signature: Option<String>,
}

impl AuditEvent {
    pub fn new(
        event_type: &str,
        subject: &str,
        action: &str,
        resource: &str,
        result: &str,
    ) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now().timestamp_nanos_opt().unwrap_or(0),
            event_type: event_type.to_string(),
            subject: subject.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            request_id: None,
            source_ip: None,
            result: result.to_string(),
            detail: None,
            previous_hash: None,
            hash: None,
            signature: None,
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let canonical = [
            self.event_id.clone(),
            self.timestamp.to_string(),
            self.event_type.clone(),
            self.subject.clone(),
            self.action.clone(),
            self.resource.clone(),
            self.request_id.clone().unwrap_or_default(),
            self.source_ip.clone().unwrap_or_default(),
            self.result.clone(),
            self.detail.clone().unwrap_or_default(),
            self.previous_hash.clone().unwrap_or_default(),
        ]
        .join("|");
        canonical.into_bytes()
    }
}

pub struct AuditLogger {
    hasher: Sm3Engine,
    signer: Option<Sm2Engine>,
    signing_key: Option<Vec<u8>>,
    store: Arc<Mutex<Box<dyn AuditStore>>>,
    last_hash: Arc<Mutex<Option<String>>>,
    enable_chain: bool,
    enable_signing: bool,
    security_level: SecurityLevel,
    disabled: AtomicBool,
}

#[async_trait::async_trait]
pub trait AuditStore: Send + Sync {
    async fn append(&self, event: &AuditEvent) -> crate::Result<()>;
    async fn query(&self, start_time: i64, end_time: i64) -> crate::Result<Vec<AuditEvent>>;
    async fn get_latest(&self) -> crate::Result<Option<AuditEvent>>;
    async fn verify_chain(&self) -> crate::Result<bool>;
}

impl AuditLogger {
    pub fn new(
        store: Box<dyn AuditStore>,
        sm2_key: Option<Vec<u8>>,
        enable_chain: bool,
        enable_signing: bool,
        security_level: SecurityLevel,
    ) -> Self {
        // Level4 下审计不可关闭
        let actual_enable_signing = if security_level == SecurityLevel::Level4 {
            true // 强制启用签名
        } else {
            enable_signing
        };
        Self {
            hasher: Sm3Engine::new(),
            signer: if actual_enable_signing {
                Some(Sm2Engine::new())
            } else {
                None
            },
            signing_key: sm2_key,
            store: Arc::new(Mutex::new(store)),
            last_hash: Arc::new(Mutex::new(None)),
            enable_chain: enable_chain || security_level == SecurityLevel::Level4,
            enable_signing: actual_enable_signing,
            security_level,
            disabled: AtomicBool::new(false),
        }
    }

    /// 检查审计是否可用（Level4 下审计不可禁用）
    pub fn is_disabled(&self) -> bool {
        if self.security_level == SecurityLevel::Level4 {
            false // Level4 审计不可关闭
        } else {
            self.disabled.load(Ordering::Relaxed)
        }
    }

    /// 设置审计禁用状态（Level4 下此操作无效并产生告警事件）
    pub fn set_disabled(&self, val: bool) {
        if self.security_level == SecurityLevel::Level4 && val {
            tracing::warn!("Attempt to disable audit in Level4 mode — operation ignored");
            // 尝试关闭审计本身需要记录审计事件（但这里无法异步写审计日志）
            // 通过 tracing 告警
        } else {
            self.disabled.store(val, Ordering::Relaxed);
        }
    }

    pub async fn log(&self, event: &mut AuditEvent) -> crate::Result<()> {
        if self.is_disabled() {
            return Err(crate::Error::Internal("Audit is disabled".into()));
        }

        if self.enable_chain {
            let mut last_hash = self.last_hash.lock().await;
            event.previous_hash = last_hash.clone();

            let canonical = event.canonical_bytes();
            let hash = self.hasher.hash(&canonical);
            let hash_hex = hex::encode(&hash);
            event.hash = Some(hash_hex.clone());

            if self.enable_signing {
                if let (Some(signer), Some(ref key)) = (&self.signer, &self.signing_key) {
                    let sig = signer.sign(key, &canonical)?;
                    event.signature = Some(hex::encode(&sig));
                }
            }

            *last_hash = Some(hash_hex);
        }

        let store = self.store.lock().await;
        store.append(event).await
    }

    pub async fn verify_chain(&self) -> crate::Result<bool> {
        let store = self.store.lock().await;
        store.verify_chain().await
    }

    pub async fn query(&self, start_time: i64, end_time: i64) -> crate::Result<Vec<AuditEvent>> {
        let store = self.store.lock().await;
        store.query(start_time, end_time).await
    }
}
