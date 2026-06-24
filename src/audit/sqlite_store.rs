use crate::audit::logger::{AuditEvent, AuditStore};
use crate::crypto::sm3_engine::Sm3Engine;
use crate::crypto::traits::HashEngine;
use async_trait::async_trait;
use sqlx::SqlitePool;

pub struct SqliteAuditStore {
    pool: SqlitePool,
}

impl SqliteAuditStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// 验证单个事件的哈希完整性
    fn check_event_integrity(
        event: &AuditEvent,
        hasher: &Sm3Engine,
        expected_prev_hash: &Option<String>,
    ) -> crate::Result<()> {
        let bytes = event.canonical_bytes();
        let computed = hasher.hash(&bytes);
        let computed_hex = hex::encode(&computed);

        if let Some(ref event_hash) = event.hash {
            if event_hash != &computed_hex {
                return Err(crate::Error::VerificationFailed(
                    "审计事件哈希不匹配".into(),
                ));
            }
        }
        if event.previous_hash != *expected_prev_hash {
            return Err(crate::Error::VerificationFailed(
                "审计事件链断裂：前一哈希不匹配".into(),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl AuditStore for SqliteAuditStore {
    async fn append(&self, event: &AuditEvent) -> crate::Result<()> {
        let detail_json = event.detail.as_deref().unwrap_or("");
        sqlx::query(
            r#"
            INSERT INTO audit_events
                (event_id, timestamp, event_type, subject, admin_role,
                 action, resource, source_ip, request_id, result,
                 detail, previous_hash, hash, signature)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&event.event_id)
        .bind(event.timestamp)
        .bind(&event.event_type)
        .bind(&event.subject)
        .bind(Option::<String>::None)
        .bind(&event.action)
        .bind(&event.resource)
        .bind(&event.source_ip)
        .bind(&event.request_id)
        .bind(&event.result)
        .bind(detail_json)
        .bind(&event.previous_hash)
        .bind(&event.hash)
        .bind(&event.signature)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn query(&self, start_time: i64, end_time: i64) -> crate::Result<Vec<AuditEvent>> {
        let rows = sqlx::query_as::<_, AuditEventRow>(
            r#"
            SELECT event_id, timestamp, event_type, subject,
                   action, resource, source_ip, request_id, result,
                   detail, previous_hash, hash, signature
            FROM audit_events
            WHERE timestamp >= ? AND timestamp <= ?
            ORDER BY timestamp ASC
            "#,
        )
        .bind(start_time)
        .bind(end_time)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into_event()).collect())
    }

    async fn get_latest(&self) -> crate::Result<Option<AuditEvent>> {
        let row = sqlx::query_as::<_, AuditEventRow>(
            r#"
            SELECT event_id, timestamp, event_type, subject,
                   action, resource, source_ip, request_id, result,
                   detail, previous_hash, hash, signature
            FROM audit_events
            ORDER BY timestamp DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.into_event()))
    }

    async fn verify_chain(&self) -> crate::Result<bool> {
        let hasher = Sm3Engine::new();
        let rows = sqlx::query_as::<_, AuditEventRow>(
            r#"
            SELECT event_id, timestamp, event_type, subject,
                   action, resource, source_ip, request_id, result,
                   detail, previous_hash, hash, signature
            FROM audit_events
            ORDER BY timestamp ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let events: Vec<AuditEvent> = rows.into_iter().map(|r| r.into_event()).collect();
        let mut previous_hash: Option<String> = None;

        for event in &events {
            if Self::check_event_integrity(event, &hasher, &previous_hash).is_err() {
                return Ok(false);
            }
            previous_hash = event.hash.clone();
        }

        Ok(true)
    }
}

/// 数据库行结构，用于从 SQLite 反序列化审计事件
#[derive(Debug, sqlx::FromRow)]
struct AuditEventRow {
    event_id: String,
    timestamp: i64,
    event_type: String,
    subject: String,
    action: String,
    resource: String,
    source_ip: Option<String>,
    request_id: Option<String>,
    result: String,
    detail: Option<String>,
    previous_hash: Option<String>,
    hash: Option<String>,
    signature: Option<String>,
}

impl AuditEventRow {
    fn into_event(self) -> AuditEvent {
        AuditEvent {
            event_id: self.event_id,
            timestamp: self.timestamp,
            event_type: self.event_type,
            subject: self.subject,
            action: self.action,
            resource: self.resource,
            request_id: self.request_id,
            source_ip: self.source_ip,
            result: self.result,
            detail: self.detail,
            previous_hash: self.previous_hash,
            hash: self.hash,
            signature: self.signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::logger::AuditEvent;
    use crate::crypto::sm3_engine::Sm3Engine;
    use crate::crypto::traits::HashEngine;

    #[tokio::test]
    async fn test_sqlite_audit_store_append_and_query() {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("无法创建内存数据库");

        crate::store::migrations::run_migrations(&pool)
            .await
            .expect("迁移失败");

        let store = SqliteAuditStore::new(pool);

        let mut event = AuditEvent::new(
            "key.create",
            "admin",
            "POST:/api/v1/keys",
            "key:test",
            "success",
        );
        event.event_id = "test-event-1".into();
        event.timestamp = 1000;
        event.hash = Some("abc123".into());

        store.append(&event).await.expect("追加审计事件失败");

        let events = store.query(0, 2000).await.expect("查询审计事件失败");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "test-event-1");
        assert_eq!(events[0].result, "success");
    }

    #[tokio::test]
    async fn test_sqlite_audit_store_verify_chain() {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("无法创建内存数据库");

        crate::store::migrations::run_migrations(&pool)
            .await
            .expect("迁移失败");

        let store = SqliteAuditStore::new(pool);
        let hasher = Sm3Engine::new();

        let mut first = AuditEvent::new("key.create", "admin", "CREATE", "key:one", "success");
        first.timestamp = 1000;
        first.hash = Some(hex::encode(hasher.hash(&first.canonical_bytes())));

        let mut second = AuditEvent::new("key.rotate", "admin", "ROTATE", "key:one", "success");
        second.timestamp = 1001;
        second.previous_hash = first.hash.clone();
        second.hash = Some(hex::encode(hasher.hash(&second.canonical_bytes())));

        store.append(&first).await.expect("追加第一个事件失败");
        store.append(&second).await.expect("追加第二个事件失败");

        assert!(store.verify_chain().await.expect("链校验失败"));
    }
}
