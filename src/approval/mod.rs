use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// 审批状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    /// 已消费（审批已被用于执行操作）
    Used,
}

/// 审批请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: String,
    pub action: String,
    pub resource: String,
    pub subject: String,
    pub reason: String,
    pub status: ApprovalStatus,
    pub reviewed_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

impl ApprovalRequest {
    pub fn new(action: &str, resource: &str, subject: &str, reason: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            subject: subject.to_string(),
            reason: reason.to_string(),
            status: ApprovalStatus::Pending,
            reviewed_by: None,
            created_at: Utc::now(),
            resolved_at: None,
        }
    }
}

/// 审批存储 trait
#[async_trait]
pub trait ApprovalStore: Send + Sync {
    async fn create_request(&self, req: &ApprovalRequest) -> crate::Result<()>;
    async fn get_request(&self, id: &str) -> crate::Result<ApprovalRequest>;
    async fn list_pending(&self) -> crate::Result<Vec<ApprovalRequest>>;
    async fn resolve(&self, id: &str, approved: bool, reviewer: &str) -> crate::Result<()>;
    async fn has_pending_for(&self, resource: &str, action: &str) -> crate::Result<bool>;
    /// 检查是否存在指定操作的已批准请求
    async fn has_approved_for(&self, resource: &str, action: &str) -> crate::Result<bool>;
    /// 消费已批准的请求（标记为已使用），防止重复使用
    async fn consume_approved_for(&self, resource: &str, action: &str) -> crate::Result<()>;
}

/// SQLite 审批存储
pub struct SqliteApprovalStore {
    pool: sqlx::SqlitePool,
}

impl SqliteApprovalStore {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ApprovalStore for SqliteApprovalStore {
    async fn create_request(&self, req: &ApprovalRequest) -> crate::Result<()> {
        let status_str = format!("{:?}", req.status);
        sqlx::query(
            "INSERT INTO approval_requests (id, action, resource, subject, reason, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&req.id)
        .bind(&req.action)
        .bind(&req.resource)
        .bind(&req.subject)
        .bind(&req.reason)
        .bind(&status_str)
        .bind(req.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_request(&self, id: &str) -> crate::Result<ApprovalRequest> {
        let row = sqlx::query_as::<_, ApprovalRow>(
            "SELECT id, action, resource, subject, reason, status, reviewed_by, created_at, resolved_at FROM approval_requests WHERE id = ?"
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| crate::Error::Internal(format!("审批请求未找到: {}", id)))?;
        row.into_request()
    }

    async fn list_pending(&self) -> crate::Result<Vec<ApprovalRequest>> {
        let rows = sqlx::query_as::<_, ApprovalRow>(
            "SELECT id, action, resource, subject, reason, status, reviewed_by, created_at, resolved_at FROM approval_requests WHERE status = 'Pending' ORDER BY created_at DESC"
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(|r| r.into_request()).collect()
    }

    async fn resolve(&self, id: &str, approved: bool, reviewer: &str) -> crate::Result<()> {
        let status = if approved { "Approved" } else { "Rejected" };
        let now = Utc::now();
        let rows = sqlx::query(
            "UPDATE approval_requests SET status = ?, reviewed_by = ?, resolved_at = ? WHERE id = ? AND status = 'Pending'"
        )
        .bind(status)
        .bind(reviewer)
        .bind(now)
        .bind(id)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if rows == 0 {
            return Err(crate::Error::Internal("审批请求不存在或已处理".into()));
        }
        Ok(())
    }

    async fn has_pending_for(&self, resource: &str, action: &str) -> crate::Result<bool> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM approval_requests WHERE resource = ? AND action = ? AND status = 'Pending'"
        )
        .bind(resource)
        .bind(action)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0 > 0)
    }

    async fn has_approved_for(&self, resource: &str, action: &str) -> crate::Result<bool> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM approval_requests WHERE resource = ? AND action = ? AND status = 'Approved'"
        )
        .bind(resource)
        .bind(action)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0 > 0)
    }

    async fn consume_approved_for(&self, resource: &str, action: &str) -> crate::Result<()> {
        sqlx::query(
            "UPDATE approval_requests SET status = 'Used' WHERE resource = ? AND action = ? AND status = 'Approved'"
        )
        .bind(resource)
        .bind(action)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

/// 数据库行结构
#[derive(Debug, sqlx::FromRow)]
struct ApprovalRow {
    id: String,
    action: String,
    resource: String,
    subject: String,
    reason: String,
    status: String,
    reviewed_by: Option<String>,
    created_at: DateTime<Utc>,
    resolved_at: Option<DateTime<Utc>>,
}

impl ApprovalRow {
    fn into_request(self) -> crate::Result<ApprovalRequest> {
        let status = match self.status.as_str() {
            "Pending" => ApprovalStatus::Pending,
            "Approved" => ApprovalStatus::Approved,
            "Rejected" => ApprovalStatus::Rejected,
            "Used" => ApprovalStatus::Used,
            _ => {
                return Err(crate::Error::Internal(format!(
                    "无效的状态: {}",
                    self.status
                )))
            }
        };
        Ok(ApprovalRequest {
            id: self.id,
            action: self.action,
            resource: self.resource,
            subject: self.subject,
            reason: self.reason,
            status,
            reviewed_by: self.reviewed_by,
            created_at: self.created_at,
            resolved_at: self.resolved_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;

    #[tokio::test]
    async fn test_approval_create_resolve() {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("无法创建内存数据库");
        crate::store::migrations::run_migrations(&pool)
            .await
            .expect("迁移失败");

        let store = SqliteApprovalStore::new(pool);

        let req = ApprovalRequest::new("DESTROY_KEY", "key:test-123", "admin1", "需要销毁测试密钥");
        store.create_request(&req).await.expect("创建审批失败");

        let pending = store.list_pending().await.expect("查询待审批失败");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].status, ApprovalStatus::Pending);

        store
            .resolve(&req.id, true, "admin2")
            .await
            .expect("审批失败");
        let resolved = store.get_request(&req.id).await.expect("查询失败");
        assert_eq!(resolved.status, ApprovalStatus::Approved);
    }

    #[tokio::test]
    async fn test_approval_double_resolve_fails() {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("无法创建内存数据库");
        crate::store::migrations::run_migrations(&pool)
            .await
            .expect("迁移失败");

        let store = SqliteApprovalStore::new(pool);
        let req = ApprovalRequest::new("EXPORT_KEY", "key:test-456", "admin1", "导出测试密钥");
        store.create_request(&req).await.expect("创建审批失败");

        store
            .resolve(&req.id, true, "admin2")
            .await
            .expect("首次审批失败");
        let result = store.resolve(&req.id, false, "admin3").await;
        assert!(result.is_err(), "重复审批应该失败");
    }
    #[tokio::test]
    async fn test_approval_consume_flow() {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("无法创建内存数据库");
        crate::store::migrations::run_migrations(&pool)
            .await
            .expect("迁移失败");

        let store = SqliteApprovalStore::new(pool);

        let req = ApprovalRequest::new("DESTROY", "key:test-001", "admin1", "销毁密钥");
        store.create_request(&req).await.expect("创建审批失败");
        store
            .resolve(&req.id, true, "admin2")
            .await
            .expect("审批失败");

        assert!(store
            .has_approved_for("key:test-001", "DESTROY")
            .await
            .unwrap());
        store
            .consume_approved_for("key:test-001", "DESTROY")
            .await
            .unwrap();
        assert!(!store
            .has_approved_for("key:test-001", "DESTROY")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_approval_reject_status() {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("无法创建内存数据库");
        crate::store::migrations::run_migrations(&pool)
            .await
            .expect("迁移失败");

        let store = SqliteApprovalStore::new(pool);
        let req = ApprovalRequest::new("EXPORT", "keys", "admin1", "导出密钥");
        store.create_request(&req).await.expect("创建审批失败");
        store
            .resolve(&req.id, false, "admin2")
            .await
            .expect("驳回失败");

        let rejected = store.get_request(&req.id).await.expect("查询失败");
        assert_eq!(rejected.status, ApprovalStatus::Rejected);
        assert_eq!(rejected.reviewed_by.unwrap(), "admin2");
        assert!(rejected.resolved_at.is_some());
    }

    #[tokio::test]
    async fn test_has_pending_for() {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("无法创建内存数据库");
        crate::store::migrations::run_migrations(&pool)
            .await
            .expect("迁移失败");

        let store = SqliteApprovalStore::new(pool);
        let req = ApprovalRequest::new("ROTATE", "key:test-002", "admin1", "轮换密钥");
        store.create_request(&req).await.expect("创建审批失败");

        assert!(store
            .has_pending_for("key:test-002", "ROTATE")
            .await
            .unwrap());

        store.resolve(&req.id, true, "admin2").await.unwrap();
        assert!(!store
            .has_pending_for("key:test-002", "ROTATE")
            .await
            .unwrap());
    }
}
