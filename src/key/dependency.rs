use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// 密钥依赖关系
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDependency {
    pub id: String,
    pub key_id: String,
    pub version_number: u32,
    pub dependent_key_id: String,
    pub backup_id: Option<String>,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl KeyDependency {
    pub fn new(
        key_id: &str,
        version_number: u32,
        dependent_key_id: &str,
        description: Option<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            key_id: key_id.to_string(),
            version_number,
            dependent_key_id: dependent_key_id.to_string(),
            backup_id: None,
            description,
            created_at: Utc::now(),
        }
    }
}

/// 依赖存储 trait
#[async_trait]
pub trait DependencyStore: Send + Sync {
    async fn add_dependency(&self, dep: &KeyDependency) -> crate::Result<()>;
    async fn remove_dependency(&self, id: &str) -> crate::Result<()>;
    async fn list_dependents(&self, key_id: &str) -> crate::Result<Vec<KeyDependency>>;
    async fn has_dependents(&self, key_id: &str) -> crate::Result<bool>;
}

/// SQLite 依赖存储
pub struct SqliteDependencyStore {
    pool: sqlx::SqlitePool,
}

impl SqliteDependencyStore {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DependencyStore for SqliteDependencyStore {
    async fn add_dependency(&self, dep: &KeyDependency) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO key_dependencies (id, key_id, version_number, dependent_key_id, description, created_at) VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(&dep.id)
        .bind(&dep.key_id)
        .bind(dep.version_number as i64)
        .bind(&dep.dependent_key_id)
        .bind(&dep.description)
        .bind(dep.created_at)
        .execute(&self.pool)
        .await
        .map_err(crate::Error::DatabaseError)?;
        Ok(())
    }

    async fn remove_dependency(&self, id: &str) -> crate::Result<()> {
        sqlx::query("DELETE FROM key_dependencies WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_dependents(&self, key_id: &str) -> crate::Result<Vec<KeyDependency>> {
        sqlx::query_as::<_, DependencyRow>(
            "SELECT id, key_id, version_number, dependent_key_id, description, created_at FROM key_dependencies WHERE key_id = ?"
        )
        .bind(key_id)
        .fetch_all(&self.pool)
        .await
        .map(|rows| rows.into_iter().map(|r| r.into_dependency()).collect())
        .map_err(crate::Error::DatabaseError)
    }

    async fn has_dependents(&self, key_id: &str) -> crate::Result<bool> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM key_dependencies WHERE key_id = ?")
            .bind(key_id)
            .fetch_one(&self.pool)
            .await
            .map_err(crate::Error::DatabaseError)?;
        Ok(row.0 > 0)
    }
}

#[derive(Debug, sqlx::FromRow)]
struct DependencyRow {
    id: String,
    key_id: String,
    version_number: i64,
    dependent_key_id: String,
    description: Option<String>,
    created_at: DateTime<Utc>,
}

impl DependencyRow {
    fn into_dependency(self) -> KeyDependency {
        KeyDependency {
            id: self.id,
            key_id: self.key_id,
            version_number: self.version_number as u32,
            dependent_key_id: self.dependent_key_id,
            backup_id: None,
            description: self.description,
            created_at: self.created_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;

    #[tokio::test]
    async fn test_dependency_add_remove() {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("无法创建内存数据库");
        crate::store::migrations::run_migrations(&pool)
            .await
            .expect("迁移失败");

        let store = SqliteDependencyStore::new(pool);

        let dep = KeyDependency::new("key-root", 1, "key-child", Some("测试依赖".to_string()));
        store.add_dependency(&dep).await.expect("添加依赖失败");

        let has = store.has_dependents("key-root").await.expect("查询失败");
        assert!(has);

        let deps = store.list_dependents("key-root").await.expect("查询失败");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].dependent_key_id, "key-child");

        store
            .remove_dependency(&dep.id)
            .await
            .expect("删除依赖失败");
        let has = store.has_dependents("key-root").await.expect("查询失败");
        assert!(!has);
    }

    #[tokio::test]
    async fn test_dependency_blocks_destroy() {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("无法创建内存数据库");
        crate::store::migrations::run_migrations(&pool)
            .await
            .expect("迁移失败");

        let store = SqliteDependencyStore::new(pool);
        let dep = KeyDependency::new("key-root", 1, "key-child", None::<String>);
        store.add_dependency(&dep).await.expect("添加依赖失败");

        let has = store.has_dependents("key-root").await.expect("查询失败");
        assert!(has, "有依赖应该返回 true");
    }
    #[tokio::test]
    async fn test_dependency_multiple_dependents() {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("无法创建内存数据库");
        crate::store::migrations::run_migrations(&pool)
            .await
            .expect("迁移失败");

        let store = SqliteDependencyStore::new(pool.clone());
        let key_store = crate::key::store::KeyStoreSqlite::new(pool.clone());
        let key_manager = crate::key::manager::KeyManager::new(Box::new(key_store));

        let ka = key_manager
            .create_key(
                "ka",
                crate::key::types::KeySpec {
                    algorithm: crate::key::types::KeyAlgorithm::Sm4,
                    key_length: 128,
                    usage: vec![],
                    extractable: false,
                },
                crate::key::types::KeyPolicy {
                    rotation_days: None,
                    expiration_days: None,
                    max_versions: 3,
                    require_mfa_to_disable: false,
                    require_mfa_to_destroy: true,
                    allowed_roles: vec![],
                },
                None,
            )
            .await
            .unwrap();

        let kb = key_manager
            .create_key(
                "kb",
                crate::key::types::KeySpec {
                    algorithm: crate::key::types::KeyAlgorithm::Sm4,
                    key_length: 128,
                    usage: vec![],
                    extractable: false,
                },
                crate::key::types::KeyPolicy {
                    rotation_days: None,
                    expiration_days: None,
                    max_versions: 3,
                    require_mfa_to_disable: false,
                    require_mfa_to_destroy: true,
                    allowed_roles: vec![],
                },
                None,
            )
            .await
            .unwrap();

        let kc = key_manager
            .create_key(
                "kc",
                crate::key::types::KeySpec {
                    algorithm: crate::key::types::KeyAlgorithm::Sm4,
                    key_length: 128,
                    usage: vec![],
                    extractable: false,
                },
                crate::key::types::KeyPolicy {
                    rotation_days: None,
                    expiration_days: None,
                    max_versions: 3,
                    require_mfa_to_disable: false,
                    require_mfa_to_destroy: true,
                    allowed_roles: vec![],
                },
                None,
            )
            .await
            .unwrap();

        // B 和 C 都依赖 A
        let dep1 = KeyDependency::new(&ka.id, ka.current_version, &kb.id, Some("B依赖A".into()));
        let dep2 = KeyDependency::new(&ka.id, ka.current_version, &kc.id, Some("C依赖A".into()));
        store.add_dependency(&dep1).await.unwrap();
        store.add_dependency(&dep2).await.unwrap();

        let deps = store.list_dependents(&ka.id).await.unwrap();
        assert_eq!(deps.len(), 2);

        // 删除一个依赖
        store.remove_dependency(&dep1.id).await.unwrap();
        let deps = store.list_dependents(&ka.id).await.unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].dependent_key_id, kc.id);
    }
}
