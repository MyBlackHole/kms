use crate::key::types::Key;
use async_trait::async_trait;

#[async_trait]
pub trait KeyStore: Send + Sync {
    async fn create_key(&self, key: &Key) -> crate::Result<()>;
    async fn get_key(&self, key_id: &str) -> crate::Result<Key>;
    async fn list_keys(&self) -> crate::Result<Vec<Key>>;
    async fn update_key(&self, key: &Key) -> crate::Result<()>;
    async fn delete_key(&self, key_id: &str) -> crate::Result<()>;
}

pub struct KeyStoreSqlite {
    pool: sqlx::SqlitePool,
}

impl KeyStoreSqlite {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl KeyStore for KeyStoreSqlite {
    async fn create_key(&self, key: &Key) -> crate::Result<()> {
        let serialized = serde_json::to_string(key).map_err(crate::Error::SerializationError)?;
        sqlx::query(
            "INSERT INTO keys (id, name, data, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&key.id)
        .bind(&key.name)
        .bind(&serialized)
        .bind(key.created_at)
        .bind(key.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_key(&self, key_id: &str) -> crate::Result<Key> {
        let row: (String,) = sqlx::query_as("SELECT data FROM keys WHERE id = ?")
            .bind(key_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|_| crate::Error::KeyNotFound(key_id.to_string()))?;

        serde_json::from_str(&row.0).map_err(crate::Error::SerializationError)
    }

    async fn list_keys(&self) -> crate::Result<Vec<Key>> {
        let rows: Vec<(String,)> = sqlx::query_as("SELECT data FROM keys ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await?;

        rows.iter()
            .map(|(data,)| serde_json::from_str(data).map_err(crate::Error::SerializationError))
            .collect()
    }

    async fn update_key(&self, key: &Key) -> crate::Result<()> {
        let serialized = serde_json::to_string(key).map_err(crate::Error::SerializationError)?;
        let rows = sqlx::query("UPDATE keys SET data = ?, updated_at = ? WHERE id = ?")
            .bind(&serialized)
            .bind(key.updated_at)
            .bind(&key.id)
            .execute(&self.pool)
            .await?
            .rows_affected();

        if rows == 0 {
            return Err(crate::Error::KeyNotFound(key.id.clone()));
        }
        Ok(())
    }

    async fn delete_key(&self, key_id: &str) -> crate::Result<()> {
        let rows = sqlx::query("DELETE FROM keys WHERE id = ?")
            .bind(key_id)
            .execute(&self.pool)
            .await?
            .rows_affected();

        if rows == 0 {
            return Err(crate::Error::KeyNotFound(key_id.to_string()));
        }
        Ok(())
    }
}
