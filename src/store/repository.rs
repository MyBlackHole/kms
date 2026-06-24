use crate::audit::logger::AuditEvent;
use crate::crypto::traits::HashEngine;
use crate::key::types::Key;
use async_trait::async_trait;

#[async_trait]
pub trait KeyRepository: Send + Sync {
    async fn create_key(&self, key: &Key) -> crate::Result<()>;
    async fn get_key(&self, key_id: &str) -> crate::Result<Key>;
    async fn list_keys(&self) -> crate::Result<Vec<Key>>;
    async fn update_key(&self, key: &Key) -> crate::Result<()>;
    async fn delete_key(&self, key_id: &str) -> crate::Result<()>;
}

#[async_trait]
pub trait AuditRepository: Send + Sync {
    async fn append_event(&self, event: &AuditEvent) -> crate::Result<()>;
    async fn query_events(&self, start_time: i64, end_time: i64) -> crate::Result<Vec<AuditEvent>>;
    async fn verify_chain_integrity(&self) -> crate::Result<bool>;
}

pub struct SqliteKeyRepository {
    pool: sqlx::SqlitePool,
}

impl SqliteKeyRepository {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl KeyRepository for SqliteKeyRepository {
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

pub struct SqliteAuditRepository {
    pool: sqlx::SqlitePool,
}

impl SqliteAuditRepository {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuditRepository for SqliteAuditRepository {
    async fn append_event(&self, event: &AuditEvent) -> crate::Result<()> {
        let serialized = serde_json::to_string(event).map_err(crate::Error::SerializationError)?;
        sqlx::query("INSERT INTO audit_log (event_id, timestamp, data) VALUES (?, ?, ?)")
            .bind(&event.event_id)
            .bind(event.timestamp)
            .bind(&serialized)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn query_events(&self, start_time: i64, end_time: i64) -> crate::Result<Vec<AuditEvent>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT data FROM audit_log WHERE timestamp >= ? AND timestamp <= ? ORDER BY timestamp",
        )
        .bind(start_time)
        .bind(end_time)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|(data,)| serde_json::from_str(data).map_err(crate::Error::SerializationError))
            .collect()
    }

    async fn verify_chain_integrity(&self) -> crate::Result<bool> {
        let rows: Vec<(String,)> = sqlx::query_as("SELECT data FROM audit_log ORDER BY timestamp")
            .fetch_all(&self.pool)
            .await?;

        let hasher = crate::crypto::sm3_engine::Sm3Engine::new();
        let mut prev_hash: Option<String> = None;

        for (data,) in &rows {
            let event: AuditEvent =
                serde_json::from_str(data).map_err(crate::Error::SerializationError)?;

            let canonical = event.canonical_bytes();
            let computed = hasher.hash(&canonical);
            let computed_hex = hex::encode(&computed);

            if let Some(ref event_hash) = event.hash {
                if event_hash != &computed_hex {
                    return Ok(false);
                }
            }
            if event.previous_hash != prev_hash {
                return Ok(false);
            }
            prev_hash = event.hash.clone();
        }

        Ok(true)
    }
}
