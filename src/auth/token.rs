use crate::crypto::HashEngine;
use crate::Error;
use base64::Engine;
use serde::Serialize;
use sqlx::SqlitePool;

#[derive(Debug, Clone, Serialize)]
pub struct ApiToken {
    pub id: String,
    pub name: String,
    pub token_hint: String,
    #[serde(skip_serializing)]
    pub token_hash: String,
    pub role: Option<String>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub last_used: Option<i64>,
    pub disabled: bool,
}

#[derive(Clone)]
pub struct TokenStore {
    pool: SqlitePool,
}

impl TokenStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create_token(
        &self,
        name: &str,
        role: Option<&str>,
        ttl_secs: Option<u64>,
    ) -> crate::Result<(String, String, String)> {
        let id = uuid::Uuid::new_v4().to_string();
        let mut raw = vec![0u8; 32];
        getrandom::getrandom(&mut raw)
            .map_err(|e| Error::Internal(format!("生成 token 失败: {}", e)))?;
        let raw_token = format!(
            "kms_{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
        );
        let token_hash =
            hex::encode(crate::crypto::sm3_engine::Sm3Engine::new().hash(raw_token.as_bytes()));
        let hint = if raw_token.len() > 12 {
            format!("{}****", &raw_token[..12])
        } else {
            raw_token.clone()
        };
        let now = chrono::Utc::now().timestamp();
        let expires_at = ttl_secs.map(|s| now + s as i64);

        sqlx::query(
            "INSERT INTO api_tokens (id, name, token_hash, token_hint, role, created_at, expires_at, disabled) VALUES (?, ?, ?, ?, ?, ?, ?, 0)"
        )
            .bind(&id)
            .bind(name)
            .bind(&token_hash)
            .bind(&hint)
            .bind(role)
            .bind(now)
            .bind(expires_at)
            .execute(&self.pool)
            .await?;

        Ok((id, raw_token, hint))
    }

    pub async fn validate_token(&self, raw_token: &str) -> crate::Result<Option<ApiToken>> {
        let token_hash =
            hex::encode(crate::crypto::sm3_engine::Sm3Engine::new().hash(raw_token.as_bytes()));
        let row = sqlx::query_as::<_, (String, String, String, String, Option<String>, i64, Option<i64>, Option<i64>, i32)>(
            "SELECT id, name, token_hash, token_hint, role, created_at, expires_at, last_used, disabled FROM api_tokens WHERE token_hash = ?"
        )
            .bind(&token_hash)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some((id, name, th, hint, role, created_at, expires_at, _last_used, disabled)) => {
                if disabled != 0 {
                    return Ok(None);
                }
                if let Some(exp) = expires_at {
                    if chrono::Utc::now().timestamp() > exp {
                        return Ok(None);
                    }
                }
                sqlx::query("UPDATE api_tokens SET last_used = ? WHERE id = ?")
                    .bind(chrono::Utc::now().timestamp())
                    .bind(&id)
                    .execute(&self.pool)
                    .await?;
                Ok(Some(ApiToken {
                    id,
                    name,
                    token_hash: th,
                    token_hint: hint,
                    role,
                    created_at,
                    expires_at,
                    last_used: Some(chrono::Utc::now().timestamp()),
                    disabled: disabled != 0,
                }))
            }
            None => Ok(None),
        }
    }

    pub async fn list_tokens(&self) -> crate::Result<Vec<ApiToken>> {
        let rows = sqlx::query_as::<_, (String, String, String, String, Option<String>, i64, Option<i64>, Option<i64>, i32)>(
            "SELECT id, name, token_hash, token_hint, role, created_at, expires_at, last_used, disabled FROM api_tokens ORDER BY created_at DESC"
        )
            .fetch_all(&self.pool)
            .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, name, th, hint, role, created_at, expires_at, last_used, disabled)| {
                    ApiToken {
                        id,
                        name,
                        token_hash: th,
                        token_hint: hint,
                        role,
                        created_at,
                        expires_at,
                        last_used,
                        disabled: disabled != 0,
                    }
                },
            )
            .collect())
    }

    pub async fn revoke_token(&self, id: &str) -> crate::Result<bool> {
        let result = sqlx::query("UPDATE api_tokens SET disabled = 1 WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}
