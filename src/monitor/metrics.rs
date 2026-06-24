use sqlx::SqlitePool;
use std::time::Instant;

/// Prometheus 指标收集
pub struct MetricsCollector;

impl MetricsCollector {
    /// 生成 Prometheus 格式的指标文本
    pub async fn generate(pool: &SqlitePool, started_at: Instant) -> crate::Result<String> {
        let key_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM keys")
            .fetch_one(pool)
            .await
            .map_err(crate::Error::DatabaseError)?;
        let uptime_seconds = started_at.elapsed().as_secs();

        let mut output = String::new();
        output.push_str("# HELP kms_keys_total 密钥总数\n");
        output.push_str("# TYPE kms_keys_total gauge\n");
        output.push_str(&format!("kms_keys_total {}\n", key_count));
        output.push_str("# HELP kms_uptime_seconds 服务运行时间\n");
        output.push_str("# TYPE kms_uptime_seconds counter\n");
        output.push_str(&format!("kms_uptime_seconds {}\n", uptime_seconds));
        Ok(output)
    }
}
