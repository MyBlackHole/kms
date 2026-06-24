use crate::audit::logger::{AuditEvent, AuditStore};
use async_trait::async_trait;

/// 审计上报目标
#[derive(Debug, Clone)]
pub enum ReporterTarget {
    /// syslog（通过 log crate）
    Syslog,
    /// HTTPS POST 到指定 URL
    HttpsPost { url: String, timeout_secs: u64 },
}

/// 审计上报器包装器
///
/// 将审计事件上报到外部安全管理中心。
/// 上报失败不丢本地审计记录，仅产生告警日志。
pub struct ReporterAuditStore {
    inner: Box<dyn AuditStore>,
    target: ReporterTarget,
    client: Option<reqwest::Client>,
}

impl ReporterAuditStore {
    pub fn new(inner: Box<dyn AuditStore>, target: ReporterTarget) -> Self {
        let client = match &target {
            ReporterTarget::HttpsPost { timeout_secs, .. } => reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(*timeout_secs))
                .build()
                .ok(),
            ReporterTarget::Syslog => None,
        };

        Self {
            inner,
            target,
            client,
        }
    }

    async fn report(&self, event: &AuditEvent) {
        let result = match &self.target {
            ReporterTarget::Syslog => {
                #[cfg(feature = "monitoring")]
                {
                    log::info!(
                        "[AUDIT] {} | {} | {} | {} | {} | {}",
                        event.event_id,
                        event.timestamp,
                        event.subject,
                        event.action,
                        event.resource,
                        event.result,
                    );
                }
                #[cfg(not(feature = "monitoring"))]
                {
                    tracing::info!(
                        "AUDIT_REPORT {} | {} | {} | {} | {} | {}",
                        event.event_id,
                        event.timestamp,
                        event.subject,
                        event.action,
                        event.resource,
                        event.result,
                    );
                }
                Ok(())
            }
            ReporterTarget::HttpsPost { url, .. } => {
                if let Some(client) = &self.client {
                    match client.post(url).json(event).send().await {
                        Ok(resp) => {
                            if resp.status().is_success() {
                                Ok(())
                            } else {
                                Err(format!("HTTP {}", resp.status()))
                            }
                        }
                        Err(e) => Err(e.to_string()),
                    }
                } else {
                    Err("HTTP client not available".to_string())
                }
            }
        };

        if let Err(e) = result {
            // 上报失败不丢记录，仅告警
            tracing::warn!(
                "审计上报失败 (event={}): {} — 本地记录已保留",
                event.event_id,
                e,
            );
        }
    }
}

#[async_trait]
impl AuditStore for ReporterAuditStore {
    async fn append(&self, event: &AuditEvent) -> crate::Result<()> {
        // 先写入本地（保证不丢记录）
        self.inner.append(event).await?;
        // 异步上报（不阻塞主流程）
        self.report(event).await;
        Ok(())
    }

    async fn query(&self, start_time: i64, end_time: i64) -> crate::Result<Vec<AuditEvent>> {
        self.inner.query(start_time, end_time).await
    }

    async fn get_latest(&self) -> crate::Result<Option<AuditEvent>> {
        self.inner.get_latest().await
    }

    async fn verify_chain(&self) -> crate::Result<bool> {
        self.inner.verify_chain().await
    }
}
