use crate::audit::logger::{AuditEvent, AuditStore};
use async_trait::async_trait;
use std::sync::Mutex;

/// Syslog 审计存储：将审计事件发送到本地 syslog
pub struct SyslogAuditStore {
    logger: Option<Mutex<syslog::BasicLogger>>,
    enabled: bool,
}

impl SyslogAuditStore {
    pub fn new() -> Self {
        let logger = Self::try_init();
        let enabled = logger.is_some();
        if enabled {
            tracing::info!("Syslog 审计存储已初始化");
        }
        Self {
            logger: logger.map(Mutex::new),
            enabled,
        }
    }

    fn try_init() -> Option<syslog::BasicLogger> {
        #[cfg(all(unix, feature = "monitoring"))]
        {
            let formatter = syslog::Formatter3164 {
                facility: syslog::Facility::LOG_USER,
                hostname: None,
                process: "kms".into(),
                pid: 0,
            };
            match syslog::unix(formatter) {
                Ok(logger) => {
                    return Some(syslog::BasicLogger::new(logger));
                }
                Err(e) => {
                    tracing::warn!("无法连接 syslog: {:?}", e);
                }
            }
        }
        #[cfg(not(all(unix, feature = "monitoring")))]
        {
            let _ = ();
        }
        None
    }
}

#[async_trait]
impl AuditStore for SyslogAuditStore {
    async fn append(&self, event: &AuditEvent) -> crate::Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let msg = serde_json::to_string(event).unwrap_or_else(|_| "序列化失败".into());

        if let Some(ref logger) = self.logger {
            let logger = logger
                .lock()
                .map_err(|e| crate::Error::Internal(format!("syslog 锁获取失败: {}", e)))?;
            let level = match event.result.as_str() {
                "denied" | "failure" | "error" => log::Level::Error,
                "success" => log::Level::Info,
                _ => log::Level::Warn,
            };
            log::Log::log(
                &*logger,
                &log::Record::builder()
                    .args(format_args!("{}", msg))
                    .level(level)
                    .target("kms::audit")
                    .module_path(Some("kms::monitor::syslog"))
                    .build(),
            );
        }
        Ok(())
    }

    async fn query(&self, _start_time: i64, _end_time: i64) -> crate::Result<Vec<AuditEvent>> {
        Ok(Vec::new()) // syslog 不支持查询
    }

    async fn get_latest(&self) -> crate::Result<Option<AuditEvent>> {
        Ok(None)
    }

    async fn verify_chain(&self) -> crate::Result<bool> {
        Ok(true)
    }
}

/// 双写审计存储：同时写入主存储和副存储
pub struct DualAuditStore {
    primary: Box<dyn AuditStore>,
    secondary: Box<dyn AuditStore>,
}

impl DualAuditStore {
    pub fn new(primary: Box<dyn AuditStore>, secondary: Box<dyn AuditStore>) -> Self {
        Self { primary, secondary }
    }
}

#[async_trait]
impl AuditStore for DualAuditStore {
    async fn append(&self, event: &AuditEvent) -> crate::Result<()> {
        self.primary.append(event).await?;
        let _ = self.secondary.append(event).await;
        Ok(())
    }

    async fn query(&self, start_time: i64, end_time: i64) -> crate::Result<Vec<AuditEvent>> {
        self.primary.query(start_time, end_time).await
    }

    async fn get_latest(&self) -> crate::Result<Option<AuditEvent>> {
        self.primary.get_latest().await
    }

    async fn verify_chain(&self) -> crate::Result<bool> {
        self.primary.verify_chain().await
    }
}
