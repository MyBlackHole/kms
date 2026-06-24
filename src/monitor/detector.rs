use crate::audit::logger::AuditEvent;
use crate::monitor::rules::{AlertEvent, AlertSeverity, RuleEngine, RuleType};
use std::sync::Arc;
use tokio::sync::Mutex;

/// 入侵检测引擎
pub struct IntrusionDetector {
    rule_engine: Arc<Mutex<RuleEngine>>,
    alert_history: Arc<Mutex<Vec<AlertEvent>>>,
}

impl Default for IntrusionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl IntrusionDetector {
    pub fn new() -> Self {
        Self {
            rule_engine: Arc::new(Mutex::new(RuleEngine::new())),
            alert_history: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// 审计事件接收入口 — 分析审计事件并产生告警
    pub async fn analyze_event(&self, event: &AuditEvent) -> Option<AlertEvent> {
        let counter_key = format!("{}:{}", event.action, event.subject);

        let rule_type = match event.action.as_str() {
            a if a.contains("LOGIN_FAILED") || a.contains("AUTH_FAILURE") => {
                RuleType::FailedLoginThreshold
            }
            a if a.starts_with("GET:") || a.starts_with("POST:") => RuleType::RateLimiting,
            _ => return None,
        };

        let mut engine = self.rule_engine.lock().await;
        let alert = engine.record_and_check(&counter_key, rule_type);

        if let Some(ref alert) = alert {
            let mut history = self.alert_history.lock().await;
            history.push(alert.clone());
        }

        alert
    }

    /// 获取最近的告警列表
    pub async fn recent_alerts(&self, limit: usize) -> Vec<AlertEvent> {
        let history = self.alert_history.lock().await;
        history.iter().rev().take(limit).cloned().collect()
    }

    /// 获取高严重性告警
    pub async fn high_severity_alerts(&self) -> Vec<AlertEvent> {
        let history = self.alert_history.lock().await;
        history
            .iter()
            .rev()
            .filter(|a| matches!(a.severity, AlertSeverity::High | AlertSeverity::Critical))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::logger::AuditEvent;

    fn make_event(action: &str) -> AuditEvent {
        AuditEvent::new("ACCESS", "test-user", action, "/api/v1/keys", "denied")
    }

    #[tokio::test]
    async fn test_detector_ignores_normal_events() {
        let detector = IntrusionDetector::new();
        let event = make_event("GET:/api/v1/keys");
        let alert = detector.analyze_event(&event).await;
        assert!(alert.is_none());
    }

    #[tokio::test]
    async fn test_detector_triggers_on_failed_login_burst() {
        let detector = IntrusionDetector::new();
        let mut last_alert = None;
        for _ in 0..5 {
            let event = make_event("LOGIN_FAILED:admin");
            last_alert = detector.analyze_event(&event).await;
        }
        assert!(last_alert.is_some());
        let alert = last_alert.unwrap();
        assert_eq!(alert.count, 5);
    }
}
