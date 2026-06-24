use std::collections::HashMap;
use std::time::{Duration, Instant};

/// 检测规则类型
#[derive(Debug, Clone, PartialEq)]
pub enum RuleType {
    FailedLoginThreshold,
    AbnormalAccessTime,
    RateLimiting,
    SuspiciousPattern,
}

/// 规则定义
#[derive(Debug, Clone)]
pub struct DetectionRule {
    pub rule_type: RuleType,
    pub name: &'static str,
    pub description: &'static str,
    pub threshold: u32,
    pub window_secs: u64,
    pub severity: AlertSeverity,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// 规则管理器
pub struct RuleEngine {
    rules: Vec<DetectionRule>,
    counters: HashMap<String, Vec<Instant>>,
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            rules: vec![
                DetectionRule {
                    rule_type: RuleType::FailedLoginThreshold,
                    name: "failed-login-burst",
                    description: "Failed login attempts exceed threshold",
                    threshold: 5,
                    window_secs: 300,
                    severity: AlertSeverity::High,
                },
                DetectionRule {
                    rule_type: RuleType::AbnormalAccessTime,
                    name: "abnormal-access-time",
                    description: "Access outside normal business hours",
                    threshold: 1,
                    window_secs: 1,
                    severity: AlertSeverity::Medium,
                },
                DetectionRule {
                    rule_type: RuleType::RateLimiting,
                    name: "rate-limit-exceeded",
                    description: "API request rate exceeds limit",
                    threshold: 100,
                    window_secs: 60,
                    severity: AlertSeverity::Low,
                },
                DetectionRule {
                    rule_type: RuleType::SuspiciousPattern,
                    name: "suspicious-key-access",
                    description: "Suspicious repeated key access pattern",
                    threshold: 10,
                    window_secs: 60,
                    severity: AlertSeverity::High,
                },
            ],
            counters: HashMap::new(),
        }
    }

    /// 记录事件并检查是否触发规则
    pub fn record_and_check(
        &mut self,
        counter_key: &str,
        rule_type: RuleType,
    ) -> Option<AlertEvent> {
        let rule = self.rules.iter().find(|r| r.rule_type == rule_type)?;

        let now = Instant::now();
        let entries = self.counters.entry(counter_key.to_string()).or_default();
        entries.push(now);

        // 移除窗口外的记录
        let cutoff = now - Duration::from_secs(rule.window_secs);
        entries.retain(|&t| t > cutoff);

        if entries.len() as u32 >= rule.threshold {
            Some(AlertEvent {
                rule_name: rule.name.to_string(),
                description: rule.description.to_string(),
                severity: rule.severity.clone(),
                counter_key: counter_key.to_string(),
                count: entries.len() as u32,
                timestamp: chrono::Utc::now(),
            })
        } else {
            None
        }
    }
}

/// 告警事件
#[derive(Debug, Clone, serde::Serialize)]
pub struct AlertEvent {
    pub rule_name: String,
    pub description: String,
    pub severity: AlertSeverity,
    pub counter_key: String,
    pub count: u32,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_not_triggered_below_threshold() {
        let mut engine = RuleEngine::new();
        let result = engine.record_and_check("test-user", RuleType::FailedLoginThreshold);
        assert!(result.is_none());
    }

    #[test]
    fn test_rule_triggered_at_threshold() {
        let mut engine = RuleEngine::new();
        let mut last_result = None;
        for _ in 0..5 {
            last_result = engine.record_and_check("test-user", RuleType::FailedLoginThreshold);
        }
        assert!(last_result.is_some());
        let alert = last_result.unwrap();
        assert_eq!(alert.count, 5);
        assert_eq!(alert.severity, AlertSeverity::High);
    }

    #[test]
    fn test_separate_counters() {
        let mut engine = RuleEngine::new();
        for _ in 0..5 {
            engine.record_and_check("user-a", RuleType::FailedLoginThreshold);
        }
        let result_b = engine.record_and_check("user-b", RuleType::FailedLoginThreshold);
        assert!(result_b.is_none());
    }
}
