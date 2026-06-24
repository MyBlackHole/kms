//! 自动阻断模块（等保四级 入侵自动响应）
//!
//! 当入侵检测引擎产生告警时，自动将来源 IP 或用户加入临时封禁名单。
//! 支持分级时间窗口：首次短封、累进延长。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// 封禁原因
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum BlockReason {
    /// 登录失败超限
    BruteForce,
    /// 速率超限
    RateLimit,
    /// 可疑模式
    Suspicious,
    /// 手动封禁
    Manual,
}

impl std::fmt::Display for BlockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockReason::BruteForce => write!(f, "brute_force"),
            BlockReason::RateLimit => write!(f, "rate_limit"),
            BlockReason::Suspicious => write!(f, "suspicious"),
            BlockReason::Manual => write!(f, "manual"),
        }
    }
}

/// 封禁条目
#[derive(Debug, Clone)]
pub struct BlockEntry {
    /// 被封禁的 IP 或用户名
    pub target: String,
    /// 封禁原因
    pub reason: BlockReason,
    /// 封禁开始时间
    pub since: Instant,
    /// 封禁持续时间（None 表示永久）
    pub duration: Option<Duration>,
    /// 当前累计封禁次数
    pub strike: u32,
}

impl BlockEntry {
    /// 是否已过期
    pub fn is_expired(&self) -> bool {
        match self.duration {
            Some(d) => self.since.elapsed() >= d,
            None => false,
        }
    }

    /// 剩余封禁秒数（0 表示已过期或永久）
    pub fn remaining_secs(&self) -> u64 {
        match self.duration {
            Some(d) => {
                let elapsed = self.since.elapsed();
                if elapsed >= d {
                    0
                } else {
                    (d - elapsed).as_secs()
                }
            }
            None => u64::MAX,
        }
    }
}

/// 自动阻断管理器
pub struct Blocklist {
    blocks: HashMap<String, BlockEntry>,
    /// 各目标的累进封禁阶梯
    strike_counters: HashMap<String, u32>,
    /// 基础封禁时长（秒）
    base_block_duration: u64,
    /// 最大封禁时长（秒）
    max_block_duration: u64,
}

impl Default for Blocklist {
    fn default() -> Self {
        Self::new()
    }
}

impl Blocklist {
    pub fn new() -> Self {
        Self {
            blocks: HashMap::new(),
            strike_counters: HashMap::new(),
            base_block_duration: 300,  // 5 分钟
            max_block_duration: 86400, // 24 小时
        }
    }

    /// 对目标执行自动封禁
    ///
    /// 封禁时长随 strike 次数递增：base * 2^(strike-1)，上限 max
    pub fn block(&mut self, target: &str, reason: BlockReason) -> BlockEntry {
        let strike = {
            let counter = self.strike_counters.entry(target.to_string()).or_insert(0);
            *counter += 1;
            *counter
        };

        let duration_secs = (self.base_block_duration * 2u64.pow(strike.saturating_sub(1)))
            .min(self.max_block_duration);
        let duration = if reason == BlockReason::Manual {
            None // 手动封禁为永久
        } else {
            Some(Duration::from_secs(duration_secs))
        };

        let entry = BlockEntry {
            target: target.to_string(),
            reason,
            since: Instant::now(),
            duration,
            strike,
        };

        self.blocks.insert(target.to_string(), entry.clone());
        entry
    }

    /// 手动解封
    pub fn unblock(&mut self, target: &str) -> bool {
        self.blocks.remove(target).is_some()
    }

    /// 检查目标是否被封禁
    pub fn is_blocked(&mut self, target: &str) -> bool {
        match self.blocks.get(target) {
            Some(entry) if entry.is_expired() => {
                // 过期自动清除
                self.blocks.remove(target);
                false
            }
            Some(_) => true,
            None => false,
        }
    }

    /// 获取所有活跃封禁列表
    pub fn active_blocks(&self) -> Vec<BlockEntry> {
        self.blocks
            .values()
            .filter(|e| !e.is_expired())
            .cloned()
            .collect()
    }

    /// 获取指定目标的封禁状态
    pub fn get_block(&self, target: &str) -> Option<&BlockEntry> {
        self.blocks.get(target).filter(|e| !e.is_expired())
    }

    /// 重置目标的 strike 计数（封禁解除后调用）
    pub fn reset_strikes(&mut self, target: &str) {
        self.strike_counters.remove(target);
    }

    /// 配置基础封禁时长（秒）
    pub fn set_base_duration(&mut self, secs: u64) {
        self.base_block_duration = secs;
    }
}

/// 带自动锁的 Blocklist（用于多线程上下文）
pub struct SharedBlocklist {
    inner: Arc<Mutex<Blocklist>>,
}

impl Default for SharedBlocklist {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedBlocklist {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Blocklist::new())),
        }
    }

    pub async fn block(&self, target: &str, reason: BlockReason) -> BlockEntry {
        self.inner.lock().await.block(target, reason)
    }

    pub async fn unblock(&self, target: &str) -> bool {
        self.inner.lock().await.unblock(target)
    }

    pub async fn is_blocked(&self, target: &str) -> bool {
        self.inner.lock().await.is_blocked(target)
    }

    pub async fn active_blocks(&self) -> Vec<BlockEntry> {
        self.inner.lock().await.active_blocks()
    }

    pub fn arc(&self) -> Arc<Mutex<Blocklist>> {
        self.inner.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_expiry() {
        let mut bl = Blocklist::new();
        bl.set_base_duration(1); // 1 秒
        let entry = bl.block("192.168.1.1", BlockReason::BruteForce);
        assert_eq!(entry.reason, BlockReason::BruteForce);
        assert!(bl.is_blocked("192.168.1.1"));
        std::thread::sleep(Duration::from_millis(1100));
        assert!(!bl.is_blocked("192.168.1.1"), "过期后应自动解封");
    }

    #[test]
    fn test_manual_block_is_permanent() {
        let mut bl = Blocklist::new();
        bl.block("attacker", BlockReason::Manual);
        assert!(bl.is_blocked("attacker"));
        // 手动解封
        assert!(bl.unblock("attacker"));
        assert!(!bl.is_blocked("attacker"));
    }

    #[test]
    fn test_strike_escalation() {
        let mut bl = Blocklist::new();
        bl.set_base_duration(60);
        // 连续触发多次封禁，时长应递增
        let first = bl.block("user", BlockReason::RateLimit);
        assert_eq!(first.duration.unwrap().as_secs(), 60);
        let second = bl.block("user", BlockReason::RateLimit);
        assert_eq!(second.duration.unwrap().as_secs(), 120, "第二次应翻倍");
        let third = bl.block("user", BlockReason::RateLimit);
        assert_eq!(third.duration.unwrap().as_secs(), 240, "第三次应再翻倍");
    }

    #[test]
    fn test_unblock_resets_strikes() {
        let mut bl = Blocklist::new();
        bl.block("user", BlockReason::BruteForce);
        bl.reset_strikes("user");
        // 重新封禁应从基础时长开始
        let entry = bl.block("user", BlockReason::BruteForce);
        assert_eq!(entry.strike, 1, "reset 后 strike 应从 1 开始");
    }

    #[test]
    fn test_multiple_targets_independent() {
        let mut bl = Blocklist::new();
        bl.block("target-a", BlockReason::BruteForce);
        assert!(!bl.is_blocked("target-b"));
    }

    #[tokio::test]
    async fn test_shared_blocklist() {
        let shared = SharedBlocklist::new();
        shared.block("10.0.0.1", BlockReason::Suspicious).await;
        assert!(shared.is_blocked("10.0.0.1").await);
        shared.unblock("10.0.0.1").await;
        assert!(!shared.is_blocked("10.0.0.1").await);
    }
}
