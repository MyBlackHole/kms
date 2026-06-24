pub mod blocklist;
pub mod detector;
pub mod metrics;
pub mod rules;
#[cfg(feature = "monitoring")]
pub mod syslog;

pub use blocklist::{BlockEntry, BlockReason, Blocklist, SharedBlocklist};
pub use detector::IntrusionDetector;
pub use rules::{AlertEvent, AlertSeverity, RuleEngine, RuleType};
