use clap::Parser;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "kms-server", about = "国密合规密钥管理系统")]
pub struct Cli {
    #[arg(short, long, default_value = "config.toml")]
    pub config: PathBuf,
    /// 输出自身二进制 SM3 哈希并退出
    #[arg(long)]
    pub hash_self: bool,
    /// 导出合规证据包到指定目录
    #[arg(long)]
    pub evidence: Option<PathBuf>,
    /// 管理子命令
    #[command(subcommand)]
    pub command: Option<CliCommand>,
}

#[derive(Debug, Parser)]
pub enum CliCommand {
    /// 导出密钥到文件
    ExportKeys {
        /// 输出文件路径
        output: PathBuf,
    },
    /// 从文件导入密钥
    ImportKeys {
        /// 输入文件路径
        input: PathBuf,
    },
    /// 导出 Master Seed 备份
    BackupSeed {
        /// 输出备份文件路径
        output: PathBuf,
    },
    /// 从备份恢复 Master Seed
    RestoreSeed {
        /// 备份文件路径
        input: PathBuf,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub crypto: CryptoConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub hsm: HsmConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub trust: crate::trust::TrustConfig,
    #[serde(default)]
    pub tpm: TpmConfig,
    #[serde(default)]
    pub cluster: ClusterConfig,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityLevel {
    #[default]
    Level3,
    Level4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default = "default_totp_issuer")]
    pub totp_issuer: String,
    #[serde(default)]
    pub admin_token: Option<String>,
    #[serde(default)]
    pub security_level: SecurityLevel,
    #[serde(default)]
    pub anti_repudiation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_workers")]
    pub workers: usize,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default = "default_session_ttl")]
    pub session_ttl_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    #[serde(default)]
    pub client_ca_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_db_url")]
    pub url: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_true")]
    pub run_migrations: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    #[serde(default = "default_kek_path")]
    pub kek_path: PathBuf,
    #[serde(default = "default_key_rotation_days")]
    pub key_rotation_days: u32,
    #[serde(default = "default_max_key_versions")]
    pub max_key_versions: u32,
    #[serde(default)]
    pub master_seed_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    #[serde(default = "default_audit_log_path")]
    pub log_path: PathBuf,
    #[serde(default = "default_audit_retention_days")]
    pub retention_days: u32,
    #[serde(default = "default_true")]
    pub enable_chain: bool,
    #[serde(default = "default_true")]
    pub enable_signing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmConfig {
    #[serde(default = "default_hsm_mode")]
    pub mode: String,
    pub pkcs11_module_path: Option<PathBuf>,
    pub pkcs11_slot_id: Option<u64>,
    pub pkcs11_pin: Option<String>,
    pub software_master_seed: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default = "default_true")]
    pub enable_rbac: bool,
    #[serde(default = "default_true")]
    pub enforce_https: bool,
}

/// TPM 2.0 可信根配置（等保四级）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmConfig {
    /// TPM 模式: "software" (开发/测试) | "tpm" (真实 TPM 2.0)
    #[serde(default = "default_tpm_mode")]
    pub mode: String,
    /// 可选 TCTI 配置，例如 `device:/dev/tpmrm0` 或 `swtpm:host=127.0.0.1,port=2321`
    #[serde(default)]
    pub tcti: Option<String>,
    /// 是否在启动时度量二进制和配置到 PCR
    #[serde(default = "default_true")]
    pub enable_startup_measurement: bool,
    /// 用于应用度量的 PCR 索引（默认 16）
    #[serde(default = "default_tpm_pcr")]
    pub app_pcr_index: u8,
}

/// 集群节点配置（等保四级 节点间可信通信）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    /// 本节点 ID（UUID）
    #[serde(default = "default_node_id")]
    pub node_id: String,
    /// 集群对等节点列表
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    /// 节点间通信端口
    #[serde(default = "default_cluster_port")]
    pub peer_port: u16,
    /// 是否启用集群模式
    #[serde(default)]
    pub enabled: bool,
}

/// 对等节点配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    /// 节点 ID
    pub node_id: String,
    /// 节点地址 (host:port)
    pub address: String,
    /// 用于 mTLS 的 CA 证书路径
    #[serde(default)]
    pub ca_cert_path: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            workers: default_workers(),
            tls: None,
            session_ttl_secs: default_session_ttl(),
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: default_db_url(),
            max_connections: default_max_connections(),
            run_migrations: default_true(),
        }
    }
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            kek_path: default_kek_path(),
            key_rotation_days: default_key_rotation_days(),
            max_key_versions: default_max_key_versions(),
            master_seed_path: None,
        }
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_path: default_audit_log_path(),
            retention_days: default_audit_retention_days(),
            enable_chain: default_true(),
            enable_signing: default_true(),
        }
    }
}

impl Default for HsmConfig {
    fn default() -> Self {
        Self {
            mode: default_hsm_mode(),
            pkcs11_module_path: None,
            pkcs11_slot_id: None,
            pkcs11_pin: None,
            software_master_seed: None,
        }
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            enable_rbac: default_true(),
            enforce_https: default_true(),
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            totp_issuer: default_totp_issuer(),
            admin_token: None,
            security_level: SecurityLevel::Level3,
            anti_repudiation: false,
        }
    }
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            node_id: "standalone".into(),
            peers: vec![],
            peer_port: 9443,
            enabled: false,
        }
    }
}

fn default_node_id() -> String {
    "standalone".into()
}
fn default_cluster_port() -> u16 {
    9443
}

impl Default for TpmConfig {
    fn default() -> Self {
        Self {
            mode: default_tpm_mode(),
            tcti: None,
            enable_startup_measurement: true,
            app_pcr_index: 16,
        }
    }
}

fn default_tpm_mode() -> String {
    "software".into()
}
fn default_tpm_pcr() -> u8 {
    16
}

fn default_host() -> String {
    "127.0.0.1".into()
}
fn default_port() -> u16 {
    8443
}
fn default_workers() -> usize {
    4
}
fn default_db_url() -> String {
    "sqlite://data/kms.db?mode=rwc".into()
}
fn default_max_connections() -> u32 {
    10
}
fn default_true() -> bool {
    true
}
fn default_kek_path() -> PathBuf {
    PathBuf::from("data/master.key")
}
fn default_key_rotation_days() -> u32 {
    365
}
fn default_max_key_versions() -> u32 {
    10
}
fn default_audit_log_path() -> PathBuf {
    PathBuf::from("data/audit.log")
}
fn default_audit_retention_days() -> u32 {
    365
}
fn default_hsm_mode() -> String {
    "software".into()
}
fn default_session_ttl() -> u64 {
    3600
}
fn default_totp_issuer() -> String {
    "KMS".into()
}

impl Config {
    pub fn load(path: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("无法读取配置文件 {}: {}", path.display(), e))?;
        let config: Config = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// 验证配置合法性
    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Level4 模式强制要求配置 admin_token
        if self.auth.security_level == SecurityLevel::Level4 && self.auth.admin_token.is_none() {
            return Err("Level4 mode requires admin_token to be configured".into());
        }
        // Level4 模式审计不可关闭
        if self.auth.security_level == SecurityLevel::Level4 && !self.audit.enable_signing {
            return Err("Level4 mode requires audit signing to be enabled".into());
        }
        Ok(())
    }

    pub fn default_config() -> String {
        r#"# KMS 配置文件
[server]
host = "127.0.0.1"
port = 8443
workers = 4

[database]
url = "sqlite://data/kms.db?mode=rwc"
max_connections = 10
run_migrations = true

[crypto]
kek_path = "data/master.key"
key_rotation_days = 365
max_key_versions = 10

[audit]
log_path = "data/audit.log"
retention_days = 365
enable_chain = true
enable_signing = true

[hsm]
mode = "software"

[policy]
enable_rbac = true
enforce_https = true

[auth]
totp_issuer = "KMS"
# security_level = "level4"    # 等保四级模式（默认为 level3）
# anti_repudiation = true      # 抗抵赖模块（需 level4）

[trust]
# expected_binary_hash = "your-binary-sm3-hash"
# expected_config_hash = "your-config-sm3-hash"
"#
        .into()
    }
}
