use clap::Subcommand;

#[derive(Subcommand)]
pub enum CliCommand {
    Health,
    Auth {
        #[command(subcommand)]
        action: AuthAction,
    },
    Keys {
        #[command(subcommand)]
        action: KeyAction,
    },
    Encrypt {
        key_id: String,
        #[arg(long, help = "明文文本（与 --input 二选一）")]
        plaintext: Option<String>,
        #[arg(long, help = "输入文件（与 --plaintext 二选一）")]
        input: Option<String>,
        #[arg(long, help = "输出文件（可选，默认 stdout）")]
        output: Option<String>,
    },
    Decrypt {
        key_id: String,
        #[arg(long, help = "密文 hex（与 --input 二选一）")]
        ciphertext: Option<String>,
        #[arg(long, help = "输入文件（与 --ciphertext 二选一）")]
        input: Option<String>,
        #[arg(long, help = "输出文件（可选，默认 stdout）")]
        output: Option<String>,
    },
    Debug {
        #[command(subcommand)]
        action: DebugAction,
    },
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
    Approvals {
        #[command(subcommand)]
        action: ApprovalAction,
    },
    Admin {
        #[command(subcommand)]
        action: AdminAction,
    },
    /// 配置管理
    Configure {
        #[command(subcommand)]
        action: ConfigureAction,
    },
    /// 服务器本地命令
    Server {
        #[command(subcommand)]
        action: ServerAction,
    },
    /// 抗抵赖证据签名/验证
    Evidence {
        #[command(subcommand)]
        action: EvidenceAction,
    },
}

#[derive(Subcommand)]
pub enum AuthAction {
    Login {
        username: String,
    },
    TotpVerify {
        code: String,
        #[arg(long)]
        session: String,
    },
    Tokens {
        #[command(subcommand)]
        action: TokenAction,
    },
    TotpCode {
        secret: String,
    },
    TotpSetup {
        username: String,
    },
    Logout {
        #[arg(long)]
        session: String,
    },
    Recovery {
        code: String,
        #[arg(long)]
        session: String,
    },
    RecoveryCodes,
    CertInfo,
}

#[derive(Subcommand)]
pub enum TokenAction {
    List,
    Create { name: String },
    Delete { id: String },
}

#[derive(Subcommand)]
pub enum KeyAction {
    List,
    Create {
        name: String,
        #[arg(long, default_value = "Sm4")]
        key_type: String,
        #[arg(long, default_value_t = String::new())]
        usage: String,
    },
    Get {
        id: String,
    },
    Enable {
        id: String,
    },
    Disable {
        id: String,
    },
    Rotate {
        id: String,
    },
    Archive {
        id: String,
    },
    Destroy {
        id: String,
    },
    Datakey {
        id: String,
    },
    Decrypt {
        id: String,
        #[arg(long)]
        ciphertext: String,
    },
    Acl {
        #[command(subcommand)]
        action: AclAction,
    },
    Dependencies {
        #[command(subcommand)]
        action: DepAction,
    },
    Dependents {
        id: String,
    },
    Export {
        id: String,
        #[arg(long)]
        output: Option<String>,
    },
    Import {
        #[arg(long)]
        input: String,
    },
}

#[derive(Subcommand)]
pub enum AclAction {
    Add {
        id: String,
        subject: String,
        #[arg(long, default_value = "Use")]
        permission: String,
    },
    Remove {
        id: String,
        subject: String,
    },
}

#[derive(Subcommand)]
pub enum DepAction {
    Add { id: String, dep_id: String },
    Remove { id: String, dep_id: String },
}

#[derive(Subcommand)]
pub enum DebugAction {
    Sm3 {
        data: String,
    },
    Sha256 {
        data: String,
    },
    Rng {
        bytes: u32,
    },
    Hmac {
        key: String,
        data: String,
        #[arg(long, default_value = "sha256")]
        algorithm: String,
    },
}

#[derive(Subcommand)]
pub enum AuditAction {
    Logs {
        #[arg(long, help = "起始时间戳（秒），映射 InitialDate")]
        since: Option<i64>,
        #[arg(long, help = "截止时间戳（秒），映射 LastChangeDate")]
        until: Option<i64>,
    },
    Verify,
}

#[derive(Subcommand)]
pub enum ApprovalAction {
    /// 提交审批请求
    Submit {
        key_id: String,
        #[arg(long)]
        operation: String,
        #[arg(long)]
        reason: Option<String>,
    },
    Pending,
    Approve {
        id: String,
    },
    Reject {
        id: String,
    },
}

#[derive(Subcommand)]
pub enum ConfigureAction {
    /// 生成 ~/.kms/config.toml 配置模板
    Init,
    /// 显示当前配置
    Show,
}

#[derive(Subcommand)]
pub enum ServerAction {
    /// 计算本地二进制文件 SM3 哈希
    HashSelf {
        /// 二进制文件路径（默认当前可执行文件）
        path: Option<String>,
    },
    /// 导出合规证据包到目录
    Evidence {
        /// 输出目录
        dir: String,
    },
}

#[derive(Subcommand)]
pub enum EvidenceAction {
    /// 生成抗抵赖签名证据
    Sign {
        key_id: String,
        #[arg(long, help = "待签名数据（hex 编码）")]
        data: String,
    },
    /// 验证抗抵赖证据
    Verify { evidence_id: String },
}

#[derive(Subcommand)]
pub enum AdminAction {
    Blocklist,
    Unblock { target: String },
}
