# Research: Cosmian KMS CLI (ckms) 命令树结构

- **Query**: Cosmian KMS CLI 实现 — 子命令结构、功能特性、命令层次
- **Scope**: mixed（外部文档 + 源码分析）
- **Date**: 2026-07-09

## 源码位置

| 仓库 | 路径 | 说明 |
|---|---|---|
| `Cosmian/kms` | `crate/clients/ckms/` | **当前主 CLI** —— `ckms` 二进制在此构建，使用 Clap v4 |
| `Cosmian/kms` | `crate/clients/clap/` | **Clap 命令定义和动作实现** —— `KmsActions` 枚举及所有子命令处理 |
| `Cosmian/kms` | `crate/clients/client/` | KMS 客户端库（`cosmian_kms_client`） |
| `Cosmian/cli`（已归档） | `crate/cli/` | **旧版 CLI** —— 2026年3月后移至上述仓库 |

**仓库 URL**: https://github.com/Cosmian/kms

**技术栈**：
- Rust 语言，Clap v4 (`#[derive(Parser)]` / `#[derive(Subcommand)]`)
- 异步运行时: Tokio
- HTTP 客户端: reqwest
- KMIP 协议: cosmian_kmip crate
- 安装：`cargo install ckms`、DEB/RPM 包、或从 [Cosmian packages](https://package.cosmian.com/kms/) 下载

---

## 1. 顶层结构

```
ckms [OPTIONS] <COMMAND>
```

### 全局选项 (Options)

| 选项 | 环境变量 | 说明 |
|---|---|---|
| `-c, --conf-path <PATH>` | `CKMS_CONF_PATH` | 配置文件路径（TOML） |
| `--url <URL>` | `KMS_DEFAULT_URL` | KMS 服务端 URL |
| `--print-json` | - | 输出 KMIP JSON 请求/响应（调试用） |
| `--accept-invalid-certs` | - | 允许自签名/不安全证书 |
| `-H, --header <"Name: Value">` | `CLI_HEADER` | 自定义 HTTP 请求头（可重复） |
| `--proxy-url <URL>` | `CLI_PROXY_URL` | 代理 URL（HTTP/SOCKS） |
| `--proxy-basic-auth-username` | `CLI_PROXY_BASIC_AUTH_USERNAME` | 代理 Basic 认证用户名 |
| `--proxy-basic-auth-password` | `CLI_PROXY_BASIC_AUTH_PASSWORD` | 代理 Basic 认证密码 |
| `--proxy-custom-auth-header` | `CLI_PROXY_CUSTOM_AUTH_HEADER` | 代理自定义认证头 |
| `--proxy-exclusion-list` | `CLI_PROXY_NO_PROXY` | 代理排除列表 |
| `-h, --help` | - | 打印帮助信息 |
| `-V, --version` | - | 打印版本信息 |

### 配置文件

配置文件搜索顺序：
1. `CKMS_CONF` 环境变量指定的路径
2. `--conf-path` / `-c` CLI 参数
3. `~/.cosmian/ckms.toml`（用户级别默认）
4. `/etc/cosmian/ckms.toml`（系统级别备用）

可使用 `ckms configure` 交互式命令创建配置。

---

## 2. 完整子命令树

### 2.1 访问控制

#### `ckms access-rights`
管理用户对加密对象的访问权限。

```
ckms access-rights
├── grant      授权用户访问对象
├── revoke     撤销用户访问权限
├── list       列出对象的访问权限
├── owned      列出当前用户拥有的权限
└── obtained   列出当前用户获得的权限
```

### 2.2 属性管理

#### `ckms attributes`
获取/设置/删除/修改 KMIP 对象属性。

```
ckms attributes
├── get      获取对象的 KMIP 属性
├── set      设置对象的 KMIP 属性
├── delete   删除对象的 KMIP 属性
└── modify   修改对象的 KMIP 属性
```

### 2.3 云服务集成

#### `ckms azure`
Azure 特殊交互支持。

```
ckms azure byok
├── import   将密钥导入 Azure Key Vault（BYOK）
└── export   从 Azure Key Vault 导出密钥
```

#### `ckms aws`
AWS 特殊交互支持。

```
ckms aws byok
├── import   将密钥导入 AWS KMS（BYOK）
└── export   从 AWS KMS 导出密钥
```

### 2.4 基准测试

#### `ckms bench`
使用 Criterion 库运行基准测试（统计分析）。

**参数**：`<out-dir>` — 输出目录

### 2.5 密码学算法分组

#### `ckms cc` *(非 FIPS 模式)* — **Covercrypt（后量子策略加密）**
管理 Covercrypt 密钥和策略，旋转属性，加密/解密数据。

```
ckms cc
├── keys
│   ├── activate                 激活密钥
│   ├── create-master-key-pair   创建主密钥对（需要策略文件）
│   ├── create-user-key          创建用户解密密钥
│   ├── export                   导出密钥
│   ├── import                   导入密钥
│   ├── wrap                     密钥封装（密钥级加密）
│   ├── unwrap                   密钥解封
│   ├── revoke                   撤销密钥
│   ├── destroy                  销毁密钥
│   ├── rekey                    密钥轮换（Re-Key）
│   └── prune                    清理旧密钥版本
├── access-structure
│   ├── view                    查看访问策略结构
│   ├── add-attribute           添加策略属性
│   ├── remove-attribute        移除策略属性
│   ├── disable-attribute       禁用策略属性
│   └── rename-attribute        重命名策略属性
├── encrypt                      Covercrypt 加密数据
└── decrypt                      Covercrypt 解密数据
```

#### `ckms fpe` *(非 FIPS 模式)* — **FPE（格式保留加密）**
管理 FPE 密钥，基于 KMIP Encrypt/Decrypt 执行格式保留加密/解密。

```
ckms fpe
├── keys
│   ├── create   创建 FPE 密钥
│   ├── export   导出 FPE 密钥
│   ├── import   导入 FPE 密钥
│   ├── wrap     封装 FPE 密钥
│   ├── unwrap   解封 FPE 密钥
│   ├── revoke   撤销 FPE 密钥
│   └── destroy  销毁 FPE 密钥
├── encrypt      FPE 加密（格式保留）
└── decrypt      FPE 解密
```

#### `ckms pqc` *(非 FIPS 模式)* — **后量子密码学**
管理后量子密钥（ML-KEM, ML-DSA, Hybrid KEM, SLH-DSA），封装/解封/签名/验证。

```
ckms pqc
├── keys
│   ├── activate   激活密钥
│   ├── create     创建后量子密钥（指定算法类型）
│   ├── export     导出密钥
│   ├── import     导入密钥
│   ├── wrap       封装密钥
│   ├── unwrap     解封密钥
│   ├── revoke     撤销密钥
│   └── destroy    销毁密钥
├── encrypt        后量子加密
├── decrypt        后量子解密
├── sign           后量子签名
└── sign-verify    后量子签名验证
```

#### `ckms tokenize` *(非 FIPS 模式)* — **数据匿名化**
匿名化工具：哈希/噪声/词掩码/模式掩码/聚合/缩放。

```
ckms tokenize
├── hash                哈希数据
├── noise               添加噪声
├── word-mask           词掩码
├── word-tokenize       词标记化
├── word-pattern-mask   词模式掩码
├── aggregate-number    数字聚合
├── aggregate-date      日期聚合
└── scale-number        数字缩放
```

#### `ckms certificates` — **证书管理（PKI）**
管理证书：创建、导入、销毁、撤销、加密和解密。

```
ckms certificates
├── activate      激活证书
├── certify       签发证书（CA 签名）
├── decrypt       使用证书解密
├── encrypt       使用证书加密
├── export        导出证书（PKCS#12 / PEM 等）
├── import        导入证书
├── revoke        撤销证书
├── destroy       销毁证书
└── validate      验证证书
```

#### `ckms cng` — **Windows CNG KSP**
管理 Windows CNG 密钥存储提供程序。

```
ckms cng
├── register      注册 CNG KSP
├── unregister    注销 CNG KSP
├── status        查看 KSP 状态
├── list-keys     列出 KSP 中的密钥
└── verify        验证 CNG 集成
```

#### `ckms ec` — **椭圆曲线密码**
管理椭圆曲线密钥，使用 ECIES 加密/解密数据。

```
ckms ec
├── keys
│   ├── activate   激活密钥
│   ├── create     创建 EC 密钥对（指定曲线）
│   ├── export     导出密钥
│   ├── import     导入密钥
│   ├── wrap       封装密钥
│   ├── unwrap     解封密钥
│   ├── revoke     撤销密钥
│   └── destroy    销毁密钥
├── encrypt        ECIES 加密
├── decrypt        ECIES 解密
├── sign           EC 签名
└── sign-verify    EC 签名验证
```

#### `ckms rsa` — **RSA 密码**
管理 RSA 密钥，加密/解密数据。

```
ckms rsa
├── keys
│   ├── activate   激活密钥
│   ├── create     创建 RSA 密钥对（指定位数）
│   ├── export     导出密钥
│   ├── import     导入密钥
│   ├── wrap       封装密钥
│   ├── unwrap     解封密钥
│   ├── revoke     撤销密钥
│   └── destroy    销毁密钥
├── encrypt        RSA 加密
├── decrypt        RSA 解密
├── sign           RSA 签名
└── sign-verify    RSA 签名验证
```

#### `ckms sym` — **对称密钥**
管理对称密钥，加密/解密数据。

```
ckms sym
├── keys
│   ├── activate   激活密钥
│   ├── create     创建对称密钥（AES 等，可指定位数）
│   ├── re-key     密钥轮换
│   ├── export     导出密钥
│   ├── import     导入密钥
│   ├── wrap       封装密钥
│   ├── unwrap     解封密钥
│   ├── revoke     撤销密钥
│   └── destroy    销毁密钥
├── encrypt        对称加密（AES-GCM 等）
└── decrypt        对称解密
```

### 2.6 其他加密操作

#### `ckms derive-key`
从已有密钥派生新密钥。

#### `ckms hash`
哈希任意数据。

#### `ckms mac`
MAC 工具：计算或验证 MAC 值。

```
ckms mac
├── compute   计算 MAC
└── verify    验证 MAC
```

#### `ckms rng`
随机数生成工具：获取随机字节或播种 RNG。

```
ckms rng
├── retrieve   获取随机字节
└── seed       播种 RNG
```

#### `ckms opaque-object`
创建、导入、导出、撤销和销毁 Opaque 对象（任意二进制数据）。

```
ckms opaque-object
├── activate   激活对象
├── create     创建 Opaque 对象
├── export     导出对象
├── import     导入对象
├── revoke     撤销对象
└── destroy    销毁对象
```

#### `ckms pkcs11`
验证 PKCS#11 共享库集成。

```
ckms pkcs11
└── verify    验证 PKCS#11 共享库
```

#### `ckms secret-data`
创建、导入、导出和销毁 Secret Data（机密数据对象）。

```
ckms secret-data
├── activate   激活
├── create     创建
├── export     导出
├── import     导入
├── wrap       封装
├── unwrap     解封
├── revoke     撤销
└── destroy    销毁
```

### 2.7 Google 集成

#### `ckms google`
管理 Google 元素（Gmail API 集成）。

```
ckms google
├── key-pairs
│   ├── get         获取密钥对
│   ├── list        列出所有密钥对
│   ├── enable      启用密钥对
│   ├── disable     禁用密钥对
│   ├── obliterate  彻底删除密钥对
│   └── create      创建密钥对
└── identities
    ├── get         获取身份
    ├── list        列出身份
    ├── insert      插入身份
    ├── delete      删除身份
    └── patch       更新身份
```

### 2.8 定位和搜索

#### `ckms locate`
在 KMS 中定位加密对象。支持通过标签、ID、类型等条件查找。

### 2.9 认证和会话

#### `ckms login`
使用 OAuth2 授权码流程登录 KMS 的 Identity Provider。
- 支持 PKCE（Proof Key for Code Exchange）
- 启动浏览器进行交互式登录
- 自动将 Access Token 保存到配置

#### `ckms logout`
登出 Identity Provider，从配置文件移除 Access Token。

### 2.10 服务端操作

#### `ckms server`
服务端相关命令。

```
ckms server
├── version           查看服务器版本信息
├── discover-versions 发现支持的 KMIP 协议版本
└── query             查询服务器能力和元数据
```

### 2.11 工具命令

#### `ckms markdown`
以 Markdown 格式重新生成 CLI 文档。
**参数**：`<markdown-file>` — 输出文件路径

#### `ckms configure`
交互式配置向导，创建/更新 `ckms.toml`。
支持配置：
- 服务器 URL
- 认证方式（无认证 / Access Token / TLS 证书 / OAuth2）
- 代理设置
- 自定义 HTTP 头

#### `ckms help`
打印帮助信息或指定子命令的帮助。

---

## 3. Clap 命令架构（源码实现）

### 3.1 顶层定义（`commands.rs`）

```rust
// crate/clients/ckms/src/commands.rs

#[derive(Parser)]
pub struct Cli {
    #[arg(short, env = "CKMS_CONF_PATH", long)]
    conf_path: Option<PathBuf>,

    #[command(subcommand)]
    pub command: CliCommands,

    #[arg(long, env = "KMS_DEFAULT_URL", action)]
    pub url: Option<String>,

    #[arg(long)]
    pub print_json: bool,

    #[arg(long)]
    pub accept_invalid_certs: bool,

    #[clap(flatten)]
    pub headers: HeadersConfig,

    #[clap(flatten)]
    pub proxy: ProxyConfig,
}

#[derive(Subcommand)]
pub enum CliCommands {
    #[clap(flatten)]
    Kms(KmsActions),              // 所有 KMS 操作
    Markdown(MarkdownAction),     // 生成文档
    Configure,                    // 配置向导
}
```

### 3.2 KmsActions 枚举

```rust
// crate/clients/clap/src/actions/kms_actions.rs

#[derive(Subcommand)]
pub enum KmsActions {
    AccessRights(AccessAction),
    Attributes(AttributesCommands),
    Azure(AzureCommands),
    Aws(AwsCommands),
    Bench(BenchAction),
    #[cfg(feature = "non-fips")]
    Cc(CovercryptCommands),       // 仅在非 FIPS 模式下可用
    #[cfg(feature = "non-fips")]
    Fpe(FpeCommands),             // 仅在非 FIPS 模式下可用
    #[cfg(feature = "non-fips")]
    Pqc(PqcCommands),             // 仅在非 FIPS 模式下可用
    #[cfg(feature = "non-fips")]
    Tokenize(TokenizeCommands),   // 仅在非 FIPS 模式下可用
    Certificates(CertificatesCommands),
    Cng(CngCommands),
    DeriveKey(DeriveKeyAction),
    Ec(EllipticCurveCommands),
    Google(GoogleCommands),
    Locate(LocateObjectsAction),
    Login(LoginAction),
    Logout,
    Hash(HashAction),
    Mac(MacCommands),
    Rng(RngAction),
    Server(ServerCommands),
    Rsa(RsaCommands),
    OpaqueObject(OpaqueObjectCommands),
    Pkcs11(Pkcs11Commands),
    SecretData(SecretDataCommands),
    Sym(SymmetricCommands),
}
```

### 3.3 源码目录结构

```
crate/clients/clap/src/actions/
├── mod.rs
├── kms_actions.rs          # KmsActions 枚举
├── access.rs               # AccessRights
├── attributes/             # Attributes 子命令
├── aws/                    # AWS 相关
├── azure/                  # Azure 相关
├── bench/                  # 基准测试
├── certificates/           # 证书管理
├── cng.rs                  # Windows CNG
├── cng_verify.rs           # CNG 验证
├── console.rs              # 控制台输出
├── cover_crypt/            # Covercrypt 子命令
├── derive_key/             # 密钥派生
├── elliptic_curves/        # EC 密钥管理
├── fpe/                    # FPE 子命令
├── google/                 # Google 集成
├── hash.rs                 # 哈希
├── labels.rs               # 标签处理
├── login.rs                # 登录/注销
├── mac.rs                  # MAC 工具
├── opaque_object/          # Opaque 对象
├── pkcs11.rs               # PKCS#11 验证
├── pkcs11_verify.rs        # PKCS#11 验证细节
├── pqc/                    # 后量子密钥
├── rng.rs                  # RNG 工具
├── rsa/                    # RSA 密钥管理
├── secret_data/            # Secret Data
├── shared/                 # 共享组件（locate 等）
├── symmetric/              # 对称密钥
├── tokenize/               # 匿名化工具
└── version.rs              # 版本查询
```

### 3.4 二进制入口（`main.rs`）

```rust
// crate/clients/ckms/src/main.rs
// 使用 32MB 栈空间线程 + Tokio 多线程运行时
// 目的是避免 Windows 上解析 KMIP/TTLV 深度嵌套结构时栈溢出
fn main() {
    let handle = std::thread::Builder::new()
        .name("ckms-main".into())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(16 * 1024 * 1024)
                .build()
                .expect("failed to build tokio runtime");
            rt.block_on(ckms_main())
        })
        .expect("failed to spawn ckms main thread");
    // ...
}
```

---

## 4. 认证支持

CLI 支持以下认证方式（配置在 `ckms.toml` 中）：

| 方法 | 配置项 | 说明 |
|---|---|---|
| 无认证 | 仅 `server_url` | 开发环境 |
| Access Token | `access_token` | 简单 API 令牌 |
| TLS 客户端证书 (PEM) | `tls_client_pem_cert_path` + `tls_client_pem_key_path` | FIPS 兼容 |
| TLS 客户端证书 (PKCS#12) | `tls_client_pkcs12_path` + `tls_client_pkcs12_password` | 非 FIPS |
| OAuth2/OIDC | `oauth2_conf` 段 | SSO + Identity Provider |
| 数据库密钥 | `database_secret` | 加密数据库访问 |

---

## 5. 关键设计要点

1. **Clap v4 派生宏**：所有命令使用 `#[derive(Parser)]` 和 `#[derive(Subcommand)]`，通过 Rust 的类型系统提供编译时保证。

2. **扁平化 vs 层级化混合**：顶层通过 `CliCommands -> KmsActions` 两层嵌套达到扁平效果，`KmsActions` 各变体各自拥有子命令结构。

3. **Feature gate 控制**：`cc`, `fpe`, `pqc`, `tokenize` 四个命令组使用 `#[cfg(feature = "non-fips")]` 条件编译，FIPS 模式下不编译。

4. **KMIP 2.1 协议**：所有加密操作最终转化为 KMIP 2.1 JSON TTLV 请求发送给 KMS 服务端。

5. **交互式配置**：`ckms configure` 使用 `dialoguer` crate 实现交互式引导。

---

## 6. 参考资料

- **官方 CLI 文档**: https://docs.cosmian.com/kms_clients/cli/main_commands/
- **使用指南**: https://docs.cosmian.com/kms_clients/usage/
- **GitHub 仓库**: https://github.com/Cosmian/kms
- **crates.io**: https://crates.io/crates/cosmian_kms_cli
- **配置示例**: https://docs.cosmian.com/kms_clients/configuration/
- **认证文档**: https://docs.cosmian.com/kms_clients/authentication/
