# 研究：Rust 后端代码结构分析

- **查询**: 探索 KMS Rust 后端项目的代码结构，包括路由注册、Handler 目录、KeyManager trait/impl、模型/序列化、中间件链
- **范围**: internal
- **日期**: 2026-07-09

## 1. 项目概况

- **框架**: Axum 0.7（异步 Web 框架）
- **数据库**: SQLx + SQLite/PostgreSQL（通过 feature 切换）
- **序列化**: serde (JSON)
- **加密**: 国密 SM2/SM3/SM4 + AES-256-GCM + HKDF
- **HSM**: 三种实现（software/ PKCS#11 / SDF），默认 `software-hsm`
- **编译目标**: `kms-server`（`src/main.rs`）+ `kms-cli`（`src/bin/kms_cli.rs`）

### Cargo.toml 关键依赖

| 依赖 | 版本 | 用途 |
|---|---|---|
| `axum` | 0.7 | Web 框架 |
| `axum-server` | 0.7 (tls-rustls) | TLS 服务 |
| `tower` / `tower-http` | 0.4 / 0.5 | 中间件层 |
| `serde` / `serde_json` | 1 | JSON 序列化 |
| `sqlx` | 0.7 | SQLite/Postgres 异步数据库 |
| `libsm` | 0.6 | 国密 SM2/SM3/SM4 |
| `aes-gcm` | 0.10 | AES-256-GCM |
| `rustls` | 0.23 | TLS/mTLS |
| `cryptoki` | 0.6 (optional) | PKCS#11 HSM |
| `tss-esapi` | 7.7.0 (optional) | TPM 2.0 |
| `prometheus` | 0.13 (optional) | 监控指标 |

---

## 2. 路由注册（axum::Router）

**文件**: `src/api/routes.rs` — `build_router()` 函数 (第 39-93 行)

**方式**: `Router::new().route(...).route(...)` 链式注册，最后 `with_state(state)`

### 所有已注册 API 端点

#### 认证（Auth）— 需跳过中间件认证
| 方法 | 路径 | Handler 函数 | 说明 |
|------|------|-------------|------|
| POST | `/api/v1/auth/login` | `login` | 登录创建会话 |
| POST | `/api/v1/auth/totp-verify` | `totp_verify` | TOTP 双因子验证 |
| POST | `/api/v1/auth/recovery` | `recovery_verify` | 恢复码验证 |
| POST | `/api/v1/auth/recovery-codes` | `generate_recovery_codes` | 生成恢复码 |
| POST | `/api/v1/auth/tokens` | `create_token` | 创建 API Token |
| GET | `/api/v1/auth/tokens` | `list_tokens` | 列出 API Token |
| DELETE | `/api/v1/auth/tokens/:id` | `revoke_token` | 吊销 Token |
| GET | `/api/v1/auth/cert-info` | `cert_info` | mTLS 证书信息 |
| POST | `/api/v1/auth/logout` | `logout` | 注销会话 |

#### 密钥管理（Keys）
| 方法 | 路径 | Handler 函数 | 说明 |
|------|------|-------------|------|
| GET | `/api/v1/keys` | `list_keys` | 列出所有密钥 |
| POST | `/api/v1/keys` | `create_key` | 创建密钥 |
| GET | `/api/v1/keys/:id` | `get_key` | 获取单个密钥 |
| POST | `/api/v1/keys/:id/enable` | `enable_key` | 启用密钥 |
| POST | `/api/v1/keys/:id/disable` | `disable_key` | 禁用密钥 |
| POST | `/api/v1/keys/:id/rotate` | `rotate_key` | 轮换密钥（需审批） |
| POST | `/api/v1/keys/:id/archive` | `archive_key` | 归档密钥（需审批） |
| POST | `/api/v1/keys/:id/destroy` | `destroy_key` | 销毁密钥（需审批） |
| POST | `/api/v1/keys/:id/datakey` | `generate_data_key` | 生成数据密钥（DEK） |
| POST | `/api/v1/keys/:id/decrypt` | `decrypt_data_key` | 解密数据密钥 |
| POST | `/api/v1/keys/:id/acl` | `add_key_acl` | 添加 ACL 条目 |
| DELETE | `/api/v1/keys/:id/acl/:subject` | `remove_key_acl` | 移除 ACL 条目 |
| POST | `/api/v1/keys/:id/dependencies` | `add_key_dependency` | 添加密钥依赖 |
| DELETE | `/api/v1/keys/:id/dependencies/:dep_id` | `remove_key_dependency` | 移除密钥依赖 |
| GET | `/api/v1/keys/:id/dependents` | `list_key_dependents` | 列出密钥依赖者 |

#### 加密操作
| 方法 | 路径 | Handler 函数 | 说明 |
|------|------|-------------|------|
| POST | `/api/v1/encrypt` | `encrypt_with_key` | 使用指定密钥加密 |
| POST | `/api/v1/decrypt` | `decrypt_with_key` | 使用指定密钥解密 |

#### 审计
| 方法 | 路径 | Handler 函数 | 说明 |
|------|------|-------------|------|
| GET | `/api/v1/audit/logs` | `query_audit_logs` | 查询审计日志 |
| GET | `/api/v1/audit/verify` | `verify_audit_chain` | 验证审计链完整性 |

#### 双人复核审批
| 方法 | 路径 | Handler 函数 | 说明 |
|------|------|-------------|------|
| POST | `/api/v1/approvals` | `submit_approval` | 提交审批请求 |
| GET | `/api/v1/approvals/pending` | `list_pending_approvals` | 列出待审批请求 |
| POST | `/api/v1/approvals/:id/approve` | `approve_request` | 批准 |
| POST | `/api/v1/approvals/:id/reject` | `reject_request` | 驳回 |

#### 密钥导出/导入
| 方法 | 路径 | Handler 函数 | 说明 |
|------|------|-------------|------|
| POST | `/api/v1/keys/export` | `export_keys_handler` | 导出密钥（需审批） |
| POST | `/api/v1/keys/import` | `import_keys_handler` | 导入密钥（需审批） |

#### 管理接口（等保四级）
| 方法 | 路径 | Handler 函数 | 说明 |
|------|------|-------------|------|
| GET | `/api/v1/admin/blocklist` | `blocklist_handler` | 查看封禁列表 |
| POST | `/api/v1/admin/unblock/:target` | `blocklist_unblock_handler` | 解封目标 |

#### 监控
| 方法 | 路径 | Handler 函数 | 说明 |
|------|------|-------------|------|
| GET | `/api/v1/metrics` | `metrics_handler` | Prometheus 指标（feature=monitoring） |

#### 健康检查（无认证）
| 方法 | 路径 | Handler 函数 | 说明 |
|------|------|-------------|------|
| GET | `/api/v1/health` | `health_check` | 健康检查 |

---

## 3. Handler 文件路径及关键函数

项目中没有独立的 `handlers/` 目录，所有 handler 函数都定义在 `src/api/routes.rs` 中（以请求/响应结构体结尾）。

| 文件路径 | Handler 函数 | 功能摘要 |
|---|---|---|
| `src/api/routes.rs:209` | `login()` | 登录 → 创建会话，返回 TOTP Provisioning URI |
| `src/api/routes.rs:259` | `totp_verify()` | TOTP 双因子验证（含速率限制） |
| `src/api/routes.rs:126` | `recovery_verify()` | 恢复码验证，标记为已使用 |
| `src/api/routes.rs:164` | `generate_recovery_codes()` | 生成 5 个恢复码 |
| `src/api/routes.rs:1002` | `create_token()` | 创建 API Token |
| `src/api/routes.rs:1021` | `list_tokens()` | 列出所有 API Token |
| `src/api/routes.rs:1031` | `revoke_token()` | 吊销指定 Token |
| `src/api/routes.rs:194` | `cert_info()` | 获取 mTLS 证书信息 |
| `src/api/routes.rs:320` | `logout()` | 销毁会话 |
| `src/api/routes.rs:375` | `create_key()` | 创建密钥（SM4/SM2/AES256） |
| `src/api/routes.rs:419` | `list_keys()` | 列出所有密钥 |
| `src/api/routes.rs:435` | `get_key()` | 获取单个密钥 |
| `src/api/routes.rs:443` | `enable_key()` | 启用密钥 |
| `src/api/routes.rs:451` | `disable_key()` | 禁用密钥 |
| `src/api/routes.rs:459` | `rotate_key()` | 轮换密钥（需审批） |
| `src/api/routes.rs:467` | `archive_key()` | 归档密钥（需审批） |
| `src/api/routes.rs:477` | `destroy_key()` | 销毁密钥（需审批） |
| `src/api/routes.rs:505` | `generate_data_key()` | 生成信封加密 DEK |
| `src/api/routes.rs:541` | `decrypt_data_key()` | 解密 DEK 返回明文 |
| `src/api/routes.rs:581` | `encrypt_with_key()` | 用指定密钥加密（DEK+数据） |
| `src/api/routes.rs:626` | `decrypt_with_key()` | 用指定密钥解密 |
| `src/api/routes.rs:685` | `add_key_acl()` | 添加 ACL 条目 |
| `src/api/routes.rs:718` | `remove_key_acl()` | 移除 ACL 条目 |
| `src/api/routes.rs:822` | `add_key_dependency()` | 添加密钥依赖 |
| `src/api/routes.rs:838` | `remove_key_dependency()` | 移除密钥依赖 |
| `src/api/routes.rs:846` | `list_key_dependents()` | 列出依赖者 |
| `src/api/routes.rs:860` | `query_audit_logs()` | 查询审计日志 |
| `src/api/routes.rs:870` | `verify_audit_chain()` | 验证审计链 |
| `src/api/routes.rs:751` | `submit_approval()` | 提交双人复核申请 |
| `src/api/routes.rs:766` | `list_pending_approvals()` | 列出待审批 |
| `src/api/routes.rs:773` | `approve_request()` | 批准审批 |
| `src/api/routes.rs:792` | `reject_request()` | 驳回审批 |
| `src/api/routes.rs:960` | `export_keys_handler()` | 导出密钥（需审批） |
| `src/api/routes.rs:971` | `import_keys_handler()` | 导入密钥（需审批） |
| `src/api/routes.rs:890` | `blocklist_handler()` | 查看封禁列表 |
| `src/api/routes.rs:912` | `blocklist_unblock_handler()` | 解封 |
| `src/api/routes.rs:335` | `metrics_handler()` | Prometheus 指标 |
| `src/api/routes.rs:348` | `health_check()` | 健康检查 |

---

## 4. 核心密钥管理接口与实现

### 4.1 `KeyStore` trait — `src/key/store.rs:5-11`

```rust
#[async_trait]
pub trait KeyStore: Send + Sync {
    async fn create_key(&self, key: &Key) -> crate::Result<()>;
    async fn get_key(&self, key_id: &str) -> crate::Result<Key>;
    async fn list_keys(&self) -> crate::Result<Vec<Key>>;
    async fn update_key(&self, key: &Key) -> crate::Result<()>;
    async fn delete_key(&self, key_id: &str) -> crate::Result<()>;
}
```

### 4.2 `KeyStoreSqlite` — `src/key/store.rs:13-88`

SQLite 实现，使用 `serde_json` 序列化 `Key` 存储到 `keys` 表的 `data` 列。

### 4.3 `KeyManager` — `src/key/manager.rs:8-160`

| 方法 | 行号 | 功能 |
|---|---|---|
| `new(store)` | 14 | 构造，传入 Box<dyn KeyStore> |
| `create_key(name, spec, policy, owner)` | 21 | 创建新密钥 |
| `get_key(key_id)` | 34 | 获取密钥 |
| `list_keys()` | 38 | 列出所有密钥 |
| `enable_key(key_id)` | 42 | 启用（销毁/归档不可启用） |
| `disable_key(key_id)` | 53 | 禁用（销毁/归档不可禁用） |
| `rotate_key(key_id)` | 64 | 轮换（生成新版本，含 max_versions 清理） |
| `archive_key(key_id, dep_store)` | 103 | 归档（检查依赖 → PendingArchive） |
| `destroy_key(key_id, dep_store)` | 123 | 销毁（检查依赖+状态，清除版本材料） |
| `derive_cmk(key_material, key_id, version)` | 154 | 使用 SM3 HKDF 派生 CMK |

### 4.4 `KekProvider` trait — `src/crypto/traits.rs:35-41`

```rust
pub trait KekProvider: Send + Sync {
    fn name(&self) -> &str;
    fn wrap_key(&self, key_id: &str, key_version: u32, plaintext: &[u8]) -> CryptoResult<Vec<u8>>;
    fn unwrap_key(&self, key_id: &str, key_version: u32) -> CryptoResult<Vec<u8>>;
    fn generate_random(&self, length: usize) -> CryptoResult<Vec<u8>>;
    fn is_hardware_backed(&self) -> bool;
}
```

### 4.5 HSM Provider 实现

| 实现 | 文件 | 说明 |
|---|---|---|
| `SoftwareKekProvider` | `src/hsm/software_provider.rs:10` | SM3 派生 master_key → SM4 wrap/unwrap |
| `Pkcs11KekProvider` | `src/hsm/pkcs11_provider.rs` | PKCS#11 cryptoki 接口（feature=pkcs11-hsm） |
| `SdfKekProvider` | `src/hsm/sdf_provider.rs` | SDF 接口（feature=sdf-hsm） |

### 4.6 密钥生命周期状态

`src/key/types.rs:5-17`

```
Enabled → Disabled → PendingArchive → Archived → Destroyed
  ↑          ↑
  └───── Enable/Disable 循环
```

- `Enabled`: 可加密/解密
- `Disabled`: 仅可解密（已有密文保持可用）
- `PendingArchive`: 等待归档操作
- `Archived`: 密钥材料已安全删除
- `Destroyed`: 记录保留但材料不可恢复

---

## 5. 模型/序列化

全部使用 **serde JSON** 序列化（无 protobuf）。

### 5.1 密钥模型 — `src/key/types.rs`

| 结构体 | 行 | 字段 | 说明 |
|---|---|---|---|
| `KeyVersion` | 30 | version_number, key_material_hash, hsm_key_id, state, created_at, destroyed_at | 密钥版本 |
| `KeySpec` | 39 | algorithm, key_length, usage, extractable | 密钥规格 |
| `KeyPolicy` | 85 | rotation_days, expiration_days, max_versions, require_mfa_*, allowed_roles | 密钥策略 |
| `Key` | 96 | id, name, description, spec, policy, state, versions, current_version, created_at, updated_at, owner, tags, acl | 主密钥对象 |
| `KeyAclEntry` | 76 | subject, permission (Use/Admin/Full), role | ACL 条目 |
| `KeyAlgorithm` | 47 | Sm4, Sm2, Aes256, Rsa2048 | 算法枚举 |
| `KeyUsage` | 55 | EncryptDecrypt, SignVerify, KeyWrap, DeriveKey | 用途枚举 |
| `KeyPermission` | 64 | Use, Admin, Full | 权限等级 |

### 5.2 请求/响应模型 — `src/api/routes.rs`

| 结构体 | 行 | 用途 |
|---|---|---|
| `LoginRequest` | 96 | 登录：username + password |
| `LoginResponse` | 101 | session_id, totp_required, totp_provisioning_uri |
| `TotpVerifyRequest` | 253 | session_id + totp_code |
| `RecoveryVerifyRequest` | 109 | session_id + recovery_code |
| `CreateKeyRequest` | 356 | name, algorithm, key_length, description, rotation_days |
| `KeyResponse` | 365 | id, name, state, algorithm, current_version, created_at |
| `DataKeyResponse` | 497 | key_id, key_version, ciphertext, algorithm |
| `DecryptRequest` | 529 | key_id, key_version, ciphertext |
| `DecryptResponse` | 536 | plaintext |
| `CreateTokenRequest` | 985 | name, role, ttl_secs |
| `CreateTokenResponse` | 994 | id, token, hint |
| `HealthResponse` | 328 | status, version, hsm_mode |
| `EncryptWithKeyRequest` | 568 | key_id, plaintext |
| `AddAclRequest` | 672 | subject, permission, role |
| `AclResponse` | 679 | key_id + entries |
| `SubmitApprovalRequest` | 734 | action, resource, reason |
| `AddDependencyRequest` | 810 | dependent_key_id, version_number, description |
| `AuditQuery` | 854 | start_time, end_time |

### 5.3 审计模型 — `src/audit/logger.rs`

| 结构体 | 行 | 说明 |
|---|---|---|
| `AuditEvent` | 9 | event_id, timestamp, event_type, subject, action, resource, result, previous_hash, hash, signature → 防篡改审计链 |

### 5.4 审批模型 — `src/approval/mod.rs`

| 结构体 | 行 | 说明 |
|---|---|---|
| `ApprovalRequest` | 16 | id, action, resource, subject, reason, status (Pending/Approved/Rejected/Used), reviewed_by |
| `AuthContext` | `policy/types.rs:45` | subject, roles, admin_role, security_level, action, resource → 完整的鉴权上下文 |

### 5.5 加密模型 — `src/crypto/envelope.rs`

| 结构体 | 行 | 说明 |
|---|---|---|
| `EncryptedDataKey` | 10 | ciphertext, key_id, algorithm, key_version → 信封加密 DEK |
| `DataKey` | 18 | plaintext (Zeroizing) + encrypted |

---

## 6. 中间件链

中间件在 `src/main.rs:335-342` 中按以下顺序挂载：

```
请求进入
  ↓
1. request_tracking_middleware          (最外层 layer)
   - 生成 UUID request_id
   - 插入 X-Request-Id 响应头
   - 文件: src/api/middleware.rs:173-183
  ↓
2. auth_middleware                       (route_layer，带 AppState)
   - 跳过: /api/v1/health, /api/v1/auth/*
   - Bearer Token 验证（admin_token / token_store）
   - mTLS 身份提取（从 TlsIdentity extension）
   - 角色提取：X-Admin-Role 请求头
   - 安全等级提取：X-Security-Level 请求头
   - 策略引擎评估：PolicyEngine::evaluate()
   - TOTP 验证检查：需 X-Session-Id 且 totp_verified=true
   - 构建 AuthContext 并注入 request.extensions
   - 文件: src/api/middleware.rs:57-171
  ↓
3. mTLS 层                                (TLS 连接层)
   - MtlsAcceptor 包装 TcpStream → TlsStream
   - 提取客户端证书指纹 + subject
   - 注入 TlsIdentity 到 request.extensions
   - 文件: src/api/mtls.rs:77-113
  ↓
4. Axum Router                           (路由分发)
   - 文件: src/api/routes.rs:39-93
  ↓
5. Handler 执行
```

### 中间件实现细节

| 中间件 | 文件 | 行 | 功能 |
|---|---|---|---|
| `request_tracking_middleware` | `src/api/middleware.rs` | 173 | Request ID 追踪（注入 uuid 到 extensions + 响应头） |
| `auth_middleware` | `src/api/middleware.rs` | 57 | 认证鉴权核心 |
| `Auth::validate_token` | `src/api/middleware.rs` | 25 | Token 验证（admin_token + TokenStore） |
| `MtlsAcceptor` | `src/api/mtls.rs` | 77 | 接受 TLS 连接，提取客户端证书（mTLS） |
| `build_rustls_config` | `src/api/mtls.rs` | 115 | 构建 rustls ServerConfig（TLS/mTLS） |

### 跳过认证的路径前缀

- `src/api/middleware.rs:51` — `SKIP_AUTH_PREFIXES: &["/api/v1/health", "/api/v1/auth/"]`
- `src/api/middleware.rs:52` — `SKIP_TOTP_PREFIXES: &["/api/v1/auth/", "/api/v1/health"]`
- `src/api/middleware.rs:55` — `TOTP_OPTIONAL_PREFIXES: &["/api/v1/auth/recovery"]`

---

## 7. 其他关键模块

| 模块 | 文件 | 行 | 说明 |
|---|---|---|---|
| **策略引擎** | `src/policy/engine.rs` | 7 | ABAC + MAC + 角色（三权分立）三重策略评估 |
| **角色/标签** | `src/policy/roles.rs`, `src/policy/label.rs` | - | AdminRole 三权分立 + SecurityLevel 安全等级 |
| **审计日志** | `src/audit/logger.rs` | 70 | 带 SM3 哈希链 + SM2 签名的防篡改审计链 |
| **SQLite 审计存储** | `src/audit/sqlite_store.rs` | - | 审计日志持久化 |
| **Session 管理** | `src/auth/session.rs` | 15 | DashMap 内存会话，TTL 自动过期 |
| **TOTP 双因子** | `src/auth/totp.rs` | - | totp-rs，支持恢复码 |
| **Token 管理** | `src/auth/token.rs` | 21 | SQLite 持久化 API Token |
| **审批流程** | `src/approval/mod.rs` | 46 | ApprovalStore trait + SqliteApprovalStore |
| **密钥依赖** | `src/key/dependency.rs` | - | 密钥依赖关系追踪 |
| **入侵阻断** | `src/monitor/blocklist.rs` | 75 | 累进封禁（base 5min → max 24h） |
| **入侵检测** | `src/monitor/detector.rs` | - | 可疑行为检测引擎 |
| **监控指标** | `src/monitor/metrics.rs` | - | Prometheus 指标（feature=monitoring） |
| **TPM 可信根** | `src/trust/tpm.rs` | - | 等保四级 TPM 2.0 PCR 度量 |
| **证据导出** | `src/evidence/mod.rs` | - | 等保证据包导出 |
| **备份** | `src/backup/mod.rs` | - | 密钥导入/导出 + master seed 管理 |
| **数据库迁移** | `src/store/migrations.rs` | - | SQLx 数据库迁移 |
| **CLI 客户端** | `src/bin/kms_cli.rs` + `src/cli/` | - | CLI 管理工具（keys, auth, audit, crypto 等子命令） |

---

## 8. AppState 全局状态结构

**文件**: `src/api/routes.rs:18-34`

`AppState` 承载所有全局依赖，通过 `axum::extract::State` 注入到每个 handler：

```rust
pub struct AppState {
    pub key_manager: KeyManager,           // 密钥管理
    pub envelope: EnvelopeEncryption,       // 信封加密引擎
    pub kek_provider: Box<dyn KekProvider>, // KEK 提供者（HSM/软件）
    pub audit_logger: AuditLogger,          // 审计日志
    pub policy_engine: PolicyEngine,        // 策略引擎
    pub session_manager: Arc<SessionManager>, // 会话管理
    pub totp_secret_issuer: String,          // TOTP 发行人名称
    pub pool: SqlitePool,                    // 数据库连接池
    pub token_store: TokenStore,             // Token 存储
    pub approval_store: SqliteApprovalStore, // 审批存储
    pub dep_store: SqliteDependencyStore,    // 依赖存储
    pub blocklist: SharedBlocklist,          // 自动阻断
    pub tpm: Box<dyn TrustedPlatformModule>, // TPM 可信根
    pub started_at: Instant,                  // 启动时间
    pub totp_attempts: Arc<Mutex<HashMap<String, (u32, Instant)>>>,  // TOTP 速率限制
}
```

---

## 9. 架构总结

```
[CLI Tool] ──→ [kms-server (Axum 0.7)]
                  │
                  ├── Middleware Chain
                  │   ├── request_tracking (Request ID)
                  │   └── auth_middleware (Token/Session/TOTP → Policy → ACL)
                  │
                  ├── Router (40+ API endpoints)
                  │
                  ├── KeyManager
                  │   └── KeyStore (trait + SQLite impl, serde JSON)
                  │
                  ├── EnvelopeEncryption (SM4-GCM / AES-256-GCM + HKDF)
                  │   └── KekProvider (trait)
                  │       ├── SoftwareKekProvider (default)
                  │       ├── Pkcs11KekProvider (optional)
                  │       └── SdfKekProvider (optional)
                  │
                  ├── AuditLogger (SM3 hash chain + SM2 signature)
                  │
                  ├── PolicyEngine (ABAC + MAC + 三权分立)
                  │
                  ├── ApprovalStore (双人复核)
                  │
                  ├── Blocklist (入侵自动阻断)
                  │
                  └── TPM Provider (等保四级可信根)
```

---

## 10. 注意事项

- **无独立的 Handler 目录**：所有 handler 函数集中在 `src/api/routes.rs`（1041 行），随着更多端点增加可能需要拆分
- **所有序列化使用 JSON (serde)**：无 protobuf 或 msgpack
- **HSM feature gate**：PKCS#11 和 SDF 模式需对应 feature 编译
- **监控 feature gate**：Prometheus 指标、syslog 审计依赖 `monitoring` feature
- **等保四级**：TPM 通过 `tpm` feature 可选编译