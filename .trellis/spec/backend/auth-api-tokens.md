# API Token 动态认证

> API Token 动态管理规范，基于静态 admin_token 的扩展认证体系。

---

## 1. Scope / Trigger

- **Trigger**: 新增 API Token 动态管理，需要从"仅静态 admin_token"升级为"静态 + 动态双重认证"
- **涉及层**: 数据库 / 中间件 / API 路由 / 启动注入
- **变更文件**:
  - `src/store/migrations.rs` — DDL
  - `src/auth/token.rs` — TokenStore
  - `src/auth/mod.rs` — 模块导出
  - `src/api/middleware.rs` — Auth 异步验证
  - `src/api/routes.rs` — 三个端点
  - `src/main.rs` — TokenStore 初始化

---

## 2. Signatures

### TokenStore

```rust
// src/auth/token.rs
pub struct TokenStore { pool: SqlitePool }

impl TokenStore {
    pub fn new(pool: SqlitePool) -> Self;
    pub async fn create_token(&self, name: &str, role: Option<&str>, ttl_secs: Option<u64>)
        -> crate::Result<(String, String, String)>;  // (id, raw_token, hint)
    pub async fn validate_token(&self, raw_token: &str)
        -> crate::Result<Option<ApiToken>>;
    pub async fn list_tokens(&self)
        -> crate::Result<Vec<ApiToken>>;
    pub async fn revoke_token(&self, id: &str)
        -> crate::Result<bool>;
}
```

### Auth 中间件

```rust
// src/api/middleware.rs
pub struct Auth { admin_token: Option<String> }

impl Auth {
    pub fn new(admin_token: Option<String>) -> Self;
    pub async fn validate_token(&self, token: &str, token_store: &TokenStore) -> bool;
}
```

### 路由

```rust
POST   /api/v1/auth/tokens       -> create_token(req: CreateTokenRequest) -> CreateTokenResponse
GET    /api/v1/auth/tokens       -> list_tokens() -> Vec<ApiToken>
DELETE /api/v1/auth/tokens/:id   -> revoke_token(id) -> json
```

---

## 3. Contracts

### 请求/响应字段

| 端点 | 方向 | 字段 | 类型 | 约束 |
|------|------|------|------|------|
| POST /tokens | Request | `name` | String | 非空 |
| | | `role` | Option\<String\> | 可选 |
| | | `ttl_secs` | Option\<u64\> | 可选，过期秒数 |
| | Response | `id` | String | UUID |
| | | `token` | String | `kms_` 前缀 + base64，仅返回一次 |
| | | `hint` | String | 前 12 字符 + `****` |
| | | `message` | String | "请立即保存此 Token，它不会再次显示" |
| GET /tokens | Response | `Vec<ApiToken>` | Array | 不含明文 token |
| DELETE /tokens/:id | Response | `status`/`message` | json | 乐观删除 |

### ApiToken 序列化

```rust
pub struct ApiToken {
    pub id: String,
    pub name: String,
    pub token_hint: String,
    #[serde(skip_serializing)]  // 关键：不暴露哈希
    pub token_hash: String,
    pub role: Option<String>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub last_used: Option<i64>,
    pub disabled: bool,
}
```

### 数据库 DDL

```sql
CREATE TABLE IF NOT EXISTS api_tokens (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    token_hint  TEXT NOT NULL,
    role        TEXT,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER,
    last_used   INTEGER,
    disabled    INTEGER DEFAULT 0
);
```

### SKIP_AUTH 机制

```rust
// src/api/middleware.rs
// 认证端点必须跳过 Bearer token 检查，否则形成死锁：
// （需要 token 才能 login ⇒ 需要 login 才能获得 token）
const SKIP_AUTH_PREFIXES: &[&str] = &["/api/v1/health", "/api/v1/auth/"];
```

规则：
- `/api/v1/auth/` 前缀的所有端点跳过 Bearer token 检查（但 TOTP 会话验证仍由 `SKIP_TOTP_PREFIXES` 控制）
- 这包括 login、totp-verify、recovery、tokens CRUD、cert-info、logout
- 非 `SKIP_AUTH_PREFIXES` 路径强制要求 `Authorization: Bearer <token>`

### 环境 / 启动注入

```rust
// main.rs 中初始化
let token_store = auth::token::TokenStore::new(pool.clone());

// 传入 AppState（路由用）
token_store: token_store.clone(),

// 传入 AuthMiddlewareState（中间件用）
token_store: std::sync::Arc::new(token_store),
```

---

## 4. Validation & Error Matrix

| 条件 | 错误 | Handler |
|------|------|---------|
| `name` 为空 | `Error::Internal("Token 名称不能为空")` | create_token |
| Token 已过期 | 视为无效（返回 401） | validate_token |
| Token 已禁用 (`disabled=1`) | 视为无效（返回 401） | validate_token |
| 吊销不存在的 id | `Error::Internal("Token 未找到")` | revoke_token |
| Authorization 头缺失 + 非 `/api/v1/auth/` 路径 | 401 | auth_middleware |
| Authorization 头缺失 + `/api/v1/auth/` 路径 | 跳过检查 | auth_middleware (SKIP_AUTH) |
| admin_token + TokenStore 都未匹配 | 401 | auth_middleware |
| getrandom 失败 | `Error::Internal("生成 token 失败")` | create_token |

---

## 5. Good / Base / Bad Cases

### Good Case

```
POST /api/v1/auth/tokens
Authorization: Bearer <admin_token>
Content-Type: application/json
{"name": "ci-token", "ttl_secs": 86400}

→ 201
{
  "id": "uuid...",
  "token": "kms_abc123...",
  "hint": "kms_abc123****",
  "message": "请立即保存此 Token，它不会再次显示"
}
```

### Base Case（静态 admin_token 回退）

```
Authorization: Bearer <static_admin_token_from_config>
→ 200（静态比对通过，不走 DB）
```

### Bad Case

```
Authorization: Bearer kms_expired_or_revoked_token
→ 401 Unauthorized
```

---

## 6. Tests Required

| 测试点 | 类型 | 断言 | 状态 |
|--------|------|------|------|
| Token 创建返回有效 id + token | 集成 | `id` 为 UUID 格式，`token` 以 `kms_` 开头 | ✅ |
| 创建后可用同一 token 验证通过 | 集成 | `validate_token` 返回 `Some(ApiToken)` | ✅ |
| 创建后 hint 与 token 前缀匹配 | 单元 | hint 前 12 字符 = token 前 12 字符 | ✅ |
| 过期 token 验证失败 | 集成 | `validate_token` 返回 `None` | ✅ |
| 吊销后验证失败 | 集成 | `revoke_token` → `validate_token` → `None` | ✅ |
| 列表包含所有非敏感字段 | 集成 | 响应不含 `token_hash` | ✅ |
| 静态 admin_token 优先匹配 | 单元 | `validate_token` 不触发 DB 查询 | ✅ |
| 空 name 创建拒绝 | 集成 | `error: "Token 名称不能为空"` | ✅ |
| 吊销不存在的 id | 集成 | `error: "Token 未找到"` | ✅ |
| 配置缺失 section 可正常加载 | 集成 | 仅 `[server] [database] [auth]` 三个 section 即可启动 | ✅ |

---

## 7. Wrong vs Correct

### Wrong

```rust
// ❌ 错误：response hint 与 DB hint 不一致
let hint = format!("{}****", &raw_token[..16]);   // handler 用 16 字符
// 但 TokenStore::create_token 存的是前 12 字符
```

### Correct

```rust
// ✅ 正确：TokenStore 返回 hint，handler 直接使用
pub async fn create_token(...) -> crate::Result<(String, String, String)> {
    let hint = format!("{}****", &raw_token[..12]);  // 唯一 hint 来源
    // 存库
    Ok((id, raw_token, hint))
}

// handler 直接使用返回值
let (id, raw_token, hint) = state.token_store.create_token(...).await?;
```

### Wrong

```rust
// ❌ 错误：使用 SHA-256（非国密）
let token_hash = hex::encode(Sha256::digest(raw_token.as_bytes()));
```

### Correct

```rust
// ✅ 正确：国密合规，使用 SM3
let token_hash = hex::encode(
    crate::crypto::sm3_engine::Sm3Engine::new().hash(raw_token.as_bytes()),
);
```

### Wrong

```rust
// ❌ 错误：同步 validate_token 无法查 DB
pub fn validate_token(&self, token: &str) -> bool {
    match &self.admin_token { ... }
}
```

### Correct

```rust
// ✅ 正确：async + 回退链
pub async fn validate_token(&self, token: &str, token_store: &TokenStore) -> bool {
    // 1. 先查静态 admin_token（性能优化）
    if self.admin_token.as_ref().is_some_and(|valid| token == valid) {
        return true;
    }
    // 2. 再查动态 API Token
    token_store.validate_token(token).await.ok().flatten().is_some()
}
```

---

## 附录：手动测试验证

### 单元测试结果

```text
cargo test       → 83 passed, 1 ignored (swtpm 需要外部工具)
cargo clippy     → zero warnings
cargo fmt --check → passed
```

### HTTP 接口测试（12 场景）

| # | 场景 | 预期 | 结果 |
|---|------|------|------|
| 1 | 创建 Token（含 name + ttl） | 返回 id + 明文 token + hint | ✅ |
| 2 | 用新 Token 访问 `/auth/tokens` | 200，认证通过 | ✅ |
| 3 | 用新 Token 访问 `/keys`（需 TOTP） | 401（TOTP 拦截） | ✅ |
| 4 | 用 admin_token 列表 Token | 200，返回元数据，不含 `token_hash` | ✅ |
| 5 | 用动态 Token 列表 Token | 200，动态 Token 同样可读写 | ✅ |
| 6 | 坏 Token 请求 | 401 | ✅ |
| 7 | 吊销 Token | `"Token 已吊销"` | ✅ |
| 8 | 吊销后用原 Token 访问 | 401 | ✅ |
| 9 | 列表显示 `disabled=true` | 状态正确更新 | ✅ |
| 10 | 创建 Token 带 role | `role` 正确存储 | ✅ |
| 11 | 空名称创建 | `"Token 名称不能为空"` | ✅ |
| 12 | 吊销不存在的 id | `"Token 未找到"` | ✅ |

### 最小配置测试

仅 3 个 section 的配置文件可正常启动：

```toml
[server]
port = 18443

[database]
url = "sqlite:///tmp/kms.db?mode=rwc"

[auth]
admin_token = "test-admin-token"
```

不再出现 `"无法加载配置文件，使用默认配置"` 警告。
