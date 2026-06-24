# KMS 详细设计文档

> 国密合规密钥管理系统 — Rust 实现
> 版本: 0.1.0 | 状态: 等保三级 + 等保四级功能完备

---

## 目录

- [1. 设计目标与约束](#1-设计目标与约束)
- [2. 设计决策](#2-设计决策)
- [3. 安全架构概览](#3-安全架构概览)
- [4. 数据模型](#4-数据模型)
- [5. API 设计](#5-api-设计)
  - [5.1 密钥管理 API](#51-密钥管理-api)
  - [5.2 数据密钥 API](#52-数据密钥-api)
  - [5.3 数据加解密 API](#53-数据加解密-api)
  - [5.4 审计 API](#54-审计-api)
  - [5.5 认证 API](#55-认证-api)
  - [5.6 入侵检测 API](#56-入侵检测-api)
  - [5.7 备份恢复 API](#57-备份恢复-api)
  - [5.8 错误响应格式](#58-错误响应格式)
- [6. 算法与协议](#6-算法与协议)
- [7. 配置参考](#7-配置参考)
- [8. 部署方案](#8-部署方案)
- [9. 安全模型详解](#9-安全模型详解)
  - [9.1 强制访问控制（MAC）](#91-强制访问控制mac)
  - [9.2 三权分立（RBAC）](#92-三权分立rbac)
  - [9.3 策略评估引擎](#93-策略评估引擎)
  - [9.4 认证流程](#94-认证流程)
- [10. 异常处理](#10-异常处理)
- [11. 性能目标](#11-性能目标)
- [12. 开发扩展](#12-开发扩展)

---

## 1. 设计目标与约束

### 1.1 核心目标

1. **等保三级合规** — 满足 GB/T 22239-2019 三级要求
2. **国密算法** — 纯 SM2/SM3/SM4，不使用国际算法
3. **自建部署** — 不依赖云 KMS，完全自主可控
4. **硬件无关** — 同一 API 支持软件 HSM 和物理 HSM
5. **信封加密** — KMS 不接触用户数据，只管理密钥

### 1.2 关键约束

| 约束 | 来源 | 影响 |
|------|------|------|
| 密钥材料不能明文出 HSM | 等保三级 | KEK 永不离开 HSM 边界 |
| 审计日志不可篡改 | 等保三级 | SM3 哈希链 + 定期校验 |
| 算法必须为国密 | GM/T 标准 | 禁用 AES/RSA/SHA 系列 |
| 管理员权限分离 | 等保三级 | 策略引擎 + 审计员角色 |

---

## 2. 设计决策

### 2.1 决策记录

| ID | 决策 | 方案 | 放弃的方案 | 理由 |
|----|------|------|-----------|------|
| D01 | KEK 派生方式 | SM3-HMAC-KDF | 直接存储主密钥 | KDF 可派生多个独立 KEK |
| D02 | 加密模式 | SM4-GCM | SM4-CBC/PKCS7 | GCM 提供认证加密，一次操作 |
| D03 | HSM 抽象 | KekProvider trait | 直接调用 HSM API | 开发测试可用软件回退 |
| D04 | 审计签名 | SM2 DER 编码 | SM2 RAW (r\|\|s) | DER 是标准交换格式 |
| D05 | 状态管理 | 显式状态机 | 简单启用/禁用 | 满足归档销毁合规需求 |
| D06 | 密钥存储 | JSONB 序列化 | ORM 映射 | 灵活应对 Key 结构演进 |
| D07 | HTTP 框架 | Axum | Actix-web/tower | Axum 更轻量，与 tokio 集成好 |
| D08 | 数据库 | SQLx | Diesel/sea-orm | 异步原生，编译期 SQL 检查 |
| D09 | 信封格式 | nonce\|\|ct\|\|tag | 分离存储 | 自包含，便于传输 |

### 2.2 KEK 派生方案详解

```
master_seed (32 bytes, 来自 HSM 或 CSPRNG)
       │
       ▼
   SM3(master_seed) → master_key (16 bytes)
       │
       ├── SM3(master_key || "KEK_user_keys_1") → KEK_user_keys_v1 (16 bytes)
       ├── SM3(master_key || "KEK_user_keys_2") → KEK_user_keys_v2 (16 bytes)
       ├── SM3(master_key || "KEK_audit_keys_1") → KEK_audit_keys_v1 (16 bytes)
       │
       ▼
   每个 KEK 只用于包裹对应密钥版本的 DEK
   版本轮换时派生新 KEK，旧 KEK 只解密不解密新数据
```

### 2.3 为什么选择信封加密而非直接加密

```
方案 A: KMS 直接加密数据        方案 B: 信封加密 (选用)
┌──────────────────────┐       ┌──────────────────────┐
│  数据 → KMS → 密文   │       │  KMS = 只管理 DEK    │
│  每次加解密都要网络   │       │  数据本地 SM4-GCM    │
│  吞吐量受限于 KMS    │       │  吞吐量无限           │
│  KMS 成为瓶颈        │       │  KMS 只做密钥分发     │
└──────────────────────┘       └──────────────────────┘

选择 B 的理由:
1. 性能 — 数据加密在本地，KMS 不成为瓶颈
2. 可用性 — 加密操作不依赖网络
3. 合规 — 数据不离开本地网络
4. 粒度 — 不同数据可用不同 DEK
```

---

## 3. 安全架构概览

### 3.1 信任边界

```
┌──────────────────────────────────────────────┐
│                 信任边界                       │
│  ┌─────────┐  ┌──────────┐  ┌────────────┐  │
│  │ 应用    │  │ KMS 服务 │  │ HSM/数据库 │  │
│  │ (不可信)│─▶│ (可信)   │─▶│ (可信)     │  │
│  └─────────┘  └──────────┘  └────────────┘  │
│       │             │              │          │
│  通过 TLS + Token    │              │          │
│  做身份认证          │  内部 API    │          │
│                      │              │          │
│  应用看不到 KEK      │            密钥材料      │
│  应用看到的是 DEK    │            加密存储       │
└──────────────────────────────────────────────┘
```

### 3.2 威胁模型

| 威胁 | 攻击向量 | 缓解措施 |
|------|---------|---------|
| **密钥泄露** | 内存 dump、核心转储 | zeroize 零化、HSM 隔离 |
| **重放攻击** | 重复发送请求 | nonce 唯一性、timestamp 窗口 |
| **篡改密钥** | 直接修改数据库 | 密钥材料被 KEK 加密保护 |
| **审计篡改** | 修改审计日志 | SM3 哈希链 + SM2 签名 |
| **中间人** | 拦截 API 通信 | TLS 1.3 双向认证 |
| **权限提升** | 越权操作 | ABAC 策略引擎逐请求鉴权 |
| **侧信道** | 时序分析 | constant-time 比较 |
| **回滚攻击** | 恢复旧密钥版本 | 版本号单调递增 |

### 3.3 密钥材料保护层级

```
Layer 0: HSM 内部 (硬件)
  └── 主密钥 (master_seed) — 永不离开 HSM

Layer 1: 内存（KMS 进程）
  ├── KEK — 从 HSM unwrap 得到，用完立即 zeroize
  └── DEK — 从 KEK 解密得到，返回给应用后立即 zeroize

Layer 2: 数据库（静止）
  └── 密文 DEK — {nonce || SM4-GCM(DEK, key=KEK) || tag}

Layer 3: 应用（使用中）
  └── 明文 DEK — 应用本地使用，KMS 不追踪使用情况
```

---

## 4. 数据模型

### 4.1 Key 数据结构

```rust
pub struct Key {
    pub id: String,              // UUID v4, 全局唯一
    pub name: String,            // 人类可读名称（如 "prod-db-key"）
    pub description: Option<String>,
    pub spec: KeySpec,           // 算法/长度/用途
    pub policy: KeyPolicy,       // 轮换/过期/MFA/角色
    pub state: KeyState,         // 当前状态
    pub versions: Vec<KeyVersion>, // 所有版本
    pub current_version: u32,     // 当前活跃版本号
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub owner: Option<String>,
    pub tags: HashMap<String, String>,
}
```

### 4.2 KeyVersion 数据结构

```rust
pub struct KeyVersion {
    pub version_number: u32,        // 单调递增
    pub key_material_hash: String,  // SM3(plaintext_key)，用于验证
    pub hsm_key_id: Option<String>, // HSM 内部 ID
    pub state: KeyState,            // 每个版本独立状态
    pub created_at: DateTime<Utc>,
    pub destroyed_at: Option<DateTime<Utc>>,
}
```

### 4.3 数据库 Schema

```sql
-- 密钥元数据表
CREATE TABLE keys (
    id          TEXT PRIMARY KEY,         -- UUID
    name        TEXT NOT NULL,
    data        JSONB NOT NULL,           -- 完整 Key 对象 JSON 序列化
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL
);

-- 密钥材料表（密文存储）
CREATE TABLE key_material (
    id              TEXT PRIMARY KEY,
    key_id          TEXT NOT NULL,         -- 外键 → keys.id
    version_number  INTEGER NOT NULL,
    encrypted_key   BLOB NOT NULL,         -- SM4-GCM(nonce||ct||tag)
    algorithm       TEXT DEFAULT 'SM4-GCM',
    created_at      TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (key_id) REFERENCES keys(id)
);

-- 审计日志表
CREATE TABLE audit_log (
    id          SERIAL PRIMARY KEY,
    event_id    TEXT NOT NULL UNIQUE,
    timestamp   BIGINT NOT NULL,           -- 毫秒时间戳
    data        JSONB NOT NULL             -- AuditEvent 序列化
);

-- HSM 状态表
CREATE TABLE hsm_state (
    id          TEXT PRIMARY KEY,
    provider    TEXT NOT NULL,
    state_data  JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL
);
```

### 4.4 审计事件结构

```rust
pub struct AuditEvent {
    pub event_id: String,          // UUID
    pub timestamp: i64,            // 纳秒
    pub event_type: String,        // "key.create", "key.rotate" 等
    pub subject: String,           // 操作主体
    pub action: String,            // "POST /api/v1/keys/{id}/enable"
    pub resource: String,          // "key:xxx"
    pub request_id: Option<String>,
    pub source_ip: Option<String>,
    pub result: String,            // "success" | "denied" | "error"
    pub detail: Option<String>,
    pub previous_hash: Option<String>,  // 前一事件的 SM3 哈希
    pub hash: Option<String>,           // 当前事件的 SM3 哈希
    pub signature: Option<String>,      // SM2 DER 签名
}
```

### 4.5 规范字节串（Canonical Form）

用于哈希和签名的字节序列格式：

```
canonical = timestamp | "|" |
            event_type | "|" |
            subject | "|" |
            action | "|" |
            resource | "|" |
            result | "|" |
            previous_hash | "|" |
            hash | "|" |
            detail
```

---

## 5. API 设计

### 5.1 密钥管理 API

#### POST /api/v1/keys — 创建密钥

```json
// Request
{
    "name": "prod-db-key",
    "algorithm": "sm4",
    "key_length": 128,
    "description": "生产数据库加密密钥",
    "rotation_days": 90
}

// Response 201
{
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "prod-db-key",
    "state": "Enabled",
    "algorithm": "Sm4",
    "current_version": 0,
    "created_at": "2026-06-24T10:00:00+00:00"
}
```

#### POST /api/v1/keys/{id}/rotate — 轮换密钥

```json
// Response 200
{
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "prod-db-key",
    "state": "Enabled",
    "current_version": 2,
    "created_at": "2026-06-24T10:00:00+00:00"
}
```

轮换过程：
1. 生成新版本的密钥材料
2. 版本号 +1
3. 如果达到 `policy.max_versions`（默认 10），淘汰最旧版本
4. 当前版本指向最新

#### POST /api/v1/keys/{id}/disable — 禁用密钥

禁用后：
- `can_encrypt() = false` — 不能用于加密新数据
- `can_decrypt() = true` — 仍可解密已有密文
- 可用于灾难恢复场景

#### POST /api/v1/keys/{id}/destroy — 销毁密钥

销毁后：
- `can_encrypt() = false`
- `can_decrypt() = false`
- 密钥材料被 SM3 零化
- 元数据和审计日志保留
- **不可逆操作**

### 5.2 数据密钥 API

#### POST /api/v1/keys/{id}/datakey — 生成数据密钥

```json
// Response 200
{
    "key_id": "550e8400-e29b-41d4-a716-446655440000",
    "key_version": 1,
    "ciphertext": "a1b2c3d4...",       // 十六进制
    "algorithm": "SM4-GCM"
}
```

处理流程：
1. KMS 生成 32 字节随机 DEK
2. 从 KEK Provider 获取 KEK
3. `ciphertext_DEK = SM4-GCM-Encrypt(key=KEK, plaintext=DEK, aad="key_id:version")`
4. 返回 `nonce || ciphertext || tag`
5. 明文 DEK 仅在 KMS 内存中存在，不存储

#### POST /api/v1/keys/{id}/decrypt — 解密数据密钥

```json
// Request
{
    "key_id": "550e8400-e29b-41d4-a716-446655440000",
    "key_version": 1,
    "ciphertext": "a1b2c3d4..."
}

// Response 200
{
    "plaintext": "e5f6g7h8..."       // 十六进制 DEK
}
```

处理流程：
1. 从 KEK Provider 获取对应版本的 KEK
2. `DEK = SM4-GCM-Decrypt(key=KEK, ciphertext, aad="key_id:version")`
3. 验证 GCM 认证标签
4. 返回明文 DEK（应用一次性使用）

### 5.3 数据加解密 API

#### POST /api/v1/encrypt — 使用 KMS 密钥加密数据

```json
// Request
{
    "key_id": "550e8400-e29b-41d4-a716-446655440000",
    "plaintext": "48656c6c6f...s=="    // hex 编码的明文
}

// Response 200
{
    "ciphertext": "...",
    "key_id": "550e8400-e29b-41d4-a716-446655440000",
    "algorithm": "SM4-GCM+Envelope"
}
```

处理流程：
1. 内部调用 GenerateDataKey
2. 使用明文 DEK 加密数据
3. 返回 `[密文DEK][SM4-GCM密文]`

#### POST /api/v1/decrypt — 解密

```json
// Request
{
    "key_id": "550e8400-e29b-41d4-a716-446655440000",
    "key_version": 1,
    "ciphertext": "..."
}

// Response 200
{
    "plaintext": "48656c6c6f..."
}
```

处理流程：
1. 从密文前 N 字节解析出密文 DEK
2. 调用 DecryptDataKey 获取明文 DEK
3. 用 DEK 解密剩余数据

### 5.4 审计 API

#### GET /api/v1/audit/verify — 验证审计链完整性

```json
// Response 200
true   // 或 false

// 验证逻辑
// 1. 查询所有审计事件（按时间排序）
// 2. 对每个事件计算 canonical_bytes → SM3 → hash
// 3. 比较 computed_hash == event.hash
// 4. 比较 event.previous_hash == previous_event.hash
// 5. 如果启用了签名，验证 SM2 签名
```

#### GET /api/v1/health — 健康检查

```json
// Response 200
{
    "status": "ok",
    "version": "0.1.0",
    "hsm_mode": "software-kek-provider"
}
```

### 5.5 认证 API

#### POST /api/v1/auth/login — 登录获取会话

```json
// Request
{
    "username": "admin",
    "password": null           // 可选，保留扩展
}

// Response 200
{
    "session_id": "550e8400-e29b-41d4-a716-446655440000",
    "totp_required": true,
    "message": "请调用 /api/v1/auth/totp-verify 完成双因子验证"
}
```

**认证流程**：
1. 客户端发送 `Authorization: Bearer <token>` + 用户名 → 服务端验证 token
2. 成功后在内存 DashMap 中创建 `SessionInfo { username, totp_verified: false }`
3. 返回 `session_id`，要求客户端继续 TOTP 验证

#### POST /api/v1/auth/totp-verify — TOTP 双因子验证

```json
// Request
{
    "session_id": "550e8400-e29b-41d4-a716-446655440000",
    "totp_code": "123456"
}

// Response 200
{
    "status": "ok",
    "message": "双因子验证通过",
    "username": "admin"
}
```

**验证过程**：
1. 校验 session 是否存在且未过期
2. 标记 `SessionInfo.totp_verified = true`
3. 后续请求需同时携带 `Authorization: Bearer <token>` + `X-Session-Id: <session_id>`

#### POST /api/v1/auth/logout — 登出

```json
// Request
{
    "session_id": "550e8400-e29b-41d4-a716-446655440000"
}

// Response 200
{
    "status": "ok"
}
```

#### 认证请求头

| 头 | 必填 | 说明 |
|-----|------|------|
| `Authorization: Bearer <token>` | 是 | 服务端 token 验证 |
| `X-Session-Id` | 是（非 auth 路径） | 会话标识，需先 TOTP 验证 |
| `X-Admin-Role` | 否 | `system_admin` / `security_admin` / `audit_admin` |
| `X-Security-Level` | 否 | `Public` / `Internal` / `Secret` / `Classified` / `TopSecret` |

#### 免认证路径

- `GET /api/v1/health` — 健康检查

#### 免 TOTP 路径

- `/api/v1/auth/*` — 登录/验证/登出

### 5.6 入侵检测 API

#### POST /api/v1/monitor/alert — 提交检测告警

```json
// Response 200
{
    "alerts": [
        {
            "rule": "FailedLoginThreshold",
            "severity": "Medium",
            "message": "用户 admin 登录失败 5 次 (阈值: 5)",
            "timestamp": 1719360000000000000,
            "event_id": "550e8400-e29b-41d4-a716-446655440000"
        }
    ]
}
```

#### 检测规则

| 规则 | 描述 | 阈值 | 窗口 |
|------|------|------|------|
| `FailedLoginThreshold` | 登录失败次数过高 | 5 次 | 300 秒 |
| `AbnormalAccessTime` | 非工作时间访问（00:00-06:00） | 3 次 | 600 秒 |
| `RateLimiting` | 请求频率过高 | 100 次 | 60 秒 |
| `SuspiciousPattern` | 可疑路径/参数模式 | 3 次 | 300 秒 |

**处理流程**：
1. `AuditLogger.emit()` 每次写入审计事件后调用 `IntrusionDetector.analyze()`
2. 检测器将事件转交给 `RuleEngine` 的各规则计数器
3. 规则使用滑动窗口（`VecDeque` + 时间戳）判断是否达到阈值
4. 达到阈值则生成 `AlertEvent`，记录到审计日志

### 5.7 备份恢复 API

#### POST /api/v1/export/keys — 导出密钥

```json
// Response 200
{
    "header": {
        "version": 1,
        "created_at": "2026-06-25T12:00:00+00:00",
        "checksum": "a1b2c3d4e5f6..."  // SM3 哈希
    },
    "keys": [
        {
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "name": "prod-db-key",
            "algorithm": "Sm4",
            "state": "Enabled",
            "versions": [{ "version": 1, "key_material": "..." }],
            "created_at": "...",
            "updated_at": "..."
        }
    ]
}
```

#### POST /api/v1/import/keys — 导入密钥

```json
// Request (from /export/keys output)
{
    "header": { "version": 1, "checksum": "..." },
    "keys": [ /* ... */ ]
}

// Response 200
{
    "imported": 3,
    "skipped": 0,
    "errors": []
}
```

#### GET /api/v1/export/audit — 导出审计日志

```json
// Response 200
{
    "header": { "version": 1, "created_at": "..." },
    "events": [
        {
            "event_id": "550e...",
            "timestamp": 1719360000000000000,
            "event_type": "key.create",
            "subject": "admin",
            "action": "POST /api/v1/keys",
            "resource": "key:xxx",
            "result": "success",
            "hash": "a1b2...",
            "previous_hash": "c3d4..."
        }
    ]
}
```

**安全约束**：
- 密钥材料以密文形式导出（KEK 包裹）
- 导出文件包含 SM3 校验和，导入时验证完整性
- 导入操作记录到审计日志

### 5.8 错误响应格式

所有错误使用统一格式：

```json
// 401 Unauthorized
{
    "code": "UNAUTHORIZED",
    "message": "缺少或无效的 Authorization header",
    "request_id": "req-xxx"
}

// 403 Forbidden
{
    "code": "POLICY_DENIED",
    "message": "策略拒绝: subject=admin, action=POST:/api/v1/keys/xxx/destroy",
    "request_id": "req-xxx"
}

// 404 Not Found
{
    "code": "KEY_NOT_FOUND",
    "message": "密钥未找到: 550e8400-e29b-41d4-a716-446655440000",
    "request_id": "req-xxx"
}

// 409 Conflict
{
    "code": "KEY_DISABLED",
    "message": "密钥已禁用: xxx",
    "request_id": "req-xxx"
}

// 500 Internal Server Error
{
    "code": "CRYPTO_ERROR",
    "message": "SM4-GCM 解密失败: InvalidTag",
    "request_id": "req-xxx"
}
```

---

## 6. 算法与协议

### 6.1 SM4-GCM 认证加密

```
SM4-GCM 是 KMS 的核心加密协议，用于:
  1. KEK 包裹 DEK
  2. DEK 加密用户数据
  3. 审计日志签名密钥保护

算法参数:
  ┌──────────────┬──────────────────────┐
  │ 参数         │ 值                   │
  ├──────────────┼──────────────────────┤
  │ 区块算法     │ SM4 (128-bit)        │
  │ 工作模式     │ GCM (Galois/CTR)     │
  │ 密钥长度     │ 128 bits (16 bytes)  │
  │ Nonce 长度   │ 96 bits (12 bytes)   │
  │ 认证标签     │ 128 bits (16 bytes)  │
  │ 附加数据 AAD │ "key_id:version"     │
  └──────────────┴──────────────────────┘

密文格式:
  [nonce: 12 bytes] [ciphertext: N bytes] [tag: 16 bytes]
  总开销 = 28 bytes

Nonce 生成:
  CSPRNG (getrandom)，每次加密生成新 nonce
  同 key+nonce 组合禁止加密超过 2^32 个消息
```

### 6.2 SM3 哈希

```
SM3 用于:
  1. KEK 派生 (HMAC-SM3)
  2. 审计日志哈希链
  3. 密钥材料指纹

算法参数:
  ┌──────────────┬──────────────────────┐
  │ 参数         │ 值                   │
  ├──────────────┼──────────────────────┤
  │ 输出长度     │ 256 bits (32 bytes)  │
  │ 块大小       │ 512 bits (64 bytes)  │
  │ 安全强度     │ 128 bits             │
  └──────────────┴──────────────────────┘

SM3-HMAC 实现:
  HMAC-SM3(K, m) = SM3(K⊕opad || SM3(K⊕ipad || m))
  其中 opad = 0x5c... (重复块大小)
       ipad = 0x36... (重复块大小)
```

### 6.3 SM2 签名

```
SM2 用于审计日志的数字签名

算法参数:
  ┌──────────────┬──────────────────────┐
  │ 参数         │ 值                   │
  ├──────────────┼──────────────────────┤
  │ 曲线         │ SM2 椭圆曲线         │
  │ 私钥长度     │ 32 bytes             │
  │ 公钥长度     │ 65 bytes (未压缩)    │
  │ 签名长度     │ 64-72 bytes (DER)    │
  │ 签名方案     │ SM2 Digital Signature│
  └──────────────┴──────────────────────┘

签名过程:
  1. hash = SM3(canonical_bytes)
  2. sig = SM2_SIGN(sk, hash)
  3. der_bytes = sig.der_encode()
  4. event.signature = hex(der_bytes)

验签过程:
  1. hash = SM3(canonical_bytes)
  2. sig = Signature::der_decode(hex_bytes)
  3. valid = SM2_VERIFY(pk, hash, sig)
```

---

## 7. 配置参考

### 7.1 完整配置项

```toml
[server]
host = "127.0.0.1"          # 监听地址
port = 8443                  # 监听端口（推荐 HTTPS）
workers = 4                  # Tokio 工作线程数

[database]
url = "sqlite://data/kms.db?mode=rwc"   # 数据库连接
max_connections = 10                     # 连接池大小
run_migrations = true                    # 自动建表迁移

[crypto]
kek_path = "data/master.key"             # 软件 HSM 主密钥路径
key_rotation_days = 365                  # 默认轮换周期
max_key_versions = 10                    # 最大历史版本数

[audit]
log_path = "data/audit.log"              # 日志文件路径
retention_days = 365                     # 审计日志保留天数
enable_chain = true                      # 开启哈希链
enable_signing = true                    # 开启 SM2 签名

[auth]
totp_issuer = "KMS"                   # TOTP 签发者名称
admin_token = "your-secret-token"     # 管理员 Bearer token
session_ttl_secs = 3600               # 会话过期时间（秒）
default_security_level = "Internal"   # 默认安全标记级别

[hsm]
mode = "software"                        # software | sdf | pkcs11
# PKCS#11 模式需额外配置:
# pkcs11_module_path = "/usr/lib/libswhsm.so"
# pkcs11_slot_id = 0
# pkcs11_pin = "123456"

[policy]
enable_rbac = true                       # 开启 RBAC
enforce_https = true                     # 强制 HTTPS
# admin_token = "your-secret-token"      # 管理员令牌
```

### 7.2 Feature Flags

```toml
# 默认 feature（软件 HSM 模式）
default = ["software-hsm"]

# 启用 PKCS#11 HSM 支持
cargo build --features pkcs11-hsm

# 启用 PostgreSQL 存储
cargo build --features postgres

# 启用真实 TPM 2.0
cargo build --features tpm

# 全部启用
cargo build --features "pkcs11-hsm postgres"
```

---

## 8. 部署方案

### 8.1 开发环境

```
┌─────────────────────────────────────────┐
│  本地开发机                              │
│  ┌─────────────────────────────────┐   │
│  │  KMS 进程 (cargo run)           │   │
│  │  ├── 软件 HSM (master_seed)     │   │
│  │  └── SQLite 数据库              │   │
│  └─────────────────────────────────┘   │
│           ↕ HTTPS :8443                 │
│  ┌─────────────────────────────────┐   │
│  │  应用进程 (curl / SDK)          │   │
│  └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

### 8.2 生产环境

```
                    ┌──────────────┐
                    │  客户端应用   │
                    └──────┬───────┘
                           │ HTTPS (TLS 1.3)
                           ▼
                    ┌──────────────┐
                    │  反向代理     │  ← Nginx/HAProxy
                    │  TLS 终止     │
                    └──────┬───────┘
                           │ HTTP/1.1
                    ┌──────┴───────┐
                    │  KMS 服务     │
                    │  (主备部署)   │
                    └──────┬───────┘
                           │
               ┌───────────┼───────────┐
               ▼           ▼           ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │  主数据库  │ │  备用 HSM │ │  审计存储  │
        │ PostgreSQL│ │  PKCS#11  │ │  独立 DB   │
        └──────────┘ └──────────┘ └──────────┘
```

### 8.3 高可用方案

```
KMS 无状态设计:
  ┌────────┐    ┌────────┐
  │ KMS-A  │    │ KMS-B  │  ← 共享数据库 / 共享 HSM
  └───┬────┘    └───┬────┘
      └──────┬──────┘
             ▼
      ┌──────────────┐
      │  负载均衡     │
      │  (轮询/最小连接)│
      └──────────────┘

关键点:
  - KMS 实例无本地状态
  - 所有持久状态在数据库和 HSM 中
  - 密钥材料由 KEK 保护存储在数据库
  - KEK 由共享 HSM 管理
  - 支持水平扩展
```

---

## 9. 安全模型详解

### 9.1 强制访问控制（MAC）

基于 Bell-LaPadula 模型的安全标记控制：

```
安全级偏序: TopSecret ≥ Classified ≥ Secret ≥ Internal ≥ Public

读规则: 主体安全级 ≥ 客体安全级 → 可读 (No Read Up)
写规则: 主体安全级 = 客体安全级 → 可写 (No Write Down)
```

实现位置：`src/policy/label.rs`

| 安全级 | 标签 | 示例 |
|--------|------|------|
| 绝密 | `TopSecret` | 国家级密钥 |
| 机密 | `Classified` | 核心系统密钥 |
| 秘密 | `Secret` | 业务密钥 |
| 内部 | `Internal` | 内部工具密钥 |
| 公开 | `Public` | 公开证书 |

### 9.2 三权分立（RBAC）

基于角色的权限矩阵：

| 权限 | 系统管理员 | 安全管理员 | 审计管理员 |
|------|-----------|-----------|-----------|
| 密钥创建/启用/禁用 | ✓ | | |
| 密钥轮换 | ✓ | | |
| 密钥销毁 | ✓ | | |
| 策略配置 | | ✓ | |
| 审计日志查看 | | | ✓ |
| 审计日志导出 | | | ✓ |
| 日志清理 | | | ✗（只读） |

实现位置：`src/policy/roles.rs`

### 9.3 策略评估引擎

三级评估流水线：

```
HTTP 请求
   │
   ▼
┌─────────────────────────────┐
│ 第一级: 角色检查             │
│ 如果请求头包含 X-Admin-Role   │
│ → 检查角色是否有权限执行操作   │
│ → 无权限则返回 POLICY_DENIED  │
└─────────────────────────────┘
   │
   ▼
┌─────────────────────────────┐
│ 第二级: MAC 检查              │
│ 如果请求头包含 X-Security-Level│
│ → 检查安全标记读写规则        │
│ → 违反规则则返回 POLICY_DENIED│
└─────────────────────────────┘
   │
   ▼
┌─────────────────────────────┐
│ 第三级: ABAC 检查             │
│ 针对特定资源的自定义规则       │
│ → 可扩展策略接口              │
└─────────────────────────────┘
   │
   ▼
允许/拒绝决策

向后兼容: 无角色头 → 跳过第一级；无标记头 → 跳过第二级
```

### 9.4 认证流程

```
请求 → 路径判断
   ├── /health → 放行（免认证）
   ├── /auth/* → Bearer 验证（免 TOTP）
   └── 其他 → 
       ├── Bearer 验证 → fail → 401
       ├── Session 验证 → fail → 401
       ├── TOTP 已认证 → 通过
       └── TOTP 未认证 → 401（要求双因子）
```

---

## 10. 异常处理

### 10.1 错误分类

| 类别 | HTTP 状态码 | 示例 | 恢复策略 |
|------|-----------|------|---------|
| 客户端错误 | 4xx | 无效请求、权限不足 | 修复请求后重试 |
| 服务端错误 | 5xx | 数据库不可达、HSM 故障 | 指数退避重试 |
| 安全错误 | 401/403 | 令牌失效、策略拒绝 | 检查权限配置 |
| 数据错误 | 404/409 | 密钥不存在、已禁用 | 检查密钥 ID |

### 10.2 重试策略

```
HSM 操作失败:
  - 第 1 次: 立即重试
  - 第 2 次: 100ms 延迟
  - 第 3 次: 500ms 延迟
  - >3 次: 返回 503 Service Unavailable

数据库操作失败:
  - 连接超时: 自动重连（SQLx 连接池）
  - 唯一约束冲突: 返回 409，不重试
  - 死锁: 自动重试（PostgreSQL 自动处理）

认证标签验证失败（SM4-GCM）:
  - 不重试 — 密文已损坏或被篡改
  - 返回 500 CRYPTO_ERROR
```

### 10.3 日志规范

所有操作通过 tracing 输出结构化 JSON 日志：

```json
{
    "timestamp": "2026-06-24T10:00:00.123Z",
    "level": "INFO",
    "target": "kms::api::routes",
    "event": "key.create",
    "key_id": "550e8400-e29b-41d4-a716-446655440000",
    "subject": "admin",
    "duration_ms": 15,
    "result": "success"
}
```

日志级别：
- `ERROR` — 不可恢复错误（HSM 故障、数据库断开）
- `WARN` — 可恢复异常（重试、认证失败）
- `INFO` — 关键操作（创建密钥、轮换、销毁）
- `DEBUG` — 调试信息（请求详情、内部状态）

---

## 11. 性能目标

### 11.1 基准目标

| 操作 | 目标延迟 (p99) | 吞吐量 (单实例) |
|------|---------------|----------------|
| 创建密钥 | < 50ms | 5000 ops/s |
| 生成数据密钥 | < 20ms | 10000 ops/s |
| 解密数据密钥 | < 20ms | 10000 ops/s |
| 加密数据 | < 10ms (本地) | 无限 |
| 审计日志写入 | < 5ms | 20000 ops/s |
| 审计链验证 | < 100ms (100万条) | — |

### 11.2 数据密钥大小

```
一次 GenerateDataKey 操作:
  ┌──────────────┬─────────┬──────────┐
  │ 项目          │ 大小    │ 备注     │
  ├──────────────┼─────────┼──────────┤
  │ 请求体       │ ~50 B   │ JSON     │
  │ 响应体       │ ~200 B  │ JSON     │
  │ 密文 DEK     │ 76 B    │ 12+32+16+16 │
  │ KEK 派生     │ 32 B    │ SM3      │
  │ DEK (明文)   │ 32 B    │ 零化后释放 │
  └──────────────┴─────────┴──────────┘

DEK 生命周期:
  生成 → (10μs) → 包裹为密文 DEK → (1ms) → 返回给应用
  应用使用 → (可变) → 应用销毁明文 DEK
```

### 11.3 可扩展性瓶颈

| 瓶颈点 | 当前状态 | 扩展方案 |
|--------|---------|---------|
| KEK 派生 | CPU 密集型 (SM3) | 多 worker 并行 |
| HSM 操作 | HSM 硬件吞吐量 | 多 HSM 会话池 |
| 数据库连接 | SQLx 连接池 | 读写分离 |
| 审计写入 | 串行追加 | 批量写入 + 缓冲区 |

---

## 12. 开发扩展

### 12.1 新增加密算法

实现 `SymmetricCrypto` trait：

```rust
pub trait SymmetricCrypto: Send + Sync {
    fn encrypt(&self, key: &[u8], plaintext: &[u8], aad: &[u8])
        -> CryptoResult<Vec<u8>>;
    fn decrypt(&self, key: &[u8], ciphertext: &[u8], aad: &[u8])
        -> CryptoResult<Vec<u8>>;
    fn key_len(&self) -> usize;
    fn nonce_len(&self) -> usize;
    fn tag_len(&self) -> usize;
}
```

示例：添加 AES-256-GCM 支持（非国密场景）：

```rust
pub struct Aes256GcmEngine;

impl SymmetricCrypto for Aes256GcmEngine {
    fn encrypt(&self, key: &[u8], plaintext: &[u8], aad: &[u8])
        -> CryptoResult<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| Error::CryptoError(format!("AES 初始化失败: {}", e)))?;
        let nonce = generate_nonce();
        let ciphertext = cipher.encrypt(&nonce, aad, plaintext)
            .map_err(|e| Error::CryptoError(format!("加密失败: {}", e)))?;
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }
    // ... decrypt
}
```

### 12.2 新增 KEK Provider

实现 `KekProvider` trait：

```rust
pub trait KekProvider: Send + Sync {
    fn name(&self) -> &str;
    fn wrap_key(&self, key_id: &str, key_version: u32, plaintext: &[u8])
        -> HsmResult<Vec<u8>>;
    fn unwrap_key(&self, key_id: &str, key_version: u32)
        -> HsmResult<Vec<u8>>;
    fn generate_random(&self, length: usize) -> HsmResult<Vec<u8>>;
    fn is_hardware_backed(&self) -> bool;
}
```

示例：对接国密 SDF 接口（GM/T 0018-2012）：

```rust
pub struct SdfKekProvider {
    session: SdfSession,
}

impl KekProvider for SdfKekProvider {
    fn wrap_key(&self, key_id: &str, key_version: u32, plaintext: &[u8])
        -> HsmResult<Vec<u8>> {
        // 调用 SDF_ExportEncrypt 或 SDF_InternalEncrypt
        self.session.export_encrypt(key_id, plaintext)
            .map_err(|e| Error::HsmError(format!("SDF 加密失败: {}", e)))
    }
    // ...
}
```

### 12.3 新增审计存储后端

实现 `AuditStore` trait：

```rust
#[async_trait]
pub trait AuditStore: Send + Sync {
    async fn append(&self, event: &AuditEvent) -> crate::Result<()>;
    async fn query(&self, start_time: i64, end_time: i64)
        -> crate::Result<Vec<AuditEvent>>;
    async fn get_latest(&self) -> crate::Result<Option<AuditEvent>>;
    async fn verify_chain(&self) -> crate::Result<bool>;
}
```

### 12.4 开发阶段

```
Phase 1 (2-3 周): 核心数据模型 + 软件 KEK + SM4 引擎 + 信封加密 API
  ├── key/types.rs, key/store.rs, key/manager.rs
  ├── hsm/traits.rs, hsm/software_provider.rs
  ├── crypto/sm4_engine.rs, crypto/envelope.rs
  └── api/routes.rs (datakey / decrypt 路由)

Phase 2 (1-2 周): SM3 哈希 + SM2 签名 + 审计日志
  ├── crypto/sm3_engine.rs, crypto/sm2_engine.rs
  ├── audit/logger.rs, audit/store.rs
  └── api/routes.rs (audit 路由)

Phase 3 (1-2 周): 策略引擎 + 认证中间件 + 完善 API
  ├── policy/engine.rs, policy/types.rs
  ├── api/middleware.rs
  └── 完整的 CRUD 路由

Phase 4 (2-3 周): 等保合规加固
  ├── PKCS#11 HSM 对接
  ├── TLS 配置
  ├── 审计链完整性验证
  └── 安全测试

Phase 5 (持续): 测试 + 文档 + 部署
  ├── 单元测试 / 集成测试
  ├── 性能基准
  ├── 部署脚本
  └── 运维手册
```

---

> **相关文档**
> - `ARCHITECTURE.md` — 系统架构与模块关系图
> - `diagrams/*.mmd` — Mermaid 架构图源文件
> - `src/` — Rust 源码实现
> - `KMS实现调研报告.md` — 技术选型与市场调研
