# KMS 测试文档

> 测试策略、用例和覆盖率说明

## 1. 测试策略

### 分层策略

```
单元测试                    — 各模块独立验证
├── 安全标记 (label)        — MAC 读写规则
├── 三权分立 (roles)        — 角色权限矩阵
├── TOTP (totp)            — base32 编码/解码、URI 生成
├── 会话 (session)          — 创建/验证/销毁/过期
├── 检测规则 (rules)        — 阈值触发、滑动窗口
├── 入侵检测 (detector)     — 审计事件分析
├── 备份恢复 (backup)       — 序列化/反序列化
└── 审计存储 (sqlite_store) — SQLite 追加写入
集成测试 (Rust)             — API 端点功能验证（Rust #[cfg(test)]）
API 集成测试 (bash)          — HTTP 接口全链路验证（自动 curl 脚本，30 个场景）
```

## 2. 单元测试

### 运行方式

```bash
# 全部测试
cargo test

# 特定模块
cargo test policy::label       # 安全标记
cargo test policy::roles       # 三权分立
cargo test auth::totp          # TOTP 双因子
cargo test auth::session       # 会话管理
cargo test monitor::rules      # 检测规则
cargo test monitor::detector   # 入侵检测
cargo test backup              # 备份恢复
cargo test audit::sqlite_store # 审计存储
```

### 当前测试覆盖率

21 个单元测试，覆盖以下场景：

#### auth::totp（3 个）

| 测试 | 验证内容 |
|------|---------|
| `test_base32_roundtrip` | Base32 编码→解码一致性 |
| `test_generate_secret` | Secret 生成（20 字节→Base32） |
| `test_qr_uri` | `otpauth://` URI 格式 |

#### auth::session（3 个）

| 测试 | 验证内容 |
|------|---------|
| `test_session_create_and_validate` | 创建会话后可验证 |
| `test_session_totp_verification` | TOTP 标记状态转换 |
| `test_session_destroy` | 销毁后无法验证 |

#### policy::label（4 个）

| 测试 | 验证内容 |
|------|---------|
| `test_security_level_ordering` | 五级偏序关系（TopSecret ≥ Classified ≥ ...） |
| `test_level_parsing` | 字符串↔SecurityLevel 转换 |
| `test_mac_read_rule` | MAC 读规则（主体安全级≥客体可读） |
| `test_mac_write_rule` | MAC 写规则（主体安全级=客体可写） |

#### policy::roles（4 个）

| 测试 | 验证内容 |
|------|---------|
| `test_role_parsing` | 字符串↔AdminRole 转换 |
| `test_system_admin_permissions` | 系统管理员权限（密钥全生命周期） |
| `test_security_admin_permissions` | 安全管理员权限（策略配置） |
| `test_audit_admin_permissions` | 审计管理员权限（只读审计日志） |

#### monitor::rules（3 个）

| 测试 | 验证内容 |
|------|---------|
| `test_rule_not_triggered_below_threshold` | 阈值以下不触发告警 |
| `test_rule_triggered_at_threshold` | 达到阈值触发告警 |
| `test_separate_counters` | 不同计数器隔离 |

#### monitor::detector（2 个）

| 测试 | 验证内容 |
|------|---------|
| `test_detector_ignores_normal_events` | 正常事件不触发告警 |
| `test_detector_triggers_on_failed_login_burst` | 登录失败 5 次触发告警 |

#### backup（1 个）

| 测试 | 验证内容 |
|------|---------|
| `test_backup_header_serde` | BackupHeader 序列化→反序列化一致性 |

#### audit::sqlite_store（1 个）

| 测试 | 验证内容 |
|------|---------|
| `test_sqlite_audit_store_append_and_query` | SQLite 追加写入 + 查询 |

### 添加新测试

测试文件位置：
- `src/auth/totp.rs` 末尾 `#[cfg(test)] mod tests`
- `src/auth/session.rs` 末尾 `#[cfg(test)] mod tests`
- `src/policy/label.rs` 末尾 `#[cfg(test)] mod tests`
- `src/policy/roles.rs` 末尾 `#[cfg(test)] mod tests`
- `src/monitor/rules.rs` 末尾 `#[cfg(test)] mod tests`
- `src/monitor/detector.rs` 末尾 `#[cfg(test)] mod tests`
- `src/backup/mod.rs` 末尾 `#[cfg(test)] mod tests`
- `src/audit/sqlite_store.rs` 末尾 `#[cfg(test)] mod tests`

## 3. API 集成测试（自动化）

### 测试脚本

位于 `tests/api/` 目录，使用 bash + curl 实现全链路 HTTP 测试：

| 脚本 | 测试内容 | 场景数 |
|------|---------|--------|
| `run.sh` | 主运行器（启动服务 → 执行测试 → 清理） | - |
| `helpers.sh` | 断言辅助函数 | - |
| `test_health.sh` | 健康检查（状态/版本/HSM 模式） | 4 |
| `test_auth.sh` | 认证（无认证/坏 Token/动态 Token CRUD/空名称/吊销） | 10 |
| `test_totp.sh` | TOTP 双因子（登录/TOTP 校验/空用户名） | 3 |
| `test_keys.sh` | 密钥操作（未认证创建被拒/登出失效） | 2 |
| `test_admin.sh` | 管理端点（审计/blocklist/metrics/审批） | 5 |
| `test_tpm.sh` | TPM 可信根（--hash-self / PCR 度量 / 证据导出） | 5 |
| `test_edge.sh` | 边缘场景（格式错误/Token 前缀/并发/幂等） | 6 |

### 运行方式

```bash
# 一键运行（自动编译 + 启动 + 测试 + 清理）
./tests/api/run.sh

# 指定端口 / token / 二进制路径
./tests/api/run.sh --port 18443 --token my-token --binary target/release/kms-server

# 连接已有服务（不重启）
./tests/api/run.sh --no-restart --port 8443

# 运行指定测试
./tests/api/run.sh health auth
```

### 运行要求

- `bash` 4.0+
- `curl`
- `python3`
- 编译后的二进制 (`cargo build --release`)

### 预期结果

```text
全部通过: 35 项
```

## 4. 功能测试（手动）

### 启动服务

```bash
# 创建测试数据目录
mkdir -p /tmp/kms-test/data

# 创建测试配置
cat > /tmp/kms-test/config.toml << 'EOF'
[server]
host = "127.0.0.1"
port = 8443
workers = 2
session_ttl_secs = 3600

[database]
url = "sqlite:///tmp/kms-test/data/kms.db?mode=rwc"
max_connections = 5
run_migrations = true

[crypto]
kek_path = "/tmp/kms-test/data/master.key"
key_rotation_days = 365
max_key_versions = 10

[audit]
log_path = "/tmp/kms-test/data/audit.log"
retention_days = 365
enable_chain = true
enable_signing = true

[hsm]
mode = "software"
EOF

# 启动服务
RUST_LOG=info cargo run -- --config /tmp/kms-test/config.toml
```

### 测试用例

#### 1. 健康检查（免认证）

```bash
curl http://127.0.0.1:8443/api/v1/health
# 预期: {"status":"ok","version":"0.1.0","hsm_mode":"software-kek-provider"}
```

#### 2. 无认证请求被拒绝

```bash
curl -o /dev/null -w "%{http_code}" http://127.0.0.1:8443/api/v1/keys
# 预期: 401
```

#### 3. 双因素认证流程

```bash
# 步骤1: 登录（需 Bearer token）
LOGIN=$(curl -s -X POST http://127.0.0.1:8443/api/v1/auth/login \
  -H 'Authorization: Bearer test' \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin"}')
echo "$LOGIN"
# 预期: {"session_id":"...","totp_required":true,"message":"请调用..."}

# 提取 session_id
SESSION_ID=$(echo "$LOGIN" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])")

# 步骤2: TOTP 验证
curl -s -X POST http://127.0.0.1:8443/api/v1/auth/totp-verify \
  -H 'Authorization: Bearer test' \
  -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$SESSION_ID\",\"totp_code\":\"123456\"}"
# 预期: {"message":"双因子验证通过","status":"ok","username":"admin"}
```

#### 4. 密钥操作（完整认证后）

```bash
# 创建密钥
KEYRESP=$(curl -s -X POST http://127.0.0.1:8443/api/v1/keys \
  -H 'Authorization: Bearer test' \
  -H "X-Session-Id: $SESSION_ID" \
  -H 'Content-Type: application/json' \
  -d '{"name":"test-key","algorithm":"sm4","key_length":128}')
echo "$KEYRESP"
KEY_ID=$(echo "$KEYRESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

# 获取密钥
curl -s http://127.0.0.1:8443/api/v1/keys/$KEY_ID \
  -H 'Authorization: Bearer test' \
  -H "X-Session-Id: $SESSION_ID"

# 轮换密钥
curl -s -X POST http://127.0.0.1:8443/api/v1/keys/$KEY_ID/rotate \
  -H 'Authorization: Bearer test' \
  -H "X-Session-Id: $SESSION_ID"

# 生成数据密钥
curl -s -X POST http://127.0.0.1:8443/api/v1/keys/$KEY_ID/datakey \
  -H 'Authorization: Bearer test' \
  -H "X-Session-Id: $SESSION_ID"

# 解密数据密钥
CIPHER=$(curl -s -X POST http://127.0.0.1:8443/api/v1/keys/$KEY_ID/datakey \
  -H 'Authorization: Bearer test' \
  -H "X-Session-Id: $SESSION_ID" | python3 -c "import sys,json; print(json.load(sys.stdin)['ciphertext'])")
curl -s -X POST http://127.0.0.1:8443/api/v1/keys/$KEY_ID/decrypt \
  -H 'Authorization: Bearer test' \
  -H "X-Session-Id: $SESSION_ID" \
  -H 'Content-Type: application/json' \
  -d "{\"key_id\":\"$KEY_ID\",\"key_version\":1,\"ciphertext\":\"$CIPHER\"}"
```

#### 5. 审计链验证

```bash
curl -s http://127.0.0.1:8443/api/v1/audit/verify \
  -H 'Authorization: Bearer test' \
  -H "X-Session-Id: $SESSION_ID"
# 预期: true
```

#### 6. 登出

```bash
curl -s -X POST http://127.0.0.1:8443/api/v1/auth/logout \
  -H 'Authorization: Bearer test' \
  -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$SESSION_ID\"}"

# 登出后应返回 401
curl -o /dev/null -w "%{http_code}" \
  -H 'Authorization: Bearer test' \
  -H "X-Session-Id: $SESSION_ID" \
  http://127.0.0.1:8443/api/v1/keys
# 预期: 401
```

#### 7. 安全标记 + 角色（请求头）

```bash
# 以安全管理员身份、Secret 级别创建密钥
curl -s -X POST http://127.0.0.1:8443/api/v1/keys \
  -H 'Authorization: Bearer test' \
  -H "X-Session-Id: $SESSION_ID" \
  -H 'X-Admin-Role: security_admin' \
  -H 'X-Security-Level: Secret' \
  -H 'Content-Type: application/json' \
  -d '{"name":"classified-key","algorithm":"sm4","key_length":128}'
```

## 5. 编译验证

```bash
# 全量构建
cargo build

# 检查（快速）
cargo check

# LSP 诊断（在 IDE 或使用 rust-analyzer）
# 预期: 零错误零警告
```

## 6. 预期测试结果一览

| 场景 | 预期 HTTP | 备注 |
|------|----------|------|
| `GET /api/v1/health` | 200 | 免认证 |
| 无认证访问保护资源 | 401 | |
| 仅 Bearer 无 Session | 401 | TOTP 未验证 |
| `POST /api/v1/auth/login` | 200 | 需 Bearer |
| `POST /api/v1/auth/totp-verify` | 200 | |
| `POST /api/v1/keys` | 200 | 需完整认证 |
| `GET /api/v1/keys/:id` | 200/404 | 存在/不存在 |
| `POST /api/v1/keys/:id/rotate` | 200 | `current_version` +1 |
| `POST /api/v1/keys/:id/datakey` | 200 | 版本≥1 |
| `POST /api/v1/keys/:id/decrypt` | 200 | |
| `POST /api/v1/auth/logout` | 200 | |
| 登出后访问 | 401 | |
| `GET /api/v1/audit/verify` | 200 `true` | |
| `POST /api/v1/encrypt` | 200 | 需密钥有版本 |
| `POST /api/v1/decrypt` | 200 | |
| `POST /api/v1/auth/tokens` | 200 | 创建动态 Token，返回明文 |
| `GET /api/v1/auth/tokens` | 200 | 列表 Token（不含 hash） |
| `DELETE /api/v1/auth/tokens/:id` | 200 | 吊销 Token |

## 7. 常见问题

### 编译失败

```bash
# 清理缓存
cargo clean
# 重新构建
cargo build
```

### DataKey 解密失败（invalid hmac tag）

确保密钥版本 ≥ 1（先执行轮换）：

```bash
curl -s -X POST http://127.0.0.1:8443/api/v1/keys/$KEY_ID/rotate \
  -H 'Authorization: Bearer test' \
  -H "X-Session-Id: $SESSION_ID"
```

### 数据库文件清理

测试数据库位于配置 `database.url` 指定的路径。清理后重启会自动迁移：

```bash
rm -f /tmp/kms-test/data/kms.db
```
