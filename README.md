# KMS — 国密合规密钥管理系统

[![Rust](https://img.shields.io/badge/Rust-1.75%2B-blue)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![等保三级](https://img.shields.io/badge/等保-三级-orange)](https://github.com)
[![等保四级](https://img.shields.io/badge/等保-四级-red)](https://github.com)

满足 **GB/T 22239-2019 信息安全技术 网络安全等级保护基本要求 — 第三级（安全标记保护级）** 及 **第四级（结构化保护级）** 关键安全功能。

## 特性

- **国密算法全栈**：SM2（签名/密钥交换）、SM3（哈希/HMAC）、SM4（对称加密/GCM 模式）
- **密钥全生命周期**：创建、启用、禁用、轮换、归档、销毁
- **信封加密**：数据密钥（DEK）+ 密钥加密密钥（KEK）双层架构
- **安全标记（MAC）**：绝密/机密/秘密/内部/公开五级强制访问控制
- **三权分立**：系统管理员 / 安全管理员 / 审计管理员角色分离
- **双因素认证**：TOTP 会话管理
- **审计追踪**：SM3 哈希链 + 可选 SM2 签名，防篡改
- **入侵检测**：登录失败阈值、限流、可疑模式检测
- **等保四级增强**：TPM 可信根、PKCS#11/SDF 硬件密码模块、入侵自动阻断、集群通信框架
- **备份恢复**：密钥和审计日志导出/导入

## 快速开始

### 前置要求

- Rust 1.75+
- SQLite3（开发环境）或 PostgreSQL（生产环境）

### 安装

```bash
git clone https://github.com/MyBlackHole/kms.git
cd kms
```

### 配置

生成默认配置文件：

```bash
cargo run -- --config config.toml 2>&1 | head -5
```

编辑 `config.toml`：

```toml
[server]
host = "127.0.0.1"
port = 8443

[database]
url = "sqlite://data/kms.db?mode=rwc"

[auth]
totp_issuer = "KMS"
```

### 启动

```bash
cargo run -- --config config.toml
```

### 使用

```bash
# 1. 健康检查
curl http://127.0.0.1:8443/api/v1/health

# 2. 登录获取会话
LOGIN=$(curl -s -X POST http://127.0.0.1:8443/api/v1/auth/login \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin"}')
SID=$(echo $LOGIN | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])")

# 3. TOTP 双因子验证
curl -s -X POST http://127.0.0.1:8443/api/v1/auth/totp-verify \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$SID\",\"totp_code\":\"123456\"}"

# 4. 创建密钥
curl -X POST http://127.0.0.1:8443/api/v1/keys \
  -H 'Authorization: Bearer <token>' \
  -H "X-Session-Id: $SID" \
  -H 'Content-Type: application/json' \
  -d '{"name":"my-key","algorithm":"sm4","key_length":128}'
```

## API 概览

| Method | Path | 描述 | 认证 |
|--------|------|------|------|
| GET | `/api/v1/health` | 健康检查 | 免认证 |
| POST | `/api/v1/auth/login` | 登录获取 session | Bearer |
| POST | `/api/v1/auth/totp-verify` | TOTP 双因子验证 | Bearer |
| POST | `/api/v1/auth/recovery` | 恢复码验证 | Bearer |
| POST | `/api/v1/auth/recovery-codes` | 生成恢复码 | Bearer + Session |
| GET | `/api/v1/auth/cert-info` | 获取 mTLS 证书信息 | Bearer |
| POST | `/api/v1/auth/tokens` | 创建 API Token（仅返回一次明文） | Bearer |
| GET | `/api/v1/auth/tokens` | 列出 API Token | Bearer |
| DELETE | `/api/v1/auth/tokens/:id` | 吊销 API Token | Bearer |
| POST | `/api/v1/auth/logout` | 登出 | Bearer + Session |
| GET | `/api/v1/keys` | 列出密钥 | Bearer + Session |
| POST | `/api/v1/keys` | 创建密钥 | Bearer + Session |
| GET | `/api/v1/keys/:id` | 获取密钥详情 | Bearer + Session |
| POST | `/api/v1/keys/:id/enable` | 启用密钥 | Bearer + Session |
| POST | `/api/v1/keys/:id/disable` | 禁用密钥 | Bearer + Session |
| POST | `/api/v1/keys/:id/rotate` | 轮换密钥 | Bearer + Session + 审批 |
| POST | `/api/v1/keys/:id/archive` | 归档密钥 | Bearer + Session + 审批 |
| POST | `/api/v1/keys/:id/destroy` | 销毁密钥 | Bearer + Session + 审批 |
| POST | `/api/v1/keys/:id/datakey` | 生成数据密钥 | Bearer + Session |
| POST | `/api/v1/keys/:id/decrypt` | 解密数据密钥 | Bearer + Session |
| POST | `/api/v1/encrypt` | 信封加密数据 | Bearer + Session |
| POST | `/api/v1/decrypt` | 信封解密数据 | Bearer + Session |
| POST | `/api/v1/keys/:id/acl` | 添加密钥 ACL | Bearer + Session |
| DELETE | `/api/v1/keys/:id/acl/:subject` | 移除密钥 ACL | Bearer + Session |
| POST | `/api/v1/keys/:id/dependencies` | 添加密钥依赖 | Bearer + Session |
| DELETE | `/api/v1/keys/:id/dependencies/:dep_id` | 移除密钥依赖 | Bearer + Session |
| GET | `/api/v1/keys/:id/dependents` | 列出依赖方 | Bearer + Session |
| POST | `/api/v1/keys/export` | 导出密钥库 | Bearer + Session + 审批 |
| POST | `/api/v1/keys/import` | 导入密钥库 | Bearer + Session + 审批 |
| GET | `/api/v1/audit/verify` | 验证审计链 | Bearer + Session |
| GET | `/api/v1/audit/logs` | 查询审计日志 | Bearer + Session |
| POST | `/api/v1/approvals` | 提交审批请求 | Bearer + Session |
| GET | `/api/v1/approvals/pending` | 待审批列表 | Bearer + Session |
| POST | `/api/v1/approvals/:id/approve` | 审批通过 | Bearer + Session |
| POST | `/api/v1/approvals/:id/reject` | 审批驳回 | Bearer + Session |
| GET | `/api/v1/admin/blocklist` | 查看封禁列表 | Bearer + Session |
| POST | `/api/v1/admin/unblock/:target` | 解封目标 | Bearer + Session |
| GET | `/api/v1/metrics` | Prometheus 指标 | Bearer + Session |

### 认证

- **静态 admin_token**：通过 `auth.admin_token` 配置，内存比对，零开销
- **动态 API Token**：可动态创建/吊销，SM3 哈希存储，支持 TTL 过期
- **认证回退链**：先查静态 admin_token → 再查动态 API Token → 401
- **Session**：登录后通过 `X-Session-Id` 头传递，需先完成 TOTP 验证
- **安全标记**：通过 `X-Security-Level` 头（Public/Internal/Secret/Classified/TopSecret）
- **管理角色**：通过 `X-Admin-Role` 头（system_admin/security_admin/audit_admin）

### API Token 管理

```bash
# 创建 Token（指定名称和可选 TTL）
curl -s -X POST http://127.0.0.1:8443/api/v1/auth/tokens \
  -H 'Authorization: Bearer <admin_token>' \
  -H 'Content-Type: application/json' \
  -d '{"name":"ci-token", "ttl_secs": 86400}'
# → 返回 {"id":"...", "token":"kms_...", "hint":"kms_****", "message":"请立即保存..."}

# 使用 Token 认证
curl -H 'Authorization: Bearer kms_...' http://127.0.0.1:8443/api/v1/keys

# 列出所有 Token
curl -s http://127.0.0.1:8443/api/v1/auth/tokens \
  -H 'Authorization: Bearer <admin_token>'

# 吊销 Token
curl -s -X DELETE http://127.0.0.1:8443/api/v1/auth/tokens/<id> \
  -H 'Authorization: Bearer <admin_token>'
```

> Token 格式：`kms_` + 32 字节随机数 base64 URL-safe 编码。哈希使用 SM3（国密合规）。创建时仅返回一次明文，丢失需重新创建。

## 安全模型

### 等保三级覆盖

| 等保要求 | 实现 |
|---------|------|
| 双因素认证 | Bearer token + TOTP |
| 自主访问控制（DAC） | 资源属主权限 |
| 强制访问控制（MAC） | 五级安全标记 + Bell-LaPadula 模型 |
| 三权分立 | 系统/安全/审计管理员角色分离 |
| 审计记录 | SM3 哈希链 + 可选 SM2 签名 |
| 审计存储 | SQLite 追加写入（不支持 UPDATE/DELETE） |
| 入侵检测 | 登录失败阈值 / 限流 / 可疑模式 |
| 数据保护 | Zeroize 内存清零 |
| 备份恢复 | JSON 导出/导入 |

## 配置参考

详见 [CONFIGURATION.md](CONFIGURATION.md)。支持软件 HSM 和 PKCS#11 HSM 两种模式。

## 测试

```bash
# 全部测试
cargo test

# 特定模块
cargo test policy::label       # 安全标记
cargo test policy::roles       # 三权分立
cargo test auth::totp          # TOTP
cargo test auth::session       # 会话管理
cargo test monitor::rules      # 检测规则
cargo test monitor::detector   # 入侵检测
cargo test backup              # 备份恢复
cargo test audit::sqlite_store # 审计存储
```

详见 [TESTING.md](TESTING.md)。API 集成测试：

```bash
./tests/api/run.sh        # 30 个场景全自动验证
```

## 项目结构

```
src/
├── api/           # HTTP API 路由、中间件、mTLS
├── audit/         # 审计日志（logger + sqlite_store）
├── auth/          # 认证（TOTP + Session + 恢复码 + API Token）
├── backup/        # 备份导出/导入
├── config.rs      # 配置解析
├── crypto/        # 加解密引擎（SM2/SM3/SM4）
├── hsm/           # HSM 抽象层（software + sdf + pkcs11）
├── key/           # 密钥管理（manager + store + types + dependency）
├── lib.rs         # 库入口 + 错误类型
├── main.rs        # 入口
├── monitor/       # 入侵检测（rules + detector + blocklist）
├── policy/        # 安全策略（label + roles + engine + types）
├── approval/      # 双人复核审批
├── evidence/      # 等保合规证据包
├── trust/         # 可信验证（软件 TPM + 硬件 TPM）
└── store/         # 数据库迁移和存储
```

## 架构

详见 [ARCHITECTURE.md](ARCHITECTURE.md) 和 [DESIGN.md](DESIGN.md)。

## 构建选项

```bash
# 默认（SQLite + 软件 HSM）
cargo build

# PostgreSQL + 软件 HSM
cargo build --features postgres

# SQLite + PKCS#11 HSM
cargo build --features pkcs11-hsm

# PostgreSQL + PKCS#11 HSM
cargo build --features "pkcs11-hsm postgres"

# 启用真实 TPM 2.0 支持
cargo build --features tpm
```

## License

MIT
