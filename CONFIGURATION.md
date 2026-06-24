# KMS 配置参考手册

## CLI 选项

```bash
kms-server [OPTIONS] [COMMAND]

选项:
  -c, --config <FILE>      配置文件路径（默认: config.toml）
      --hash-self          输出自身二进制 SM3 哈希并退出
      --evidence <DIR>     导出等保合规证据包到目录

子命令:
  export-keys <OUTPUT>     导出密钥库到文件
  import-keys <INPUT>      从文件导入密钥库
  backup-seed <OUTPUT>     备份 Master Seed 到文件
  restore-seed <INPUT>     从文件恢复 Master Seed
```

---

## 配置项总表

### `[server]` — 服务端

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `host` | string | `"127.0.0.1"` | 监听地址 |
| `port` | uint16 | `8443` | 监听端口 |
| `workers` | uint | `4` | 工作线程数 |
| `session_ttl_secs` | uint64 | `3600` | Session 存活秒数（1 小时） |
| `[server.tls]` | table | 不启用 | HTTPS/TLS 配置 |

示例：

```toml
[server]
host = "0.0.0.0"
port = 8443
workers = 4
session_ttl_secs = 3600

[server.tls]
cert_path = "/etc/kms/server.crt"
key_path = "/etc/kms/server.key"
# client_ca_path = "/etc/kms/ca.crt"  # 启用 mTLS
```

> TLS 配置详见下文「HTTPS / mTLS 配置」。

---

### `[database]` — 数据库

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `url` | string | `"sqlite://data/kms.db?mode=rwc"` | 数据库连接串 |
| `max_connections` | uint32 | `10` | 连接池大小 |
| `run_migrations` | bool | `true` | 启动时自动执行迁移 |

支持的数据库：

| 数据库 | 连接串示例 | 需要 feature |
|--------|-----------|-------------|
| SQLite | `sqlite://data/kms.db?mode=rwc` | `sqlite`（默认） |
| PostgreSQL | `postgres://user:pass@host:5432/kms` | `postgres` |

示例：

```toml
[database]
url = "postgres://kms:secret@localhost:5432/kms"
max_connections = 20
run_migrations = true
```

---

### `[crypto]` — 加密引擎

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `kek_path` | path | `"data/master.key"` | KEK 持久化路径 |
| `key_rotation_days` | uint32 | `365` | KEK 轮换周期（天） |
| `max_key_versions` | uint32 | `10` | 最大 KEK 版本数 |
| `master_seed_path` | path | 不设置 | Master Seed 文件路径（自动生成 256 位） |

示例：

```toml
[crypto]
kek_path = "data/master.key"
key_rotation_days = 180        # 半年轮换一次
max_key_versions = 5
master_seed_path = "data/seed.bin"  # 自动生成种子文件
```

> `master_seed_path` 首次启动自动生成 32 字节随机种子，后续读取同一文件保证 KEK 稳定可恢复。

---

### `[audit]` — 审计日志

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `log_path` | path | `"data/audit.log"` | 审计日志文件路径 |
| `retention_days` | uint32 | `365` | 日志保留天数 |
| `enable_chain` | bool | `true` | 启用 SM3 哈希链（防篡改） |
| `enable_signing` | bool | `true` | 启用 SM2 签名（需预置密钥） |

示例：

```toml
[audit]
log_path = "data/audit.log"
retention_days = 730         # 保留两年
enable_chain = true
enable_signing = true
```

---

### `[hsm]` — 硬件安全模块

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `mode` | string | `"software"` | HSM 模式 |
| `pkcs11_module_path` | path | 不设置 | PKCS#11 动态库路径 |
| `pkcs11_slot_id` | uint64 | 不设置 | PKCS#11 Slot ID |
| `pkcs11_pin` | string | 不设置 | PKCS#11 PIN |
| `software_master_seed` | string | 不设置 | 软件模式种子（十六进制） |

支持的模式：

| 模式 | 说明 | 需要 feature |
|------|------|-------------|
| `software` | 软件 KEK（默认，开发/测试用） | `software-hsm`（默认） |
| `pkcs11` | PKCS#11 硬件 HSM（如加密机） | `pkcs11-hsm` |
| `sdf` | SDF 接口国密硬件 | `sdf-hsm` |

示例：

```toml
# 软件模式
[hsm]
mode = "software"
software_master_seed = "a1b2c3d4..."  # 可选：固定种子便于恢复

# PKCS#11 加密机
[hsm]
mode = "pkcs11"
pkcs11_module_path = "/usr/lib/libsw11.so"
pkcs11_slot_id = 0
pkcs11_pin = "123456"
```

---

### `[policy]` — 安全策略

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enable_rbac` | bool | `true` | 启用三权分立（系统/安全/审计管理员） |
| `enforce_https` | bool | `true` | 拒绝非 HTTPS 请求 |

> `enforce_https` 启用时：不通过 TLS 加密的请求将被拒绝。

---

### `[auth]` — 认证

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `totp_issuer` | string | `"KMS"` | TOTP 身份验证器显示的颁发者名称 |
| `admin_token` | string | 不设置 | 静态管理员令牌（不设则仅用动态 API Token） |

示例：

```toml
[auth]
admin_token = "your-secure-admin-token"
totp_issuer = "MyCompany-KMS"
```

> 认证回退链：静态 admin_token（内存比对）→ 动态 API Token（DB 查询）→ 401。

---

### `[trust]` — 可信验证

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `expected_binary_hash` | string | 不设置 | 预期二进制 SM3 哈希（防篡改） |
| `expected_config_hash` | string | 不设置 | 预期配置文件 SM3 哈希 |

使用步骤：

```bash
# 1. 计算当前二进制哈希
cargo run --release -- --hash-self
# → 输出: 344efa22dec4744c...（64 字符十六进制）

# 2. 写入配置
# [trust]
# expected_binary_hash = "344efa22dec4744c..."

# 3. 再次启动，二进制被篡改时拒绝启动
```

---

### `[tpm]` — TPM 可信根（等保四级）

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `mode` | string | `"software"` | TPM 模式 |
| `tcti` | string | 不设置 | TCTI 连接串（真实 TPM） |
| `enable_startup_measurement` | bool | `true` | 启动时度量二进制到 PCR |
| `app_pcr_index` | uint8 | `16` | 应用度量 PCR 索引 |

支持的模式：

| 模式 | 说明 | 需要 feature |
|------|------|-------------|
| `software` | 软件模拟 TPM（默认） | 无 |
| `tpm` | 真实 TPM 2.0 | `tpm` |

TCTI 示例：

```toml
[tpm]
mode = "tpm"
tcti = "device:/dev/tpmrm0"                # Linux 内核驱动
# tcti = "swtpm:host=127.0.0.1,port=2321"  # 软件模拟
enable_startup_measurement = true
app_pcr_index = 16
```

---

### `[cluster]` — 集群（等保四级）

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `node_id` | string | `"standalone"` | 本节点 ID |
| `enabled` | bool | `false` | 启用集群模式 |
| `peer_port` | uint16 | `9443` | 节点间通信端口 |
| `[[cluster.peers]]` | array | `[]` | 对等节点列表 |

对等节点：

| 字段 | 类型 | 说明 |
|------|------|------|
| `node_id` | string | 节点 ID |
| `address` | string | 节点地址（host:port） |
| `ca_cert_path` | string | 节点 mTLS CA 证书（可选） |

示例：

```toml
[cluster]
node_id = "kms-node-01"
enabled = true
peer_port = 9443

[[cluster.peers]]
node_id = "kms-node-02"
address = "10.0.1.2:9443"
ca_cert_path = "/etc/kms/peer-ca.crt"

[[cluster.peers]]
node_id = "kms-node-03"
address = "10.0.1.3:9443"
ca_cert_path = "/etc/kms/peer-ca.crt"
```

---

## 完整配置示例

### 最小配置

```toml
[server]
port = 8443

[database]
url = "sqlite://data/kms.db?mode=rwc"

[auth]
admin_token = "my-token"
```

仅需覆盖要修改的字段，其余自动使用默认值。

### 生产环境（SQLite + 软件 HSM）

```toml
[server]
host = "0.0.0.0"
port = 8443

[server.tls]
cert_path = "/etc/kms/server.crt"
key_path = "/etc/kms/server.key"

[database]
url = "sqlite://data/kms.db?mode=rwc"
max_connections = 10

[hsm]
mode = "software"

[audit]
enable_chain = true
enable_signing = true

[policy]
enable_rbac = true
enforce_https = true

[auth]
admin_token = "production-admin-token"
totp_issuer = "Prod-KMS"

[trust]
expected_binary_hash = "344efa22dec4744c..."
```

### 生产环境（PostgreSQL + PKCS#11 HSM）

```toml
[server]
host = "0.0.0.0"
port = 8443
workers = 8

[server.tls]
cert_path = "/etc/kms/server.crt"
key_path = "/etc/kms/server.key"
client_ca_path = "/etc/kms/ca.crt"       # 启用 mTLS

[database]
url = "postgres://kms:secret@pg-host:5432/kms"
max_connections = 50
run_migrations = true

[crypto]
kek_path = "/data/kms/master.key"
key_rotation_days = 180
max_key_versions = 5
master_seed_path = "/data/kms/seed.bin"

[hsm]
mode = "pkcs11"
pkcs11_module_path = "/usr/lib/libsw11.so"
pkcs11_slot_id = 0
pkcs11_pin = "$HSM_PIN"

[audit]
log_path = "/data/kms/audit.log"
retention_days = 730

[policy]
enable_rbac = true
enforce_https = true

[auth]
admin_token = "$ADMIN_TOKEN"
totp_issuer = "Prod-KMS"

[trust]
expected_binary_hash = "344efa22dec4744c..."

[tpm]
mode = "tpm"
tcti = "device:/dev/tpmrm0"
enable_startup_measurement = true
app_pcr_index = 16
```

---

## HTTPS / mTLS 配置

### 自签名证书（测试用）

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key -out server.crt \
  -subj "/CN=localhost"
```

### CA 签发证书（生产用）

```bash
# 1. 生成 CA
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
  -keyout ca.key -out ca.crt -subj "/CN=KMS-CA"

# 2. 生成服务端证书
openssl req -new -nodes -newkey rsa:2048 \
  -keyout server.key -out server.csr -subj "/CN=kms.example.com"
openssl x509 -req -days 365 -in server.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

# 3. 生成客户端证书（mTLS 用）
openssl req -new -nodes -newkey rsa:2048 \
  -keyout client.key -out client.csr -subj "/CN=admin"
openssl x509 -req -days 365 -in client.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt
```

### mTLS 配置

```toml
[server.tls]
cert_path = "/etc/kms/server.crt"
key_path = "/etc/kms/server.key"
client_ca_path = "/etc/kms/ca.crt"  # 启用双向认证
```

客户端请求需要携带证书：

```bash
curl -k https://127.0.0.1:8443/api/v1/keys \
  --cert client.crt --key client.key \
  -H 'Authorization: Bearer <token>'
```

---

## CLI 管理命令

### 密钥备份恢复

```bash
# 导出所有密钥到文件
kms-server --config config.toml export-keys /backup/keys.json

# 从文件导入密钥
kms-server --config config.toml import-keys /backup/keys.json

# 备份 Master Seed
kms-server --config config.toml backup-seed /backup/seed.bin

# 恢复 Master Seed
kms-server --config config.toml restore-seed /backup/seed.bin
```

### 等保合规证据

```bash
# 导出合规证据包（审计日志、配置、哈希等）
kms-server --config config.toml --evidence /evidence-output/
```

### 完整性校验

```bash
# 计算当前二进制 SM3 哈希
kms-server --hash-self
# 输出: 344efa22dec4744c6e1e43fc29b2c8b9a3f7d5e1b0a2c3d4e5f6a7b8c9d0e1f
```

---

## 构建 / Feature 选项

```bash
# 默认（SQLite + 软件 HSM）
cargo build

# PostgreSQL + 软件 HSM
cargo build --features postgres

# SQLite + PKCS#11 HSM
cargo build --features pkcs11-hsm

# 完整功能
cargo build --features "pkcs11-hsm postgres monitoring tpm"
```

| Feature | 说明 | 依赖 |
|---------|------|------|
| `software-hsm` | 软件 KEK（默认） | 无 |
| `pkcs11-hsm` | PKCS#11 硬件 HSM | cryptoki |
| `sdf-hsm` | SDF 国密硬件 | 无 |
| `postgres` | PostgreSQL 支持 | sqlx/postgres |
| `sqlite` | SQLite 支持（默认） | sqlx/sqlite |
| `monitoring` | Prometheus 指标 + syslog | prometheus, syslog |
| `tpm` | 真实 TPM 2.0 | tss-esapi |
| `level3-compliant` | 等保三级增强 | 无 |

---

## 认证体系

KMS 支持三种认证方式，按以下顺序回退：

```
请求 → 静态 admin_token（内存比对）→ 动态 API Token（DB 查询）→ 401
```

### 静态 admin_token

配置 `auth.admin_token`，每个请求比对内存中的令牌值，零开销。

### 动态 API Token

可动态创建和吊销，SM3 哈希存储，支持 TTL 过期。

```bash
# 创建
curl -X POST http://localhost:8443/api/v1/auth/tokens \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"name":"ci-token", "ttl_secs": 86400}'

# 使用
curl -H 'Authorization: Bearer kms_...' http://localhost:8443/api/v1/keys

# 列表
curl http://localhost:8443/api/v1/auth/tokens \
  -H 'Authorization: Bearer <token>'

# 吊销
curl -X DELETE http://localhost:8443/api/v1/auth/tokens/<id> \
  -H 'Authorization: Bearer <token>'
```

Token 格式：`kms_` + 32 字节随机 → base64 URL-safe 编码，创建仅返回一次明文。

### TOTP 双因子认证

```bash
# 1. 登录获取 session
curl -X POST http://localhost:8443/api/v1/auth/login \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin"}'

# 2. TOTP 验证（获取 session_id 后）
curl -X POST http://localhost:8443/api/v1/auth/totp-verify \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"session_id":"...","totp_code":"123456"}'

# 3. 携带 X-Session-Id 访问受保护端点
curl -H 'Authorization: Bearer <token>' \
  -H 'X-Session-Id: ...' \
  http://localhost:8443/api/v1/keys
```

### 恢复码

```bash
# 生成恢复码（需先完成 TOTP 绑定）
curl -X POST http://localhost:8443/api/v1/auth/recovery-codes \
  -H 'Authorization: Bearer <token>' \
  -H 'X-Session-Id: ...'

# 使用恢复码登录
curl -X POST http://localhost:8443/api/v1/auth/recovery \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","recovery_code":"..."}'
```

---

## 密钥操作

```bash
# 创建密钥
curl -X POST http://localhost:8443/api/v1/keys \
  -H 'Authorization: Bearer <token>' \
  -H 'X-Session-Id: <sid>' \
  -H 'Content-Type: application/json' \
  -d '{"name":"my-key","algorithm":"sm4","key_length":128}'

# 信封加密（生成数据密钥）
curl -X POST http://localhost:8443/api/v1/keys/<id>/datakey \
  -H 'Authorization: Bearer <token>' \
  -H 'X-Session-Id: <sid>'

# 信封解密
curl -X POST http://localhost:8443/api/v1/keys/<id>/decrypt \
  -H 'Authorization: Bearer <token>' \
  -H 'X-Session-Id: <sid>' \
  -H 'Content-Type: application/json' \
  -d '{"ciphertext":"<encrypted_key>","nonce":"<nonce>"}'

# 启/禁/轮换/归档/销毁
curl -X POST http://localhost:8443/api/v1/keys/<id>/enable   -H ...
curl -X POST http://localhost:8443/api/v1/keys/<id>/disable  -H ...
curl -X POST http://localhost:8443/api/v1/keys/<id>/rotate   -H ...  # 需审批
curl -X POST http://localhost:8443/api/v1/keys/<id>/archive  -H ...  # 需审批
curl -X POST http://localhost:8443/api/v1/keys/<id>/destroy  -H ...  # 需审批
```

---

## 审计日志

```bash
# 查询审计日志
curl -s 'http://localhost:8443/api/v1/audit/logs?limit=10&offset=0' \
  -H 'Authorization: Bearer <token>' \
  -H 'X-Session-Id: <sid>'

# 验证审计链完整性
curl -s 'http://localhost:8443/api/v1/audit/verify' \
  -H 'Authorization: Bearer <token>' \
  -H 'X-Session-Id: <sid>'
```

## 入侵检测与封禁

```bash
# 查看封禁列表
curl http://localhost:8443/api/v1/admin/blocklist \
  -H 'Authorization: Bearer <token>' \
  -H 'X-Session-Id: <sid>'

# 手动解封
curl -X POST http://localhost:8443/api/v1/admin/unblock/<ip> \
  -H 'Authorization: Bearer <token>' \
  -H 'X-Session-Id: <sid>'
```

## 监控指标

启用 `monitoring` feature 后：

```bash
curl http://localhost:8443/api/v1/metrics
```

Prometheus 端点，包含请求计数、延迟、密钥操作等指标。

## 安全标记（MAC）

通过 `X-Security-Level` 头传递安全级别：

| 级别 | 值 | 说明 |
|------|-----|------|
| 公开 | `Public` | 可公开信息 |
| 内部 | `Internal` | 内部使用 |
| 秘密 | `Secret` | 需授权访问 |
| 机密 | `Classified` | 严格受限 |
| 绝密 | `TopSecret` | 最高等级 |

遵循 Bell-LaPadula 模型：读向下、写向上（简单安全属性 + 星属性）。
