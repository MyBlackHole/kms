# 等保四级配置说明

## 配置结构

等保四级配置位于 `[auth]` 和 `[level4]` 段：

```toml
# ==========================================
# 等保三级/四级主开关
# ==========================================
[auth]
security_level = "level3"   # "level3"（默认）| "level4"

# ==========================================
# 运行画像（profile）
# ==========================================
# 可在配置文件中或通过 CLI --profile 指定
# profile = "production"  # 默认，用于生产环境
# profile = "dev"         # 开发环境，允许软件模拟
# profile = "ci"          # CI 环境，允许软件模拟

# ==========================================
# 等保四级详细配置 (仅 level4 生效)
# ==========================================
[level4]
# --- 身份鉴别 ---
# 服务端会话超时秒数（默认 600，即 10 分钟）
session_timeout_seconds = 600

# 敏感操作二次鉴权 TTL（默认 300，即 5 分钟）
sensitive_operation_reauth_ttl_seconds = 300

# --- 审计上报 ---
# 审计管理中心上报端点（HTTPS POST）
# audit_management_center_endpoint = "https://audit-center.example/events"

# 审计上报配置需要安全管理员权限（默认 true）
# audit_reporting_requires_security_admin = true

# --- HSM 配置 ---
# HSM PKCS#11 模块路径
# hsm_pkcs11_module = "/usr/lib/libswsds.so"
# HSM Slot ID（默认 0）
# hsm_slot_id = 0

# 生产环境是否必须使用 HSM（默认 true）
# hsm_required_in_production = true

# 开发/CI 是否允许软件 provider 模拟 HSM（默认 true）
# hsm_allow_software_provider_in_dev = true

# --- mTLS 配置 ---
# 管理 API 是否需要 mTLS
# mtls_required_for_management_api = false

# --- 可信验证 ---
# 可信验证上报端点
# trusted_verification_report_endpoint = "https://security-center.example/trust"

# ==========================================
# 抗抵赖模块
# ==========================================
[auth]
anti_repudiation = false   # 默认关闭，法律责任场景启用
```

## 安全画像模型

| 画像 | 配置方式 | HSM 要求 | 宽松 Bearer | 使用场景 |
|------|---------|---------|------------|---------|
| **production** | 默认 / `--profile production` | Level4 必须 | 禁止 | 生产环境 |
| **dev** | `--profile dev` | 可用软件模拟 | Level3 下允许 | 本地开发 |
| **ci** | `--profile ci` | 可用软件模拟 | Level3 下允许 | CI 测试 |

## level4 封闭安全画像说明

Level4 模式是封闭安全画像，以下关键控制项不可单独降配：

| 控制项 | 固定值 | 说明 |
|--------|--------|------|
| 双因素认证 | 强制 | 口令 + TOTP |
| 二次鉴权 | 强制 | 敏感操作需重新认证 |
| MAC 全覆盖 | 强制 | 主体/客体安全标记校验 |
| 审计不可关闭 | 强制 | 应用内审计功能始终启用 |
| HSM（生产）| 强制 | 生产画像必须使用 HSM |
| 严格输入验证 | 强制 | 白名单校验 |

需要降级时必须切换到 level3 或显式非生产画像。

## 启动校验

Level4 模式下启动时会执行以下校验：

1. `admin_token` 必须配置
2. 审计签名必须启用
3. 审计哈希链必须启用
4. RBAC 必须启用
5. Session TTL 不得超过 `level4.session_timeout_seconds`
6. 生产画像下 HSM 模式不能为 `software`
7. 如果提供了 HSM 模块路径，尝试加载并执行自检

## 配置迁移从 Level3 到 Level4

```
Level3:                                         Level4:
[auth]                                          [auth]
admin_token = "..."                             security_level = "level4"
  ← 无                                           admin_token = "..."

[hsm]                                           [level4]
mode = "software"                               session_timeout_seconds = 600
                                                 hsm_pkcs11_module = "/usr/lib/libswsds.so"

                                                [hsm]
                                                mode = "pkcs11"
```

完整迁移指南参见 [level3-to-level4-migration.md](./level3-to-level4-migration.md)。
