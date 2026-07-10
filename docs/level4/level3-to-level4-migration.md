# Level3 → Level4 配置迁移指南

## 概述

本文档说明如何从等保三级（Level3）模式迁移至等保四级（Level4）模式。

## 配置变更清单

| 配置项 | Level3 | Level4 | 说明 |
|--------|--------|--------|------|
| `auth.security_level` | `"level3"`（默认） | `"level4"` | 主开关 |
| `auth.admin_token` | 可选 | **必须** | level4 拒绝无 admin_token 启动 |
| `auth.anti_repudiation` | 可选 | 建议启用 | 法律责任保护 |
| `hsm.mode` | `"software"` | `"pkcs11"` / `"sdf"` | 生产画像必须 |
| `level4.session_timeout_seconds` | — | 600（默认） | 会话超时比 level3 更严格 |
| `level4.sensitive_operation_reauth_ttl_seconds` | — | 300（默认） | 二次鉴权 TTL |

## 功能行为变化

| 功能 | Level3 行为 | Level4 行为 | 影响 |
|------|------------|-------------|------|
| API 认证 | Bearer Token | Bearer + **二次鉴权** | 敏感操作需要多一步 TOTP 验证 |
| 会话超时 | 1 小时（可配） | 10 分钟（可配） | 更频繁重新登录 |
| 审计关闭 | 可关闭 | **不可关闭** | 试关闭导致告警 |
| 审计签名 | 可选 | **强制** | 所有审计事件签名 |
| MAC 校验 | 部分客体 | **主体+客体全覆盖** | 低标记用户无法访问高标记密钥 |
| 输入验证 | 无 | **白名单校验** | 格式异常请求被拒绝 |
| HSM | 软件 provider | **生产必须硬件 HSM** | 性能变化 ~1-10ms 额外延迟 |

## 迁移步骤

### 第一步：准备配置

创建 level4 配置文件：

```toml
[auth]
security_level = "level4"
admin_token = "<your-admin-token>"
totp_issuer = "KMS"
anti_repudiation = true
sensitive_operations = ["DESTROY", "DISABLE", "ROTATE", "EXPORT", "SET_LABEL", "ATTACH_POLICY"]

[server]
session_ttl_secs = 600

[hsm]
mode = "pkcs11"
pkcs11_module_path = "/usr/lib/libswsds.so"
pkcs11_slot_id = 0
pkcs11_pin = "<hsm-pin>"

[level4]
session_timeout_seconds = 600
sensitive_operation_reauth_ttl_seconds = 300

[audit]
enable_chain = true
enable_signing = true
```

### 第二步：开发/测试环境验证

```bash
# 使用 dev profile 测试
cargo run -- --config config-level4.toml --profile dev
```

### 第三步：生产环境部署

1. 配置 HSM/密码卡
2. 配置 mTLS（参考 [mtls-guide.md](./mtls-guide.md)）
3. 配置审计管理中心上报端点
4. 启动并验证启动摘要日志中的 Level4 标记

### 第四步：回归验证

```bash
# Level3 兼容性测试
cargo test --test level3_compatibility -- --nocapture
# Level4 全链路测试
cargo test --test level4_full_chain -- --nocapture
```

## 回滚

如果 Level4 模式出现问题，可随时切回 Level3：

```toml
[auth]
security_level = "level3"  # 切回三级
```

回滚后所有 Level4 新增行为关闭，无需数据迁移。
