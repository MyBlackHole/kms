# 等保四级支持概述

## 什么是等保四级

网络安全等级保护制度是中国信息安全的基本制度。GB/T 22239-2019 将安全保护等级分为五级，其中第四级（简称"等保四级"或"Level4"）适用于：

> 应能够在统一安全策略下防护免受来自**国家级别的、敌对组织的、拥有丰富资源的威胁源**发起的恶意攻击、严重的自然灾害，以及其他相当危害程度的威胁所造成的资源损害，能够及时发现、监测发现攻击行为和安全事件，在自身遭到损害后，能够**迅速恢复所有功能**。

四级系统约全国 1000 个（如中央电视台播出系统），大部分系统定级为二级或三级。

## 交付目标

本 KMS 系统将当前"等保三级"定位扩展为可支撑"网络安全等级保护第四级"测评准备的能力包，覆盖：

1. **Layer 1 — 应用内实现**（KMS 仓库代码）：身份鉴别增强、MAC 全覆盖、审计增强、抗抵赖、HSM 对接、输入验证等
2. **Layer 2 — 部署/运维配合**：mTLS 配置、安全管理中心对接、主机加固、灾备等
3. **Layer 3 — 第三方测评确认**：测评机构检测、商密评估、源代码审计等

**不承诺正式通过四级测评**（涉及基础设施和制度部分超出仓库范围），但代码和文档层面已完成四级差异项实现。

## 使用方式

等保四级功能以配置开关方式提供，不改变三级默认行为。

```toml
[auth]
security_level = "level3"   # 默认，等保三级行为
# security_level = "level4" # 启用全部四级增强

# 运行画像（覆盖配置中的 profile 设置）
# 可通过 CLI 参数 --profile production|dev|ci 指定
```

更多配置项参见 [configuration.md](./configuration.md)。

## 核心控制点覆盖

| 控制点 | Level3 | Level4 |
|--------|--------|--------|
| 身份鉴别 | 双因素（TOTP + Bearer） | 双因素 + **重要操作二次鉴权** |
| 访问控制 | DAC + 安全标记 | **MAC 主体/客体全覆盖** |
| 安全审计 | 可关闭 | **应用内审计不可关闭** + 管理中心上报 |
| 抗抵赖 | 无 | **数据原发/接收证据**（可选） |
| 密码运算 | 软件 provider | **HSM/PKCS#11 生产必选** |
| 通信安全 | TLS（可选） | **mTLS 双向认证** + HSM |
| 输入验证 | 无 | **白名单校验** |
| 会话管理 | 基础超时 | **服务端超时 + 防劫持** |

## 快速开始

### Level3 模式（默认，无变化）

```bash
cargo run -- --config config.toml
```

### Level4 开发模式

```bash
# 配置 level4 + dev profile
cat > config-level4.toml << 'EOF'
[auth]
security_level = "level4"
admin_token = "your-admin-token"

[level4]
hsm_allow_software_provider_in_dev = true
EOF

cargo run -- --config config-level4.toml --profile dev
```

### Level4 生产模式

```bash
# 配置 level4 + production（需要 HSM）
cargo run --features pkcs11-hsm -- --config config-level4-prod.toml
```

## 实现架构

```
┌─────────────────────────────────────────────────────┐
│                   KMS Application                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │ Auth     │ │ MAC+     │ │ Audit +          │   │
│  │ 2FA+ReAuth│ │ Access   │ │ Anti-Repudiation │   │
│  └────┬─────┘ └────┬─────┘ └────────┬─────────┘   │
│       │            │                │              │
│  ┌────┴────┐ ┌────┴────────┐ ┌─────┴───────────┐  │
│  │ HSM +   │ │ Input       │ │ Security Config │  │
│  │ mTLS    │ │ Validation  │ │ (Phase-0)       │  │
│  └─────────┘ └─────────────┘ └─────────────────┘  │
└────────────────────────────────────────────────────┘
```

详见架构设计文档 [design.md](../../.trellis/tasks/07-01-support-mlps-level-4/design.md)。
