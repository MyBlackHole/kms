# HSM 部署说明

## 概述

等保四级要求**基于硬件密码模块进行密码运算和密钥管理**。本 KMS 支持通过 PKCS#11 接口对接硬件密码模块（HSM/密码卡）。

## 架构

```
KMS → PKCS#11 接口 → HSM/密码卡
     └── cryptoki crate (Rust PKCS#11 绑定)
        └── hsm_pkcs11_module (如 libswsds.so, libsofthsm2.so)
```

## 支持模式

| 模式 | 说明 | 生产环境 | 开发/CI |
|------|------|---------|---------|
| `software` | 软件 KEK provider | ❌ Level4 | ✅ Level4 dev |
| `pkcs11` | PKCS#11 标准接口 | ✅ | ✅ |
| `sdf` | 国密 SDF 接口 | ✅ | ✅ |

## 生产环境部署（Level4 必选）

### 前置条件

1. 已安装 HSM 或密码卡硬件
2. 已安装对应的 PKCS#11 驱动（如 `libswsds.so`）
3. 获取 Slot ID 和 PIN

### 编译

```bash
cargo build --release --features pkcs11-hsm
```

### 配置

```toml
[hsm]
mode = "pkcs11"
pkcs11_module_path = "/usr/lib/libswsds.so"
pkcs11_slot_id = 0
pkcs11_pin = "<hsm-pin>"

[auth]
security_level = "level4"

[level4]
hsm_required_in_production = true
```

### 启动自检

Level4 生产画像启动时会自动执行 HSM 自检：

- PKCS#11 模块加载
- Slot 打开
- 会话登录
- 密钥操作探测

自检失败拒绝启动。

## 开发/CI 环境

开发环境可使用 SoftHSM 模拟或软件 provider 模拟：

```bash
# 安装 SoftHSM
apt install softhsm2

# 配置使用 SoftHSM
[hsm]
mode = "pkcs11"
pkcs11_module_path = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
pkcs11_slot_id = 0
pkcs11_pin = "1234"

# 或使用软件模拟（dev profile）
cargo run -- --profile dev
```

软件模拟模式下启动日志会明确标记为非生产四级模式。

## 性能影响

HSM 调用增加约 1-10ms 延迟（取决于硬件和网络），建议在性能测试中确认。
