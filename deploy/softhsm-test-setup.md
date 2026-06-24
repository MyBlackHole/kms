# SoftHSM 测试环境配置

用于在开发环境中模拟 PKCS#11 HSM，验证 KMS 硬件密码模块（等保四级 #22）。

## 安装 SoftHSM

```bash
# Ubuntu / Debian
sudo apt install softhsm2

# CentOS / RHEL / Fedora
sudo dnf install softhsm

# macOS
brew install softhsm

# 验证安装
softhsm2-util --version
# 应输出: 2.7.0 (或更高)
```

## 初始化测试 Token

```bash
# 创建 token（PIN 1234, SO-PIN 5678）
softhsm2-util --init-token --slot 0 --label "KMS Test" --pin 1234 --so-pin 5678

# 查看已初始化的 slot
softhsm2-util --show-slots

# 记下输出中的 Slot ID（例如 1011352824），配置时需要
```

## 配置 KMS

编辑 `config-test-hsm.toml`：

```toml
[hsm]
mode = "pkcs11"
pkcs11_module_path = "/usr/lib/softhsm/libsofthsm2.so"
pkcs11_slot_id = 1011352824   # 替换为 --show-slots 输出的实际 slot
pkcs11_pin = "1234"
```

> **注意**：每次重新初始化 token 时 slot ID 会变化，需同步更新配置。

## 编译并启动

```bash
# 启用 pkcs11-hsm feature 编译
cargo build --features pkcs11-hsm --release

# 启动 KMS（使用 HSM 模式）
./target/release/kms-server --config config-test-hsm.toml
```

启动日志应包含：
```
INFO  KEK 提供程序: pkcs11-hsm-1011352824
INFO  PKCS#11 HSM ready: slot=1011352824
```

## 运行集成测试

```bash
# 运行 SoftHSM 集成测试（--ignored 因为需要外部硬件）
cargo test --features pkcs11-hsm -- --ignored --nocapture
```

预期输出：
```
test hsm::pkcs11_provider::tests::test_pkcs11_provider_softhsm ... ok
```

测试验证内容：
1. `Pkcs11KekProvider::new()` — C_Initialize / C_OpenSession / C_Login
2. `generate_random(32)` — C_GenerateRandom 返回 32 字节硬件随机数
3. `wrap_key()` — C_Encrypt(CKM_AES_GCM) 密钥包装
4. `unwrap_key()` — 返回 KEK 32 字节

## 常见问题

### "PKCS#11 模块加载失败"

```bash
# 确认 so 文件位置
find /usr -name "libsofthsm2.so" 2>/dev/null
# 常见位置: /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so

# 如不存在，重新安装:
sudo apt install --reinstall softhsm2
```

### "HSM 登录失败"

```bash
# 确认 PIN 正确（默认 1234）
# 重新初始化 token:
softhsm2-util --init-token --slot 0 --label "KMS Test" --pin 1234 --so-pin 5678 --force
```

### "HSM session open failed"

```bash
# 检查 softhsm2 配置文件
cat /etc/softhsm/softhsm2.conf
# 默认:
# directories.tokendir = /var/lib/softhsm/tokens/

# 确认 token 目录存在且可写:
ls -la /var/lib/softhsm/tokens/
```

## 清理测试数据

```bash
# 删除所有 token（重新开始）
sudo rm -rf /var/lib/softhsm/tokens/*
sudo systemctl restart softhsm2  # 如使用 systemd 服务
```

## 对接真实 HSM

SoftHSM 验证通过后，切换到真实密码卡只需更换配置：

```toml
[hsm]
mode = "pkcs11"
pkcs11_module_path = "/usr/lib/libpkcs11.so"    # 密码卡厂商提供的 .so
pkcs11_slot_id = 0
pkcs11_pin = "********"                          # 实际 PIN
```
