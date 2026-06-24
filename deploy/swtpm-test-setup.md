# swtpm 测试环境配置

用于在开发环境中模拟 TPM 2.0，验证 KMS 可信根模块（等保四级 #21）。

## 安装

```bash
# Ubuntu / Debian
sudo apt install swtpm swtpm-tools

# 编译安装（如 apt 版本过旧）
# git clone https://github.com/stefanberger/swtpm.git
# cd swtpm && ./autogen.sh && make && sudo make install

# 验证
swtpm --version
# 应输出: TPM emulator version 0.10.x
```

## 启动 TPM 模拟器

```bash
# 创建状态目录
mkdir -p /tmp/kms-swtpm

# 启动 swtpm（TCP 接口）
swtpm socket \
  --tpmstate dir=/tmp/kms-swtpm \
  --tpm2 \
  --server type=tcp,port=2321 \
  --ctrl type=tcp,port=2322 \
  --flags not-need-init &

# 验证启动
ss -tlnp | grep -E '232[12]'

# 应看到 LISTEN 状态 on 127.0.0.1:2321 和 2322
```

## 停止

```bash
# 关停 swtpm
pkill swtpm

# 清理状态（可选）
rm -rf /tmp/kms-swtpm
```

## 集成测试用法

KMS 的 `SoftwareTpm` 模拟了 TPM 2.0 的基本操作（PCR 度量、seal/unseal），
可在无真实 TPM 硬件或 swtpm 时正常开发和测试。

```bash
# 运行 TPM 相关单元测试（无需 swtpm）
cargo test -- trust::tpm
# 输出: 5 passed
```

如需对接真实 swtpm/TPM 硬件（通过 TSS2 ESAPI），需添加 `tpm` feature：

```bash
# 启用 tpm feature（占位，待 tss-esapi 集成）
cargo build --features tpm
```

## 验证 TPM 功能

KMS 启动时自动执行 TPM PCR 度量：

```bash
# 正常启动（使用 SoftwareTpm 模拟）
cargo run -- --config config.toml 2>&1 | grep PCR
# 应输出: TPM PCR[16] 度量二进制哈希: xxxx
```

在 `config.toml` 中可控制 TPM 行为：

```toml
[tpm]
mode = "software"          # software | tpm（tpm 模式需硬件）
enable_startup_measurement = true
app_pcr_index = 16
```

## 常见问题

### "Address already in use"

```bash
# 检查端口占用
ss -tlnp | grep -E '232[12]'
# 杀掉旧进程
pkill swtpm
# 或使用其他端口:
swtpm socket --server type=tcp,port=2323 --ctrl type=tcp,port=2324 ...
```

### "TPM PCR 度量失败 (非致命)"

此警告表示 TPM 模块未正常初始化。SoftwareTpm 模式下不影响 KMS 核心功能。
如使用真实 TPM，请确认：
- `/dev/tpm0` 存在且有读写权限
- 内核启用了 TPM 支持（`ls /sys/class/tpm/`）
- 当前用户属于 `tss` 组（`sudo usermod -aG tss $USER`）
