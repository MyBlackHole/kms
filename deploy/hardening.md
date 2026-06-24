# KMS 主机加固指南

## 1. 系统服务权限

```bash
# 创建专用用户
sudo useradd -r -s /sbin/nologin -d /opt/kms kms

# 文件权限
sudo chown -R kms:kms /opt/kms
sudo chmod 750 /opt/kms
sudo chmod 640 /opt/kms/config.toml
sudo chmod 640 /opt/kms/data/master.seed
```

## 2. 内核加固

```bash
# 禁用 core dump
echo "kms-server hard core 0" | sudo tee /etc/security/limits.d/kms.conf
echo "* hard core 0" | sudo tee -a /etc/security/limits.d/kms.conf

# 限制 swap 使用
sudo sysctl -w vm.swappiness=1

# 内核地址空间随机化（默认应已开启）
sudo sysctl -w kernel.randomize_va_space=2
```

## 3. seccomp 推荐策略

```bash
# 使用 systemd 的 SystemCallFilter（已在 .service 中配置）
# 也可手动测试:
sudo -u kms strace -c -f /opt/kms/kms-server --config /opt/kms/config.toml 2>&1
```

systemd service 已包含:
```
SystemCallFilter=@system-service
SystemCallArchitectures=native
```

## 4. SELinux (可选)

若系统启用 SELinux，创建策略模块:

```bash
# 生成类型强制文件
sepolicy generate --init -n kms -d /opt/kms/kms-server
# 编译安装
sudo semodule -i kms.pp
```

## 5. 内存锁定

KMS 启动时自动调用 `mlock()` 锁定 master_key 和密钥材料内存。
确认生效:

```bash
grep VmLck /proc/$(pidof kms-server)/status
# 应显示非零值
```

## 6. 审计日志保护

```bash
# 审计日志文件设为仅追加
sudo chattr +a /opt/kms/data/audit_events.db

# 日志轮转
cat > /etc/logrotate.d/kms << 'EOF'
/opt/kms/data/audit.log {
    daily
    rotate 365
    compress
    delaycompress
    missingok
    notifempty
    create 640 kms kms
}
EOF
```

## 7. 网络加固

```bash
# 仅监听本地 loopback（默认配置）
# 生产环境建议置于内网并配置防火墙
sudo ufw allow from 10.0.0.0/8 to any port 8443 proto tcp
sudo ufw deny 8443
```

## 8. 定时完整性校验

```bash
# 每日校验二进制和配置哈希
cat > /etc/cron.daily/kms-integrity << 'SCRIPT'
#!/bin/sh
/opt/kms/kms-server hash-self > /var/log/kms-hash.log
sha256sum /opt/kms/config.toml > /opt/kms/config.hash
SCRIPT
sudo chmod +x /etc/cron.daily/kms-integrity
```


## 9. 等保四级增强

等保四级共 9 项要求，分为 **代码实现** 和 **运维实施** 两类：

| 类型 | 项 | 说明 |
|------|----|------|
| ✅ 代码实现 | #21 TPM 可信根 | SoftwareTpm + TssTpm(tss-esapi) 两套实现 |
| ✅ 代码实现 | #22 硬件密码模块 | PKCS#11 cryptoki 对接 + SoftHSM 实测通过 |
| ✅ 代码实现 | #23 入侵自动阻断 | Blocklist 累进封禁 + REST API |
| ✅ 代码实现 | #25 可信启动链 | 启动时 PCR[16] 度量二进制+配置 |
| ✅ 代码实现 | #27 节点间通信 | ClusterConfig + PeerConfig 框架 |
| ✅ 代码实现 | #28 灾难恢复 | CLI backup-seed/restore-seed/export-keys/import-keys |
| ⚠️ 运维实施 | #24 全盘加密 | §9.1 — 需运维执行 LUKS 加密 |
| ⚠️ 运维实施 | #26 物理安全 | §9.3 — 需机房部署硬件防护 |
| ⚠️ 运维实施 | #29 资源隔离 | §9.7 — 需配置 cgroup/SELinux |

代码框架已全部就绪，⚠️ 项需要运维按照以下指南执行才能完全达标。



### 9.1 全盘加密（运维实施）

**等保四级要求**：所有持久化存储介质必须加密，防止物理磁盘拆卸导致密钥材料泄露。

**KMS 的代码层**：无侵入式加密代码（加密应由 OS 层完成）。KMS 在启动时可通过 `TrustVerifier` 校验关键文件完整性，但全盘加密本身是 OS 管理员的职责。

**运维操作**：推荐使用 LUKS2 对系统盘和数据盘分别加密。

```bash
# ---- 数据盘加密（推荐独立磁盘 /dev/sdb） ----

# 1. 分区
sudo parted /dev/sdb mklabel gpt
sudo parted /dev/sdb mkpart primary ext4 0% 100%

# 2. 创建 LUKS2 加密容器（使用 Argon2 KDF）
sudo cryptsetup luksFormat --type luks2 --pbkdf argon2id /dev/sdb1

# 3. 打开容器
sudo cryptsetup open /dev/sdb1 kms-data

# 4. 创建文件系统
sudo mkfs.ext4 /dev/mapper/kms-data

# 5. 挂载
sudo mount /dev/mapper/kms-data /opt/kms/data

# 6. 自动挂载配置（/etc/crypttab）
echo 'kms-data /dev/sdb1 none luks' | sudo tee -a /etc/crypttab

# 7. /etc/fstab 追加
echo '/dev/mapper/kms-data /opt/kms/data ext4 defaults,noexec,nodev,nosuid 0 2' | sudo tee -a /etc/fstab

# ---- 系统盘完整性校验 ----
# 建议启用 dm-verity 或 Integrity Measurement Architecture (IMA)
# 使用 AIDE 进行文件完整性基线:
sudo apt install aide
sudo aideinit
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
# 每日检查:
echo '0 6 * * * root /usr/bin/aide --check | mail -s "AIDE report" admin@example.com' | sudo tee -a /etc/crontab

# ---- 密钥材料保护 ----
# 确保 master.seed 和密钥数据库在加密分区上
# KMS 配置示例:
#   [crypto]
#   master_seed_path = "/opt/kms/data/encrypted/master.seed"
#   [database]
#   url = "sqlite:///opt/kms/data/encrypted/kms.db"
```

### 9.2 TPM 可信启动链

```bash
# 启用 TPM 2.0 PCR 度量（需硬件支持）
# BIOS:   PCR 0 → 启用 Secure Boot
# 内核:   PCR 1 → 度量内核镜像
# KMS:    PCR 16 → KMS 应用度量（二进制+配置）
# 每次启动时自动扩展 PCR 值，非法替换将导致密钥解封失败
```

### 9.3 物理安全（运维实施）

**等保四级要求**：硬件层面的物理防护，防止攻击者通过物理接触窃取或篡改密钥。

**KMS 的代码层**：
- TPM 模块提供 `PcrIndex::KmsApp`（PCR 16），可配合机箱侵入传感器
- 机箱打开 → GPIO 触发 TPM PCR 复位 → KMS 启动时检测 PCR 异常 → 阻止密钥解封
- HSM provider 要求密钥操作在硬件密码卡内完成，密钥材料不出设备

**但以下必须由机房运维执行**（代码无法替代）：
- 服务器机柜上锁 + 双人开柜流程
- HSM 密码卡物理固定、防拆卸
- 管理口（串口/IPMI）与业务网络物理隔离
- 温湿度监控、UPS、气体灭火

```bash
# ---- 硬件选型 ----
# HSM / 密码卡（四级必选）:
# - 江南天安 SJJ1310 系列（GM/T 0018-2012 SDF 接口）
# - 渔翁信息 SJJ1928 系列（PKCS#11 + SDF 双接口）
# - 三未信安 SJJ1416 系列（PCIe + 远程管理）
#
# KMS 支持 SDF 和 PKCS#11 两种接口：
#   [hsm]
#   mode = "pkcs11"
#   pkcs11_module_path = "/usr/lib/libpkcs11.so"
#   pkcs11_slot_id = 0
#   pkcs11_pin = "********"
#
# 或:
#   [hsm]
#   mode = "sdf"
#   software_master_seed = "/dev/crypto/sdf"

# ---- 机箱侵入检测 ----
# 配合 TPM 实现：打开机箱触发 PCR 复位，HSM 密钥自动销毁
# 实现方式:
# 1. 主板机箱侵入开关连接 GPIO
# 2. GPIO 中断触发 TPM PCR[16] 复位
# 3. KMS 启动时检测 PCR 值，若异常则拒绝解封密钥
#
# 验证机箱侵入:
# sudo cat /sys/devices/platform/tpm/tpm0/pcr-read/16
# 记录基准值，侵入后应变化

# ---- 物理访问控制 ----
# - 服务器机柜上锁，双人开柜
# - HSM 管理口和业务口物理隔离
# - 串口/管理网口禁用或接入独立管理网络
# - 禁用 USB 存储:
echo 'blacklist usb-storage' | sudo tee /etc/modprobe.d/disable-usb-storage.conf

# ---- 环境安全 ----
# - 部署区域应配备视频监控 + 门禁系统
# - 温湿度监控（建议 20-25°C / 40-60% RH）
# - UPS 不间断电源（支持至少 30 分钟正常关机）
# - 消防系统（气体灭火，非水喷淋）

# ---- 操作合规 ----
# - HSM 管理员操作全程录像
# - 密钥注入需双人到场（双人复核）
# - 硬件维护前需执行密钥备份并验证可用
```

### 9.4 入侵自动阻断

```bash
# KMS 内置自动封禁（源代码级）
# - 登录失败超限 → IP 临时封禁（累进：5min → 10min → 20min → … → 24h）
# - API 速率超限 → 账户暂停 5 分钟
# - 手动封禁 → 永久封禁 / 管理员手动解封
# 查看活跃封禁:
curl -X GET https://kms:8443/api/v1/admin/blocklist \
  -H "Authorization: Bearer <admin-token>"
```

### 9.5 节点间可信通信（集群预留）

```bash
# 等保四级要求节点间通信加密
# 预留 mTLS 互认证通道：
# - 每个集群节点拥有独立证书
# - 节点间通信使用 TLCP/GM/TLS
# - 当前为单机部署，扩展集群时需启用
```

### 9.6 灾难恢复与 RTO/RPO

```bash
# 目标：RTO ≤ 30 分钟，RPO ≤ 5 分钟
# 备份方案：
# 1. Master seed 异地备份（每日）
#    rsync -a /opt/kms/data/master.seed backup@dr-site:/backup/kms/
# 2. 密钥库定时导出（每小时）：
#    /opt/kms/kms-server export-keys --output /backup/kms/keys-$(date +%Y%m%d%H).json
# 3. 恢复演练（每月）：
#    /opt/kms/kms-server --restore-from /backup/kms/seed-backup.dat
# 审计日志异地同步（实时）：使用 syslog 远程转发
```

### 9.7 安全标记与资源控制（运维实施）

**等保四级要求**：进程级资源隔离和强制访问控制（MAC），防止同一主机上的其他进程影响 KMS。

**KMS 的代码层**：
- systemd unit 已内置：`ProtectSystem=strict`、`PrivateTmp`、`NoNewPrivileges=yes`、`CapabilityBoundingSet`
- 内置 `SecurityLabel` MAC 引擎（`policy/label.rs`），支持多级安全标记 + 分类标签
- 启动时自动 `mlock()` 锁定 master_key 内存

**以下必须由 OS 管理员配置**：
- cgroup CPU/内存限制（`systemd override.conf`）
- SELinux 策略模块或 AppArmor 配置文件
- 文件系统 `noexec,nodev,nosuid` 挂载选项

```bash
# ---- systemd 资源限制 ----
# /etc/systemd/system/kms-server.service.d/override.conf:
[Service]
# CPU 限制
CPUQuota=200%
# 内存限制（根据实际配置调整）
MemoryMax=2G
MemoryHigh=1.5G
# IO 限制
IOReadBandwidthMax="/dev/sda 100M"
IOWriteBandwidthMax="/dev/sda 50M"
# 进程数限制
TasksMax=100
# 文件描述符限制
LimitNOFILE=65536
# 禁止特权提升
NoNewPrivileges=yes
# 只读文件系统保护
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
# 网络隔离
PrivateNetwork=no  # KMS 需要网络

# ---- 内核命名空间隔离 ----
# 已内置于 deploy/kms.service:
#   CapabilityBoundingSet=CAP_IPC_LOCK CAP_NET_BIND_SERVICE
#   ProtectSystem=full
#   PrivateDevices=yes
#   ProtectKernelModules=yes
#   ProtectKernelTunables=yes

# ---- KMS 内置安全标记（MAC） ----
# KMS 支持 SecurityLabel 标记，结合 RBAC 实现 MAC：
# 设置密钥的安全标记:
# curl -X POST https://kms:8443/api/v1/keys/:id/label \
#   -H "Authorization: Bearer <admin-token>" \
#   -d '{"level": "Secret", "categories": ["finance", "prod"]}'
#
# 安全标记规则:
# - TopSecret 可读 Secret，反之不行
# - 密钥只能被具有相同或更高安全等级的主体访问
# - 分类标签做交集匹配（主体需包含密钥的所有分类）

# ---- SELinux 强制策略 ----
# 启用 SELinux 并设为 Enforcing:
sudo setenforce 1
# 修改 /etc/selinux/config:
# SELINUX=enforcing
# 为 KMS 创建自定义策略:
sudo ausearch -c kms-server --raw | audit2allow -M kms-server
sudo semodule -i kms-server.pp
# 确认策略加载:
sudo semodule -l | grep kms

# ---- AppArmor 替代方案 ----
# 如使用 AppArmor 而非 SELinux:
sudo aa-genprof /opt/kms/kms-server
# 配置 /etc/apparmor.d/opt.kms.kms-server:
#   /opt/kms/data/** rwk,
#   /opt/kms/config.toml r,
#   /opt/kms/log/** rw,
#   /dev/tpm0 rw,
#   /dev/urandom r,
#   network tcp,
sudo aa-enforce /opt/kms/kms-server

# ---- 文件系统安全挂载 ----
# /etc/fstab:
# /dev/mapper/kms-data /opt/kms/data ext4 defaults,noexec,nodev,nosuid,relatime 0 2
# /tmp                   tmpfs tmpfs defaults,noexec,nosuid,nodev,size=1G 0 0
# /var/tmp               tmpfs tmpfs defaults,noexec,nosuid,nodev,size=512M 0 0
```

### 9.8 合规验证清单

| # | 要求 | 验证方法 | 命令/工具 | 预期结果 |
|---|------|---------|----------|---------|
| 1 | TPM 可用 | 检查设备节点 | `test -c /dev/tpm0 && echo OK` | OK |
| 2 | 全盘加密 | 检查 LUKS 状态 | `sudo dmsetup status \| grep crypt` | 显示加密设备 |
| 3 | 内存锁定 | 检查 VmLck | `grep VmLck /proc/$(pidof kms-server)/status` | 非零值 |
| 4 | 入侵阻断 | 模拟 5 次错误登录 | `for i in $(seq 5); do curl -s -o /dev/null -w '%{http_code}\n' -X POST https://localhost:8443/api/v1/auth/login -d '{}'; done` | 第5次返回 403 |
| 5 | 内核 ASLR | 检查随机化配置 | `sysctl kernel.randomize_va_space` | 2 |
| 6 | SELinux | 检查强制模式 | `getenforce` | Enforcing |
| 7 | Audit 日志 | 检查审计文件 | `sqlite3 /opt/kms/data/audit_events.db 'SELECT count(*) FROM audit_events'` | > 0 |
| 8 | HSM 可用 | 检查 PKCS#11 状态 | `cargo test --features pkcs11-hsm -- --ignored --nocapture` | hsm 测试通过 |
| 9 | TPM PCR | 读取 PCR 值 | `cargo run -- hash-self \| xargs -I{} sh -c 'test -f /sys/class/tpm/tpm0/pcr-read/16 && cat /sys/class/tpm/tpm0/pcr-read/16 \| grep {} && echo PCR MATCH'` | PCR 值匹配二进制哈希 |
| 10 | 灾难恢复演练 | 验证备份文件 | `kms-server restore-seed --input /backup/seed-backup.dat 2>&1 \| grep success` | 恢复成功 |
| 11 | cgroup 限制 | 检查 systemd 状态 | `systemctl show kms-server -p MemoryMax,CPUQuota` | 显示已配置值 |
| 12 | 物理安全 | 检查机柜锁、HSM 固定 | 人工巡检 | 机房巡检记录 |
