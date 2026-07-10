# mTLS 配置指南

## 概述

等保四级要求**通信前基于密码技术对通信双方进行验证/认证**。mTLS（双向 TLS）确保客户端和服务端都持有合法证书，实现通信双方的身份验证。

## 架构

```
客户端证书 → TLS 握手 → 服务端证书
     │                        │
     ▼                        ▼
服务端验证客户端 ←—— 双向认证 ——→ 客户端验证服务端
     │
     ▼
KMS 提取客户端证书身份 (TlsIdentity)
     │
     ▼
AuthMiddleware 检查 mTLS 身份
```

## 配置步骤

### 1. 生成 CA 证书

```bash
# 生成 CA 私钥和证书
openssl req -x509 -newkey rsa:4096 -keyout ca-key.pem -out ca-cert.pem \
  -days 365 -nodes -subj "/CN=KMS-CA"
```

### 2. 生成服务端证书

```bash
# 生成服务端私钥和 CSR
openssl req -newkey rsa:4096 -keyout server-key.pem -out server-csr.pem \
  -nodes -subj "/CN=kms.example.com"

# 用 CA 签名
openssl x509 -req -in server-csr.pem -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out server-cert.pem -days 365
```

### 3. 生成客户端证书

```bash
# 生成客户端私钥和 CSR
openssl req -newkey rsa:4096 -keyout client-key.pem -out client-csr.pem \
  -nodes -subj "/CN=kms-client"

# 用 CA 签名
openssl x509 -req -in client-csr.pem -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out client-cert.pem -days 365
```

### 4. 配置 KMS

```toml
[server]
tls = { cert_path = "server-cert.pem", key_path = "server-key.pem", client_ca_path = "ca-cert.pem" }
```

### 5. Level4 增强配置

```toml
[level4]
mtls_required_for_management_api = true
```

## 验证

```bash
# 使用客户端证书访问
curl --cert client-cert.pem --key client-key.pem --cacert ca-cert.pem \
  https://localhost:8443/api/v1/health

# 无证书访问应被拒绝（mTLS 模式下）
curl --cacert ca-cert.pem https://localhost:8443/api/v1/health
# 期望: 401 Unauthorized
```

## 生产注意事项

1. 证书过期管理：设置证书自动续期提醒
2. CRL/OCSP：配置证书吊销检查
3. 密钥保护：服务端私钥应使用 HSM 保护
4. 证书轮换：建立证书轮换流程
