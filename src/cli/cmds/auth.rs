use crate::cli::client::KmsClient;
use crate::cli::types::{AuthAction, TokenAction};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, TOTP};

pub async fn handle(
    client: &KmsClient,
    action: &AuthAction,
) -> crate::Result<Option<serde_json::Value>> {
    match action {
        AuthAction::Login { username } => login(client, username).await,
        AuthAction::TotpVerify { code, session } => totp_verify(client, code, session).await,
        AuthAction::TotpCode { secret } => {
            handle_totp_code(secret)?;
            Ok(None)
        }
        AuthAction::TotpSetup { username } => {
            handle_totp_setup(client, username).await?;
            Ok(None)
        }
        AuthAction::Logout { session } => {
            let sid = session.clone().unwrap_or_else(|| {
                KmsClient::load_session_id(&client.server_url())
                    .unwrap_or_default()
            });
            if sid.is_empty() {
                eprintln!("错误: 未提供 session ID，也没有已保存的凭据");
                std::process::exit(1);
            }
            handle_logout(client, &sid).await?;
            Ok(None)
        }
        AuthAction::Recovery { code, session } => {
            handle_recovery(client, code, session).await?;
            Ok(None)
        }
        AuthAction::RecoveryCodes => {
            handle_recovery_codes(client).await?;
            Ok(None)
        }
        AuthAction::CertInfo => {
            handle_cert_info(client).await?;
            Ok(None)
        }
        AuthAction::Tokens { action } => handle_token(client, action).await,
    }
}

async fn handle_token(
    client: &KmsClient,
    action: &TokenAction,
) -> crate::Result<Option<serde_json::Value>> {
    match action {
        TokenAction::List => tokens_list(client).await,
        TokenAction::Create { name } => tokens_create(client, name).await,
        TokenAction::Delete { id } => tokens_delete(client, id).await,
    }
}

// ─── KMIP 认证 ───

/// auth login —— 通过 x-Login + (可选 x-TotpVerify) 完成 KMIP 认证
async fn login(client: &KmsClient, username: &str) -> crate::Result<Option<serde_json::Value>> {
    // kmip_login 会在内部执行 x-Login，如有后续 TOTP 步骤会提示
    let resp = client.kmip_login(username, None).await?;

    if let Some(totp_uri) = resp.get("totp_uri").and_then(|v| v.as_str()) {
        if !totp_uri.is_empty() {
            // 有 TOTP 要求，提示用户继续验证
            let session_id = resp
                .get("session_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            println!("需要 TOTP 验证。请运行:");
            println!("  kms-cli auth totp-verify <code> --session {}", session_id);

            if let Some(secret) = extract_totp_secret(totp_uri) {
                println!("  (或使用 kms-cli auth totp-code {} 生成验证码)", secret);
            }
        }
    }

    Ok(Some(resp))
}

/// auth totp-verify —— 通过 KMIP x-TotpVerify 完成 TOTP 验证
async fn totp_verify(
    client: &KmsClient,
    code: &str,
    session_id: &str,
) -> crate::Result<Option<serde_json::Value>> {
    let resp = client.kmip_totp_verify(session_id, code).await?;
    println!("认证成功");
    Ok(Some(resp))
}

// ─── KMIP Token 管理 ───

/// tokens list → x-ListTokens
async fn tokens_list(client: &KmsClient) -> crate::Result<Option<serde_json::Value>> {
    let resp = client.kmip_request("x-ListTokens", None).await?;
    Ok(Some(resp))
}

/// tokens create → x-CreateToken
async fn tokens_create(client: &KmsClient, name: &str) -> crate::Result<Option<serde_json::Value>> {
    let payload = serde_json::json!([
        {"tag": "Name", "type": "TextString", "value": name}
    ]);
    let resp = client.kmip_request("x-CreateToken", Some(payload)).await?;
    println!("创建 Token: {}", name);
    if let Some(token) = resp.get("UniqueIdentifier").and_then(|v| v.as_str()) {
        println!("  ID: {}", token);
    }
    if let Some(raw) = resp.get("TokenValue").and_then(|v| v.as_str()) {
        println!("  Token: {}", raw);
    }
    Ok(Some(resp))
}

/// tokens delete → x-RevokeToken
async fn tokens_delete(client: &KmsClient, id: &str) -> crate::Result<Option<serde_json::Value>> {
    let payload = serde_json::json!([
        {"tag": "UniqueIdentifier", "type": "TextString", "value": id}
    ]);
    let resp = client.kmip_request("x-RevokeToken", Some(payload)).await?;
    println!("Token 已吊销: {}", id);
    Ok(Some(resp))
}

// ─── 本地 TOTP 工具 ───

pub fn handle_totp_code(secret: &str) -> crate::Result<()> {
    let cleaned: String = secret.chars().filter(|c| !c.is_whitespace()).collect();

    let secret_bytes = base32_decode(&cleaned)
        .ok_or_else(|| crate::Error::CryptoError("TOTP secret Base32 解码失败".into()))?;

    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes, None, "kms".into())
        .map_err(|e| crate::Error::CryptoError(format!("TOTP 创建失败: {}", e)))?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| crate::Error::CryptoError(format!("时间错误: {}", e)))?
        .as_secs();

    let code = totp.generate(timestamp);
    println!("{}", code);
    Ok(())
}

pub async fn handle_totp_setup(client: &KmsClient, username: &str) -> crate::Result<()> {
    let resp = client.kmip_login(username, None).await?;
    let session_id = resp
        .get("session_id")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    println!("会话: {}", session_id);
    if let Some(totp_uri) = resp.get("totp_uri").and_then(|v| v.as_str()) {
        if !totp_uri.is_empty() {
            println!("TOTP URI: {}", totp_uri);
            if let Some(secret) = extract_totp_secret(totp_uri) {
                println!("Secret: {}", secret);
                println!("\n请使用 Authenticator App 扫描二维码或手动输入 Secret。");
                println!(
                    "然后运行: kms-cli auth totp-verify <code> --session {}",
                    session_id
                );
            }
        }
    }
    Ok(())
}

fn extract_totp_secret(uri: &str) -> Option<String> {
    // parse otpauth:// URL manually (avoids adding `url` crate dep)
    let query = uri.split('?').nth(1)?;
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        if parts.next()? == "secret" {
            return Some(parts.next()?.to_uppercase());
        }
    }
    None
}

// ─── 其他 KMIP 操作 ───
// logout / recovery / cert-info 等通过 KMIP x-* 操作实现

async fn handle_logout(client: &KmsClient, session_id: &str) -> crate::Result<()> {
    let payload = serde_json::json!([
        {"tag": "UniqueIdentifier", "type": "TextString", "value": session_id}
    ]);
    client.kmip_request("x-Logout", Some(payload)).await?;
    // 清除本地凭据文件
    KmsClient::clear_credential_file();
    println!("已登出");
    Ok(())
}

async fn handle_recovery(client: &KmsClient, code: &str, session_id: &str) -> crate::Result<()> {
    let payload = serde_json::json!([
        {"tag": "UniqueIdentifier", "type": "TextString", "value": session_id},
        {"tag": "Password", "type": "TextString", "value": code}
    ]);
    let resp = client.kmip_request("x-Recovery", Some(payload)).await?;
    if let Some(msg) = resp.get("ResultMessage").and_then(|v| v.as_str()) {
        println!("{}", msg);
    }
    Ok(())
}

async fn handle_recovery_codes(client: &KmsClient) -> crate::Result<()> {
    let resp = client.kmip_request("x-RecoveryCodes", None).await?;
    if let Some(codes) = resp.get("RecoveryCodes").and_then(|v| v.as_array()) {
        println!("恢复码:");
        for code in codes {
            println!("  {}", code.as_str().unwrap_or("?"));
        }
        println!("\n请妥善保存以上恢复码，每个恢复码只能使用一次。");
    }
    Ok(())
}

async fn handle_cert_info(client: &KmsClient) -> crate::Result<()> {
    let resp = client.kmip_request("x-CertInfo", None).await?;
    println!("mTLS 证书信息:");
    if let Some(subject) = resp.get("Subject").and_then(|v| v.as_str()) {
        println!("  Subject: {}", subject);
    }
    if let Some(fp) = resp.get("Fingerprint").and_then(|v| v.as_str()) {
        println!("  指纹: {}", fp);
    }
    Ok(())
}

fn base32_decode(input: &str) -> Option<Vec<u8>> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .filter(|c| *c != '=')
        .collect();

    let mut result = Vec::new();
    let mut buffer = 0u64;
    let mut bits = 0;

    for c in cleaned.chars() {
        let idx = match c {
            'A'..='Z' => (c as u8 - b'A') as u64,
            '2'..='7' => (c as u8 - b'2' + 26) as u64,
            _ => return None,
        };
        buffer = (buffer << 5) | idx;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(result)
}
