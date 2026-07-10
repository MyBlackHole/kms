use crate::cli::config::ServerConfig;
use std::cell::RefCell;
use std::path::PathBuf;
use std::fs::{self, File};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub struct KmsClient {
    client: reqwest::Client,
    server_url: String,
    token: Option<String>,
    print_json: bool,
    // KMIP session state —— 使用 RefCell 实现内部可变性
    session_id: RefCell<Option<String>>,
    credential_json: RefCell<Option<String>>,
    username: RefCell<Option<String>>,
}

impl KmsClient {
    pub fn new(cfg: &ServerConfig) -> crate::Result<Self> {
        let mut builder = reqwest::Client::builder();
        if cfg.accept_invalid_certs {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let server_url = cfg.server_url.trim_end_matches('/').to_string();

        let credential = Self::load_credential(&server_url);

        Ok(Self {
            client: builder.build()?,
            server_url,
            token: cfg.token.clone(),
            print_json: cfg.print_json,
            session_id: RefCell::new(None),
            credential_json: RefCell::new(credential),
            username: RefCell::new(None),
        })
    }

    /// 凭据文件路径：~/.kms/credentials.json
    fn cred_path() -> Option<PathBuf> {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .ok()?;
        Some(PathBuf::from(home).join(".kms").join("credentials.json"))
    }

    /// 从文件加载 credential（仅 server_url 匹配时使用）
    fn load_credential(server_url: &str) -> Option<String> {
        let path = Self::cred_path()?;
        let content = fs::read_to_string(path).ok()?;
        let data: serde_json::Value = serde_json::from_str(&content).ok()?;
        let saved_url = data.get("server_url")?.as_str()?;
        if saved_url == server_url {
            data.get("credential")?.as_str().map(|s| s.to_string())
        } else {
            None
        }
    }

    /// 保存 session 信息（login 后，totp-verify 前）
    fn save_session_info(server_url: &str, username: &str, session_id: &str) {
        let path = match Self::cred_path() {
            Some(p) => p,
            None => return,
        };
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let data = serde_json::json!({
            "server_url": server_url,
            "username": username,
            "session_id": session_id,
        });
        if let Ok(json) = serde_json::to_string_pretty(&data) {
            if let Ok(mut f) = File::create(&path) {
                let _ = f.write_all(json.as_bytes());
                #[cfg(unix)]
                {
                    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
                }
            }
        }
    }

    /// 从已保存的文件中读取 username（用于 totp-verify 在不同 CLI 进程间传递 username）
    fn load_username_from_session(server_url: &str) -> Option<String> {
        let path = Self::cred_path()?;
        let content = fs::read_to_string(path).ok()?;
        let data: serde_json::Value = serde_json::from_str(&content).ok()?;
        if data.get("server_url")?.as_str()? == server_url {
            data.get("username")?.as_str().map(|s| s.to_string())
        } else {
            None
        }
    }

    /// 持久化 credential 到文件（0600 权限），同时保存 session_id 供 logout 使用
    fn save_credential(server_url: &str, username: &str, credential: &str, session_id: &str) {
        let path = match Self::cred_path() {
            Some(p) => p,
            None => return,
        };
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let data = serde_json::json!({
            "server_url": server_url,
            "username": username,
            "session_id": session_id,
            "credential": credential,
        });
        if let Ok(json) = serde_json::to_string_pretty(&data) {
            if let Ok(mut f) = File::create(&path) {
                let _ = f.write_all(json.as_bytes());
                #[cfg(unix)]
                {
                    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
                }
            }
        }
    }

    /// 从凭据文件读取 session_id（供 logout 使用）
    pub fn load_session_id(server_url: &str) -> Option<String> {
        let path = Self::cred_path()?;
        let content = fs::read_to_string(path).ok()?;
        let data: serde_json::Value = serde_json::from_str(&content).ok()?;
        if data.get("server_url")?.as_str()? == server_url {
            data.get("session_id")?.as_str().map(|s| s.to_string())
        } else {
            None
        }
    }

    /// 删除凭据文件
    pub fn clear_credential_file() {
        if let Some(path) = Self::cred_path() {
            let _ = fs::remove_file(path);
        }
    }

    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    /// 认证流程：x-Login → (可选) x-TotpVerify
    /// 成功后 credential_json 自动保存，后续请求自动携带
    pub async fn kmip_login(
        &self,
        username: &str,
        totp_code: Option<&str>,
    ) -> crate::Result<serde_json::Value> {
        // 1. x-Login
        let login_payload = serde_json::json!([
            {"tag": "Username", "type": "TextString", "value": username}
        ]);
        let login_resp = self
            .kmip_request_raw("x-Login", Some(login_payload))
            .await?;

        let batch = extract_batch_items(&login_resp)?;
        let session_id = find_value_tag(batch, "UniqueIdentifier")
            .and_then(|v| v.as_str())
            .ok_or_else(|| crate::Error::ApiError(400, "x-Login 响应缺少 UniqueIdentifier".into()))?
            .to_string();

        self.session_id.replace(Some(session_id.clone()));
        self.username.replace(Some(username.to_string()));
        // 保存 session 信息到文件（让后续 totp-verify 能拿到 username）
        Self::save_session_info(&self.server_url, username, &session_id);

        // 提取 totp_uri（如果有）
        let totp_uri = find_value_tag(batch, "ServerURI")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        println!("会话: {}", session_id);
        if !totp_uri.is_empty() {
            println!("TOTP URI: {}", totp_uri);
        }

        // 2. 如有 totp_code → x-TotpVerify
        if let Some(code) = totp_code {
            return self.kmip_totp_verify(&session_id, code).await;
        }

        Ok(serde_json::json!({
            "session_id": session_id,
            "totp_uri": totp_uri,
        }))
    }

    /// x-TotpVerify —— 验证 TOTP 码后获取 credential
    pub async fn kmip_totp_verify(
        &self,
        session_id: &str,
        code: &str,
    ) -> crate::Result<serde_json::Value> {
        let verify_payload = serde_json::json!([
            {"tag": "UniqueIdentifier", "type": "TextString", "value": session_id},
            {"tag": "Password", "type": "TextString", "value": code}
        ]);
        let resp = self
            .kmip_request_raw("x-TotpVerify", Some(verify_payload))
            .await?;
        let batch = extract_batch_items(&resp)?;

        // 提取 credential JSON —— x-TotpVerify 返回 CredentialValue
        let credential = find_value_tag(batch, "CredentialValue")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if credential.is_empty() {
            let msg = find_value_tag(batch, "ResultMessage")
                .and_then(|v| v.as_str())
                .unwrap_or("TOTP 验证失败");
            return Err(crate::Error::ApiError(401, msg.to_string()));
        }

        self.credential_json.replace(Some(credential.clone()));
        let mut username = self.username.borrow().clone().unwrap_or_default();
        if username.is_empty() {
            username = Self::load_username_from_session(&self.server_url).unwrap_or_default();
        }
        Self::save_credential(&self.server_url, &username, &credential, session_id);

        println!("认证成功");
        Ok(serde_json::json!({
            "credential": credential,
            "session_id": session_id,
        }))
    }

    /// 执行 KMIP 操作并返回解析后的结果项 map
    pub async fn kmip_request(
        &self,
        operation: &str,
        payload: Option<serde_json::Value>,
    ) -> crate::Result<serde_json::Value> {
        let resp = self.kmip_request_raw(operation, payload).await?;
        parse_kmip_response(&resp)
    }

    // ─── 内部方法 ───

    /// 发送原始 KMIP request，返回完整 ResponseMessage JSON
    async fn kmip_request_raw(
        &self,
        operation: &str,
        payload: Option<serde_json::Value>,
    ) -> crate::Result<serde_json::Value> {
        let url = format!("{}/kmip/2_1", self.server_url);

        let mut batch_items = vec![
            serde_json::json!({"tag": "Operation", "type": "Enumeration", "value": operation}),
        ];
        if let Some(p) = payload {
            batch_items.push(serde_json::json!({
                "tag": "RequestPayload", "type": "Structure", "value": p
            }));
        }

        // 构建 Authentication 节点（如有已保存的 credential）
        let mut request_value = vec![serde_json::json!({
            "tag": "BatchItem", "type": "Structure",
            "value": batch_items
        })];

        // 如果有 credential，添加 Authentication 字段
        if let Some(ref cred) = *self.credential_json.borrow() {
            request_value.push(serde_json::json!({
                "tag": "Authentication", "type": "Structure",
                "value": [{
                    "tag": "Credential", "type": "Structure",
                    "value": [
                        {"tag": "CredentialType", "type": "Enumeration", "value": "KMIPToken"},
                        {"tag": "CredentialValue", "type": "TextString", "value": cred}
                    ]
                }]
            }));
        }

        let body = serde_json::json!({
            "tag": "RequestMessage",
            "type": "Structure",
            "value": request_value
        });

        if self.print_json {
            eprintln!("> POST {}", url);
            eprintln!(
                "> {}",
                serde_json::to_string_pretty(&body).unwrap_or_default()
            );
        }

        let resp = self
            .client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        let text = resp.text().await?;

        if self.print_json {
            eprintln!("< {} {}", status.as_u16(), &text);
        }

        // KMIP 协议层始终返回 200（业务错误在 ResultStatus 中）
        let value: serde_json::Value = serde_json::from_str(&text).map_err(|_| {
            crate::Error::ApiError(status.as_u16(), format!("无效 JSON 响应: {}", &text))
        })?;

        Ok(value)
    }

    // ─── 保留的 REST 方法（仅用于 /api/v1/health） ───

    fn headers(&self) -> reqwest::header::HeaderMap {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(
            reqwest::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        if let Some(ref token) = self.token {
            h.insert(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", token).parse().unwrap(),
            );
        }
        h
    }

    pub async fn get(&self, path: &str) -> crate::Result<serde_json::Value> {
        let url = format!("{}{}", self.server_url, path);
        if self.print_json {
            eprintln!("> GET {}", url);
        }
        let resp = self.client.get(&url).headers(self.headers()).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if self.print_json {
            eprintln!("< {} {}", status.as_u16(), &text);
        }
        let value: serde_json::Value = serde_json::from_str(&text)
            .map_err(|_| crate::Error::ApiError(status.as_u16(), text.clone()))?;
        if !status.is_success() {
            let msg = value
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error")
                .to_string();
            if status.as_u16() == 401 {
                eprintln!("提示: 需要先登录。运行 `kms-cli auth login <username>` 或设置 KMS_TOKEN 环境变量");
            }
            return Err(crate::Error::ApiError(status.as_u16(), msg));
        }
        Ok(value)
    }
}

// ─── KMIP 响应解析辅助函数 ───

/// 从 ResponseMessage JSON 中提取 BatchItem 的 value 数组
fn extract_batch_items(resp: &serde_json::Value) -> crate::Result<&[serde_json::Value]> {
    resp["value"]
        .as_array()
        .and_then(|arr| arr.iter().find(|v| v["tag"] == "BatchItem"))
        .and_then(|batch| batch["value"].as_array())
        .map(|v| v.as_slice())
        .ok_or_else(|| crate::Error::ApiError(400, "KMIP 响应缺少 BatchItem".into()))
}

/// 从 KMIP 响应中提取指定 tag 的值（在 ResponseHeader 中查找）
fn extract_from_header(resp: &serde_json::Value, tag_name: &str) -> Option<String> {
    if let Some(items) = resp["value"].as_array() {
        for item in items {
            if item["tag"] == "ResponseHeader" {
                if let Some(children) = item["value"].as_array() {
                    for child in children {
                        if child["tag"] == tag_name {
                            return child["value"].as_str().map(|s| s.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

/// 从 KMIP 响应中提取 ResultStatus
fn extract_result_status(resp: &serde_json::Value) -> Option<String> {
    extract_from_header(resp, "ResultStatus")
}

/// 从 KMIP 响应中提取 ResultReason
fn extract_result_reason(resp: &serde_json::Value) -> Option<String> {
    extract_from_header(resp, "ResultReason")
}

/// 从 KMIP 响应中提取 ResultMessage
fn extract_result_message(resp: &serde_json::Value) -> Option<String> {
    extract_from_header(resp, "ResultMessage")
}

/// 解析 KMIP 响应：检查 ResultStatus，返回结果字段的 map（tag → value）
fn parse_kmip_response(resp: &serde_json::Value) -> crate::Result<serde_json::Value> {
    let batch = extract_batch_items(resp)?;

    // 检查 ResultStatus（在 ResponseHeader 中）
    let status = extract_result_status(resp).unwrap_or_else(|| "Unknown".to_string());

    if status == "Success" || status == "OperationPending" {
        // 收集所有非 ResultStatus/ResultReason/ResultMessage 的字段 → map
        // 同时递归展开 ResponsePayload
        let mut result = serde_json::Map::new();
        for item in batch {
            if let Some(tag) = item.get("tag").and_then(|t| t.as_str()) {
                if tag == "ResultStatus" || tag == "ResultReason" || tag == "ResultMessage" {
                    continue;
                }
                // ResponsePayload → 展开其子节点
                if tag == "ResponsePayload" {
                    if let Some(children) = item.get("value").and_then(|v| v.as_array()) {
                        for child in children {
                            if let Some(t) = child.get("tag").and_then(|t| t.as_str()) {
                                if let Some(v) = child.get("value") {
                                    result.insert(t.to_string(), v.clone());
                                }
                            }
                        }
                    }
                } else if let Some(value) = item.get("value") {
                    result.insert(tag.to_string(), value.clone());
                }
            }
        }
        Ok(serde_json::Value::Object(result))
    } else {
        // 错误信息可能在 ResponseHeader 或 BatchItem 的 ResponsePayload 中
        let reason = extract_result_reason(resp).unwrap_or_else(|| "OPERATION_FAILED".to_string());
        let message = extract_result_message(resp).unwrap_or_else(|| "KMIP 操作失败".to_string());

        // 认证失败 → 清除本地凭据
        if reason == "AUTH_FAILED" {
            KmsClient::clear_credential_file();
            eprintln!("提示: 凭据已过期，需要重新登录。运行 `kms-cli auth login <username>`");
        }

        Err(crate::Error::ApiError(
            400,
            format!("{}: {}", reason, message),
        ))
    }
}

/// 在数组中按 tag 找 value（支持嵌套 value 是数组或单个值的情况）
fn find_value_tag<'a>(items: &'a [serde_json::Value], tag: &str) -> Option<&'a serde_json::Value> {
    // 先直接搜索，再递归搜索嵌套的 ResponsePayload/Structure
    for item in items {
        let item_tag = item.get("tag").and_then(|t| t.as_str());
        if item_tag == Some(tag) {
            return item.get("value");
        }
    }
    // 递归搜索嵌套结构
    for item in items {
        if let Some(children) = item.get("value").and_then(|v| v.as_array()) {
            if let found @ Some(_) = find_value_tag(children, tag) {
                return found;
            }
        }
    }
    None
}
