use crate::cli::client::KmsClient;
use crate::cli::types::KeyAction;

pub async fn handle(
    client: &KmsClient,
    action: &KeyAction,
) -> crate::Result<Option<serde_json::Value>> {
    match action {
        KeyAction::List => list(client).await,
        KeyAction::Create {
            name,
            key_type,
            usage,
        } => create(client, name, key_type, usage).await,
        KeyAction::Get { id } => get(client, id).await,
        KeyAction::Enable { id } => enable(client, id).await,
        KeyAction::Disable { id } => disable(client, id).await,
        KeyAction::Rotate { id } => rotate(client, id).await,
        KeyAction::Archive { id } => archive(client, id).await,
        KeyAction::Destroy { id } => destroy(client, id).await,
        KeyAction::Datakey { id } => datakey(client, id).await,
        KeyAction::Decrypt { id, ciphertext } => decrypt_data_key(client, id, ciphertext).await,
        KeyAction::Export { id, output } => export_key(client, id, output.as_deref()).await,
        KeyAction::Import { input } => import_key(client, input).await,
        KeyAction::Acl { action } => super::dispatch_acl(client, action).await,
        KeyAction::Dependencies { action } => super::dispatch_dep(client, action).await,
        KeyAction::Dependents { id } => dependents(client, id).await,
    }
}

/// keys list → Locate
async fn list(client: &KmsClient) -> crate::Result<Option<serde_json::Value>> {
    let resp = client.kmip_request("Locate", None).await?;
    Ok(Some(resp))
}

/// keys create → Create（对称密钥）或 CreateKeyPair（SM2/RSA）
async fn create(
    client: &KmsClient,
    name: &str,
    key_type: &str,
    usage: &str,
) -> crate::Result<Option<serde_json::Value>> {
    let algorithm = match key_type.to_lowercase().as_str() {
        "aes" => "AES",
        "sm4" | "sm4_cbc" | "sm4-gcm" | "sm4_gcm" => "SM4",
        "sm2" => "SM2",
        "rsa" => "RSA",
        _ => key_type,
    };

    let is_asymmetric = algorithm == "SM2" || algorithm == "RSA";

    // 构建 Attributes
    let usage_value = if usage.is_empty() {
        None
    } else {
        let mapped = match usage.to_lowercase().as_str() {
            "encryptdecrypt" | "encrypt" => "EncryptDecrypt",
            "signverify" | "sign" => "SignVerify",
            "keywrap" | "wrap" => "KeyWrap",
            "derivekey" | "derive" => "DeriveKey",
            _ => usage,
        };
        Some(mapped)
    };

    let mut attrs = vec![
        serde_json::json!({"tag": "CryptographicAlgorithm", "type": "Enumeration", "value": algorithm}),
    ];
    if let Some(u) = usage_value {
        attrs.push(
            serde_json::json!({"tag": "CryptographicUsageMask", "type": "Enumeration", "value": u}),
        );
    }

    let payload = serde_json::json!([
        {"tag": "ObjectType", "type": "Enumeration", "value": if is_asymmetric { "PrivateKey" } else { "SymmetricKey" }},
        {"tag": "Attributes", "type": "Structure", "value": attrs}
    ]);

    let operation = if is_asymmetric {
        "CreateKeyPair"
    } else {
        "Create"
    };
    let resp = client.kmip_request(operation, Some(payload)).await?;

    println!("创建密钥: {}", name);
    if let Some(id) = resp.get("UniqueIdentifier").and_then(|v| v.as_str()) {
        println!("  ID: {}", id);
    }
    Ok(Some(resp))
}

/// keys get → Get
async fn get(client: &KmsClient, id: &str) -> crate::Result<Option<serde_json::Value>> {
    let payload = serde_json::json!([
        {"tag": "UniqueIdentifier", "type": "TextString", "value": id}
    ]);
    let resp = client.kmip_request("Get", Some(payload)).await?;
    Ok(Some(resp))
}

/// keys enable → Activate
async fn enable(client: &KmsClient, id: &str) -> crate::Result<Option<serde_json::Value>> {
    let payload = serde_json::json!([
        {"tag": "UniqueIdentifier", "type": "TextString", "value": id}
    ]);
    let resp = client.kmip_request("Activate", Some(payload)).await?;
    println!("密钥已启用: {}", id);
    Ok(Some(resp))
}

/// keys disable → Revoke
async fn disable(client: &KmsClient, id: &str) -> crate::Result<Option<serde_json::Value>> {
    let payload = serde_json::json!([
        {"tag": "UniqueIdentifier", "type": "TextString", "value": id}
    ]);
    let resp = client.kmip_request("Revoke", Some(payload)).await?;
    println!("密钥已禁用: {}", id);
    Ok(Some(resp))
}

/// keys rotate → ReKey
async fn rotate(client: &KmsClient, id: &str) -> crate::Result<Option<serde_json::Value>> {
    let payload = serde_json::json!([
        {"tag": "UniqueIdentifier", "type": "TextString", "value": id}
    ]);
    let resp = client.kmip_request("ReKey", Some(payload)).await?;
    if let Some(approval) = resp.get("ApprovalID").and_then(|v| v.as_str()) {
        println!("需要审批: {}", approval);
    }
    Ok(Some(resp))
}

/// keys archive → Archive
async fn archive(client: &KmsClient, id: &str) -> crate::Result<Option<serde_json::Value>> {
    let payload = serde_json::json!([
        {"tag": "UniqueIdentifier", "type": "TextString", "value": id}
    ]);
    let resp = client.kmip_request("Archive", Some(payload)).await?;
    if let Some(approval) = resp.get("ApprovalID").and_then(|v| v.as_str()) {
        println!("需要审批: {}", approval);
    }
    Ok(Some(resp))
}

/// keys destroy → Destroy
async fn destroy(client: &KmsClient, id: &str) -> crate::Result<Option<serde_json::Value>> {
    let payload = serde_json::json!([
        {"tag": "UniqueIdentifier", "type": "TextString", "value": id}
    ]);
    let resp = client.kmip_request("Destroy", Some(payload)).await?;
    if let Some(approval) = resp.get("ApprovalID").and_then(|v| v.as_str()) {
        println!("需要审批: {}", approval);
    }
    Ok(Some(resp))
}

/// keys datakey → x-DataKey 或 Get（用于生成/获取数据密钥）
async fn datakey(client: &KmsClient, id: &str) -> crate::Result<Option<serde_json::Value>> {
    let payload = serde_json::json!([
        {"tag": "UniqueIdentifier", "type": "TextString", "value": id}
    ]);
    let resp = client.kmip_request("x-DataKey", Some(payload)).await?;
    Ok(Some(resp))
}

/// keys decrypt → Decrypt
async fn decrypt_data_key(
    client: &KmsClient,
    id: &str,
    ciphertext: &str,
) -> crate::Result<Option<serde_json::Value>> {
    let payload = serde_json::json!([
        {"tag": "UniqueIdentifier", "type": "TextString", "value": id},
        {"tag": "Data", "type": "ByteString", "value": ciphertext}
    ]);
    let resp = client.kmip_request("Decrypt", Some(payload)).await?;
    Ok(Some(resp))
}

// ─── 依赖管理 ───

async fn dependents(client: &KmsClient, id: &str) -> crate::Result<Option<serde_json::Value>> {
    let payload = serde_json::json!([
        {"tag": "UniqueIdentifier", "type": "TextString", "value": id}
    ]);
    let resp = client
        .kmip_request("x-ListDependents", Some(payload))
        .await?;
    Ok(Some(resp))
}

pub async fn handle_dep_add(
    client: &KmsClient,
    id: &str,
    dep_id: &str,
) -> crate::Result<Option<serde_json::Value>> {
    let payload = serde_json::json!([
        {"tag": "UniqueIdentifier", "type": "TextString", "value": id},
        {"tag": "LinkedObjectIdentifier", "type": "TextString", "value": dep_id},
        {"tag": "Description", "type": "TextString", "value": "cli-dependency"}
    ]);
    let resp = client
        .kmip_request("x-AddDependency", Some(payload))
        .await?;
    println!("依赖已添加: {} -> {}", id, dep_id);
    Ok(Some(resp))
}

pub async fn handle_dep_remove(
    client: &KmsClient,
    id: &str,
    dep_id: &str,
) -> crate::Result<Option<serde_json::Value>> {
    let payload = serde_json::json!([
        {"tag": "UniqueIdentifier", "type": "TextString", "value": dep_id}
    ]);
    let resp = client
        .kmip_request("x-RemoveDependency", Some(payload))
        .await?;
    println!("依赖已移除: {} -> {}", id, dep_id);
    Ok(Some(resp))
}

// ─── ACL 管理 ───

pub async fn handle_acl_add(
    client: &KmsClient,
    id: &str,
    subject: &str,
    permission: &str,
) -> crate::Result<Option<serde_json::Value>> {
    let payload = serde_json::json!([
        {"tag": "UniqueIdentifier", "type": "TextString", "value": id},
        {"tag": "Name", "type": "TextString", "value": subject},
        {"tag": "KeyRoleType", "type": "Enumeration", "value": permission}
    ]);
    let resp = client.kmip_request("x-AddAclEntry", Some(payload)).await?;
    println!("ACL 已添加: {} -> {} ({})", subject, id, permission);
    Ok(Some(resp))
}

pub async fn handle_acl_remove(
    client: &KmsClient,
    id: &str,
    subject: &str,
) -> crate::Result<Option<serde_json::Value>> {
    let payload = serde_json::json!([
        {"tag": "UniqueIdentifier", "type": "TextString", "value": id},
        {"tag": "Name", "type": "TextString", "value": subject}
    ]);
    let resp = client
        .kmip_request("x-RemoveAclEntry", Some(payload))
        .await?;
    println!("ACL 已移除: {} -> {}", subject, id);
    Ok(Some(resp))
}

// ─── 导入/导出 ───

async fn export_key(
    client: &KmsClient,
    id: &str,
    output: Option<&str>,
) -> crate::Result<Option<serde_json::Value>> {
    let payload = serde_json::json!([
        {"tag": "UniqueIdentifier", "type": "TextString", "value": id}
    ]);
    let resp = client.kmip_request("Export", Some(payload)).await?;

    // 将 KMIP 响应转换为可移植格式
    let algorithm = resp
        .get("CryptographicAlgorithm")
        .and_then(|v| v.as_str())
        .unwrap_or("SM4");
    let key_length = resp
        .get("CryptographicLength")
        .and_then(|v| v.as_i64())
        .unwrap_or(128);
    let key_name = resp
        .get("Name")
        .and_then(|v| v.as_str())
        .unwrap_or("exported-key");
    let material = resp.get("Data").and_then(|v| v.as_str()).unwrap_or("");

    let export = serde_json::json!({
        "name": key_name,
        "algorithm": algorithm,
        "key_length": key_length,
        "key_material": material
    });

    if let Some(output_path) = output {
        let json = serde_json::to_string_pretty(&export)?;
        std::fs::write(output_path, json)?;
        println!("密钥已导出到: {}", output_path);
    }
    Ok(Some(export))
}

async fn import_key(client: &KmsClient, input: &str) -> crate::Result<Option<serde_json::Value>> {
    let data = std::fs::read_to_string(input)?;
    let import: serde_json::Value = serde_json::from_str(&data)?;

    let name = import
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("imported-key");
    let algorithm = import
        .get("algorithm")
        .and_then(|v| v.as_str())
        .unwrap_or("SM4");
    let key_length = import
        .get("key_length")
        .and_then(|v| v.as_i64())
        .unwrap_or(128);
    let material = import
        .get("key_material")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let payload = serde_json::json!([
        {"tag": "Name", "type": "TextString", "value": name},
        {"tag": "CryptographicAlgorithm", "type": "Enumeration", "value": algorithm},
        {"tag": "CryptographicLength", "type": "Integer", "value": key_length},
        {"tag": "Data", "type": "ByteString", "value": material}
    ]);

    let resp = client.kmip_request("Import", Some(payload)).await?;
    if let Some(id) = resp.get("UniqueIdentifier").and_then(|v| v.as_str()) {
        println!("密钥已导入: ID = {}", id);
    }
    Ok(Some(resp))
}
