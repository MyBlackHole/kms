use crate::cli::client::KmsClient;

fn hex_encode_bytes(data: &[u8]) -> String {
    hex::encode(data)
}

fn hex_decode(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_default()
}

/// 读取输入：优先从文件读取，否则从文本参数读取
fn read_input(plaintext: Option<&str>, input: Option<&str>) -> Vec<u8> {
    if let Some(path) = input {
        std::fs::read(path).unwrap_or_default()
    } else if let Some(text) = plaintext {
        text.as_bytes().to_vec()
    } else {
        Vec::new()
    }
}

/// 写入输出：file 非空则写文件，否则打印到 stdout
fn write_output(data: &[u8], tag: &str, file: Option<&str>) {
    if let Some(path) = file {
        let _ = std::fs::write(path, data);
        println!("  {} 已写入: {}", tag, path);
    } else if tag == "Plaintext" {
        let text = String::from_utf8(data.to_vec()).unwrap_or_default();
        println!("  {}: {}", tag, text);
    } else {
        println!("  {}: {}", tag, hex_encode_bytes(data));
    }
}

/// encrypt → Encrypt
pub async fn encrypt(
    client: &KmsClient,
    key_id: &str,
    plaintext: Option<&str>,
    input: Option<&str>,
    output: Option<&str>,
) -> crate::Result<Option<serde_json::Value>> {
    let data = read_input(plaintext, input);
    let hex_data = hex_encode_bytes(&data);
    let payload = serde_json::json!([
        {"tag": "UniqueIdentifier", "type": "TextString", "value": key_id},
        {"tag": "Data", "type": "ByteString", "value": hex_data}
    ]);
    let resp = client.kmip_request("Encrypt", Some(payload)).await?;
    if let Some(ciphertext) = resp.get("Data").and_then(|v| v.as_str()) {
        let raw = hex_decode(ciphertext);
        if !raw.is_empty() {
            write_output(&raw, "Ciphertext", output);
        }
    }
    Ok(Some(resp))
}

/// decrypt → Decrypt
pub async fn decrypt(
    client: &KmsClient,
    key_id: &str,
    ciphertext: Option<&str>,
    input: Option<&str>,
    output: Option<&str>,
) -> crate::Result<Option<serde_json::Value>> {
    let data = if let Some(path) = input {
        let raw = std::fs::read(path).unwrap_or_default();
        hex_encode_bytes(&raw)
    } else {
        ciphertext.unwrap_or("").to_string()
    };
    let payload = serde_json::json!([
        {"tag": "UniqueIdentifier", "type": "TextString", "value": key_id},
        {"tag": "Data", "type": "ByteString", "value": data}
    ]);
    let resp = client.kmip_request("Decrypt", Some(payload)).await?;
    if let Some(plaintext) = resp.get("Data").and_then(|v| v.as_str()) {
        let raw = hex_decode(plaintext);
        if !raw.is_empty() {
            write_output(&raw, "Plaintext", output);
        }
    }
    Ok(Some(resp))
}
