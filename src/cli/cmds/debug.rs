use crate::cli::client::KmsClient;
use crate::cli::types::CliCommand;
use crate::crypto::sha256_engine::Sha256Engine;
use crate::crypto::sm3_engine::Sm3Engine;
use crate::crypto::traits::HashEngine;

pub async fn dispatch(client: Option<&KmsClient>, command: &CliCommand) -> crate::Result<()> {
    if let CliCommand::Debug { action } = command {
        match action {
            crate::cli::types::DebugAction::Sm3 { data } => cmd_sm3(data),
            crate::cli::types::DebugAction::Sha256 { data } => cmd_sha256(data),
            crate::cli::types::DebugAction::Rng { bytes } => cmd_rng(client, *bytes).await,
            crate::cli::types::DebugAction::Hmac {
                key,
                data,
                algorithm,
            } => cmd_hmac(client, key, data, algorithm).await,
        }
    } else {
        Ok(())
    }
}

fn cmd_sm3(data: &str) -> crate::Result<()> {
    let engine = Sm3Engine::new();
    let hash = engine.hash(data.as_bytes());
    println!("SM3({}): {}", data, hex::encode(&hash));
    Ok(())
}

fn cmd_sha256(data: &str) -> crate::Result<()> {
    let engine = Sha256Engine::new();
    let hash = engine.hash(data.as_bytes());
    println!("SHA256({}): {}", data, hex::encode(&hash));
    Ok(())
}

/// HMAC 优先调用服务端 KMIP x-Hmac，无 client 时回退到本地
async fn cmd_hmac(
    client: Option<&KmsClient>,
    key: &str,
    data: &str,
    algorithm: &str,
) -> crate::Result<()> {
    if let Some(c) = client {
        let key_hex = hex::encode(key.as_bytes());
        let data_hex = hex::encode(data.as_bytes());
        let algo_upper = algorithm.to_uppercase();
        let payload = serde_json::json!([
            {"tag": "Password", "type": "TextString", "value": key_hex},
            {"tag": "Data", "type": "ByteString", "value": data_hex},
            {"tag": "CryptographicAlgorithm", "type": "Enumeration", "value": algo_upper}
        ]);
        let resp = c.kmip_request("x-Hmac", Some(payload)).await?;
        if let Some(mac_hex) = resp.get("Data").and_then(|v| v.as_str()) {
            let label = format!("HMAC-{}", algo_upper);
            println!("{}({}, {}): {}", label, key, data, mac_hex);
        }
    } else {
        // 回退到本地实现
        match algorithm {
            "sm3" => {
                let engine = Sm3Engine::new();
                let mac = engine.hmac(key.as_bytes(), data.as_bytes())?;
                println!("HMAC-SM3({}, {}): {}", key, data, hex::encode(&mac));
            }
            "sha256" => {
                let engine = Sha256Engine::new();
                let mac = engine.hmac(key.as_bytes(), data.as_bytes())?;
                println!("HMAC-SHA256({}, {}): {}", key, data, hex::encode(&mac));
            }
            _ => {
                return Err(crate::Error::CryptoError(format!(
                    "不支持的 HMAC 算法: {}",
                    algorithm
                )));
            }
        }
    }
    Ok(())
}

/// RNG 调用服务端 KMIP x-GetRandom
async fn cmd_rng(client: Option<&KmsClient>, bytes: u32) -> crate::Result<()> {
    if let Some(c) = client {
        let payload = serde_json::json!([
            {"tag": "CryptographicLength", "type": "Integer", "value": bytes as i32}
        ]);
        let resp = c.kmip_request("x-GetRandom", Some(payload)).await?;
        if let Some(hex_data) = resp.get("Data").and_then(|v| v.as_str()) {
            println!("{}", hex_data);
        }
    } else {
        // 回退到本地
        let mut buf = vec![0u8; bytes as usize];
        getrandom::getrandom(&mut buf)
            .map_err(|e| crate::Error::CryptoError(format!("生成随机数失败: {}", e)))?;
        println!("{}", hex::encode(&buf));
    }
    Ok(())
}
