use crate::cli::client::KmsClient;
use crate::cli::types::AdminAction;

pub async fn handle(
    client: &KmsClient,
    action: &AdminAction,
) -> crate::Result<Option<serde_json::Value>> {
    match action {
        AdminAction::Blocklist => blocklist(client).await,
        AdminAction::Unblock { target } => unblock(client, target).await,
    }
}

/// admin blocklist → x-GetBlocklist
async fn blocklist(client: &KmsClient) -> crate::Result<Option<serde_json::Value>> {
    let resp = client.kmip_request("x-GetBlocklist", None).await?;
    Ok(Some(resp))
}

/// admin unblock → x-UnblockTarget
async fn unblock(client: &KmsClient, target: &str) -> crate::Result<Option<serde_json::Value>> {
    let payload = serde_json::json!([
        {"tag": "UniqueIdentifier", "type": "TextString", "value": target}
    ]);
    let resp = client
        .kmip_request("x-UnblockTarget", Some(payload))
        .await?;
    println!("已解封: {}", target);
    Ok(Some(resp))
}
