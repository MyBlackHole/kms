use crate::cli::client::KmsClient;
use crate::cli::types::EvidenceAction;

pub async fn handle(
    client: &KmsClient,
    action: &EvidenceAction,
) -> crate::Result<Option<serde_json::Value>> {
    match action {
        EvidenceAction::Sign { key_id, data } => sign(client, key_id, data).await,
        EvidenceAction::Verify { evidence_id } => verify(client, evidence_id).await,
    }
}

/// evidence sign → x-NonRepudiationSign
async fn sign(
    client: &KmsClient,
    key_id: &str,
    data: &str,
) -> crate::Result<Option<serde_json::Value>> {
    let payload = serde_json::json!([
        {"tag": "UniqueIdentifier", "type": "TextString", "value": key_id},
        {"tag": "Data", "type": "ByteString", "value": data}
    ]);
    let resp = client
        .kmip_request("x-NonRepudiationSign", Some(payload))
        .await?;
    if let Some(id) = resp.get("UniqueIdentifier").and_then(|v| v.as_str()) {
        println!("证据 ID: {}", id);
    }
    Ok(Some(resp))
}

/// evidence verify → x-NonRepudiationVerify
async fn verify(client: &KmsClient, evidence_id: &str) -> crate::Result<Option<serde_json::Value>> {
    let payload = serde_json::json!([
        {"tag": "UniqueIdentifier", "type": "TextString", "value": evidence_id}
    ]);
    let resp = client
        .kmip_request("x-NonRepudiationVerify", Some(payload))
        .await?;
    Ok(Some(resp))
}
