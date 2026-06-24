use crate::cli::client::KmsClient;
use crate::cli::types::AuditAction;

pub async fn handle(
    client: &KmsClient,
    action: &AuditAction,
) -> crate::Result<Option<serde_json::Value>> {
    match action {
        AuditAction::Logs { since, until } => logs(client, *since, *until).await,
        AuditAction::Verify => verify(client).await,
    }
}

/// audit logs → x-QueryAuditLogs
async fn logs(
    client: &KmsClient,
    since: Option<i64>,
    until: Option<i64>,
) -> crate::Result<Option<serde_json::Value>> {
    let mut nodes = vec![];
    if let Some(t) = since {
        nodes.push(serde_json::json!({"tag": "InitialDate", "type": "Integer", "value": t}));
    }
    if let Some(t) = until {
        nodes.push(serde_json::json!({"tag": "LastChangeDate", "type": "Integer", "value": t}));
    }
    let payload = serde_json::json!(nodes);
    let resp = client
        .kmip_request("x-QueryAuditLogs", Some(payload))
        .await?;
    Ok(Some(resp))
}

/// audit verify → x-VerifyAuditChain
async fn verify(client: &KmsClient) -> crate::Result<Option<serde_json::Value>> {
    let resp = client.kmip_request("x-VerifyAuditChain", None).await?;
    Ok(Some(resp))
}
