use crate::cli::client::KmsClient;
use crate::cli::types::ApprovalAction;

pub async fn handle(
    client: &KmsClient,
    action: &ApprovalAction,
) -> crate::Result<Option<serde_json::Value>> {
    match action {
        ApprovalAction::Submit {
            key_id,
            operation,
            reason,
        } => submit(client, key_id, operation, reason.as_deref()).await,
        ApprovalAction::Pending => pending(client).await,
        ApprovalAction::Approve { id } => approve(client, id).await,
        ApprovalAction::Reject { id } => reject(client, id).await,
    }
}

/// approval submit → x-SubmitApproval
async fn submit(
    client: &KmsClient,
    key_id: &str,
    operation: &str,
    reason: Option<&str>,
) -> crate::Result<Option<serde_json::Value>> {
    let mut items = vec![
        serde_json::json!({"tag": "Operation", "type": "Enumeration", "value": operation}),
        serde_json::json!({"tag": "UniqueIdentifier", "type": "TextString", "value": key_id}),
    ];
    if let Some(r) = reason {
        items.push(serde_json::json!({"tag": "Description", "type": "TextString", "value": r}));
    }
    let payload = serde_json::Value::Array(items);
    let resp = client
        .kmip_request("x-SubmitApproval", Some(payload))
        .await?;
    if let Some(id) = resp.get("UniqueIdentifier").and_then(|v| v.as_str()) {
        println!("审批已提交: {}", id);
    }
    Ok(Some(resp))
}

/// approval pending → x-ListApprovals
async fn pending(client: &KmsClient) -> crate::Result<Option<serde_json::Value>> {
    let resp = client.kmip_request("x-ListApprovals", None).await?;
    Ok(Some(resp))
}

/// approval approve → x-ApproveRequest
async fn approve(client: &KmsClient, id: &str) -> crate::Result<Option<serde_json::Value>> {
    let payload = serde_json::json!([
        {"tag": "UniqueIdentifier", "type": "TextString", "value": id}
    ]);
    let resp = client
        .kmip_request("x-ApproveRequest", Some(payload))
        .await?;
    println!("审批已通过: {}", id);
    Ok(Some(resp))
}

/// approval reject → x-RejectRequest
async fn reject(client: &KmsClient, id: &str) -> crate::Result<Option<serde_json::Value>> {
    let payload = serde_json::json!([
        {"tag": "UniqueIdentifier", "type": "TextString", "value": id}
    ]);
    let resp = client
        .kmip_request("x-RejectRequest", Some(payload))
        .await?;
    println!("审批已拒绝: {}", id);
    Ok(Some(resp))
}
