use crate::cli::client::KmsClient;

pub async fn handle(client: &KmsClient) -> crate::Result<Option<serde_json::Value>> {
    let resp = client.get("/api/v1/health").await?;
    Ok(Some(resp))
}
