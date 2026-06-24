pub mod admin;
pub mod approvals;
pub mod audit;
pub mod auth;
pub mod configure;
pub mod crypto;
pub mod debug;
pub mod evidence;
pub mod health;
pub mod keys;
pub mod server;

use crate::cli::client::KmsClient;
use crate::cli::types::{AclAction, CliCommand, DepAction};

pub async fn dispatch(
    command: &CliCommand,
    client: &KmsClient,
) -> crate::Result<Option<serde_json::Value>> {
    match command {
        CliCommand::Health => health::handle(client).await,
        CliCommand::Auth { action } => auth::handle(client, action).await,
        CliCommand::Keys { action } => keys::handle(client, action).await,
        CliCommand::Encrypt {
            key_id,
            plaintext,
            input,
            output,
        } => {
            crypto::encrypt(
                client,
                key_id,
                plaintext.as_deref(),
                input.as_deref(),
                output.as_deref(),
            )
            .await
        }
        CliCommand::Decrypt {
            key_id,
            ciphertext,
            input,
            output,
        } => {
            crypto::decrypt(
                client,
                key_id,
                ciphertext.as_deref(),
                input.as_deref(),
                output.as_deref(),
            )
            .await
        }
        CliCommand::Debug { .. } => unreachable!("debug commands handled in main"),
        CliCommand::Audit { action } => audit::handle(client, action).await,
        CliCommand::Approvals { action } => approvals::handle(client, action).await,
        CliCommand::Admin { action } => admin::handle(client, action).await,
        CliCommand::Configure { action } => configure::handle(action).await.map(|_| None),
        CliCommand::Server { action } => server::handle(action).await.map(|_| None),
        CliCommand::Evidence { action } => evidence::handle(client, action).await,
    }
}

pub async fn dispatch_acl(
    client: &KmsClient,
    action: &AclAction,
) -> crate::Result<Option<serde_json::Value>> {
    match action {
        AclAction::Add {
            id,
            subject,
            permission,
        } => keys::handle_acl_add(client, id, subject, permission).await,
        AclAction::Remove { id, subject } => keys::handle_acl_remove(client, id, subject).await,
    }
}

pub async fn dispatch_dep(
    client: &KmsClient,
    action: &DepAction,
) -> crate::Result<Option<serde_json::Value>> {
    match action {
        DepAction::Add { id, dep_id } => keys::handle_dep_add(client, id, dep_id).await,
        DepAction::Remove { id, dep_id } => keys::handle_dep_remove(client, id, dep_id).await,
    }
}
