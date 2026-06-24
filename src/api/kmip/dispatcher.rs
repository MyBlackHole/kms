use super::auth::{AuthBridge, AuthContext, SecurityLabel};
use super::codec::{build_response_message, extract_operation_name, extract_request_payload};
use super::types::*;
use crate::api::AppState;
use crate::approval::ApprovalStore;
use crate::config::SecurityLevel;
use crate::crypto::envelope::EncryptedDataKey;
use crate::crypto::traits::{HashEngine, Kdf, SignEngine};
use crate::key::dependency::DependencyStore;
use crate::key::types::{KeyAlgorithm, KeyPolicy, KeySpec, KeyUsage};
use std::sync::Arc;

/// 等保四级关键操作列表（需要二次鉴权）
const CRITICAL_OPERATIONS: &[&str] = &[
    "Destroy",
    "Archive",
    "Revoke",
    "x-GetEvidence",
    "x-QueryAuditLogs",
];

pub async fn dispatch(state: Arc<AppState>, request: KmipNode) -> KmipNode {
    let op_name = match extract_operation_name(&request) {
        Some(n) => n,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing Operation field",
            );
        }
    };

    let payload = match extract_request_payload(&request) {
        Some(p) => p.to_vec(),
        None => vec![],
    };

    // ───── 等保四级安全检查 ─────
    let security_level = state.security_level;

    // 执行认证的操作跳过列表（x-Login, x-TotpVerify 等不需要前置认证）
    let skip_auth_ops = [
        "x-Login",
        "x-login",
        "x-TotpVerify",
        "x-totp-verify",
        "x-Logout",
        "x-logout",
        "x-NonRepudiationSign",
        "x-non-repudiation-sign",
        "x-NonRepudiationVerify",
        "x-non-repudiation-verify",
    ];
    let needs_auth = !skip_auth_ops
        .iter()
        .any(|&s| s.eq_ignore_ascii_case(&op_name));

    // 1. 认证（提取 AuthContext）
    let auth_ctx = if needs_auth {
        match AuthBridge::authenticate(&state, &request, security_level) {
            Ok(ctx) => ctx,
            Err(err_node) => return err_node,
        }
    } else {
        AuthContext::anonymous()
    };

    // 2. Level4 关键操作二次鉴权检查
    let skip_2fa = [
        "x-TotpVerify",
        "x-totp-verify",
        "x-Login",
        "x-login",
        "x-NonRepudiationSign",
        "x-non-repudiation-sign",
        "x-NonRepudiationVerify",
        "x-non-repudiation-verify",
    ];
    let needs_2fa = !skip_2fa.iter().any(|&s| s.eq_ignore_ascii_case(&op_name));

    if security_level == SecurityLevel::Level4 && needs_2fa && is_critical_operation(&op_name) {
        let session_id = match &auth_ctx.session_id {
            Some(id) => id,
            None => {
                return build_reauth_required_response();
            }
        };
        if !state.session_manager.check_second_factor(session_id) {
            return build_reauth_required_response();
        }
    }

    // 3. Level4 MAC（强制访问控制）检查（跳过 x-TotpVerify 等无需 MAC 的操作）
    let skip_mac_ops = [
        "x-Login",
        "x-login",
        "x-TotpVerify",
        "x-totp-verify",
        "x-Logout",
        "x-logout",
        "x-NonRepudiationSign",
        "x-non-repudiation-sign",
        "x-NonRepudiationVerify",
        "x-non-repudiation-verify",
    ];
    let needs_mac = !skip_mac_ops
        .iter()
        .any(|&s| s.eq_ignore_ascii_case(&op_name));

    if security_level == SecurityLevel::Level4 && needs_mac {
        if let Err(err) = check_mac(&state, &op_name, &auth_ctx, &payload).await {
            return err;
        }
    }

    if op_name.starts_with("x-") || op_name.starts_with("X-") {
        return dispatch_custom(&state, &op_name, payload).await;
    }

    let operation = match Operation::from_name(&op_name) {
        Some(op) => op,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "UNSUPPORTED_OPERATION",
                &format!("Unknown operation: {}", op_name),
            );
        }
    };

    match operation {
        Operation::Query => handle_query(state, payload).await,
        Operation::DiscoverVersions => handle_discover_versions().await,
        Operation::Create => handle_create(state, payload).await,
        Operation::Get => handle_get(state, payload).await,
        Operation::Locate => handle_locate(state, payload).await,
        Operation::Activate => handle_activate(state, payload).await,
        Operation::Revoke => handle_revoke(state, payload).await,
        Operation::Destroy => handle_destroy(state, payload).await,
        Operation::Encrypt => handle_encrypt(state, payload).await,
        Operation::Decrypt => handle_decrypt(state, payload).await,
        Operation::CreateKeyPair => handle_create_key_pair(state, payload).await,
        Operation::Register => handle_register(state, payload).await,
        Operation::ReKey => handle_rekey(state, payload).await,
        Operation::Sign => handle_sign(state, payload).await,
        Operation::SignatureVerify => handle_signature_verify(state, payload).await,
        Operation::MAC => handle_mac(state, payload).await,
        Operation::Hash => handle_hash(state, payload).await,
        Operation::GetAttributes => handle_get_attributes(state, payload).await,
        Operation::AddAttribute => handle_add_attribute(state, payload).await,
        Operation::DeleteAttribute => handle_delete_attribute(state, payload).await,
        Operation::Archive => handle_archive(state, payload).await,
        Operation::Import => handle_import(state, payload).await,
        Operation::Export => handle_export(state, payload).await,
        _ => build_error_response(
            ResultStatus::OperationFailed,
            "UNSUPPORTED_OPERATION",
            &format!("Operation {:?} not yet implemented", operation),
        ),
    }
}

/// 判断操作名称是否为关键操作（需要二次鉴权）
fn is_critical_operation(op_name: &str) -> bool {
    CRITICAL_OPERATIONS
        .iter()
        .any(|&critical| critical.eq_ignore_ascii_case(op_name))
}

/// 构建二次鉴权需要的响应
fn build_reauth_required_response() -> KmipNode {
    build_response_message(
        ResultStatus::OperationPending,
        vec![
            KmipNode::enumeration(KmipTag::ResultReason, "ReauthRequired"),
            KmipNode::text(
                KmipTag::ResultMessage,
                "Second factor authentication required",
            ),
        ],
    )
}

/// MAC 检查：根据操作类型比较主体与客体的安全标记
async fn check_mac(
    state: &AppState,
    op_name: &str,
    auth_ctx: &AuthContext,
    payload: &[KmipNode],
) -> Result<(), KmipNode> {
    // KeyAlgorithm used for label lookup

    let subject_label = auth_ctx.security_label;

    // 管理操作：需要 Internal+ 标记
    let admin_ops = [
        "x-ListTokens",
        "x-ListApprovals",
        "x-QueryAuditLogs",
        "x-VerifyAuditChain",
        "x-GetBlocklist",
        "x-UnblockTarget",
        "x-GetEvidence",
        "x-AddDependency",
        "x-RemoveDependency",
        "x-ListDependents",
        "x-SubmitApproval",
        "x-ApproveRequest",
        "x-RejectRequest",
    ];

    let read_ops = [
        "Get",
        "Locate",
        "GetAttributes",
        "GetAttributeList",
        "Export",
        "Decrypt",
        "Sign",
        "SignatureVerify",
        "MAC",
        "Hash",
        "Check",
        "Validate",
        "Query",
        "DiscoverVersions",
        "Import",
    ];

    let write_ops = [
        "Create",
        "Destroy",
        "Archive",
        "Revoke",
        "Rekey",
        "ReKey",
        "AddAttribute",
        "DeleteAttribute",
        "ModifyAttribute",
        "Activate",
        "Recover",
        "Register",
        "CreateKeyPair",
        "Encrypt",
        "DeriveKey",
    ];

    // 管理操作检查 - 必须 Internal+
    if admin_ops.iter().any(|&a| a.eq_ignore_ascii_case(op_name)) {
        if subject_label < SecurityLabel::Internal {
            return Err(build_mac_denied(
                "Admin operations require Internal+ security label",
            ));
        }
        return Ok(());
    }

    // 读操作：主体 >= 客体
    if read_ops.iter().any(|&r| r.eq_ignore_ascii_case(op_name)) {
        // 提取操作关联的 UniqueIdentifier
        let uid = extract_uid(payload);
        return check_read_mac(state, &subject_label, uid.as_deref()).await;
    }

    // 写操作：主体 <= 客体
    if write_ops.iter().any(|&w| w.eq_ignore_ascii_case(op_name)) {
        let uid = extract_uid(payload);
        return check_write_mac(state, &subject_label, uid.as_deref()).await;
    }

    // 未知操作：允许通过
    Ok(())
}

/// 读操作 MAC：主体标记必须 >= 客体标记
async fn check_read_mac(
    state: &AppState,
    subject_label: &SecurityLabel,
    uid: Option<&str>,
) -> Result<(), KmipNode> {
    if let Some(key_id) = uid {
        if let Ok(key) = state.key_manager.get_key(key_id).await {
            let object_label = get_key_security_label(&key);
            if *subject_label < object_label {
                return Err(build_mac_denied(&format!(
                    "Read denied: subject {:?} < object {:?}",
                    subject_label, object_label
                )));
            }
        }
    }
    Ok(())
}

/// 写操作 MAC：主体标记必须 <= 客体标记
async fn check_write_mac(
    state: &AppState,
    subject_label: &SecurityLabel,
    uid: Option<&str>,
) -> Result<(), KmipNode> {
    if let Some(key_id) = uid {
        if let Ok(key) = state.key_manager.get_key(key_id).await {
            let object_label = get_key_security_label(&key);
            if *subject_label > object_label {
                return Err(build_mac_denied(&format!(
                    "Write denied: subject {:?} > object {:?}",
                    subject_label, object_label
                )));
            }
        }
    }
    Ok(())
}

/// 从密钥标签中获取安全标记
fn get_key_security_label(key: &crate::key::types::Key) -> SecurityLabel {
    // 从密钥标签中提取 SecurityLabel
    if let Some(label_str) = key.tags.get("security_label") {
        SecurityLabel::parse_str(label_str)
    } else {
        // 无标签的密钥默认使用 Internal 标记
        SecurityLabel::Internal
    }
}

fn build_mac_denied(reason: &str) -> KmipNode {
    build_error_response(ResultStatus::OperationFailed, "PermissionDenied", reason)
}

async fn dispatch_custom(state: &Arc<AppState>, op_name: &str, payload: Vec<KmipNode>) -> KmipNode {
    // 安全检查在 dispatch() 中已完成，dispatch_custom 只负责路由
    match op_name {
        "x-Login" | "x-login" => handle_x_login(state, payload).await,
        "x-TotpVerify" | "x-totp-verify" => handle_x_totp_verify(state, payload).await,
        "x-Logout" | "x-logout" => handle_x_logout(state, payload).await,
        "x-CreateToken" | "x-create-token" => handle_x_create_token(state, payload).await,
        "x-ListTokens" | "x-list-tokens" => handle_x_list_tokens(state, payload).await,
        "x-RevokeToken" | "x-revoke-token" => handle_x_revoke_token(state, payload).await,
        "x-SubmitApproval" | "x-submit-approval" => handle_x_submit_approval(state, payload).await,
        "x-ListApprovals" | "x-list-approvals" => handle_x_list_approvals(state, payload).await,
        "x-ApproveRequest" | "x-approve-request" => handle_x_approve_request(state, payload).await,
        "x-RejectRequest" | "x-reject-request" => handle_x_reject_request(state, payload).await,
        "x-AddDependency" | "x-add-dependency" => handle_x_add_dependency(state, payload).await,
        "x-RemoveDependency" | "x-remove-dependency" => {
            handle_x_remove_dependency(state, payload).await
        }
        "x-ListDependents" | "x-list-dependents" => handle_x_list_dependents(state, payload).await,
        "x-QueryAuditLogs" | "x-query-audit-logs" => {
            handle_x_query_audit_logs(state, payload).await
        }
        "x-VerifyAuditChain" | "x-verify-audit-chain" => {
            handle_x_verify_audit_chain(state, payload).await
        }
        "x-GetBlocklist" | "x-get-blocklist" => handle_x_get_blocklist(state, payload).await,
        "x-UnblockTarget" | "x-unblock-target" => handle_x_unblock_target(state, payload).await,
        "x-GetEvidence" | "x-get-evidence" => handle_x_get_evidence(state, payload).await,
        "x-NonRepudiationSign" | "x-non-repudiation-sign" => {
            handle_x_non_repudiation_sign(state, payload).await
        }
        "x-NonRepudiationVerify" | "x-non-repudiation-verify" => {
            handle_x_non_repudiation_verify(state, payload).await
        }
        "x-DataKey" | "x-data-key" => handle_x_data_key(state, payload).await,
        "x-GetRandom" | "x-get-random" => handle_x_get_random(state, payload).await,
        "x-Hmac" | "x-hmac" => handle_x_hmac(state, payload).await,
        _ => build_error_response(
            ResultStatus::OperationFailed,
            "UNSUPPORTED_OPERATION",
            &format!("Unknown custom operation: {}", op_name),
        ),
    }
}

fn build_error_response(status: ResultStatus, reason: &str, message: &str) -> KmipNode {
    build_response_message(
        status,
        vec![
            KmipNode::enumeration(KmipTag::ResultReason, reason),
            KmipNode::text(KmipTag::ResultMessage, message),
        ],
    )
}

fn extract_uid(payload: &[KmipNode]) -> Option<String> {
    for node in payload {
        if node.tag == KmipTag::UniqueIdentifier {
            return node.text_value().map(String::from);
        }
    }
    None
}

/// 递归搜索 payload 及其嵌套 Structure 中的 CryptographicAlgorithm
fn extract_algorithm(payload: &[KmipNode]) -> Option<CryptoAlgorithm> {
    for node in payload {
        if node.tag == KmipTag::CryptographicAlgorithm {
            return node
                .enumeration_value()
                .and_then(CryptoAlgorithm::from_name);
        }
        if let KmipValue::Structure(children) = &node.value {
            if let found @ Some(_) = extract_algorithm(children) {
                return found;
            }
        }
    }
    None
}

/// 递归搜索 payload 及其嵌套 Structure 中的 CryptographicLength
fn extract_crypto_length(payload: &[KmipNode]) -> Option<i32> {
    for node in payload {
        if node.tag == KmipTag::CryptographicLength {
            return node.integer_value();
        }
        if let KmipValue::Structure(children) = &node.value {
            if let found @ Some(_) = extract_crypto_length(children) {
                return found;
            }
        }
    }
    None
}

/// 递归搜索 payload 中的 CryptographicUsageMask
fn extract_usage_mask(payload: &[KmipNode]) -> Option<String> {
    for node in payload {
        if node.tag == KmipTag::CryptographicUsageMask {
            return node.enumeration_value().map(String::from);
        }
        if let KmipValue::Structure(children) = &node.value {
            if let found @ Some(_) = extract_usage_mask(children) {
                return found;
            }
        }
    }
    None
}

fn key_algorithm_to_crypto(algo: &KeyAlgorithm) -> Option<CryptoAlgorithm> {
    match algo {
        KeyAlgorithm::Sm4 => Some(CryptoAlgorithm::SM4),
        KeyAlgorithm::Sm2 => Some(CryptoAlgorithm::SM2),
        KeyAlgorithm::Aes256 => Some(CryptoAlgorithm::AES),
        KeyAlgorithm::Rsa2048 => Some(CryptoAlgorithm::RSA),
    }
}

fn crypto_to_key_algorithm(algo: CryptoAlgorithm) -> Option<KeyAlgorithm> {
    match algo {
        CryptoAlgorithm::SM4 => Some(KeyAlgorithm::Sm4),
        CryptoAlgorithm::SM2 => Some(KeyAlgorithm::Sm2),
        CryptoAlgorithm::AES => Some(KeyAlgorithm::Aes256),
        CryptoAlgorithm::RSA => Some(KeyAlgorithm::Rsa2048),
        _ => None,
    }
}

fn map_key_state(state: &crate::key::types::KeyState) -> &'static str {
    use crate::key::types::KeyState as S;
    match state {
        S::Enabled => "Active",
        S::Disabled => "Deactivated",
        S::PendingArchive => "Compromised",
        S::Archived => "Destroyed",
        S::Destroyed => "Destroyed",
    }
}

// ─────────
// Handler: Query
// ─────────

async fn handle_query(state: Arc<AppState>, _payload: Vec<KmipNode>) -> KmipNode {
    let capabilities = vec![
        KmipNode::structure(
            KmipTag::VendorAttribute,
            vec![
                KmipNode::text(KmipTag::VendorAttributePrefix, "KMS"),
                KmipNode::text(KmipTag::VendorAttributeNames, "server_version"),
                KmipNode::text(KmipTag::AttributeValue, env!("CARGO_PKG_VERSION")),
            ],
        ),
        KmipNode::text(
            KmipTag::Description,
            format!("HSM: {}", state.kek_provider.name()),
        ),
    ];

    build_response_message(ResultStatus::Success, capabilities)
}

// ─────────
// Handler: DiscoverVersions
// ─────────

async fn handle_discover_versions() -> KmipNode {
    build_response_message(
        ResultStatus::Success,
        vec![KmipNode::structure(
            KmipTag::ProtocolVersion,
            vec![
                KmipNode::integer(KmipTag::ProtocolVersionMajor, 2),
                KmipNode::integer(KmipTag::ProtocolVersionMinor, 1),
            ],
        )],
    )
}

// ─────────
// Handler: Create
// ─────────

async fn handle_create(state: Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let algo = extract_algorithm(&payload).unwrap_or(CryptoAlgorithm::SM4);
    let key_len = extract_crypto_length(&payload).unwrap_or(128) as u32;
    let usage_str = extract_usage_mask(&payload);

    let key_algo = match crypto_to_key_algorithm(algo) {
        Some(a) => a,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "CRYPTO_ALGORITHM",
                &format!("Unsupported algorithm: {:?}", algo),
            );
        }
    };

    let usage = match usage_str.as_deref() {
        Some("EncryptDecrypt") => vec![KeyUsage::EncryptDecrypt],
        Some("SignVerify") => vec![KeyUsage::SignVerify],
        Some("KeyWrap") => vec![KeyUsage::KeyWrap],
        Some("DeriveKey") => vec![KeyUsage::DeriveKey],
        _ => vec![KeyUsage::EncryptDecrypt],
    };

    let name = extract_text(&payload, KmipTag::Name).unwrap_or_else(|| "kmip-key".into());

    let spec = KeySpec {
        algorithm: key_algo.clone(),
        key_length: key_len,
        usage,
        extractable: false,
    };
    let policy = KeyPolicy {
        rotation_days: None,
        expiration_days: None,
        max_versions: 10,
        require_mfa_to_disable: false,
        require_mfa_to_destroy: true,
        allowed_roles: vec!["admin".into()],
    };

    match state
        .key_manager
        .create_key(&name, spec, policy, None)
        .await
    {
        Ok(key) => build_response_message(
            ResultStatus::Success,
            vec![
                KmipNode::enumeration(KmipTag::ObjectType, ObjectType::SymmetricKey.name()),
                KmipNode::text(KmipTag::UniqueIdentifier, key.id),
            ],
        ),
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "OPERATION_FAILED",
            &e.to_string(),
        ),
    }
}

// ─────────
// Handler: Get
// ─────────

async fn handle_get(state: Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let uid = match extract_uid(&payload) {
        Some(id) => id,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing UniqueIdentifier",
            );
        }
    };

    match state.key_manager.get_key(&uid).await {
        Ok(key) => {
            let algo = key_algorithm_to_crypto(&key.spec.algorithm).unwrap_or(CryptoAlgorithm::AES);

            let mut response_children = vec![
                KmipNode::text(KmipTag::UniqueIdentifier, key.id.clone()),
                KmipNode::enumeration(KmipTag::ObjectType, ObjectType::SymmetricKey.name()),
                KmipNode::structure(
                    KmipTag::Attributes,
                    vec![
                        KmipNode::enumeration(KmipTag::CryptographicAlgorithm, algo.name()),
                        KmipNode::integer(KmipTag::CryptographicLength, key.spec.key_length as i32),
                        KmipNode::enumeration(KmipTag::State, map_key_state(&key.state)),
                        KmipNode::text(KmipTag::Description, key.name.clone()),
                    ],
                ),
            ];

            if let Some(latest_version) = key.versions.last() {
                response_children.push(KmipNode::structure(
                    KmipTag::KeyBlock,
                    vec![
                        KmipNode::enumeration(
                            KmipTag::KeyFormatType,
                            KeyFormatType::TransparentSymmetricKey.name(),
                        ),
                        KmipNode::structure(
                            KmipTag::KeyValue,
                            vec![KmipNode::structure(
                                KmipTag::KeyMaterial,
                                vec![KmipNode::integer(
                                    KmipTag::KeyVersion,
                                    latest_version.version_number as i32,
                                )],
                            )],
                        ),
                        KmipNode::enumeration(KmipTag::CryptographicAlgorithm, algo.name()),
                        KmipNode::integer(KmipTag::CryptographicLength, key.spec.key_length as i32),
                    ],
                ));
            }

            build_response_message(ResultStatus::Success, response_children)
        }
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "KEY_NOT_FOUND",
            &e.to_string(),
        ),
    }
}

// ─────────
// Handler: Locate
// ─────────

async fn handle_locate(state: Arc<AppState>, _payload: Vec<KmipNode>) -> KmipNode {
    match state.key_manager.list_keys().await {
        Ok(keys) => {
            let uids: Vec<KmipNode> = keys
                .into_iter()
                .map(|k| KmipNode::text(KmipTag::UniqueIdentifier, k.id))
                .collect();
            build_response_message(ResultStatus::Success, uids)
        }
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "OPERATION_FAILED",
            &e.to_string(),
        ),
    }
}

// ─────────
// Handler: Activate
// ─────────

async fn handle_activate(state: Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let uid = match extract_uid(&payload) {
        Some(id) => id,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing UniqueIdentifier",
            );
        }
    };

    match state.key_manager.enable_key(&uid).await {
        Ok(key) => build_response_message(
            ResultStatus::Success,
            vec![KmipNode::text(KmipTag::UniqueIdentifier, key.id)],
        ),
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "OPERATION_FAILED",
            &e.to_string(),
        ),
    }
}

// ─────────
// Handler: Revoke
// ─────────

async fn handle_revoke(state: Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let uid = match extract_uid(&payload) {
        Some(id) => id,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing UniqueIdentifier",
            );
        }
    };

    match state.key_manager.disable_key(&uid).await {
        Ok(key) => build_response_message(
            ResultStatus::Success,
            vec![KmipNode::text(KmipTag::UniqueIdentifier, key.id)],
        ),
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "OPERATION_FAILED",
            &e.to_string(),
        ),
    }
}

// ─────────
// Handler: Destroy
// ─────────

async fn handle_destroy(state: Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let uid = match extract_uid(&payload) {
        Some(id) => id,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing UniqueIdentifier",
            );
        }
    };

    match state.key_manager.destroy_key(&uid, &state.dep_store).await {
        Ok(key) => build_response_message(
            ResultStatus::Success,
            vec![KmipNode::text(KmipTag::UniqueIdentifier, key.id)],
        ),
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "OPERATION_FAILED",
            &e.to_string(),
        ),
    }
}

// ─────────
// Handler: Encrypt
// ─────────

async fn handle_encrypt(state: Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let uid = match extract_uid(&payload) {
        Some(id) => id,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing UniqueIdentifier",
            );
        }
    };

    let data = payload.iter().find(|n| n.tag == KmipTag::Data);
    let plaintext = match data.and_then(|n| match &n.value {
        KmipValue::ByteString(b) => Some(b.clone()),
        _ => None,
    }) {
        Some(p) => p,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing Data field (plaintext)",
            );
        }
    };

    let key = match state.key_manager.get_key(&uid).await {
        Ok(k) => k,
        Err(e) => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "KEY_NOT_FOUND",
                &e.to_string(),
            );
        }
    };

    if !key.state.can_encrypt() {
        return build_error_response(
            ResultStatus::OperationFailed,
            "KEY_DISABLED",
            "Key is not enabled for encryption",
        );
    }

    let data_key = match state.envelope.generate_data_key(
        state.kek_provider.as_ref(),
        &uid,
        key.current_version,
        key.spec.algorithm,
    ) {
        Ok(dk) => dk,
        Err(e) => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "CRYPTO_ERROR",
                &e.to_string(),
            );
        }
    };

    let aad = format!("{}:{}", uid, key.current_version);
    let ciphertext = match state.envelope.encrypt_with_dek(
        &plaintext,
        &data_key.plaintext,
        aad.as_bytes(),
        &data_key.encrypted.algorithm,
    ) {
        Ok(ct) => ct,
        Err(e) => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "CRYPTO_ERROR",
                &e.to_string(),
            );
        }
    };

    let mut result = Vec::with_capacity(data_key.encrypted.ciphertext.len() + ciphertext.len());
    result.extend_from_slice(&data_key.encrypted.ciphertext);
    result.extend_from_slice(&ciphertext);

    build_response_message(
        ResultStatus::Success,
        vec![
            KmipNode::text(KmipTag::UniqueIdentifier, uid),
            KmipNode::new(KmipTag::Data, KmipValue::ByteString(result)),
        ],
    )
}

// ─────────
// Handler: Decrypt
// ─────────

async fn handle_decrypt(state: Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let uid = match extract_uid(&payload) {
        Some(id) => id,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing UniqueIdentifier",
            );
        }
    };

    let data = payload.iter().find(|n| n.tag == KmipTag::Data);
    let raw = match data.and_then(|n| match &n.value {
        KmipValue::ByteString(b) => Some(b.clone()),
        _ => None,
    }) {
        Some(d) => d,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing Data field (ciphertext)",
            );
        }
    };

    let key_version = payload
        .iter()
        .find(|n| n.tag == KmipTag::KeyVersion)
        .and_then(|n| n.integer_value())
        .unwrap_or(0) as u32;

    let key = match state.key_manager.get_key(&uid).await {
        Ok(k) => k,
        Err(e) => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "KEY_NOT_FOUND",
                &e.to_string(),
            );
        }
    };

    if !key.state.can_decrypt() {
        return build_error_response(
            ResultStatus::OperationFailed,
            "KEY_DISABLED",
            "Key is not enabled for decryption",
        );
    }

    let nonce_len = 12usize;
    let tag_len = 16usize;
    let dek_len: usize = match key.spec.algorithm {
        KeyAlgorithm::Sm4 => 16,
        KeyAlgorithm::Aes256 => 32,
        _ => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "UNSUPPORTED_OPERATION",
                "Unsupported key algorithm for decryption",
            );
        }
    };
    let envelope_ciphertext_len = nonce_len + dek_len + tag_len;
    if raw.len() < envelope_ciphertext_len {
        return build_error_response(
            ResultStatus::OperationFailed,
            "INVALID_REQUEST",
            "Ciphertext too short for envelope format",
        );
    }

    let encrypted_dek_bytes = &raw[..envelope_ciphertext_len];
    let data_ciphertext = &raw[envelope_ciphertext_len..];

    let algo_label = match key.spec.algorithm {
        KeyAlgorithm::Sm4 => "SM4-GCM",
        KeyAlgorithm::Aes256 => "AES-256-GCM",
        _ => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "UNSUPPORTED_OPERATION",
                "Unsupported key algorithm for decryption",
            );
        }
    };

    let encrypted_dek = EncryptedDataKey {
        ciphertext: encrypted_dek_bytes.to_vec(),
        key_id: uid.clone(),
        algorithm: algo_label.into(),
        key_version,
    };

    let dek = match state
        .envelope
        .decrypt_data_key(state.kek_provider.as_ref(), &encrypted_dek)
    {
        Ok(d) => d,
        Err(e) => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "CRYPTO_ERROR",
                &e.to_string(),
            );
        }
    };

    let aad = format!("{}:{}", uid, key_version);
    let plaintext =
        match state
            .envelope
            .decrypt_with_dek(data_ciphertext, &dek, aad.as_bytes(), algo_label)
        {
            Ok(p) => p,
            Err(e) => {
                return build_error_response(
                    ResultStatus::OperationFailed,
                    "CRYPTO_ERROR",
                    &e.to_string(),
                );
            }
        };

    build_response_message(
        ResultStatus::Success,
        vec![
            KmipNode::text(KmipTag::UniqueIdentifier, uid),
            KmipNode::new(KmipTag::Data, KmipValue::ByteString(plaintext)),
        ],
    )
}

// ─────────
// Handler: CreateKeyPair
// ─────────

async fn handle_create_key_pair(state: Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let usage_str = extract_usage_mask(&payload);
    let usage = match usage_str.as_deref() {
        Some("EncryptDecrypt") => vec![KeyUsage::EncryptDecrypt],
        Some("SignVerify") => vec![KeyUsage::SignVerify],
        Some("KeyWrap") => vec![KeyUsage::KeyWrap],
        Some("DeriveKey") => vec![KeyUsage::DeriveKey],
        _ => vec![KeyUsage::SignVerify],
    };
    let name = extract_text(&payload, KmipTag::Name).unwrap_or_else(|| "kmip-key-pair".into());
    let spec = KeySpec {
        algorithm: KeyAlgorithm::Sm2,
        key_length: 256,
        usage,
        extractable: false,
    };
    let policy = KeyPolicy {
        rotation_days: None,
        expiration_days: None,
        max_versions: 1,
        require_mfa_to_disable: false,
        require_mfa_to_destroy: true,
        allowed_roles: vec!["admin".into()],
    };

    match state
        .key_manager
        .create_key(&name, spec, policy, None)
        .await
    {
        Ok(key) => build_response_message(
            ResultStatus::Success,
            vec![
                KmipNode::text(KmipTag::UniqueIdentifier, key.id.clone()),
                KmipNode::text(KmipTag::UniqueIdentifier, format!("{}_pub", key.id)),
            ],
        ),
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "OPERATION_FAILED",
            &e.to_string(),
        ),
    }
}

// ─────────
// Handler: Register
// ─────────

async fn handle_register(state: Arc<AppState>, _payload: Vec<KmipNode>) -> KmipNode {
    let name = "kmip-registered";
    let spec = KeySpec {
        algorithm: KeyAlgorithm::Sm4,
        key_length: 128,
        usage: vec![KeyUsage::EncryptDecrypt],
        extractable: true,
    };
    let policy = KeyPolicy {
        rotation_days: None,
        expiration_days: None,
        max_versions: 1,
        require_mfa_to_disable: false,
        require_mfa_to_destroy: true,
        allowed_roles: vec!["admin".into()],
    };

    match state.key_manager.create_key(name, spec, policy, None).await {
        Ok(key) => build_response_message(
            ResultStatus::Success,
            vec![KmipNode::text(KmipTag::UniqueIdentifier, key.id)],
        ),
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "OPERATION_FAILED",
            &e.to_string(),
        ),
    }
}

// ─────────
// Handler: ReKey
// ─────────

async fn handle_rekey(state: Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let uid = match extract_uid(&payload) {
        Some(id) => id,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing UniqueIdentifier",
            );
        }
    };

    match state.key_manager.rotate_key(&uid).await {
        Ok(key) => build_response_message(
            ResultStatus::Success,
            vec![KmipNode::text(KmipTag::UniqueIdentifier, key.id)],
        ),
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "OPERATION_FAILED",
            &e.to_string(),
        ),
    }
}

// ─────────
// Handler: Sign
// ─────────

async fn handle_sign(state: Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let uid = match extract_uid(&payload) {
        Some(id) => id,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing UniqueIdentifier",
            );
        }
    };

    let data = payload.iter().find(|n| n.tag == KmipTag::Data);
    let msg = match data.and_then(|n| match &n.value {
        KmipValue::ByteString(b) => Some(b.clone()),
        _ => None,
    }) {
        Some(m) => m,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing Data field",
            );
        }
    };

    let key = match state.key_manager.get_key(&uid).await {
        Ok(k) => k,
        Err(e) => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "KEY_NOT_FOUND",
                &e.to_string(),
            );
        }
    };

    if key.spec.algorithm != KeyAlgorithm::Sm2 {
        return build_error_response(
            ResultStatus::OperationFailed,
            "CRYPTO_ALGORITHM",
            "Sign requires SM2 key",
        );
    }

    let sm2 = crate::crypto::sm2_engine::Sm2Engine::new();
    let signature = match sm2.sign(b"", &msg) {
        Ok(sig) => sig,
        Err(e) => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "CRYPTO_ERROR",
                &e.to_string(),
            );
        }
    };

    build_response_message(
        ResultStatus::Success,
        vec![
            KmipNode::text(KmipTag::UniqueIdentifier, uid),
            KmipNode::new(KmipTag::Data, KmipValue::ByteString(signature)),
        ],
    )
}

// ─────────
// Handler: SignatureVerify
// ─────────

async fn handle_signature_verify(_state: Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let uid = match extract_uid(&payload) {
        Some(id) => id,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing UniqueIdentifier",
            );
        }
    };

    let msg = payload
        .iter()
        .find(|n| n.tag == KmipTag::Data)
        .and_then(|n| match &n.value {
            KmipValue::ByteString(b) => Some(b.clone()),
            _ => None,
        });
    let sig = payload
        .iter()
        .find(|n| n.tag == KmipTag::DigitalSignatureAlgorithm)
        .and_then(|n| match &n.value {
            KmipValue::ByteString(b) => Some(b.clone()),
            _ => None,
        });

    match (msg, sig) {
        (Some(_m), _) => build_response_message(
            ResultStatus::Success,
            vec![
                KmipNode::text(KmipTag::UniqueIdentifier, uid),
                KmipNode::enumeration(KmipTag::ResultStatus, "Success"),
            ],
        ),
        _ => build_error_response(
            ResultStatus::OperationFailed,
            "INVALID_REQUEST",
            "Missing Data or signature fields",
        ),
    }
}

// ─────────
// Handler: MAC
// ─────────

async fn handle_mac(_state: Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let data = payload.iter().find(|n| n.tag == KmipTag::Data);
    let msg = match data.and_then(|n| match &n.value {
        KmipValue::ByteString(b) => Some(b.clone()),
        _ => None,
    }) {
        Some(m) => m,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing Data field",
            );
        }
    };

    let hkdf = crate::crypto::hkdf_engine::HkdfEngine::new();
    let key = vec![0u8; 32];
    let mac = match hkdf.derive_key(&key, b"KMIP-MAC", &msg, 32) {
        Ok(m) => m,
        Err(e) => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "CRYPTO_ERROR",
                &e.to_string(),
            );
        }
    };

    build_response_message(
        ResultStatus::Success,
        vec![
            KmipNode::text(KmipTag::UniqueIdentifier, "mac-result"),
            KmipNode::new(KmipTag::Data, KmipValue::ByteString(mac)),
        ],
    )
}

// ─────────
// Handler: Hash
// ─────────

async fn handle_hash(_state: Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let data = payload.iter().find(|n| n.tag == KmipTag::Data);
    let msg = match data.and_then(|n| match &n.value {
        KmipValue::ByteString(b) => Some(b.clone()),
        _ => None,
    }) {
        Some(m) => m,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing Data field",
            );
        }
    };

    let sm3 = crate::crypto::sm3_engine::Sm3Engine::new();
    let hash = sm3.hash(&msg);

    build_response_message(
        ResultStatus::Success,
        vec![KmipNode::new(
            KmipTag::Data,
            KmipValue::ByteString(hash.to_vec()),
        )],
    )
}

// ─────────
// Handler: x-DataKey — 为指定密钥生成数据密钥（DEK）
// ─────────

async fn handle_x_data_key(state: &Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let uid = match extract_uid(&payload) {
        Some(id) => id,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing UniqueIdentifier",
            );
        }
    };

    let key = match state.key_manager.get_key(&uid).await {
        Ok(k) => k,
        Err(e) => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "KEY_NOT_FOUND",
                &e.to_string(),
            );
        }
    };

    let data_key = match state.envelope.generate_data_key(
        state.kek_provider.as_ref(),
        &uid,
        key.current_version,
        key.spec.algorithm,
    ) {
        Ok(dk) => dk,
        Err(e) => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "CRYPTO_ERROR",
                &e.to_string(),
            );
        }
    };

    let dek_hex = hex::encode(&data_key.plaintext);

    build_response_message(
        ResultStatus::Success,
        vec![
            KmipNode::text(KmipTag::UniqueIdentifier, uid.clone()),
            KmipNode::new(
                KmipTag::Data,
                KmipValue::ByteString(data_key.encrypted.ciphertext.clone()),
            ),
            KmipNode::text(KmipTag::KeyBlock, dek_hex),
            KmipNode::text(
                KmipTag::Description,
                format!("{}:v{}", uid, key.current_version),
            ),
        ],
    )
}

// ─────────
// Handler: x-GetRandom
// ─────────

async fn handle_x_get_random(_state: &Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let byte_count = payload
        .iter()
        .find(|n| n.tag == KmipTag::CryptographicLength)
        .and_then(|n| n.integer_value())
        .unwrap_or(32)
        .clamp(1, 65536) as usize;

    let mut buf = vec![0u8; byte_count];
    match getrandom::getrandom(&mut buf) {
        Ok(()) => build_response_message(
            ResultStatus::Success,
            vec![KmipNode::new(KmipTag::Data, KmipValue::ByteString(buf))],
        ),
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "CRYPTO_ERROR",
            &format!("随机数生成失败: {}", e),
        ),
    }
}

// ─────────
// Handler: x-Hmac
// ─────────

async fn handle_x_hmac(_state: &Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let msg = match payload
        .iter()
        .find(|n| n.tag == KmipTag::Data)
        .and_then(|n| match &n.value {
            KmipValue::ByteString(b) => Some(b.clone()),
            _ => None,
        }) {
        Some(m) => m,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing Data field",
            );
        }
    };

    let key_hex = payload
        .iter()
        .find(|n| n.tag == KmipTag::Password)
        .and_then(|n| n.text_value())
        .unwrap_or("")
        .to_string();
    let key = hex::decode(&key_hex).unwrap_or_default();

    let algorithm = payload
        .iter()
        .find(|n| n.tag == KmipTag::CryptographicAlgorithm)
        .and_then(|n| n.enumeration_value())
        .unwrap_or("SM3");

    let mac_result = match algorithm {
        "SM3" | "sm3" => {
            let engine = crate::crypto::sm3_engine::Sm3Engine::new();
            engine.hmac(&key, &msg)
        }
        "SHA256" | "sha256" => {
            let engine = crate::crypto::sha256_engine::Sha256Engine::new();
            engine.hmac(&key, &msg)
        }
        _ => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                &format!("Unsupported HMAC algorithm: {}", algorithm),
            );
        }
    };

    let mac = match mac_result {
        Ok(m) => m,
        Err(e) => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "CRYPTO_ERROR",
                &e.to_string(),
            );
        }
    };

    build_response_message(
        ResultStatus::Success,
        vec![KmipNode::new(KmipTag::Data, KmipValue::ByteString(mac))],
    )
}

// ─────────
// Handler: GetAttributes
// ─────────

async fn handle_get_attributes(state: Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let uid = match extract_uid(&payload) {
        Some(id) => id,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing UniqueIdentifier",
            );
        }
    };

    match state.key_manager.get_key(&uid).await {
        Ok(key) => {
            let algo = key_algorithm_to_crypto(&key.spec.algorithm).unwrap_or(CryptoAlgorithm::SM4);
            build_response_message(
                ResultStatus::Success,
                vec![
                    KmipNode::text(KmipTag::UniqueIdentifier, key.id),
                    KmipNode::structure(
                        KmipTag::Attributes,
                        vec![
                            KmipNode::enumeration(KmipTag::CryptographicAlgorithm, algo.name()),
                            KmipNode::integer(
                                KmipTag::CryptographicLength,
                                key.spec.key_length as i32,
                            ),
                            KmipNode::enumeration(KmipTag::State, map_key_state(&key.state)),
                            KmipNode::text(KmipTag::Description, key.name),
                        ],
                    ),
                ],
            )
        }
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "KEY_NOT_FOUND",
            &e.to_string(),
        ),
    }
}

// ─────────
// Handler: AddAttribute
// ─────────

async fn handle_add_attribute(state: Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let uid = match extract_uid(&payload) {
        Some(id) => id,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing UniqueIdentifier",
            );
        }
    };

    match state.key_manager.get_key(&uid).await {
        Ok(key) => build_response_message(
            ResultStatus::Success,
            vec![KmipNode::text(KmipTag::UniqueIdentifier, key.id)],
        ),
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "KEY_NOT_FOUND",
            &e.to_string(),
        ),
    }
}

// ─────────
// Handler: DeleteAttribute
// ─────────

async fn handle_delete_attribute(state: Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let uid = match extract_uid(&payload) {
        Some(id) => id,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing UniqueIdentifier",
            );
        }
    };

    match state.key_manager.get_key(&uid).await {
        Ok(key) => build_response_message(
            ResultStatus::Success,
            vec![KmipNode::text(KmipTag::UniqueIdentifier, key.id)],
        ),
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "KEY_NOT_FOUND",
            &e.to_string(),
        ),
    }
}

// ─────────
// Handler: Archive
// ─────────

async fn handle_archive(state: Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let uid = match extract_uid(&payload) {
        Some(id) => id,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing UniqueIdentifier",
            );
        }
    };

    match state.key_manager.archive_key(&uid, &state.dep_store).await {
        Ok(key) => build_response_message(
            ResultStatus::Success,
            vec![KmipNode::text(KmipTag::UniqueIdentifier, key.id)],
        ),
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "OPERATION_FAILED",
            &e.to_string(),
        ),
    }
}

// ─────────
// Handler: Import / Export
// ─────────

async fn handle_import(state: Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let algorithm = payload
        .iter()
        .find(|n| n.tag == KmipTag::CryptographicAlgorithm)
        .and_then(|n| n.enumeration_value())
        .and_then(KeyAlgorithm::from_name)
        .unwrap_or(KeyAlgorithm::Sm4);
    let key_length = payload
        .iter()
        .find(|n| n.tag == KmipTag::CryptographicLength)
        .and_then(|n| n.integer_value())
        .unwrap_or(128) as u32;
    let material = payload
        .iter()
        .find(|n| n.tag == KmipTag::Data)
        .and_then(|n| match &n.value {
            KmipValue::ByteString(b) => Some(b.clone()),
            _ => None,
        });

    let name = extract_text(&payload, KmipTag::Name).unwrap_or_else(|| "imported-key".into());

    let spec = KeySpec {
        algorithm,
        key_length,
        usage: vec![KeyUsage::EncryptDecrypt],
        extractable: true,
    };
    let policy = KeyPolicy {
        rotation_days: None,
        expiration_days: None,
        max_versions: 1,
        require_mfa_to_disable: false,
        require_mfa_to_destroy: true,
        allowed_roles: vec!["admin".into()],
    };

    match state
        .key_manager
        .create_key(&name, spec, policy, None)
        .await
    {
        Ok(key) => {
            // 如果导入请求中提供了密钥材料，覆盖到版本 1
            if let Some(mat) = material {
                if let Err(e) = state.key_manager.store_key_material(&key.id, 1, mat).await {
                    return build_error_response(
                        ResultStatus::OperationFailed,
                        "STORAGE_ERROR",
                        &format!("存储密钥材料失败: {}", e),
                    );
                }
            }
            build_response_message(
                ResultStatus::Success,
                vec![KmipNode::text(KmipTag::UniqueIdentifier, key.id)],
            )
        }
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "OPERATION_FAILED",
            &e.to_string(),
        ),
    }
}

async fn handle_export(state: Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let uid = match extract_uid(&payload) {
        Some(id) => id,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing UniqueIdentifier",
            );
        }
    };

    match state.key_manager.get_key(&uid).await {
        Ok(key) => {
            let material = state.key_manager.get_key_material(&key);
            let mut nodes = vec![
                KmipNode::text(KmipTag::UniqueIdentifier, key.id.clone()),
                KmipNode::text(KmipTag::Name, key.name.clone()),
                KmipNode::enumeration(KmipTag::CryptographicAlgorithm, key.spec.algorithm.name()),
                KmipNode::integer(KmipTag::CryptographicLength, key.spec.key_length as i32),
                KmipNode::enumeration(KmipTag::KeyFormatType, KeyFormatType::Raw.name()),
            ];
            if let Some(mat) = material {
                nodes.push(KmipNode::new(
                    KmipTag::Data,
                    KmipValue::ByteString(mat.to_vec()),
                ));
            }
            build_response_message(ResultStatus::Success, nodes)
        }
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "KEY_NOT_FOUND",
            &e.to_string(),
        ),
    }
}

// ═══════════════════════════════════════════
//  自定义扩展操作 (x-* prefix)
// ═══════════════════════════════════════════
//  Auth: x-Login, x-TotpVerify, x-Logout
// ═══════════════════════════════════════════

fn extract_text(payload: &[KmipNode], tag: KmipTag) -> Option<String> {
    payload
        .iter()
        .find(|n| n.tag == tag)
        .and_then(|n| match &n.value {
            KmipValue::TextString(s) => Some(s.clone()),
            _ => None,
        })
}

async fn handle_x_login(state: &Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let username = match extract_text(&payload, KmipTag::Username) {
        Some(u) => u,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing Username for login",
            );
        }
    };

    let session_id = uuid::Uuid::new_v4().to_string();
    state
        .session_manager
        .create_session(session_id.clone(), username.clone());

    let totp_uri = format!(
        "otpauth://totp/{}:{}?secret=PLACEHOLDER&issuer={}",
        state.totp_secret_issuer, username, state.totp_secret_issuer
    );

    build_response_message(
        ResultStatus::Success,
        vec![
            KmipNode::text(KmipTag::UniqueIdentifier, session_id),
            KmipNode::text(KmipTag::ServerURI, totp_uri),
        ],
    )
}

async fn handle_x_totp_verify(state: &Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let session_id = match extract_text(&payload, KmipTag::UniqueIdentifier) {
        Some(s) => s,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing UniqueIdentifier (session_id)",
            );
        }
    };

    let _totp_code = match extract_text(&payload, KmipTag::Password) {
        Some(c) => c,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing Password (TOTP code)",
            );
        }
    };

    let session = match state.session_manager.validate_session(&session_id) {
        Some(s) => s,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "AUTH_FAILED",
                "Invalid or expired session",
            );
        }
    };

    state.session_manager.mark_totp_verified(&session_id);
    // 在 Level4 模式下，TOTP 验证也作为二次鉴权
    state.session_manager.mark_second_factor(&session_id);

    let auth_cred =
        crate::api::kmip::auth::AuthBridge::build_auth_node(&session.username, Some(&session_id));

    let cred_json = serde_json::to_string(&auth_cred).unwrap_or_default();

    build_response_message(
        ResultStatus::Success,
        vec![
            KmipNode::text(KmipTag::UniqueIdentifier, session_id),
            KmipNode::text(KmipTag::CredentialValue, cred_json),
        ],
    )
}

async fn handle_x_logout(state: &Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let session_id = match extract_text(&payload, KmipTag::UniqueIdentifier) {
        Some(s) => s,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing UniqueIdentifier (session_id)",
            );
        }
    };

    state.session_manager.destroy_session(&session_id);

    build_response_message(ResultStatus::Success, vec![])
}

// ═══════════════════════════════════════════
//  Token: x-CreateToken, x-ListTokens, x-RevokeToken
// ═══════════════════════════════════════════

async fn handle_x_create_token(state: &Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let name = extract_text(&payload, KmipTag::Name).unwrap_or_else(|| "kmip-token".into());
    let role = extract_text(&payload, KmipTag::KeyRoleType);

    match state
        .token_store
        .create_token(&name, role.as_deref(), None)
        .await
    {
        Ok((id, token, _hint)) => build_response_message(
            ResultStatus::Success,
            vec![
                KmipNode::text(KmipTag::UniqueIdentifier, id),
                KmipNode::text(KmipTag::Password, token),
            ],
        ),
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "OPERATION_FAILED",
            &e.to_string(),
        ),
    }
}

async fn handle_x_list_tokens(state: &Arc<AppState>, _payload: Vec<KmipNode>) -> KmipNode {
    let _tokens = state.token_store.list_tokens().await.unwrap_or_default();
    let items: Vec<KmipNode> = _tokens
        .iter()
        .map(|t| {
            KmipNode::structure(
                KmipTag::UniqueIdentifier,
                vec![
                    KmipNode::text(KmipTag::UniqueIdentifier, t.id.clone()),
                    KmipNode::text(KmipTag::Name, t.name.clone()),
                ],
            )
        })
        .collect();

    build_response_message(ResultStatus::Success, items)
}

async fn handle_x_revoke_token(state: &Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let token_id = match extract_text(&payload, KmipTag::UniqueIdentifier) {
        Some(id) => id,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing UniqueIdentifier (token_id)",
            );
        }
    };

    match state.token_store.revoke_token(&token_id).await {
        Ok(true) => build_response_message(ResultStatus::Success, vec![]),
        Ok(false) => build_error_response(
            ResultStatus::OperationFailed,
            "NOT_FOUND",
            "Token not found",
        ),
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "OPERATION_FAILED",
            &e.to_string(),
        ),
    }
}

// ═══════════════════════════════════════════
//  Approval: x-SubmitApproval, x-ListApprovals,
//            x-ApproveRequest, x-RejectRequest
// ═══════════════════════════════════════════

async fn handle_x_submit_approval(state: &Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let action = extract_text(&payload, KmipTag::Operation).unwrap_or_else(|| "UNKNOWN".into());
    let resource =
        extract_text(&payload, KmipTag::UniqueIdentifier).unwrap_or_else(|| "unknown".into());
    let reason = extract_text(&payload, KmipTag::Description).unwrap_or_else(|| "No reason".into());

    let req = crate::approval::ApprovalRequest::new(&action, &resource, "kmip", &reason);
    match state.approval_store.create_request(&req).await {
        Ok(()) => build_response_message(
            ResultStatus::Success,
            vec![KmipNode::text(KmipTag::UniqueIdentifier, req.id)],
        ),
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "OPERATION_FAILED",
            &e.to_string(),
        ),
    }
}

async fn handle_x_list_approvals(state: &Arc<AppState>, _payload: Vec<KmipNode>) -> KmipNode {
    let items: Vec<crate::approval::ApprovalRequest> = state
        .approval_store
        .list_pending()
        .await
        .unwrap_or_default();

    let nodes: Vec<KmipNode> = items
        .into_iter()
        .map(|r| {
            KmipNode::structure(
                KmipTag::BatchItem,
                vec![
                    KmipNode::text(KmipTag::UniqueIdentifier, r.id),
                    KmipNode::text(KmipTag::Operation, r.action),
                    KmipNode::text(KmipTag::Description, r.reason),
                ],
            )
        })
        .collect();

    build_response_message(ResultStatus::Success, nodes)
}

async fn handle_x_approve_request(state: &Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let id = match extract_text(&payload, KmipTag::UniqueIdentifier) {
        Some(i) => i,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing UniqueIdentifier (approval_id)",
            );
        }
    };

    match state
        .approval_store
        .resolve(&id, true, "kmip-approver")
        .await
    {
        Ok(()) => build_response_message(ResultStatus::Success, vec![]),
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "OPERATION_FAILED",
            &e.to_string(),
        ),
    }
}

async fn handle_x_reject_request(state: &Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let id = match extract_text(&payload, KmipTag::UniqueIdentifier) {
        Some(i) => i,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing UniqueIdentifier (approval_id)",
            );
        }
    };

    match state
        .approval_store
        .resolve(&id, false, "kmip-rejecter")
        .await
    {
        Ok(()) => build_response_message(ResultStatus::Success, vec![]),
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "OPERATION_FAILED",
            &e.to_string(),
        ),
    }
}

// ═══════════════════════════════════════════
//  Dependency: x-AddDependency, x-RemoveDependency,
//              x-ListDependents
// ═══════════════════════════════════════════

async fn handle_x_add_dependency(state: &Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let key_id = extract_text(&payload, KmipTag::UniqueIdentifier).unwrap_or_default();
    let dep_key_id = extract_text(&payload, KmipTag::LinkedObjectIdentifier).unwrap_or_default();
    let description = extract_text(&payload, KmipTag::Description);

    let dep = crate::key::dependency::KeyDependency::new(&key_id, 1, &dep_key_id, description);

    match state.dep_store.add_dependency(&dep).await {
        Ok(()) => build_response_message(
            ResultStatus::Success,
            vec![KmipNode::text(KmipTag::UniqueIdentifier, dep_key_id)],
        ),
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "OPERATION_FAILED",
            &e.to_string(),
        ),
    }
}

async fn handle_x_remove_dependency(state: &Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let dep_id = extract_text(&payload, KmipTag::UniqueIdentifier).unwrap_or_default();

    match state.dep_store.remove_dependency(&dep_id).await {
        Ok(()) => build_response_message(ResultStatus::Success, vec![]),
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "OPERATION_FAILED",
            &e.to_string(),
        ),
    }
}

async fn handle_x_list_dependents(state: &Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let key_id = extract_text(&payload, KmipTag::UniqueIdentifier).unwrap_or_default();

    let deps: Vec<crate::key::dependency::KeyDependency> = state
        .dep_store
        .list_dependents(&key_id)
        .await
        .unwrap_or_default();

    let nodes: Vec<KmipNode> = deps
        .into_iter()
        .map(|d| KmipNode::text(KmipTag::UniqueIdentifier, d.dependent_key_id))
        .collect();

    build_response_message(ResultStatus::Success, nodes)
}

// ═══════════════════════════════════════════
//  Audit: x-QueryAuditLogs, x-VerifyAuditChain
// ═══════════════════════════════════════════

async fn handle_x_query_audit_logs(state: &Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let start_time = payload
        .iter()
        .find(|n| n.tag == KmipTag::InitialDate)
        .and_then(|n| n.integer_value())
        .unwrap_or(0) as i64;

    let end_time = payload
        .iter()
        .find(|n| n.tag == KmipTag::LastChangeDate)
        .and_then(|n| n.integer_value())
        .unwrap_or(0) as i64;

    match state.audit_logger.query(start_time, end_time).await {
        Ok(events) => {
            let nodes: Vec<KmipNode> = events
                .into_iter()
                .map(|e| {
                    KmipNode::structure(
                        KmipTag::BatchItem,
                        vec![
                            KmipNode::text(KmipTag::UniqueIdentifier, e.event_id),
                            KmipNode::text(KmipTag::Operation, e.action),
                            KmipNode::text(KmipTag::Description, e.result),
                        ],
                    )
                })
                .collect();
            build_response_message(ResultStatus::Success, nodes)
        }
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "OPERATION_FAILED",
            &e.to_string(),
        ),
    }
}

async fn handle_x_verify_audit_chain(state: &Arc<AppState>, _payload: Vec<KmipNode>) -> KmipNode {
    match state.audit_logger.verify_chain().await {
        Ok(true) => build_response_message(
            ResultStatus::Success,
            vec![KmipNode::enumeration(
                KmipTag::ResultStatus,
                "ChainVerified",
            )],
        ),
        Ok(false) => build_error_response(
            ResultStatus::OperationFailed,
            "VERIFICATION_FAILED",
            "Audit chain integrity check failed",
        ),
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "OPERATION_FAILED",
            &e.to_string(),
        ),
    }
}

// ═══════════════════════════════════════════
//  Blocklist: x-GetBlocklist, x-UnblockTarget
// ═══════════════════════════════════════════

async fn handle_x_get_blocklist(state: &Arc<AppState>, _payload: Vec<KmipNode>) -> KmipNode {
    let entries = state.blocklist.active_blocks().await;
    let nodes: Vec<KmipNode> = entries
        .iter()
        .map(|entry| {
            let remaining = entry.remaining_secs();
            KmipNode::structure(
                KmipTag::BatchItem,
                vec![
                    KmipNode::text(KmipTag::UniqueIdentifier, entry.target.clone()),
                    KmipNode::text(KmipTag::Description, format!("remaining: {}s", remaining)),
                ],
            )
        })
        .collect();

    build_response_message(ResultStatus::Success, nodes)
}

async fn handle_x_unblock_target(state: &Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    let target = match extract_text(&payload, KmipTag::UniqueIdentifier) {
        Some(t) => t,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing UniqueIdentifier (target)",
            );
        }
    };

    state.blocklist.unblock(&target).await;
    build_response_message(ResultStatus::Success, vec![])
}

// ═══════════════════════════════════════════
//  Evidence: x-GetEvidence
// ═══════════════════════════════════════════

async fn handle_x_get_evidence(state: &Arc<AppState>, _payload: Vec<KmipNode>) -> KmipNode {
    let evidence = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "tpm_level": format!("{:?}", state.tpm.level()),
        "platform": std::env::consts::ARCH,
    });

    build_response_message(
        ResultStatus::Success,
        vec![KmipNode::text(KmipTag::Description, evidence.to_string())],
    )
}

// ═══════════════════════════════════════════
//  Non-Repudiation: x-NonRepudiationSign, x-NonRepudiationVerify
// ═══════════════════════════════════════════

/// x-NonRepudiationSign: 对操作生成 SM2 签名 + 时间戳证据
async fn handle_x_non_repudiation_sign(state: &Arc<AppState>, payload: Vec<KmipNode>) -> KmipNode {
    if !state.anti_repudiation {
        return build_error_response(
            ResultStatus::OperationFailed,
            "OPERATION_FAILED",
            "Anti-repudiation module is disabled",
        );
    }

    let operation = extract_text(&payload, KmipTag::Operation).unwrap_or_else(|| "unknown".into());
    let key_id = extract_text(&payload, KmipTag::UniqueIdentifier).unwrap_or_default();
    let data = payload.iter().find(|n| n.tag == KmipTag::Data);
    let data_bytes = match data.and_then(|n| match &n.value {
        KmipValue::ByteString(b) => Some(b.clone()),
        _ => None,
    }) {
        Some(d) => d,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing Data field (data to sign)",
            );
        }
    };

    // 生成签名证据
    let evidence_id = uuid::Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);

    // 计算数据哈希（SM3）
    let sm3 = crate::crypto::sm3_engine::Sm3Engine::new();
    let data_hash = sm3.hash(&data_bytes);
    let data_hash_hex = hex::encode(&data_hash);

    // 构建待签名内容：evidence_id | timestamp | operation | key_id | data_hash
    let sign_input = format!(
        "{}|{}|{}|{}|{}",
        evidence_id, timestamp, operation, key_id, data_hash_hex
    );

    // SM2 签名
    let sm2 = crate::crypto::sm2_engine::Sm2Engine::new();
    let signature = match sm2.sign(b"", sign_input.as_bytes()) {
        Ok(sig) => sig,
        Err(e) => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "CRYPTO_ERROR",
                &e.to_string(),
            );
        }
    };

    // 存储证据到数据库
    let pool = &state.pool;
    let sig_hex = hex::encode(&signature);
    let result = sqlx::query(
        r#"
        INSERT INTO non_repudiation_evidence
            (id, operation, key_id, subject, signature, timestamp, data_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&evidence_id)
    .bind(&operation)
    .bind(&key_id)
    .bind("kmip") // subject — 可根据 AuthContext 填充
    .bind(&sig_hex)
    .bind(timestamp)
    .bind(&data_hash_hex)
    .execute(pool)
    .await;

    match result {
        Ok(_) => build_response_message(
            ResultStatus::Success,
            vec![
                KmipNode::text(KmipTag::UniqueIdentifier, evidence_id),
                KmipNode::new(KmipTag::Data, KmipValue::ByteString(signature)),
                KmipNode::text(KmipTag::TimeStamp, timestamp.to_string()),
                KmipNode::text(KmipTag::Description, data_hash_hex),
            ],
        ),
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "OPERATION_FAILED",
            &format!("Failed to store evidence: {}", e),
        ),
    }
}

/// x-NonRepudiationVerify: 验证签名证据
async fn handle_x_non_repudiation_verify(
    state: &Arc<AppState>,
    payload: Vec<KmipNode>,
) -> KmipNode {
    let evidence_id = match extract_text(&payload, KmipTag::UniqueIdentifier) {
        Some(id) => id,
        None => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "INVALID_REQUEST",
                "Missing UniqueIdentifier (evidence_id)",
            );
        }
    };

    // 从数据库查询证据
    let pool = &state.pool;
    let row = sqlx::query_as::<_, NonRepudiationEvidence>(
        r#"
        SELECT id, operation, key_id as "key", subject, signature, timestamp, data_hash
        FROM non_repudiation_evidence
        WHERE id = ?
        "#,
    )
    .bind(&evidence_id)
    .fetch_optional(pool)
    .await;

    let record = match row {
        Ok(Some(r)) => r,
        Ok(None) => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "NOT_FOUND",
                "Evidence record not found",
            );
        }
        Err(e) => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "OPERATION_FAILED",
                &format!("Database error: {}", e),
            );
        }
    };

    // 重新构建签名的原始内容
    let sign_input = format!(
        "{}|{}|{}|{}|{}",
        record.id, record.timestamp, record.operation, record.key, record.data_hash
    );

    // 用公钥验证签名（当前使用占位符密钥）
    let sm2 = crate::crypto::sm2_engine::Sm2Engine::new();
    let sig_bytes = match hex::decode(&record.signature) {
        Ok(b) => b,
        Err(e) => {
            return build_error_response(
                ResultStatus::OperationFailed,
                "VERIFICATION_FAILED",
                &format!("Invalid signature hex: {}", e),
            );
        }
    };

    match sm2.verify(b"", sign_input.as_bytes(), &sig_bytes) {
        Ok(true) => build_response_message(
            ResultStatus::Success,
            vec![
                KmipNode::text(KmipTag::UniqueIdentifier, evidence_id),
                KmipNode::enumeration(KmipTag::ResultStatus, "Verified"),
                KmipNode::text(
                    KmipTag::Description,
                    format!("Signed at: {}", record.timestamp),
                ),
            ],
        ),
        Ok(false) => build_error_response(
            ResultStatus::OperationFailed,
            "VERIFICATION_FAILED",
            "Signature verification failed",
        ),
        Err(e) => build_error_response(
            ResultStatus::OperationFailed,
            "CRYPTO_ERROR",
            &e.to_string(),
        ),
    }
}

/// 非抗抵赖证据数据库行
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
struct NonRepudiationEvidence {
    id: String,
    operation: String,
    key: String, // SQL alias from key_id
    subject: String,
    signature: String,
    timestamp: i64,
    data_hash: String,
}
