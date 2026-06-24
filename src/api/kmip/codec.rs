use serde::de::{self, Deserialize, Deserializer, MapAccess, Visitor};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};
use std::fmt;

use super::types::*;

// ─────────
// 辅助：十六进制编码/解码
// ─────────

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("Hex string must have even length".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

// ─────────
// Serialize
// ─────────

impl Serialize for KmipNode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("tag", self.tag.name())?;
        map.serialize_entry("type", self.type_.name())?;
        match &self.value {
            KmipValue::Structure(children) => {
                map.serialize_entry("value", &KmipNodeList(children))?;
            }
            KmipValue::Integer(n) => {
                map.serialize_entry("value", n)?;
            }
            KmipValue::LongInteger(n) => {
                map.serialize_entry("value", n)?;
            }
            KmipValue::BigInteger(bytes) => {
                map.serialize_entry("value", &hex_encode(bytes))?;
            }
            KmipValue::Enumeration(s) => {
                map.serialize_entry("value", s)?;
            }
            KmipValue::Boolean(b) => {
                map.serialize_entry("value", b)?;
            }
            KmipValue::TextString(s) => {
                map.serialize_entry("value", s)?;
            }
            KmipValue::ByteString(bytes) => {
                map.serialize_entry("value", &hex_encode(bytes))?;
            }
            KmipValue::DateTime(ts) => {
                map.serialize_entry("value", ts)?;
            }
            KmipValue::Interval(ival) => {
                map.serialize_entry("value", ival)?;
            }
        }
        map.end()
    }
}

struct KmipNodeList<'a>(&'a [KmipNode]);

impl<'a> Serialize for KmipNodeList<'a> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for node in self.0 {
            seq.serialize_element(node)?;
        }
        seq.end()
    }
}

// ─────────
// Deserialize
// ─────────

impl<'de> Deserialize<'de> for KmipNode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(KmipNodeVisitor)
    }
}

struct KmipNodeVisitor;

impl<'de> Visitor<'de> for KmipNodeVisitor {
    type Value = KmipNode;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a KMIP TTLV node with tag, type, and value fields")
    }

    fn visit_map<V: MapAccess<'de>>(self, mut map: V) -> Result<KmipNode, V::Error> {
        let mut tag_str: Option<String> = None;
        let mut type_str: Option<String> = None;
        let mut value: Option<KmipValue> = None;

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "tag" => {
                    tag_str = Some(map.next_value()?);
                }
                "type" => {
                    type_str = Some(map.next_value()?);
                }
                "value" => {
                    let node_type = type_str.as_deref().unwrap_or("");
                    match node_type {
                        "Structure" => {
                            let nodes: Vec<KmipNode> = map.next_value()?;
                            value = Some(KmipValue::Structure(nodes));
                        }
                        "Integer" => {
                            let n: i32 = map.next_value()?;
                            value = Some(KmipValue::Integer(n));
                        }
                        "LongInteger" => {
                            let n: i64 = map.next_value()?;
                            value = Some(KmipValue::LongInteger(n));
                        }
                        "BigInteger" => {
                            let s: String = map.next_value()?;
                            let bytes = hex_decode(&s).map_err(de::Error::custom)?;
                            value = Some(KmipValue::BigInteger(bytes));
                        }
                        "Enumeration" => {
                            let s: String = map.next_value()?;
                            value = Some(KmipValue::Enumeration(s));
                        }
                        "Boolean" => {
                            let b: bool = map.next_value()?;
                            value = Some(KmipValue::Boolean(b));
                        }
                        "TextString" => {
                            let s: String = map.next_value()?;
                            value = Some(KmipValue::TextString(s));
                        }
                        "ByteString" => {
                            let s: String = map.next_value()?;
                            let bytes = hex_decode(&s).map_err(de::Error::custom)?;
                            value = Some(KmipValue::ByteString(bytes));
                        }
                        "DateTime" => {
                            let ts: i64 = map.next_value()?;
                            value = Some(KmipValue::DateTime(ts));
                        }
                        "Interval" => {
                            let ival: i32 = map.next_value()?;
                            value = Some(KmipValue::Interval(ival));
                        }
                        _ => {
                            let v: serde_json::Value = map.next_value()?;
                            let fallback = match v {
                                serde_json::Value::String(s) => KmipValue::TextString(s),
                                serde_json::Value::Number(n) => {
                                    if let Some(i) = n.as_i64() {
                                        KmipValue::LongInteger(i)
                                    } else {
                                        KmipValue::TextString(n.to_string())
                                    }
                                }
                                serde_json::Value::Bool(b) => KmipValue::Boolean(b),
                                _ => KmipValue::TextString(v.to_string()),
                            };
                            value = Some(fallback);
                        }
                    }
                }
                _ => {
                    let _: serde_json::Value = map.next_value()?;
                }
            }
        }

        let tag_str = tag_str.ok_or_else(|| de::Error::missing_field("tag"))?;
        let type_str = type_str.ok_or_else(|| de::Error::missing_field("type"))?;

        let tag = KmipTag::from_name(&tag_str)
            .ok_or_else(|| de::Error::custom(format!("unknown tag: {}", tag_str)))?;
        let type_ = KmipType::from_name(&type_str)
            .ok_or_else(|| de::Error::custom(format!("unknown type: {}", type_str)))?;
        let value = value.ok_or_else(|| de::Error::missing_field("value"))?;

        Ok(KmipNode { tag, type_, value })
    }
}

// ─────────
// RequestMessage / ResponseMessage 便捷构造
// ─────────

pub fn build_request_message(
    operation: Operation,
    payload: Vec<KmipNode>,
    auth: Option<KmipNode>,
) -> KmipNode {
    let mut header_children = vec![KmipNode::structure(
        KmipTag::ProtocolVersion,
        vec![
            KmipNode::integer(KmipTag::ProtocolVersionMajor, 2),
            KmipNode::integer(KmipTag::ProtocolVersionMinor, 1),
        ],
    )];

    if let Some(auth_node) = auth {
        header_children.push(auth_node);
    }

    header_children.push(KmipNode::integer(KmipTag::BatchCount, 1));

    let header = KmipNode::structure(KmipTag::RequestHeader, header_children);

    let batch_item = KmipNode::structure(
        KmipTag::BatchItem,
        vec![
            KmipNode::enumeration(KmipTag::Operation, operation.name()),
            KmipNode::structure(KmipTag::RequestPayload, payload),
        ],
    );

    KmipNode::structure(KmipTag::RequestMessage, vec![header, batch_item])
}

pub fn build_response_message(status: ResultStatus, payload: Vec<KmipNode>) -> KmipNode {
    let header = KmipNode::structure(
        KmipTag::ResponseHeader,
        vec![
            KmipNode::structure(
                KmipTag::ProtocolVersion,
                vec![
                    KmipNode::integer(KmipTag::ProtocolVersionMajor, 2),
                    KmipNode::integer(KmipTag::ProtocolVersionMinor, 1),
                ],
            ),
            KmipNode::enumeration(KmipTag::ResultStatus, status.name()),
            KmipNode::integer(KmipTag::BatchCount, 1),
        ],
    );

    let batch_item = KmipNode::structure(
        KmipTag::BatchItem,
        vec![
            KmipNode::enumeration(KmipTag::Operation, "Create"),
            KmipNode::structure(KmipTag::ResponsePayload, payload),
        ],
    );

    KmipNode::structure(KmipTag::ResponseMessage, vec![header, batch_item])
}

pub fn build_authentication_block(
    credential_type: CredentialType,
    username: &str,
    password: Option<&str>,
) -> KmipNode {
    let mut credential_value = vec![KmipNode::text(KmipTag::Username, username)];
    if let Some(pw) = password {
        credential_value.push(KmipNode::text(KmipTag::Password, pw));
    }

    let credential = KmipNode::structure(
        KmipTag::Credential,
        vec![
            KmipNode::enumeration(KmipTag::CredentialType, credential_type.name()),
            KmipNode::structure(KmipTag::CredentialValue, credential_value),
        ],
    );

    KmipNode::structure(KmipTag::Authentication, vec![credential])
}

// ─────────
// 高层操作提取函数
// ─────────

pub fn extract_operation(msg: &KmipNode) -> Option<Operation> {
    let name = extract_operation_name(msg)?;
    Operation::from_name(&name)
}

pub fn extract_operation_name(msg: &KmipNode) -> Option<String> {
    let batch = msg.child(KmipTag::BatchItem)?;
    let op_node = batch.child(KmipTag::Operation)?;
    op_node.enumeration_value().map(String::from)
}

pub fn extract_request_payload(msg: &KmipNode) -> Option<&[KmipNode]> {
    let batch = msg.child(KmipTag::BatchItem)?;
    let payload = batch.child(KmipTag::RequestPayload)?;
    match &payload.value {
        KmipValue::Structure(children) => Some(children),
        _ => None,
    }
}

pub fn extract_response_payload(msg: &KmipNode) -> Option<&[KmipNode]> {
    let batch = msg.child(KmipTag::BatchItem)?;
    let payload = batch.child(KmipTag::ResponsePayload)?;
    match &payload.value {
        KmipValue::Structure(children) => Some(children),
        _ => None,
    }
}

pub fn extract_result_status(msg: &KmipNode) -> Option<ResultStatus> {
    let header = msg.child(KmipTag::ResponseHeader)?;
    let status = header.child(KmipTag::ResultStatus)?;
    let name = status.enumeration_value()?;
    ResultStatus::from_name(name)
}

pub fn extract_authentication(msg: &KmipNode) -> Option<&[KmipNode]> {
    let header = msg.child(KmipTag::RequestHeader)?;
    let auth = header.child(KmipTag::Authentication)?;
    match &auth.value {
        KmipValue::Structure(children) => Some(children.as_slice()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_create_request() {
        let node = build_request_message(
            Operation::Create,
            vec![
                KmipNode::enumeration(KmipTag::ObjectType, ObjectType::SymmetricKey.name()),
                KmipNode::structure(
                    KmipTag::Attributes,
                    vec![
                        KmipNode::enumeration(
                            KmipTag::CryptographicAlgorithm,
                            CryptoAlgorithm::AES.name(),
                        ),
                        KmipNode::integer(KmipTag::CryptographicLength, 256),
                    ],
                ),
            ],
            None,
        );

        let json = serde_json::to_string_pretty(&node).unwrap();
        assert!(json.contains("RequestMessage"));
        assert!(json.contains("Create"));
        assert!(json.contains("SymmetricKey"));
        assert!(json.contains("AES"));
        assert!(json.contains("256"));
    }

    #[test]
    fn test_roundtrip_create_request() {
        let original = build_request_message(
            Operation::Create,
            vec![
                KmipNode::enumeration(KmipTag::ObjectType, ObjectType::SymmetricKey.name()),
                KmipNode::structure(
                    KmipTag::Attributes,
                    vec![
                        KmipNode::enumeration(
                            KmipTag::CryptographicAlgorithm,
                            CryptoAlgorithm::AES.name(),
                        ),
                        KmipNode::integer(KmipTag::CryptographicLength, 256),
                        KmipNode::integer(
                            KmipTag::CryptographicUsageMask,
                            usage_mask::ENCRYPT | usage_mask::DECRYPT,
                        ),
                    ],
                ),
            ],
            None,
        );

        let json = serde_json::to_string(&original).unwrap();
        let decoded: KmipNode = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_roundtrip_with_authentication() {
        let auth = build_authentication_block(
            CredentialType::UsernameAndPassword,
            "admin",
            Some("secret123"),
        );

        let original = build_request_message(
            Operation::Get,
            vec![KmipNode::text(KmipTag::UniqueIdentifier, "test-key-id")],
            Some(auth),
        );

        let json = serde_json::to_string_pretty(&original).unwrap();
        let decoded: KmipNode = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
        assert!(json.contains("UsernameAndPassword"));
        assert!(json.contains("admin"));
    }

    #[test]
    fn test_byte_string_roundtrip() {
        let data = vec![0x00, 0x01, 0xFF, 0xAB, 0xCD];
        let node = KmipNode::new(KmipTag::Data, KmipValue::ByteString(data.clone()));

        let json = serde_json::to_string(&node).unwrap();
        let decoded: KmipNode = serde_json::from_str(&json).unwrap();
        assert_eq!(node, decoded);
    }

    #[test]
    fn test_extract_operation() {
        let msg = build_request_message(
            Operation::Encrypt,
            vec![
                KmipNode::text(KmipTag::UniqueIdentifier, "key-1"),
                KmipNode::new(KmipTag::Data, KmipValue::ByteString(vec![0x01, 0x02])),
            ],
            None,
        );

        assert_eq!(extract_operation(&msg), Some(Operation::Encrypt));
    }

    #[test]
    fn test_extract_request_payload() {
        let msg = build_request_message(
            Operation::Create,
            vec![KmipNode::enumeration(
                KmipTag::ObjectType,
                ObjectType::SymmetricKey.name(),
            )],
            None,
        );

        let payload = extract_request_payload(&msg).unwrap();
        assert_eq!(payload.len(), 1);
        assert_eq!(payload[0].tag, KmipTag::ObjectType);
    }

    #[test]
    fn test_result_status_roundtrip() {
        for status in &[ResultStatus::Success, ResultStatus::OperationFailed] {
            assert_eq!(ResultStatus::from_name(status.name()), Some(*status),);
        }
    }

    #[test]
    fn test_json_output_format() {
        let node = KmipNode::text(KmipTag::Description, "test key");
        let json = serde_json::to_string(&node).unwrap();
        assert_eq!(
            json,
            r#"{"tag":"Description","type":"TextString","value":"test key"}"#
        );
    }

    #[test]
    fn test_empty_structure() {
        let node = KmipNode::structure(KmipTag::Attributes, vec![]);
        let json = serde_json::to_string(&node).unwrap();
        let decoded: KmipNode = serde_json::from_str(&json).unwrap();
        assert_eq!(node, decoded);
    }

    #[test]
    fn test_authentication_extraction() {
        let auth =
            build_authentication_block(CredentialType::UsernameAndPassword, "user1", Some("pass1"));
        let msg = build_request_message(Operation::Create, vec![], Some(auth));

        let extracted = extract_authentication(&msg).unwrap();
        assert_eq!(extracted.len(), 1);
        let cred_ref = &extracted[0];
        assert_eq!(cred_ref.tag, KmipTag::Credential);
        let ct = cred_ref.child(KmipTag::CredentialType).unwrap();
        assert_eq!(ct.enumeration_value(), Some("UsernameAndPassword"));
        let cv = cred_ref.child(KmipTag::CredentialValue).unwrap();
        let un = cv.child(KmipTag::Username).unwrap();
        assert_eq!(un.text_value(), Some("user1"));
    }
}
