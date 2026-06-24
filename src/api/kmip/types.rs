// ────────
// 数据类型（对应 TTLV Type 字段）
// ─────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmipType {
    Structure,
    Integer,
    LongInteger,
    BigInteger,
    Enumeration,
    Boolean,
    TextString,
    ByteString,
    DateTime,
    Interval,
}

impl KmipType {
    pub fn name(&self) -> &'static str {
        match self {
            KmipType::Structure => "Structure",
            KmipType::Integer => "Integer",
            KmipType::LongInteger => "LongInteger",
            KmipType::BigInteger => "BigInteger",
            KmipType::Enumeration => "Enumeration",
            KmipType::Boolean => "Boolean",
            KmipType::TextString => "TextString",
            KmipType::ByteString => "ByteString",
            KmipType::DateTime => "DateTime",
            KmipType::Interval => "Interval",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "Structure" => Some(KmipType::Structure),
            "Integer" => Some(KmipType::Integer),
            "LongInteger" => Some(KmipType::LongInteger),
            "BigInteger" => Some(KmipType::BigInteger),
            "Enumeration" => Some(KmipType::Enumeration),
            "Boolean" => Some(KmipType::Boolean),
            "TextString" => Some(KmipType::TextString),
            "ByteString" => Some(KmipType::ByteString),
            "DateTime" => Some(KmipType::DateTime),
            "Interval" => Some(KmipType::Interval),
            _ => None,
        }
    }
}

// ─────────
// 值
// ─────────

#[derive(Debug, Clone, PartialEq)]
pub enum KmipValue {
    Structure(Vec<KmipNode>),
    Integer(i32),
    LongInteger(i64),
    BigInteger(Vec<u8>),
    Enumeration(String),
    Boolean(bool),
    TextString(String),
    ByteString(Vec<u8>),
    DateTime(i64),
    Interval(i32),
}

impl From<Vec<KmipNode>> for KmipValue {
    fn from(v: Vec<KmipNode>) -> Self {
        KmipValue::Structure(v)
    }
}
impl From<i32> for KmipValue {
    fn from(v: i32) -> Self {
        KmipValue::Integer(v)
    }
}
impl From<i64> for KmipValue {
    fn from(v: i64) -> Self {
        KmipValue::LongInteger(v)
    }
}
impl From<&str> for KmipValue {
    fn from(v: &str) -> Self {
        KmipValue::TextString(v.to_string())
    }
}
impl From<String> for KmipValue {
    fn from(v: String) -> Self {
        KmipValue::TextString(v)
    }
}
impl From<bool> for KmipValue {
    fn from(v: bool) -> Self {
        KmipValue::Boolean(v)
    }
}
impl From<Vec<u8>> for KmipValue {
    fn from(v: Vec<u8>) -> Self {
        KmipValue::ByteString(v)
    }
}

// ─────────
// 通用节点
// ─────────

#[derive(Debug, Clone, PartialEq)]
pub struct KmipNode {
    pub tag: KmipTag,
    pub type_: KmipType,
    pub value: KmipValue,
}

impl KmipNode {
    pub fn new(tag: KmipTag, value: impl Into<KmipValue>) -> Self {
        let value = value.into();
        let type_ = match &value {
            KmipValue::Structure(_) => KmipType::Structure,
            KmipValue::Integer(_) => KmipType::Integer,
            KmipValue::LongInteger(_) => KmipType::LongInteger,
            KmipValue::BigInteger(_) => KmipType::BigInteger,
            KmipValue::Enumeration(_) => KmipType::Enumeration,
            KmipValue::Boolean(_) => KmipType::Boolean,
            KmipValue::TextString(_) => KmipType::TextString,
            KmipValue::ByteString(_) => KmipType::ByteString,
            KmipValue::DateTime(_) => KmipType::DateTime,
            KmipValue::Interval(_) => KmipType::Interval,
        };
        KmipNode { tag, type_, value }
    }

    pub fn structure(tag: KmipTag, children: Vec<KmipNode>) -> Self {
        Self::new(tag, KmipValue::Structure(children))
    }

    pub fn enumeration(tag: KmipTag, value: impl Into<String>) -> Self {
        Self::new(tag, KmipValue::Enumeration(value.into()))
    }

    pub fn text(tag: KmipTag, value: impl Into<String>) -> Self {
        Self::new(tag, KmipValue::TextString(value.into()))
    }

    pub fn integer(tag: KmipTag, value: i32) -> Self {
        Self::new(tag, KmipValue::Integer(value))
    }

    pub fn bool_(tag: KmipTag, value: bool) -> Self {
        Self::new(tag, KmipValue::Boolean(value))
    }

    pub fn child(&self, tag: KmipTag) -> Option<&KmipNode> {
        match &self.value {
            KmipValue::Structure(children) => children.iter().find(|c| c.tag == tag),
            _ => None,
        }
    }

    pub fn text_value(&self) -> Option<&str> {
        match &self.value {
            KmipValue::TextString(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn integer_value(&self) -> Option<i32> {
        match &self.value {
            KmipValue::Integer(n) => Some(*n),
            _ => None,
        }
    }

    pub fn enumeration_value(&self) -> Option<&str> {
        match &self.value {
            KmipValue::Enumeration(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn bool_value(&self) -> Option<bool> {
        match &self.value {
            KmipValue::Boolean(b) => Some(*b),
            _ => None,
        }
    }
}

// ─────────
// KMIP Tag 枚举（KMIP 2.1 规范）
// ─────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KmipTag {
    // 消息结构
    RequestMessage,
    ResponseMessage,
    RequestHeader,
    ResponseHeader,
    BatchItem,
    BatchCount,
    BatchOrderOption,
    BatchErrorContinuationOption,
    Operation,
    ObjectType,
    UniqueIdentifier,
    TimeStamp,
    MaximumResponseSize,
    ClientCorrelationValue,
    ServerCorrelationValue,
    AsynchronousIndicator,
    AsynchronousCorrelationValue,
    ResultStatus,
    ResultMessage,
    ResultReason,
    AttestationType,
    AttestationCapableIndicator,
    AttestationStatement,
    ProtocolVersion,
    ProtocolVersionMajor,
    ProtocolVersionMinor,

    // 认证
    Authentication,
    Credential,
    CredentialType,
    CredentialValue,
    Username,
    Password,

    // 密钥对象
    KeyBlock,
    KeyValue,
    KeyFormatType,
    KeyCompressionType,
    KeyMaterial,
    KeyWrappingData,
    WrappingMethod,
    EncryptionKeyInformation,
    MACSignatureKeyInformation,
    KeyWrappingSpecification,
    AttributeName,
    AttributeValue,
    Attributes,
    CryptographicAlgorithm,
    CryptographicLength,
    CryptographicUsageMask,
    CryptographicParameters,
    KeyRoleType,
    KeyVersion,
    KeyState,

    // 对象类型 & 属性
    SymmetricKey,
    PrivateKey,
    PublicKey,
    Certificate,
    SecretData,
    OpaqueObject,
    SplitKey,
    Template,
    State,
    Name,
    NameType,
    ObjectGroup,
    ApplicationSpecificInformation,
    ContactInformation,
    Description,
    Extractable,
    NeverExtractable,
    Fresh,
    Link,
    LinkedObjectIdentifier,
    LinkType,
    LastChangeDate,
    InitialDate,
    ActivationDate,
    DeactivationDate,
    CompromiseDate,
    CompromiseOccurrenceDate,
    DestroyDate,
    CertificateType,
    CertificateIdentifier,
    CertificateIssuer,
    CertificateSubject,
    DigitalSignatureAlgorithm,
    CertificateRequest,
    DigitalBase,
    AsymmetricKeyType,
    CertificateValue,
    X509CertificateIdentifier,
    X509CertificateIssuer,
    X509CertificateSubject,

    // 操作相关
    RequestPayload,
    ResponsePayload,
    Data,
    IVCounterNonce,
    CorrelationValue,
    InitIndicator,
    FinalIndicator,
    AuthenticatedEncryptionAdditionalData,
    Salt,
    MaskGenerator,
    MaskGeneratorHmac,
    MaskGeneratorIterationCount,
    PaddingMethod,
    HmacAlgorithm,
    IterationCount,
    DerivationMethod,
    DerivationParameters,
    SaltLength,
    XLength,
    YLength,
    InputData,
    MaximumItems,
    Passphrase,
    UsageLimits,
    UsageLimitsTotal,
    UsageLimitsCount,
    UsageLimitsState,
    ProtectionStorageMasks,
    StorageStatusMask,
    ObjectGroupMember,
    WrappedData,
    DataLength,
    KeyLength,
    ObjectCount,
    ServerHashedPassword,
    ServerRegistrationInformation,
    ServerInformation,
    ServerNegotiatedValue,
    ServerURI,
    ServerPort,
    ServerAddress,
    NetworkContactName,
    NetworkIdentifier,

    // 供应商扩展
    VendorAttribute,
    VendorAttributePrefix,
    VendorAttributeNames,
    ExtensionInformation,
    ExtensionTag,
    ExtensionType,
    ExtensionName,
    Extensions,

    // 自定义扩展（x- prefix）
    CustomAttribute,
}

impl KmipTag {
    pub fn name(&self) -> &'static str {
        match self {
            KmipTag::RequestMessage => "RequestMessage",
            KmipTag::ResponseMessage => "ResponseMessage",
            KmipTag::RequestHeader => "RequestHeader",
            KmipTag::ResponseHeader => "ResponseHeader",
            KmipTag::BatchItem => "BatchItem",
            KmipTag::BatchCount => "BatchCount",
            KmipTag::BatchOrderOption => "BatchOrderOption",
            KmipTag::BatchErrorContinuationOption => "BatchErrorContinuationOption",
            KmipTag::Operation => "Operation",
            KmipTag::ObjectType => "ObjectType",
            KmipTag::UniqueIdentifier => "UniqueIdentifier",
            KmipTag::TimeStamp => "TimeStamp",
            KmipTag::MaximumResponseSize => "MaximumResponseSize",
            KmipTag::ClientCorrelationValue => "ClientCorrelationValue",
            KmipTag::ServerCorrelationValue => "ServerCorrelationValue",
            KmipTag::AsynchronousIndicator => "AsynchronousIndicator",
            KmipTag::AsynchronousCorrelationValue => "AsynchronousCorrelationValue",
            KmipTag::ResultStatus => "ResultStatus",
            KmipTag::ResultMessage => "ResultMessage",
            KmipTag::ResultReason => "ResultReason",
            KmipTag::AttestationType => "AttestationType",
            KmipTag::AttestationCapableIndicator => "AttestationCapableIndicator",
            KmipTag::AttestationStatement => "AttestationStatement",
            KmipTag::ProtocolVersion => "ProtocolVersion",
            KmipTag::ProtocolVersionMajor => "ProtocolVersionMajor",
            KmipTag::ProtocolVersionMinor => "ProtocolVersionMinor",
            KmipTag::Authentication => "Authentication",
            KmipTag::Credential => "Credential",
            KmipTag::CredentialType => "CredentialType",
            KmipTag::CredentialValue => "CredentialValue",
            KmipTag::Username => "Username",
            KmipTag::Password => "Password",
            KmipTag::KeyBlock => "KeyBlock",
            KmipTag::KeyValue => "KeyValue",
            KmipTag::KeyFormatType => "KeyFormatType",
            KmipTag::KeyCompressionType => "KeyCompressionType",
            KmipTag::KeyMaterial => "KeyMaterial",
            KmipTag::KeyWrappingData => "KeyWrappingData",
            KmipTag::WrappingMethod => "WrappingMethod",
            KmipTag::EncryptionKeyInformation => "EncryptionKeyInformation",
            KmipTag::MACSignatureKeyInformation => "MACSignatureKeyInformation",
            KmipTag::KeyWrappingSpecification => "KeyWrappingSpecification",
            KmipTag::AttributeName => "AttributeName",
            KmipTag::AttributeValue => "AttributeValue",
            KmipTag::Attributes => "Attributes",
            KmipTag::CryptographicAlgorithm => "CryptographicAlgorithm",
            KmipTag::CryptographicLength => "CryptographicLength",
            KmipTag::CryptographicUsageMask => "CryptographicUsageMask",
            KmipTag::CryptographicParameters => "CryptographicParameters",
            KmipTag::KeyRoleType => "KeyRoleType",
            KmipTag::KeyVersion => "KeyVersion",
            KmipTag::KeyState => "KeyState",
            KmipTag::SymmetricKey => "SymmetricKey",
            KmipTag::PrivateKey => "PrivateKey",
            KmipTag::PublicKey => "PublicKey",
            KmipTag::Certificate => "Certificate",
            KmipTag::SecretData => "SecretData",
            KmipTag::OpaqueObject => "OpaqueObject",
            KmipTag::SplitKey => "SplitKey",
            KmipTag::Template => "Template",
            KmipTag::State => "State",
            KmipTag::Name => "Name",
            KmipTag::NameType => "NameType",
            KmipTag::ObjectGroup => "ObjectGroup",
            KmipTag::ApplicationSpecificInformation => "ApplicationSpecificInformation",
            KmipTag::ContactInformation => "ContactInformation",
            KmipTag::Description => "Description",
            KmipTag::Extractable => "Extractable",
            KmipTag::NeverExtractable => "NeverExtractable",
            KmipTag::Fresh => "Fresh",
            KmipTag::Link => "Link",
            KmipTag::LinkedObjectIdentifier => "LinkedObjectIdentifier",
            KmipTag::LinkType => "LinkType",
            KmipTag::LastChangeDate => "LastChangeDate",
            KmipTag::InitialDate => "InitialDate",
            KmipTag::ActivationDate => "ActivationDate",
            KmipTag::DeactivationDate => "DeactivationDate",
            KmipTag::CompromiseDate => "CompromiseDate",
            KmipTag::CompromiseOccurrenceDate => "CompromiseOccurrenceDate",
            KmipTag::DestroyDate => "DestroyDate",
            KmipTag::CertificateType => "CertificateType",
            KmipTag::CertificateIdentifier => "CertificateIdentifier",
            KmipTag::CertificateIssuer => "CertificateIssuer",
            KmipTag::CertificateSubject => "CertificateSubject",
            KmipTag::DigitalSignatureAlgorithm => "DigitalSignatureAlgorithm",
            KmipTag::CertificateRequest => "CertificateRequest",
            KmipTag::DigitalBase => "DigitalBase",
            KmipTag::AsymmetricKeyType => "AsymmetricKeyType",
            KmipTag::CertificateValue => "CertificateValue",
            KmipTag::X509CertificateIdentifier => "X509CertificateIdentifier",
            KmipTag::X509CertificateIssuer => "X509CertificateIssuer",
            KmipTag::X509CertificateSubject => "X509CertificateSubject",
            KmipTag::RequestPayload => "RequestPayload",
            KmipTag::ResponsePayload => "ResponsePayload",
            KmipTag::Data => "Data",
            KmipTag::IVCounterNonce => "IVCounterNonce",
            KmipTag::CorrelationValue => "CorrelationValue",
            KmipTag::InitIndicator => "InitIndicator",
            KmipTag::FinalIndicator => "FinalIndicator",
            KmipTag::AuthenticatedEncryptionAdditionalData => {
                "AuthenticatedEncryptionAdditionalData"
            }
            KmipTag::Salt => "Salt",
            KmipTag::MaskGenerator => "MaskGenerator",
            KmipTag::MaskGeneratorHmac => "MaskGeneratorHmac",
            KmipTag::MaskGeneratorIterationCount => "MaskGeneratorIterationCount",
            KmipTag::PaddingMethod => "PaddingMethod",
            KmipTag::HmacAlgorithm => "HmacAlgorithm",
            KmipTag::IterationCount => "IterationCount",
            KmipTag::DerivationMethod => "DerivationMethod",
            KmipTag::DerivationParameters => "DerivationParameters",
            KmipTag::SaltLength => "SaltLength",
            KmipTag::XLength => "XLength",
            KmipTag::YLength => "YLength",
            KmipTag::InputData => "InputData",
            KmipTag::MaximumItems => "MaximumItems",
            KmipTag::Passphrase => "Passphrase",
            KmipTag::UsageLimits => "UsageLimits",
            KmipTag::UsageLimitsTotal => "UsageLimitsTotal",
            KmipTag::UsageLimitsCount => "UsageLimitsCount",
            KmipTag::UsageLimitsState => "UsageLimitsState",
            KmipTag::ProtectionStorageMasks => "ProtectionStorageMasks",
            KmipTag::StorageStatusMask => "StorageStatusMask",
            KmipTag::ObjectGroupMember => "ObjectGroupMember",
            KmipTag::WrappedData => "WrappedData",
            KmipTag::DataLength => "DataLength",
            KmipTag::KeyLength => "KeyLength",
            KmipTag::ObjectCount => "ObjectCount",
            KmipTag::ServerHashedPassword => "ServerHashedPassword",
            KmipTag::ServerRegistrationInformation => "ServerRegistrationInformation",
            KmipTag::ServerInformation => "ServerInformation",
            KmipTag::ServerNegotiatedValue => "ServerNegotiatedValue",
            KmipTag::ServerURI => "ServerURI",
            KmipTag::ServerPort => "ServerPort",
            KmipTag::ServerAddress => "ServerAddress",
            KmipTag::NetworkContactName => "NetworkContactName",
            KmipTag::NetworkIdentifier => "NetworkIdentifier",
            KmipTag::VendorAttribute => "VendorAttribute",
            KmipTag::VendorAttributePrefix => "VendorAttributePrefix",
            KmipTag::VendorAttributeNames => "VendorAttributeNames",
            KmipTag::ExtensionInformation => "ExtensionInformation",
            KmipTag::ExtensionTag => "ExtensionTag",
            KmipTag::ExtensionType => "ExtensionType",
            KmipTag::ExtensionName => "ExtensionName",
            KmipTag::Extensions => "Extensions",
            KmipTag::CustomAttribute => "CustomAttribute",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "RequestMessage" => Some(KmipTag::RequestMessage),
            "ResponseMessage" => Some(KmipTag::ResponseMessage),
            "RequestHeader" => Some(KmipTag::RequestHeader),
            "ResponseHeader" => Some(KmipTag::ResponseHeader),
            "BatchItem" => Some(KmipTag::BatchItem),
            "BatchCount" => Some(KmipTag::BatchCount),
            "BatchOrderOption" => Some(KmipTag::BatchOrderOption),
            "BatchErrorContinuationOption" => Some(KmipTag::BatchErrorContinuationOption),
            "Operation" => Some(KmipTag::Operation),
            "ObjectType" => Some(KmipTag::ObjectType),
            "UniqueIdentifier" => Some(KmipTag::UniqueIdentifier),
            "TimeStamp" => Some(KmipTag::TimeStamp),
            "MaximumResponseSize" => Some(KmipTag::MaximumResponseSize),
            "ClientCorrelationValue" => Some(KmipTag::ClientCorrelationValue),
            "ServerCorrelationValue" => Some(KmipTag::ServerCorrelationValue),
            "AsynchronousIndicator" => Some(KmipTag::AsynchronousIndicator),
            "AsynchronousCorrelationValue" => Some(KmipTag::AsynchronousCorrelationValue),
            "ResultStatus" => Some(KmipTag::ResultStatus),
            "ResultMessage" => Some(KmipTag::ResultMessage),
            "ResultReason" => Some(KmipTag::ResultReason),
            "AttestationType" => Some(KmipTag::AttestationType),
            "AttestationCapableIndicator" => Some(KmipTag::AttestationCapableIndicator),
            "AttestationStatement" => Some(KmipTag::AttestationStatement),
            "ProtocolVersion" => Some(KmipTag::ProtocolVersion),
            "ProtocolVersionMajor" => Some(KmipTag::ProtocolVersionMajor),
            "ProtocolVersionMinor" => Some(KmipTag::ProtocolVersionMinor),
            "Authentication" => Some(KmipTag::Authentication),
            "Credential" => Some(KmipTag::Credential),
            "CredentialType" => Some(KmipTag::CredentialType),
            "CredentialValue" => Some(KmipTag::CredentialValue),
            "Username" => Some(KmipTag::Username),
            "Password" => Some(KmipTag::Password),
            "KeyBlock" => Some(KmipTag::KeyBlock),
            "KeyValue" => Some(KmipTag::KeyValue),
            "KeyFormatType" => Some(KmipTag::KeyFormatType),
            "KeyCompressionType" => Some(KmipTag::KeyCompressionType),
            "KeyMaterial" => Some(KmipTag::KeyMaterial),
            "KeyWrappingData" => Some(KmipTag::KeyWrappingData),
            "WrappingMethod" => Some(KmipTag::WrappingMethod),
            "EncryptionKeyInformation" => Some(KmipTag::EncryptionKeyInformation),
            "MACSignatureKeyInformation" => Some(KmipTag::MACSignatureKeyInformation),
            "KeyWrappingSpecification" => Some(KmipTag::KeyWrappingSpecification),
            "AttributeName" => Some(KmipTag::AttributeName),
            "AttributeValue" => Some(KmipTag::AttributeValue),
            "Attributes" => Some(KmipTag::Attributes),
            "CryptographicAlgorithm" => Some(KmipTag::CryptographicAlgorithm),
            "CryptographicLength" => Some(KmipTag::CryptographicLength),
            "CryptographicUsageMask" => Some(KmipTag::CryptographicUsageMask),
            "CryptographicParameters" => Some(KmipTag::CryptographicParameters),
            "KeyRoleType" => Some(KmipTag::KeyRoleType),
            "KeyVersion" => Some(KmipTag::KeyVersion),
            "KeyState" => Some(KmipTag::KeyState),
            "SymmetricKey" => Some(KmipTag::SymmetricKey),
            "PrivateKey" => Some(KmipTag::PrivateKey),
            "PublicKey" => Some(KmipTag::PublicKey),
            "Certificate" => Some(KmipTag::Certificate),
            "SecretData" => Some(KmipTag::SecretData),
            "OpaqueObject" => Some(KmipTag::OpaqueObject),
            "SplitKey" => Some(KmipTag::SplitKey),
            "Template" => Some(KmipTag::Template),
            "State" => Some(KmipTag::State),
            "Name" => Some(KmipTag::Name),
            "NameType" => Some(KmipTag::NameType),
            "ObjectGroup" => Some(KmipTag::ObjectGroup),
            "ApplicationSpecificInformation" => Some(KmipTag::ApplicationSpecificInformation),
            "ContactInformation" => Some(KmipTag::ContactInformation),
            "Description" => Some(KmipTag::Description),
            "Extractable" => Some(KmipTag::Extractable),
            "NeverExtractable" => Some(KmipTag::NeverExtractable),
            "Fresh" => Some(KmipTag::Fresh),
            "Link" => Some(KmipTag::Link),
            "LinkedObjectIdentifier" => Some(KmipTag::LinkedObjectIdentifier),
            "LinkType" => Some(KmipTag::LinkType),
            "LastChangeDate" => Some(KmipTag::LastChangeDate),
            "InitialDate" => Some(KmipTag::InitialDate),
            "ActivationDate" => Some(KmipTag::ActivationDate),
            "DeactivationDate" => Some(KmipTag::DeactivationDate),
            "CompromiseDate" => Some(KmipTag::CompromiseDate),
            "CompromiseOccurrenceDate" => Some(KmipTag::CompromiseOccurrenceDate),
            "DestroyDate" => Some(KmipTag::DestroyDate),
            "CertificateType" => Some(KmipTag::CertificateType),
            "CertificateIdentifier" => Some(KmipTag::CertificateIdentifier),
            "CertificateIssuer" => Some(KmipTag::CertificateIssuer),
            "CertificateSubject" => Some(KmipTag::CertificateSubject),
            "DigitalSignatureAlgorithm" => Some(KmipTag::DigitalSignatureAlgorithm),
            "CertificateRequest" => Some(KmipTag::CertificateRequest),
            "DigitalBase" => Some(KmipTag::DigitalBase),
            "AsymmetricKeyType" => Some(KmipTag::AsymmetricKeyType),
            "CertificateValue" => Some(KmipTag::CertificateValue),
            "X509CertificateIdentifier" => Some(KmipTag::X509CertificateIdentifier),
            "X509CertificateIssuer" => Some(KmipTag::X509CertificateIssuer),
            "X509CertificateSubject" => Some(KmipTag::X509CertificateSubject),
            "RequestPayload" => Some(KmipTag::RequestPayload),
            "ResponsePayload" => Some(KmipTag::ResponsePayload),
            "Data" => Some(KmipTag::Data),
            "IVCounterNonce" => Some(KmipTag::IVCounterNonce),
            "CorrelationValue" => Some(KmipTag::CorrelationValue),
            "InitIndicator" => Some(KmipTag::InitIndicator),
            "FinalIndicator" => Some(KmipTag::FinalIndicator),
            "AuthenticatedEncryptionAdditionalData" => {
                Some(KmipTag::AuthenticatedEncryptionAdditionalData)
            }
            "Salt" => Some(KmipTag::Salt),
            "MaskGenerator" => Some(KmipTag::MaskGenerator),
            "MaskGeneratorHmac" => Some(KmipTag::MaskGeneratorHmac),
            "MaskGeneratorIterationCount" => Some(KmipTag::MaskGeneratorIterationCount),
            "PaddingMethod" => Some(KmipTag::PaddingMethod),
            "HmacAlgorithm" => Some(KmipTag::HmacAlgorithm),
            "IterationCount" => Some(KmipTag::IterationCount),
            "DerivationMethod" => Some(KmipTag::DerivationMethod),
            "DerivationParameters" => Some(KmipTag::DerivationParameters),
            "SaltLength" => Some(KmipTag::SaltLength),
            "XLength" => Some(KmipTag::XLength),
            "YLength" => Some(KmipTag::YLength),
            "InputData" => Some(KmipTag::InputData),
            "MaximumItems" => Some(KmipTag::MaximumItems),
            "Passphrase" => Some(KmipTag::Passphrase),
            "UsageLimits" => Some(KmipTag::UsageLimits),
            "UsageLimitsTotal" => Some(KmipTag::UsageLimitsTotal),
            "UsageLimitsCount" => Some(KmipTag::UsageLimitsCount),
            "UsageLimitsState" => Some(KmipTag::UsageLimitsState),
            "ProtectionStorageMasks" => Some(KmipTag::ProtectionStorageMasks),
            "StorageStatusMask" => Some(KmipTag::StorageStatusMask),
            "ObjectGroupMember" => Some(KmipTag::ObjectGroupMember),
            "WrappedData" => Some(KmipTag::WrappedData),
            "DataLength" => Some(KmipTag::DataLength),
            "KeyLength" => Some(KmipTag::KeyLength),
            "ObjectCount" => Some(KmipTag::ObjectCount),
            "ServerHashedPassword" => Some(KmipTag::ServerHashedPassword),
            "ServerRegistrationInformation" => Some(KmipTag::ServerRegistrationInformation),
            "ServerInformation" => Some(KmipTag::ServerInformation),
            "ServerNegotiatedValue" => Some(KmipTag::ServerNegotiatedValue),
            "ServerURI" => Some(KmipTag::ServerURI),
            "ServerPort" => Some(KmipTag::ServerPort),
            "ServerAddress" => Some(KmipTag::ServerAddress),
            "NetworkContactName" => Some(KmipTag::NetworkContactName),
            "NetworkIdentifier" => Some(KmipTag::NetworkIdentifier),
            "VendorAttribute" => Some(KmipTag::VendorAttribute),
            "VendorAttributePrefix" => Some(KmipTag::VendorAttributePrefix),
            "VendorAttributeNames" => Some(KmipTag::VendorAttributeNames),
            "ExtensionInformation" => Some(KmipTag::ExtensionInformation),
            "ExtensionTag" => Some(KmipTag::ExtensionTag),
            "ExtensionType" => Some(KmipTag::ExtensionType),
            "ExtensionName" => Some(KmipTag::ExtensionName),
            "Extensions" => Some(KmipTag::Extensions),
            "CustomAttribute" => Some(KmipTag::CustomAttribute),
            _ => None,
        }
    }
}

// ─────────
// Operation 枚举（KMIP 2.1）
// ─────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Create,
    CreateKeyPair,
    Register,
    ReKey,
    ReKeyKeyPair,
    DeriveKey,
    Certify,
    ReCertify,
    Locate,
    Check,
    Get,
    GetAttributes,
    GetAttributeList,
    AddAttribute,
    ModifyAttribute,
    DeleteAttribute,
    ObtainLease,
    Activate,
    Revoke,
    Destroy,
    Archive,
    Recover,
    Validate,
    Query,
    Cancel,
    Poll,
    Notify,
    Put,
    Encrypt,
    Decrypt,
    Sign,
    SignatureVerify,
    MAC,
    MACVerify,
    Hash,
    CreateSplitKey,
    JoinSplitKey,
    Import,
    Export,
    Log,
    Login,
    Logout,
    CredentialManagement,
    CertificateRequestOperation,
    DiscoverVersions,
}

impl Operation {
    pub fn name(&self) -> &'static str {
        match self {
            Operation::Create => "Create",
            Operation::CreateKeyPair => "CreateKeyPair",
            Operation::Register => "Register",
            Operation::ReKey => "ReKey",
            Operation::ReKeyKeyPair => "ReKeyKeyPair",
            Operation::DeriveKey => "DeriveKey",
            Operation::Certify => "Certify",
            Operation::ReCertify => "ReCertify",
            Operation::Locate => "Locate",
            Operation::Check => "Check",
            Operation::Get => "Get",
            Operation::GetAttributes => "GetAttributes",
            Operation::GetAttributeList => "GetAttributeList",
            Operation::AddAttribute => "AddAttribute",
            Operation::ModifyAttribute => "ModifyAttribute",
            Operation::DeleteAttribute => "DeleteAttribute",
            Operation::ObtainLease => "ObtainLease",
            Operation::Activate => "Activate",
            Operation::Revoke => "Revoke",
            Operation::Destroy => "Destroy",
            Operation::Archive => "Archive",
            Operation::Recover => "Recover",
            Operation::Validate => "Validate",
            Operation::Query => "Query",
            Operation::Cancel => "Cancel",
            Operation::Poll => "Poll",
            Operation::Notify => "Notify",
            Operation::Put => "Put",
            Operation::Encrypt => "Encrypt",
            Operation::Decrypt => "Decrypt",
            Operation::Sign => "Sign",
            Operation::SignatureVerify => "SignatureVerify",
            Operation::MAC => "MAC",
            Operation::MACVerify => "MACVerify",
            Operation::Hash => "Hash",
            Operation::CreateSplitKey => "CreateSplitKey",
            Operation::JoinSplitKey => "JoinSplitKey",
            Operation::Import => "Import",
            Operation::Export => "Export",
            Operation::Log => "Log",
            Operation::Login => "Login",
            Operation::Logout => "Logout",
            Operation::CredentialManagement => "CredentialManagement",
            Operation::CertificateRequestOperation => "CertificateRequest",
            Operation::DiscoverVersions => "DiscoverVersions",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "Create" => Some(Operation::Create),
            "CreateKeyPair" => Some(Operation::CreateKeyPair),
            "Register" => Some(Operation::Register),
            "ReKey" => Some(Operation::ReKey),
            "ReKeyKeyPair" => Some(Operation::ReKeyKeyPair),
            "DeriveKey" => Some(Operation::DeriveKey),
            "Certify" => Some(Operation::Certify),
            "ReCertify" => Some(Operation::ReCertify),
            "Locate" => Some(Operation::Locate),
            "Check" => Some(Operation::Check),
            "Get" => Some(Operation::Get),
            "GetAttributes" => Some(Operation::GetAttributes),
            "GetAttributeList" => Some(Operation::GetAttributeList),
            "AddAttribute" => Some(Operation::AddAttribute),
            "ModifyAttribute" => Some(Operation::ModifyAttribute),
            "DeleteAttribute" => Some(Operation::DeleteAttribute),
            "ObtainLease" => Some(Operation::ObtainLease),
            "Activate" => Some(Operation::Activate),
            "Revoke" => Some(Operation::Revoke),
            "Destroy" => Some(Operation::Destroy),
            "Archive" => Some(Operation::Archive),
            "Recover" => Some(Operation::Recover),
            "Validate" => Some(Operation::Validate),
            "Query" => Some(Operation::Query),
            "Cancel" => Some(Operation::Cancel),
            "Poll" => Some(Operation::Poll),
            "Notify" => Some(Operation::Notify),
            "Put" => Some(Operation::Put),
            "Encrypt" => Some(Operation::Encrypt),
            "Decrypt" => Some(Operation::Decrypt),
            "Sign" => Some(Operation::Sign),
            "SignatureVerify" => Some(Operation::SignatureVerify),
            "MAC" => Some(Operation::MAC),
            "MACVerify" => Some(Operation::MACVerify),
            "Hash" => Some(Operation::Hash),
            "CreateSplitKey" => Some(Operation::CreateSplitKey),
            "JoinSplitKey" => Some(Operation::JoinSplitKey),
            "Import" => Some(Operation::Import),
            "Export" => Some(Operation::Export),
            "Log" => Some(Operation::Log),
            "Login" => Some(Operation::Login),
            "Logout" => Some(Operation::Logout),
            "CredentialManagement" => Some(Operation::CredentialManagement),
            "CertificateRequest" => Some(Operation::CertificateRequestOperation),
            "DiscoverVersions" => Some(Operation::DiscoverVersions),
            _ => None,
        }
    }
}

// ─────────
// ObjectType 枚举
// ─────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectType {
    Certificate,
    SymmetricKey,
    PublicKey,
    PrivateKey,
    SplitKey,
    Template,
    SecretData,
    OpaqueObject,
}

impl ObjectType {
    pub fn name(&self) -> &'static str {
        match self {
            ObjectType::Certificate => "Certificate",
            ObjectType::SymmetricKey => "SymmetricKey",
            ObjectType::PublicKey => "PublicKey",
            ObjectType::PrivateKey => "PrivateKey",
            ObjectType::SplitKey => "SplitKey",
            ObjectType::Template => "Template",
            ObjectType::SecretData => "SecretData",
            ObjectType::OpaqueObject => "OpaqueObject",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "Certificate" => Some(ObjectType::Certificate),
            "SymmetricKey" => Some(ObjectType::SymmetricKey),
            "PublicKey" => Some(ObjectType::PublicKey),
            "PrivateKey" => Some(ObjectType::PrivateKey),
            "SplitKey" => Some(ObjectType::SplitKey),
            "Template" => Some(ObjectType::Template),
            "SecretData" => Some(ObjectType::SecretData),
            "OpaqueObject" => Some(ObjectType::OpaqueObject),
            _ => None,
        }
    }
}

// ─────────
// CredentialType 枚举
// ─────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialType {
    UsernameAndPassword,
    Device,
    Attestation,
    OneTimePassword,
    HashedPassword,
    Ticket,
}

impl CredentialType {
    pub fn name(&self) -> &'static str {
        match self {
            CredentialType::UsernameAndPassword => "UsernameAndPassword",
            CredentialType::Device => "Device",
            CredentialType::Attestation => "Attestation",
            CredentialType::OneTimePassword => "OneTimePassword",
            CredentialType::HashedPassword => "HashedPassword",
            CredentialType::Ticket => "Ticket",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "UsernameAndPassword" => Some(CredentialType::UsernameAndPassword),
            "Device" => Some(CredentialType::Device),
            "Attestation" => Some(CredentialType::Attestation),
            "OneTimePassword" => Some(CredentialType::OneTimePassword),
            "HashedPassword" => Some(CredentialType::HashedPassword),
            "Ticket" => Some(CredentialType::Ticket),
            _ => None,
        }
    }
}

// ─────────
// ResultStatus 枚举（KMIP 标准响应状态码）
// ─────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultStatus {
    Success,
    OperationFailed,
    OperationPending,
    OperationUndone,
}

impl ResultStatus {
    pub fn name(&self) -> &'static str {
        match self {
            ResultStatus::Success => "Success",
            ResultStatus::OperationFailed => "OperationFailed",
            ResultStatus::OperationPending => "OperationPending",
            ResultStatus::OperationUndone => "OperationUndone",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "Success" => Some(ResultStatus::Success),
            "OperationFailed" => Some(ResultStatus::OperationFailed),
            "OperationPending" => Some(ResultStatus::OperationPending),
            "OperationUndone" => Some(ResultStatus::OperationUndone),
            _ => None,
        }
    }
}

// ─────────
// CryptographicAlgorithm 枚举
// ─────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoAlgorithm {
    AES,
    SM4,
    SM2,
    RSA,
    ECDH,
    ECDSA,
    HMAC,
    SHA256,
    SHA384,
    SHA512,
}

impl CryptoAlgorithm {
    pub fn name(&self) -> &'static str {
        match self {
            CryptoAlgorithm::AES => "AES",
            CryptoAlgorithm::SM4 => "SM4",
            CryptoAlgorithm::SM2 => "SM2",
            CryptoAlgorithm::RSA => "RSA",
            CryptoAlgorithm::ECDH => "ECDH",
            CryptoAlgorithm::ECDSA => "ECDSA",
            CryptoAlgorithm::HMAC => "HMAC",
            CryptoAlgorithm::SHA256 => "SHA256",
            CryptoAlgorithm::SHA384 => "SHA384",
            CryptoAlgorithm::SHA512 => "SHA512",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "AES" => Some(CryptoAlgorithm::AES),
            "SM4" => Some(CryptoAlgorithm::SM4),
            "SM2" => Some(CryptoAlgorithm::SM2),
            "RSA" => Some(CryptoAlgorithm::RSA),
            "ECDH" => Some(CryptoAlgorithm::ECDH),
            "ECDSA" => Some(CryptoAlgorithm::ECDSA),
            "HMAC" => Some(CryptoAlgorithm::HMAC),
            "SHA256" => Some(CryptoAlgorithm::SHA256),
            "SHA384" => Some(CryptoAlgorithm::SHA384),
            "SHA512" => Some(CryptoAlgorithm::SHA512),
            _ => None,
        }
    }
}

// ─────────
// State 枚举（密钥生命周期）
// ─────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    PreActive,
    Active,
    Deactivated,
    Compromised,
    Destroyed,
    DestroyedCompromised,
}

impl KeyState {
    pub fn name(&self) -> &'static str {
        match self {
            KeyState::PreActive => "PreActive",
            KeyState::Active => "Active",
            KeyState::Deactivated => "Deactivated",
            KeyState::Compromised => "Compromised",
            KeyState::Destroyed => "Destroyed",
            KeyState::DestroyedCompromised => "DestroyedCompromised",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "PreActive" => Some(KeyState::PreActive),
            "Active" => Some(KeyState::Active),
            "Deactivated" => Some(KeyState::Deactivated),
            "Compromised" => Some(KeyState::Compromised),
            "Destroyed" => Some(KeyState::Destroyed),
            "DestroyedCompromised" => Some(KeyState::DestroyedCompromised),
            _ => None,
        }
    }
}

// ─────────
// KeyFormatType 枚举
// ─────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormatType {
    Raw,
    Opaque,
    TransparentSymmetricKey,
    TransparentDSAPrivateKey,
    TransparentDSAPublicKey,
    TransparentRSAPrivateKey,
    TransparentRSAPublicKey,
    TransparentDHPrivateKey,
    TransparentDHPublicKey,
    TransparentECDSAPrivateKey,
    TransparentECDSAPublicKey,
    TransparentECPrivateKey,
    TransparentECPublicKey,
    PKCS1,
    PKCS8,
    X509,
    ECPrivateKey,
}

impl KeyFormatType {
    pub fn name(&self) -> &'static str {
        match self {
            KeyFormatType::Raw => "Raw",
            KeyFormatType::Opaque => "Opaque",
            KeyFormatType::TransparentSymmetricKey => "TransparentSymmetricKey",
            KeyFormatType::TransparentDSAPrivateKey => "TransparentDSAPrivateKey",
            KeyFormatType::TransparentDSAPublicKey => "TransparentDSAPublicKey",
            KeyFormatType::TransparentRSAPrivateKey => "TransparentRSAPrivateKey",
            KeyFormatType::TransparentRSAPublicKey => "TransparentRSAPublicKey",
            KeyFormatType::TransparentDHPrivateKey => "TransparentDHPrivateKey",
            KeyFormatType::TransparentDHPublicKey => "TransparentDHPublicKey",
            KeyFormatType::TransparentECDSAPrivateKey => "TransparentECDSAPrivateKey",
            KeyFormatType::TransparentECDSAPublicKey => "TransparentECDSAPublicKey",
            KeyFormatType::TransparentECPrivateKey => "TransparentECPrivateKey",
            KeyFormatType::TransparentECPublicKey => "TransparentECPublicKey",
            KeyFormatType::PKCS1 => "PKCS1",
            KeyFormatType::PKCS8 => "PKCS8",
            KeyFormatType::X509 => "X509",
            KeyFormatType::ECPrivateKey => "ECPrivateKey",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "Raw" => Some(KeyFormatType::Raw),
            "Opaque" => Some(KeyFormatType::Opaque),
            "TransparentSymmetricKey" => Some(KeyFormatType::TransparentSymmetricKey),
            "TransparentDSAPrivateKey" => Some(KeyFormatType::TransparentDSAPrivateKey),
            "TransparentDSAPublicKey" => Some(KeyFormatType::TransparentDSAPublicKey),
            "TransparentRSAPrivateKey" => Some(KeyFormatType::TransparentRSAPrivateKey),
            "TransparentRSAPublicKey" => Some(KeyFormatType::TransparentRSAPublicKey),
            "TransparentDHPrivateKey" => Some(KeyFormatType::TransparentDHPrivateKey),
            "TransparentDHPublicKey" => Some(KeyFormatType::TransparentDHPublicKey),
            "TransparentECDSAPrivateKey" => Some(KeyFormatType::TransparentECDSAPrivateKey),
            "TransparentECDSAPublicKey" => Some(KeyFormatType::TransparentECDSAPublicKey),
            "TransparentECPrivateKey" => Some(KeyFormatType::TransparentECPrivateKey),
            "TransparentECPublicKey" => Some(KeyFormatType::TransparentECPublicKey),
            "PKCS1" => Some(KeyFormatType::PKCS1),
            "PKCS8" => Some(KeyFormatType::PKCS8),
            "X509" => Some(KeyFormatType::X509),
            "ECPrivateKey" => Some(KeyFormatType::ECPrivateKey),
            _ => None,
        }
    }
}

// ─────────
// CryptographicUsageMask 常量
// ─────────

pub mod usage_mask {
    pub const SIGN: i32 = 0x0000_0001;
    pub const VERIFY: i32 = 0x0000_0002;
    pub const ENCRYPT: i32 = 0x0000_0004;
    pub const DECRYPT: i32 = 0x0000_0008;
    pub const WRAP_KEY: i32 = 0x0000_0010;
    pub const UNWRAP_KEY: i32 = 0x0000_0020;
    pub const EXPORT: i32 = 0x0000_0040;
    pub const MAC_GENERATE: i32 = 0x0000_0080;
    pub const MAC_VERIFY: i32 = 0x0000_0100;
    pub const DERIVE_KEY: i32 = 0x0000_0200;
    pub const KEY_AGREEMENT: i32 = 0x0000_0400;
    pub const CERTIFICATE_SIGN: i32 = 0x0000_0800;
    pub const CRL_SIGN: i32 = 0x0000_1000;
    pub const GENERATE_CRYPTOGRAM: i32 = 0x0000_2000;
    pub const VALIDATE_CRYPTOGRAM: i32 = 0x0000_4000;
    pub const TRANSLATE_ENCRYPT: i32 = 0x0000_8000;
    pub const TRANSLATE_DECRYPT: i32 = 0x0001_0000;
    pub const TRANSLATE_WRAP: i32 = 0x0002_0000;
    pub const TRANSLATE_UNWRAP: i32 = 0x0004_0000;
    pub const AUTHENTICATE: i32 = 0x0008_0000;
}
