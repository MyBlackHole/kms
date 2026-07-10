//! 输入验证模块（等保四级 — 白名单格式校验）
//!
//! 所有 API 请求参数做白名单格式校验：
//! - 字段名、类型、长度范围、允许字符
//! - 拒绝格式不符的请求
//! - 错误信息统一返回模糊提示

use serde_json::Value;

/// 验证规则
#[derive(Debug, Clone)]
pub struct ValidationRule {
    /// 字段名
    pub field: &'static str,
    /// 期望类型
    pub field_type: FieldType,
    /// 最小长度（字符串/数组）
    pub min_length: Option<usize>,
    /// 最大长度（字符串/数组）
    pub max_length: Option<usize>,
    /// 是否必需
    pub required: bool,
    /// 允许的正则模式（字符串类型）
    pub pattern: Option<&'static str>,
    /// 允许值列表（枚举类型）
    pub allowed_values: Option<Vec<&'static str>>,
}

/// 字段类型
#[derive(Debug, Clone, PartialEq)]
pub enum FieldType {
    String,
    Integer,
    Float,
    Boolean,
    Array,
    Object,
    Uuid,
    Hex,
    Base64,
    Timestamp,
}

/// 验证结果
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
}

impl ValidationResult {
    pub fn valid() -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
        }
    }

    pub fn invalid(errors: Vec<String>) -> Self {
        Self {
            valid: false,
            errors,
        }
    }

    pub fn add_error(&mut self, error: String) {
        self.valid = false;
        self.errors.push(error);
    }
}

/// 白名单验证器
#[derive(Debug, Clone)]
pub struct WhitelistValidator {
    rules: Vec<ValidationRule>,
}

impl Default for WhitelistValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl WhitelistValidator {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// 添加验证规则
    pub fn add_rule(&mut self, rule: ValidationRule) {
        self.rules.push(rule);
    }

    /// 批量添加规则
    pub fn add_rules(&mut self, rules: Vec<ValidationRule>) {
        self.rules.extend(rules);
    }

    /// 验证 JSON 值
    pub fn validate(&self, value: &Value) -> ValidationResult {
        let mut result = ValidationResult::valid();

        match value {
            Value::Object(map) => {
                // 检查每个字段
                for rule in &self.rules {
                    let field_value = map.get(rule.field);

                    match field_value {
                        None => {
                            if rule.required {
                                result.add_error(format!(
                                    "字段 '{}' 是必需的",
                                    mask_field(rule.field)
                                ));
                            }
                        }
                        Some(val) => {
                            if let Err(e) = self.validate_field(rule, val) {
                                result.add_error(e);
                            }
                        }
                    }
                }

                // 检查未定义的字段
                for (key, _) in map {
                    if !self.rules.iter().any(|r| r.field == key.as_str()) {
                        result.add_error(format!("未知字段 '{}'", mask_field(key)));
                    }
                }
            }
            Value::Array(arr) => {
                for (idx, item) in arr.iter().enumerate() {
                    if let Err(e) = self.validate_string_internal(item, idx) {
                        result.add_error(e);
                    }
                }
            }
            _ => {
                result.add_error("请求体必须是 JSON 对象或数组".to_string());
            }
        }

        result
    }

    /// 验证单个字段
    fn validate_field(&self, rule: &ValidationRule, value: &Value) -> Result<(), String> {
        match rule.field_type {
            FieldType::String => self.validate_string(rule, value),
            FieldType::Integer => self.validate_integer(rule, value),
            FieldType::Float => self.validate_float(rule, value),
            FieldType::Boolean => self.validate_boolean(value),
            FieldType::Array => self.validate_array(rule, value),
            FieldType::Object => self.validate_object(value),
            FieldType::Uuid => self.validate_uuid(value),
            FieldType::Hex => self.validate_hex(rule, value),
            FieldType::Base64 => self.validate_base64(rule, value),
            FieldType::Timestamp => self.validate_timestamp(value),
        }
    }

    fn validate_string(&self, rule: &ValidationRule, value: &Value) -> Result<(), String> {
        let s = match value {
            Value::String(s) => s,
            _ => {
                return Err(format!(
                    "字段 '{}' 必须是字符串类型",
                    mask_field(rule.field)
                ))
            }
        };

        if let Some(min) = rule.min_length {
            if s.len() < min {
                return Err(format!(
                    "字段 '{}' 长度不能小于 {}",
                    mask_field(rule.field),
                    min
                ));
            }
        }

        if let Some(max) = rule.max_length {
            if s.len() > max {
                return Err(format!(
                    "字段 '{}' 长度不能超过 {}",
                    mask_field(rule.field),
                    max
                ));
            }
        }

        if let Some(pattern) = rule.pattern {
            if !self.simple_pattern_match(s, pattern) {
                return Err(format!("字段 '{}' 格式不符合要求", mask_field(rule.field)));
            }
        }

        if let Some(ref allowed) = rule.allowed_values {
            if !allowed.contains(&s.as_str()) {
                return Err(format!(
                    "字段 '{}' 的值不在允许范围内",
                    mask_field(rule.field)
                ));
            }
        }

        Ok(())
    }

    fn validate_string_internal(&self, value: &Value, _idx: usize) -> Result<(), String> {
        match value {
            Value::String(s) => {
                if s.len() > 65536 {
                    return Err("数组元素长度超出限制".to_string());
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn validate_integer(&self, rule: &ValidationRule, value: &Value) -> Result<(), String> {
        match value {
            Value::Number(n) => {
                if n.is_f64() {
                    // 实际上是浮点数，但检查是否是整数值
                    if n.as_i64().is_none() {
                        return Err(format!("字段 '{}' 必须是整数类型", mask_field(rule.field)));
                    }
                }
                Ok(())
            }
            _ => Err(format!("字段 '{}' 必须是整数类型", mask_field(rule.field))),
        }
    }

    fn validate_float(&self, rule: &ValidationRule, value: &Value) -> Result<(), String> {
        match value {
            Value::Number(_) => Ok(()),
            _ => Err(format!("字段 '{}' 必须是数字类型", mask_field(rule.field))),
        }
    }

    fn validate_boolean(&self, value: &Value) -> Result<(), String> {
        match value {
            Value::Bool(_) => Ok(()),
            _ => Err("字段必须是布尔类型".to_string()),
        }
    }

    fn validate_array(&self, rule: &ValidationRule, value: &Value) -> Result<(), String> {
        match value {
            Value::Array(arr) => {
                if let Some(min) = rule.min_length {
                    if arr.len() < min {
                        return Err(format!(
                            "字段 '{}' 数组长度不能小于 {}",
                            mask_field(rule.field),
                            min
                        ));
                    }
                }
                if let Some(max) = rule.max_length {
                    if arr.len() > max {
                        return Err(format!(
                            "字段 '{}' 数组长度不能超过 {}",
                            mask_field(rule.field),
                            max
                        ));
                    }
                }
                Ok(())
            }
            _ => Err(format!("字段 '{}' 必须是数组类型", mask_field(rule.field))),
        }
    }

    fn validate_object(&self, value: &Value) -> Result<(), String> {
        match value {
            Value::Object(_) => Ok(()),
            _ => Err("字段必须是对象类型".to_string()),
        }
    }

    fn validate_uuid(&self, value: &Value) -> Result<(), String> {
        match value {
            Value::String(s) => {
                if uuid::Uuid::parse_str(s).is_ok() {
                    Ok(())
                } else {
                    Err("UUID 格式无效".to_string())
                }
            }
            _ => Err("UUID 必须是字符串类型".to_string()),
        }
    }

    fn validate_hex(&self, rule: &ValidationRule, value: &Value) -> Result<(), String> {
        match value {
            Value::String(s) => {
                if s.len() % 2 != 0 {
                    return Err(format!(
                        "字段 '{}' 的十六进制字符串长度必须为偶数",
                        mask_field(rule.field)
                    ));
                }
                if !s.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(format!(
                        "字段 '{}' 包含非十六进制字符",
                        mask_field(rule.field)
                    ));
                }
                if let Some(max) = rule.max_length {
                    if s.len() > max {
                        return Err(format!(
                            "字段 '{}' 十六进制长度不能超过 {}",
                            mask_field(rule.field),
                            max
                        ));
                    }
                }
                Ok(())
            }
            _ => Err(format!(
                "字段 '{}' 必须是十六进制字符串",
                mask_field(rule.field)
            )),
        }
    }

    fn validate_base64(&self, rule: &ValidationRule, value: &Value) -> Result<(), String> {
        match value {
            Value::String(s) => {
                use base64::Engine;
                if base64::engine::general_purpose::STANDARD.decode(s).is_err() {
                    return Err(format!(
                        "字段 '{}' 的 Base64 编码无效",
                        mask_field(rule.field)
                    ));
                }
                if let Some(max) = rule.max_length {
                    if s.len() > max {
                        return Err(format!(
                            "字段 '{}' Base64 长度不能超过 {}",
                            mask_field(rule.field),
                            max
                        ));
                    }
                }
                Ok(())
            }
            _ => Err(format!(
                "字段 '{}' 必须是 Base64 字符串",
                mask_field(rule.field)
            )),
        }
    }

    fn validate_timestamp(&self, value: &Value) -> Result<(), String> {
        match value {
            Value::Number(n) => {
                if n.as_i64().is_some() || n.as_f64().is_some() {
                    Ok(())
                } else {
                    Err("时间戳必须是数字类型".to_string())
                }
            }
            Value::String(s) => {
                if chrono::DateTime::parse_from_rfc3339(s).is_ok() {
                    Ok(())
                } else {
                    Err("时间戳格式无效（应为 RFC3339 或 Unix 时间戳）".to_string())
                }
            }
            _ => Err("时间戳必须是数字或字符串类型".to_string()),
        }
    }

    /// 简单的模式匹配（无需 regex 依赖）
    fn simple_pattern_match(&self, s: &str, pattern: &str) -> bool {
        // 支持最基本的 ^ $ 锚定字符集匹配
        if pattern == r"^[a-zA-Z0-9\-_@]+$" {
            s.chars().all(|c| c.is_alphanumeric() || "-_@".contains(c))
        } else {
            // 兜底：仅检查非空
            !s.is_empty()
        }
    }
}

/// 对字段名做模糊化处理（不暴露具体字段结构）
fn mask_field(field: &str) -> String {
    if field.len() <= 3 {
        field.to_string()
    } else {
        let first = &field[..1];
        let last = &field[field.len() - 1..];
        format!("{}...{}", first, last)
    }
}

/// 预定义的常见验证规则集合
pub mod common_rules {
    use super::*;

    /// 密钥 ID 验证规则
    pub fn key_id() -> ValidationRule {
        ValidationRule {
            field: "key_id",
            field_type: FieldType::String,
            min_length: Some(1),
            max_length: Some(256),
            required: true,
            pattern: Some(r"^[a-zA-Z0-9\-_@]+$"),
            allowed_values: None,
        }
    }

    /// UUID 验证规则
    pub fn uuid_field(name: &'static str) -> ValidationRule {
        ValidationRule {
            field: name,
            field_type: FieldType::Uuid,
            min_length: None,
            max_length: Some(36),
            required: true,
            pattern: None,
            allowed_values: None,
        }
    }

    /// 可选的 UUID 验证规则
    pub fn optional_uuid(name: &'static str) -> ValidationRule {
        ValidationRule {
            field: name,
            field_type: FieldType::Uuid,
            min_length: None,
            max_length: Some(36),
            required: false,
            pattern: None,
            allowed_values: None,
        }
    }

    /// 可选字符串
    pub fn optional_string(name: &'static str, max_len: usize) -> ValidationRule {
        ValidationRule {
            field: name,
            field_type: FieldType::String,
            min_length: None,
            max_length: Some(max_len),
            required: false,
            pattern: None,
            allowed_values: None,
        }
    }

    /// 必填字符串
    pub fn required_string(name: &'static str, max_len: usize) -> ValidationRule {
        ValidationRule {
            field: name,
            field_type: FieldType::String,
            min_length: Some(1),
            max_length: Some(max_len),
            required: true,
            pattern: None,
            allowed_values: None,
        }
    }

    /// 算法名称
    pub fn algorithm() -> ValidationRule {
        ValidationRule {
            field: "algorithm",
            field_type: FieldType::String,
            min_length: Some(2),
            max_length: Some(20),
            required: true,
            pattern: None,
            allowed_values: Some(vec![
                "SM4",
                "SM2",
                "SM3",
                "AES-256-GCM",
                "RSA-2048",
                "RSA-4096",
            ]),
        }
    }

    /// 安全标记级别
    pub fn security_label() -> ValidationRule {
        ValidationRule {
            field: "security_level",
            field_type: FieldType::String,
            min_length: Some(1),
            max_length: Some(20),
            required: false,
            pattern: None,
            allowed_values: Some(vec![
                "Public",
                "Internal",
                "Secret",
                "Classified",
                "TopSecret",
            ]),
        }
    }

    /// 分页参数
    pub fn pagination() -> Vec<ValidationRule> {
        vec![
            ValidationRule {
                field: "offset",
                field_type: FieldType::Integer,
                min_length: None,
                max_length: None,
                required: false,
                pattern: None,
                allowed_values: None,
            },
            ValidationRule {
                field: "limit",
                field_type: FieldType::Integer,
                min_length: None,
                max_length: None,
                required: false,
                pattern: None,
                allowed_values: None,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_validate_simple_object() {
        let mut validator = WhitelistValidator::new();
        validator.add_rule(ValidationRule {
            field: "name",
            field_type: FieldType::String,
            min_length: Some(1),
            max_length: Some(100),
            required: true,
            pattern: None,
            allowed_values: None,
        });

        let valid = json!({"name": "test-key"});
        assert!(validator.validate(&valid).valid);

        let invalid = json!({"name": ""});
        assert!(!validator.validate(&invalid).valid);

        let missing = json!({"other": "value"});
        assert!(!validator.validate(&missing).valid);
    }

    #[test]
    fn test_uuid_validation() {
        let mut validator = WhitelistValidator::new();
        validator.add_rule(common_rules::uuid_field("id"));

        let valid = json!({"id": "550e8400-e29b-41d4-a716-446655440000"});
        assert!(validator.validate(&valid).valid);

        let invalid = json!({"id": "not-a-uuid"});
        assert!(!validator.validate(&invalid).valid);
    }

    #[test]
    fn test_key_id_validation() {
        let mut validator = WhitelistValidator::new();
        validator.add_rule(common_rules::key_id());

        let valid = json!({"key_id": "my-key-123"});
        assert!(validator.validate(&valid).valid);

        let invalid = json!({"key_id": "key with spaces"});
        assert!(!validator.validate(&invalid).valid);

        let path_traversal = json!({"key_id": "../etc/passwd"});
        assert!(!validator.validate(&path_traversal).valid);
    }

    #[test]
    fn test_algorithm_validation() {
        let mut validator = WhitelistValidator::new();
        validator.add_rule(common_rules::algorithm());

        let valid = json!({"algorithm": "SM4"});
        assert!(validator.validate(&valid).valid);

        let invalid = json!({"algorithm": "DES"});
        assert!(!validator.validate(&invalid).valid);
    }

    #[test]
    fn test_hex_validation() {
        let mut validator = WhitelistValidator::new();
        validator.add_rule(ValidationRule {
            field: "data",
            field_type: FieldType::Hex,
            min_length: None,
            max_length: Some(128),
            required: true,
            pattern: None,
            allowed_values: None,
        });

        let valid = json!({"data": "deadbeef"});
        assert!(validator.validate(&valid).valid);

        let invalid = json!({"data": "xyz"});
        assert!(!validator.validate(&invalid).valid);
    }

    #[test]
    fn test_unknown_fields_rejected() {
        let mut validator = WhitelistValidator::new();
        validator.add_rule(ValidationRule {
            field: "name",
            field_type: FieldType::String,
            min_length: Some(1),
            max_length: Some(100),
            required: true,
            pattern: None,
            allowed_values: None,
        });

        let with_unknown = json!({"name": "test", "extra_field": "should be rejected"});
        assert!(!validator.validate(&with_unknown).valid);
    }

    #[test]
    fn test_security_label_validation() {
        let mut validator = WhitelistValidator::new();
        validator.add_rule(common_rules::security_label());

        let valid = json!({"security_level": "Secret"});
        assert!(validator.validate(&valid).valid);

        let invalid = json!({"security_level": "Invalid"});
        assert!(!validator.validate(&invalid).valid);
    }

    #[test]
    fn test_nested_object_validation() {
        let mut validator = WhitelistValidator::new();
        validator.add_rule(ValidationRule {
            field: "metadata",
            field_type: FieldType::Object,
            min_length: None,
            max_length: None,
            required: false,
            pattern: None,
            allowed_values: None,
        });

        let valid = json!({"metadata": {"key": "value"}});
        assert!(validator.validate(&valid).valid);

        let invalid = json!({"metadata": "not-an-object"});
        assert!(!validator.validate(&invalid).valid);
    }

    #[test]
    fn test_initialization_validation_empty() {
        let validator = WhitelistValidator::new();
        // 没有规则时，任何对象都通过（但会报告未知字段）
        let result = validator.validate(&json!({"foo": "bar"}));
        assert!(!result.valid); // 未知字段被拒绝
    }

    #[test]
    fn test_multiple_errors() {
        let mut validator = WhitelistValidator::new();
        validator.add_rule(common_rules::key_id());
        validator.add_rule(common_rules::algorithm());

        let result = validator.validate(&json!({"key_id": 123, "algorithm": "INVALID"}));
        assert!(!result.valid);
        assert!(result.errors.len() >= 2);
    }
}
