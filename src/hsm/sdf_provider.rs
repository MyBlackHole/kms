use crate::hsm::software_provider::SoftwareKekProvider;
use crate::hsm::traits::{HsmResult, KekProvider};

/// 国密 SDF 接口密钥提供程序（GM/T 0018-2012）
///
/// 当前版本先提供一个可运行的兼容层：
/// 1. 对外保留 SDF 模式入口；
/// 2. 内部复用现有软件 HSM 的 KEK 派生和包装逻辑；
/// 3. 后续接入真实 SDF 动态库时，只需要替换 backend 实现。
pub struct SdfKekProvider {
    name: String,
    backend: SoftwareKekProvider,
}

impl SdfKekProvider {
    pub fn new(device_path: Option<&str>) -> HsmResult<Self> {
        let name = match device_path {
            Some(path) => format!("sdf-hsm-{}", path),
            None => "sdf-hsm-software-fallback".into(),
        };
        let backend = SoftwareKekProvider::new(device_path)?;
        tracing::info!("SDF HSM 提供程序已初始化: {}", name);

        Ok(Self { name, backend })
    }
}

impl KekProvider for SdfKekProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn wrap_key(&self, key_id: &str, key_version: u32, plaintext: &[u8]) -> HsmResult<Vec<u8>> {
        self.backend.wrap_key(key_id, key_version, plaintext)
    }

    fn unwrap_key(&self, key_id: &str, key_version: u32) -> HsmResult<Vec<u8>> {
        self.backend.unwrap_key(key_id, key_version)
    }

    fn generate_random(&self, length: usize) -> HsmResult<Vec<u8>> {
        self.backend.generate_random(length)
    }

    fn is_hardware_backed(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdf_provider_creation() {
        let provider = SdfKekProvider::new(None);
        assert!(provider.is_ok());
        assert!(!provider.unwrap().is_hardware_backed());
    }

    #[test]
    fn test_sdf_wrap_unwrap_roundtrip() {
        let provider = SdfKekProvider::new(Some("0123456789abcdef0123456789abcdef")).unwrap();
        let plaintext = b"this is a 32 byte test vector!!!!!";

        let wrapped = provider.wrap_key("test-key", 1, plaintext).unwrap();
        assert!(!wrapped.is_empty());

        let unwrapped = provider.unwrap_key("test-key", 1).unwrap();
        assert_eq!(unwrapped.len(), 16);
    }

    #[test]
    fn test_sdf_generate_random() {
        let provider = SdfKekProvider::new(None).unwrap();
        let random = provider.generate_random(32).unwrap();
        assert_eq!(random.len(), 32);
    }
}
