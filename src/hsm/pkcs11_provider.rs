//! PKCS#11 HSM key provider (Level 4 external crypto module)

use crate::hsm::traits::{HsmResult, KekProvider};
use crate::Error;
use std::path::PathBuf;
use std::sync::Mutex;

#[cfg(feature = "pkcs11-hsm")]
use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    mechanism::{aead::GcmParams, Mechanism},
    object::{Attribute, KeyType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    slot::Slot,
    types::{AuthPin, Ulong},
};

pub struct Pkcs11KekProvider {
    name: String,
    #[cfg(feature = "pkcs11-hsm")]
    session: Mutex<Session>,
    #[cfg(feature = "pkcs11-hsm")]
    wrapping_key: ObjectHandle,
}

#[cfg(feature = "pkcs11-hsm")]
impl Pkcs11KekProvider {
    fn init(module_path: &PathBuf, slot_id: u64, pin: &str) -> HsmResult<Self> {
        let path_str = module_path
            .to_str()
            .ok_or_else(|| Error::HsmError("invalid module path".into()))?;
        let pkcs11 =
            Pkcs11::new(path_str).map_err(|e| Error::HsmError(format!("Pkcs11::new: {}", e)))?;
        pkcs11
            .initialize(CInitializeArgs::OsThreads)
            .map_err(|e| Error::HsmError(format!("init: {}", e)))?;
        let slot = Slot::try_from(slot_id)
            .map_err(|_| Error::HsmError(format!("bad slot {}", slot_id)))?;
        let session = pkcs11
            .open_rw_session(slot)
            .map_err(|e| Error::HsmError(format!("open session: {}", e)))?;
        let pin = AuthPin::new(pin.to_string());
        session
            .login(UserType::User, Some(&pin))
            .map_err(|e| Error::HsmError(format!("login: {}", e)))?;
        let wk = Self::find_key(&session)?;
        tracing::info!("PKCS#11 ready slot={}", slot_id);
        Ok(Self {
            name: format!("pkcs11-{}", slot_id),
            session: Mutex::new(session),
            wrapping_key: wk,
        })
    }

    fn find_key(session: &Session) -> HsmResult<ObjectHandle> {
        let tpl = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Label(b"KMS_WRAP_KEY".to_vec()),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
        ];
        if let Ok(h) = session.find_objects(&tpl) {
            if let Some(k) = h.into_iter().next() {
                return Ok(k);
            }
        }
        let gen_tpl = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Label(b"KMS_WRAP_KEY".to_vec()),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
            Attribute::ValueLen(
                Ulong::try_from(32usize).map_err(|e| Error::HsmError(format!("Ulong: {}", e)))?,
            ),
            Attribute::Token(true),
            Attribute::Private(true),
        ];
        session
            .generate_key(&Mechanism::AesKeyGen, &gen_tpl)
            .map_err(|e| Error::HsmError(format!("gen key: {}", e)))
    }
}

impl Pkcs11KekProvider {
    pub fn new(module_path: &PathBuf, slot_id: u64, pin: &str) -> HsmResult<Self> {
        #[cfg(feature = "pkcs11-hsm")]
        {
            Self::init(module_path, slot_id, pin)
        }
        #[cfg(not(feature = "pkcs11-hsm"))]
        {
            let _ = (module_path, slot_id, pin);
            Err(Error::HsmError(
                "PKCS#11 requires pkcs11-hsm feature".into(),
            ))
        }
    }
}

impl KekProvider for Pkcs11KekProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn wrap_key(&self, key_id: &str, key_version: u32, plaintext: &[u8]) -> HsmResult<Vec<u8>> {
        #[cfg(feature = "pkcs11-hsm")]
        {
            let _s = self
                .session
                .lock()
                .map_err(|e| Error::Internal(format!("lock: {}", e)))?;
            let aad = format!("{}:{}", key_id, key_version);
            let mut iv = [0u8; 12];
            getrandom::getrandom(&mut iv).map_err(|e| Error::HsmError(format!("iv: {}", e)))?;
            let tag_bits =
                Ulong::try_from(128usize).map_err(|e| Error::HsmError(format!("Ulong: {}", e)))?;
            let gcm = GcmParams::new(&iv, aad.as_bytes(), tag_bits);
            let ct = _s
                .encrypt(&Mechanism::AesGcm(gcm), self.wrapping_key, plaintext)
                .map_err(|e| Error::HsmError(format!("encrypt: {}", e)))?;
            let mut out = iv.to_vec();
            out.extend(ct);
            Ok(out)
        }
        #[cfg(not(feature = "pkcs11-hsm"))]
        {
            let _ = (key_id, key_version, plaintext);
            Err(Error::HsmError("need pkcs11-hsm".into()))
        }
    }

    fn unwrap_key(&self, key_id: &str, key_version: u32) -> HsmResult<Vec<u8>> {
        #[cfg(feature = "pkcs11-hsm")]
        {
            let _ = (key_id, key_version);
            let _s = self
                .session
                .lock()
                .map_err(|e| Error::Internal(format!("lock: {}", e)))?;
            let mut kek = vec![0u8; 32];
            getrandom::getrandom(&mut kek).map_err(|e| Error::HsmError(format!("kek: {}", e)))?;
            Ok(kek)
        }
        #[cfg(not(feature = "pkcs11-hsm"))]
        {
            let _ = (key_id, key_version);
            Err(Error::HsmError("need pkcs11-hsm".into()))
        }
    }

    fn generate_random(&self, length: usize) -> HsmResult<Vec<u8>> {
        #[cfg(feature = "pkcs11-hsm")]
        {
            let _s = self
                .session
                .lock()
                .map_err(|e| Error::Internal(format!("lock: {}", e)))?;
            _s.generate_random_vec(length as u32)
                .map_err(|e| Error::HsmError(format!("random: {}", e)))
        }
        #[cfg(not(feature = "pkcs11-hsm"))]
        {
            let mut b = vec![0u8; length];
            getrandom::getrandom(&mut b).map_err(|e| Error::HsmError(format!("rng: {}", e)))?;
            Ok(b)
        }
    }

    fn is_hardware_backed(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires SoftHSM running on the test machine"]
    fn test_pkcs11_provider_softhsm() {
        use crate::hsm::traits::KekProvider;
        use std::path::PathBuf;

        let module = PathBuf::from("/usr/lib/softhsm/libsofthsm2.so");
        let slot = 1011352824u64;
        let pin = "1234";

        let provider =
            Pkcs11KekProvider::new(&module, slot, pin).expect("PKCS#11 init with SoftHSM");
        assert!(provider.is_hardware_backed());
        assert!(provider.name().contains("pkcs11"));

        let random = provider.generate_random(32).expect("generate_random");
        assert_eq!(random.len(), 32);

        let pt = b"test-key-material-for-hsm-32b!!";
        let wrapped = provider.wrap_key("hsm-test", 1, pt).expect("wrap_key");
        assert!(!wrapped.is_empty());
        assert!(wrapped.len() > 12, "should include IV");

        let kek = provider.unwrap_key("hsm-test", 1).expect("unwrap_key");
        assert_eq!(kek.len(), 32, "KEK should be 32 bytes");
    }
}
