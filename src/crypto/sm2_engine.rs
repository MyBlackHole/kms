use crate::crypto::traits::{CryptoResult, SignEngine};
use crate::Error;

pub struct Sm2Engine;

impl Default for Sm2Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Sm2Engine {
    pub fn new() -> Self {
        Self
    }
}

impl SignEngine for Sm2Engine {
    fn generate_keypair(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        use libsm::sm2::signature::SigCtx;

        let ctx = SigCtx::new();
        let (pk_point, sk_bigint) = ctx
            .new_keypair()
            .map_err(|e| Error::CryptoError(format!("SM2 密钥对生成失败: {:?}", e)))?;

        let pk_bytes = ctx
            .serialize_pubkey(&pk_point, false)
            .map_err(|e| Error::CryptoError(format!("SM2 公钥序列化失败: {:?}", e)))?;

        let sk_bytes = ctx
            .serialize_seckey(&sk_bigint)
            .map_err(|e| Error::CryptoError(format!("SM2 私钥序列化失败: {:?}", e)))?;

        Ok((sk_bytes, pk_bytes))
    }

    fn sign(&self, private_key: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>> {
        use libsm::sm2::signature::SigCtx;
        use libsm::sm3::hash::Sm3Hash;

        let ctx = SigCtx::new();
        let sk = ctx
            .load_seckey(private_key)
            .map_err(|_| Error::CryptoError("SM2 私钥加载失败".into()))?;
        let pk = ctx
            .pk_from_sk(&sk)
            .map_err(|_| Error::CryptoError("SM2 公钥推导失败".into()))?;

        let hash = Sm3Hash::new(data).get_hash();
        let sig = ctx
            .sign(&hash, &sk, &pk)
            .map_err(|e| Error::CryptoError(format!("SM2 签名失败: {:?}", e)))?;

        Ok(sig.der_encode())
    }

    fn verify(&self, public_key: &[u8], data: &[u8], signature: &[u8]) -> CryptoResult<bool> {
        use libsm::sm2::signature::{SigCtx, Signature};
        use libsm::sm3::hash::Sm3Hash;

        let ctx = SigCtx::new();
        let pk = ctx
            .load_pubkey(public_key)
            .map_err(|_| Error::CryptoError("SM2 公钥加载失败".into()))?;

        let sig = Signature::der_decode(signature)
            .map_err(|_| Error::CryptoError("SM2 签名格式解析失败".into()))?;

        let hash = Sm3Hash::new(data).get_hash();
        let valid = ctx
            .verify(&hash, &pk, &sig)
            .map_err(|e| Error::CryptoError(format!("SM2 验签失败: {:?}", e)))?;

        Ok(valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::traits::SignEngine;

    #[test]
    fn test_sm2_sign_verify_roundtrip() {
        let engine = Sm2Engine::new();
        let (sk, pk) = engine.generate_keypair().expect("生成 SM2 密钥对失败");

        let data = b"SM2 signature test data";
        let sig = engine.sign(&sk, data).expect("SM2 签名失败");
        assert!(!sig.is_empty(), "签名不应为空");

        let valid = engine.verify(&pk, data, &sig).expect("SM2 验签失败");
        assert!(valid, "签名应验证通过");
    }

    #[test]
    fn test_sm2_verify_rejects_tampered_data() {
        let engine = Sm2Engine::new();
        let (sk, pk) = engine.generate_keypair().unwrap();

        let data = b"original data";
        let sig = engine.sign(&sk, data).unwrap();

        let tampered = b"tampered data";
        let valid = engine.verify(&pk, tampered, &sig).unwrap();
        assert!(!valid, "篡改后的数据应验证失败");
    }

    #[test]
    fn test_sm2_different_keys_produce_different_signatures() {
        let engine = Sm2Engine::new();
        let (sk1, _pk1) = engine.generate_keypair().unwrap();
        let (sk2, _pk2) = engine.generate_keypair().unwrap();

        let data = b"test data";
        let sig1 = engine.sign(&sk1, data).unwrap();
        let sig2 = engine.sign(&sk2, data).unwrap();
        assert_ne!(sig1, sig2, "不同密钥签名应不同");
    }

    #[test]
    fn test_sm2_generate_keypair_returns_valid_keys() {
        let engine = Sm2Engine::new();
        let (sk, pk) = engine.generate_keypair().unwrap();
        assert!(!sk.is_empty(), "私钥不应为空");
        assert!(!pk.is_empty(), "公钥不应为空");
        // SM2 私钥通常 32 字节，公钥 65 字节（未压缩）
        assert_eq!(sk.len(), 32, "SM2 私钥应为 32 字节");
    }
}
