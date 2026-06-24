//! 软件 TPM 模拟实现（开发/测试用）
//!
//! PCR 度量使用 SM3 哈希模拟，seal/unseal 为直通。
//! 不依赖任何 TPM 硬件或外部库。

use crate::crypto::traits::HashEngine;
use crate::trust::tpm::{PcrIndex, TpmLevel, TpmResult, TrustedPlatformModule};
use crate::Error;
use std::sync::Mutex;

/// 软件 TPM 模拟
///
/// 无真实硬件时的降级方案。不支持密封/远程证明，
/// PCR 度量以 SM3 哈希模拟，seal/unseal 为明文直通。
pub struct SoftwareTpm {
    pcrs: Mutex<[Vec<u8>; 24]>,
}

impl Default for SoftwareTpm {
    fn default() -> Self {
        Self::new()
    }
}

impl SoftwareTpm {
    pub fn new() -> Self {
        Self {
            pcrs: Mutex::new(std::array::from_fn(|_| vec![0u8; 32])),
        }
    }
}

impl TrustedPlatformModule for SoftwareTpm {
    fn level(&self) -> TpmLevel {
        TpmLevel::None
    }

    fn pcr_extend(&self, index: PcrIndex, data: &[u8]) -> TpmResult<()> {
        let mut pcrs = self
            .pcrs
            .lock()
            .map_err(|e| Error::Internal(format!("lock: {}", e)))?;
        let idx = index as usize;
        if idx >= pcrs.len() {
            return Err(Error::Internal("PCR index out of range".into()));
        }
        let hasher = crate::crypto::sm3_engine::Sm3Engine::new();
        pcrs[idx] = hasher.hash(&[&pcrs[idx], data].concat());
        Ok(())
    }

    fn pcr_read(&self, index: PcrIndex) -> TpmResult<Vec<u8>> {
        let pcrs = self
            .pcrs
            .lock()
            .map_err(|e| Error::Internal(format!("lock: {}", e)))?;
        let idx = index as usize;
        if idx >= pcrs.len() {
            return Err(Error::Internal("PCR index out of range".into()));
        }
        Ok(pcrs[idx].clone())
    }

    fn seal(&self, _index: PcrIndex, data: &[u8]) -> TpmResult<Vec<u8>> {
        tracing::warn!("SoftwareTpm: seal degraded to plaintext (no real TPM)");
        Ok(data.to_vec())
    }

    fn unseal(&self, _index: PcrIndex, sealed: &[u8]) -> TpmResult<Vec<u8>> {
        Ok(sealed.to_vec())
    }

    fn get_random(&self, length: usize) -> TpmResult<Vec<u8>> {
        let mut buf = vec![0u8; length];
        getrandom::getrandom(&mut buf).map_err(|e| Error::Internal(format!("rng: {}", e)))?;
        Ok(buf)
    }

    fn attest(&self, _challenge: &[u8]) -> TpmResult<Vec<u8>> {
        Err(Error::Internal(
            "SoftwareTpm: no attestation support".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::tpm::PcrIndex;

    #[test]
    fn test_pcr_initial_state() {
        let tpm = SoftwareTpm::new();
        for idx in &[PcrIndex::Pcr0, PcrIndex::Pcr8, PcrIndex::KmsApp] {
            let val = tpm.pcr_read(*idx).unwrap();
            assert_eq!(val.len(), 32, "PCR {:?} should be 32 bytes", idx);
            assert_eq!(val, vec![0u8; 32], "PCR {:?} should be all zeros", idx);
        }
    }

    #[test]
    fn test_pcr_extend_and_read() {
        let tpm = SoftwareTpm::new();
        let idx = PcrIndex::KmsApp;
        let initial = tpm.pcr_read(idx).unwrap();
        assert_eq!(initial.len(), 32);
        tpm.pcr_extend(idx, b"v1").unwrap();
        let after_v1 = tpm.pcr_read(idx).unwrap();
        assert_ne!(after_v1, initial, "PCR should change after extend");
    }

    #[test]
    fn test_pcr_extend_chain() {
        let tpm = SoftwareTpm::new();
        let idx = PcrIndex::KmsApp;
        let v0 = tpm.pcr_read(idx).unwrap();
        tpm.pcr_extend(idx, b"a").unwrap();
        let v1 = tpm.pcr_read(idx).unwrap();
        tpm.pcr_extend(idx, b"b").unwrap();
        let v2 = tpm.pcr_read(idx).unwrap();
        tpm.pcr_extend(idx, b"c").unwrap();
        let v3 = tpm.pcr_read(idx).unwrap();
        // PCR chain should be deterministic:
        // v1 = SM3(v0 || a), v2 = SM3(v1 || b), v3 = SM3(v2 || c)
        let hasher = crate::crypto::sm3_engine::Sm3Engine::new();
        assert_eq!(
            v1,
            hasher.hash(&[v0.as_slice(), b"a"].concat()),
            "v1 mismatch"
        );
        assert_eq!(
            v2,
            hasher.hash(&[v1.as_slice(), b"b"].concat()),
            "v2 mismatch"
        );
        assert_eq!(
            v3,
            hasher.hash(&[v2.as_slice(), b"c"].concat()),
            "v3 mismatch"
        );
    }

    #[test]
    fn test_pcr_isolation() {
        let tpm = SoftwareTpm::new();
        // Different PCR indices should not affect each other
        tpm.pcr_extend(PcrIndex::Pcr0, b"data").unwrap();
        tpm.pcr_extend(PcrIndex::Pcr2, b"other").unwrap();
        let pcr0 = tpm.pcr_read(PcrIndex::Pcr0).unwrap();
        let pcr1 = tpm.pcr_read(PcrIndex::Pcr1).unwrap();
        let pcr2 = tpm.pcr_read(PcrIndex::Pcr2).unwrap();
        assert_ne!(pcr0, pcr1, "PCR0 and PCR1 should differ");
        assert_ne!(pcr0, pcr2, "PCR0 and PCR2 should differ");
        assert_ne!(pcr1, pcr2, "PCR1 and PCR2 should differ");
        // Unmodified PCR should still be zero
        assert_eq!(pcr1, vec![0u8; 32], "unmodified PCR should stay zero");
    }

    #[test]
    fn test_pcr_extend_empty_data() {
        let tpm = SoftwareTpm::new();
        let idx = PcrIndex::KmsApp;
        let before = tpm.pcr_read(idx).unwrap();
        tpm.pcr_extend(idx, b"").unwrap();
        let after = tpm.pcr_read(idx).unwrap();
        assert_ne!(before, after, "empty data should still change PCR");
    }

    #[test]
    fn test_pcr_extend_large_data() {
        let tpm = SoftwareTpm::new();
        let idx = PcrIndex::KmsApp;
        let large = vec![0xABu8; 1024];
        tpm.pcr_extend(idx, &large).unwrap();
        let val = tpm.pcr_read(idx).unwrap();
        assert_eq!(
            val.len(),
            32,
            "large data should still produce 32-byte digest"
        );
    }

    #[test]
    fn test_seal_unseal() {
        let tpm = SoftwareTpm::new();
        let data = b"secret-key-material-32bytes!";
        let sealed = tpm.seal(PcrIndex::Pcr11, data).unwrap();
        assert_eq!(tpm.unseal(PcrIndex::Pcr11, &sealed).unwrap(), data);
    }

    #[test]
    fn test_seal_different_pcr_indices() {
        let tpm = SoftwareTpm::new();
        let data = b"sensitive";
        // SoftwareTpm seal/unseal ignores PCR index
        let sealed = tpm.seal(PcrIndex::Pcr0, data).unwrap();
        assert_eq!(tpm.unseal(PcrIndex::KmsApp, &sealed).unwrap(), data);
    }

    #[test]
    fn test_random() {
        let tpm = SoftwareTpm::new();
        assert_ne!(tpm.get_random(16).unwrap(), tpm.get_random(16).unwrap());
        assert_eq!(tpm.get_random(32).unwrap().len(), 32);
        assert_eq!(tpm.get_random(0).unwrap().len(), 0);
    }

    #[test]
    fn test_attest_fails() {
        assert!(SoftwareTpm::new().attest(b"x").is_err());
    }

    #[test]
    fn test_level() {
        assert_eq!(SoftwareTpm::new().level(), TpmLevel::None);
    }

    #[test]
    fn test_multiple_extend_same_data_reproduces() {
        let tpm1 = SoftwareTpm::new();
        let tpm2 = SoftwareTpm::new();
        let idx = PcrIndex::KmsApp;

        tpm1.pcr_extend(idx, b"test").unwrap();
        tpm2.pcr_extend(idx, b"test").unwrap();
        assert_eq!(
            tpm1.pcr_read(idx).unwrap(),
            tpm2.pcr_read(idx).unwrap(),
            "same operations should produce same PCR values"
        );
    }

    #[test]
    fn test_extend_order_matters() {
        let tpm = SoftwareTpm::new();
        let idx = PcrIndex::KmsApp;
        tpm.pcr_extend(idx, b"a").unwrap();
        tpm.pcr_extend(idx, b"b").unwrap();
        let ab = tpm.pcr_read(idx).unwrap();

        let tpm2 = SoftwareTpm::new();
        tpm2.pcr_extend(idx, b"b").unwrap();
        tpm2.pcr_extend(idx, b"a").unwrap();
        let ba = tpm2.pcr_read(idx).unwrap();

        assert_ne!(ab, ba, "extend order should affect PCR value");
    }

    #[test]
    #[ignore = "requires swtpm installed"]
    fn test_with_swtpm() {
        use std::process::{Command, Stdio};
        use std::time::Duration;

        if Command::new("which").arg("swtpm").output().is_err() {
            panic!("swtpm not found. Install: sudo apt install swtpm");
        }

        let mut swtpm = Command::new("swtpm")
            .args([
                "socket",
                "--tpmstate",
                "dir=/tmp/kms-swtpm-test",
                "--tpm2",
                "--server",
                "type=tcp,port=2321",
                "--ctrl",
                "type=tcp,port=2322",
                "--flags",
                "not-need-init",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start swtpm");
        std::thread::sleep(Duration::from_millis(500));

        let tpm = SoftwareTpm::new();
        let i = PcrIndex::KmsApp;
        let v = tpm.pcr_read(i).unwrap();
        tpm.pcr_extend(i, b"test").unwrap();
        assert_ne!(tpm.pcr_read(i).unwrap(), v);

        let _ = swtpm.kill();
        let _ = swtpm.wait();
        let _ = std::fs::remove_dir_all("/tmp/kms-swtpm-test");
    }
}
