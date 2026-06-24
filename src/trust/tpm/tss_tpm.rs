//! TPM 2.0 硬件实现（通过 TSS2 ESAPI）

use crate::trust::tpm::{PcrIndex, TpmLevel, TpmResult, TrustedPlatformModule};
use crate::Error;
#[cfg(feature = "tpm")]
use std::str::FromStr;

/// TPM 2.0 硬件实现
pub struct TssTpm {
    tcti: Option<String>,
}

impl TssTpm {
    /// 使用 TCTI 环境变量连接
    pub fn connect() -> TpmResult<Self> {
        #[cfg(feature = "tpm")]
        {
            let _ = Self::new_context(None)?;
            tracing::info!("TPM 2.0 connected");
            Ok(Self { tcti: None })
        }
        #[cfg(not(feature = "tpm"))]
        {
            Err(Error::Internal("tpm feature required".into()))
        }
    }

    /// 指定 TCTI 配置连接，例如 `device:/dev/tpmrm0` 或 `swtpm:host=127.0.0.1,port=2321`
    pub fn connect_with_tcti(tcti: &str) -> TpmResult<Self> {
        #[cfg(feature = "tpm")]
        {
            let _ = Self::new_context(Some(tcti.to_string()))?;
            tracing::info!("TPM 2.0 connected via TCTI: {}", tcti);
            Ok(Self {
                tcti: Some(tcti.to_string()),
            })
        }
        #[cfg(not(feature = "tpm"))]
        {
            let _ = tcti;
            Err(Error::Internal("tpm feature required".into()))
        }
    }

    /// 创建 tss_esapi Context（tpm feature 可用时）
    #[cfg(feature = "tpm")]
    fn new_context(tcti: Option<String>) -> TpmResult<tss_esapi::Context> {
        use tss_esapi::{Context, TctiNameConf};
        let tcti_conf = if let Some(tcti) = tcti {
            TctiNameConf::from_str(&tcti).map_err(|e| Error::Internal(format!("TCTI: {}", e)))?
        } else {
            TctiNameConf::from_environment_variable()
                .map_err(|e| Error::Internal(format!("TCTI: {}", e)))?
        };
        Context::new(tcti_conf).map_err(|e| Error::Internal(format!("Context: {}", e)))
    }
}

impl TrustedPlatformModule for TssTpm {
    fn level(&self) -> TpmLevel {
        TpmLevel::Tpm20
    }

    fn pcr_extend(&self, index: PcrIndex, data: &[u8]) -> TpmResult<()> {
        #[cfg(feature = "tpm")]
        {
            use tss_esapi::{
                handles::PcrHandle,
                interface_types::algorithm::HashingAlgorithm,
                structures::{Digest, DigestValues},
            };
            let mut ctx = Self::new_context(self.tcti.clone())?;
            let handle = match index {
                PcrIndex::Pcr0 => PcrHandle::Pcr0,
                PcrIndex::Pcr1 => PcrHandle::Pcr1,
                PcrIndex::Pcr2 => PcrHandle::Pcr2,
                PcrIndex::Pcr5 => PcrHandle::Pcr5,
                PcrIndex::Pcr8 => PcrHandle::Pcr8,
                PcrIndex::Pcr11 => PcrHandle::Pcr11,
                PcrIndex::KmsApp => PcrHandle::Pcr16,
            };
            let digest = Digest::try_from(data.to_vec())
                .map_err(|e| Error::Internal(format!("Digest: {}", e)))?;
            let mut dv = DigestValues::new();
            dv.set(HashingAlgorithm::Sha256, digest);
            ctx.pcr_extend(handle, dv)
                .map_err(|e| Error::Internal(format!("extend: {}", e)))?;
            Ok(())
        }
        #[cfg(not(feature = "tpm"))]
        {
            let _ = (index, data);
            Err(Error::Internal("tpm feature required".into()))
        }
    }

    fn pcr_read(&self, index: PcrIndex) -> TpmResult<Vec<u8>> {
        #[cfg(feature = "tpm")]
        {
            use tss_esapi::{
                interface_types::algorithm::HashingAlgorithm,
                structures::{PcrSelectionListBuilder, PcrSlot},
            };
            let mut ctx = Self::new_context(self.tcti.clone())?;
            let slot = PcrSlot::try_from(index as u32)
                .map_err(|e| Error::Internal(format!("slot: {}", e)))?;
            let selection = PcrSelectionListBuilder::new()
                .with_selection(HashingAlgorithm::Sha256, &[slot])
                .build()
                .map_err(|e| Error::Internal(format!("sel: {}", e)))?;
            let (_count, _sel_list, pcrs) = ctx
                .pcr_read(selection)
                .map_err(|e| Error::Internal(format!("read: {}", e)))?;
            let digests = pcrs.value();
            Ok(digests
                .first()
                .map(|d| d.value().to_vec())
                .unwrap_or_default())
        }
        #[cfg(not(feature = "tpm"))]
        {
            let _ = index;
            Err(Error::Internal("tpm feature required".into()))
        }
    }

    fn seal(&self, _index: PcrIndex, _data: &[u8]) -> TpmResult<Vec<u8>> {
        Err(Error::Internal("seal needs TPM policy".into()))
    }

    fn unseal(&self, _index: PcrIndex, _sealed: &[u8]) -> TpmResult<Vec<u8>> {
        Err(Error::Internal("unseal needs TPM policy".into()))
    }

    fn get_random(&self, length: usize) -> TpmResult<Vec<u8>> {
        #[cfg(feature = "tpm")]
        {
            let mut ctx = Self::new_context(self.tcti.clone())?;
            ctx.get_random(length)
                .map(|d| d.value().to_vec())
                .map_err(|e| Error::Internal(format!("rand: {}", e)))
        }
        #[cfg(not(feature = "tpm"))]
        {
            let mut buf = vec![0u8; length];
            getrandom::getrandom(&mut buf).map_err(|e| Error::Internal(format!("rng: {}", e)))?;
            Ok(buf)
        }
    }

    fn attest(&self, _challenge: &[u8]) -> TpmResult<Vec<u8>> {
        Err(Error::Internal("attestation needs AIK".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires TPM hardware or swtpm (set TCTI env var)"]
    fn test_tss_tpm_connect() {
        let tpm = TssTpm::connect();
        assert!(tpm.is_ok(), "TssTpm::connect() failed - is TCTI env set?");
        let tpm = tpm.unwrap();
        assert_eq!(tpm.level(), TpmLevel::Tpm20);
    }

    #[test]
    #[ignore = "requires TPM hardware or swtpm"]
    fn test_tss_tpm_get_random() {
        let tpm = TssTpm::connect().unwrap();
        let r1 = tpm.get_random(16).unwrap();
        let r2 = tpm.get_random(16).unwrap();
        assert_eq!(r1.len(), 16);
        assert_eq!(r2.len(), 16);
        assert_ne!(r1, r2, "hardware random should not repeat");
    }

    #[test]
    #[ignore = "requires TPM hardware or swtpm"]
    fn test_tss_tpm_seal_unseal_fails() {
        let tpm = TssTpm::connect().unwrap();
        assert!(
            tpm.seal(PcrIndex::Pcr11, b"test").is_err(),
            "TssTpm seal should fail (needs TPM policy)"
        );
        assert!(
            tpm.unseal(PcrIndex::Pcr11, b"test").is_err(),
            "TssTpm unseal should fail (needs TPM policy)"
        );
    }
}
