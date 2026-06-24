//! TPM 2.0 可信根接口（等保四级）
//!
//! 定义 TrustedPlatformModule trait，以及 SoftwareTpm（纯软件模拟）
//! 和 TssTpm（tss-esapi 硬件对接）两套实现。

pub mod software_tpm;
#[cfg(feature = "tpm")]
pub mod tss_tpm;

pub use software_tpm::SoftwareTpm;
#[cfg(feature = "tpm")]
pub use tss_tpm::TssTpm;

use crate::Error;

/// TPM 操作结果
pub type TpmResult<T> = std::result::Result<T, Error>;

/// TPM 支持级别
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmLevel {
    /// 无 TPM 硬件，软件模拟
    None,
    /// TPM 2.0 可用
    Tpm20,
}

/// TPM 平台度量寄存器（PCR）索引
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcrIndex {
    Pcr0 = 0,
    Pcr1 = 1,
    Pcr2 = 2,
    Pcr5 = 5,
    Pcr8 = 8,
    Pcr11 = 11,
    KmsApp = 16,
}

/// TPM 可信任根接口
pub trait TrustedPlatformModule: Send + Sync {
    fn level(&self) -> TpmLevel;
    fn pcr_extend(&self, index: PcrIndex, data: &[u8]) -> TpmResult<()>;
    fn pcr_read(&self, index: PcrIndex) -> TpmResult<Vec<u8>>;
    fn seal(&self, index: PcrIndex, data: &[u8]) -> TpmResult<Vec<u8>>;
    fn unseal(&self, index: PcrIndex, sealed: &[u8]) -> TpmResult<Vec<u8>>;
    fn get_random(&self, length: usize) -> TpmResult<Vec<u8>>;
    fn attest(&self, challenge: &[u8]) -> TpmResult<Vec<u8>>;
}
