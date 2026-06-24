use zeroize::Zeroize;

pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
        }
    }

    pub fn from(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
        }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl AsRef<[u8]> for SecureBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for SecureBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// 锁定内存页，防止密钥材料被交换到磁盘
#[cfg(target_os = "linux")]
pub fn mlock_region(addr: &[u8]) -> std::io::Result<()> {
    let ret = unsafe { libc::mlock(addr.as_ptr() as *const libc::c_void, addr.len()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn mlock_region(_addr: &[u8]) -> std::io::Result<()> {
    eprintln!("[WARN] mlock 仅在 Linux 上可用，当前平台跳过");
    Ok(())
}

/// 解锁内存页
#[cfg(target_os = "linux")]
pub fn munlock_region(addr: &[u8]) -> std::io::Result<()> {
    let ret = unsafe { libc::munlock(addr.as_ptr() as *const libc::c_void, addr.len()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn munlock_region(_addr: &[u8]) -> std::io::Result<()> {
    Ok(())
}
