use crate::crypto::traits::{CryptoResult, HashEngine};

pub struct Sm3Engine;

impl Default for Sm3Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Sm3Engine {
    pub fn new() -> Self {
        Self
    }
}

impl HashEngine for Sm3Engine {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        use libsm::sm3::hash::Sm3Hash;
        let mut hasher = Sm3Hash::new(data);
        hasher.get_hash().to_vec()
    }

    fn hash_len(&self) -> usize {
        32
    }

    fn hmac(&self, key: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>> {
        let block_size = 64;
        let mut k = if key.len() > block_size {
            self.hash(key)
        } else {
            key.to_vec()
        };

        k.resize(block_size, 0);

        let mut ipad = vec![0x36u8; block_size];
        let mut opad = vec![0x5Cu8; block_size];
        for i in 0..block_size {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }

        let mut inner_data = Vec::with_capacity(block_size + data.len());
        inner_data.extend_from_slice(&ipad);
        inner_data.extend_from_slice(data);
        let inner_hash = self.hash(&inner_data);

        let mut outer_data = Vec::with_capacity(block_size + inner_hash.len());
        outer_data.extend_from_slice(&opad);
        outer_data.extend_from_slice(&inner_hash);
        Ok(self.hash(&outer_data))
    }
}
