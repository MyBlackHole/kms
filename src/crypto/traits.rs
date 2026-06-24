use crate::Error;

pub type CryptoResult<T> = std::result::Result<T, Error>;

pub trait SymmetricCrypto: Send + Sync {
    fn encrypt(&self, key: &[u8], plaintext: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>>;
    fn decrypt(&self, key: &[u8], ciphertext: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>>;
    fn key_len(&self) -> usize;
    fn nonce_len(&self) -> usize;
    fn tag_len(&self) -> usize;
}

pub trait HashEngine: Send + Sync {
    fn hash(&self, data: &[u8]) -> Vec<u8>;
    fn hash_len(&self) -> usize;
    fn hmac(&self, key: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>>;
}

pub trait SignEngine: Send + Sync {
    fn generate_keypair(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)>;
    fn sign(&self, private_key: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>>;
    fn verify(&self, public_key: &[u8], data: &[u8], signature: &[u8]) -> CryptoResult<bool>;
}

pub trait Kdf: Send + Sync {
    fn derive_key(
        &self,
        seed: &[u8],
        salt: &[u8],
        info: &[u8],
        key_len: usize,
    ) -> CryptoResult<Vec<u8>>;
}

pub trait KekProvider: Send + Sync {
    fn name(&self) -> &str;
    fn wrap_key(&self, key_id: &str, key_version: u32, plaintext: &[u8]) -> CryptoResult<Vec<u8>>;
    fn unwrap_key(&self, key_id: &str, key_version: u32) -> CryptoResult<Vec<u8>>;
    fn generate_random(&self, length: usize) -> CryptoResult<Vec<u8>>;
    fn is_hardware_backed(&self) -> bool;
}
