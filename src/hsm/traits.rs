use crate::Error;

pub type HsmResult<T> = std::result::Result<T, Error>;

pub use crate::crypto::traits::KekProvider;

pub trait KekProviderFactory: Send + Sync {
    fn create_provider(&self, config: &crate::config::HsmConfig)
        -> HsmResult<Box<dyn KekProvider>>;
}
