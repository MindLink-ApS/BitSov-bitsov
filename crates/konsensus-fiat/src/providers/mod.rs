//! Fiat rate provider implementations.
//!
//! Each module implements ["crate::FiatRateProvider"] for a specific upstream
//! data source.  Callers select a provider at startup and inject it as
//! "Arc<dyn FiatRateProvider>".

pub mod mempool_space;

pub use mempool_space::MempoolSpaceProvider;
