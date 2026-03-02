//! RNG abstraction for test determinism.
//!
//! When the `insecure-rng` feature is enabled **and** the crate is compiled in test mode
//! (`cfg(test)`), a deterministic `StdRng` seeded with [`DEFAULT_SEED`] is used. In all
//! other configurations — including `cargo build --features insecure-rng` — the secure
//! `ThreadRng` is returned. This makes it impossible to accidentally ship insecure RNG
//! in production, even if the feature flag is left on.

#[cfg(all(test, feature = "insecure-rng"))]
use rand::rngs::StdRng;
#[cfg(not(all(test, feature = "insecure-rng")))]
use rand::rngs::ThreadRng;
#[cfg(all(test, feature = "insecure-rng"))]
use rand::SeedableRng;

#[cfg(all(test, feature = "insecure-rng"))]
pub const DEFAULT_SEED: u64 = 42;

#[cfg(not(all(test, feature = "insecure-rng")))]
pub fn get_rng() -> ThreadRng {
    rand::thread_rng()
}

#[cfg(all(test, feature = "insecure-rng"))]
pub fn get_rng() -> StdRng {
    rand::rngs::StdRng::seed_from_u64(DEFAULT_SEED)
}
