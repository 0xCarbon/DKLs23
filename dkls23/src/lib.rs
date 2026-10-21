//! DKLs23 Threshold ECDSA — umbrella crate.
//!
//! Re-exports the curve-generic core at the crate root and each curve
//! instantiation as a module, selected by features:
//!
//! - `secp256k1` (default): `secp256k1` — Ethereum, Bitcoin, Litecoin,
//!   Dogecoin, Bitcoin Cash, Cosmos, TRON, XRP, Filecoin, Tezos
//! - `secp256r1`: `secp256r1` — NEO3, Sui, Tezos
//! - `serde` (default): serialization of key shares and protocol messages
//!
//! ```toml
//! [dependencies]
//! dkls23 = { version = "0.6", features = ["secp256r1"] }
//! ```
//!
//! The curve crates can also be used directly: [`dkls23-core`], [`dkls23-secp256k1`]
//! and [`dkls23-secp256r1`].
//!
//! [`dkls23-core`]: https://crates.io/crates/dkls23-core
//! [`dkls23-secp256k1`]: https://crates.io/crates/dkls23-secp256k1
//! [`dkls23-secp256r1`]: https://crates.io/crates/dkls23-secp256r1

pub use dkls23_core::*;

/// secp256k1 instantiation: type aliases and address derivation for
/// Ethereum, Bitcoin, Litecoin, Dogecoin, Bitcoin Cash, Cosmos, TRON, XRP,
/// Filecoin and Tezos.
#[cfg(feature = "secp256k1")]
pub use dkls23_secp256k1 as secp256k1;

/// NIST P-256 instantiation: type aliases and NEO3, Sui and Tezos address
/// derivation.
#[cfg(feature = "secp256r1")]
pub use dkls23_secp256r1 as secp256r1;
