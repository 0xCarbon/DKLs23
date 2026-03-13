//! DKLs23 Threshold ECDSA — secp256k1 instantiation.
//!
//! This crate provides concrete type aliases for the secp256k1 curve
//! and address derivation functions for multiple blockchains:
//!
//! - **Ethereum** (and all EVM chains): [`compute_eth_address`]
//! - **Bitcoin** (P2WPKH / Bech32): [`compute_btc_address`]
//! - **Cosmos** (Bech32 with configurable HRP): [`compute_cosmos_address`]
//! - **TRON** (Base58Check): [`compute_tron_address`]

pub use dkls23_core::*;

use elliptic_curve::sec1::ToSec1Point;
use ripemd::Ripemd160;
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::{Digest as Sha3Digest, Keccak256};

/// Type alias for a DKLs23 party using secp256k1.
pub type Party = dkls23_core::protocols::Party<k256::Secp256k1>;

/// Type alias for a DKLs23 public key package using secp256k1.
pub type PublicKeyPackage = dkls23_core::protocols::PublicKeyPackage<k256::Secp256k1>;

// ---------------------------------------------------------------------------
// Ethereum
// ---------------------------------------------------------------------------

/// Computes an ERC-55 checksummed Ethereum address from a secp256k1 public key.
///
/// The address is derived by hashing the uncompressed SEC-1 public key
/// (without the `04` prefix) with Keccak-256 and taking the last 20 bytes.
/// The mixed-case checksum follows [EIP-55](https://eips.ethereum.org/EIPS/eip-55).
///
/// Works for all EVM-compatible chains (Ethereum, Polygon, BSC, Arbitrum, Optimism, etc.).
#[must_use]
pub fn compute_eth_address(pk: &k256::AffinePoint) -> String {
    let uncompressed_pk = pk.to_sec1_point(false);

    let mut hasher = Keccak256::new();
    Sha3Digest::update(&mut hasher, &uncompressed_pk.as_bytes()[1..]);

    let full_hash = hasher.finalize_reset();
    const ETH_ADDR_OFFSET: usize = 12;
    let address = hex::encode(&full_hash[ETH_ADDR_OFFSET..]);

    Sha3Digest::update(&mut hasher, address.to_lowercase().as_bytes());
    let hash_bytes = hasher.finalize();

    // ERC-55: Mixed-case checksum address encoding
    format!(
        "0x{}",
        address
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if c.is_alphabetic() && (hash_bytes[i / 2] >> (4 * (1 - i % 2)) & 0x0f) >= 8 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect::<String>()
    )
}

/// [`AddressScheme`] implementation for Ethereum addresses on secp256k1.
pub struct EthereumAddress;

impl dkls23_core::curve::AddressScheme<k256::Secp256k1> for EthereumAddress {
    fn compute_address(pk: &k256::AffinePoint) -> String {
        compute_eth_address(pk)
    }
}

// ---------------------------------------------------------------------------
// Bitcoin (P2WPKH / Bech32)
// ---------------------------------------------------------------------------

/// Computes a Bitcoin P2WPKH (Pay-to-Witness-Public-Key-Hash) address from
/// a compressed secp256k1 public key.
///
/// The witness program is `RIPEMD160(SHA256(compressed_pubkey))` (HASH160),
/// encoded as a Bech32 segwit v0 address with the `"bc"` human-readable part.
///
/// Returns a 42-character mainnet address starting with `bc1q`.
#[must_use]
pub fn compute_btc_address(pk: &k256::AffinePoint) -> String {
    compute_btc_address_with_hrp(pk, "bc")
}

/// Computes a Bitcoin P2WPKH address with a custom HRP (human-readable part).
///
/// Use `"bc"` for mainnet, `"tb"` for testnet, `"ltc"` for Litecoin mainnet.
#[must_use]
pub fn compute_btc_address_with_hrp(pk: &k256::AffinePoint, hrp: &str) -> String {
    let compressed_pk = pk.to_sec1_point(true);
    let witness_program = hash160(compressed_pk.as_bytes());

    let hrp = bech32::Hrp::parse(hrp).expect("invalid bech32 HRP");
    bech32::segwit::encode_v0(hrp, &witness_program)
        .expect("witness program encoding should not fail")
}

/// [`AddressScheme`] implementation for Bitcoin P2WPKH addresses.
pub struct BitcoinAddress;

impl dkls23_core::curve::AddressScheme<k256::Secp256k1> for BitcoinAddress {
    fn compute_address(pk: &k256::AffinePoint) -> String {
        compute_btc_address(pk)
    }
}

// ---------------------------------------------------------------------------
// Cosmos (Bech32)
// ---------------------------------------------------------------------------

/// Computes a Cosmos SDK address from a compressed secp256k1 public key.
///
/// The address bytes are `RIPEMD160(SHA256(compressed_pubkey))` (identical to
/// Bitcoin's HASH160), encoded as Bech32 with the `"cosmos"` HRP.
///
/// For other Cosmos chains, use [`compute_cosmos_address_with_hrp`] with
/// the chain's HRP (e.g. `"osmo"`, `"juno"`, `"terra"`, `"atom"`).
#[must_use]
pub fn compute_cosmos_address(pk: &k256::AffinePoint) -> String {
    compute_cosmos_address_with_hrp(pk, "cosmos")
}

/// Computes a Cosmos-style Bech32 address with a custom HRP.
///
/// The same secp256k1 key produces the same underlying 20-byte address;
/// only the human-readable prefix changes between Cosmos chains.
#[must_use]
pub fn compute_cosmos_address_with_hrp(pk: &k256::AffinePoint, hrp: &str) -> String {
    let compressed_pk = pk.to_sec1_point(true);
    let addr_bytes = hash160(compressed_pk.as_bytes());

    let hrp = bech32::Hrp::parse(hrp).expect("invalid bech32 HRP");
    bech32::encode::<bech32::Bech32>(hrp, &addr_bytes).expect("bech32 encoding should not fail")
}

/// [`AddressScheme`] implementation for Cosmos Hub addresses.
pub struct CosmosAddress;

impl dkls23_core::curve::AddressScheme<k256::Secp256k1> for CosmosAddress {
    fn compute_address(pk: &k256::AffinePoint) -> String {
        compute_cosmos_address(pk)
    }
}

// ---------------------------------------------------------------------------
// TRON (Base58Check)
// ---------------------------------------------------------------------------

/// Computes a TRON address from a secp256k1 public key.
///
/// Derivation follows the same initial steps as Ethereum (Keccak-256 of
/// uncompressed pubkey sans `04` prefix, take last 20 bytes), but encodes
/// the result as Base58Check with version byte `0x41`.
///
/// Returns a 34-character address starting with `T`.
#[must_use]
pub fn compute_tron_address(pk: &k256::AffinePoint) -> String {
    let uncompressed_pk = pk.to_sec1_point(false);

    // Keccak-256 of uncompressed pubkey (sans 0x04 prefix)
    let mut hasher = Keccak256::new();
    Sha3Digest::update(&mut hasher, &uncompressed_pk.as_bytes()[1..]);
    let full_hash = hasher.finalize();

    // Take last 20 bytes
    const TRON_ADDR_OFFSET: usize = 12;
    let addr_bytes = &full_hash[TRON_ADDR_OFFSET..];

    // Prepend version byte 0x41
    let mut versioned = Vec::with_capacity(25);
    versioned.push(0x41);
    versioned.extend_from_slice(addr_bytes);

    // Base58Check: double SHA-256 checksum
    let checksum = double_sha256_checksum(&versioned);
    versioned.extend_from_slice(&checksum);

    bs58::encode(versioned).into_string()
}

/// [`AddressScheme`] implementation for TRON addresses.
pub struct TronAddress;

impl dkls23_core::curve::AddressScheme<k256::Secp256k1> for TronAddress {
    fn compute_address(pk: &k256::AffinePoint) -> String {
        compute_tron_address(pk)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// HASH160: `RIPEMD160(SHA256(data))`.
fn hash160(data: &[u8]) -> [u8; 20] {
    let sha_hash = Sha256::digest(data);
    let ripemd_hash = Ripemd160::digest(sha_hash);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripemd_hash);
    out
}

/// Returns the first 4 bytes of `SHA256(SHA256(data))`.
fn double_sha256_checksum(data: &[u8]) -> [u8; 4] {
    let hash = Sha256::digest(&Sha256::digest(data));
    let mut checksum = [0u8; 4];
    checksum.copy_from_slice(&hash[..4]);
    checksum
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use elliptic_curve::ops::Reduce;
    use rustcrypto_group::prime::PrimeCurveAffine;

    fn test_keypair() -> k256::AffinePoint {
        let sk = k256::Scalar::reduce(&k256::U256::from_be_hex(
            "0249815B0D7E186DB61E7A6AAD6226608BB1C48B309EA8903CAB7A7283DA64A5",
        ));
        (k256::AffinePoint::generator() * sk).to_affine()
    }

    #[test]
    fn test_compute_eth_address() {
        // Test vector from https://www.rfctools.com/ethereum-address-test-tool/
        let pk = test_keypair();
        let address = compute_eth_address(&pk);
        assert_eq!(address, "0x2afDdfDF813E567A6f357Da818B16E2dae08599F");
    }

    #[test]
    fn test_compute_btc_address() {
        let pk = test_keypair();
        let address = compute_btc_address(&pk);
        assert!(
            address.starts_with("bc1q"),
            "Bitcoin P2WPKH should start with 'bc1q', got: {address}"
        );
        assert_eq!(
            address.len(),
            42,
            "Bitcoin P2WPKH address should be 42 chars"
        );
    }

    #[test]
    fn test_compute_cosmos_address() {
        let pk = test_keypair();
        let address = compute_cosmos_address(&pk);
        assert!(
            address.starts_with("cosmos1"),
            "Cosmos address should start with 'cosmos1', got: {address}"
        );
    }

    #[test]
    fn test_cosmos_same_bytes_different_hrp() {
        let pk = test_keypair();
        let cosmos = compute_cosmos_address_with_hrp(&pk, "cosmos");
        let osmo = compute_cosmos_address_with_hrp(&pk, "osmo");
        // Same key -> different prefix, same underlying 20 bytes
        assert!(cosmos.starts_with("cosmos1"));
        assert!(osmo.starts_with("osmo1"));
        assert_ne!(cosmos, osmo);
    }

    #[test]
    fn test_compute_tron_address() {
        let pk = test_keypair();
        let address = compute_tron_address(&pk);
        assert!(
            address.starts_with('T'),
            "TRON address should start with 'T', got: {address}"
        );
        assert_eq!(address.len(), 34, "TRON address should be 34 chars");
    }
}
