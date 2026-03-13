//! DKLs23 Threshold ECDSA — secp256r1 (NIST P-256) instantiation.
//!
//! This crate provides concrete type aliases for the NIST P-256 curve
//! and address derivation functions for multiple blockchains:
//!
//! - **NEO3**: [`compute_neo3_address`]
//! - **Sui**: [`compute_sui_address`]

pub use dkls23_core::*;

use blake2::{digest::consts::U32, Blake2b, Digest as Blake2Digest};
use elliptic_curve::sec1::ToSec1Point;
use ripemd::Ripemd160;
use sha2::Sha256;

/// Type alias for a DKLs23 party using NIST P-256.
pub type Party = dkls23_core::protocols::Party<p256::NistP256>;

/// Type alias for a DKLs23 public key package using NIST P-256.
pub type PublicKeyPackage = dkls23_core::protocols::PublicKeyPackage<p256::NistP256>;

/// Blake2b-256 type alias (32-byte output).
type Blake2b256 = Blake2b<U32>;

// ---------------------------------------------------------------------------
// NEO3
// ---------------------------------------------------------------------------

/// NEO3 address version byte.
const NEO3_ADDRESS_VERSION: u8 = 0x35;

/// Computes a NEO3 address from a NIST P-256 public key.
///
/// The derivation follows the NEO3 specification:
/// 1. Compress the public key (33 bytes SEC-1 format)
/// 2. Build a verification script: `[0x0C, 0x21, <compressed_pubkey>, 0x41, 0x56, 0xe7, 0xb3, 0x27]`
/// 3. Compute the script hash: `RIPEMD160(SHA256(verification_script))`
/// 4. Encode as a Base58Check address: `Base58(0x35 || script_hash || checksum)`
///    where checksum = first 4 bytes of `SHA256(SHA256(0x35 || script_hash))`
///
/// Returns a 34-character address starting with `N`.
#[must_use]
pub fn compute_neo3_address(pk: &p256::AffinePoint) -> String {
    // Step 1: Compressed public key (33 bytes)
    let compressed_pk = pk.to_sec1_point(true);
    let pk_bytes = compressed_pk.as_bytes();

    // Step 2: Build verification script (40 bytes)
    // PUSHDATA1 (0x0C) + length (0x21 = 33) + pubkey + SYSCALL (0x41) +
    // System.Crypto.CheckSig hash (0x56e7b327)
    let mut script = Vec::with_capacity(40);
    script.push(0x0C); // PUSHDATA1
    script.push(0x21); // 33 bytes
    script.extend_from_slice(pk_bytes);
    script.push(0x41); // SYSCALL
    script.extend_from_slice(&[0x56, 0xe7, 0xb3, 0x27]); // System.Crypto.CheckSig

    // Step 3: Script hash = RIPEMD160(SHA256(script))
    let sha256_hash = Sha256::digest(&script);
    let script_hash = Ripemd160::digest(sha256_hash);

    // Step 4: Base58Check encode with version byte 0x35
    let mut payload = Vec::with_capacity(25);
    payload.push(NEO3_ADDRESS_VERSION);
    payload.extend_from_slice(&script_hash);

    let checksum = double_sha256_checksum(&payload);
    payload.extend_from_slice(&checksum);

    bs58::encode(payload).into_string()
}

/// [`AddressScheme`] implementation for NEO3 addresses on NIST P-256.
pub struct Neo3Address;

impl dkls23_core::curve::AddressScheme<p256::NistP256> for Neo3Address {
    fn compute_address(pk: &p256::AffinePoint) -> String {
        compute_neo3_address(pk)
    }
}

// ---------------------------------------------------------------------------
// Sui
// ---------------------------------------------------------------------------

/// Sui flag byte for ECDSA secp256r1 keys.
const SUI_SECP256R1_FLAG: u8 = 0x02;

/// Computes a Sui address from a NIST P-256 (secp256r1) public key.
///
/// The address is `BLAKE2b-256(flag_byte || compressed_pubkey)` where
/// `flag_byte = 0x02` for secp256r1, encoded as `0x`-prefixed lowercase hex.
///
/// Returns a 66-character hex string (e.g. `0x...`).
#[must_use]
pub fn compute_sui_address(pk: &p256::AffinePoint) -> String {
    let compressed_pk = pk.to_sec1_point(true);
    let pk_bytes = compressed_pk.as_bytes();

    let mut hasher = Blake2b256::new();
    Blake2Digest::update(&mut hasher, [SUI_SECP256R1_FLAG]);
    Blake2Digest::update(&mut hasher, pk_bytes);
    let hash = hasher.finalize();

    format!("0x{}", hex::encode(hash))
}

/// [`AddressScheme`] implementation for Sui addresses on NIST P-256.
pub struct SuiAddress;

impl dkls23_core::curve::AddressScheme<p256::NistP256> for SuiAddress {
    fn compute_address(pk: &p256::AffinePoint) -> String {
        compute_sui_address(pk)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns the first 4 bytes of `SHA256(SHA256(data))`.
fn double_sha256_checksum(data: &[u8]) -> [u8; 4] {
    let hash = Sha256::digest(Sha256::digest(data));
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
    use elliptic_curve::CurveArithmetic;
    use rustcrypto_group::prime::PrimeCurveAffine;

    fn test_pubkey() -> p256::AffinePoint {
        <p256::NistP256 as CurveArithmetic>::AffinePoint::generator()
    }

    #[test]
    fn test_neo3_address() {
        let pk = test_pubkey();
        let address = compute_neo3_address(&pk);
        assert!(
            address.starts_with('N'),
            "NEO3 address should start with 'N', got: {address}"
        );
        assert_eq!(
            address.len(),
            34,
            "NEO3 address should be 34 chars, got: {}",
            address.len()
        );
    }

    #[test]
    fn test_sui_address() {
        let pk = test_pubkey();
        let address = compute_sui_address(&pk);
        assert!(
            address.starts_with("0x"),
            "Sui address should start with '0x', got: {address}"
        );
        assert_eq!(
            address.len(),
            66,
            "Sui address should be 66 chars (0x + 64 hex), got: {}",
            address.len()
        );
    }
}
