//! DKLs23 Threshold ECDSA — secp256k1 instantiation.
//!
//! This crate provides concrete type aliases for the secp256k1 curve
//! and address derivation functions for multiple blockchains:
//!
//! - **Ethereum** (and all EVM chains): [`compute_eth_address`]
//! - **Bitcoin** (P2WPKH / Bech32): [`compute_btc_address`]; legacy P2PKH
//!   ([`compute_btc_p2pkh_address`]) and nested SegWit P2SH-P2WPKH
//!   ([`compute_btc_p2sh_p2wpkh_address`])
//! - **Litecoin**: [`compute_ltc_address`] (P2WPKH), [`compute_ltc_p2pkh_address`]
//! - **Dogecoin** (P2PKH): [`compute_doge_address`]
//! - **Bitcoin Cash** (CashAddr): [`compute_bch_address`]
//! - **Cosmos** (Bech32 with configurable HRP): [`compute_cosmos_address`]
//! - **TRON** (Base58Check): [`compute_tron_address`]
//! - **XRP Ledger** (classic address): [`compute_xrp_address`]
//! - **Filecoin** (`f1` secp256k1 address): [`compute_filecoin_address`]
//! - **Tezos** (`tz2`): [`compute_tezos_address`]

pub use dkls23_core::*;

use blake2::digest::consts::{U20, U4};
use blake2::Blake2b;
use elliptic_curve::sec1::ToSec1Point;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

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
    Digest::update(&mut hasher, &uncompressed_pk.as_bytes()[1..]);

    let full_hash = hasher.finalize_reset();
    const ETH_ADDR_OFFSET: usize = 12;
    let address = hex::encode(&full_hash[ETH_ADDR_OFFSET..]);

    Digest::update(&mut hasher, address.to_lowercase().as_bytes());
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

/// [`AddressScheme`](dkls23_core::curve::AddressScheme) implementation for Ethereum addresses on secp256k1.
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
///
/// # Panics
///
/// Panics if `hrp` is not a valid bech32 HRP; use
/// [`try_compute_btc_address_with_hrp`] for untrusted input.
#[must_use]
pub fn compute_btc_address_with_hrp(pk: &k256::AffinePoint, hrp: &str) -> String {
    try_compute_btc_address_with_hrp(pk, hrp).expect("invalid bech32 HRP")
}

/// Like [`compute_btc_address_with_hrp`], returning an error for an
/// invalid HRP.
///
/// # Errors
///
/// Returns [`InvalidHrp`] if `hrp` is not a valid bech32 HRP for a segwit
/// address.
pub fn try_compute_btc_address_with_hrp(
    pk: &k256::AffinePoint,
    hrp: &str,
) -> Result<String, InvalidHrp> {
    let compressed_pk = pk.to_sec1_point(true);
    let witness_program = hash160(compressed_pk.as_bytes());

    let hrp = bech32::Hrp::parse(hrp).map_err(|_| InvalidHrp)?;
    bech32::segwit::encode_v0(hrp, &witness_program).map_err(|_| InvalidHrp)
}

/// [`AddressScheme`](dkls23_core::curve::AddressScheme) implementation for Bitcoin P2WPKH addresses.
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
///
/// # Panics
///
/// Panics if `hrp` is not a valid bech32 HRP; use
/// [`try_compute_cosmos_address_with_hrp`] for untrusted input.
#[must_use]
pub fn compute_cosmos_address_with_hrp(pk: &k256::AffinePoint, hrp: &str) -> String {
    try_compute_cosmos_address_with_hrp(pk, hrp).expect("invalid bech32 HRP")
}

/// Like [`compute_cosmos_address_with_hrp`], returning an error for an
/// invalid HRP.
///
/// # Errors
///
/// Returns [`InvalidHrp`] if `hrp` is not a valid bech32 HRP or the address
/// would be too long.
pub fn try_compute_cosmos_address_with_hrp(
    pk: &k256::AffinePoint,
    hrp: &str,
) -> Result<String, InvalidHrp> {
    let compressed_pk = pk.to_sec1_point(true);
    let addr_bytes = hash160(compressed_pk.as_bytes());

    let hrp = bech32::Hrp::parse(hrp).map_err(|_| InvalidHrp)?;
    bech32::encode::<bech32::Bech32>(hrp, &addr_bytes).map_err(|_| InvalidHrp)
}

/// The human-readable part given for a bech32 address is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidHrp;

impl std::fmt::Display for InvalidHrp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid bech32 human-readable part")
    }
}

impl std::error::Error for InvalidHrp {}

/// [`AddressScheme`](dkls23_core::curve::AddressScheme) implementation for Cosmos Hub addresses.
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
    Digest::update(&mut hasher, &uncompressed_pk.as_bytes()[1..]);
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

/// [`AddressScheme`](dkls23_core::curve::AddressScheme) implementation for TRON addresses.
pub struct TronAddress;

impl dkls23_core::curve::AddressScheme<k256::Secp256k1> for TronAddress {
    fn compute_address(pk: &k256::AffinePoint) -> String {
        compute_tron_address(pk)
    }
}

// ---------------------------------------------------------------------------
// Bitcoin family (Base58Check: legacy P2PKH and nested SegWit)
// ---------------------------------------------------------------------------

/// Bitcoin mainnet P2PKH version byte.
const BTC_P2PKH_VERSION: u8 = 0x00;
/// Bitcoin mainnet P2SH version byte.
const BTC_P2SH_VERSION: u8 = 0x05;
/// Litecoin mainnet P2PKH version byte.
const LTC_P2PKH_VERSION: u8 = 0x30;
/// Dogecoin mainnet P2PKH version byte.
const DOGE_P2PKH_VERSION: u8 = 0x1e;

/// Computes a Bitcoin legacy P2PKH address (`1...`) from the compressed
/// public key: `Base58Check(0x00 || HASH160(compressed_pubkey))`.
#[must_use]
pub fn compute_btc_p2pkh_address(pk: &k256::AffinePoint) -> String {
    p2pkh_address(pk, BTC_P2PKH_VERSION)
}

/// Computes a Bitcoin nested SegWit P2SH-P2WPKH address (`3...`).
///
/// The redeem script is `OP_0 <HASH160(compressed_pubkey)>`, and the address
/// is `Base58Check(0x05 || HASH160(redeem_script))` (BIP-49 / BIP-141).
#[must_use]
pub fn compute_btc_p2sh_p2wpkh_address(pk: &k256::AffinePoint) -> String {
    let mut redeem_script = Vec::with_capacity(22);
    redeem_script.extend_from_slice(&[0x00, 0x14]); // OP_0, push 20 bytes
    redeem_script.extend_from_slice(&hash160(pk.to_sec1_point(true).as_bytes()));
    base58check(&[BTC_P2SH_VERSION], &hash160(&redeem_script))
}

/// Computes a Litecoin native SegWit P2WPKH address (`ltc1q...`).
#[must_use]
pub fn compute_ltc_address(pk: &k256::AffinePoint) -> String {
    compute_btc_address_with_hrp(pk, "ltc")
}

/// Computes a Litecoin legacy P2PKH address (`L...`):
/// `Base58Check(0x30 || HASH160(compressed_pubkey))`.
#[must_use]
pub fn compute_ltc_p2pkh_address(pk: &k256::AffinePoint) -> String {
    p2pkh_address(pk, LTC_P2PKH_VERSION)
}

/// Computes a Dogecoin P2PKH address (`D...`):
/// `Base58Check(0x1e || HASH160(compressed_pubkey))`.
#[must_use]
pub fn compute_doge_address(pk: &k256::AffinePoint) -> String {
    p2pkh_address(pk, DOGE_P2PKH_VERSION)
}

/// [`AddressScheme`](dkls23_core::curve::AddressScheme) implementation for Bitcoin legacy P2PKH addresses.
pub struct BitcoinP2pkhAddress;

impl dkls23_core::curve::AddressScheme<k256::Secp256k1> for BitcoinP2pkhAddress {
    fn compute_address(pk: &k256::AffinePoint) -> String {
        compute_btc_p2pkh_address(pk)
    }
}

/// [`AddressScheme`](dkls23_core::curve::AddressScheme) implementation for Bitcoin P2SH-P2WPKH addresses.
pub struct BitcoinP2shP2wpkhAddress;

impl dkls23_core::curve::AddressScheme<k256::Secp256k1> for BitcoinP2shP2wpkhAddress {
    fn compute_address(pk: &k256::AffinePoint) -> String {
        compute_btc_p2sh_p2wpkh_address(pk)
    }
}

/// [`AddressScheme`](dkls23_core::curve::AddressScheme) implementation for Litecoin P2WPKH addresses.
pub struct LitecoinAddress;

impl dkls23_core::curve::AddressScheme<k256::Secp256k1> for LitecoinAddress {
    fn compute_address(pk: &k256::AffinePoint) -> String {
        compute_ltc_address(pk)
    }
}

/// [`AddressScheme`](dkls23_core::curve::AddressScheme) implementation for Litecoin P2PKH addresses.
pub struct LitecoinP2pkhAddress;

impl dkls23_core::curve::AddressScheme<k256::Secp256k1> for LitecoinP2pkhAddress {
    fn compute_address(pk: &k256::AffinePoint) -> String {
        compute_ltc_p2pkh_address(pk)
    }
}

/// [`AddressScheme`](dkls23_core::curve::AddressScheme) implementation for Dogecoin P2PKH addresses.
pub struct DogecoinAddress;

impl dkls23_core::curve::AddressScheme<k256::Secp256k1> for DogecoinAddress {
    fn compute_address(pk: &k256::AffinePoint) -> String {
        compute_doge_address(pk)
    }
}

// ---------------------------------------------------------------------------
// Bitcoin Cash (CashAddr)
// ---------------------------------------------------------------------------

/// CashAddr base32 alphabet (same as Bech32).
const CASHADDR_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Computes a Bitcoin Cash P2PKH CashAddr address (`bitcoincash:q...`) for
/// `HASH160(compressed_pubkey)`.
#[must_use]
pub fn compute_bch_address(pk: &k256::AffinePoint) -> String {
    cashaddr_encode(
        "bitcoincash",
        0x00,
        &hash160(pk.to_sec1_point(true).as_bytes()),
    )
}

/// [`AddressScheme`](dkls23_core::curve::AddressScheme) implementation for Bitcoin Cash CashAddr addresses.
pub struct BitcoinCashAddress;

impl dkls23_core::curve::AddressScheme<k256::Secp256k1> for BitcoinCashAddress {
    fn compute_address(pk: &k256::AffinePoint) -> String {
        compute_bch_address(pk)
    }
}

/// Encodes `version || hash` as a CashAddr string with the given prefix.
fn cashaddr_encode(prefix: &str, version: u8, hash: &[u8]) -> String {
    let mut payload = Vec::with_capacity(1 + hash.len());
    payload.push(version);
    payload.extend_from_slice(hash);
    let data = to_5bit_groups(&payload);

    let mut checksum_input: Vec<u8> = prefix.bytes().map(|b| b & 0x1f).collect();
    checksum_input.push(0);
    checksum_input.extend_from_slice(&data);
    checksum_input.extend_from_slice(&[0; 8]);
    let checksum = cashaddr_polymod(&checksum_input);

    let mut out = String::with_capacity(prefix.len() + 1 + data.len() + 8);
    out.push_str(prefix);
    out.push(':');
    for value in data
        .iter()
        .copied()
        .chain((0..8).map(|i| ((checksum >> (5 * (7 - i))) & 0x1f) as u8))
    {
        out.push(CASHADDR_CHARSET[value as usize] as char);
    }
    out
}

/// The CashAddr BCH-code checksum over 5-bit values.
fn cashaddr_polymod(values: &[u8]) -> u64 {
    const GENERATORS: [u64; 5] = [
        0x98_f2bc_8e61,
        0x79_b76d_99e2,
        0xf3_3e5f_b3c4,
        0xae_2eab_e2a8,
        0x1e_4f43_e470,
    ];
    let mut c: u64 = 1;
    for &d in values {
        let c0 = c >> 35;
        c = ((c & 0x07_ffff_ffff) << 5) ^ u64::from(d);
        for (i, generator) in GENERATORS.iter().enumerate() {
            if (c0 >> i) & 1 == 1 {
                c ^= generator;
            }
        }
    }
    c ^ 1
}

/// Splits bytes into 5-bit groups, most significant first, zero-padding
/// the last group.
fn to_5bit_groups(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 8 / 5 + 1);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &byte in data {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((acc >> bits) & 0x1f) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 0x1f) as u8);
    }
    out
}

// ---------------------------------------------------------------------------
// XRP Ledger
// ---------------------------------------------------------------------------

/// Computes an XRP Ledger classic address (`r...`) from a secp256k1 key.
///
/// The account ID is `HASH160(compressed_pubkey)`, encoded as Base58Check
/// with version byte `0x00` in the XRP Ledger alphabet.
#[must_use]
pub fn compute_xrp_address(pk: &k256::AffinePoint) -> String {
    let mut payload = Vec::with_capacity(25);
    payload.push(0x00);
    payload.extend_from_slice(&hash160(pk.to_sec1_point(true).as_bytes()));
    let checksum = double_sha256_checksum(&payload);
    payload.extend_from_slice(&checksum);
    bs58::encode(payload)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_string()
}

/// [`AddressScheme`](dkls23_core::curve::AddressScheme) implementation for XRP Ledger classic addresses.
pub struct XrpAddress;

impl dkls23_core::curve::AddressScheme<k256::Secp256k1> for XrpAddress {
    fn compute_address(pk: &k256::AffinePoint) -> String {
        compute_xrp_address(pk)
    }
}

// ---------------------------------------------------------------------------
// Filecoin
// ---------------------------------------------------------------------------

/// Filecoin protocol byte for secp256k1 addresses.
const FILECOIN_SECP256K1_PROTOCOL: u8 = 0x01;

/// Computes a Filecoin mainnet secp256k1 address (`f1...`).
///
/// The payload is `BLAKE2b-160(uncompressed_pubkey)`, the checksum is
/// `BLAKE2b-32(0x01 || payload)`, and the address is `"f1"` followed by the
/// lowercase, unpadded RFC 4648 base32 encoding of `payload || checksum`.
#[must_use]
pub fn compute_filecoin_address(pk: &k256::AffinePoint) -> String {
    let payload = Blake2b::<U20>::digest(pk.to_sec1_point(false).as_bytes());
    filecoin_address_from_payload(&payload)
}

/// Encodes a protocol-1 Filecoin payload with its checksum.
fn filecoin_address_from_payload(payload: &[u8]) -> String {
    let mut hasher = Blake2b::<U4>::new();
    Digest::update(&mut hasher, [FILECOIN_SECP256K1_PROTOCOL]);
    Digest::update(&mut hasher, payload);
    let checksum = hasher.finalize();

    let mut bytes = payload.to_vec();
    bytes.extend_from_slice(&checksum);
    format!("f1{}", base32_lower_nopad(&bytes))
}

/// RFC 4648 base32, lowercase, without padding.
fn base32_lower_nopad(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    to_5bit_groups(data)
        .into_iter()
        .map(|value| ALPHABET[value as usize] as char)
        .collect()
}

/// [`AddressScheme`](dkls23_core::curve::AddressScheme) implementation for Filecoin `f1` addresses.
pub struct FilecoinAddress;

impl dkls23_core::curve::AddressScheme<k256::Secp256k1> for FilecoinAddress {
    fn compute_address(pk: &k256::AffinePoint) -> String {
        compute_filecoin_address(pk)
    }
}

// ---------------------------------------------------------------------------
// Tezos
// ---------------------------------------------------------------------------

/// Tezos Base58Check prefix for secp256k1 public key hashes (`tz2`).
const TEZOS_TZ2_PREFIX: [u8; 3] = [6, 161, 161];

/// Computes a Tezos `tz2` address from a secp256k1 public key:
/// `Base58Check([6, 161, 161] || BLAKE2b-160(compressed_pubkey))`.
#[must_use]
pub fn compute_tezos_address(pk: &k256::AffinePoint) -> String {
    let hash = Blake2b::<U20>::digest(pk.to_sec1_point(true).as_bytes());
    base58check(&TEZOS_TZ2_PREFIX, &hash)
}

/// [`AddressScheme`](dkls23_core::curve::AddressScheme) implementation for Tezos `tz2` addresses.
pub struct TezosAddress;

impl dkls23_core::curve::AddressScheme<k256::Secp256k1> for TezosAddress {
    fn compute_address(pk: &k256::AffinePoint) -> String {
        compute_tezos_address(pk)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// `Base58Check(version || HASH160(compressed_pubkey))`.
fn p2pkh_address(pk: &k256::AffinePoint, version: u8) -> String {
    base58check(&[version], &hash160(pk.to_sec1_point(true).as_bytes()))
}

/// Bitcoin-alphabet Base58Check of `prefix || payload`.
fn base58check(prefix: &[u8], payload: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(prefix.len() + payload.len() + 4);
    bytes.extend_from_slice(prefix);
    bytes.extend_from_slice(payload);
    let checksum = double_sha256_checksum(&bytes);
    bytes.extend_from_slice(&checksum);
    bs58::encode(bytes).into_string()
}

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
    use elliptic_curve::ops::Reduce;
    use group::CurveAffine;

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
        assert_eq!(address, "bc1qgzz5kypj5dc9c9sndewpa8x560spd3pymcqvqp");
    }

    #[test]
    fn test_compute_cosmos_address() {
        let pk = test_keypair();
        let address = compute_cosmos_address(&pk);
        assert!(
            address.starts_with("cosmos1"),
            "Cosmos address should start with 'cosmos1', got: {address}"
        );
        assert_eq!(address, "cosmos1gzz5kypj5dc9c9sndewpa8x560spd3pydz78yv");
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
        assert_eq!(address, "TDtXWdEzw5XAtumHt7M143Y2bajq11LNJu");
    }

    fn generator() -> k256::AffinePoint {
        k256::AffinePoint::generator()
    }

    /// Expected addresses come from an independent implementation, which
    /// reproduces the BIP-173 HASH160 and address of the generator, the
    /// CashAddr and Filecoin specification vectors, and the XRP Ledger
    /// genesis account.
    #[test]
    fn test_bitcoin_family_addresses() {
        let g = generator();
        assert_eq!(
            compute_btc_address(&g),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );
        assert_eq!(
            compute_btc_p2pkh_address(&g),
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
        );
        assert_eq!(
            compute_btc_p2sh_p2wpkh_address(&g),
            "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN"
        );
        assert_eq!(
            compute_ltc_address(&g),
            "ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9"
        );
        assert_eq!(
            compute_ltc_p2pkh_address(&g),
            "LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ"
        );
        assert_eq!(
            compute_doge_address(&g),
            "DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE"
        );
        assert_eq!(
            compute_bch_address(&g),
            "bitcoincash:qp63uahgrxged4z5jswyt5dn5v3lzsem6cy4spdc2h"
        );

        let pk = test_keypair();
        assert_eq!(
            compute_btc_p2pkh_address(&pk),
            "16t9vepqVPXshDPvPurAnHw22nHGm2764c"
        );
        assert_eq!(
            compute_btc_p2sh_p2wpkh_address(&pk),
            "3CHfEHaVbMq4jUhcTQ2thuojnWN2gdNNqi"
        );
        assert_eq!(
            compute_ltc_address(&pk),
            "ltc1qgzz5kypj5dc9c9sndewpa8x560spd3pyly6gc3"
        );
        assert_eq!(
            compute_ltc_p2pkh_address(&pk),
            "LR77Bs8fa3mvx265a3qU4JznEzeYuAGJAm"
        );
        assert_eq!(
            compute_doge_address(&pk),
            "DB2FTumUnoSAEDaX8VqjL46cuv1a7GXaj6"
        );
        assert_eq!(
            compute_bch_address(&pk),
            "bitcoincash:qpqg2jcsx23hqhqkzdh9c85u6nf7q9kyys7aw5rck0"
        );
    }

    /// CashAddr specification vectors (P2PKH, 160-bit hash).
    #[test]
    fn test_cashaddr_spec_vectors() {
        for (legacy, cashaddr) in [
            (
                "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu",
                "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
            ),
            (
                "1KXrWXciRDZUpQwQmuM1DbwsKDLYAYsVLR",
                "bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy",
            ),
            (
                "16w1D5WRVKJuZUsSRzdLp9w3YGcgoxDXb",
                "bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r",
            ),
        ] {
            let decoded = bs58::decode(legacy).into_vec().unwrap();
            let (versioned, checksum) = decoded.split_at(21);
            assert_eq!(double_sha256_checksum(versioned), checksum);
            assert_eq!(
                cashaddr_encode("bitcoincash", 0x00, &versioned[1..]),
                cashaddr
            );
        }
        assert_eq!(
            cashaddr_encode(
                "bitcoincash",
                0x00,
                &hex::decode("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9").unwrap()
            ),
            "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2"
        );
    }

    /// XRP Ledger genesis account (secret "masterpassphrase").
    #[test]
    fn test_xrp_address() {
        let pk = k256::PublicKey::from_sec1_bytes(
            &hex::decode("0330E7FC9D56BB25D6893BA3F317AE5BCF33B3291BD63DB32654A313222F7FD020")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            compute_xrp_address(pk.as_affine()),
            "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
        );
        assert_eq!(
            compute_xrp_address(&generator()),
            "rBgGZ9tc4him9KBzD8fKFiQz3fSZpaSwMH"
        );
    }

    /// Filecoin specification vectors (payload to address), then the
    /// payload derivation from a public key.
    #[test]
    fn test_filecoin_address() {
        for (address, payload) in [
            (
                "f17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
                "fd1d0f4dfcd7e99afcb99a8326b7dc459d32c628",
            ),
            (
                "f1xcbgdhkgkwht3hrrnui3jdopeejsoatkzmoltqy",
                "b882619d46558f3d9e316d11b48dcf211327026a",
            ),
            (
                "f12fiakbhe2gwd5cnmrenekasyn6v5tnaxaqizq6a",
                "d1500504e4d1ac3e89ac891a4502586fabd9b417",
            ),
        ] {
            assert_eq!(
                filecoin_address_from_payload(&hex::decode(payload).unwrap()),
                address
            );
        }
        assert_eq!(
            compute_filecoin_address(&generator()),
            "f1wcuzrs736zqzbbjjdgl2wvyyufuk4pefbymzf2i"
        );
        assert_eq!(
            compute_filecoin_address(&test_keypair()),
            "f1ge5kpof3yryrrkm46pl6vy72u6qa2mhmedbfcfq"
        );
    }

    #[test]
    fn test_tezos_address() {
        assert_eq!(
            compute_tezos_address(&generator()),
            "tz2BCeQSi5ETyKJsob61pWCoQvoGtsrJBEt2"
        );
        assert_eq!(
            compute_tezos_address(&test_keypair()),
            "tz2V2f6Harrwpnm5x7E55ceTAcWmYg4iNhZC"
        );
    }

    #[test]
    fn test_invalid_hrp_is_an_error() {
        let pk = generator();
        for hrp in ["", "bc 1", "\u{e9}", &"a".repeat(84)] {
            assert_eq!(try_compute_btc_address_with_hrp(&pk, hrp), Err(InvalidHrp));
            assert_eq!(
                try_compute_cosmos_address_with_hrp(&pk, hrp),
                Err(InvalidHrp)
            );
        }
        assert_eq!(
            try_compute_btc_address_with_hrp(&pk, "bc").unwrap(),
            compute_btc_address(&pk)
        );
        assert_eq!(
            try_compute_cosmos_address_with_hrp(&pk, "cosmos").unwrap(),
            compute_cosmos_address(&pk)
        );
    }
}
