//! Functions relating hashes and byte conversions.
//!
//! We are using SHA-256 from SHA-2 as in the implementation of the
//! previous version of the `DKLs` protocol (<https://gitlab.com/neucrypt/mpecdsa/-/blob/release/src/lib.rs>).
//!
//! As explained by one of the authors (see <https://youtu.be/-d0Ny7NAG-w?si=POTKF1BwwGOzvIpL&t=3065>),
//! each subprotocol should use a different random oracle. This crate implements
//! explicit domain separation via [`tagged_hash`] and fixed tags in
//! `utilities::oracle_tags`.
//!
//! The legacy `hash(msg, salt)` helpers are retained for compatibility at the
//! API level, but internal protocol oracles should use tagged hashing.

use bitcoin_hashes::sha256;
use k256::elliptic_curve::{bigint::Encoding, group::GroupEncoding, ops::Reduce};
use k256::{AffinePoint, Scalar, U256};

use crate::SECURITY;

/// Represents the output of the hash function.
///
/// We are using SHA-256, so the hash values have 256 bits.
pub type HashOutput = [u8; SECURITY as usize];

fn hash_bytes(msg: &[u8]) -> HashOutput {
    sha256::Hash::hash(msg).to_byte_array()
}

fn append_len_prefixed(encoded: &mut Vec<u8>, component: &[u8]) {
    encoded.extend_from_slice(&(component.len() as u64).to_be_bytes());
    encoded.extend_from_slice(component);
}

/// Hash with result in bytes.
#[must_use]
pub fn hash(msg: &[u8], salt: &[u8]) -> HashOutput {
    let concatenation = [salt, msg].concat();
    hash_bytes(&concatenation)
}

/// Hash with result as an integer.
#[must_use]
pub fn hash_as_int(msg: &[u8], salt: &[u8]) -> U256 {
    let as_bytes = hash(msg, salt);
    U256::from_be_bytes(as_bytes.into())
}

/// Hash with result as a scalar.
///
/// It takes the integer from [`hash_as_int`] and reduces it modulo the order of the curve secp256k1.
#[must_use]
pub fn hash_as_scalar(msg: &[u8], salt: &[u8]) -> Scalar {
    let as_int = hash_as_int(msg, salt);
    Scalar::reduce(&as_int)
}

/// Length-delimited tagged hash with result in bytes.
///
/// Encoding is:
/// `len(tag)||tag||len(component_0)||component_0||...`.
#[must_use]
pub fn tagged_hash(tag: &[u8], components: &[&[u8]]) -> HashOutput {
    let mut encoded =
        Vec::with_capacity(8 + tag.len() + components.iter().map(|c| 8 + c.len()).sum::<usize>());
    append_len_prefixed(&mut encoded, tag);
    for component in components {
        append_len_prefixed(&mut encoded, component);
    }
    hash_bytes(&encoded)
}

/// Length-delimited tagged hash with result as an integer.
#[must_use]
pub fn tagged_hash_as_int(tag: &[u8], components: &[&[u8]]) -> U256 {
    let as_bytes = tagged_hash(tag, components);
    U256::from_be_bytes(as_bytes.into())
}

/// Length-delimited tagged hash with result as a scalar.
#[must_use]
pub fn tagged_hash_as_scalar(tag: &[u8], components: &[&[u8]]) -> Scalar {
    let as_int = tagged_hash_as_int(tag, components);
    Scalar::reduce(&as_int)
}

/// Converts a `Scalar` to bytes.
///
/// The scalar is represented by an integer.
/// This function writes this integer as a byte array.
#[must_use]
pub fn scalar_to_bytes(scalar: &Scalar) -> Vec<u8> {
    scalar.to_bytes().to_vec()
}

/// Converts a point on the elliptic curve secp256k1 to bytes.
///
/// Apart from the point at infinity, it computes the compressed
/// representation of `point`.
#[must_use]
pub fn point_to_bytes(point: &AffinePoint) -> Vec<u8> {
    point.to_bytes().to_vec()
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::utilities::rng;
    use hex;
    use k256::elliptic_curve::{point::AffineCoordinates, Field};
    use rand::RngExt;

    /// Tests if [`hash`] really works as `SHA-256` is intended.
    ///
    /// In this case, you should manually change the values and
    /// use a trusted source which computes `SHA-256` to compare.
    #[test]
    fn test_hash() {
        let msg_string = "Testing message";
        let salt_string = "Testing salt";

        let msg = msg_string.as_bytes();
        let salt = salt_string.as_bytes();

        assert_eq!(
            hash(msg, salt).to_vec(),
            hex::decode("847bf2f0d27a519b25e519efebc9d509316539b89ee8f6f09ef6d2abc08113ba")
                .unwrap()
        );
    }

    /// Tests if [`hash_as_int`] gives the correct integer.
    ///
    /// In this case, you should manually change the values and
    /// use a trusted source which computes `SHA-256` to compare.
    #[test]
    fn test_hash_as_int() {
        let msg_string = "Testing message";
        let salt_string = "Testing salt";

        let msg = msg_string.as_bytes();
        let salt = salt_string.as_bytes();

        assert_eq!(
            hash_as_int(msg, salt),
            U256::from_be_hex("847bf2f0d27a519b25e519efebc9d509316539b89ee8f6f09ef6d2abc08113ba")
        );
    }

    #[test]
    fn test_tagged_hash_is_length_delimited() {
        let tag = b"tag";
        let hash1 = tagged_hash(tag, &[b"ab", b"c"]);
        let hash2 = tagged_hash(tag, &[b"a", b"bc"]);
        assert_ne!(hash1, hash2);
    }

    /// Tests if [`scalar_to_bytes`] converts a `Scalar`
    /// in the expected way.
    #[test]
    fn test_scalar_to_bytes() {
        for _ in 0..100 {
            let number: u32 = rng::get_rng().random();
            let scalar = Scalar::from(number);

            let number_as_bytes = [vec![0u8; 28], number.to_be_bytes().to_vec()].concat();

            assert_eq!(number_as_bytes, scalar_to_bytes(&scalar));
        }
    }

    /// Tests if [`point_to_bytes`] indeed returns the compressed
    /// representation of a point on the elliptic curve.
    #[test]
    fn test_point_to_bytes() {
        for _ in 0..100 {
            let point = (AffinePoint::GENERATOR * Scalar::random(&mut rng::get_rng())).to_affine();
            if point == AffinePoint::IDENTITY {
                continue;
            }

            let mut compressed_point = Vec::with_capacity(33);
            compressed_point.push(if bool::from(point.y_is_odd()) { 3 } else { 2 });
            compressed_point.extend_from_slice(point.x().as_ref());

            assert_eq!(compressed_point, point_to_bytes(&point));
        }
    }
}
