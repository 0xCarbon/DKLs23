//! Functions relating hashes and byte conversions.
//!
//! We are using SHA-256 from SHA-2 as in the implementation of the
//! previous version of the `DKLs` protocol (<https://gitlab.com/neucrypt/mpecdsa/-/blob/release/src/lib.rs>).
//!
//! As explained by one of the authors (see <https://youtu.be/-d0Ny7NAG-w?si=POTKF1BwwGOzvIpL&t=3065>),
//! each subprotocol should use a different random oracle. For this purpose, our implementation
//! has a "salt" parameter to modify the hash function. In our main protocol, the salt is
//! usually derived from the session id.

// TODO/FOR THE FUTURE: It requires some work to really guarantee that all "salts" are
// different for each subprotocol. For example, the implementation above has a
// file just for this purpose. Thus, it's worth analyzing this code in the future
// and maybe implementing something similar.

use bitcoin_hashes::{sha256, Hash};
use k256::elliptic_curve::{bigint::Encoding, group::GroupEncoding, ops::Reduce};
use k256::{AffinePoint, Scalar, U256};

use crate::SECURITY;

/// Represents the output of the hash function.
///
/// We are using SHA-256, so the hash values have 256 bits.
pub type HashOutput = [u8; SECURITY as usize];

/// Hash with result in bytes.
#[must_use]
pub fn hash(msg: &[u8], salt: &[u8]) -> HashOutput {
    let concatenation = [salt, msg].concat();
    sha256::Hash::hash(&concatenation).to_byte_array()
}

/// Hash with result as an integer.
#[must_use]
pub fn hash_as_int(msg: &[u8], salt: &[u8]) -> U256 {
    let as_bytes = hash(msg, salt);
    U256::from_be_bytes(as_bytes)
}

/// Hash with result as a scalar.
///
/// It takes the integer from [`hash_as_int`] and reduces it modulo the order of the curve secp256k1.
#[must_use]
pub fn hash_as_scalar(msg: &[u8], salt: &[u8]) -> Scalar {
    let as_int = hash_as_int(msg, salt);
    Scalar::reduce(as_int)
}

/// Converts a `Scalar` to bytes.
///
/// The scalar is represented by an integer.
/// This function writes this integer as a byte array.
#[must_use]
pub fn scalar_to_bytes(scalar: &Scalar) -> Vec<u8> {
    scalar.to_bytes().as_slice().to_vec()
}

/// Converts a point on the elliptic curve secp256k1 to bytes.
///
/// Apart from the point at infinity, it computes the compressed
/// representation of `point`.
#[must_use]
pub fn point_to_bytes(point: &AffinePoint) -> Vec<u8> {
    point.to_bytes().as_slice().to_vec()
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::utilities::rng;
    use hex;
    use k256::elliptic_curve::{point::AffineCoordinates, Field};
    use rand::Rng;

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

    /// Tests if [`scalar_to_bytes`] converts a `Scalar`
    /// in the expected way.
    #[test]
    fn test_scalar_to_bytes() {
        for _ in 0..100 {
            let number: u32 = rng::get_rng().gen();
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
            let point = (AffinePoint::GENERATOR * Scalar::random(rng::get_rng())).to_affine();
            if point == AffinePoint::IDENTITY {
                continue;
            }

            let mut compressed_point = Vec::with_capacity(33);
            compressed_point.push(if bool::from(point.y_is_odd()) { 3 } else { 2 });
            compressed_point.extend_from_slice(point.x().as_slice());

            assert_eq!(compressed_point, point_to_bytes(&point));
        }
    }
}
