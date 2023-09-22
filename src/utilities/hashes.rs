/// This file implements the hash function needed for the `DKLs23` protocol.
/// 
/// We are using SHA-256 from SHA-2 as in the implementation of the
/// previous version of the protocol (<https://gitlab.com/neucrypt/mpecdsa/-/blob/release/src/lib.rs>).
/// 
/// As explained by one of the authors (see <https://youtu.be/-d0Ny7NAG-w?si=POTKF1BwwGOzvIpL&t=3065>),
/// each subprotocol should use a different random oracle. For this purpose, our implementation
/// has a "salt" parameter to modify the hash function. In our main protocol, the salt is
/// usually derived from the session id.
///
/// FOR THE FUTURE: It requires some work to really guarantee that all "salts" are
/// different for each subprotocol. For example, the implementation above has a
/// file just for this purpose. Thus, it's worth analyzing this code in the future
/// and maybe implementing something similar.

use bitcoin_hashes::{Hash, sha256};
use k256::{Scalar, AffinePoint, U256};
use k256::elliptic_curve::{bigint::Encoding, group::GroupEncoding, ops::Reduce};

use crate::SECURITY;

// We are using SHA-256, so the hash values have 256 bits
pub type HashOutput = [u8;SECURITY as usize];

// From bytes to bytes
#[must_use]
pub fn hash(msg: &[u8], salt: &[u8]) -> HashOutput {
    let concatenation = [salt,msg].concat();
    sha256::Hash::hash(&concatenation).to_byte_array()
}

// From bytes to U256
#[must_use]
pub fn hash_as_int(msg: &[u8], salt: &[u8]) -> U256 {
    let as_bytes = hash(msg, salt);
    U256::from_be_bytes(as_bytes)
}

// From bytes to a scalar (it takes the integer and reduces it modulo the order of the curve)
#[must_use]
pub fn hash_as_scalar(msg: &[u8], salt: &[u8]) -> Scalar {
    let as_int = hash_as_int(msg, salt);
    Scalar::reduce(as_int)
}

// k256 does not convert Scalar and AffinePoint directly to bytes. We add this for convenience.
#[must_use]
pub fn scalar_to_bytes(scalar: &Scalar) -> Vec<u8> {
    scalar.to_bytes().as_slice().to_vec()
}

#[must_use]
pub fn point_to_bytes(point: &AffinePoint) -> Vec<u8> {
    point.to_bytes().as_slice().to_vec()
}

#[cfg(test)]
mod tests {
    
    use super::*;
    use hex;

    #[test]
    fn test_hash() {
        let msg_string = "Testing message";
        let salt_string = "Testing salt";

        let msg = msg_string.as_bytes();
        let salt = salt_string.as_bytes();

        assert_eq!(hash(msg, salt).to_vec(), hex::decode("847bf2f0d27a519b25e519efebc9d509316539b89ee8f6f09ef6d2abc08113ba").unwrap());
    }

    #[test]
    fn test_hash_as_int() {
        let msg_string = "Testing message";
        let salt_string = "Testing salt";

        let msg = msg_string.as_bytes();
        let salt = salt_string.as_bytes();

        assert_eq!(hash_as_int(msg, salt), U256::from_be_hex("847bf2f0d27a519b25e519efebc9d509316539b89ee8f6f09ef6d2abc08113ba"));
    }

    #[test]
    fn test_scalar_to_bytes() {
        let scalar = Scalar::from(123456789u32);

        assert_eq!(scalar_to_bytes(&scalar), vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 91, 205, 21]);
    }

}