/// This file implements the hash function needed for the DKLs23 protocol.
/// 
/// We are using SHA-256 from SHA-2 as in the implementation of the
/// previous version of the protocol (https://gitlab.com/neucrypt/mpecdsa/-/blob/release/src/lib.rs).
/// 
/// As explained by one of the authors (see https://youtu.be/-d0Ny7NAG-w?si=POTKF1BwwGOzvIpL&t=3065),
/// each subprotocol should use a different random oracle. For this purpose, our implementation
/// has a "salt" parameter to modify the hash function. In our main protocol, the salt is
/// usually derived from the session id.

/// DESCOBRIR COMO FAZER UM SESSION ID PRA CADA PROTOCOLO.
/// O DKLs19 resolvia isso de um jeito complicado, e não sei se encaixa aqui (talvez precise de comunicação).

use bitcoin_hashes::{Hash, sha256};
use curv::elliptic::curves::{Secp256k1, Scalar, Point};
use curv::arithmetic::*;

use crate::SECURITY;

//We are using SHA-256, so the hash values have 256 bits
pub type HashOutput = [u8;SECURITY];

//From bytes to bytes
pub fn hash(msg: &[u8], salt: &[u8]) -> HashOutput {
    let concatenation = [salt,msg].concat();
    sha256::Hash::hash(&concatenation).to_byte_array()
}

//From bytes to BigInt
pub fn hash_as_int(msg: &[u8], salt: &[u8]) -> BigInt {
    let as_bytes = hash(msg, salt);
    BigInt::from_bytes(&as_bytes)
}

//From bytes to a scalar (it takes the integer and reduces it modulo the order of the curve)
pub fn hash_as_scalar(msg: &[u8], salt: &[u8]) -> Scalar<Secp256k1> {
    let as_int = hash_as_int(msg, salt);
    Scalar::<Secp256k1>::from_bigint(&as_int)
}

//Curv does not convert Scalar and Point directly to bytes. We add this for convenience.
pub fn scalar_to_bytes(scalar: &Scalar<Secp256k1>) -> Vec<u8> {
    scalar.to_bytes().as_ref().to_vec()
}

pub fn point_to_bytes(point: &Point<Secp256k1>) -> Vec<u8> {
    point.to_bytes(true).as_ref().to_vec()
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

        assert_eq!(hash_as_int(msg, salt), BigInt::from_hex("847bf2f0d27a519b25e519efebc9d509316539b89ee8f6f09ef6d2abc08113ba").unwrap());
    }

}