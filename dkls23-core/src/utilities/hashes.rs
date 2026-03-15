//! Functions relating hashes and byte conversions.
//!
//! Each subprotocol uses a different random oracle via [`tagged_hash`]
//! and fixed tags in `utilities::oracle_tags`.

use elliptic_curve::ops::Reduce;
use elliptic_curve::{CurveArithmetic, FieldBytes};
use rustcrypto_group::GroupEncoding;
use sha2::{Digest, Sha256};

use crate::SECURITY;

/// Represents the output of the hash function.
///
/// We are using SHA-256, so the hash values have 256 bits.
pub type HashOutput = [u8; SECURITY as usize];

fn hash_bytes(msg: &[u8]) -> HashOutput {
    Sha256::digest(msg).into()
}

fn append_len_prefixed(encoded: &mut Vec<u8>, component: &[u8]) {
    encoded.extend_from_slice(&(component.len() as u64).to_be_bytes());
    encoded.extend_from_slice(component);
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

/// Length-delimited tagged hash with result as a scalar.
#[must_use]
pub fn tagged_hash_as_scalar<C: CurveArithmetic>(tag: &[u8], components: &[&[u8]]) -> C::Scalar
where
    C::Scalar: Reduce<FieldBytes<C>>,
{
    let as_bytes = tagged_hash(tag, components);
    reduce_hash_to_scalar::<C>(&as_bytes)
}

/// Reduce a 32-byte hash output into a scalar for curve `C`.
///
/// Uses `Reduce<FieldBytes<C>>` which is already a bound on `CurveArithmetic::Scalar`.
fn reduce_hash_to_scalar<C: CurveArithmetic>(hash: &HashOutput) -> C::Scalar
where
    C::Scalar: Reduce<FieldBytes<C>>,
{
    let field_bytes = FieldBytes::<C>::from_slice(hash);
    <C::Scalar as Reduce<FieldBytes<C>>>::reduce(field_bytes)
}

/// Converts a `Scalar` to bytes.
///
/// The scalar is represented by an integer.
/// This function writes this integer as a byte array.
#[must_use]
pub fn scalar_to_bytes<C: CurveArithmetic>(scalar: &C::Scalar) -> Vec<u8> {
    let fb: FieldBytes<C> = (*scalar).into();
    <FieldBytes<C> as AsRef<[u8]>>::as_ref(&fb).to_vec()
}

/// Converts a point on the elliptic curve to bytes.
///
/// Apart from the point at infinity, it computes the compressed
/// representation of `point`.
#[must_use]
pub fn point_to_bytes<C: CurveArithmetic>(point: &C::AffinePoint) -> Vec<u8>
where
    C::AffinePoint: GroupEncoding,
{
    point.to_bytes().as_ref().to_vec()
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::utilities::rng;
    use k256::elliptic_curve::{point::AffineCoordinates, Field};
    use k256::{AffinePoint, Scalar, Secp256k1};
    use rand::RngExt;

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

            assert_eq!(number_as_bytes, scalar_to_bytes::<Secp256k1>(&scalar));
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

            assert_eq!(compressed_point, point_to_bytes::<Secp256k1>(&point));
        }
    }
}
