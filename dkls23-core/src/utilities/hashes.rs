//! Functions relating hashes and byte conversions.
//!
//! Each subprotocol uses a different random oracle via [`tagged_hash`]
//! and fixed tags in `utilities::oracle_tags`.

use core::any::TypeId;

use elliptic_curve::ops::Reduce;
use elliptic_curve::{CurveArithmetic, FieldBytes};
use ff::PrimeField;
use group::{Curve as GroupCurve, Group, GroupEncoding};
use hash2curve::{ExpandMsg, ExpandMsgXmd, MapToCurve};
use sha2::{Digest, Sha256};

use crate::curve::DklsCurve;
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

/// Length-delimited tagged hash with result as a curve point.
///
/// For secp256k1 and P-256 this is RFC 9380 `hash_to_curve` with the
/// `secp256k1_XMD:SHA-256_SSWU_RO_` and `P256_XMD:SHA-256_SSWU_RO_` suites.
/// The DST is `tag || "-with-" || suite_id`, and the message is the
/// length-delimited encoding of `components` used by [`tagged_hash`].
///
/// Other curves fall back to try-and-increment on SEC1 compressed points.
///
/// The running time depends only on the inputs, which must be public.
///
/// # Panics
///
/// Panics if `C` is not one of the RFC 9380 curves above and its point
/// encoding is not SEC1 compressed.
#[must_use]
pub fn tagged_hash_as_point<C: DklsCurve>(tag: &[u8], components: &[&[u8]]) -> C::AffinePoint {
    let mut msg = Vec::with_capacity(components.iter().map(|c| 8 + c.len()).sum::<usize>());
    for component in components {
        append_len_prefixed(&mut msg, component);
    }

    let curve = TypeId::of::<C>();
    if curve == TypeId::of::<k256::Secp256k1>() {
        rfc9380_hash_to_point::<k256::Secp256k1, C>(tag, b"secp256k1_XMD:SHA-256_SSWU_RO_", &msg)
    } else if curve == TypeId::of::<p256::NistP256>() {
        rfc9380_hash_to_point::<p256::NistP256, C>(tag, b"P256_XMD:SHA-256_SSWU_RO_", &msg)
    } else {
        try_and_increment_hash_to_point::<C>(tag, &msg)
    }
}

/// RFC 9380 `hash_to_curve` on curve `H`, returned as a point of `C`.
///
/// The caller guarantees that `H` and `C` are the same curve.
fn rfc9380_hash_to_point<H, C>(tag: &[u8], suite_id: &[u8], msg: &[u8]) -> C::AffinePoint
where
    H: MapToCurve,
    H::AffinePoint: GroupEncoding,
    ExpandMsgXmd<Sha256>: ExpandMsg<H::SecurityLevel>,
    C: DklsCurve,
{
    let point =
        hash2curve::hash_from_bytes::<H, ExpandMsgXmd<Sha256>>(&[msg], &[tag, b"-with-", suite_id])
            .expect("DST and output length are within RFC 9380 limits");
    let bytes = point.to_affine().to_bytes();

    let mut repr = <C::AffinePoint as GroupEncoding>::Repr::default();
    repr.as_mut().copy_from_slice(bytes.as_ref());
    Option::from(<C::AffinePoint as GroupEncoding>::from_bytes(&repr))
        .expect("H and C are the same curve")
}

/// Try-and-increment hash to a SEC1 compressed point with even `y`.
///
/// Candidate x-coordinates come from SHA-256 in counter mode.
fn try_and_increment_hash_to_point<C: DklsCurve>(tag: &[u8], msg: &[u8]) -> C::AffinePoint {
    const MAX_ATTEMPTS: u32 = 1 << 16;

    let mut repr = <C::AffinePoint as GroupEncoding>::Repr::default();
    let x_len = repr.as_ref().len() - 1;
    // For a prime-order curve, the group order and the base field have the
    // same bit length up to one bit, so masking to NUM_BITS keeps candidates
    // close to the field size.
    let excess_bits = (8 * x_len).saturating_sub(<C::Scalar as PrimeField>::NUM_BITS as usize);

    for attempt in 0..MAX_ATTEMPTS {
        let candidate = repr.as_mut();
        candidate[0] = 0x02;
        for (block, chunk) in (0u32..).zip(candidate[1..].chunks_mut(SECURITY as usize)) {
            let digest = tagged_hash(
                tag,
                &[
                    b"try-and-increment",
                    msg,
                    &attempt.to_be_bytes(),
                    &block.to_be_bytes(),
                ],
            );
            chunk.copy_from_slice(&digest[..chunk.len()]);
        }
        for (i, byte) in candidate[1..].iter_mut().enumerate() {
            let excess_in_byte = excess_bits.saturating_sub(8 * i).min(8);
            *byte &= 0xffu8.checked_shr(excess_in_byte as u32).unwrap_or(0);
        }

        let point: Option<C::AffinePoint> =
            Option::from(<C::AffinePoint as GroupEncoding>::from_bytes(&repr));
        if let Some(point) = point {
            if !bool::from(C::ProjectivePoint::from(point).is_identity()) {
                return point;
            }
        }
    }

    panic!("hash to point failed: point encoding of C is not SEC1 compressed")
}

/// Reduce a 32-byte hash output into a scalar for curve `C`.
///
/// Uses `Reduce<FieldBytes<C>>` which is already a bound on `CurveArithmetic::Scalar`.
fn reduce_hash_to_scalar<C: CurveArithmetic>(hash: &HashOutput) -> C::Scalar
where
    C::Scalar: Reduce<FieldBytes<C>>,
{
    let field_bytes: &FieldBytes<C> = hash
        .as_slice()
        .try_into()
        .expect("hash output length matches field size");
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
    use p256::NistP256;
    use rand::RngExt;

    #[test]
    fn test_tagged_hash_is_length_delimited() {
        let tag = b"tag";
        let hash1 = tagged_hash(tag, &[b"ab", b"c"]);
        let hash2 = tagged_hash(tag, &[b"a", b"bc"]);
        assert_ne!(hash1, hash2);
    }

    /// Checks [`tagged_hash_as_point`] against the RFC 9380 test vectors
    /// (Appendices J.1.1 and J.8.1), whose domain-separation tags have the form
    /// `tag || "-with-" || suite_id`.
    #[test]
    fn test_rfc9380_test_vectors() {
        fn check<C>(suite_id: &[u8], msg: &[u8], x: &str, y: &str)
        where
            C: DklsCurve + MapToCurve,
            ExpandMsgXmd<Sha256>: ExpandMsg<C::SecurityLevel>,
        {
            let point = rfc9380_hash_to_point::<C, C>(b"QUUX-V01-CS02", suite_id, msg);
            let y = hex::decode(y).unwrap();
            assert_eq!(hex::encode(point.x()), x);
            assert_eq!(bool::from(point.y_is_odd()), y[31] & 1 == 1);
        }

        let k256 = b"secp256k1_XMD:SHA-256_SSWU_RO_";
        check::<Secp256k1>(
            k256,
            b"",
            "c1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb1346",
            "64fa678e07ae116126f08b022a94af6de15985c996c3a91b64c406a960e51067",
        );
        check::<Secp256k1>(
            k256,
            b"abc",
            "3377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb2c4b",
            "7f95890f33efebd1044d382a01b1bee0900fb6116f94688d487c6c7b9c8371f6",
        );

        let p256 = b"P256_XMD:SHA-256_SSWU_RO_";
        check::<NistP256>(
            p256,
            b"",
            "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
            "8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415",
        );
        check::<NistP256>(
            p256,
            b"abc",
            "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
            "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e",
        );
    }

    /// Tests that [`tagged_hash_as_point`] dispatches to the RFC 9380 suite
    /// of each supported curve with the documented DST and message encoding.
    #[test]
    fn test_tagged_hash_as_point_uses_rfc9380_suite() {
        let tag = b"tag";
        let components: [&[u8]; 2] = [b"ab", b"c"];
        let msg = [
            2u64.to_be_bytes().as_slice(),
            b"ab",
            &1u64.to_be_bytes(),
            b"c",
        ]
        .concat();

        let expected = hash2curve::hash_from_bytes::<Secp256k1, ExpandMsgXmd<Sha256>>(
            &[&msg],
            &[b"tag-with-secp256k1_XMD:SHA-256_SSWU_RO_"],
        )
        .unwrap()
        .to_affine();
        assert_eq!(
            tagged_hash_as_point::<Secp256k1>(tag, &components),
            expected
        );

        let expected = hash2curve::hash_from_bytes::<NistP256, ExpandMsgXmd<Sha256>>(
            &[&msg],
            &[b"tag-with-P256_XMD:SHA-256_SSWU_RO_"],
        )
        .unwrap()
        .to_affine();
        assert_eq!(tagged_hash_as_point::<NistP256>(tag, &components), expected);

        // Length-delimited: shifting bytes between components changes the point.
        assert_ne!(
            tagged_hash_as_point::<Secp256k1>(tag, &[b"ab", b"c"]),
            tagged_hash_as_point::<Secp256k1>(tag, &[b"a", b"bc"])
        );
    }

    /// Pins the base OT point for fixed inputs, so that any change to its
    /// tag, encoding or suite is caught here and not only in interop.
    #[test]
    fn test_tagged_hash_as_point_ot_base_h_is_stable() {
        use crate::utilities::oracle_tags::TAG_OT_BASE_H;

        let session_id = [0x11u8; 32];
        let seed = [0x22u8; 32];
        let components: [&[u8]; 2] = [&session_id, &seed];

        assert_eq!(
            hex::encode(point_to_bytes::<Secp256k1>(&tagged_hash_as_point::<
                Secp256k1,
            >(
                TAG_OT_BASE_H, &components
            ))),
            "02c25835ab4369b3b41f49aee010b74c253f2605089ba1158ad63fdee932c049ff"
        );
        assert_eq!(
            hex::encode(point_to_bytes::<NistP256>(
                &tagged_hash_as_point::<NistP256>(TAG_OT_BASE_H, &components)
            )),
            "02d62753e8e5ad43b7432a7955ad3185e307992652ac807d130c0a8cc35cee60ff"
        );
    }

    /// Tests that the try-and-increment fallback is deterministic and
    /// returns valid, input-dependent, non-identity points.
    #[test]
    fn test_try_and_increment_hash_to_point() {
        for i in 0u32..64 {
            let msg = i.to_be_bytes();
            let point = try_and_increment_hash_to_point::<Secp256k1>(b"tag", &msg);
            assert_ne!(point, AffinePoint::IDENTITY);
            assert!(!bool::from(point.y_is_odd()));
            assert_eq!(
                point,
                try_and_increment_hash_to_point::<Secp256k1>(b"tag", &msg)
            );
            assert_ne!(
                point,
                try_and_increment_hash_to_point::<Secp256k1>(b"other", &msg)
            );

            let point = try_and_increment_hash_to_point::<NistP256>(b"tag", &msg);
            assert_ne!(point, p256::AffinePoint::IDENTITY);
        }
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
