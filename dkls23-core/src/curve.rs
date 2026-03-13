//! Trait abstraction for ECDSA curves supported by DKLs23.
//!
//! The [`DklsCurve`] supertrait bundles all `CurveArithmetic` bounds
//! that the DKLs23 protocol requires. Both `k256::Secp256k1` and
//! `p256::NistP256` satisfy these bounds via the blanket impl below.

use elliptic_curve::bigint::ArrayEncoding;
use elliptic_curve::ops::Reduce;
use elliptic_curve::point::AffineCoordinates;
use elliptic_curve::scalar::IsHigh;
use elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point};
use elliptic_curve::{CurveArithmetic, FieldBytesSize, PrimeCurve};
use rustcrypto_ff::{Field, PrimeField};
use rustcrypto_group::prime::{PrimeCurveAffine, PrimeGroup};
use rustcrypto_group::{Curve as GroupCurve, Group, GroupEncoding};

/// Marker trait bundling all elliptic-curve bounds needed by DKLs23.
///
/// Any curve implementing the RustCrypto `CurveArithmetic` + `PrimeCurve`
/// traits (with the right associated-type bounds) automatically satisfies
/// this via the blanket impl.
///
/// The associated-type bounds in the supertrait ensure that callers get
/// `GroupEncoding`, `PrimeCurveAffine`, `Reduce`, `Field`, etc. for free
/// whenever they write `C: DklsCurve`.
pub trait DklsCurve:
    CurveArithmetic<
        AffinePoint: GroupEncoding
            + PrimeCurveAffine<
                Curve = <Self as CurveArithmetic>::ProjectivePoint,
                Scalar = <Self as CurveArithmetic>::Scalar,
            >
            + AffineCoordinates<FieldRepr = elliptic_curve::FieldBytes<Self>>,
        Scalar: Reduce<Self::Uint> + Reduce<elliptic_curve::FieldBytes<Self>> + IsHigh + Field + PrimeField,
        ProjectivePoint: Group + PrimeGroup + GroupCurve<AffineRepr = <Self as CurveArithmetic>::AffinePoint>,
    > + PrimeCurve
    + Sized
    + 'static
{
}

/// Blanket impl: any curve satisfying the required bounds is a `DklsCurve`.
impl<C> DklsCurve for C
where
    C: CurveArithmetic + PrimeCurve + Sized + 'static,
    C::Uint: ArrayEncoding,
    <C as CurveArithmetic>::AffinePoint: GroupEncoding
        + PrimeCurveAffine<
            Curve = <C as CurveArithmetic>::ProjectivePoint,
            Scalar = <C as CurveArithmetic>::Scalar,
        >
        + AffineCoordinates<FieldRepr = elliptic_curve::FieldBytes<C>>
        + FromSec1Point<C>
        + ToSec1Point<C>,
    <C as CurveArithmetic>::Scalar:
        Reduce<C::Uint> + Reduce<elliptic_curve::FieldBytes<C>> + IsHigh + Field + PrimeField,
    <C as CurveArithmetic>::ProjectivePoint: Group + PrimeGroup + GroupCurve<AffineRepr = <C as CurveArithmetic>::AffinePoint>,
    FieldBytesSize<C>: ModulusSize,
{
}

/// Address derivation trait — implemented per curve-specific crate.
///
/// This allows different address schemes (Ethereum, NEO3, etc.)
/// without embedding chain-specific logic in the core library.
pub trait AddressScheme<C: DklsCurve> {
    fn compute_address(pk: &<C as CurveArithmetic>::AffinePoint) -> String;
}
