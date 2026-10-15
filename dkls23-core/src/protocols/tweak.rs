//! Scalar tweaks on key shares.
//!
//! BIP-32 derivation ([`derivation`](super::derivation)) shifts every share
//! by a scalar derived from public data. Some protocols instead need a
//! caller-supplied scalar. Lightning, for instance, derives per-commitment
//! keys with an additive "single tweak" `k' = k + t (mod n)` and a
//! "revocation tweak" that composes a multiplicative step `k' = a·k (mod n)`
//! with an additive one. This module exposes both maps on [`Party`] and
//! [`PublicKeyPackage`].
//!
//! # Correctness
//!
//! Signing reconstructs `sk = Σ lᵢ·xᵢ` from the executing parties' shares
//! with Lagrange coefficients that sum to one, so `Σ lᵢ·(xᵢ + t) = sk + t`
//! and `Σ lᵢ·(a·xᵢ) = a·sk`. Applying the same tweak to every party's share
//! and to the public key package (group key and every verifying share)
//! therefore yields a consistent key set that signs under the tweaked key.
//!
//! # Security
//!
//! The base-OT correlations, zero-share seeds and multiplication state a
//! party carries never depend on the value of its share, so they are reused
//! unchanged — exactly what BIP-32 derivation already relies on. The chain
//! code is also left unchanged, because signing salts the two-party
//! multiplication transcript with it and every party must keep agreeing on
//! it. A tweak is not a BIP-32 edge: `depth`, `child_number` and
//! `parent_fingerprint` still describe the un-tweaked ancestor, and deriving
//! a child of a tweaked party is a further additive shift under the same
//! chain code.
//!
//! All executing parties and the package must apply the same tweak before a
//! signing session; a mismatch is caught by the phase-3 consistency check
//! and aborts recoverably. The tweak itself may be secret material (LND's
//! revocation tweak mixes in a per-commitment secret): callers should keep
//! it in a zeroizing container, and nothing in this module logs or formats
//! scalars.

use std::fmt;

use elliptic_curve::ops::Reduce;
use rustcrypto_ff::Field;
use rustcrypto_group::prime::PrimeCurveAffine;
use rustcrypto_group::Curve;
use zeroize::Zeroizing;

use crate::curve::DklsCurve;
use crate::protocols::derivation::DerivData;
use crate::protocols::{Party, PublicKeyPackage};

/// Errors returned by the scalar tweak operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum TweakError {
    /// `tweak_mul` was called with the zero scalar, which would destroy the key.
    ZeroFactor,
    /// The tweaked public key is the identity point (e.g. `tweak_add` with `t == -sk`).
    IdentityPublicKey,
    /// [`scalar_from_be_bytes`] received a byte string whose length is not the field size.
    InvalidScalarLength {
        /// Field size in bytes for the curve.
        expected: usize,
        /// Length of the byte string that was passed.
        got: usize,
    },
}

impl fmt::Display for TweakError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TweakError::ZeroFactor => write!(f, "multiplicative tweak factor is zero"),
            TweakError::IdentityPublicKey => {
                write!(f, "tweaked public key is the identity point")
            }
            TweakError::InvalidScalarLength { expected, got } => {
                write!(f, "scalar must be {expected} bytes, got {got}")
            }
        }
    }
}

impl std::error::Error for TweakError {}

/// Parses a big-endian byte string of exactly the field size and reduces it
/// modulo the curve order.
///
/// This is the encoding wallets exchange tweaks in (a 32-byte big-endian
/// integer for secp256k1 and P-256, reduced like btcec's `ModNScalar`). Use
/// it to turn wire bytes into the `C::Scalar` that [`Party::tweak_add`] and
/// friends take.
///
/// # Errors
///
/// Returns [`TweakError::InvalidScalarLength`] if `bytes` is not exactly the
/// field size; a shorter or longer value is never silently padded or cut.
pub fn scalar_from_be_bytes<C: DklsCurve>(bytes: &[u8]) -> Result<C::Scalar, TweakError> {
    let expected = elliptic_curve::FieldBytes::<C>::default().len();
    let field_bytes: &elliptic_curve::FieldBytes<C> =
        bytes
            .try_into()
            .map_err(|_| TweakError::InvalidScalarLength {
                expected,
                got: bytes.len(),
            })?;

    Ok(<C::Scalar as Reduce<elliptic_curve::FieldBytes<C>>>::reduce(field_bytes))
}

/// The affine map applied to a secret share and, homomorphically, to points.
pub(crate) enum Tweak<C: DklsCurve> {
    /// `x ↦ x + t` on scalars, `P ↦ P + t·G` on points.
    Add(C::Scalar),
    /// `x ↦ a·x` on scalars, `P ↦ a·P` on points.
    Mul(C::Scalar),
}

impl<C: DklsCurve> Tweak<C> {
    fn validate(&self) -> Result<(), TweakError> {
        match self {
            Tweak::Mul(factor) if bool::from(factor.is_zero()) => Err(TweakError::ZeroFactor),
            _ => Ok(()),
        }
    }

    fn apply_scalar(&self, value: &C::Scalar) -> C::Scalar {
        match self {
            Tweak::Add(tweak) => *value + *tweak,
            Tweak::Mul(factor) => *value * *factor,
        }
    }

    fn apply_point(&self, point: &C::AffinePoint) -> C::AffinePoint {
        match self {
            Tweak::Add(tweak) => {
                let generator = <C::AffinePoint as PrimeCurveAffine>::generator();
                ((generator * *tweak) + *point).to_affine()
            }
            Tweak::Mul(factor) => (*point * *factor).to_affine(),
        }
    }
}

/// Scalar tweaks on a party's key share.
impl<C: DklsCurve> Party<C> {
    /// Returns a party whose share is `poly_point + tweak (mod n)`.
    ///
    /// The public key becomes `pk + tweak·G` and `address_fn` recomputes the
    /// address for it. Everything else (session id, OT and multiplication
    /// state, chain code and the other BIP-32 metadata) is carried over
    /// unchanged. Every executing party and the [`PublicKeyPackage`] must
    /// apply the same tweak; see the module documentation.
    ///
    /// # Errors
    ///
    /// Returns [`TweakError::IdentityPublicKey`] if the tweaked public key is
    /// the identity point.
    pub fn tweak_add(
        &self,
        tweak: &C::Scalar,
        address_fn: impl Fn(&C::AffinePoint) -> String,
    ) -> Result<Party<C>, TweakError> {
        self.apply_tweak(&Tweak::Add(*tweak), address_fn)
    }

    /// Returns a party whose share is `factor · poly_point (mod n)`.
    ///
    /// The public key becomes `factor · pk`. Otherwise identical to
    /// [`Party::tweak_add`].
    ///
    /// # Errors
    ///
    /// Returns [`TweakError::ZeroFactor`] if `factor` is zero and
    /// [`TweakError::IdentityPublicKey`] if the tweaked public key is the
    /// identity point.
    pub fn tweak_mul(
        &self,
        factor: &C::Scalar,
        address_fn: impl Fn(&C::AffinePoint) -> String,
    ) -> Result<Party<C>, TweakError> {
        self.apply_tweak(&Tweak::Mul(*factor), address_fn)
    }

    fn apply_tweak(
        &self,
        tweak: &Tweak<C>,
        address_fn: impl Fn(&C::AffinePoint) -> String,
    ) -> Result<Party<C>, TweakError> {
        tweak.validate()?;

        let pk = tweak.apply_point(&self.pk);
        if pk == <C::AffinePoint as PrimeCurveAffine>::identity() {
            return Err(TweakError::IdentityPublicKey);
        }
        let poly_point = Zeroizing::new(tweak.apply_scalar(&self.poly_point));
        let address = address_fn(&pk);

        Ok(Party {
            parameters: self.parameters.clone(),
            party_index: self.party_index,
            session_id: self.session_id.clone(),

            poly_point: *poly_point,
            pk,

            zero_share: self.zero_share.clone(),

            mul_senders: self.mul_senders.clone(),
            mul_receivers: self.mul_receivers.clone(),

            derivation_data: DerivData {
                depth: self.derivation_data.depth,
                child_number: self.derivation_data.child_number,
                parent_fingerprint: self.derivation_data.parent_fingerprint,
                poly_point: *poly_point,
                pk,
                chain_code: self.derivation_data.chain_code,
            },

            address,
        })
    }
}

/// Scalar tweaks on a public key package, mirroring [`Party::tweak_add`] and
/// [`Party::tweak_mul`].
impl<C: DklsCurve> PublicKeyPackage<C> {
    /// Returns a package whose group key is `vk + tweak·G` and whose every
    /// verifying share is shifted by `tweak·G`.
    ///
    /// # Errors
    ///
    /// Returns [`TweakError::IdentityPublicKey`] if the tweaked group key is
    /// the identity point.
    pub fn tweak_add(&self, tweak: &C::Scalar) -> Result<PublicKeyPackage<C>, TweakError> {
        self.apply_tweak(&Tweak::Add(*tweak))
    }

    /// Returns a package whose group key and verifying shares are all scaled
    /// by `factor`.
    ///
    /// # Errors
    ///
    /// Returns [`TweakError::ZeroFactor`] if `factor` is zero and
    /// [`TweakError::IdentityPublicKey`] if the tweaked group key is the
    /// identity point.
    pub fn tweak_mul(&self, factor: &C::Scalar) -> Result<PublicKeyPackage<C>, TweakError> {
        self.apply_tweak(&Tweak::Mul(*factor))
    }

    fn apply_tweak(&self, tweak: &Tweak<C>) -> Result<PublicKeyPackage<C>, TweakError> {
        tweak.validate()?;

        let verifying_key = tweak.apply_point(self.verifying_key());
        if verifying_key == <C::AffinePoint as PrimeCurveAffine>::identity() {
            return Err(TweakError::IdentityPublicKey);
        }
        let verifying_shares = self
            .verifying_shares
            .iter()
            .map(|(party, share)| (*party, tweak.apply_point(share)))
            .collect();

        Ok(PublicKeyPackage::new(
            verifying_key,
            verifying_shares,
            self.parameters.clone(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestCurve = k256::Secp256k1;

    use std::collections::BTreeMap;

    use k256::elliptic_curve::Field;
    use k256::{AffinePoint, ProjectivePoint, Scalar, U256};
    use rand::RngExt;

    use crate::protocols::derivation::CHAIN_CODE_LEN;
    use crate::protocols::re_key::re_key;
    use crate::protocols::signing::*;
    use crate::protocols::{Abort, AbortReason, Parameters, PartyIndex};
    use crate::utilities::hashes::{point_to_bytes, tagged_hash, HashOutput};
    use crate::utilities::rng;
    use crate::utilities::ID_LEN;

    const THRESHOLD: u8 = 2;
    const SHARE_COUNT: u8 = 3;

    fn hex_address(pk: &AffinePoint) -> String {
        hex::encode(point_to_bytes::<TestCurve>(pk))
    }

    fn sample_parties() -> (Vec<Party<TestCurve>>, PublicKeyPackage<TestCurve>, Scalar) {
        let parameters = Parameters::new(THRESHOLD, SHARE_COUNT).unwrap();
        let session_id = rng::get_rng().random::<[u8; ID_LEN]>();
        let secret_key = Scalar::random(&mut rng::get_rng());
        let (parties, package) = re_key::<TestCurve>(
            &parameters,
            &session_id,
            &secret_key,
            Some([9u8; CHAIN_CODE_LEN]),
            hex_address,
        );
        (parties, package, secret_key)
    }

    fn scalar_bytes(value: u64) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        bytes
    }

    fn shifted(point: &AffinePoint, tweak: &Scalar) -> AffinePoint {
        ((AffinePoint::GENERATOR * *tweak) + *point).to_affine()
    }

    fn scaled(point: &AffinePoint, factor: &Scalar) -> AffinePoint {
        (ProjectivePoint::from(*point) * *factor).to_affine()
    }

    fn assert_metadata_preserved(before: &Party<TestCurve>, after: &Party<TestCurve>) {
        assert_eq!(after.parameters.threshold, before.parameters.threshold);
        assert_eq!(after.parameters.share_count, before.parameters.share_count);
        assert_eq!(after.party_index, before.party_index);
        assert_eq!(after.session_id, before.session_id);
        assert_eq!(after.mul_senders.len(), before.mul_senders.len());
        assert_eq!(after.mul_receivers.len(), before.mul_receivers.len());
        assert_eq!(
            after.derivation_data.chain_code,
            before.derivation_data.chain_code
        );
        assert_eq!(after.derivation_data.depth, before.derivation_data.depth);
        assert_eq!(
            after.derivation_data.child_number,
            before.derivation_data.child_number
        );
        assert_eq!(
            after.derivation_data.parent_fingerprint,
            before.derivation_data.parent_fingerprint
        );
        assert_eq!(after.derivation_data.poly_point, after.poly_point);
        assert_eq!(after.derivation_data.pk, after.pk);
        assert_eq!(after.address, hex_address(&after.pk));
    }

    /// Runs the four signing phases for `signers` and returns
    /// `(x_coord, signature)`, or the first abort raised.
    fn sign_with(
        parties: &[Party<TestCurve>],
        signers: &[PartyIndex],
        message_hash: &HashOutput,
    ) -> Result<(String, String), Abort> {
        let party = |index: PartyIndex| &parties[(index.as_u8() - 1) as usize];
        let sign_id = rng::get_rng().random::<[u8; ID_LEN]>();

        let mut all_data: BTreeMap<PartyIndex, SignData> = BTreeMap::new();
        for &party_index in signers {
            let mut counterparties = signers.to_vec();
            counterparties.retain(|index| *index != party_index);
            all_data.insert(
                party_index,
                SignData {
                    sign_id: sign_id.to_vec(),
                    counterparties,
                    message_hash: *message_hash,
                },
            );
        }

        let mut unique_kept_1to2 = BTreeMap::new();
        let mut kept_1to2 = BTreeMap::new();
        let mut transmit_1to2: BTreeMap<PartyIndex, Vec<TransmitPhase1to2>> = BTreeMap::new();
        for &party_index in signers {
            let (unique_keep, keep, transmit) =
                party(party_index).sign_phase1(all_data.get(&party_index).unwrap())?;
            unique_kept_1to2.insert(party_index, unique_keep);
            kept_1to2.insert(party_index, keep);
            transmit_1to2.insert(party_index, transmit);
        }

        let mut received_1to2: BTreeMap<PartyIndex, Vec<TransmitPhase1to2>> = BTreeMap::new();
        for &party_index in signers {
            let messages = transmit_1to2
                .values()
                .flat_map(|messages| {
                    messages
                        .iter()
                        .filter(|message| message.parties.receiver == party_index)
                        .cloned()
                })
                .collect();
            received_1to2.insert(party_index, messages);
        }

        let mut unique_kept_2to3 = BTreeMap::new();
        let mut kept_2to3 = BTreeMap::new();
        let mut transmit_2to3: BTreeMap<PartyIndex, Vec<TransmitPhase2to3<TestCurve>>> =
            BTreeMap::new();
        for &party_index in signers {
            let (unique_keep, keep, transmit) = party(party_index).sign_phase2(
                all_data.get(&party_index).unwrap(),
                unique_kept_1to2.get(&party_index).unwrap(),
                kept_1to2.get(&party_index).unwrap(),
                received_1to2.get(&party_index).unwrap(),
            )?;
            unique_kept_2to3.insert(party_index, unique_keep);
            kept_2to3.insert(party_index, keep);
            transmit_2to3.insert(party_index, transmit);
        }

        let mut received_2to3: BTreeMap<PartyIndex, Vec<TransmitPhase2to3<TestCurve>>> =
            BTreeMap::new();
        for &party_index in signers {
            let messages = transmit_2to3
                .values()
                .flat_map(|messages| {
                    messages
                        .iter()
                        .filter(|message| message.parties.receiver == party_index)
                        .cloned()
                })
                .collect();
            received_2to3.insert(party_index, messages);
        }

        let mut x_coords = Vec::with_capacity(signers.len());
        let mut broadcast_3to4 = Vec::with_capacity(signers.len());
        for &party_index in signers {
            let (x_coord, broadcast) = party(party_index).sign_phase3(
                all_data.get(&party_index).unwrap(),
                unique_kept_2to3.get(&party_index).unwrap(),
                kept_2to3.get(&party_index).unwrap(),
                received_2to3.get(&party_index).unwrap(),
            )?;
            x_coords.push(x_coord);
            broadcast_3to4.push(broadcast);
        }
        assert!(x_coords.iter().all(|x| *x == x_coords[0]));

        let first = signers[0];
        let (signature, _recovery_id) = party(first).sign_phase4(
            all_data.get(&first).unwrap(),
            &x_coords[0],
            &broadcast_3to4,
            true,
        )?;

        Ok((x_coords[0].clone(), signature))
    }

    fn signers() -> Vec<PartyIndex> {
        (1..=THRESHOLD)
            .map(|i| PartyIndex::new(i).unwrap())
            .collect()
    }

    #[test]
    fn test_tweak_add_shifts_share_and_public_key() {
        let (parties, _, _) = sample_parties();
        let tweak = Scalar::from(7u64);

        for before in &parties {
            let after = before.tweak_add(&tweak, hex_address).unwrap();
            assert_eq!(after.poly_point, before.poly_point + tweak);
            assert_eq!(after.pk, shifted(&before.pk, &tweak));
            assert_metadata_preserved(before, &after);
        }
    }

    #[test]
    fn test_tweak_mul_scales_share_and_public_key() {
        let (parties, _, _) = sample_parties();
        let factor = Scalar::from(3u64);

        for before in &parties {
            let after = before.tweak_mul(&factor, hex_address).unwrap();
            assert_eq!(after.poly_point, before.poly_point * factor);
            assert_eq!(after.pk, scaled(&before.pk, &factor));
            assert_metadata_preserved(before, &after);
        }
    }

    #[test]
    fn test_public_key_package_tweak_matches_parties() {
        let (parties, package, _) = sample_parties();
        let tweak = Scalar::from(7u64);
        let factor = Scalar::from(3u64);

        let added = package.tweak_add(&tweak).unwrap();
        let scaled_package = package.tweak_mul(&factor).unwrap();
        assert_eq!(added.threshold(), package.threshold());
        assert_eq!(added.share_count(), package.share_count());

        for party in &parties {
            let party_added = party.tweak_add(&tweak, hex_address).unwrap();
            assert_eq!(added.verifying_key(), &party_added.pk);
            assert!(added.verify_share(
                party.party_index,
                &(AffinePoint::GENERATOR * party_added.poly_point).to_affine()
            ));

            let party_scaled = party.tweak_mul(&factor, hex_address).unwrap();
            assert_eq!(scaled_package.verifying_key(), &party_scaled.pk);
            assert!(scaled_package.verify_share(
                party.party_index,
                &(AffinePoint::GENERATOR * party_scaled.poly_point).to_affine()
            ));
        }
    }

    #[test]
    fn test_tweak_and_signing() {
        let (parties, package, secret_key) = sample_parties();
        let tweak = Scalar::from(7u64);
        let factor = Scalar::from(3u64);

        let tweaked: Vec<Party<TestCurve>> = parties
            .iter()
            .map(|party| {
                party
                    .tweak_add(&tweak, hex_address)
                    .unwrap()
                    .tweak_mul(&factor, hex_address)
                    .unwrap()
            })
            .collect();
        let tweaked_package = package
            .tweak_add(&tweak)
            .unwrap()
            .tweak_mul(&factor)
            .unwrap();

        let expected_secret = (secret_key + tweak) * factor;
        let expected_pk = (AffinePoint::GENERATOR * expected_secret).to_affine();
        assert_eq!(tweaked_package.verifying_key(), &expected_pk);

        let message = tagged_hash(b"test-tweak", &[b"Message to sign!"]);
        let (x_coord, signature) = sign_with(&tweaked, &signers(), &message)
            .unwrap_or_else(|abort| panic!("aborted: {}", abort.description()));

        assert!(verify_ecdsa_signature::<TestCurve>(
            &message,
            &expected_pk,
            &x_coord,
            &signature
        ));
        assert!(!verify_ecdsa_signature::<TestCurve>(
            &message,
            package.verifying_key(),
            &x_coord,
            &signature
        ));
    }

    #[test]
    fn test_mixed_tweaked_and_untweaked_parties_abort() {
        let (mut parties, _, _) = sample_parties();
        parties[0] = parties[0]
            .tweak_add(&Scalar::from(7u64), hex_address)
            .unwrap();

        let message = tagged_hash(b"test-tweak", &[b"Message to sign!"]);
        let abort = sign_with(&parties, &signers(), &message)
            .expect_err("signers disagreeing on the tweak must abort");
        assert_eq!(abort.reason, AbortReason::PolynomialInconsistency);
    }

    #[test]
    fn test_tweak_mul_rejects_zero_factor() {
        let (parties, package, _) = sample_parties();
        assert_eq!(
            parties[0]
                .tweak_mul(&Scalar::ZERO, hex_address)
                .unwrap_err(),
            TweakError::ZeroFactor
        );
        assert_eq!(
            package.tweak_mul(&Scalar::ZERO).unwrap_err(),
            TweakError::ZeroFactor
        );
    }

    #[test]
    fn test_tweak_add_rejects_identity_public_key() {
        let (parties, package, secret_key) = sample_parties();
        assert_eq!(
            parties[0]
                .tweak_add(&(-secret_key), hex_address)
                .unwrap_err(),
            TweakError::IdentityPublicKey
        );
        assert_eq!(
            package.tweak_add(&(-secret_key)).unwrap_err(),
            TweakError::IdentityPublicKey
        );
    }

    #[test]
    fn test_tweak_add_zero_and_mul_one_are_noops() {
        let (parties, package, _) = sample_parties();
        let party = &parties[1];

        let same = party.tweak_add(&Scalar::ZERO, hex_address).unwrap();
        assert_eq!(same.poly_point, party.poly_point);
        assert_eq!(same.pk, party.pk);
        let same = party.tweak_mul(&Scalar::ONE, hex_address).unwrap();
        assert_eq!(same.poly_point, party.poly_point);
        assert_eq!(same.pk, party.pk);

        assert_eq!(
            package.tweak_add(&Scalar::ZERO).unwrap().verifying_key(),
            package.verifying_key()
        );
        assert_eq!(
            package.tweak_mul(&Scalar::ONE).unwrap().verifying_key(),
            package.verifying_key()
        );
    }

    #[test]
    fn test_tweak_composition_matches_single_scalar() {
        let (parties, _, _) = sample_parties();
        let party = &parties[2];
        let (t1, t2, a) = (Scalar::from(7u64), Scalar::from(5u64), Scalar::from(3u64));

        let twice = party
            .tweak_add(&t1, hex_address)
            .unwrap()
            .tweak_add(&t2, hex_address)
            .unwrap();
        let once = party.tweak_add(&(t1 + t2), hex_address).unwrap();
        assert_eq!(twice.poly_point, once.poly_point);
        assert_eq!(twice.pk, once.pk);

        let composed = party
            .tweak_mul(&a, hex_address)
            .unwrap()
            .tweak_add(&t1, hex_address)
            .unwrap();
        assert_eq!(composed.poly_point, party.poly_point * a + t1);
        assert_eq!(composed.pk, shifted(&scaled(&party.pk, &a), &t1));
    }

    #[test]
    fn test_derive_child_after_tweak_stays_consistent() {
        let (parties, package, _) = sample_parties();
        let tweak = Scalar::from(7u64);

        let tweaked_package = package.tweak_add(&tweak).unwrap();
        let child_package = tweaked_package
            .derive_child(parties[0].chain_code(), 4)
            .unwrap();

        for party in &parties {
            let tweaked = party.tweak_add(&tweak, hex_address).unwrap();
            assert_eq!(tweaked.chain_code(), party.chain_code());

            let child = tweaked.derive_child(4, hex_address).unwrap();
            assert_eq!(child_package.verifying_key(), &child.pk);
            assert!(child_package.verify_share(
                party.party_index,
                &(AffinePoint::GENERATOR * child.poly_point).to_affine()
            ));
        }
    }

    #[test]
    fn test_scalar_from_be_bytes() {
        assert_eq!(
            scalar_from_be_bytes::<TestCurve>(&scalar_bytes(42)).unwrap(),
            Scalar::from(42u64)
        );
        assert_eq!(
            scalar_from_be_bytes::<TestCurve>(&[0xff; 32]).unwrap(),
            Scalar::reduce(&U256::MAX)
        );

        let order_plus_one =
            U256::from_be_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142");
        assert_eq!(
            scalar_from_be_bytes::<TestCurve>(&order_plus_one.to_be_bytes()).unwrap(),
            Scalar::ONE
        );

        assert_eq!(
            scalar_from_be_bytes::<TestCurve>(&[1u8; 31]).unwrap_err(),
            TweakError::InvalidScalarLength {
                expected: 32,
                got: 31
            }
        );
        assert_eq!(
            scalar_from_be_bytes::<TestCurve>(&[1u8; 33]).unwrap_err(),
            TweakError::InvalidScalarLength {
                expected: 32,
                got: 33
            }
        );
    }
}
