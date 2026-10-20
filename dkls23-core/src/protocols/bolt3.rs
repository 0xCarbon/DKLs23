//! BOLT 3 key derivation on key shares.
//!
//! Lightning derives a fresh key for every commitment from a base key and a
//! per-commitment point ([BOLT 3, "Key Derivation"]):
//!
//! - `localpubkey`, `htlcpubkey`, `delayedpubkey`:
//!   `basepoint + SHA256(per_commitment_point || basepoint)·G`
//! - `revocationpubkey`:
//!   `revocation_basepoint·SHA256(revocation_basepoint || per_commitment_point)
//!   + per_commitment_point·SHA256(per_commitment_point || revocation_basepoint)`
//!
//! With a threshold key nobody holds the base secret, so each party maps its
//! own share with [`Party::bolt3_derive`] or [`Party::bolt3_derive_revocation`],
//! and the public key package maps the group key and every verifying share
//! with the matching [`PublicKeyPackage`] functions. Both are the affine map
//! `x ↦ a·x + c`. Signing reconstructs `sk = Σ lᵢ·xᵢ` with Lagrange
//! coefficients that sum to one, so the mapped shares sign under `a·sk + c`.
//!
//! # Security
//!
//! Every tweak is a hash of public points, and each party computes it from
//! the group key and the per-commitment point. A raw caller-supplied tweak is
//! deliberately not exposed: a signature on hash `m` under `a·X` is also a
//! valid signature on hash `m/a` under `X`, so whoever chooses a
//! multiplicative factor can turn an approved signature into a signature
//! under the base key on a message of their choice. A caller can still grind
//! the per-commitment point, but cannot pick the hash outputs; and a
//! signature under a derived key `a·X + c·G` corresponds under `X` to the
//! hash `(m + r·c)/a`, which depends on the nonce `r`, fixed only after the
//! message and the per-commitment point. This relies on the parties signing
//! hashes they compute from transactions they validate, and on there being
//! no presignatures.
//!
//! The derived party reuses the base-OT correlations, zero-share seeds and
//! multiplication state, which never depend on the value of the share, as
//! BIP-32 derivation does. Signing session ids include the public key, so the
//! base key and every derived key run their multiplications under distinct
//! ids for the same `sign_id`. Because the OT state is shared, an abort that
//! bans a counterparty under one derived key bans it for the base key and
//! every other derived key, and a leaked derived private key reveals the
//! base key.
//!
//! The chain code and the BIP-32 metadata are left unchanged, so deriving a
//! child of a derived party is a further additive shift under the same chain
//! code.
//!
//! All executing parties must derive with the same per-commitment point. The
//! derived public key is part of every signing message's session binding, so
//! a mismatch aborts with a recoverable `SessionBindingMismatch`.
//!
//! [BOLT 3, "Key Derivation"]: https://github.com/lightning/bolts/blob/master/03-transactions.md#key-derivation

use std::fmt;

use ff::{Field, PrimeField};
use group::{Curve as GroupCurve, CurveAffine};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::curve::DklsCurve;
use crate::protocols::derivation::DerivData;
use crate::protocols::{Party, PublicKeyPackage};
use crate::utilities::hashes::point_to_bytes;

/// Errors returned by the BOLT 3 derivations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Bolt3Error {
    /// The per-commitment point is the identity point.
    InvalidPerCommitmentPoint,
    /// `per_commitment_secret·G` is not the per-commitment point.
    PerCommitmentSecretMismatch,
    /// A BOLT 3 hash is zero or not below the group order.
    HashNotAScalar,
    /// The curve's scalars are not 32 bytes, so a SHA-256 output is not one.
    UnsupportedCurve,
    /// The derived public key is the identity point.
    IdentityPublicKey,
}

impl fmt::Display for Bolt3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Bolt3Error::InvalidPerCommitmentPoint => {
                write!(f, "per-commitment point is the identity point")
            }
            Bolt3Error::PerCommitmentSecretMismatch => {
                write!(
                    f,
                    "per-commitment secret does not match the per-commitment point"
                )
            }
            Bolt3Error::HashNotAScalar => write!(f, "BOLT 3 hash is not a valid scalar"),
            Bolt3Error::UnsupportedCurve => write!(f, "curve scalars are not 32 bytes"),
            Bolt3Error::IdentityPublicKey => write!(f, "derived public key is the identity point"),
        }
    }
}

impl std::error::Error for Bolt3Error {}

/// `SHA256(first || second)` over the points' compressed encodings, as a
/// nonzero scalar.
fn bolt3_hash<C: DklsCurve>(
    first: &C::AffinePoint,
    second: &C::AffinePoint,
) -> Result<C::Scalar, Bolt3Error> {
    let digest = Sha256::new()
        .chain_update(point_to_bytes::<C>(first))
        .chain_update(point_to_bytes::<C>(second))
        .finalize();
    digest_to_scalar::<C>(&digest)
}

/// Interprets a 32-byte digest as a big-endian scalar.
///
/// A digest that is zero or not below the group order is rejected rather
/// than reduced (rust-lightning panics on it; LND reduces). For secp256k1 this
/// happens with probability about 2^-128; for P-256, about 2^-32.
fn digest_to_scalar<C: DklsCurve>(digest: &[u8]) -> Result<C::Scalar, Bolt3Error> {
    let bytes: &elliptic_curve::FieldBytes<C> = digest
        .try_into()
        .map_err(|_| Bolt3Error::UnsupportedCurve)?;
    let scalar: Option<C::Scalar> = Option::from(<C::Scalar as PrimeField>::from_repr(*bytes));
    scalar
        .filter(|value| !bool::from(value.is_zero()))
        .ok_or(Bolt3Error::HashNotAScalar)
}

fn check_per_commitment_point<C: DklsCurve>(point: &C::AffinePoint) -> Result<(), Bolt3Error> {
    if *point == <C::AffinePoint as CurveAffine>::identity() {
        return Err(Bolt3Error::InvalidPerCommitmentPoint);
    }
    Ok(())
}

/// The affine map `x ↦ factor·x + offset` on shares, which is
/// `P ↦ factor·P + offset_point` on points, with `offset_point = offset·G`.
struct ShareMap<C: DklsCurve> {
    factor: C::Scalar,
    offset_point: C::AffinePoint,
}

impl<C: DklsCurve> ShareMap<C> {
    /// `localpubkey` and friends: `x ↦ x + SHA256(per_commitment_point || basepoint)`.
    /// Also returns the hash, which is the (public) scalar offset.
    fn simple(
        basepoint: &C::AffinePoint,
        per_commitment_point: &C::AffinePoint,
    ) -> Result<(Self, C::Scalar), Bolt3Error> {
        check_per_commitment_point::<C>(per_commitment_point)?;
        let tweak = bolt3_hash::<C>(per_commitment_point, basepoint)?;
        let generator = <C::AffinePoint as CurveAffine>::generator();
        let map = ShareMap {
            factor: <C::Scalar as Field>::ONE,
            offset_point: (generator * tweak).to_affine(),
        };
        Ok((map, tweak))
    }

    /// `revocationpubkey`: the factor is `SHA256(revocation_basepoint ||
    /// per_commitment_point)` and the offset point is
    /// `per_commitment_point·SHA256(per_commitment_point || revocation_basepoint)`.
    /// Also returns the second hash, which scales the per-commitment secret.
    fn revocation(
        basepoint: &C::AffinePoint,
        per_commitment_point: &C::AffinePoint,
    ) -> Result<(Self, C::Scalar), Bolt3Error> {
        check_per_commitment_point::<C>(per_commitment_point)?;
        let factor = bolt3_hash::<C>(basepoint, per_commitment_point)?;
        let commitment_factor = bolt3_hash::<C>(per_commitment_point, basepoint)?;
        let map = ShareMap {
            factor,
            offset_point: (*per_commitment_point * commitment_factor).to_affine(),
        };
        Ok((map, commitment_factor))
    }

    fn apply_point(&self, point: &C::AffinePoint) -> C::AffinePoint {
        ((*point * self.factor) + C::ProjectivePoint::from(self.offset_point)).to_affine()
    }

    /// Applies the map to a party, given the scalar offset (`offset·G` must be
    /// `self.offset_point`).
    fn apply_party(
        &self,
        party: &Party<C>,
        offset: &C::Scalar,
        address_fn: impl Fn(&C::AffinePoint) -> String,
    ) -> Result<Party<C>, Bolt3Error> {
        let pk = self.apply_point(&party.pk);
        if pk == <C::AffinePoint as CurveAffine>::identity() {
            return Err(Bolt3Error::IdentityPublicKey);
        }
        let poly_point = party.poly_point * self.factor + *offset;
        let address = address_fn(&pk);

        Ok(Party {
            parameters: party.parameters.clone(),
            party_index: party.party_index,
            session_id: party.session_id.clone(),

            poly_point,
            pk,

            zero_share: party.zero_share.clone(),

            mul_senders: party.mul_senders.clone(),
            mul_receivers: party.mul_receivers.clone(),

            derivation_data: DerivData {
                depth: party.derivation_data.depth,
                child_number: party.derivation_data.child_number,
                parent_fingerprint: party.derivation_data.parent_fingerprint,
                poly_point,
                pk,
                chain_code: party.derivation_data.chain_code,
            },

            address,
        })
    }

    fn apply_package(
        &self,
        package: &PublicKeyPackage<C>,
    ) -> Result<PublicKeyPackage<C>, Bolt3Error> {
        let verifying_key = self.apply_point(package.verifying_key());
        if verifying_key == <C::AffinePoint as CurveAffine>::identity() {
            return Err(Bolt3Error::IdentityPublicKey);
        }
        let verifying_shares = package
            .verifying_shares
            .iter()
            .map(|(party, share)| (*party, self.apply_point(share)))
            .collect();

        Ok(PublicKeyPackage::new(
            verifying_key,
            verifying_shares,
            package.parameters.clone(),
        ))
    }
}

/// BOLT 3 derivations of a party's key share.
impl<C: DklsCurve> Party<C> {
    /// Derives the share of the BOLT 3 `localprivkey`, `htlcprivkey` or
    /// `delayedprivkey` for this party's key as the basepoint:
    /// `x + SHA256(per_commitment_point || basepoint)`.
    ///
    /// The public key becomes `basepoint + SHA256(per_commitment_point ||
    /// basepoint)·G` and `address_fn` recomputes the address. Every executing
    /// party and the [`PublicKeyPackage`] ([`PublicKeyPackage::bolt3_derive`])
    /// must derive with the same per-commitment point. See the
    /// [module documentation](self).
    ///
    /// # Errors
    ///
    /// Returns [`Bolt3Error`] if the per-commitment point is the identity,
    /// the hash is not a valid scalar, or the derived key is the identity.
    pub fn bolt3_derive(
        &self,
        per_commitment_point: &C::AffinePoint,
        address_fn: impl Fn(&C::AffinePoint) -> String,
    ) -> Result<Party<C>, Bolt3Error> {
        let (map, tweak) = ShareMap::<C>::simple(&self.pk, per_commitment_point)?;
        map.apply_party(self, &tweak, address_fn)
    }

    /// Derives the share of the BOLT 3 `revocationprivkey` for this party's
    /// key as the revocation basepoint:
    /// `x·SHA256(basepoint || per_commitment_point) +
    /// per_commitment_secret·SHA256(per_commitment_point || basepoint)`.
    ///
    /// The per-commitment secret is the one the counterparty reveals when it
    /// revokes a commitment; it must satisfy `per_commitment_secret·G ==
    /// per_commitment_point`. The public key becomes the BOLT 3
    /// `revocationpubkey`, which [`PublicKeyPackage::bolt3_derive_revocation`]
    /// computes from public data.
    ///
    /// # Errors
    ///
    /// Returns [`Bolt3Error`] if the per-commitment point is the identity,
    /// the secret does not match it, a hash is not a valid scalar, or the
    /// derived key is the identity.
    pub fn bolt3_derive_revocation(
        &self,
        per_commitment_point: &C::AffinePoint,
        per_commitment_secret: &C::Scalar,
        address_fn: impl Fn(&C::AffinePoint) -> String,
    ) -> Result<Party<C>, Bolt3Error> {
        let (map, commitment_factor) = ShareMap::<C>::revocation(&self.pk, per_commitment_point)?;
        let generator = <C::AffinePoint as CurveAffine>::generator();
        if (generator * *per_commitment_secret).to_affine() != *per_commitment_point {
            return Err(Bolt3Error::PerCommitmentSecretMismatch);
        }
        let offset = Zeroizing::new(*per_commitment_secret * commitment_factor);
        map.apply_party(self, &offset, address_fn)
    }
}

/// BOLT 3 derivations of a public key package, mirroring the [`Party`]
/// derivations.
impl<C: DklsCurve> PublicKeyPackage<C> {
    /// Maps the group key (the basepoint) and every verifying share as
    /// [`Party::bolt3_derive`] maps the shares.
    ///
    /// # Errors
    ///
    /// Returns [`Bolt3Error`] if the per-commitment point is the identity,
    /// the hash is not a valid scalar, or the derived key is the identity.
    pub fn bolt3_derive(
        &self,
        per_commitment_point: &C::AffinePoint,
    ) -> Result<PublicKeyPackage<C>, Bolt3Error> {
        let (map, _) = ShareMap::<C>::simple(self.verifying_key(), per_commitment_point)?;
        map.apply_package(self)
    }

    /// Maps the group key (the revocation basepoint) to the BOLT 3
    /// `revocationpubkey`, and every verifying share as
    /// [`Party::bolt3_derive_revocation`] maps the shares. Needs no secret.
    ///
    /// # Errors
    ///
    /// Returns [`Bolt3Error`] if the per-commitment point is the identity,
    /// a hash is not a valid scalar, or the derived key is the identity.
    pub fn bolt3_derive_revocation(
        &self,
        per_commitment_point: &C::AffinePoint,
    ) -> Result<PublicKeyPackage<C>, Bolt3Error> {
        let (map, _) = ShareMap::<C>::revocation(self.verifying_key(), per_commitment_point)?;
        map.apply_package(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use k256::{AffinePoint, ProjectivePoint, Scalar};
    use rand::RngExt;

    use crate::protocols::derivation::CHAIN_CODE_LEN;
    use crate::protocols::re_key::re_key;
    use crate::protocols::signing::*;
    use crate::protocols::{Abort, AbortKind, AbortReason, Parameters, PartyIndex};
    use crate::utilities::hashes::{tagged_hash, HashOutput};
    use crate::utilities::rng;
    use crate::utilities::ID_LEN;

    type TestCurve = k256::Secp256k1;

    const THRESHOLD: u8 = 2;
    const SHARE_COUNT: u8 = 3;

    // BOLT 3, Appendix E: Key Derivation Test Vectors. The revocation basepoint
    // is the base point `base_secret·G`.
    const BASE_SECRET: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const PER_COMMITMENT_SECRET: &str =
        "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";
    const BASE_POINT: &str = "036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2";
    const PER_COMMITMENT_POINT: &str =
        "025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486";
    const HASH_PER_COMMITMENT_BASE: &str =
        "cbcdd70fcfad15ea8e9e5c5a12365cf00912504f08ce01593689dd426bca9ff0";
    const HASH_BASE_PER_COMMITMENT: &str =
        "efbf7ba5a074276701798376950a64a90f698997cce0dff4d24a6d2785d20963";
    const LOCAL_PUBLIC_KEY: &str =
        "0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5";
    const LOCAL_PRIVATE_KEY: &str =
        "cbced912d3b21bf196a766651e436aff192362621ce317704ea2f75d87e7be0f";
    const REVOCATION_PUBLIC_KEY: &str =
        "02916e326636d19c33f13e8c0c3a03dd157f332f3e99c317c141dd865eb01f8ff0";
    const REVOCATION_PRIVATE_KEY: &str =
        "d09ffff62ddb2297ab000cc85bcb4283fdeb6aa052affbc9dddcf33b61078110";
    // Intermediates of the revocation derivation.
    const REVOCATION_BASE_POINT_TERM: &str =
        "02c00c4aadc536290422a807250824a8d87f19d18da9d610d45621df22510db8ce";
    const PER_COMMITMENT_POINT_TERM: &str =
        "0325ee7d3323ce52c4b33d4e0a73ab637711057dd8866e3b51202a04112f054c43";
    const FIRST_PRODUCT: &str = "44bfd55f845f885b8e60b2dca4b30272d5343be048d79ce87879d9863dedc842";
    const SECOND_PRODUCT: &str = "8be02a96a97b9a3c1c9f59ebb718401128b72ec009d85ee1656319b52319b8ce";

    fn scalar(hex_value: &str) -> Scalar {
        let bytes: [u8; 32] = hex::decode(hex_value).unwrap().try_into().unwrap();
        Option::from(Scalar::from_repr(bytes.into())).unwrap()
    }

    fn point(hex_value: &str) -> AffinePoint {
        *k256::PublicKey::from_sec1_bytes(&hex::decode(hex_value).unwrap())
            .unwrap()
            .as_affine()
    }

    fn hex_address(pk: &AffinePoint) -> String {
        hex::encode(point_to_bytes::<TestCurve>(pk))
    }

    /// A 2-of-3 key whose secret is the BOLT 3 base secret.
    fn sample_parties() -> (Vec<Party<TestCurve>>, PublicKeyPackage<TestCurve>) {
        let parameters = Parameters::new(THRESHOLD, SHARE_COUNT).unwrap();
        let session_id = rng::get_rng().random::<[u8; ID_LEN]>();
        re_key::<TestCurve>(
            &parameters,
            &session_id,
            &scalar(BASE_SECRET),
            Some([9u8; CHAIN_CODE_LEN]),
            hex_address,
        )
    }

    /// Interpolates the secret at zero from the given parties' shares.
    fn reconstruct(parties: &[&Party<TestCurve>]) -> Scalar {
        parties.iter().fold(Scalar::ZERO, |sum, party| {
            let i = Scalar::from(u64::from(party.party_index.as_u8()));
            let lagrange = parties
                .iter()
                .filter(|other| other.party_index != party.party_index)
                .fold(Scalar::ONE, |product, other| {
                    let j = Scalar::from(u64::from(other.party_index.as_u8()));
                    product * j * (j - i).invert().unwrap()
                });
            sum + party.poly_point * lagrange
        })
    }

    fn assert_all_subsets_reconstruct(parties: &[Party<TestCurve>], expected: &Scalar) {
        for (a, b) in [(0, 1), (0, 2), (1, 2)] {
            assert_eq!(reconstruct(&[&parties[a], &parties[b]]), *expected);
        }
    }

    fn assert_package_matches(package: &PublicKeyPackage<TestCurve>, parties: &[Party<TestCurve>]) {
        for party in parties {
            assert_eq!(package.verifying_key(), &party.pk);
            assert!(package.verify_share(
                party.party_index,
                &(AffinePoint::GENERATOR * party.poly_point).to_affine()
            ));
        }
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

    fn per_commitment_point() -> AffinePoint {
        point(PER_COMMITMENT_POINT)
    }

    #[test]
    fn test_bolt3_vector_inputs_and_hashes() {
        let base_point = (AffinePoint::GENERATOR * scalar(BASE_SECRET)).to_affine();
        assert_eq!(base_point, point(BASE_POINT));
        assert_eq!(
            (AffinePoint::GENERATOR * scalar(PER_COMMITMENT_SECRET)).to_affine(),
            per_commitment_point()
        );
        assert_eq!(
            bolt3_hash::<TestCurve>(&per_commitment_point(), &base_point).unwrap(),
            scalar(HASH_PER_COMMITMENT_BASE)
        );
        assert_eq!(
            bolt3_hash::<TestCurve>(&base_point, &per_commitment_point()).unwrap(),
            scalar(HASH_BASE_PER_COMMITMENT)
        );

        let (map, commitment_factor) =
            ShareMap::<TestCurve>::revocation(&base_point, &per_commitment_point()).unwrap();
        assert_eq!(
            (base_point * map.factor).to_affine(),
            point(REVOCATION_BASE_POINT_TERM)
        );
        assert_eq!(map.offset_point, point(PER_COMMITMENT_POINT_TERM));
        assert_eq!(scalar(BASE_SECRET) * map.factor, scalar(FIRST_PRODUCT));
        assert_eq!(
            scalar(PER_COMMITMENT_SECRET) * commitment_factor,
            scalar(SECOND_PRODUCT)
        );
    }

    #[test]
    fn test_digest_to_scalar_range() {
        // secp256k1 group order n.
        let order = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
            .unwrap();
        let mut below_order = order.clone();
        below_order[31] -= 1;

        assert_eq!(
            digest_to_scalar::<TestCurve>(&below_order).unwrap(),
            -Scalar::ONE
        );
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(digest_to_scalar::<TestCurve>(&one).unwrap(), Scalar::ONE);
        for rejected in [vec![0u8; 32], order, vec![0xff; 32]] {
            assert_eq!(
                digest_to_scalar::<TestCurve>(&rejected).unwrap_err(),
                Bolt3Error::HashNotAScalar
            );
        }
        assert_eq!(
            digest_to_scalar::<TestCurve>(&[1u8; 31]).unwrap_err(),
            Bolt3Error::UnsupportedCurve
        );
    }

    #[test]
    fn test_bolt3_derive_matches_vectors() {
        let (parties, package) = sample_parties();
        let derived: Vec<_> = parties
            .iter()
            .map(|party| {
                party
                    .bolt3_derive(&per_commitment_point(), hex_address)
                    .unwrap()
            })
            .collect();

        for (before, after) in parties.iter().zip(&derived) {
            assert_eq!(after.pk, point(LOCAL_PUBLIC_KEY));
            assert_metadata_preserved(before, after);
        }
        assert_all_subsets_reconstruct(&derived, &scalar(LOCAL_PRIVATE_KEY));

        let derived_package = package.bolt3_derive(&per_commitment_point()).unwrap();
        assert_eq!(derived_package.threshold(), package.threshold());
        assert_eq!(derived_package.share_count(), package.share_count());
        assert_package_matches(&derived_package, &derived);
    }

    #[test]
    fn test_bolt3_derive_revocation_matches_vectors() {
        let (parties, package) = sample_parties();
        let derived: Vec<_> = parties
            .iter()
            .map(|party| {
                party
                    .bolt3_derive_revocation(
                        &per_commitment_point(),
                        &scalar(PER_COMMITMENT_SECRET),
                        hex_address,
                    )
                    .unwrap()
            })
            .collect();

        for (before, after) in parties.iter().zip(&derived) {
            assert_eq!(after.pk, point(REVOCATION_PUBLIC_KEY));
            assert_metadata_preserved(before, after);
        }
        assert_all_subsets_reconstruct(&derived, &scalar(REVOCATION_PRIVATE_KEY));

        let derived_package = package
            .bolt3_derive_revocation(&per_commitment_point())
            .unwrap();
        assert_package_matches(&derived_package, &derived);
    }

    #[test]
    fn test_bolt3_derived_keys_sign() {
        let (parties, package) = sample_parties();
        let message = tagged_hash(b"test-bolt3", &[b"commitment transaction"]);

        let local: Vec<_> = parties
            .iter()
            .map(|party| {
                party
                    .bolt3_derive(&per_commitment_point(), hex_address)
                    .unwrap()
            })
            .collect();
        let revocation: Vec<_> = parties
            .iter()
            .map(|party| {
                party
                    .bolt3_derive_revocation(
                        &per_commitment_point(),
                        &scalar(PER_COMMITMENT_SECRET),
                        hex_address,
                    )
                    .unwrap()
            })
            .collect();

        for (derived, expected_pk) in [
            (local, LOCAL_PUBLIC_KEY),
            (revocation, REVOCATION_PUBLIC_KEY),
        ] {
            let (x_coord, signature) = sign_with(&derived, &signers(), &message)
                .unwrap_or_else(|abort| panic!("aborted: {}", abort.description()));
            assert!(verify_ecdsa_signature::<TestCurve>(
                &message,
                &point(expected_pk),
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
    }

    #[test]
    fn test_bolt3_revocation_rejects_wrong_secret() {
        let (parties, _) = sample_parties();
        let wrong_secret = scalar(PER_COMMITMENT_SECRET) + Scalar::ONE;
        assert_eq!(
            parties[0]
                .bolt3_derive_revocation(&per_commitment_point(), &wrong_secret, hex_address)
                .unwrap_err(),
            Bolt3Error::PerCommitmentSecretMismatch
        );
    }

    #[test]
    fn test_bolt3_rejects_identity_per_commitment_point() {
        let (parties, package) = sample_parties();
        let identity = AffinePoint::IDENTITY;
        assert_eq!(
            parties[0].bolt3_derive(&identity, hex_address).unwrap_err(),
            Bolt3Error::InvalidPerCommitmentPoint
        );
        assert_eq!(
            parties[0]
                .bolt3_derive_revocation(&identity, &Scalar::ZERO, hex_address)
                .unwrap_err(),
            Bolt3Error::InvalidPerCommitmentPoint
        );
        assert_eq!(
            package.bolt3_derive(&identity).unwrap_err(),
            Bolt3Error::InvalidPerCommitmentPoint
        );
        assert_eq!(
            package.bolt3_derive_revocation(&identity).unwrap_err(),
            Bolt3Error::InvalidPerCommitmentPoint
        );
    }

    /// Signers that derived with different per-commitment points hold
    /// different public keys, so the session binding catches it.
    #[test]
    fn test_mismatched_per_commitment_points_abort_recoverably() {
        let (mut parties, _) = sample_parties();
        let other_point = (ProjectivePoint::GENERATOR * Scalar::from(7u64)).to_affine();
        parties[0] = parties[0]
            .bolt3_derive(&per_commitment_point(), hex_address)
            .unwrap();
        parties[1] = parties[1].bolt3_derive(&other_point, hex_address).unwrap();

        let message = tagged_hash(b"test-bolt3", &[b"commitment transaction"]);
        let abort = sign_with(&parties, &signers(), &message)
            .expect_err("signers disagreeing on the per-commitment point must abort");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(matches!(
            abort.reason,
            AbortReason::SessionBindingMismatch { .. }
        ));
    }

    #[test]
    fn test_derive_child_after_bolt3_stays_consistent() {
        let (parties, package) = sample_parties();

        let derived_package = package.bolt3_derive(&per_commitment_point()).unwrap();
        let child_package = derived_package
            .derive_child(parties[0].chain_code(), 4)
            .unwrap();

        for party in &parties {
            let derived = party
                .bolt3_derive(&per_commitment_point(), hex_address)
                .unwrap();
            assert_eq!(derived.chain_code(), party.chain_code());

            let child = derived.derive_child(4, hex_address).unwrap();
            assert_eq!(child_package.verifying_key(), &child.pk);
            assert!(child_package.verify_share(
                party.party_index,
                &(AffinePoint::GENERATOR * child.poly_point).to_affine()
            ));
        }
    }
}
