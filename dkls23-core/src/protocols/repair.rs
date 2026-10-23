//! Share repair: rebuild a lost party's share under the same group key.
//!
//! A set of at least `threshold` surviving parties (the *helpers*) rebuilds
//! the share of a party whose key material is lost (the *target*) without any
//! of them learning it. Each helper `i` sends the target, and only the
//! target, one term
//!
//! ```text
//! term_i = poly_point_i · λ_i(target) + mask_i
//! ```
//!
//! where `λ_i(target)` interpolates the group's polynomial at the target's
//! index over the helper set, and the masks are additive shares of zero drawn
//! from the pairwise zero-share seeds the helpers already hold
//! ([`ZeroShare::try_compute`]). Only the sum of all terms equals
//! `f(target)`; a proper subset of the terms reveals nothing about any share.
//! The masks are bound to the helpers' session and public key, the repair
//! id, the target and the helper set: requests that differ in any of these
//! never share a mask, and an identical request gets the identical term
//! (which reveals nothing new).
//!
//! The target assembles the terms with [`repair_assemble`] into a *hollow*
//! party: its share, group key and derivation data are correct, but it holds
//! no zero-share seeds or multiplication state, so it cannot sign (signing
//! aborts with a recoverable `MissingMulState`). A complete refresh across all
//! `n` parties ([`Party::refresh_complete_phase1`]) rebuilds that state and
//! re-randomizes every share while keeping the group key.
//!
//! # Preconditions
//!
//! - **Target authorization is the caller's responsibility.** Repair hands
//!   the share of index `target` to whoever the helpers accept as the
//!   target. If the real party with that index still exists, an impostor
//!   gains a second share and the effective threshold drops by one. Helpers
//!   must authenticate the target out of band, and the group should run the
//!   complete refresh right after the repair. Refreshed shares do not sign
//!   with shares from before the refresh, but a refresh cannot revoke old
//!   shares that someone keeps: every party must adopt its refreshed share
//!   and erase the old one, including backups.
//! - Use the **complete** refresh after a repair, never the fast refresh
//!   (`refresh_phase1..4`): the hollow party has no OT state for it, and
//!   only its own phase 4 notices, after the other parties have already
//!   moved to the refreshed shares. If that happens, repair the target again
//!   from the refreshed parties and run a complete refresh.
//! - After the complete refresh, update the group's public key package with
//!   [`PublicKeyPackage::refresh`] before any later repair: `repair_assemble`
//!   checks the terms against the package's verifying shares.
//! - Terms travel over a confidential, authenticated channel to the target.
//! - Repair is meant for the root shares from DKG, a refresh or `re_key`.
//!   BIP-32-derived shares are refused. The masks are bound to the share's
//!   public key, so terms for a root key and for a key derived from it
//!   (e.g. with BOLT 3) never share a mask.

use std::collections::BTreeMap;
use std::fmt;

use elliptic_curve::Field;
use group::{Curve, Group};
use zeroize::Zeroizing;

use crate::curve::DklsCurve;
use crate::protocols::derivation::{ChainCode, DerivData};
use crate::protocols::{Parameters, Party, PartyIndex, PublicKeyPackage};
use crate::utilities::hashes::{point_to_bytes, tagged_hash};
use crate::utilities::oracle_tags::TAG_REPAIR_MASK;
use crate::utilities::zero_shares::ZeroShare;

/// Why a repair step was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RepairError {
    /// The repair id is empty.
    EmptyRepairId,
    /// The helper set is not sorted and unique, has fewer than `threshold`
    /// members, has an index out of range, or contains the target.
    InvalidHelperSet,
    /// The caller is not in the helper set.
    NotInHelperSet,
    /// The target index is out of range.
    InvalidTarget,
    /// The caller's share is derived; repair applies to root shares.
    DerivedShare,
    /// The caller holds no zero-share seed with this helper, so its term
    /// could not be masked.
    MissingSeed { counterparty: PartyIndex },
    /// Fewer terms than the threshold.
    NotEnoughTerms,
    /// The terms do not add up to the target's verifying share (wrong
    /// helper set, repair id or session, or a corrupted term).
    ShareMismatch,
}

impl fmt::Display for RepairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyRepairId => write!(f, "the repair id is empty"),
            Self::InvalidHelperSet => write!(f, "invalid helper set"),
            Self::NotInHelperSet => write!(f, "this party is not in the helper set"),
            Self::InvalidTarget => write!(f, "invalid target index"),
            Self::DerivedShare => write!(f, "repair applies to root shares only"),
            Self::MissingSeed { counterparty } => {
                write!(f, "no zero-share seed for helper {counterparty}")
            }
            Self::NotEnoughTerms => write!(f, "fewer repair terms than the threshold"),
            Self::ShareMismatch => {
                write!(f, "repair terms do not match the target's verifying share")
            }
        }
    }
}

impl std::error::Error for RepairError {}

fn index_scalar<C: DklsCurve>(index: PartyIndex) -> C::Scalar {
    C::Scalar::from(u64::from(index.as_u8()))
}

/// `λ_self(target)` over `helpers`.
fn lagrange_at<C: DklsCurve>(
    helpers: &[PartyIndex],
    me: PartyIndex,
    target: PartyIndex,
) -> C::Scalar {
    let x_me = index_scalar::<C>(me);
    let x_target = index_scalar::<C>(target);
    let mut numerator = <C::Scalar as Field>::ONE;
    let mut denominator = <C::Scalar as Field>::ONE;
    for &other in helpers.iter().filter(|&&other| other != me) {
        let x_other = index_scalar::<C>(other);
        numerator *= x_target - x_other;
        denominator *= x_me - x_other;
    }
    // Helpers are distinct, so the denominator is non-zero.
    numerator * denominator.invert().unwrap()
}

fn validate_helpers(
    parameters: &Parameters,
    helpers: &[PartyIndex],
    target: PartyIndex,
) -> Result<(), RepairError> {
    // Index 0 cannot be built through `PartyIndex::new` or deserialization,
    // but a zeroized index is 0, and terms for target 0 would add up to the
    // group secret.
    if target.as_u8() == 0 || target.as_u8() > parameters.share_count {
        return Err(RepairError::InvalidTarget);
    }
    let sorted_unique = helpers.windows(2).all(|pair| pair[0] < pair[1]);
    if !sorted_unique
        || helpers.len() < usize::from(parameters.threshold)
        || helpers.iter().any(|&helper| {
            helper == target || helper.as_u8() == 0 || helper.as_u8() > parameters.share_count
        })
    {
        return Err(RepairError::InvalidHelperSet);
    }
    Ok(())
}

impl<C: DklsCurve> Party<C> {
    /// This helper's masked term for repairing `target`'s share.
    ///
    /// `helpers` is the sorted helper set (at least `threshold` parties,
    /// including this one, not the target). Every helper must use the same
    /// `helpers` and `repair_id`, or the masks do not cancel and
    /// [`repair_assemble`] fails. Send the term to the target only.
    ///
    /// # Errors
    ///
    /// Returns a [`RepairError`] for an empty `repair_id`, an invalid helper
    /// set or target, a derived share, or a helper this party shares no
    /// zero-share seed with (such as a hollow, not yet refreshed share).
    pub fn repair_term(
        &self,
        helpers: &[PartyIndex],
        target: PartyIndex,
        repair_id: &[u8],
    ) -> Result<C::Scalar, RepairError> {
        if repair_id.is_empty() {
            return Err(RepairError::EmptyRepairId);
        }
        validate_helpers(&self.parameters, helpers, target)?;
        if !helpers.contains(&self.party_index) {
            return Err(RepairError::NotInHelperSet);
        }
        if self.derivation_data.depth != 0 {
            return Err(RepairError::DerivedShare);
        }

        let counterparties: Vec<PartyIndex> = helpers
            .iter()
            .copied()
            .filter(|&helper| helper != self.party_index)
            .collect();
        let helper_bytes: Vec<u8> = helpers.iter().map(|helper| helper.as_u8()).collect();
        let mask_id = tagged_hash(
            TAG_REPAIR_MASK,
            &[
                &self.session_id,
                &point_to_bytes::<C>(&self.pk),
                repair_id,
                &[target.as_u8()],
                &helper_bytes,
            ],
        );
        let mask = Zeroizing::new(
            self.zero_share
                .try_compute::<C>(&counterparties, &mask_id)
                .map_err(|missing| RepairError::MissingSeed {
                    counterparty: missing.counterparty,
                })?,
        );
        let lambda = lagrange_at::<C>(helpers, self.party_index, target);
        let scaled = Zeroizing::new(self.poly_point * lambda);
        Ok(*scaled + *mask)
    }
}

/// Assembles the helpers' terms into the target's hollow party.
///
/// `package` and `session_id` are the group's public key package and
/// session id (`Party::session_id`), and `chain_code` the group's chain code,
/// as the helpers report them. The terms must add up to a share whose public
/// point is the target's verifying share in `package`.
///
/// The hollow party cannot sign until all `n` parties run a complete
/// refresh.
///
/// # Errors
///
/// Returns [`RepairError::InvalidTarget`] for an index outside `package`,
/// [`RepairError::NotEnoughTerms`] for fewer than `threshold` terms and
/// [`RepairError::ShareMismatch`] if the sum does not match.
pub fn repair_assemble<C: DklsCurve>(
    package: &PublicKeyPackage<C>,
    session_id: &[u8],
    chain_code: ChainCode,
    target: PartyIndex,
    terms: &[C::Scalar],
    address_fn: impl Fn(&C::AffinePoint) -> String,
) -> Result<Party<C>, RepairError> {
    if target.as_u8() == 0 {
        return Err(RepairError::InvalidTarget);
    }
    let expected = package
        .verifying_share(target)
        .ok_or(RepairError::InvalidTarget)?;
    if terms.len() < usize::from(package.threshold()) {
        return Err(RepairError::NotEnoughTerms);
    }
    let poly_point = Zeroizing::new(terms.iter().copied().sum::<C::Scalar>());
    if (C::ProjectivePoint::generator() * *poly_point).to_affine() != *expected {
        return Err(RepairError::ShareMismatch);
    }

    let parameters = Parameters::new(package.threshold(), package.share_count())
        .map_err(|_| RepairError::InvalidTarget)?;
    let pk = *package.verifying_key();
    Ok(Party {
        parameters,
        party_index: target,
        session_id: session_id.to_vec(),
        poly_point: *poly_point,
        pk,
        zero_share: ZeroShare::initialize(Vec::new()),
        mul_senders: BTreeMap::new(),
        mul_receivers: BTreeMap::new(),
        derivation_data: DerivData {
            depth: 0,
            child_number: 0,
            parent_fingerprint: [0; 4],
            poly_point: *poly_point,
            pk,
            chain_code,
        },
        address: address_fn(&pk),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::re_key::re_key;
    use crate::protocols::sign_session::SignSession;
    use crate::protocols::signing::{verify_ecdsa_signature, SignData};
    use crate::protocols::AbortReason;
    use crate::utilities::rng;
    use rand::RngExt;

    fn index(i: u8) -> PartyIndex {
        PartyIndex::new(i).unwrap()
    }

    fn group<C: DklsCurve>(threshold: u8, share_count: u8) -> (Vec<Party<C>>, PublicKeyPackage<C>) {
        let parameters = Parameters::new(threshold, share_count).unwrap();
        let session_id = rng::get_rng().random::<[u8; 32]>();
        let secret = C::Scalar::random(&mut rng::get_rng());
        re_key::<C>(&parameters, &session_id, &secret, None, |_| String::new())
    }

    /// A complete refresh of every party (all `n`), with the round-2 proof
    /// commitments for `PublicKeyPackage::refresh`.
    fn complete_refresh_with_proofs<C: DklsCurve>(
        parties: &[Party<C>],
        refresh_sid: &[u8],
    ) -> (
        Vec<Party<C>>,
        Vec<crate::protocols::dkg::ProofCommitment<C>>,
    ) {
        let n = parties.len();
        let fragments: Vec<Vec<C::Scalar>> =
            parties.iter().map(Party::refresh_complete_phase1).collect();
        let mut corrections = Vec::new();
        let mut proofs = Vec::new();
        let mut zero_kept_2to3 = Vec::new();
        let mut zero_2to4 = Vec::new();
        for (i, party) in parties.iter().enumerate() {
            let column: Vec<C::Scalar> = fragments.iter().map(|row| row[i]).collect();
            let (correction, proof, kept, transmit) =
                party.refresh_complete_phase2(refresh_sid, &column);
            corrections.push(correction);
            proofs.push(proof);
            zero_kept_2to3.push(kept);
            zero_2to4.extend(transmit);
        }
        let mut zero_kept_3to4 = Vec::new();
        let mut zero_3to4 = Vec::new();
        let mut mul_kept = Vec::new();
        let mut mul_3to4 = Vec::new();
        for (party, kept) in parties.iter().zip(&zero_kept_2to3) {
            let (zero_kept, zero_transmit, mul_keep, mul_transmit) =
                party.refresh_complete_phase3(refresh_sid, kept);
            zero_kept_3to4.push(zero_kept);
            zero_3to4.extend(zero_transmit);
            mul_kept.push(mul_keep);
            mul_3to4.extend(mul_transmit);
        }
        let refreshed = (0..n)
            .map(|i| {
                let me = parties[i].party_index;
                parties[i]
                    .refresh_complete_phase4(
                        refresh_sid,
                        &corrections[i],
                        &proofs,
                        &zero_kept_3to4[i],
                        &zero_2to4
                            .iter()
                            .filter(|m| m.parties.receiver == me)
                            .cloned()
                            .collect::<Vec<_>>(),
                        &zero_3to4
                            .iter()
                            .filter(|m| m.parties.receiver == me)
                            .cloned()
                            .collect::<Vec<_>>(),
                        &mul_kept[i],
                        &mul_3to4
                            .iter()
                            .filter(|m| m.parties.receiver == me)
                            .cloned()
                            .collect::<Vec<_>>(),
                    )
                    .unwrap()
            })
            .collect();
        (refreshed, proofs)
    }

    /// Signs with `signers` and checks the signature under their group key.
    fn signs<C: DklsCurve>(signers: &[&Party<C>]) -> Result<(), AbortReason> {
        let sign_id = rng::get_rng().random::<[u8; 32]>();
        let message_hash = rng::get_rng().random::<[u8; 32]>();
        let mut sessions = Vec::new();
        let mut round1 = Vec::new();
        for party in signers {
            let data = SignData {
                sign_id: sign_id.to_vec(),
                counterparties: signers
                    .iter()
                    .map(|p| p.party_index)
                    .filter(|&i| i != party.party_index)
                    .collect(),
                message_hash,
            };
            let (session, transmit) = SignSession::new(party, data).map_err(|a| a.reason)?;
            sessions.push(session);
            round1.extend(transmit);
        }
        let mut round2 = Vec::new();
        for (session, party) in sessions.iter_mut().zip(signers) {
            let received: Vec<_> = round1
                .iter()
                .filter(|m| m.parties.receiver == party.party_index)
                .cloned()
                .collect();
            round2.extend(session.phase2(&received).map_err(|a| a.reason)?);
        }
        let mut broadcasts = Vec::new();
        for (session, party) in sessions.iter_mut().zip(signers) {
            let received: Vec<_> = round2
                .iter()
                .filter(|m| m.parties.receiver == party.party_index)
                .cloned()
                .collect();
            broadcasts.push(session.phase3(&received).map_err(|a| a.reason)?);
        }
        let signature = sessions
            .remove(0)
            .phase4(&broadcasts, true)
            .map_err(|a| a.reason)?;
        assert!(verify_ecdsa_signature::<C>(
            &message_hash,
            &signers[0].pk,
            &hex::encode(signature.r),
            &hex::encode(signature.s),
        ));
        Ok(())
    }

    fn repair<C: DklsCurve>(
        parties: &[Party<C>],
        package: &PublicKeyPackage<C>,
        helpers: &[PartyIndex],
        target: PartyIndex,
        repair_id: &[u8],
    ) -> Result<Party<C>, RepairError> {
        let terms = helpers
            .iter()
            .map(|h| parties[usize::from(h.as_u8() - 1)].repair_term(helpers, target, repair_id))
            .collect::<Result<Vec<_>, _>>()?;
        repair_assemble(
            package,
            &parties[0].session_id,
            *parties[0].chain_code(),
            target,
            &terms,
            |_| String::new(),
        )
    }

    fn repair_then_refresh_signs<C: DklsCurve>() {
        let (parties, package) = group::<C>(2, 3);
        let target = index(3);
        let hollow = repair(
            &parties,
            &package,
            &[index(1), index(2)],
            target,
            b"repair-1",
        )
        .unwrap();
        assert_eq!(hollow.poly_point, parties[2].poly_point);
        assert_eq!(hollow.pk, parties[0].pk);
        assert_eq!(hollow.chain_code(), parties[0].chain_code());

        // The hollow share cannot sign.
        assert!(matches!(
            signs(&[&parties[0], &hollow]),
            Err(AbortReason::MissingMulState { .. })
        ));

        // After a complete refresh across all parties, it signs with each peer.
        let group_after = vec![parties[0].clone(), parties[1].clone(), hollow];
        let (refreshed, proofs) = complete_refresh_with_proofs(&group_after, b"after-repair");
        signs(&[&refreshed[0], &refreshed[2]]).unwrap();
        signs(&[&refreshed[1], &refreshed[2]]).unwrap();
        assert_eq!(refreshed[2].pk, parties[0].pk);

        // A share from before the refresh does not sign with refreshed ones.
        assert!(matches!(
            signs(&[&refreshed[0], &parties[2]]),
            Err(AbortReason::SessionBindingMismatch { .. })
        ));

        // With the refreshed package, a later repair works again.
        let package = package.refresh(b"after-repair", &proofs).unwrap();
        let again = repair(
            &refreshed,
            &package,
            &[index(1), index(3)],
            index(2),
            b"repair-2",
        )
        .unwrap();
        assert_eq!(again.poly_point, refreshed[1].poly_point);
    }

    #[test]
    fn test_repair_then_refresh_signs_secp256k1() {
        repair_then_refresh_signs::<k256::Secp256k1>();
    }

    #[test]
    fn test_repair_then_refresh_signs_secp256r1() {
        repair_then_refresh_signs::<p256::NistP256>();
    }

    /// More helpers than the threshold work too.
    #[test]
    fn test_repair_with_more_helpers_than_threshold() {
        let (parties, package) = group::<k256::Secp256k1>(3, 5);
        let helpers = [index(1), index(2), index(4), index(5)];
        let hollow = repair(&parties, &package, &helpers, index(3), b"repair").unwrap();
        assert_eq!(hollow.poly_point, parties[2].poly_point);
    }

    /// Terms from repairs with different helper sets or repair ids do not
    /// combine, and each term is masked.
    #[test]
    fn test_repair_terms_are_bound_and_masked() {
        let (parties, package) = group::<k256::Secp256k1>(2, 4);
        let target = index(4);
        let a = parties[0]
            .repair_term(&[index(1), index(2)], target, b"r")
            .unwrap();
        let b = parties[1]
            .repair_term(&[index(1), index(2)], target, b"r")
            .unwrap();
        let b_other_id = parties[1]
            .repair_term(&[index(1), index(2)], target, b"s")
            .unwrap();
        let b_other_set = parties[1]
            .repair_term(&[index(2), index(3)], target, b"r")
            .unwrap();
        let expected = package.verifying_share(target).unwrap();
        let point = |s: k256::Scalar| (k256::ProjectivePoint::GENERATOR * s).to_affine();
        assert_eq!(point(a + b), *expected);
        assert_ne!(point(a + b_other_id), *expected);
        assert_ne!(point(a + b_other_set), *expected);

        // Without a mask, a term would be poly_point · λ.
        let lambda = lagrange_at::<k256::Secp256k1>(&[index(1), index(2)], index(1), target);
        assert_ne!(a, parties[0].poly_point * lambda);

        // The same helper's terms for two targets differ by more than the
        // Lagrange coefficients, so their difference hides poly_point.
        let a3 = parties[0]
            .repair_term(&[index(1), index(2)], index(3), b"r")
            .unwrap();
        let lambda3 = lagrange_at::<k256::Secp256k1>(&[index(1), index(2)], index(1), index(3));
        assert_ne!(a - a3, parties[0].poly_point * (lambda - lambda3));
    }

    /// Without the helper-set binding, helper 1's terms for target 4 over
    /// {1,2}, {1,3} and {1,2,3} would combine to a known multiple of its
    /// share.
    #[test]
    fn test_repair_masks_differ_across_helper_sets() {
        let (parties, _) = group::<k256::Secp256k1>(2, 4);
        let p = &parties[0];
        let target = index(4);
        let t12 = p.repair_term(&[index(1), index(2)], target, b"r").unwrap();
        let t13 = p.repair_term(&[index(1), index(3)], target, b"r").unwrap();
        let t123 = p
            .repair_term(&[index(1), index(2), index(3)], target, b"r")
            .unwrap();
        let lambda =
            |helpers: &[PartyIndex]| lagrange_at::<k256::Secp256k1>(helpers, index(1), target);
        let factor = lambda(&[index(1), index(2), index(3)])
            - lambda(&[index(1), index(2)])
            - lambda(&[index(1), index(3)]);
        assert_ne!(t123 - t12 - t13, p.poly_point * factor);
    }

    /// A root share and a key derived from it (BOLT 3 revocation keeps
    /// depth 0, the session and the seeds) never share a mask.
    #[test]
    fn test_repair_masks_differ_for_derived_keys() {
        let (parties, _) = group::<k256::Secp256k1>(2, 3);
        let per_commitment_secret = k256::Scalar::from(5u64);
        let per_commitment_point =
            (k256::ProjectivePoint::GENERATOR * per_commitment_secret).to_affine();
        let derived = parties[0]
            .bolt3_derive_revocation(&per_commitment_point, &per_commitment_secret, |_| {
                String::new()
            })
            .unwrap();
        assert_eq!(derived.derivation_data.depth, 0);
        let helpers = [index(1), index(2)];
        let root_term = parties[0].repair_term(&helpers, index(3), b"r").unwrap();
        let derived_term = derived.repair_term(&helpers, index(3), b"r").unwrap();
        let lambda = lagrange_at::<k256::Secp256k1>(&helpers, index(1), index(3));
        // Equal masks would make the difference exactly λ·(s' − s).
        assert_ne!(
            derived_term - root_term,
            lambda * (derived.poly_point - parties[0].poly_point)
        );
    }

    /// Terms depend on the helper's session: the same request after a
    /// different session gets a different mask.
    #[test]
    fn test_repair_masks_differ_across_sessions() {
        let (parties, _) = group::<k256::Secp256k1>(2, 3);
        let mut other_session = parties[0].clone();
        other_session.session_id = b"another session".to_vec();
        let helpers = [index(1), index(2)];
        assert_ne!(
            parties[0].repair_term(&helpers, index(3), b"r").unwrap(),
            other_session.repair_term(&helpers, index(3), b"r").unwrap()
        );
    }

    /// An identical request repeats the identical term.
    #[test]
    fn test_identical_repair_requests_repeat_the_term() {
        let (parties, _) = group::<k256::Secp256k1>(2, 3);
        let helpers = [index(1), index(2)];
        assert_eq!(
            parties[0].repair_term(&helpers, index(3), b"r").unwrap(),
            parties[0].repair_term(&helpers, index(3), b"r").unwrap()
        );
    }

    /// A zeroized (index 0) target or helper is refused: terms for target 0
    /// would add up to the group secret.
    #[test]
    fn test_repair_rejects_index_zero() {
        use zeroize::Zeroize;

        let (parties, package) = group::<k256::Secp256k1>(2, 3);
        let mut zero = index(1);
        zero.zeroize();
        assert_eq!(zero.as_u8(), 0);
        assert_eq!(
            parties[0].repair_term(&[index(1), index(2)], zero, b"r"),
            Err(RepairError::InvalidTarget)
        );
        assert_eq!(
            parties[1].repair_term(&[zero, index(2)], index(3), b"r"),
            Err(RepairError::InvalidHelperSet)
        );
        let a = parties[0]
            .repair_term(&[index(1), index(2)], index(3), b"r")
            .unwrap();
        assert_eq!(
            repair_assemble(
                &package,
                &parties[0].session_id,
                *parties[0].chain_code(),
                zero,
                &[a, a],
                |_| String::new()
            )
            .unwrap_err(),
            RepairError::InvalidTarget
        );
    }

    #[test]
    fn test_repair_rejects_invalid_requests() {
        let (parties, package) = group::<k256::Secp256k1>(2, 3);
        let p = &parties[0];
        let target = index(3);
        assert_eq!(
            p.repair_term(&[index(1), index(2)], target, b""),
            Err(RepairError::EmptyRepairId)
        );
        for helpers in [
            vec![index(1)],
            vec![index(2), index(1)],
            vec![index(1), index(1)],
            vec![index(1), index(3)],
            vec![index(1), index(4)],
        ] {
            assert_eq!(
                p.repair_term(&helpers, target, b"r"),
                Err(RepairError::InvalidHelperSet),
                "{helpers:?}"
            );
        }
        assert_eq!(
            parties[2].repair_term(&[index(1), index(2)], index(4), b"r"),
            Err(RepairError::InvalidTarget)
        );
        // The target itself is not a helper.
        assert_eq!(
            parties[2].repair_term(&[index(1), index(2)], target, b"r"),
            Err(RepairError::NotInHelperSet)
        );
        assert_eq!(
            parties[1].repair_term(&[index(1), index(3)], index(2), b"r"),
            Err(RepairError::NotInHelperSet)
        );
        let derived = p.derive_child(1, |_| String::new()).unwrap();
        assert_eq!(
            derived.repair_term(&[index(1), index(2)], target, b"r"),
            Err(RepairError::DerivedShare)
        );

        // A hollow share has no seeds, so it cannot help yet.
        let hollow = repair(&parties, &package, &[index(1), index(2)], target, b"r").unwrap();
        assert_eq!(
            hollow.repair_term(&[index(1), index(3)], index(2), b"r"),
            Err(RepairError::MissingSeed {
                counterparty: index(1)
            })
        );

        // Assembly checks the sum and the number of terms.
        let a = p.repair_term(&[index(1), index(2)], target, b"r").unwrap();
        let session = &p.session_id;
        let chain_code = *p.chain_code();
        assert_eq!(
            repair_assemble(
                &package,
                session,
                chain_code,
                target,
                &[a],
                |_| String::new()
            )
            .unwrap_err(),
            RepairError::NotEnoughTerms
        );
        assert_eq!(
            repair_assemble(&package, session, chain_code, target, &[a, a], |_| {
                String::new()
            })
            .unwrap_err(),
            RepairError::ShareMismatch
        );
    }
}
