//! `DKLs23` signing protocol.
//!
//! This file implements the signing phase of Protocol 3.6 from `DKLs23`
//! (<https://eprint.iacr.org/2023/765.pdf>). It is the core of this repository.
//!
//! # Nomenclature
//!
//! For the messages structs, we will use the following nomenclature:
//!
//! **Transmit** messages refer to only one counterparty, hence
//! we must produce a whole vector of them. Each message in this
//! vector contains the party index to whom we should send it.
//!
//! **Broadcast** messages refer to all counterparties at once,
//! hence we only need to produce a unique instance of it.
//! This message is broadcasted to all parties.
//!
//! ATTENTION: we broadcast the message to ourselves as well!
//!
//! **Keep** messages refer to only one counterparty, hence
//! we must keep a whole vector of them. In this implementation,
//! we use a `BTreeMap` instead of a vector, where one can put
//! some party index in the key to retrieve the corresponding data.
//!
//! **Unique keep** messages refer to all counterparties at once,
//! hence we only need to keep a unique instance of it.

use k256::ecdsa::RecoveryId;
use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::elliptic_curve::{bigint::Encoding, ops::Reduce, point::AffineCoordinates, Curve, Field};
use k256::{AffinePoint, ProjectivePoint, Scalar, Secp256k1, U256};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, ZeroizeOnDrop};

use hex;

use crate::protocols::{Abort, PartiesMessage, Party};

use crate::utilities::commits::{commit_point, verify_commitment_point};
use crate::utilities::hashes::HashOutput;
use crate::utilities::multiplication::{MulDataToKeepReceiver, MulDataToReceiver};
use crate::utilities::ot::extension::OTEDataToSender;
use crate::utilities::rng;

/// Data needed to start the signature and is used during the phases.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignData {
    pub sign_id: Vec<u8>,
    /// Vector containing the indices of the parties participating in the protocol (without us).
    pub counterparties: Vec<u8>,
    /// Hash of message being signed.
    pub message_hash: HashOutput,
}

// STRUCTS FOR MESSAGES TO TRANSMIT IN COMMUNICATION ROUNDS.

/// Transmit - Signing.
///
/// The message is produced/sent during Phase 1 and used in Phase 2.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransmitPhase1to2 {
    pub parties: PartiesMessage,
    pub commitment: HashOutput,
    pub mul_transmit: OTEDataToSender,
}

/// Transmit - Signing.
///
/// The message is produced/sent during Phase 2 and used in Phase 3.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransmitPhase2to3 {
    pub parties: PartiesMessage,
    pub gamma_u: AffinePoint,
    pub gamma_v: AffinePoint,
    pub psi: Scalar,
    pub public_share: AffinePoint,
    pub instance_point: AffinePoint,
    pub salt: Vec<u8>,
    pub mul_transmit: MulDataToReceiver,
}

/// Broadcast - Signing.
///
/// The message is produced/sent during Phase 3 and used in Phase 4.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Broadcast3to4 {
    pub u: Scalar,
    pub w: Scalar,
}

// STRUCTS FOR MESSAGES TO KEEP BETWEEN PHASES.

/// Keep - Signing.
///
/// The message is produced during Phase 1 and used in Phase 2.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeepPhase1to2 {
    pub salt: Vec<u8>,
    pub chi: Scalar,
    pub mul_keep: MulDataToKeepReceiver,
}

/// Keep - Signing.
///
/// The message is produced during Phase 2 and used in Phase 3.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeepPhase2to3 {
    pub c_u: Scalar,
    pub c_v: Scalar,
    pub commitment: HashOutput,
    pub mul_keep: MulDataToKeepReceiver,
    pub chi: Scalar,
}

/// Unique keep - Signing.
///
/// The message is produced during Phase 1 and used in Phase 2.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UniqueKeep1to2 {
    pub instance_key: Scalar,
    #[zeroize(skip)]
    pub instance_point: AffinePoint,
    pub inversion_mask: Scalar,
    pub zeta: Scalar,
}

/// Unique keep - Signing.
///
/// The message is produced during Phase 2 and used in Phase 3.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UniqueKeep2to3 {
    pub instance_key: Scalar,
    #[zeroize(skip)]
    pub instance_point: AffinePoint,
    pub inversion_mask: Scalar,
    pub key_share: Scalar,
    #[zeroize(skip)]
    pub public_share: AffinePoint,
}

// SIGNING PROTOCOL
// We now follow Protocol 3.6 of DKLs23.

/// Implementations related to the `DKLs23` signing protocol ([read more](self)).
impl Party {
    /// Phase 1 for signing: Steps 4, 5 and 6 from
    /// Protocol 3.6 in <https://eprint.iacr.org/2023/765.pdf>.
    ///
    /// The outputs should be kept or transmitted according to the conventions
    /// [here](self).
    ///
    /// # Errors
    ///
    /// Will return `Err` if the number of counterparties is wrong, if any
    /// party index is out of range, or if the counterparty list contains our
    /// own index.
    pub fn sign_phase1(
        &self,
        data: &SignData,
    ) -> Result<
        (
            UniqueKeep1to2,
            BTreeMap<u8, KeepPhase1to2>,
            Vec<TransmitPhase1to2>,
        ),
        Abort,
    > {
        // Step 4 - We check if we have the correct number of counter parties.
        if data.counterparties.len() != (self.parameters.threshold - 1) as usize {
            return Err(Abort::new(
                self.party_index,
                "The number of signing parties is not right!",
            ));
        }

        // Validate party index ranges and uniqueness.
        if self.party_index < 1 || self.party_index > self.parameters.share_count {
            return Err(Abort::new(
                self.party_index,
                &format!(
                    "Own party index {} is out of range [1, {}]",
                    self.party_index, self.parameters.share_count
                ),
            ));
        }
        let mut seen_counterparties: BTreeSet<u8> = BTreeSet::new();
        for counterparty in &data.counterparties {
            if *counterparty < 1 || *counterparty > self.parameters.share_count {
                return Err(Abort::new(
                    self.party_index,
                    &format!(
                        "Counterparty index {} is out of range [1, {}]",
                        counterparty, self.parameters.share_count
                    ),
                ));
            }
            if !seen_counterparties.insert(*counterparty) {
                return Err(Abort::new(
                    self.party_index,
                    &format!("Counterparty index {counterparty} appears more than once"),
                ));
            }
            if *counterparty == self.party_index {
                return Err(Abort::new(
                    self.party_index,
                    "Counterparty list must not contain our own index",
                ));
            }
            if !self.mul_senders.contains_key(counterparty)
                || !self.mul_receivers.contains_key(counterparty)
            {
                return Err(Abort::new(
                    self.party_index,
                    &format!("Missing multiplication state for counterparty {counterparty}"),
                ));
            }
        }

        // Step 5 - We sample our secret data.
        let instance_key = Scalar::random(&mut rng::get_rng());
        let inversion_mask = Scalar::random(&mut rng::get_rng());

        let instance_point = (AffinePoint::GENERATOR * instance_key).to_affine();

        // Step 6 - We prepare the messages to keep and to send.

        let mut keep: BTreeMap<u8, KeepPhase1to2> = BTreeMap::new();
        let mut transmit: Vec<TransmitPhase1to2> =
            Vec::with_capacity((self.parameters.threshold - 1) as usize);
        for counterparty in &data.counterparties {
            // Commit functionality.
            let (commitment, salt) = commit_point(&instance_point);

            // Two-party multiplication functionality.
            // We start as the receiver.

            // First, let us compute a session id for it.
            // As in Protocol 3.6 of DKLs23, we include the indexes from the parties.
            // We also use both the sign id and the DKG id.
            // The chain code binds the signing session to the derived key path.
            let mul_sid = [
                "Multiplication protocol".as_bytes(),
                &self.party_index.to_be_bytes(),
                &counterparty.to_be_bytes(),
                &self.session_id,
                &data.sign_id,
                &self.derivation_data.chain_code,
            ]
            .concat();

            // We run the first phase.
            let mul_receiver = self.mul_receivers.get(counterparty).ok_or_else(|| {
                Abort::new(
                    self.party_index,
                    &format!("Missing multiplication receiver state for party {counterparty}"),
                )
            })?;
            let (chi, mul_keep, mul_transmit) = match mul_receiver.run_phase1(&mul_sid) {
                Ok(values) => values,
                Err(error) => {
                    return Err(Abort::new(
                        self.party_index,
                        &format!(
                            "Two-party multiplication setup failed with Party {counterparty}: {}",
                            error.description
                        ),
                    ));
                }
            };

            // We gather the messages.
            keep.insert(
                *counterparty,
                KeepPhase1to2 {
                    salt,
                    chi,
                    mul_keep,
                },
            );
            transmit.push(TransmitPhase1to2 {
                parties: PartiesMessage {
                    sender: self.party_index,
                    receiver: *counterparty,
                },
                commitment,
                mul_transmit,
            });
        }

        // Zero-shares functionality.
        // We put it here because it doesn't depend on counter parties.

        // We first compute a session id.
        // Now, different to DKLs23, we won't put the indexes from the parties
        // because the sign id refers only to this set of parties, hence
        // it's simpler and almost equivalent to take just the following:
        let zero_sid = [
            "Zero shares protocol".as_bytes(),
            &self.session_id,
            &data.sign_id,
            &self.derivation_data.chain_code,
        ]
        .concat();

        let zeta = self.zero_share.compute(&data.counterparties, &zero_sid);

        // "Unique" because it is only one message referring to all counter parties.
        let unique_keep = UniqueKeep1to2 {
            instance_key,
            instance_point,
            inversion_mask,
            zeta,
        };

        // We now return all these values.
        Ok((unique_keep, keep, transmit))
    }

    // Communication round 1
    // Transmit the messages.

    /// Phase 2 for signing: Step 7 from
    /// Protocol 3.6 in <https://eprint.iacr.org/2023/765.pdf>.
    ///
    /// The inputs come from the previous phase. The messages received
    /// should be gathered in a vector (in any order).
    ///
    /// The outputs should be kept or transmitted according to the conventions
    /// [here](self).
    ///
    /// # Errors
    ///
    /// Will return `Err` if the multiplication protocol fails.
    ///
    /// # Panics
    ///
    /// Will panic if the list of keys in the `BTreeMap`'s are incompatible
    /// with the party indices in the vector `received`.
    pub fn sign_phase2(
        &self,
        data: &SignData,
        unique_kept: &UniqueKeep1to2,
        kept: &BTreeMap<u8, KeepPhase1to2>,
        received: &[TransmitPhase1to2],
    ) -> Result<
        (
            UniqueKeep2to3,
            BTreeMap<u8, KeepPhase2to3>,
            Vec<TransmitPhase2to3>,
        ),
        Abort,
    > {
        // Step 7

        // We first compute the values that only depend on us.

        // We find the Lagrange coefficient associated to us.
        // It is the same as the one calculated during DKG.
        let mut l_numerator = Scalar::ONE;
        let mut l_denominator = Scalar::ONE;
        for counterparty in &data.counterparties {
            l_numerator *= Scalar::from(u32::from(*counterparty));
            l_denominator *=
                Scalar::from(u32::from(*counterparty)) - Scalar::from(u32::from(self.party_index));
        }
        let l_denominator_inverse = match Option::<Scalar>::from(l_denominator.invert()) {
            Some(inv) => inv,
            None => {
                return Err(Abort::new(
                    self.party_index,
                    "Failed to compute Lagrange coefficient (duplicate/invalid counterparties)",
                ));
            }
        };
        let l = l_numerator * l_denominator_inverse;

        // These are sk_i and pk_i from the paper.
        let key_share = (self.poly_point * l) + unique_kept.zeta;
        let public_share = (AffinePoint::GENERATOR * key_share).to_affine();

        // This is the input for the multiplication protocol.
        let input = vec![unique_kept.instance_key, key_share];

        // Now, we compute the variables related to each counter party.
        let mut keep: BTreeMap<u8, KeepPhase2to3> = BTreeMap::new();
        let mut transmit: Vec<TransmitPhase2to3> =
            Vec::with_capacity((self.parameters.threshold - 1) as usize);
        if received.len() != data.counterparties.len() {
            return Err(Abort::new(
                self.party_index,
                "Received an unexpected number of round-1 messages",
            ));
        }
        let mut seen_senders: BTreeSet<u8> = BTreeSet::new();
        for message in received {
            // Validate sender identity before processing (defense-in-depth against misrouting).
            let counterparty = message.parties.sender;
            if !data.counterparties.contains(&counterparty) {
                return Err(Abort::new(
                    self.party_index,
                    &format!("Received message from unknown sender {counterparty}"),
                ));
            }
            if message.parties.receiver != self.party_index {
                return Err(Abort::new(
                    self.party_index,
                    &format!(
                        "Received message addressed to {}, but we are {}",
                        message.parties.receiver, self.party_index
                    ),
                ));
            }
            if !seen_senders.insert(counterparty) {
                return Err(Abort::new(
                    self.party_index,
                    &format!("Duplicate round-1 message from sender {counterparty}"),
                ));
            }
            let current_kept = kept.get(&counterparty).ok_or_else(|| {
                Abort::new(
                    self.party_index,
                    &format!("Missing local kept state for counterparty {counterparty}"),
                )
            })?;

            // We continue the multiplication protocol to get the values
            // c^u and c^v from the paper. We are now the sender.

            // Let us retrieve the session id for multiplication.
            // Note that the roles are now reversed.
            let mul_sid = [
                "Multiplication protocol".as_bytes(),
                &counterparty.to_be_bytes(),
                &self.party_index.to_be_bytes(),
                &self.session_id,
                &data.sign_id,
                &self.derivation_data.chain_code,
            ]
            .concat();

            let mul_sender = self.mul_senders.get(&counterparty).ok_or_else(|| {
                Abort::new(
                    self.party_index,
                    &format!("Missing multiplication sender state for party {counterparty}"),
                )
            })?;
            let mul_result = mul_sender.run(&mul_sid, &input, &message.mul_transmit);

            let c_u: Scalar;
            let c_v: Scalar;
            let mul_transmit: MulDataToReceiver;
            match mul_result {
                Err(error) => {
                    return Err(Abort::ban(
                        self.party_index,
                        counterparty,
                        &format!(
                            "Two-party multiplication protocol failed because of Party {}: {:?}",
                            counterparty, error.description
                        ),
                    ));
                }
                Ok((c_values, data_to_receiver)) => {
                    c_u = c_values[0];
                    c_v = c_values[1];
                    mul_transmit = data_to_receiver;
                }
            }

            // We compute the remaining values.
            let gamma_u = (AffinePoint::GENERATOR * c_u).to_affine();
            let gamma_v = (AffinePoint::GENERATOR * c_v).to_affine();

            let psi = unique_kept.inversion_mask - current_kept.chi;

            keep.insert(
                counterparty,
                KeepPhase2to3 {
                    c_u,
                    c_v,
                    commitment: message.commitment,
                    mul_keep: current_kept.mul_keep.clone(),
                    chi: current_kept.chi,
                },
            );
            transmit.push(TransmitPhase2to3 {
                parties: PartiesMessage {
                    sender: self.party_index,
                    receiver: counterparty,
                },
                // Check-adjust
                gamma_u,
                gamma_v,
                psi,
                public_share,
                // Decommit
                instance_point: unique_kept.instance_point,
                salt: current_kept.salt.clone(),
                // Multiply
                mul_transmit,
            });
        }

        // Common values to keep for the next phase.
        let unique_keep = UniqueKeep2to3 {
            instance_key: unique_kept.instance_key,
            instance_point: unique_kept.instance_point,
            inversion_mask: unique_kept.inversion_mask,
            key_share,
            public_share,
        };

        Ok((unique_keep, keep, transmit))
    }

    // Communication round 2
    // Transmit the messages.

    /// Phase 3 for signing: Steps 8 and 9 from
    /// Protocol 3.6 in <https://eprint.iacr.org/2023/765.pdf>.
    ///
    /// The inputs come from the previous phase. The messages received
    /// should be gathered in a vector (in any order).
    ///
    /// The first output is already the value `r` from the ECDSA signature.
    /// The second output should be broadcasted according to the conventions
    /// [here](self).
    ///
    /// # Errors
    ///
    /// Will return `Err` if some commitment doesn't verify, if the multiplication
    /// protocol fails or if one of the consistency checks is false. The error
    /// will also happen if the total instance point is trivial (very unlikely).
    ///
    /// # Panics
    ///
    /// Will panic if the list of keys in the `BTreeMap`'s are incompatible
    /// with the party indices in the vector `received`.
    pub fn sign_phase3(
        &self,
        data: &SignData,
        unique_kept: &UniqueKeep2to3,
        kept: &BTreeMap<u8, KeepPhase2to3>,
        received: &[TransmitPhase2to3],
    ) -> Result<(String, Broadcast3to4), Abort> {
        // Steps 8 and 9

        // The following values will represent the sums calculated in this step.
        let mut expected_public_key = unique_kept.public_share;
        let mut total_instance_point = unique_kept.instance_point;

        let mut first_sum_u_v = unique_kept.inversion_mask;

        let mut second_sum_u = Scalar::ZERO;
        let mut second_sum_v = Scalar::ZERO;

        if received.len() != data.counterparties.len() {
            return Err(Abort::new(
                self.party_index,
                "Received an unexpected number of round-2 messages",
            ));
        }
        let mut seen_senders: BTreeSet<u8> = BTreeSet::new();
        for message in received {
            // Validate sender identity before processing (defense-in-depth against misrouting).
            let counterparty = message.parties.sender;
            if !data.counterparties.contains(&counterparty) {
                return Err(Abort::new(
                    self.party_index,
                    &format!("Received message from unknown sender {counterparty}"),
                ));
            }
            if message.parties.receiver != self.party_index {
                return Err(Abort::new(
                    self.party_index,
                    &format!(
                        "Received message addressed to {}, but we are {}",
                        message.parties.receiver, self.party_index
                    ),
                ));
            }
            if message.instance_point == AffinePoint::IDENTITY {
                return Err(Abort::new(
                    self.party_index,
                    &format!("Party {counterparty} sent identity as instance point"),
                ));
            }
            if !seen_senders.insert(counterparty) {
                return Err(Abort::new(
                    self.party_index,
                    &format!("Duplicate round-2 message from sender {counterparty}"),
                ));
            }
            let current_kept = kept.get(&counterparty).ok_or_else(|| {
                Abort::new(
                    self.party_index,
                    &format!("Missing local kept state for counterparty {counterparty}"),
                )
            })?;

            // Checking the committed value.
            let verification = verify_commitment_point(
                &message.instance_point,
                &current_kept.commitment,
                &message.salt,
            );
            if !verification {
                return Err(Abort::new(
                    self.party_index,
                    &format!("Failed to verify commitment from Party {counterparty}!"),
                ));
            }

            // Finishing the multiplication protocol.
            // We are now the receiver.

            // Let us retrieve the session id for multiplication.
            // Note that we reverse the roles again.
            let mul_sid = [
                "Multiplication protocol".as_bytes(),
                &self.party_index.to_be_bytes(),
                &counterparty.to_be_bytes(),
                &self.session_id,
                &data.sign_id,
                &self.derivation_data.chain_code,
            ]
            .concat();

            let mul_receiver = self.mul_receivers.get(&counterparty).ok_or_else(|| {
                Abort::new(
                    self.party_index,
                    &format!("Missing multiplication receiver state for party {counterparty}"),
                )
            })?;
            let mul_result =
                mul_receiver.run_phase2(&mul_sid, &current_kept.mul_keep, &message.mul_transmit);

            let d_u: Scalar;
            let d_v: Scalar;
            match mul_result {
                Err(error) => {
                    return Err(Abort::ban(
                        self.party_index,
                        counterparty,
                        &format!(
                            "Two-party multiplication protocol failed because of Party {}: {:?}",
                            counterparty, error.description
                        ),
                    ));
                }
                Ok(d_values) => {
                    d_u = d_values[0];
                    d_v = d_values[1];
                }
            }

            // First consistency checks.
            let generator = AffinePoint::GENERATOR;

            if (message.instance_point * current_kept.chi) != ((generator * d_u) + message.gamma_u)
            {
                return Err(Abort::ban(
                    self.party_index,
                    counterparty,
                    &format!("Consistency check with u-variables failed for Party {counterparty}!"),
                ));
            }

            // In the paper, they write "Lagrange(P, j, 0) · P(j)". For the math
            // to be consistent, we believe it should be "pk_j" instead.
            // This agrees with the alternative computation of gamma_v at the
            // end of page 21 in the paper.
            if (message.public_share * current_kept.chi) != ((generator * d_v) + message.gamma_v) {
                return Err(Abort::ban(
                    self.party_index,
                    counterparty,
                    &format!("Consistency check with v-variables failed for Party {counterparty}!"),
                ));
            }

            // We add the current summand to our sums.
            expected_public_key =
                (ProjectivePoint::from(expected_public_key) + message.public_share).to_affine();
            total_instance_point =
                (ProjectivePoint::from(total_instance_point) + message.instance_point).to_affine();

            first_sum_u_v += &message.psi;

            second_sum_u = second_sum_u + current_kept.c_u + d_u;
            second_sum_v = second_sum_v + current_kept.c_v + d_v;
        }

        // Second consistency check.
        if expected_public_key != self.pk {
            return Err(Abort::new(
                self.party_index,
                "Consistency check for public key reconstruction failed!",
            ));
        }

        // We introduce another consistency check: the total instance point
        // should not be the point at infinity (this is not specified on
        // DKLs23 but actually on ECDSA itself). In any case, the probability
        // of this happening is very low.
        if total_instance_point == AffinePoint::IDENTITY {
            return Err(Abort::new(
                self.party_index,
                "Total instance point was trivial! (Very improbable)",
            ));
        }

        // We compute u_i, v_i and w_i from the paper.
        let u = (unique_kept.instance_key * first_sum_u_v) + second_sum_u;
        let v = (unique_kept.key_share * first_sum_u_v) + second_sum_v;

        let x_coord = hex::encode(total_instance_point.x());
        // There is no salt because the hash function here is always the same.
        let w = (Scalar::reduce(&U256::from_be_bytes(data.message_hash.into()))
            * unique_kept.inversion_mask)
            + (v * Scalar::reduce(&U256::from_be_hex(&x_coord)));

        let broadcast = Broadcast3to4 { u, w };

        // We also return the x-coordinate of the instance point.
        // This is half of the final signature.

        Ok((x_coord, broadcast))
    }

    // Communication round 3
    // Broadcast the messages (including to ourselves).

    /// Phase 4 for signing: Step 10 from
    /// Protocol 3.6 in <https://eprint.iacr.org/2023/765.pdf>.
    ///
    /// The inputs come from the previous phase. The messages received
    /// should be gathered in a vector (in any order). Note that our
    /// broadcasted message from the previous round should also appear
    /// here.
    ///
    /// The first output is the value `s` from the ECDSA signature.
    /// The second output is the recovery id from the ECDSA signature.
    /// Note that the parameter 'v' isn't this value, but it is used to compute it.
    /// To know how to compute it, check the EIP which standardizes the transaction format
    /// that you're using. For example: EIP-155, EIP-2930, EIP-1559.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the final ECDSA signature is invalid
    /// or if the denominator in signature assembly is zero.
    pub fn sign_phase4(
        &self,
        data: &SignData,
        x_coord: &str,
        received: &[Broadcast3to4],
        normalize: bool,
    ) -> Result<(String, u8), Abort> {
        // Step 10

        let mut numerator = Scalar::ZERO;
        let mut denominator = Scalar::ZERO;
        for message in received {
            numerator += &message.w;
            denominator += &message.u;
        }

        let denominator_inverse = match Option::<Scalar>::from(denominator.invert()) {
            Some(inv) => inv,
            None => {
                return Err(Abort::new(
                    self.party_index,
                    "Zero denominator in signature assembly — possible adversarial u-values",
                ));
            }
        };
        let mut s = numerator * denominator_inverse;

        // Normalize signature into "low S" form as described in
        // BIP-0062 Dealing with Malleability: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
        if normalize && s.is_high().into() {
            s = -s;
        }

        let signature = hex::encode(s.to_bytes());

        let verification =
            verify_ecdsa_signature(&data.message_hash, &self.pk, x_coord, &signature);
        if !verification {
            return Err(Abort::new(
                self.party_index,
                "Invalid ECDSA signature at the end of the protocol!",
            ));
        }

        // First we need to calculate R (signature point) in order to retrieve its y coordinate.
        // This is necessary because we need to check if y is even or odd to calculate the
        // recovery id. We compute R in the same way that we did in verify_ecdsa_signature:
        // R = (G * msg_hash + pk * r_x) / s
        let x_as_int = match parse_u256_from_hex_32bytes(x_coord) {
            Some(value) => value,
            None => {
                return Err(Abort::new(
                    self.party_index,
                    "Invalid x-coordinate hex while assembling signature",
                ));
            }
        };
        let rx_as_scalar = Scalar::reduce(&x_as_int);
        let hashed_msg_as_scalar = Scalar::reduce(&U256::from_be_bytes(data.message_hash.into()));
        let first = AffinePoint::GENERATOR * hashed_msg_as_scalar;
        let second = self.pk * rx_as_scalar;
        let s_inverse = s.invert().unwrap();
        let signature_point = ((first + second) * s_inverse).to_affine();

        // Now the recovery id can be calculated using the following conditions:
        // - If R.y is even and R.x < n (curve order): recovery_id = 0
        // - If R.y is odd  and R.x < n:               recovery_id = 1
        // - If R.y is even and R.x >= n:               recovery_id = 2
        // - If R.y is odd  and R.x >= n:               recovery_id = 3
        //
        // is_x_reduced is true when R.x (as a field element) >= the curve order n,
        // meaning Scalar::reduce(&R.x) lost information. For secp256k1, n < p, so
        // this can happen in the range [n, p-1] with negligible probability.
        let is_x_reduced = x_as_int >= Secp256k1::ORDER;
        let is_y_odd = signature_point.to_sec1_point(false).y().unwrap()[31] & 1 == 1;
        let rec_id = RecoveryId::new(is_y_odd, is_x_reduced);

        Ok((signature, rec_id.into()))
    }
}

/// Parses a 32-byte hex string (64 hex chars) as `U256`.
fn parse_u256_from_hex_32bytes(hex_value: &str) -> Option<U256> {
    let mut bytes = [0u8; 32];
    if hex::decode_to_slice(hex_value, &mut bytes).is_err() {
        return None;
    }
    Some(U256::from_be_bytes(bytes.into()))
}

/// Usual verifying function from ECDSA.
///
/// It receives a message already in bytes.
#[must_use]
pub fn verify_ecdsa_signature(
    msg: &HashOutput,
    pk: &AffinePoint,
    x_coord: &str,
    signature: &str,
) -> bool {
    let rx_as_int = match parse_u256_from_hex_32bytes(x_coord) {
        Some(value) => value,
        None => return false,
    };
    let s_as_int = match parse_u256_from_hex_32bytes(signature) {
        Some(value) => value,
        None => return false,
    };

    // Verify if the numbers are in the correct range.
    if !(U256::ZERO < rx_as_int
        && rx_as_int < Secp256k1::ORDER
        && U256::ZERO < s_as_int
        && s_as_int < Secp256k1::ORDER)
    {
        return false;
    }

    let rx_as_scalar = Scalar::reduce(&rx_as_int);
    let s_as_scalar = Scalar::reduce(&s_as_int);

    let inverse_s = s_as_scalar.invert().unwrap();

    let first = Scalar::reduce(&U256::from_be_bytes((*msg).into())) * inverse_s;
    let second = rx_as_scalar * inverse_s;

    let point_to_check = ((AffinePoint::GENERATOR * first) + (*pk * second)).to_affine();
    if point_to_check == AffinePoint::IDENTITY {
        return false;
    }

    let x_check = Scalar::reduce(&U256::from_be_slice(point_to_check.x().as_ref()));

    x_check == rx_as_scalar
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::protocols::dkg::*;
    use crate::protocols::re_key::re_key;
    use crate::protocols::*;
    use crate::utilities::hashes::hash;
    use rand::RngExt;

    /// Tests if the signing protocol generates a valid ECDSA signature.
    ///
    /// In this case, parties are sampled via the [`re_key`] function.
    #[test]
    fn test_signing() {
        // Disclaimer: this implementation is not the most efficient,
        // we are only testing if everything works! Note as well that
        // parties are being simulated one after the other, but they
        // should actually execute the protocol simultaneously.

        let threshold = rng::get_rng().random_range(2..=5); // You can change the ranges here.
        let offset = rng::get_rng().random_range(0..=5);

        let parameters = Parameters {
            threshold,
            share_count: threshold + offset,
        }; // You can fix the parameters if you prefer.

        // We use the re_key function to quickly sample the parties.
        let session_id = rng::get_rng().random::<[u8; 32]>();
        let secret_key = Scalar::random(&mut rng::get_rng());
        let parties = re_key(&parameters, &session_id, &secret_key, None);

        // SIGNING

        let sign_id = rng::get_rng().random::<[u8; 32]>();
        let message_to_sign = hash("Message to sign!".as_bytes(), &[]);

        // For simplicity, we are testing only the first parties.
        let executing_parties: Vec<u8> = Vec::from_iter(1..=parameters.threshold);

        // Each party prepares their data for this signing session.
        let mut all_data: BTreeMap<u8, SignData> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            //Gather the counterparties
            let mut counterparties = executing_parties.clone();
            counterparties.retain(|index| *index != party_index);

            all_data.insert(
                party_index,
                SignData {
                    sign_id: sign_id.to_vec(),
                    counterparties,
                    message_hash: message_to_sign,
                },
            );
        }

        // Phase 1
        let mut unique_kept_1to2: BTreeMap<u8, UniqueKeep1to2> = BTreeMap::new();
        let mut kept_1to2: BTreeMap<u8, BTreeMap<u8, KeepPhase1to2>> = BTreeMap::new();
        let mut transmit_1to2: BTreeMap<u8, Vec<TransmitPhase1to2>> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            let (unique_keep, keep, transmit) = parties[(party_index - 1) as usize]
                .sign_phase1(all_data.get(&party_index).unwrap())
                .unwrap();

            unique_kept_1to2.insert(party_index, unique_keep);
            kept_1to2.insert(party_index, keep);
            transmit_1to2.insert(party_index, transmit);
        }

        // Communication round 1
        let mut received_1to2: BTreeMap<u8, Vec<TransmitPhase1to2>> = BTreeMap::new();

        for &party_index in &executing_parties {
            let messages_for_party: Vec<TransmitPhase1to2> = transmit_1to2
                .values()
                .flatten()
                .filter(|message| message.parties.receiver == party_index)
                .cloned()
                .collect();

            received_1to2.insert(party_index, messages_for_party);
        }

        // Phase 2
        let mut unique_kept_2to3: BTreeMap<u8, UniqueKeep2to3> = BTreeMap::new();
        let mut kept_2to3: BTreeMap<u8, BTreeMap<u8, KeepPhase2to3>> = BTreeMap::new();
        let mut transmit_2to3: BTreeMap<u8, Vec<TransmitPhase2to3>> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            let result = parties[(party_index - 1) as usize].sign_phase2(
                all_data.get(&party_index).unwrap(),
                unique_kept_1to2.get(&party_index).unwrap(),
                kept_1to2.get(&party_index).unwrap(),
                received_1to2.get(&party_index).unwrap(),
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                }
                Ok((unique_keep, keep, transmit)) => {
                    unique_kept_2to3.insert(party_index, unique_keep);
                    kept_2to3.insert(party_index, keep);
                    transmit_2to3.insert(party_index, transmit);
                }
            }
        }

        // Communication round 2
        let mut received_2to3: BTreeMap<u8, Vec<TransmitPhase2to3>> = BTreeMap::new();

        for &party_index in &executing_parties {
            let messages_for_party: Vec<TransmitPhase2to3> = transmit_2to3
                .values()
                .flatten()
                .filter(|message| message.parties.receiver == party_index)
                .cloned()
                .collect();

            received_2to3.insert(party_index, messages_for_party);
        }

        // Phase 3
        let mut x_coords: Vec<String> = Vec::with_capacity(parameters.threshold as usize);
        let mut broadcast_3to4: Vec<Broadcast3to4> =
            Vec::with_capacity(parameters.threshold as usize);
        for party_index in executing_parties.clone() {
            let result = parties[(party_index - 1) as usize].sign_phase3(
                all_data.get(&party_index).unwrap(),
                unique_kept_2to3.get(&party_index).unwrap(),
                kept_2to3.get(&party_index).unwrap(),
                received_2to3.get(&party_index).unwrap(),
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                }
                Ok((x_coord, broadcast)) => {
                    x_coords.push(x_coord);
                    broadcast_3to4.push(broadcast);
                }
            }
        }

        // We verify all parties got the same x coordinate.
        let x_coord = x_coords[0].clone(); // We take the first one as reference.
        for i in 1..parameters.threshold {
            assert_eq!(x_coord, x_coords[i as usize]);
        }

        // Communication round 3
        // This is a broadcast to all parties. The desired result is already broadcast_3to4.

        // Phase 4
        // It is essentially independent of the party, so we compute just once.
        let some_index = executing_parties[0];
        let result = parties[(some_index - 1) as usize].sign_phase4(
            all_data.get(&some_index).unwrap(),
            &x_coord,
            &broadcast_3to4,
            true,
        );
        if let Err(abort) = result {
            panic!("Party {} aborted: {:?}", abort.index, abort.description);
        }
        // We could call verify_ecdsa_signature here, but it is already called during Phase 4.
    }

    /// Tests if the signing protocol generates a valid ECDSA signature
    /// and that it is the same one as we would get if we knew the
    /// secret key shared by the parties.
    ///
    /// In this case, parties are sampled via the [`re_key`] function.
    #[test]
    fn test_signing_against_ecdsa() {
        let threshold = rng::get_rng().random_range(2..=5); // You can change the ranges here.
        let offset = rng::get_rng().random_range(0..=5);

        let parameters = Parameters {
            threshold,
            share_count: threshold + offset,
        }; // You can fix the parameters if you prefer.

        // We use the re_key function to quickly sample the parties.
        let session_id = rng::get_rng().random::<[u8; 32]>();
        let secret_key = Scalar::random(&mut rng::get_rng());
        let parties = re_key(&parameters, &session_id, &secret_key, None);

        // SIGNING (as in test_signing)

        let sign_id = rng::get_rng().random::<[u8; 32]>();
        let message_to_sign = hash("Message to sign!".as_bytes(), &[]);

        // For simplicity, we are testing only the first parties.
        let executing_parties: Vec<u8> = Vec::from_iter(1..=parameters.threshold);

        // Each party prepares their data for this signing session.
        let mut all_data: BTreeMap<u8, SignData> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            //Gather the counterparties
            let mut counterparties = executing_parties.clone();
            counterparties.retain(|index| *index != party_index);

            all_data.insert(
                party_index,
                SignData {
                    sign_id: sign_id.to_vec(),
                    counterparties,
                    message_hash: message_to_sign,
                },
            );
        }

        // Phase 1
        let mut unique_kept_1to2: BTreeMap<u8, UniqueKeep1to2> = BTreeMap::new();
        let mut kept_1to2: BTreeMap<u8, BTreeMap<u8, KeepPhase1to2>> = BTreeMap::new();
        let mut transmit_1to2: BTreeMap<u8, Vec<TransmitPhase1to2>> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            let (unique_keep, keep, transmit) = parties[(party_index - 1) as usize]
                .sign_phase1(all_data.get(&party_index).unwrap())
                .unwrap();

            unique_kept_1to2.insert(party_index, unique_keep);
            kept_1to2.insert(party_index, keep);
            transmit_1to2.insert(party_index, transmit);
        }

        // Communication round 1
        let mut received_1to2: BTreeMap<u8, Vec<TransmitPhase1to2>> = BTreeMap::new();

        for &party_index in &executing_parties {
            let messages_for_party: Vec<TransmitPhase1to2> = transmit_1to2
                .values()
                .flatten()
                .filter(|message| message.parties.receiver == party_index)
                .cloned()
                .collect();

            received_1to2.insert(party_index, messages_for_party);
        }

        // Phase 2
        let mut unique_kept_2to3: BTreeMap<u8, UniqueKeep2to3> = BTreeMap::new();
        let mut kept_2to3: BTreeMap<u8, BTreeMap<u8, KeepPhase2to3>> = BTreeMap::new();
        let mut transmit_2to3: BTreeMap<u8, Vec<TransmitPhase2to3>> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            let result = parties[(party_index - 1) as usize].sign_phase2(
                all_data.get(&party_index).unwrap(),
                unique_kept_1to2.get(&party_index).unwrap(),
                kept_1to2.get(&party_index).unwrap(),
                received_1to2.get(&party_index).unwrap(),
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                }
                Ok((unique_keep, keep, transmit)) => {
                    unique_kept_2to3.insert(party_index, unique_keep);
                    kept_2to3.insert(party_index, keep);
                    transmit_2to3.insert(party_index, transmit);
                }
            }
        }

        // Communication round 2
        let mut received_2to3: BTreeMap<u8, Vec<TransmitPhase2to3>> = BTreeMap::new();

        for &party_index in &executing_parties {
            let messages_for_party: Vec<TransmitPhase2to3> = transmit_2to3
                .values()
                .flatten()
                .filter(|message| message.parties.receiver == party_index)
                .cloned()
                .collect();

            received_2to3.insert(party_index, messages_for_party);
        }

        // Phase 3
        let mut x_coords: Vec<String> = Vec::with_capacity(parameters.threshold as usize);
        let mut broadcast_3to4: Vec<Broadcast3to4> =
            Vec::with_capacity(parameters.threshold as usize);
        for party_index in executing_parties.clone() {
            let result = parties[(party_index - 1) as usize].sign_phase3(
                all_data.get(&party_index).unwrap(),
                unique_kept_2to3.get(&party_index).unwrap(),
                kept_2to3.get(&party_index).unwrap(),
                received_2to3.get(&party_index).unwrap(),
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                }
                Ok((x_coord, broadcast)) => {
                    x_coords.push(x_coord);
                    broadcast_3to4.push(broadcast);
                }
            }
        }

        // We verify all parties got the same x coordinate.
        let x_coord = x_coords[0].clone(); // We take the first one as reference.
        for i in 1..parameters.threshold {
            assert_eq!(x_coord, x_coords[i as usize]);
        }

        // Communication round 3
        // This is a broadcast to all parties. The desired result is already broadcast_3to4.

        // Phase 4
        // It is essentially independent of the party, so we compute just once.
        let some_index = executing_parties[0];
        let result = parties[(some_index - 1) as usize].sign_phase4(
            all_data.get(&some_index).unwrap(),
            &x_coord,
            &broadcast_3to4,
            false,
        );
        let signature = match result {
            Err(abort) => {
                panic!("Party {} aborted: {:?}", abort.index, abort.description);
            }
            Ok(s) => s,
        };
        // We could call verify_ecdsa_signature here, but it is already called during Phase 4.

        // ECDSA (computations that would be done if there were only one person)

        // Let us retrieve the total instance/ephemeral key.
        let mut total_instance_key = Scalar::ZERO;
        for (_, kept) in unique_kept_1to2 {
            total_instance_key += kept.instance_key;
        }

        // We compare the total "instance point" with the parties' calculations.
        let total_instance_point = (AffinePoint::GENERATOR * total_instance_key).to_affine();
        let expected_x_coord = hex::encode(total_instance_point.x());
        assert_eq!(x_coord, expected_x_coord);

        // The hash of the message:
        let hashed_message = Scalar::reduce(&U256::from_be_bytes(message_to_sign.into()));
        assert_eq!(
            hashed_message,
            Scalar::reduce(&U256::from_be_hex(
                "ece3e5d77980859352a5e702cb429f3d4dbdc12443e359ae60d15fe3c0333c0d"
            ))
        );

        // Now we can find the signature in the usual way.
        let expected_signature_as_scalar = total_instance_key.invert().unwrap()
            * (hashed_message
                + (secret_key * Scalar::reduce(&U256::from_be_hex(&expected_x_coord))));
        let expected_signature = hex::encode(expected_signature_as_scalar.to_bytes());

        // Calculate the expected recovery id
        let x_as_int = U256::from_be_hex(&expected_x_coord);
        let is_x_reduced = x_as_int >= Secp256k1::ORDER;
        let is_y_odd = total_instance_point.to_sec1_point(false).y().unwrap()[31] & 1 == 1;
        let expected_rec_id = RecoveryId::new(is_y_odd, is_x_reduced);

        // We compare the results.
        assert_eq!(signature.0, expected_signature);
        assert_eq!(signature.1, expected_rec_id.into());
    }

    /// Tests DKG and signing together. The main purpose is to
    /// verify whether the initialization protocols from DKG are working.
    ///
    /// It is a combination of `test_dkg_initialization` and [`test_signing`].
    #[test]
    fn test_dkg_and_signing() {
        // DKG (as in test_dkg_initialization)

        let threshold = rng::get_rng().random_range(2..=5); // You can change the ranges here.
        let offset = rng::get_rng().random_range(0..=5);

        let parameters = Parameters {
            threshold,
            share_count: threshold + offset,
        }; // You can fix the parameters if you prefer.
        let session_id = rng::get_rng().random::<[u8; 32]>();

        // Each party prepares their data for this DKG.
        let mut all_data: Vec<SessionData> = Vec::with_capacity(parameters.share_count as usize);
        for i in 0..parameters.share_count {
            all_data.push(SessionData {
                parameters: parameters.clone(),
                party_index: i + 1,
                session_id: session_id.to_vec(),
            });
        }

        // Phase 1
        let mut dkg_1: Vec<Vec<Scalar>> = Vec::with_capacity(parameters.share_count as usize);
        for i in 0..parameters.share_count {
            let out1 = phase1(&all_data[i as usize]);

            dkg_1.push(out1);
        }

        // Communication round 1 - Each party receives a fragment from each counterparty.
        // They also produce a fragment for themselves.
        let mut poly_fragments = vec![
            Vec::<Scalar>::with_capacity(parameters.share_count as usize);
            parameters.share_count as usize
        ];
        for row_i in dkg_1 {
            for j in 0..parameters.share_count {
                poly_fragments[j as usize].push(row_i[j as usize]);
            }
        }

        // Phase 2
        let mut poly_points: Vec<Scalar> = Vec::with_capacity(parameters.share_count as usize);
        let mut proofs_commitments: Vec<ProofCommitment> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut zero_kept_2to3: Vec<BTreeMap<u8, KeepInitZeroSharePhase2to3>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut zero_transmit_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut bip_kept_2to3: Vec<UniqueKeepDerivationPhase2to3> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut bip_broadcast_2to4: BTreeMap<u8, BroadcastDerivationPhase2to4> = BTreeMap::new();
        for i in 0..parameters.share_count {
            let (out1, out2, out3, out4, out5, out6) =
                phase2(&all_data[i as usize], &poly_fragments[i as usize]);

            poly_points.push(out1);
            proofs_commitments.push(out2);
            zero_kept_2to3.push(out3);
            zero_transmit_2to4.push(out4);
            bip_kept_2to3.push(out5);
            bip_broadcast_2to4.insert(i + 1, out6); // This variable should be grouped into a BTreeMap.
        }

        // Communication round 2
        let mut zero_received_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> =
            Vec::with_capacity(parameters.share_count as usize);
        for i in 1..=parameters.share_count {
            // We don't need to transmit the commitments because proofs_commitments is already what we need.
            // In practice, this should be done here.

            let mut new_row: Vec<TransmitInitZeroSharePhase2to4> =
                Vec::with_capacity((parameters.share_count - 1) as usize);
            for party in &zero_transmit_2to4 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i {
                        new_row.push(message.clone());
                    }
                }
            }
            zero_received_2to4.push(new_row);
        }

        // bip_transmit_2to4 is already in the format we need.
        // In practice, the messages received should be grouped into a BTreeMap.

        // Phase 3
        let mut zero_kept_3to4: Vec<BTreeMap<u8, KeepInitZeroSharePhase3to4>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut zero_transmit_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut mul_kept_3to4: Vec<BTreeMap<u8, KeepInitMulPhase3to4>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut mul_transmit_3to4: Vec<Vec<TransmitInitMulPhase3to4>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut bip_broadcast_3to4: BTreeMap<u8, BroadcastDerivationPhase3to4> = BTreeMap::new();
        for i in 0..parameters.share_count {
            let (out1, out2, out3, out4, out5) = phase3(
                &all_data[i as usize],
                &zero_kept_2to3[i as usize],
                &bip_kept_2to3[i as usize],
            );

            zero_kept_3to4.push(out1);
            zero_transmit_3to4.push(out2);
            mul_kept_3to4.push(out3);
            mul_transmit_3to4.push(out4);
            bip_broadcast_3to4.insert(i + 1, out5); // This variable should be grouped into a BTreeMap.
        }

        // Communication round 3
        let mut zero_received_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut mul_received_3to4: Vec<Vec<TransmitInitMulPhase3to4>> =
            Vec::with_capacity(parameters.share_count as usize);
        for i in 1..=parameters.share_count {
            // We don't need to transmit the proofs because proofs_commitments is already what we need.
            // In practice, this should be done here.

            let mut new_row: Vec<TransmitInitZeroSharePhase3to4> =
                Vec::with_capacity((parameters.share_count - 1) as usize);
            for party in &zero_transmit_3to4 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i {
                        new_row.push(message.clone());
                    }
                }
            }
            zero_received_3to4.push(new_row);

            let mut new_row: Vec<TransmitInitMulPhase3to4> =
                Vec::with_capacity((parameters.share_count - 1) as usize);
            for party in &mul_transmit_3to4 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i {
                        new_row.push(message.clone());
                    }
                }
            }
            mul_received_3to4.push(new_row);
        }

        // bip_transmit_3to4 is already in the format we need.
        // In practice, the messages received should be grouped into a BTreeMap.

        // Phase 4
        let mut parties: Vec<Party> = Vec::with_capacity(parameters.share_count as usize);
        for i in 0..parameters.share_count {
            let result = phase4(
                &all_data[i as usize],
                &poly_points[i as usize],
                &proofs_commitments,
                &zero_kept_3to4[i as usize],
                &zero_received_2to4[i as usize],
                &zero_received_3to4[i as usize],
                &mul_kept_3to4[i as usize],
                &mul_received_3to4[i as usize],
                &bip_broadcast_2to4,
                &bip_broadcast_3to4,
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                }
                Ok(party) => {
                    parties.push(party);
                }
            }
        }

        // We check if the public keys and chain codes are the same.
        let expected_pk = parties[0].pk;
        let expected_chain_code = parties[0].derivation_data.chain_code;
        for party in &parties {
            assert_eq!(expected_pk, party.pk);
            assert_eq!(expected_chain_code, party.derivation_data.chain_code);
        }

        // SIGNING (as in test_signing)

        let sign_id = rng::get_rng().random::<[u8; 32]>();
        let message_to_sign = hash("Message to sign!".as_bytes(), &[]);

        // For simplicity, we are testing only the first parties.
        let executing_parties: Vec<u8> = Vec::from_iter(1..=parameters.threshold);

        // Each party prepares their data for this signing session.
        let mut all_data: BTreeMap<u8, SignData> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            //Gather the counterparties
            let mut counterparties = executing_parties.clone();
            counterparties.retain(|index| *index != party_index);

            all_data.insert(
                party_index,
                SignData {
                    sign_id: sign_id.to_vec(),
                    counterparties,
                    message_hash: message_to_sign,
                },
            );
        }

        // Phase 1
        let mut unique_kept_1to2: BTreeMap<u8, UniqueKeep1to2> = BTreeMap::new();
        let mut kept_1to2: BTreeMap<u8, BTreeMap<u8, KeepPhase1to2>> = BTreeMap::new();
        let mut transmit_1to2: BTreeMap<u8, Vec<TransmitPhase1to2>> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            let (unique_keep, keep, transmit) = parties[(party_index - 1) as usize]
                .sign_phase1(all_data.get(&party_index).unwrap())
                .unwrap();

            unique_kept_1to2.insert(party_index, unique_keep);
            kept_1to2.insert(party_index, keep);
            transmit_1to2.insert(party_index, transmit);
        }

        // Communication round 1
        let mut received_1to2: BTreeMap<u8, Vec<TransmitPhase1to2>> = BTreeMap::new();

        for &party_index in &executing_parties {
            let messages_for_party: Vec<TransmitPhase1to2> = transmit_1to2
                .values()
                .flatten()
                .filter(|message| message.parties.receiver == party_index)
                .cloned()
                .collect();

            received_1to2.insert(party_index, messages_for_party);
        }

        // Phase 2
        let mut unique_kept_2to3: BTreeMap<u8, UniqueKeep2to3> = BTreeMap::new();
        let mut kept_2to3: BTreeMap<u8, BTreeMap<u8, KeepPhase2to3>> = BTreeMap::new();
        let mut transmit_2to3: BTreeMap<u8, Vec<TransmitPhase2to3>> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            let result = parties[(party_index - 1) as usize].sign_phase2(
                all_data.get(&party_index).unwrap(),
                unique_kept_1to2.get(&party_index).unwrap(),
                kept_1to2.get(&party_index).unwrap(),
                received_1to2.get(&party_index).unwrap(),
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                }
                Ok((unique_keep, keep, transmit)) => {
                    unique_kept_2to3.insert(party_index, unique_keep);
                    kept_2to3.insert(party_index, keep);
                    transmit_2to3.insert(party_index, transmit);
                }
            }
        }

        // Communication round 2
        let mut received_2to3: BTreeMap<u8, Vec<TransmitPhase2to3>> = BTreeMap::new();

        for &party_index in &executing_parties {
            let messages_for_party: Vec<TransmitPhase2to3> = transmit_2to3
                .values()
                .flatten()
                .filter(|message| message.parties.receiver == party_index)
                .cloned()
                .collect();

            received_2to3.insert(party_index, messages_for_party);
        }

        // Phase 3
        let mut x_coords: Vec<String> = Vec::with_capacity(parameters.threshold as usize);
        let mut broadcast_3to4: Vec<Broadcast3to4> =
            Vec::with_capacity(parameters.threshold as usize);
        for party_index in executing_parties.clone() {
            let result = parties[(party_index - 1) as usize].sign_phase3(
                all_data.get(&party_index).unwrap(),
                unique_kept_2to3.get(&party_index).unwrap(),
                kept_2to3.get(&party_index).unwrap(),
                received_2to3.get(&party_index).unwrap(),
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                }
                Ok((x_coord, broadcast)) => {
                    x_coords.push(x_coord);
                    broadcast_3to4.push(broadcast);
                }
            }
        }

        // We verify all parties got the same x coordinate.
        let x_coord = x_coords[0].clone(); // We take the first one as reference.
        for i in 1..parameters.threshold {
            assert_eq!(x_coord, x_coords[i as usize]);
        }

        // Communication round 3
        // This is a broadcast to all parties. The desired result is already broadcast_3to4.

        // Phase 4
        // It is essentially independent of the party, so we compute just once.
        let some_index = executing_parties[0];
        let result = parties[(some_index - 1) as usize].sign_phase4(
            all_data.get(&some_index).unwrap(),
            &x_coord,
            &broadcast_3to4,
            true,
        );
        if let Err(abort) = result {
            panic!("Party {} aborted: {:?}", abort.index, abort.description);
        }
        // We could call verify_ecdsa_signature here, but it is already called during Phase 4.
    }

    /// Tests if sign_phase4 handles zero denominator without panicking.
    #[test]
    fn test_sign_phase4_zero_denominator_returns_abort() {
        let parameters = Parameters {
            threshold: 2,
            share_count: 2,
        };
        let session_id = rng::get_rng().random::<[u8; 32]>();
        let secret_key = Scalar::random(&mut rng::get_rng());
        let parties = re_key(&parameters, &session_id, &secret_key, None);

        let data = SignData {
            sign_id: rng::get_rng().random::<[u8; 32]>().to_vec(),
            counterparties: vec![2],
            message_hash: hash("Message to sign!".as_bytes(), &[]),
        };

        let received = vec![Broadcast3to4 {
            u: Scalar::ZERO,
            w: Scalar::ONE,
        }];
        let result = parties[0].sign_phase4(&data, "01", &received, true);
        let abort = result.expect_err("zero denominator should return abort");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(abort
            .description
            .contains("Zero denominator in signature assembly"));
    }

    /// Tests that malformed hex inputs are rejected without panicking.
    #[test]
    fn test_verify_ecdsa_signature_rejects_malformed_hex() {
        let message = hash("Message to sign!".as_bytes(), &[]);
        let pk = AffinePoint::GENERATOR;

        assert!(!verify_ecdsa_signature(&message, &pk, "zz", "11"));
        assert!(!verify_ecdsa_signature(&message, &pk, "", ""));
        assert!(!verify_ecdsa_signature(
            &message,
            &pk,
            "010203",
            "not-a-hex-string"
        ));
    }

    /// Tests if phase 1 rejects duplicate counterparties.
    #[test]
    fn test_sign_phase1_rejects_duplicate_counterparty() {
        let parameters = Parameters {
            threshold: 3,
            share_count: 3,
        };
        let session_id = rng::get_rng().random::<[u8; 32]>();
        let secret_key = Scalar::random(&mut rng::get_rng());
        let parties = re_key(&parameters, &session_id, &secret_key, None);

        let data = SignData {
            sign_id: rng::get_rng().random::<[u8; 32]>().to_vec(),
            counterparties: vec![2, 2],
            message_hash: hash("Message to sign!".as_bytes(), &[]),
        };

        let abort = parties[0]
            .sign_phase1(&data)
            .expect_err("duplicate counterparty should be rejected");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(abort.description.contains("appears more than once"));
    }

    /// Tests if phase 1 rejects missing multiplication state.
    #[test]
    fn test_sign_phase1_rejects_missing_mul_state() {
        let (parties, all_data, _, _, _) = setup_two_party_signing_phase1();
        let mut party = parties[0].clone();
        party.mul_senders.remove(&2);

        let abort = party
            .sign_phase1(all_data.get(&1).expect("party data should exist"))
            .expect_err("missing multiplication state should be rejected");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(abort
            .description
            .contains("Missing multiplication state for counterparty 2"));
    }

    fn setup_two_party_signing_phase1() -> (
        Vec<Party>,
        BTreeMap<u8, SignData>,
        BTreeMap<u8, UniqueKeep1to2>,
        BTreeMap<u8, BTreeMap<u8, KeepPhase1to2>>,
        BTreeMap<u8, Vec<TransmitPhase1to2>>,
    ) {
        let parameters = Parameters {
            threshold: 2,
            share_count: 2,
        };
        let session_id = rng::get_rng().random::<[u8; 32]>();
        let secret_key = Scalar::random(&mut rng::get_rng());
        let parties = re_key(&parameters, &session_id, &secret_key, None);

        let sign_id = rng::get_rng().random::<[u8; 32]>();
        let message_to_sign = hash("Message to sign!".as_bytes(), &[]);

        let mut all_data: BTreeMap<u8, SignData> = BTreeMap::new();
        all_data.insert(
            1,
            SignData {
                sign_id: sign_id.to_vec(),
                counterparties: vec![2],
                message_hash: message_to_sign,
            },
        );
        all_data.insert(
            2,
            SignData {
                sign_id: sign_id.to_vec(),
                counterparties: vec![1],
                message_hash: message_to_sign,
            },
        );

        let mut unique_kept_1to2: BTreeMap<u8, UniqueKeep1to2> = BTreeMap::new();
        let mut kept_1to2: BTreeMap<u8, BTreeMap<u8, KeepPhase1to2>> = BTreeMap::new();
        let mut transmit_1to2: BTreeMap<u8, Vec<TransmitPhase1to2>> = BTreeMap::new();
        for party_index in [1u8, 2u8] {
            let (unique_keep, keep, transmit) = match parties[(party_index - 1) as usize]
                .sign_phase1(all_data.get(&party_index).unwrap())
            {
                Ok(result) => result,
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                }
            };

            unique_kept_1to2.insert(party_index, unique_keep);
            kept_1to2.insert(party_index, keep);
            transmit_1to2.insert(party_index, transmit);
        }

        let mut received_1to2: BTreeMap<u8, Vec<TransmitPhase1to2>> = BTreeMap::new();
        for party_index in [1u8, 2u8] {
            let messages_for_party: Vec<TransmitPhase1to2> = transmit_1to2
                .values()
                .flatten()
                .filter(|message| message.parties.receiver == party_index)
                .cloned()
                .collect();
            received_1to2.insert(party_index, messages_for_party);
        }

        (
            parties,
            all_data,
            unique_kept_1to2,
            kept_1to2,
            received_1to2,
        )
    }

    fn run_two_party_phase2(
        parties: &[Party],
        all_data: &BTreeMap<u8, SignData>,
        unique_kept_1to2: &BTreeMap<u8, UniqueKeep1to2>,
        kept_1to2: &BTreeMap<u8, BTreeMap<u8, KeepPhase1to2>>,
        received_1to2: &BTreeMap<u8, Vec<TransmitPhase1to2>>,
    ) -> (
        BTreeMap<u8, UniqueKeep2to3>,
        BTreeMap<u8, BTreeMap<u8, KeepPhase2to3>>,
        BTreeMap<u8, Vec<TransmitPhase2to3>>,
    ) {
        let mut unique_kept_2to3: BTreeMap<u8, UniqueKeep2to3> = BTreeMap::new();
        let mut kept_2to3: BTreeMap<u8, BTreeMap<u8, KeepPhase2to3>> = BTreeMap::new();
        let mut transmit_2to3: BTreeMap<u8, Vec<TransmitPhase2to3>> = BTreeMap::new();
        for party_index in [1u8, 2u8] {
            let result = parties[(party_index - 1) as usize].sign_phase2(
                all_data.get(&party_index).unwrap(),
                unique_kept_1to2.get(&party_index).unwrap(),
                kept_1to2.get(&party_index).unwrap(),
                received_1to2.get(&party_index).unwrap(),
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                }
                Ok((unique_keep, keep, transmit)) => {
                    unique_kept_2to3.insert(party_index, unique_keep);
                    kept_2to3.insert(party_index, keep);
                    transmit_2to3.insert(party_index, transmit);
                }
            }
        }

        let mut received_2to3: BTreeMap<u8, Vec<TransmitPhase2to3>> = BTreeMap::new();
        for party_index in [1u8, 2u8] {
            let messages_for_party: Vec<TransmitPhase2to3> = transmit_2to3
                .values()
                .flatten()
                .filter(|message| message.parties.receiver == party_index)
                .cloned()
                .collect();
            received_2to3.insert(party_index, messages_for_party);
        }

        (unique_kept_2to3, kept_2to3, received_2to3)
    }

    fn run_two_party_phase3(
        parties: &[Party],
        all_data: &BTreeMap<u8, SignData>,
        unique_kept_2to3: &BTreeMap<u8, UniqueKeep2to3>,
        kept_2to3: &BTreeMap<u8, BTreeMap<u8, KeepPhase2to3>>,
        received_2to3: &BTreeMap<u8, Vec<TransmitPhase2to3>>,
    ) -> (String, Vec<Broadcast3to4>) {
        let mut x_coords: Vec<String> = Vec::with_capacity(2);
        let mut broadcasts: Vec<Broadcast3to4> = Vec::with_capacity(2);
        for party_index in [1u8, 2u8] {
            let result = parties[(party_index - 1) as usize].sign_phase3(
                all_data.get(&party_index).unwrap(),
                unique_kept_2to3.get(&party_index).unwrap(),
                kept_2to3.get(&party_index).unwrap(),
                received_2to3.get(&party_index).unwrap(),
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                }
                Ok((x_coord, broadcast)) => {
                    x_coords.push(x_coord);
                    broadcasts.push(broadcast);
                }
            }
        }

        assert_eq!(x_coords[0], x_coords[1]);
        (x_coords[0].clone(), broadcasts)
    }

    /// Tests if phase 2 rejects messages from unknown senders.
    #[test]
    fn test_sign_phase2_rejects_unknown_sender() {
        let (parties, all_data, unique_kept_1to2, kept_1to2, received_1to2) =
            setup_two_party_signing_phase1();

        let mut tampered = received_1to2.get(&1).unwrap().clone();
        tampered[0].parties.sender = 3;

        let result = parties[0].sign_phase2(
            all_data.get(&1).unwrap(),
            unique_kept_1to2.get(&1).unwrap(),
            kept_1to2.get(&1).unwrap(),
            &tampered,
        );
        let abort = result.expect_err("unknown sender should be rejected");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(abort
            .description
            .contains("Received message from unknown sender"));
    }

    /// Tests if phase 2 rejects messages addressed to a different receiver.
    #[test]
    fn test_sign_phase2_rejects_wrong_receiver() {
        let (parties, all_data, unique_kept_1to2, kept_1to2, received_1to2) =
            setup_two_party_signing_phase1();

        let mut tampered = received_1to2.get(&1).unwrap().clone();
        tampered[0].parties.receiver = 2;

        let result = parties[0].sign_phase2(
            all_data.get(&1).unwrap(),
            unique_kept_1to2.get(&1).unwrap(),
            kept_1to2.get(&1).unwrap(),
            &tampered,
        );
        let abort = result.expect_err("wrong receiver should be rejected");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(abort.description.contains("Received message addressed to"));
    }

    /// Tests if phase 2 rejects message vectors with unexpected size.
    #[test]
    fn test_sign_phase2_rejects_wrong_message_count() {
        let (parties, all_data, unique_kept_1to2, kept_1to2, _) = setup_two_party_signing_phase1();

        let result = parties[0].sign_phase2(
            all_data.get(&1).unwrap(),
            unique_kept_1to2.get(&1).unwrap(),
            kept_1to2.get(&1).unwrap(),
            &[],
        );
        let abort = result.expect_err("wrong message count should be rejected");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(abort
            .description
            .contains("unexpected number of round-1 messages"));
    }

    /// Tests if phase 3 rejects invalid decommitment data.
    #[test]
    fn test_sign_phase3_rejects_invalid_commitment_decommit() {
        let (parties, all_data, unique_kept_1to2, kept_1to2, received_1to2) =
            setup_two_party_signing_phase1();
        let (unique_kept_2to3, kept_2to3, received_2to3) = run_two_party_phase2(
            &parties,
            &all_data,
            &unique_kept_1to2,
            &kept_1to2,
            &received_1to2,
        );

        let mut tampered = received_2to3.get(&1).unwrap().clone();
        assert!(
            !tampered[0].salt.is_empty(),
            "phase-3 decommit salt should be non-empty"
        );
        tampered[0].salt[0] ^= 1;

        let result = parties[0].sign_phase3(
            all_data.get(&1).unwrap(),
            unique_kept_2to3.get(&1).unwrap(),
            kept_2to3.get(&1).unwrap(),
            &tampered,
        );
        let abort = result.expect_err("invalid decommit should be rejected");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(abort.description.contains("Failed to verify commitment"));
    }

    /// Tests if phase 3 rejects message vectors with unexpected size.
    #[test]
    fn test_sign_phase3_rejects_wrong_message_count() {
        let (parties, all_data, unique_kept_1to2, kept_1to2, received_1to2) =
            setup_two_party_signing_phase1();
        let (unique_kept_2to3, kept_2to3, _) = run_two_party_phase2(
            &parties,
            &all_data,
            &unique_kept_1to2,
            &kept_1to2,
            &received_1to2,
        );

        let result = parties[0].sign_phase3(
            all_data.get(&1).unwrap(),
            unique_kept_2to3.get(&1).unwrap(),
            kept_2to3.get(&1).unwrap(),
            &[],
        );
        let abort = result.expect_err("wrong message count should be rejected");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(abort
            .description
            .contains("unexpected number of round-2 messages"));
    }

    /// Tests if phase 3 emits a ban abort on gamma_u inconsistency.
    #[test]
    fn test_sign_phase3_bans_on_inconsistent_gamma_u() {
        let (parties, all_data, unique_kept_1to2, kept_1to2, received_1to2) =
            setup_two_party_signing_phase1();
        let (unique_kept_2to3, kept_2to3, received_2to3) = run_two_party_phase2(
            &parties,
            &all_data,
            &unique_kept_1to2,
            &kept_1to2,
            &received_1to2,
        );

        let mut tampered = received_2to3.get(&1).unwrap().clone();
        tampered[0].gamma_u =
            (ProjectivePoint::from(tampered[0].gamma_u) + ProjectivePoint::GENERATOR).to_affine();

        let result = parties[0].sign_phase3(
            all_data.get(&1).unwrap(),
            unique_kept_2to3.get(&1).unwrap(),
            kept_2to3.get(&1).unwrap(),
            &tampered,
        );
        let abort = result.expect_err("inconsistent gamma_u should be rejected");
        assert_eq!(abort.kind, AbortKind::BanCounterparty(2));
        assert!(abort
            .description
            .contains("Consistency check with u-variables failed"));
    }

    /// Tests if phase 4 rejects tampered broadcast values that invalidate signature assembly.
    #[test]
    fn test_sign_phase4_rejects_tampered_broadcast() {
        let (parties, all_data, unique_kept_1to2, kept_1to2, received_1to2) =
            setup_two_party_signing_phase1();
        let (unique_kept_2to3, kept_2to3, received_2to3) = run_two_party_phase2(
            &parties,
            &all_data,
            &unique_kept_1to2,
            &kept_1to2,
            &received_1to2,
        );
        let (x_coord, mut broadcasts) = run_two_party_phase3(
            &parties,
            &all_data,
            &unique_kept_2to3,
            &kept_2to3,
            &received_2to3,
        );

        broadcasts[0].w += Scalar::ONE;

        let result = parties[0].sign_phase4(all_data.get(&1).unwrap(), &x_coord, &broadcasts, true);
        let abort = result.expect_err("tampered broadcast should fail signature validation");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(abort.description.contains("Invalid ECDSA signature"));
    }
}
