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

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::ScalarPrimitive;
use k256::elliptic_curve::{bigint::Encoding, ops::Reduce, point::AffineCoordinates, Curve, Field};
use k256::{AffinePoint, ProjectivePoint, Scalar, Secp256k1, U256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use hex;

use crate::protocols::{Abort, PartiesMessage, Party};

use crate::utilities::commits::{commit_point, verify_commitment_point};
use crate::utilities::hashes::HashOutput;
use crate::utilities::multiplication::{MulDataToKeepReceiver, MulDataToReceiver};
use crate::utilities::ot::extension::OTEDataToSender;
use crate::utilities::rng;

/// Data needed to start the signature and is used during the phases.
#[derive(Serialize, Deserialize, Debug)]
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
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TransmitPhase1to2 {
    pub parties: PartiesMessage,
    pub commitment: HashOutput,
    pub mul_transmit: OTEDataToSender,
}

/// Transmit - Signing.
///
/// The message is produced/sent during Phase 2 and used in Phase 3.
#[derive(Clone, Serialize, Deserialize, Debug)]
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
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Broadcast3to4 {
    pub u: Scalar,
    pub w: Scalar,
}

// STRUCTS FOR MESSAGES TO KEEP BETWEEN PHASES.

/// Keep - Signing.
///
/// The message is produced during Phase 1 and used in Phase 2.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct KeepPhase1to2 {
    pub salt: Vec<u8>,
    pub chi: Scalar,
    pub mul_keep: MulDataToKeepReceiver,
}

/// Keep - Signing.
///
/// The message is produced during Phase 2 and used in Phase 3.
#[derive(Clone, Serialize, Deserialize, Debug)]
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
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct UniqueKeep1to2 {
    pub instance_key: Scalar,
    pub instance_point: AffinePoint,
    pub inversion_mask: Scalar,
    pub zeta: Scalar,
}

/// Unique keep - Signing.
///
/// The message is produced during Phase 2 and used in Phase 3.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct UniqueKeep2to3 {
    pub instance_key: Scalar,
    pub instance_point: AffinePoint,
    pub inversion_mask: Scalar,
    pub key_share: Scalar,
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
    /// # Panics
    ///
    /// Will panic if the number of counterparties in `data` is incompatible.
    #[must_use]
    pub fn sign_phase1(
        &self,
        data: &SignData,
    ) -> (
        UniqueKeep1to2,
        BTreeMap<u8, KeepPhase1to2>,
        Vec<TransmitPhase1to2>,
    ) {
        // Step 4 - We check if we have the correct number of counter parties.
        assert_eq!(
            data.counterparties.len(),
            (self.parameters.threshold - 1) as usize,
            "The number of signing parties is not right!"
        );

        // Step 5 - We sample our secret data.
        let instance_key = Scalar::random(rng::get_rng());
        let inversion_mask = Scalar::random(rng::get_rng());

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
            let mul_sid = [
                "Multiplication protocol".as_bytes(),
                &self.party_index.to_be_bytes(),
                &counterparty.to_be_bytes(),
                &self.session_id,
                &data.sign_id,
            ]
            .concat();

            // We run the first phase.
            let (chi, mul_keep, mul_transmit) = self
                .mul_receivers
                .get(counterparty)
                .unwrap()
                .run_phase1(&mul_sid);

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
        (unique_keep, keep, transmit)
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
        let l = l_numerator * (l_denominator.invert().unwrap());

        // These are sk_i and pk_i from the paper.
        let key_share = (self.poly_point * l) + unique_kept.zeta;
        let public_share = (AffinePoint::GENERATOR * key_share).to_affine();

        // This is the input for the multiplication protocol.
        let input = vec![unique_kept.instance_key, key_share];

        // Now, we compute the variables related to each counter party.
        let mut keep: BTreeMap<u8, KeepPhase2to3> = BTreeMap::new();
        let mut transmit: Vec<TransmitPhase2to3> =
            Vec::with_capacity((self.parameters.threshold - 1) as usize);
        for message in received {
            // Index for the counterparty.
            let counterparty = message.parties.sender;
            let current_kept = kept.get(&counterparty).unwrap();

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
            ]
            .concat();

            let mul_result = self.mul_senders.get(&counterparty).unwrap().run(
                &mul_sid,
                &input,
                &message.mul_transmit,
            );

            let c_u: Scalar;
            let c_v: Scalar;
            let mul_transmit: MulDataToReceiver;
            match mul_result {
                Err(error) => {
                    return Err(Abort::new(
                        self.party_index,
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

        for message in received {
            // Index for the counterparty.
            let counterparty = message.parties.sender;
            let current_kept = kept.get(&counterparty).unwrap();

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
            ]
            .concat();

            let mul_result = self.mul_receivers.get(&counterparty).unwrap().run_phase2(
                &mul_sid,
                &current_kept.mul_keep,
                &message.mul_transmit,
            );

            let d_u: Scalar;
            let d_v: Scalar;
            match mul_result {
                Err(error) => {
                    return Err(Abort::new(
                        self.party_index,
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
                return Err(Abort::new(
                    self.party_index,
                    &format!("Consistency check with u-variables failed for Party {counterparty}!"),
                ));
            }

            // In the paper, they write "Lagrange(P, j, 0) · P(j)". For the math
            // to be consistent, we believe it should be "pk_j" instead.
            // This agrees with the alternative computation of gamma_v at the
            // end of page 21 in the paper.
            if (message.public_share * current_kept.chi) != ((generator * d_v) + message.gamma_v) {
                return Err(Abort::new(
                    self.party_index,
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

        let x_coord = hex::encode(total_instance_point.x().as_slice());
        // There is no salt because the hash function here is always the same.
        let w = (Scalar::reduce(U256::from_be_bytes(data.message_hash))
            * unique_kept.inversion_mask)
            + (v * Scalar::reduce(U256::from_be_hex(&x_coord)));

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
    /// Will return `Err` if the final ECDSA signature is invalid.
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

        let mut s = numerator * (denominator.invert().unwrap());

        // Normalize signature into "low S" form as described in
        // BIP-0062 Dealing with Malleability: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
        if normalize && s.is_high().into() {
            s = ScalarPrimitive::from(-s).into();
        }

        let signature = hex::encode(s.to_bytes().as_slice());

        let verification =
            verify_ecdsa_signature(&data.message_hash, &self.pk, x_coord, &signature);
        if !verification {
            return Err(Abort::new(
                self.party_index,
                "Invalid ECDSA signature at the end of the protocol!",
            ));
        }

        let prehash_signed = data.message_hash.as_slice();

        let verifying_key_from_pk = VerifyingKey::from_affine(self.pk).unwrap();

        let scalar_sig_r = Scalar::reduce(U256::from_be_hex(x_coord));
        let scalar_sig_s = Scalar::reduce(U256::from_be_hex(&signature));
        let partial_sig: Signature = Signature::from_scalars(scalar_sig_r, scalar_sig_s).unwrap();

        // Choose the recovery id by testing which possibility recover the right public key.
        let rec_id = RecoveryId::trial_recovery_from_prehash(
            &verifying_key_from_pk,
            prehash_signed,
            &partial_sig,
        )
        .unwrap()
        .to_byte();

        Ok((signature, rec_id))
    }
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
    let rx_as_int = U256::from_be_hex(x_coord);
    let s_as_int = U256::from_be_hex(signature);

    // Verify if the numbers are in the correct range.
    if !(U256::ZERO < rx_as_int
        && rx_as_int < Secp256k1::ORDER
        && U256::ZERO < s_as_int
        && s_as_int < Secp256k1::ORDER)
    {
        return false;
    }

    let rx_as_scalar = Scalar::reduce(rx_as_int);
    let s_as_scalar = Scalar::reduce(s_as_int);

    let inverse_s = s_as_scalar.invert().unwrap();

    let first = Scalar::reduce(U256::from_be_bytes(*msg)) * inverse_s;
    let second = rx_as_scalar * inverse_s;

    let point_to_check = ((AffinePoint::GENERATOR * first) + (*pk * second)).to_affine();
    if point_to_check == AffinePoint::IDENTITY {
        return false;
    }

    let x_check = Scalar::reduce(U256::from_be_slice(point_to_check.x().as_slice()));

    x_check == rx_as_scalar
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::dkg::*;
    use crate::protocols::re_key::re_key;
    use crate::protocols::*;
    use crate::utilities::hashes::hash;
    use rand::Rng;

    /// Tests if the signing protocol generates a valid ECDSA signature.
    ///
    /// In this case, parties are sampled via the [`re_key`] function.
    #[test]
    fn test_signing() {
        // Disclaimer: this implementation is not the most efficient,
        // we are only testing if everything works! Note as well that
        // parties are being simulated one after the other, but they
        // should actually execute the protocol simultaneously.

        let threshold = rng::get_rng().gen_range(2..=5); // You can change the ranges here.
        let offset = rng::get_rng().gen_range(0..=5);

        let parameters = Parameters {
            threshold,
            share_count: threshold + offset,
        }; // You can fix the parameters if you prefer.

        // We use the re_key function to quickly sample the parties.
        let session_id = rng::get_rng().gen::<[u8; 32]>();
        let secret_key = Scalar::random(rng::get_rng());
        let parties = re_key(&parameters, &session_id, &secret_key, None);

        // SIGNING

        let sign_id = rng::get_rng().gen::<[u8; 32]>();
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
                .sign_phase1(all_data.get(&party_index).unwrap());

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
        let threshold = rng::get_rng().gen_range(2..=5); // You can change the ranges here.
        let offset = rng::get_rng().gen_range(0..=5);

        let parameters = Parameters {
            threshold,
            share_count: threshold + offset,
        }; // You can fix the parameters if you prefer.

        // We use the re_key function to quickly sample the parties.
        let session_id = rng::get_rng().gen::<[u8; 32]>();
        let secret_key = Scalar::random(rng::get_rng());
        let parties = re_key(&parameters, &session_id, &secret_key, None);

        // SIGNING (as in test_signing)

        let sign_id = rng::get_rng().gen::<[u8; 32]>();
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
                .sign_phase1(all_data.get(&party_index).unwrap());

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
        let expected_x_coord = hex::encode(total_instance_point.x().as_slice());
        assert_eq!(x_coord, expected_x_coord);

        // The hash of the message:
        let hashed_message = Scalar::reduce(U256::from_be_bytes(message_to_sign));
        assert_eq!(
            hashed_message,
            Scalar::reduce(U256::from_be_hex(
                "ece3e5d77980859352a5e702cb429f3d4dbdc12443e359ae60d15fe3c0333c0d"
            ))
        );

        // Now we can find the signature in the usual way.
        let expected_signature_as_scalar = total_instance_key.invert().unwrap()
            * (hashed_message
                + (secret_key * Scalar::reduce(U256::from_be_hex(&expected_x_coord))));
        let expected_signature = hex::encode(expected_signature_as_scalar.to_bytes().as_slice());

        // We compare the results.
        assert_eq!(signature.0, expected_signature);
    }

    /// Tests DKG and signing together. The main purpose is to
    /// verify whether the initialization protocols from DKG are working.
    ///
    /// It is a combination of `test_dkg_initialization` and [`test_signing`].
    #[test]
    fn test_dkg_and_signing() {
        // DKG (as in test_dkg_initialization)

        let threshold = rng::get_rng().gen_range(2..=5); // You can change the ranges here.
        let offset = rng::get_rng().gen_range(0..=5);

        let parameters = Parameters {
            threshold,
            share_count: threshold + offset,
        }; // You can fix the parameters if you prefer.
        let session_id = rng::get_rng().gen::<[u8; 32]>();

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

        let sign_id = rng::get_rng().gen::<[u8; 32]>();
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
                .sign_phase1(all_data.get(&party_index).unwrap());

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
}
