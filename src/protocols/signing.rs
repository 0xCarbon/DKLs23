/// This file implements the signing phase of Protocol 3.6 from DKLs23
/// (https://eprint.iacr.org/2023/765.pdf). It is the core of this repository.

use std::collections::HashMap;

use curv::elliptic::curves::{Scalar,Point,Secp256k1};
use curv::arithmetic::*;

use crate::protocols::{Party, Abort, PartiesMessage};

use crate::utilities::commits::*;
use crate::utilities::hashes::*;
use crate::utilities::multiplication::*;
use crate::utilities::ot::ot_extension::*;

// This struct contains the data needed to start
// the signature and that are used during the phases.

pub struct SignData {
    pub sign_id: Vec<u8>,
    pub counterparties: Vec<usize>,
    pub message_to_sign: Vec<u8>,
}

////////// STRUCTS FOR MESSAGES TO TRANSMIT IN COMMUNICATION ROUNDS.

// "Transmit" messages refer to only one counterparty, hence
// we must send a whole vector of them.

#[derive(Clone)]
pub struct TransmitPhase1to2 {
    pub parties: PartiesMessage,
    pub commitment: HashOutput,
    pub mul_transmit: OTEDataToSender,
}

#[derive(Clone)]
pub struct TransmitPhase2to3 {
    pub parties: PartiesMessage,
    pub gamma_u: Point<Secp256k1>,
    pub gamma_v: Point<Secp256k1>,
    pub psi: Scalar<Secp256k1>,
    pub public_share: Point<Secp256k1>,
    pub instance_point: Point<Secp256k1>,
    pub salt: Vec<u8>,
    pub mul_transmit: MulDataToReceiver,
}

// "Broadcast" messages refer to all counterparties at once,
// hence we only need to send a unique instance of it.

#[derive(Clone)]
pub struct Broadcast3to4 {
    pub u: Scalar<Secp256k1>,
    pub w: Scalar<Secp256k1>,
}

////////// STRUCTS FOR MESSAGES TO KEEP BETWEEN PHASES.

// "Keep" messages refer to only one counterparty, hence
// we must keep a whole vector of them.

#[derive(Clone)]
pub struct KeepPhase1to2 {
    pub salt: Vec<u8>,
    pub chi: Scalar<Secp256k1>,
    pub mul_keep: MulDataToKeepReceiver,
}

#[derive(Clone)]
pub struct KeepPhase2to3 {
    pub c_u: Scalar<Secp256k1>,
    pub c_v: Scalar<Secp256k1>,
    pub commitment: HashOutput,
    pub mul_keep: MulDataToKeepReceiver,
    pub chi: Scalar<Secp256k1>,
}

// "Unique keep" messages refer to all counterparties at once,
// hence we only need to keep a unique instance of it.

#[derive(Clone)]
pub struct UniqueKeep1to2 {
    pub instance_key: Scalar<Secp256k1>,
    pub instance_point: Point<Secp256k1>,
    pub inversion_mask: Scalar<Secp256k1>,
    pub zeta: Scalar<Secp256k1>,
}

#[derive(Clone)]
pub struct UniqueKeep2to3 {
    pub instance_key: Scalar<Secp256k1>,
    pub instance_point: Point<Secp256k1>,
    pub inversion_mask: Scalar<Secp256k1>,
    pub key_share: Scalar<Secp256k1>,
    pub public_share: Point<Secp256k1>,
}

//////////////////////////

// SIGNING PROTOCOL
// We now follow Protocol 3.6 of DKLs23.

impl Party {

    pub fn sign_phase1(&self, data: &SignData) -> (UniqueKeep1to2, HashMap<usize,KeepPhase1to2>, Vec<TransmitPhase1to2>) {

        // Step 4 - We check if we have the correct number of counter parties.
        if data.counterparties.len() != self.parameters.threshold - 1 {
            panic!("The number of signing parties is not right!");
        }

        // Step 5 - We sample our secret data.
        let instance_key = Scalar::<Secp256k1>::random();
        let inversion_mask = Scalar::<Secp256k1>::random();

        let instance_point = Point::<Secp256k1>::generator() * &instance_key;

        // Step 6 - We prepare the messages to keep and to send.

        let mut keep: HashMap<usize,KeepPhase1to2> = HashMap::with_capacity(self.parameters.threshold - 1);
        let mut transmit: Vec<TransmitPhase1to2> = Vec::with_capacity(self.parameters.threshold - 1);
        for counterparty in &data.counterparties {

            // Commit functionality.
            let (commitment, salt) = commit_point(&instance_point);

            // Two-party multiplication functionality.
            // We start as the receiver.

            // First, let us compute a session id for it.
            // As in Protocol 3.6 of DKLs23, we include the indexes from the parties.
            // We also use both the sign id and the DKG id.
            let mul_sid = [self.party_index.to_be_bytes().to_vec(), counterparty.to_be_bytes().to_vec(), self.session_id.clone(), data.sign_id.clone()].concat();

            // We run the first phase.
            let (chi, mul_keep, mul_transmit) = self.mul_receivers.get(counterparty).unwrap().run_phase1(&mul_sid);

            // We gather the messages.
            keep.insert(*counterparty,KeepPhase1to2 {
                salt,
                chi,
                mul_keep,
            });
            transmit.push( TransmitPhase1to2 {
                parties: PartiesMessage { sender: self.party_index, receiver: *counterparty },
                commitment,
                mul_transmit,
            });
        }

        // Zero-sharing functionality.
        // We put it here because it doesn't depend on counter parties.

        // We first compute a session id.
        // Now, different to DKLs23, we won't put the indexes from the parties
        // because the sign id refers only to this set of parties, hence
        // it's simpler and almost equivalent to take just the following:
        let zero_sid = [self.session_id.clone(), data.sign_id.clone()].concat();

        let zeta = self.zero_share.compute(&data.counterparties, &zero_sid);

        // "Unique" because it is only one message refering to all counter parties.
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

    pub fn sign_phase2(&self, data: &SignData, unique_kept: &UniqueKeep1to2, kept: &HashMap<usize,KeepPhase1to2>, received: &Vec<TransmitPhase1to2>) -> Result<(UniqueKeep2to3, HashMap<usize,KeepPhase2to3>, Vec<TransmitPhase2to3>),Abort> {

        // Step 7

        // We first compute the values that only depend on us.
        
        // We find the Lagrange coefficient associated to us.
        // It is the same as the one calculated during DKG.
        let mut l_numerator = Scalar::<Secp256k1>::from(1);
        let mut l_denominator = Scalar::<Secp256k1>::from(1);
        for counterparty in &data.counterparties {
            l_numerator = l_numerator * Scalar::<Secp256k1>::from(*counterparty as u16);
            l_denominator = l_denominator * (Scalar::<Secp256k1>::from(*counterparty as u16) - Scalar::<Secp256k1>::from(self.party_index as u16));
        }
        let l = l_numerator * (l_denominator.invert().unwrap());

        // These are sk_i and pk_i from the paper.
        let key_share = (&self.poly_point * l) + &unique_kept.zeta;
        let public_share = Point::<Secp256k1>::generator() * &key_share;
        
        // This is the input for the multiplication protocol.
        let input = vec![unique_kept.instance_key.clone(), key_share.clone()];

        // Now, we compute the variables related to each counter party. 
        let mut keep: HashMap<usize,KeepPhase2to3> = HashMap::with_capacity(self.parameters.threshold - 1);
        let mut transmit: Vec<TransmitPhase2to3> = Vec::with_capacity(self.parameters.threshold - 1);
        for message in received {

            // Index for the counterparty.
            let counterparty = message.parties.sender;
            let current_kept = kept.get(&counterparty).unwrap();

            // We continue the multiplciation protocol to get the values
            // c^u and c^v from the paper. We are now the sender.

            // Let us retrieve the session id for multiplication.
            // Note that the roles are now reversed.
            let mul_sid = [counterparty.to_be_bytes().to_vec(), self.party_index.to_be_bytes().to_vec(), self.session_id.clone(), data.sign_id.clone()].concat();

            let mul_result = self.mul_senders.get(&counterparty).unwrap().run(&mul_sid, &input, &message.mul_transmit);
            
            let c_u: Scalar<Secp256k1>;
            let c_v: Scalar<Secp256k1>;
            let mul_transmit: MulDataToReceiver;
            match mul_result {
                Err(error) => {
                    return Err(Abort::new(self.party_index, &format!("Two-party multiplication protocol failed because of Party {}: {:?}", counterparty, error.description)));
                },
                Ok((c_values, data_to_receiver)) => {
                    c_u = c_values[0].clone();
                    c_v = c_values[1].clone();
                    mul_transmit = data_to_receiver;
                },
            }

            // We compute the remaining values.
            let gamma_u = Point::<Secp256k1>::generator() * &c_u;
            let gamma_v = Point::<Secp256k1>::generator() * &c_v;

            let psi = &unique_kept.inversion_mask - &current_kept.chi;

            keep.insert(counterparty,KeepPhase2to3 {
                c_u,
                c_v,
                commitment: message.commitment,
                mul_keep: current_kept.mul_keep.clone(),
                chi: current_kept.chi.clone(),
            });
            transmit.push( TransmitPhase2to3 {
                parties: PartiesMessage { sender: self.party_index, receiver: counterparty },
                // Check-adjust
                gamma_u,
                gamma_v,
                psi,
                public_share: public_share.clone(),
                // Decommit 
                instance_point: unique_kept.instance_point.clone(),
                salt: current_kept.salt.clone(),
                // Multiply
                mul_transmit,
            });            
        }

        // Common values to keep for the next phase.
        let unique_keep = UniqueKeep2to3 {
            instance_key: unique_kept.instance_key.clone(),
            instance_point: unique_kept.instance_point.clone(),
            inversion_mask: unique_kept.inversion_mask.clone(),
            key_share,
            public_share,
        };

        Ok((unique_keep, keep, transmit))
    }

    // Communication round 2
    // Transmit the messages.

    pub fn sign_phase3(&self, data: &SignData, unique_kept: &UniqueKeep2to3, kept: &HashMap<usize,KeepPhase2to3>, received: &Vec<TransmitPhase2to3>) -> Result<(BigInt,Broadcast3to4),Abort> {

        // Steps 8 and 9

        // The following values will represent the sums calculated in this step.
        let mut expected_public_key = unique_kept.public_share.clone();
        let mut total_instance_point = unique_kept.instance_point.clone();

        let mut first_sum_u_v = unique_kept.inversion_mask.clone();

        let mut second_sum_u = Scalar::<Secp256k1>::zero();
        let mut second_sum_v = Scalar::<Secp256k1>::zero();

        for message in received {

            // Index for the counterparty.
            let counterparty = message.parties.sender;
            let current_kept = kept.get(&counterparty).unwrap();

            // Checking the commited value.
            let verification = verify_commitment_point(&message.instance_point, &current_kept.commitment, &message.salt);
            if !verification {
                return Err(Abort::new(self.party_index, &format!("Failed to verify commitment from Party {}!", counterparty)));
            }

            // Finishing the multiplication protocol.
            // We are now the receiver.

            // Let us retrieve the session id for multiplication.
            // Note that we reverse the roles again.
            let mul_sid = [self.party_index.to_be_bytes().to_vec(), counterparty.to_be_bytes().to_vec(), self.session_id.clone(), data.sign_id.clone()].concat();

            let mul_result = self.mul_receivers.get(&counterparty).unwrap().run_phase2(&mul_sid, &current_kept.mul_keep, &message.mul_transmit);

            let d_u: Scalar<Secp256k1>;
            let d_v: Scalar<Secp256k1>;
            match mul_result {
                Err(error) => {
                    return Err(Abort::new(self.party_index, &format!("Two-party multiplication protocol failed because of Party {}: {:?}", counterparty, error.description)));
                },
                Ok(d_values) => {
                    d_u = d_values[0].clone();
                    d_v = d_values[1].clone();
                },
            }

            // First consistency checks.
            let generator = Point::<Secp256k1>::generator();
            
            if &current_kept.chi * &message.instance_point != &message.gamma_u + (generator * &d_u) {
                return Err(Abort::new(self.party_index, &format!("Consistency check with u-variables failed for Party {}!", counterparty)));
            }

            // In the paper, they write "lagrange(P, j, 0) · P(j)". For the math
            // to be consistent, we belive it should be "pk_j" instead.
            // This agrees with the alternative computation of gamma_v at the
            // end of page 21 in the paper.
            if &current_kept.chi * &message.public_share != &message.gamma_v + (generator * &d_v) {
                return Err(Abort::new(self.party_index, &format!("Consistency check with v-variables failed for Party {}!", counterparty)));
            }

            // We add the current summands to our sums.
            expected_public_key = expected_public_key + &message.public_share;
            total_instance_point = total_instance_point + &message.instance_point;

            first_sum_u_v = first_sum_u_v + &message.psi;

            second_sum_u = second_sum_u + &current_kept.c_u + d_u;
            second_sum_v = second_sum_v + &current_kept.c_v + d_v;
        }

        // Second consistency check.
        if expected_public_key != self.pk {
            return Err(Abort::new(self.party_index, "Consistency check for public key reconstruction failed!"));
        }

        // We compute u_i, v_i and w_i from the paper.
        let u = (&unique_kept.instance_key * &first_sum_u_v) + second_sum_u;
        let v = (&unique_kept.key_share * &first_sum_u_v) + second_sum_v;

        let x_coord = total_instance_point.x_coord().unwrap().modulus(Scalar::<Secp256k1>::group_order());
        // There is no salt because the hash function here is always the same.
        let w = (hash_as_scalar(&data.message_to_sign, &[]) * &unique_kept.inversion_mask) + (v * Scalar::<Secp256k1>::from_bigint(&x_coord));

        let broadcast = Broadcast3to4 {
            u,
            w,
        };

        // We also return the x-coordinate of the instance point.
        // This is half of the final signature.
        Ok((x_coord, broadcast))
    }

    // Communication round 3
    // Broadcast the messages (including to ourselves).

    pub fn sign_phase4(&self, data: &SignData, x_coord: &BigInt, received: &Vec<Broadcast3to4>) -> Result<BigInt,Abort> {

        // Step 10

        let mut numerator = Scalar::<Secp256k1>::zero();
        let mut denominator = Scalar::<Secp256k1>::zero();
        for message in received {
            numerator = numerator + &message.w;
            denominator = denominator + &message.u;
        }

        let signature_as_scalar = numerator * (denominator.invert().unwrap());
        let signature = signature_as_scalar.to_bigint();

        let verification = verify_ecdsa_signature(&data.message_to_sign, &self.pk, x_coord, &signature);
        if !verification {
            return Err(Abort::new(self.party_index, "Invalid ECDSA signature at the end of the protocol!"));
        }

        Ok(signature)
    }
}

// This function is the verifying function from usual ECDSA.
pub fn verify_ecdsa_signature(msg: &[u8], pk: &Point<Secp256k1>, x_coord: &BigInt, signature: &BigInt) -> bool {

    // Verify if the numbers are in the correct range.
    if !(&BigInt::zero() < x_coord && x_coord < Scalar::<Secp256k1>::group_order() && &BigInt::zero() < signature && signature < Scalar::<Secp256k1>::group_order()) {
        return false;
    }

    let rx_as_scalar = Scalar::<Secp256k1>::from_bigint(x_coord);
    let s_as_scalar = Scalar::<Secp256k1>::from_bigint(signature);

    let inverse_s = s_as_scalar.invert().unwrap();

    let first = hash_as_scalar(msg, &[]) * &inverse_s;
    let second = &rx_as_scalar * inverse_s;

    let point_to_check = first * Point::<Secp256k1>::generator() + second * pk;
    let x_check = point_to_check.x_coord();

    match x_check {
        None => { false },
        Some(x) => {
            let x_check_as_scalar = Scalar::<Secp256k1>::from_bigint(&x);
            x_check_as_scalar == rx_as_scalar
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::*;
    use crate::protocols::dkg::*;
    use crate::protocols::re_key::re_key;
    use rand::Rng;

    #[test]
    fn test_signing() {

        // Disclaimer: this implementation is not the most efficient,
        // we are only testing if everything works! Note as well that
        // parties are being simulated one after the other, but they
        // should actually execute the protocol simultaneously.

        let threshold = rand::thread_rng().gen_range(2..=5); // You can change the ranges here.
        let offset = rand::thread_rng().gen_range(0..=5);

        let parameters = Parameters { threshold, share_count: threshold + offset }; // You can fix the parameters if you prefer.

        // We use the re_key function to quickly sample the parties.
        let session_id = rand::thread_rng().gen::<[u8; 32]>();
        let secret_key = Scalar::<Secp256k1>::random();
        let parties = re_key(&parameters, &session_id, &secret_key, None);

        // SIGNING

        let sign_id = rand::thread_rng().gen::<[u8; 32]>();
        let message_to_sign = "Message to sign!".as_bytes();

        // For simplicity, we are testing only the first parties.
        let executing_parties: Vec<usize> = Vec::from_iter(1..=parameters.threshold);

        // Each party prepares their data for this signing session.
        let mut all_data: HashMap<usize, SignData> = HashMap::with_capacity(parameters.threshold);
        for party_index in executing_parties.clone() {
            //Gather the counterparties
            let mut counterparties = executing_parties.clone();
            counterparties.retain(|index| *index != party_index);

            all_data.insert(party_index, SignData {
                sign_id: sign_id.to_vec(),
                counterparties,
                message_to_sign: message_to_sign.to_vec(),
            });
        }

        // Phase 1
        let mut unique_kept_1to2: HashMap<usize,UniqueKeep1to2> = HashMap::with_capacity(parameters.threshold);
        let mut kept_1to2: HashMap<usize,HashMap<usize,KeepPhase1to2>> = HashMap::with_capacity(parameters.threshold);
        let mut transmit_1to2: HashMap<usize,Vec<TransmitPhase1to2>> = HashMap::with_capacity(parameters.threshold); 
        for party_index in executing_parties.clone() {
            let (unique_keep, keep, transmit) = parties[party_index - 1].sign_phase1(all_data.get(&party_index).unwrap());
        
            unique_kept_1to2.insert(party_index, unique_keep);
            kept_1to2.insert(party_index, keep);
            transmit_1to2.insert(party_index, transmit);
        }

        // Communication round 1
        let mut received_1to2: HashMap<usize,Vec<TransmitPhase1to2>> = HashMap::with_capacity(parameters.threshold);
        for party_index in executing_parties.clone() {

            let mut new_row: Vec<TransmitPhase1to2> = Vec::with_capacity(parameters.threshold - 1);
            for (_, messages) in &transmit_1to2 {
                for message in messages {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == party_index {
                        new_row.push(message.clone());
                    }
                }
            }
            received_1to2.insert(party_index, new_row);

        }

        // Phase 2
        let mut unique_kept_2to3: HashMap<usize,UniqueKeep2to3> = HashMap::with_capacity(parameters.threshold);
        let mut kept_2to3: HashMap<usize,HashMap<usize,KeepPhase2to3>> = HashMap::with_capacity(parameters.threshold);
        let mut transmit_2to3: HashMap<usize,Vec<TransmitPhase2to3>> = HashMap::with_capacity(parameters.threshold);
        for party_index in executing_parties.clone() {
            let result = parties[party_index - 1].sign_phase2(all_data.get(&party_index).unwrap(), unique_kept_1to2.get(&party_index).unwrap(), kept_1to2.get(&party_index).unwrap(), received_1to2.get(&party_index).unwrap());
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                },
                Ok((unique_keep, keep, transmit)) => {
                    unique_kept_2to3.insert(party_index, unique_keep);
                    kept_2to3.insert(party_index, keep);
                    transmit_2to3.insert(party_index, transmit);
                },
            }
        }

        // Communication round 2
        let mut received_2to3: HashMap<usize,Vec<TransmitPhase2to3>> = HashMap::with_capacity(parameters.threshold);
        for party_index in executing_parties.clone() {

            let mut new_row: Vec<TransmitPhase2to3> = Vec::with_capacity(parameters.threshold - 1);
            for (_, messages) in &transmit_2to3 {
                for message in messages {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == party_index {
                        new_row.push(message.clone());
                    }
                }
            }
            received_2to3.insert(party_index, new_row);

        }

        // Phase 3
        let mut x_coords: Vec<BigInt> = Vec::with_capacity(parameters.threshold);
        let mut broadcast_3to4: Vec<Broadcast3to4> = Vec::with_capacity(parameters.threshold);
        for party_index in executing_parties.clone() {
            let result = parties[party_index - 1].sign_phase3(all_data.get(&party_index).unwrap(), unique_kept_2to3.get(&party_index).unwrap(), kept_2to3.get(&party_index).unwrap(), received_2to3.get(&party_index).unwrap());
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                },
                Ok((x_coord, broadcast)) => {
                    x_coords.push(x_coord);
                    broadcast_3to4.push(broadcast);
                },
            }
        }

        // We verify all parties got the same x coordinate.
        let x_coord = x_coords[0].clone(); // We take the first one as reference.
        for i in 1..parameters.threshold {
            assert_eq!(x_coord, x_coords[i]);
        }

        // Communication round 3
        // This is a broadcast to all parties. The desired result is already broadcast_3to4.

        // Phase 4
        // It is essentially independent of the party, so we compute just once.
        let some_index = executing_parties[0];
        let result = parties[some_index - 1].sign_phase4(all_data.get(&some_index).unwrap(), &x_coord, &broadcast_3to4);
        if let Err(abort) = result {
            panic!("Party {} aborted: {:?}", abort.index, abort.description);
        }
        // We could call verify_ecdsa_signature here, but it is already called during Phase 4.
    }

    #[test]
    // This function compares the signature generated during
    // the protocol with the usual signature someone would
    // compute for ECDSA.
    fn test_signing_against_ecdsa() {

        let threshold = rand::thread_rng().gen_range(2..=5); // You can change the ranges here.
        let offset = rand::thread_rng().gen_range(0..=5);

        let parameters = Parameters { threshold, share_count: threshold + offset }; // You can fix the parameters if you prefer.

        // We use the re_key function to quickly sample the parties.
        let session_id = rand::thread_rng().gen::<[u8; 32]>();
        let secret_key = Scalar::<Secp256k1>::random();
        let parties = re_key(&parameters, &session_id, &secret_key, None);

        // SIGNING (as in test_signing)

        let sign_id = rand::thread_rng().gen::<[u8; 32]>();
        let message_to_sign = "Message to sign!".as_bytes();

        // For simplicity, we are testing only the first parties.
        let executing_parties: Vec<usize> = Vec::from_iter(1..=parameters.threshold);

        // Each party prepares their data for this signing session.
        let mut all_data: HashMap<usize, SignData> = HashMap::with_capacity(parameters.threshold);
        for party_index in executing_parties.clone() {
            //Gather the counterparties
            let mut counterparties = executing_parties.clone();
            counterparties.retain(|index| *index != party_index);

            all_data.insert(party_index, SignData {
                sign_id: sign_id.to_vec(),
                counterparties,
                message_to_sign: message_to_sign.to_vec(),
            });
        }

        // Phase 1
        let mut unique_kept_1to2: HashMap<usize,UniqueKeep1to2> = HashMap::with_capacity(parameters.threshold);
        let mut kept_1to2: HashMap<usize,HashMap<usize,KeepPhase1to2>> = HashMap::with_capacity(parameters.threshold);
        let mut transmit_1to2: HashMap<usize,Vec<TransmitPhase1to2>> = HashMap::with_capacity(parameters.threshold); 
        for party_index in executing_parties.clone() {
            let (unique_keep, keep, transmit) = parties[party_index - 1].sign_phase1(all_data.get(&party_index).unwrap());
        
            unique_kept_1to2.insert(party_index, unique_keep);
            kept_1to2.insert(party_index, keep);
            transmit_1to2.insert(party_index, transmit);
        }

        // Communication round 1
        let mut received_1to2: HashMap<usize,Vec<TransmitPhase1to2>> = HashMap::with_capacity(parameters.threshold);
        for party_index in executing_parties.clone() {

            let mut new_row: Vec<TransmitPhase1to2> = Vec::with_capacity(parameters.threshold - 1);
            for (_, messages) in &transmit_1to2 {
                for message in messages {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == party_index {
                        new_row.push(message.clone());
                    }
                }
            }
            received_1to2.insert(party_index, new_row);

        }

        // Phase 2
        let mut unique_kept_2to3: HashMap<usize,UniqueKeep2to3> = HashMap::with_capacity(parameters.threshold);
        let mut kept_2to3: HashMap<usize,HashMap<usize,KeepPhase2to3>> = HashMap::with_capacity(parameters.threshold);
        let mut transmit_2to3: HashMap<usize,Vec<TransmitPhase2to3>> = HashMap::with_capacity(parameters.threshold);
        for party_index in executing_parties.clone() {
            let result = parties[party_index - 1].sign_phase2(all_data.get(&party_index).unwrap(), unique_kept_1to2.get(&party_index).unwrap(), kept_1to2.get(&party_index).unwrap(), received_1to2.get(&party_index).unwrap());
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                },
                Ok((unique_keep, keep, transmit)) => {
                    unique_kept_2to3.insert(party_index, unique_keep);
                    kept_2to3.insert(party_index, keep);
                    transmit_2to3.insert(party_index, transmit);
                },
            }
        }

        // Communication round 2
        let mut received_2to3: HashMap<usize,Vec<TransmitPhase2to3>> = HashMap::with_capacity(parameters.threshold);
        for party_index in executing_parties.clone() {

            let mut new_row: Vec<TransmitPhase2to3> = Vec::with_capacity(parameters.threshold - 1);
            for (_, messages) in &transmit_2to3 {
                for message in messages {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == party_index {
                        new_row.push(message.clone());
                    }
                }
            }
            received_2to3.insert(party_index, new_row);

        }

        // Phase 3
        let mut x_coords: Vec<BigInt> = Vec::with_capacity(parameters.threshold);
        let mut broadcast_3to4: Vec<Broadcast3to4> = Vec::with_capacity(parameters.threshold);
        for party_index in executing_parties.clone() {
            let result = parties[party_index - 1].sign_phase3(all_data.get(&party_index).unwrap(), unique_kept_2to3.get(&party_index).unwrap(), kept_2to3.get(&party_index).unwrap(), received_2to3.get(&party_index).unwrap());
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                },
                Ok((x_coord, broadcast)) => {
                    x_coords.push(x_coord);
                    broadcast_3to4.push(broadcast);
                },
            }
        }

        // We verify all parties got the same x coordinate.
        let x_coord = x_coords[0].clone(); // We take the first one as reference.
        for i in 1..parameters.threshold {
            assert_eq!(x_coord, x_coords[i]);
        }

        // Communication round 3
        // This is a broadcast to all parties. The desired result is already broadcast_3to4.

        // Phase 4
        // It is essentially independent of the party, so we compute just once.
        let some_index = executing_parties[0];
        let result = parties[some_index - 1].sign_phase4(all_data.get(&some_index).unwrap(), &x_coord, &broadcast_3to4);
        let signature: BigInt;
        match result {
            Err(abort) => {
                panic!("Party {} aborted: {:?}", abort.index, abort.description);
            },
            Ok(s) => {
                signature = s;
            },
        }
        // We could call verify_ecdsa_signature here, but it is already called during Phase 4.

        // ECDSA (computations that would be done if there were only one person)

        // Let us retrieve the total instance/ephemeral key.
        let mut total_instance_key = Scalar::<Secp256k1>::zero();
        for (_,kept) in unique_kept_1to2 {
            total_instance_key = total_instance_key + kept.instance_key;
        }

        // We compare the total "instance point" with the parties' calculations.
        let total_instance_point = Point::<Secp256k1>::generator() * &total_instance_key;
        let expected_x_coord = total_instance_point.x_coord().unwrap().modulus(Scalar::<Secp256k1>::group_order());
        assert_eq!(x_coord, expected_x_coord);

        // The hash of the message:
        let hashed_message = hash_as_scalar(message_to_sign, &[]);
        assert_eq!(hashed_message, Scalar::<Secp256k1>::from_bigint(&BigInt::from_hex("ece3e5d77980859352a5e702cb429f3d4dbdc12443e359ae60d15fe3c0333c0d").unwrap()));

        // Now we can find the signature in the usual way.
        let expected_signature_as_scalar = total_instance_key.invert().unwrap() * (hashed_message + (secret_key * Scalar::<Secp256k1>::from_bigint(&expected_x_coord)));
        let expected_signature = expected_signature_as_scalar.to_bigint();

        // We compare the results.
        assert_eq!(signature, expected_signature);

    }

    #[test]
    // This function tests DKG and signing. The main purpose is to
    // verify wheter the initialization protocols from DKG are working.
    //
    // It is a combination of test_dkg_initialization and test_signing.
    fn test_dkg_and_signing() {

        // DKG (as in test_dkg_initialization)

        let threshold = rand::thread_rng().gen_range(2..=5); // You can change the ranges here.
        let offset = rand::thread_rng().gen_range(0..=5);

        let parameters = Parameters { threshold, share_count: threshold + offset }; // You can fix the parameters if you prefer.
        let session_id = rand::thread_rng().gen::<[u8; 32]>();

        // Each party prepares their data for this DKG.
        let mut all_data: Vec<SessionData> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {
            all_data.push(SessionData {
                parameters: parameters.clone(),
                party_index: i+1,
                session_id: session_id.to_vec(),
            });
        }

        // Phase 1
        let mut dkg_1: Vec<Vec<Scalar<Secp256k1>>> = Vec::with_capacity(parameters.share_count);
        let mut zero_kept_1to2: Vec<HashMap<usize,KeepInitZeroSharePhase1to2>> = Vec::with_capacity(parameters.share_count);
        let mut zero_transmit_1to3: Vec<Vec<TransmitInitZeroSharePhase1to3>> = Vec::with_capacity(parameters.share_count);
        let mut mul_kept_1to3: Vec<HashMap<usize,KeepInitMulPhase1to3>> = Vec::with_capacity(parameters.share_count);
        let mut mul_transmit_1to2: Vec<Vec<TransmitInitMulPhase1to2>> = Vec::with_capacity(parameters.share_count);
        let mut bip_kept_1to2: Vec<KeepDerivationPhase1to2> = Vec::with_capacity(parameters.share_count);
        let mut bip_transmit_1to3: Vec<TransmitDerivationPhase1to3> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {
            let (out1, out2, out3, out4, out5, out6, out7) = dkg_phase1(&all_data[i]);

            dkg_1.push(out1);
            zero_kept_1to2.push(out2);
            zero_transmit_1to3.push(out3);
            mul_kept_1to3.push(out4);
            mul_transmit_1to2.push(out5);
            bip_kept_1to2.push(out6);
            bip_transmit_1to3.push(out7);
        }

        // Communication round 1
        let mut poly_fragments = vec![Vec::<Scalar<Secp256k1>>::with_capacity(parameters.share_count); parameters.share_count];
        for row_i in dkg_1 {
            for j in 0..parameters.share_count {
                poly_fragments[j].push(row_i[j].clone());
            }
        }

        let mut zero_received_1to3: Vec<Vec<TransmitInitZeroSharePhase1to3>> = Vec::with_capacity(parameters.share_count);
        let mut mul_received_1to2: Vec<Vec<TransmitInitMulPhase1to2>> = Vec::with_capacity(parameters.share_count);
        for i in 1..=parameters.share_count {

            let mut new_row: Vec<TransmitInitZeroSharePhase1to3> = Vec::with_capacity(parameters.share_count - 1);
            for party in &zero_transmit_1to3 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i {
                        new_row.push(message.clone());
                    }
                }
            }
            zero_received_1to3.push(new_row);

            let mut new_row: Vec<TransmitInitMulPhase1to2> = Vec::with_capacity(parameters.share_count - 1);
            for party in &mul_transmit_1to2 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i {
                        new_row.push(message.clone());
                    }
                }
            }
            mul_received_1to2.push(new_row);

        }

        // bip_transmit_1to3 is already in the format we need.

        // Phase 2
        let mut poly_points: Vec<Scalar<Secp256k1>> = Vec::with_capacity(parameters.share_count);
        let mut proofs_commitments: Vec<ProofCommitment> = Vec::with_capacity(parameters.share_count);
        let mut zero_kept_2to3: Vec<HashMap<usize,KeepInitZeroSharePhase2to3>> = Vec::with_capacity(parameters.share_count);
        let mut zero_transmit_2to3: Vec<Vec<TransmitInitZeroSharePhase2to3>> = Vec::with_capacity(parameters.share_count);
        let mut mul_kept_2to4: Vec<HashMap<usize,KeepInitMulPhase2to4>> = Vec::with_capacity(parameters.share_count);
        let mut mul_transmit_2to3: Vec<Vec<TransmitInitMulPhase2to3>> = Vec::with_capacity(parameters.share_count);
        let mut bip_transmit_2to3: Vec<TransmitDerivationPhase2to3> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {

            let result = dkg_phase2(&all_data[i], &poly_fragments[i], &zero_kept_1to2[i], &mul_received_1to2[i], &bip_kept_1to2[i]);
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                },
                Ok((out1, out2, out3, out4, out5, out6, out7)) => {
                    poly_points.push(out1);
                    proofs_commitments.push(out2);
                    zero_kept_2to3.push(out3);
                    zero_transmit_2to3.push(out4);
                    mul_kept_2to4.push(out5);
                    mul_transmit_2to3.push(out6);
                    bip_transmit_2to3.push(out7);
                },
            }
        }

        // Communication round 2
        let mut zero_received_2to3: Vec<Vec<TransmitInitZeroSharePhase2to3>> = Vec::with_capacity(parameters.share_count);
        let mut mul_received_2to3: Vec<Vec<TransmitInitMulPhase2to3>> = Vec::with_capacity(parameters.share_count);
        for i in 1..=parameters.share_count {

            // We don't need to transmit the commitments because proofs_commitments is already what we need.
            // In practice, this should be done here.

            let mut new_row: Vec<TransmitInitZeroSharePhase2to3> = Vec::with_capacity(parameters.share_count - 1);
            for party in &zero_transmit_2to3 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i {
                        new_row.push(message.clone());
                    }
                }
            }
            zero_received_2to3.push(new_row);

            let mut new_row: Vec<TransmitInitMulPhase2to3> = Vec::with_capacity(parameters.share_count - 1);
            for party in &mul_transmit_2to3 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i {
                        new_row.push(message.clone());
                    }
                }
            }
            mul_received_2to3.push(new_row);

        }

        // bip_transmit_2to3 is already in the format we need.

        // Phase 3
        let mut complete_kept_3to6: Vec<KeepCompletePhase3to6> = Vec::with_capacity(parameters.share_count);
        let mut mul_kept_3to5: Vec<HashMap<usize,KeepInitMulPhase3to5>> = Vec::with_capacity(parameters.share_count);
        let mut mul_transmit_3to4: Vec<Vec<TransmitInitMulPhase3to4>> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {

            let result = dkg_phase3(&all_data[i], &zero_kept_2to3[i], &zero_received_1to3[i], &zero_received_2to3[i], &mul_kept_1to3[i], &mul_received_2to3[i], &bip_transmit_1to3, &bip_transmit_2to3);
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                },
                Ok((out1, out2, out3)) => {
                    complete_kept_3to6.push(out1);
                    mul_kept_3to5.push(out2);
                    mul_transmit_3to4.push(out3);
                },
            }
        }

        // Communication round 3
        let mut mul_received_3to4: Vec<Vec<TransmitInitMulPhase3to4>> = Vec::with_capacity(parameters.share_count);
        for i in 1..=parameters.share_count {

           // We don't need to transmit the proofs because proofs_commitments is already what we need.
           // In practice, this should be done here.

            let mut new_row: Vec<TransmitInitMulPhase3to4> = Vec::with_capacity(parameters.share_count - 1);
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

        // Phase 4
        let mut public_keys: Vec<Point<Secp256k1>> = Vec::with_capacity(parameters.share_count);
        let mut mul_kept_4to6: Vec<HashMap<usize,KeepInitMulPhase4to6>> = Vec::with_capacity(parameters.share_count);
        let mut mul_transmit_4to5: Vec<Vec<TransmitInitMulPhase4to5>> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {

            let result = dkg_phase4(&all_data[i], &proofs_commitments, &mul_kept_2to4[i], &mul_received_3to4[i]);
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                },
                Ok((out1, out2, out3)) => {
                    public_keys.push(out1);
                    mul_kept_4to6.push(out2);
                    mul_transmit_4to5.push(out3);
                },
            }
        }

        // Communication round 4
        let mut mul_received_4to5: Vec<Vec<TransmitInitMulPhase4to5>> = Vec::with_capacity(parameters.share_count);
        for i in 1..=parameters.share_count {

            let mut new_row: Vec<TransmitInitMulPhase4to5> = Vec::with_capacity(parameters.share_count - 1);
            for party in &mul_transmit_4to5 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i {
                        new_row.push(message.clone());
                    }
                }
            }
            mul_received_4to5.push(new_row);

        }

        // Phase 5
        let mut mul_kept_5to6: Vec<HashMap<usize,KeepInitMulPhase5to6>> = Vec::with_capacity(parameters.share_count);
        let mut mul_transmit_5to6: Vec<Vec<TransmitInitMulPhase5to6>> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {

            let result = dkg_phase5(&all_data[i], &mul_kept_3to5[i], &mul_received_4to5[i]);
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                },
                Ok((out1, out2)) => {
                    mul_kept_5to6.push(out1);
                    mul_transmit_5to6.push(out2);
                },
            }
        }

        // Communication round 5
        let mut mul_received_5to6: Vec<Vec<TransmitInitMulPhase5to6>> = Vec::with_capacity(parameters.share_count);
        for i in 1..=parameters.share_count {

            let mut new_row: Vec<TransmitInitMulPhase5to6> = Vec::with_capacity(parameters.share_count - 1);
            for party in &mul_transmit_5to6 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i {
                        new_row.push(message.clone());
                    }
                }
            }
            mul_received_5to6.push(new_row);

        }

        // Phase 6
        let mut parties: Vec<Party> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {

            let result = dkg_phase6(&all_data[i], &poly_points[i], &public_keys[i], &complete_kept_3to6[i], &mul_kept_4to6[i], &mul_kept_5to6[i], &mul_received_5to6[i]);
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                },
                Ok(party) => {
                    parties.push(party);
                },
            }
        }

        // We check if the public keys and chain codes are the same.
        let expected_pk = parties[0].pk.clone();
        let expected_chain_code = parties[0].derivation_data.chain_code;
        for party in &parties {
            assert_eq!(expected_pk, party.pk);
            assert_eq!(expected_chain_code, party.derivation_data.chain_code);
        }

        // SIGNING (as in test_signing)

        let sign_id = rand::thread_rng().gen::<[u8; 32]>();
        let message_to_sign = "Message to sign!".as_bytes();

        // For simplicity, we are testing only the first parties.
        let executing_parties: Vec<usize> = Vec::from_iter(1..=parameters.threshold);

        // Each party prepares their data for this signing session.
        let mut all_data: HashMap<usize, SignData> = HashMap::with_capacity(parameters.threshold);
        for party_index in executing_parties.clone() {
            //Gather the counterparties
            let mut counterparties = executing_parties.clone();
            counterparties.retain(|index| *index != party_index);

            all_data.insert(party_index, SignData {
                sign_id: sign_id.to_vec(),
                counterparties,
                message_to_sign: message_to_sign.to_vec(),
            });
        }

        // Phase 1
        let mut unique_kept_1to2: HashMap<usize,UniqueKeep1to2> = HashMap::with_capacity(parameters.threshold);
        let mut kept_1to2: HashMap<usize,HashMap<usize,KeepPhase1to2>> = HashMap::with_capacity(parameters.threshold);
        let mut transmit_1to2: HashMap<usize,Vec<TransmitPhase1to2>> = HashMap::with_capacity(parameters.threshold); 
        for party_index in executing_parties.clone() {
            let (unique_keep, keep, transmit) = parties[party_index - 1].sign_phase1(all_data.get(&party_index).unwrap());
        
            unique_kept_1to2.insert(party_index, unique_keep);
            kept_1to2.insert(party_index, keep);
            transmit_1to2.insert(party_index, transmit);
        }

        // Communication round 1
        let mut received_1to2: HashMap<usize,Vec<TransmitPhase1to2>> = HashMap::with_capacity(parameters.threshold);
        for party_index in executing_parties.clone() {

            let mut new_row: Vec<TransmitPhase1to2> = Vec::with_capacity(parameters.threshold - 1);
            for (_, messages) in &transmit_1to2 {
                for message in messages {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == party_index {
                        new_row.push(message.clone());
                    }
                }
            }
            received_1to2.insert(party_index, new_row);

        }

        // Phase 2
        let mut unique_kept_2to3: HashMap<usize,UniqueKeep2to3> = HashMap::with_capacity(parameters.threshold);
        let mut kept_2to3: HashMap<usize,HashMap<usize,KeepPhase2to3>> = HashMap::with_capacity(parameters.threshold);
        let mut transmit_2to3: HashMap<usize,Vec<TransmitPhase2to3>> = HashMap::with_capacity(parameters.threshold);
        for party_index in executing_parties.clone() {
            let result = parties[party_index - 1].sign_phase2(all_data.get(&party_index).unwrap(), unique_kept_1to2.get(&party_index).unwrap(), kept_1to2.get(&party_index).unwrap(), received_1to2.get(&party_index).unwrap());
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                },
                Ok((unique_keep, keep, transmit)) => {
                    unique_kept_2to3.insert(party_index, unique_keep);
                    kept_2to3.insert(party_index, keep);
                    transmit_2to3.insert(party_index, transmit);
                },
            }
        }

        // Communication round 2
        let mut received_2to3: HashMap<usize,Vec<TransmitPhase2to3>> = HashMap::with_capacity(parameters.threshold);
        for party_index in executing_parties.clone() {

            let mut new_row: Vec<TransmitPhase2to3> = Vec::with_capacity(parameters.threshold - 1);
            for (_, messages) in &transmit_2to3 {
                for message in messages {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == party_index {
                        new_row.push(message.clone());
                    }
                }
            }
            received_2to3.insert(party_index, new_row);

        }

        // Phase 3
        let mut x_coords: Vec<BigInt> = Vec::with_capacity(parameters.threshold);
        let mut broadcast_3to4: Vec<Broadcast3to4> = Vec::with_capacity(parameters.threshold);
        for party_index in executing_parties.clone() {
            let result = parties[party_index - 1].sign_phase3(all_data.get(&party_index).unwrap(), unique_kept_2to3.get(&party_index).unwrap(), kept_2to3.get(&party_index).unwrap(), received_2to3.get(&party_index).unwrap());
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                },
                Ok((x_coord, broadcast)) => {
                    x_coords.push(x_coord);
                    broadcast_3to4.push(broadcast);
                },
            }
        }

        // We verify all parties got the same x coordinate.
        let x_coord = x_coords[0].clone(); // We take the first one as reference.
        for i in 1..parameters.threshold {
            assert_eq!(x_coord, x_coords[i]);
        }

        // Communication round 3
        // This is a broadcast to all parties. The desired result is already broadcast_3to4.

        // Phase 4
        // It is essentially independent of the party, so we compute just once.
        let some_index = executing_parties[0];
        let result = parties[some_index - 1].sign_phase4(all_data.get(&some_index).unwrap(), &x_coord, &broadcast_3to4);
        if let Err(abort) = result {
            panic!("Party {} aborted: {:?}", abort.index, abort.description);
        }
        // We could call verify_ecdsa_signature here, but it is already called during Phase 4.
    }
}