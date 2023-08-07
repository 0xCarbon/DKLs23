/// For the future: ver se nos protocolos, é possível entrar ids diferentes
/// para inicializar e para executar. Nesse caso, é preferível implementar isso.

use std::collections::HashMap;

use curv::elliptic::curves::{Scalar,Point,Secp256k1};
use curv::arithmetic::*;

use crate::protocols::{Party, Abort, PartiesMessage};

use crate::utilities::commits::*;
use crate::utilities::hashes::*;
use crate::utilities::multiplication::*;
use crate::utilities::ot::ot_extension::*;

//////////////////////////

pub struct KeepPhase1to2 {
    salt: Vec<u8>,
    chi: Scalar<Secp256k1>,
    mul_keep: MulDataToKeepReceiver,
}

pub struct KeepPhase2to3 {
    c_u: Scalar<Secp256k1>,
    c_v: Scalar<Secp256k1>,
    commitment: HashOutput,
    mul_keep: MulDataToKeepReceiver,
    chi: Scalar<Secp256k1>,
}

//

pub struct UniqueKeep1to2 {
    instance_key: Scalar<Secp256k1>,
    instance_point: Point<Secp256k1>,
    inversion_mask: Scalar<Secp256k1>,
    zeta: Scalar<Secp256k1>,
}

pub struct UniqueKeep2to3 {
    instance_key: Scalar<Secp256k1>,
    instance_point: Point<Secp256k1>,
    inversion_mask: Scalar<Secp256k1>,
    key_share: Scalar<Secp256k1>,
    public_share: Point<Secp256k1>,
}

//

pub struct TransmitPhase1to2 {
    parties: PartiesMessage,
    commitment: HashOutput,
    mul_transmit: OTEDataToSender,
}

pub struct TransmitPhase2to3 {
    parties: PartiesMessage,
    gamma_u: Point<Secp256k1>,
    gamma_v: Point<Secp256k1>,
    psi: Scalar<Secp256k1>,
    public_share: Point<Secp256k1>,
    instance_point: Point<Secp256k1>,
    salt: Vec<u8>,
    mul_transmit: MulDataToReceiver,
}

//

pub struct Broadcast3to4 {
    u: Scalar<Secp256k1>,
    w: Scalar<Secp256k1>,
}

//////////////////////////

impl Party {

    pub fn sign_phase1(&self, sign_id: &[u8], counterparties: &Vec<usize>) -> (UniqueKeep1to2, HashMap<usize,KeepPhase1to2>, Vec<TransmitPhase1to2>) {

        // Step 4 - We check if we have the correct number of counter parties.
        if counterparties.len() != self.parameters.threshold - 1 {
            panic!("The number of signing parties is not right!");
        }

        // Step 5 - We sample our secret data.
        let instance_key = Scalar::<Secp256k1>::random();
        let inversion_mask = Scalar::<Secp256k1>::random();

        let instance_point = Point::<Secp256k1>::generator() * &instance_key;

        // Step 6 - We prepare the messages to keep and to send.

        let mut keep: HashMap<usize,KeepPhase1to2> = HashMap::with_capacity(self.parameters.threshold - 1);
        let mut transmit: Vec<TransmitPhase1to2> = Vec::with_capacity(self.parameters.threshold - 1);
        for counterparty in counterparties {

            // Commit functionality.
            let (commitment, salt) = commit_point(&instance_point);

            // Two-party multiplication functionality.
            // We start as the receiver.

            // First, let us compute a session id for it.
            // As in Protocol 3.6 of DKLs23, we include the indexes from the parties.
            // We also use both the sign id and the DKG id.
            let mul_sid = [self.party_index.to_be_bytes().to_vec(), counterparty.to_be_bytes().to_vec(), self.session_id.clone(), sign_id.to_vec()].concat();

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
        // Now, different to DKLs23, we won't put the indexes from the parties.
        // It's simpler and almost equivalent to take just the following:
        let zero_sid = [self.session_id.clone(), sign_id.to_vec()].concat();

        let zeta = self.zero_share.compute(counterparties, &zero_sid);

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

    pub fn sign_phase2(&self, sign_id: &[u8], counterparties: &Vec<usize>, unique_kept: &UniqueKeep1to2, kept: &HashMap<usize,KeepPhase1to2>, received: &Vec<TransmitPhase1to2>) -> Result<(UniqueKeep2to3, HashMap<usize,KeepPhase2to3>, Vec<TransmitPhase2to3>),Abort> {

        // Step 7

        // We first compute the values that only depend on us.
        
        // We find the Lagrange coefficient associated to us.
        // It is the same as the one calculated during DKG.
        let mut l_numerator = Scalar::<Secp256k1>::from(1);
        let mut l_denominator = Scalar::<Secp256k1>::from(1);
        for counterparty in counterparties {
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
            let mul_sid = [counterparty.to_be_bytes().to_vec(), self.party_index.to_be_bytes().to_vec(), self.session_id.clone(), sign_id.to_vec()].concat();

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

    pub fn sign_phase3(&self, sign_id: &[u8], message_to_sign: &[u8], unique_kept: &UniqueKeep2to3, kept: &HashMap<usize,KeepPhase2to3>, received: &Vec<TransmitPhase2to3>) -> Result<(BigInt,Broadcast3to4),Abort> {

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
            let mul_sid = [self.party_index.to_be_bytes().to_vec(), counterparty.to_be_bytes().to_vec(), self.session_id.clone(), sign_id.to_vec()].concat();

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
            return Err(Abort::new(self.party_index, &format!("Consistency check for public key reconstruction failed!")));
        }

        // We compute u_i, v_i and w_i from the paper.
        let u = (&unique_kept.instance_key * &first_sum_u_v) + second_sum_u;
        let v = (&unique_kept.key_share * &first_sum_u_v) + second_sum_v;

        let x_coord = total_instance_point.x_coord().unwrap();
        // There is no salt here because the hash function here is always the same.
        let w = (hash_as_scalar(message_to_sign, &[]) * &unique_kept.inversion_mask) + (v * Scalar::<Secp256k1>::from_bigint(&x_coord));

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

    pub fn sign_phase4 (&self, message_to_sign: &[u8], x_coord: &BigInt, received: &Vec<Broadcast3to4>) -> Result<BigInt,Abort> {

        // Step 10

        let mut numerator = Scalar::<Secp256k1>::zero();
        let mut denominator = Scalar::<Secp256k1>::zero();
        for message in received {
            numerator = numerator + &message.w;
            denominator = denominator + &message.u;
        }

        let signature_as_scalar = numerator * (denominator.invert().unwrap());
        let signature = signature_as_scalar.to_bigint();

        let verification = verify_ecdsa_signature(message_to_sign, &self.pk, x_coord, &signature);
        if !verification {
            return Err(Abort::new(self.party_index, &format!("Invalid ECDSA signature at the end of the protocol!")));
        }

        Ok(signature)
    }
}

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