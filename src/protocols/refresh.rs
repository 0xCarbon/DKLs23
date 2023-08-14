/// This file implements a refresh protocol: periodically, all parties
/// engage in a protocol to rerandomize their secret values (while, of
/// course, still maintining the same public key).
/// 
/// The most direct way of doing this is simply executing DKG and restricting
/// the possible random values so that we don't change our address. We
/// implement this procedure under the name of "complete refresh".
/// 
/// DKG also initializes the multiplication protocol, but we may take
/// advantage of the fact the we have already initialized this protocol
/// before. If we use this data for refresh, we don't need to execute
/// the OT protocols and we may save some time and some rounds. This
/// approach is implemented in another refresh protocol.

use std::collections::HashMap;

use curv::elliptic::curves::{Secp256k1, Scalar};
use curv::cryptographic_primitives::secret_sharing::Polynomial;

use crate::protocols::{Party, Abort};
use crate::protocols::dkg::*;

impl Party {

    // COMPLETE REFRESH

    // In this case, we recompute all data from the parties. Hence, we essentially
    // rerun DKG but we force the final public key to be the original one.

    // To adapt the DKG protocol, we change Step 1: instead of sampling any random
    // polynomial, each party generates a polynomial whose constant term is zero.
    // In this way, the key generation provides each party with point on a polyinomial
    // whose constant term (the "secret key") is zero. This new point is just a correction
    // factor and must be added to the original poly_point variable. This refreshs each
    // key share while preserving the same public key.

    // Each party cannot trust that their adversaries really chose a polyinomial
    // with zero constant term. Therefore, we must add a new consistency check in
    // Phase 4: after recovering the auxiliary public key, each party must check that
    // it is equal to the zero point on the curve. This ensures that the correction
    // factors will not change the public key.

    pub fn refresh_complete_phase1(&self, refresh_sid: &[u8]) -> (Vec<Scalar<Secp256k1>>, HashMap<usize,KeepInitZeroSharePhase1to2>, Vec<TransmitInitZeroSharePhase1to3>, HashMap<usize,KeepInitMulPhase1to3>, Vec<TransmitInitMulPhase1to2>) {

        // We run Phase 1 in DKG, but we force the constant term in Step 1 to be zero.
        let secret_polynomial = Polynomial::<Secp256k1>::sample_exact_with_fixed_const_term((self.parameters.threshold - 1) as u16, Scalar::<Secp256k1>::zero());
        let evaluations = dkg_step2(&self.parameters, secret_polynomial);

        let (_, zero_keep, zero_transmit, mul_keep, mul_transmit) = dkg_phase1(&self.parameters, self.party_index, refresh_sid);

        (evaluations, zero_keep, zero_transmit, mul_keep, mul_transmit)
    }

    pub fn refresh_complete_phase2(&self, refresh_sid: &[u8], poly_fragments: &Vec<Scalar<Secp256k1>>, zero_kept: &HashMap<usize,KeepInitZeroSharePhase1to2>, mul_received: &Vec<TransmitInitMulPhase1to2>) -> Result<(Scalar<Secp256k1>, ProofCommitment, HashMap<usize,KeepInitZeroSharePhase2to3>, Vec<TransmitInitZeroSharePhase2to3>, HashMap<usize,KeepInitMulPhase2to4>, Vec<TransmitInitMulPhase2to3>),Abort> {
        dkg_phase2(&self.parameters, self.party_index, refresh_sid, poly_fragments, zero_kept, mul_received)
    }

    pub fn refresh_complete_phase3(&self, refresh_sid: &[u8], zero_kept: &HashMap<usize,KeepInitZeroSharePhase2to3>, zero_received_phase1: &Vec<TransmitInitZeroSharePhase1to3>, zero_received_phase2: &Vec<TransmitInitZeroSharePhase2to3>, mul_kept: &HashMap<usize,KeepInitMulPhase1to3>, mul_received: &Vec<TransmitInitMulPhase2to3>) -> Result<(KeepInitZeroSharePhase3to6, HashMap<usize,KeepInitMulPhase3to5>, Vec<TransmitInitMulPhase3to4>), Abort> {
        dkg_phase3(&self.parameters, refresh_sid, zero_kept, zero_received_phase1, zero_received_phase2, mul_kept, mul_received)
    }

    pub fn refresh_complete_phase4(&self, refresh_sid: &[u8], proofs_commitments: &Vec<ProofCommitment>, mul_kept: &HashMap<usize,KeepInitMulPhase2to4>, mul_received: &Vec<TransmitInitMulPhase3to4>) -> Result<(HashMap<usize,KeepInitMulPhase4to6>, Vec<TransmitInitMulPhase4to5>),Abort> {
        let (verifying_pk, mul_keep, mul_transmit) = dkg_phase4(&self.parameters, self.party_index, refresh_sid, proofs_commitments, mul_kept, mul_received)?;

        // The public key calculated above should be the zero point on the curve.
        if verifying_pk.is_zero() {
            Ok((mul_keep, mul_transmit))
        } else {
            Err(Abort::new(self.party_index, &format!("The auxiliary public key is not the zero point!")))
        }
    }

    pub fn refresh_complete_phase5(&self, mul_kept: &HashMap<usize,KeepInitMulPhase3to5>, mul_received: &Vec<TransmitInitMulPhase4to5>) -> Result<(HashMap<usize,KeepInitMulPhase5to6>, Vec<TransmitInitMulPhase5to6>),Abort> {
        dkg_phase5(&self.parameters, mul_kept, mul_received)
    }

    pub fn refresh_complete_phase6(&self, refresh_sid: &[u8], correction_value: &Scalar<Secp256k1>, zero_kept: &KeepInitZeroSharePhase3to6, mul_kept_phase4: &HashMap<usize,KeepInitMulPhase4to6>, mul_kept_phase5: &HashMap<usize,KeepInitMulPhase5to6>, mul_received: &Vec<TransmitInitMulPhase5to6>) -> Result<Party,Abort> {
        let correction_data = dkg_phase6(&self.parameters, self.party_index, refresh_sid, correction_value, &self.pk, zero_kept, mul_kept_phase4, mul_kept_phase5, mul_received)?;

        let party = Party {
            parameters: self.parameters.clone(),
            party_index: self.party_index,
            session_id: refresh_sid.to_vec(),  // We replace the old session id by the new one.
    
            poly_point: &self.poly_point + correction_value,  // We update poly_point.
            pk: self.pk.clone(),
    
            zero_share: correction_data.zero_share.clone(),
    
            mul_senders: correction_data.mul_senders.clone(),
            mul_receivers: correction_data.mul_receivers.clone(),
        };
    
        Ok(party)
    }

    // A FASTER REFRESH

    // During a complete refresh, we initialize the multiplication protocol
    // from scratch. Instead, we can use our previous data to more efficiently
    // refresh this initialization. This results in a faster refresh and,
    // depending on the multiplication protocol, fewer communication rounds.

    // FAZEEEER

}

#[cfg(test)]
mod tests {

    use super::*;

    use crate::protocols::Parameters;
    use crate::protocols::re_key::re_key;
    use crate::protocols::signing::*;

    use curv::arithmetic::*;
    use rand::Rng;

    #[test]
    // Test for complete refresh: initializations are rerun from the beginning.
    fn test_refresh_complete() {

        let threshold = rand::thread_rng().gen_range(2..=5); // You can change the ranges here.
        let offset = rand::thread_rng().gen_range(0..=5);

        let parameters = Parameters { threshold, share_count: threshold + offset }; // You can fix the parameters if you prefer.

        // We use the re_key function to quickly sample the parties.
        let session_id = rand::thread_rng().gen::<[u8; 32]>();
        let secret_key = Scalar::<Secp256k1>::random();
        let parties = re_key(&parameters, &session_id, &secret_key);

        // REFRESH (it follows test_dkg_initialization closely)

        let refresh_sid = rand::thread_rng().gen::<[u8; 32]>();

        // Phase 1
        let mut dkg_1: Vec<Vec<Scalar<Secp256k1>>> = Vec::with_capacity(parameters.share_count);
        let mut zero_kept_1to2: Vec<HashMap<usize,KeepInitZeroSharePhase1to2>> = Vec::with_capacity(parameters.share_count);
        let mut zero_transmit_1to3: Vec<Vec<TransmitInitZeroSharePhase1to3>> = Vec::with_capacity(parameters.share_count);
        let mut mul_kept_1to3: Vec<HashMap<usize,KeepInitMulPhase1to3>> = Vec::with_capacity(parameters.share_count);
        let mut mul_transmit_1to2: Vec<Vec<TransmitInitMulPhase1to2>> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {
            let (out1, out2, out3, out4, out5) = parties[i].refresh_complete_phase1(&refresh_sid);

            dkg_1.push(out1);
            zero_kept_1to2.push(out2);
            zero_transmit_1to3.push(out3);
            mul_kept_1to3.push(out4);
            mul_transmit_1to2.push(out5);
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

        // Phase 2
        let mut correction_values: Vec<Scalar<Secp256k1>> = Vec::with_capacity(parameters.share_count);
        let mut proofs_commitments: Vec<ProofCommitment> = Vec::with_capacity(parameters.share_count);
        let mut zero_kept_2to3: Vec<HashMap<usize,KeepInitZeroSharePhase2to3>> = Vec::with_capacity(parameters.share_count);
        let mut zero_transmit_2to3: Vec<Vec<TransmitInitZeroSharePhase2to3>> = Vec::with_capacity(parameters.share_count);
        let mut mul_kept_2to4: Vec<HashMap<usize,KeepInitMulPhase2to4>> = Vec::with_capacity(parameters.share_count);
        let mut mul_transmit_2to3: Vec<Vec<TransmitInitMulPhase2to3>> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {

            let result = parties[i].refresh_complete_phase2(&refresh_sid, &poly_fragments[i], &zero_kept_1to2[i], &mul_received_1to2[i]);
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                },
                Ok((out1, out2, out3, out4, out5, out6)) => {
                    correction_values.push(out1);
                    proofs_commitments.push(out2);
                    zero_kept_2to3.push(out3);
                    zero_transmit_2to3.push(out4);
                    mul_kept_2to4.push(out5);
                    mul_transmit_2to3.push(out6);
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

        // Phase 3
        let mut zero_kept_3to6: Vec<KeepInitZeroSharePhase3to6> = Vec::with_capacity(parameters.share_count);
        let mut mul_kept_3to5: Vec<HashMap<usize,KeepInitMulPhase3to5>> = Vec::with_capacity(parameters.share_count);
        let mut mul_transmit_3to4: Vec<Vec<TransmitInitMulPhase3to4>> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {

            let result = parties[i].refresh_complete_phase3(&refresh_sid, &zero_kept_2to3[i], &zero_received_1to3[i], &zero_received_2to3[i], &mul_kept_1to3[i], &mul_received_2to3[i]);
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                },
                Ok((out1, out2, out3)) => {
                    zero_kept_3to6.push(out1);
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
        let mut mul_kept_4to6: Vec<HashMap<usize,KeepInitMulPhase4to6>> = Vec::with_capacity(parameters.share_count);
        let mut mul_transmit_4to5: Vec<Vec<TransmitInitMulPhase4to5>> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {

            let result = parties[i].refresh_complete_phase4(&refresh_sid, &proofs_commitments, &mul_kept_2to4[i], &mul_received_3to4[i]);
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                },
                Ok((out1, out2)) => {
                    mul_kept_4to6.push(out1);
                    mul_transmit_4to5.push(out2);
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

            let result = parties[i].refresh_complete_phase5(&mul_kept_3to5[i], &mul_received_4to5[i]);
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
        let mut refreshed_parties: Vec<Party> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {

            let result = parties[i].refresh_complete_phase6(&refresh_sid, &correction_values[i], &zero_kept_3to6[i], &mul_kept_4to6[i], &mul_kept_5to6[i], &mul_received_5to6[i]);
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                },
                Ok(party) => {
                    refreshed_parties.push(party);
                },
            }
        }

        let parties = refreshed_parties;

        // SIGNING (as in test_signing)

        let sign_id = rand::thread_rng().gen::<[u8; 32]>();
        let message_to_sign = "Message to sign!".as_bytes();

        // For simplicity, we are testing only the first parties.
        let executing_parties: Vec<usize> = Vec::from_iter(1..=parameters.threshold);

        // Phase 1
        let mut unique_kept_1to2: HashMap<usize,UniqueKeep1to2> = HashMap::with_capacity(parameters.threshold);
        let mut kept_1to2: HashMap<usize,HashMap<usize,KeepPhase1to2>> = HashMap::with_capacity(parameters.threshold);
        let mut transmit_1to2: HashMap<usize,Vec<TransmitPhase1to2>> = HashMap::with_capacity(parameters.threshold); 
        for party_index in executing_parties.clone() {
            //Gather the counterparties
            let mut counterparties = executing_parties.clone();
            counterparties.retain(|index| *index != party_index);

            let (unique_keep, keep, transmit) = parties[party_index - 1].sign_phase1(&sign_id, &counterparties);
        
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
            //Gather the counterparties
            let mut counterparties = executing_parties.clone();
            counterparties.retain(|index| *index != party_index);

            let result = parties[party_index - 1].sign_phase2(&sign_id, &counterparties, unique_kept_1to2.get(&party_index).unwrap(), kept_1to2.get(&party_index).unwrap(), received_1to2.get(&party_index).unwrap());
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
            let result = parties[party_index - 1].sign_phase3(&sign_id, &message_to_sign, unique_kept_2to3.get(&party_index).unwrap(), kept_2to3.get(&party_index).unwrap(), received_2to3.get(&party_index).unwrap());
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
        let x_coord = x_coords[0].clone();
        for i in 1..parameters.threshold {
            assert_eq!(x_coord, x_coords[i]);
        }

        // Communication round 3
        // This is a broadcast to all parties. The desired result is already broadcast_3to4.

        // Phase 4
        let some_index = executing_parties[0];
        let result = parties[some_index - 1].sign_phase4(&message_to_sign, &x_coord, &broadcast_3to4);
        if let Err(abort) = result {
            panic!("Party {} aborted: {:?}", abort.index, abort.description);
        }

    }

}