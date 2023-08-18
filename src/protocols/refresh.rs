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
/// 
/// ATTENTION: The protocols here work for any instance of Party, including
/// for derived addresses. However, refreshing a derivation is not such a
/// good idea because the refreshed derivation becomes essentially independent
/// of the master node. We recommend that only master nodes are refreshed
/// and derivations are calculated as needed afterwards.

use std::collections::HashMap;

use curv::elliptic::curves::{Secp256k1, Scalar};
use curv::cryptographic_primitives::secret_sharing::Polynomial;

use crate::utilities::hashes::*;
use crate::utilities::multiplication::{MulSender, MulReceiver};
use crate::utilities::ot::ot_extension;
use crate::utilities::zero_sharings::{self, ZeroShare};

use crate::protocols::{Party, Abort, PartiesMessage};
use crate::protocols::derivation::DerivationData;
use crate::protocols::dkg::*;

///////// STRUCTS FOR MESSAGES TO TRANSMIT IN COMMUNICATION ROUNDS.

// "Transmit" messages refer to only one counterparty, hence
// we must send a whole vector of them.

#[derive(Clone)]
pub struct TransmitRefreshPhase1to3 {
    pub parties: PartiesMessage,
    pub commitment: HashOutput,
}

#[derive(Clone)]
pub struct TransmitRefreshPhase2to3 {
    pub parties: PartiesMessage,
    pub seed: zero_sharings::Seed,
    pub salt: Vec<u8>,
}

////////// STRUCTS FOR MESSAGES TO KEEP BETWEEN PHASES.

// "Keep" messages refer to only one counterparty, hence
// we must keep a whole vector of them.

#[derive(Clone)]
pub struct KeepRefreshPhase1to2 {
    pub seed: zero_sharings::Seed,
    pub salt: Vec<u8>,
}

#[derive(Clone)]
pub struct KeepRefreshPhase2to3 {
    pub seed: zero_sharings::Seed,
}

// This one we just keep one instance (it's a "unique keep").
#[derive(Clone)]
pub struct KeepRefreshPhase3to4 {
    pub zero_share: ZeroShare,
    pub new_mul_senders: HashMap<usize,MulSender>,
    pub new_mul_receivers: HashMap<usize,MulReceiver>,
}

//////////////////////////

// We implement now two refresh protocols.

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

    pub fn refresh_complete_phase1(&self, refresh_sid: &[u8]) -> (Vec<Scalar<Secp256k1>>, HashMap<usize,KeepInitZeroSharePhase1to2>, Vec<TransmitInitZeroSharePhase1to3>, HashMap<usize,KeepInitMulPhase1to3>, Vec<TransmitInitMulPhase1to2>, KeepDerivationPhase1to2, TransmitDerivationPhase1to3) {

        // We run Phase 1 in DKG, but we force the constant term in Step 1 to be zero.
        let secret_polynomial = Polynomial::<Secp256k1>::sample_exact_with_fixed_const_term((self.parameters.threshold - 1) as u16, Scalar::<Secp256k1>::zero());
        let evaluations = dkg_step2(&self.parameters, secret_polynomial);

        // We won't use the derivation part, but we'll run it for simplicity in the code.
        let data = SessionData {
            parameters: self.parameters.clone(),
            party_index: self.party_index,
            session_id: refresh_sid.to_vec(),
        };
        let (_, zero_keep, zero_transmit, mul_keep, mul_transmit, bip_keep, bip_transmit) = dkg_phase1(&data);

        (evaluations, zero_keep, zero_transmit, mul_keep, mul_transmit, bip_keep, bip_transmit)
    }

    pub fn refresh_complete_phase2(&self, refresh_sid: &[u8], poly_fragments: &Vec<Scalar<Secp256k1>>, zero_kept: &HashMap<usize,KeepInitZeroSharePhase1to2>, mul_received: &Vec<TransmitInitMulPhase1to2>, bip_kept: &KeepDerivationPhase1to2) -> Result<(Scalar<Secp256k1>, ProofCommitment, HashMap<usize,KeepInitZeroSharePhase2to3>, Vec<TransmitInitZeroSharePhase2to3>, HashMap<usize,KeepInitMulPhase2to4>, Vec<TransmitInitMulPhase2to3>, TransmitDerivationPhase2to3),Abort> {
        let data = SessionData {
            parameters: self.parameters.clone(),
            party_index: self.party_index,
            session_id: refresh_sid.to_vec(),
        };
        dkg_phase2(&data, poly_fragments, zero_kept, mul_received, bip_kept)
    }

    pub fn refresh_complete_phase3(&self, refresh_sid: &[u8], zero_kept: &HashMap<usize,KeepInitZeroSharePhase2to3>, zero_received_phase1: &Vec<TransmitInitZeroSharePhase1to3>, zero_received_phase2: &Vec<TransmitInitZeroSharePhase2to3>, mul_kept: &HashMap<usize,KeepInitMulPhase1to3>, mul_received: &Vec<TransmitInitMulPhase2to3>, bip_received_phase1: &Vec<TransmitDerivationPhase1to3>, bip_received_phase2: &Vec<TransmitDerivationPhase2to3>) -> Result<(KeepCompletePhase3to6, HashMap<usize,KeepInitMulPhase3to5>, Vec<TransmitInitMulPhase3to4>), Abort> {
        let data = SessionData {
            parameters: self.parameters.clone(),
            party_index: self.party_index,
            session_id: refresh_sid.to_vec(),
        };
        dkg_phase3(&data, zero_kept, zero_received_phase1, zero_received_phase2, mul_kept, mul_received, bip_received_phase1, bip_received_phase2)
    }

    pub fn refresh_complete_phase4(&self, refresh_sid: &[u8], proofs_commitments: &Vec<ProofCommitment>, mul_kept: &HashMap<usize,KeepInitMulPhase2to4>, mul_received: &Vec<TransmitInitMulPhase3to4>) -> Result<(HashMap<usize,KeepInitMulPhase4to6>, Vec<TransmitInitMulPhase4to5>),Abort> {
        let data = SessionData {
            parameters: self.parameters.clone(),
            party_index: self.party_index,
            session_id: refresh_sid.to_vec(),
        };
        let (verifying_pk, mul_keep, mul_transmit) = dkg_phase4(&data, proofs_commitments, mul_kept, mul_received)?;

        // The public key calculated above should be the zero point on the curve.
        if verifying_pk.is_zero() {
            Ok((mul_keep, mul_transmit))
        } else {
            Err(Abort::new(self.party_index, "The auxiliary public key is not the zero point!"))
        }
    }

    pub fn refresh_complete_phase5(&self, refresh_sid: &[u8], mul_kept: &HashMap<usize,KeepInitMulPhase3to5>, mul_received: &Vec<TransmitInitMulPhase4to5>) -> Result<(HashMap<usize,KeepInitMulPhase5to6>, Vec<TransmitInitMulPhase5to6>),Abort> {
        let data = SessionData {
            parameters: self.parameters.clone(),
            party_index: self.party_index,
            session_id: refresh_sid.to_vec(),
        };
        dkg_phase5(&data, mul_kept, mul_received)
    }

    pub fn refresh_complete_phase6(&self, refresh_sid: &[u8], correction_value: &Scalar<Secp256k1>, complete_kept: &KeepCompletePhase3to6, mul_kept_phase4: &HashMap<usize,KeepInitMulPhase4to6>, mul_kept_phase5: &HashMap<usize,KeepInitMulPhase5to6>, mul_received: &Vec<TransmitInitMulPhase5to6>) -> Result<Party,Abort> {
        let data = SessionData {
            parameters: self.parameters.clone(),
            party_index: self.party_index,
            session_id: refresh_sid.to_vec(),
        };
        let correction_data = dkg_phase6(&data, correction_value, &self.pk, complete_kept, mul_kept_phase4, mul_kept_phase5, mul_received)?;

        // For key derivation, we just update poly_point.
        let derivation_data = DerivationData {
            depth: self.derivation_data.depth,
            child_number: self.derivation_data.child_number,
            parent_fingerprint: self.derivation_data.parent_fingerprint,
            poly_point: &self.poly_point + correction_value,  // We update poly_point.
            pk: self.pk.clone(),
            chain_code: self.derivation_data.chain_code,
        };

        let party = Party {
            parameters: self.parameters.clone(),
            party_index: self.party_index,
            session_id: refresh_sid.to_vec(),  // We replace the old session id by the new one.
    
            poly_point: &self.poly_point + correction_value,  // We update poly_point.
            pk: self.pk.clone(),
    
            zero_share: correction_data.zero_share.clone(),
    
            mul_senders: correction_data.mul_senders.clone(),
            mul_receivers: correction_data.mul_receivers.clone(),

            derivation_data,
        };
    
        Ok(party)
    }

    // A FASTER REFRESH

    // During a complete refresh, we initialize the multiplication protocol
    // from scratch. Instead, we can use our previous data to more efficiently
    // refresh this initialization. This results in a faster refresh and,
    // depending on the multiplication protocol, fewer communication rounds.

    // We will base this implementation on the article "Refresh When You Wake Up:
    // Proactive Threshold Wallets with Offline Devices" (https://eprint.iacr.org/2019/1328.pdf)
    // More specifically, we use their ideas from Section 8 (and Appendix E).

    // In their protocol, a common random string is sampled by each pair of
    // parties. They achieve this by using their "coin tossing functionality".
    // Note that their suggestion of implementation for this functionality is
    // very similar to the way our zero sharing protocol computes its seeds.

    // Hence, our new refresh protocol will work as follows: we run the first
    // four phases of DKG ignoring any procedure related to the multiplication
    // protocol (and we do the same modifications we did for the complete refresh).
    // During the third phase, the initialization for the zero sharing protocol
    // generates its seeds. We reuse them to apply the Beaver trick (described
    // in the article) to refresh the OT instances used for multiplication.

    pub fn refresh_phase1(&self) -> (Vec<Scalar<Secp256k1>>, HashMap<usize,KeepRefreshPhase1to2>, Vec<TransmitRefreshPhase1to3>) {

        // DKG - Step 1 (modified) + Step 2.
        let secret_polynomial = Polynomial::<Secp256k1>::sample_exact_with_fixed_const_term((self.parameters.threshold - 1) as u16, Scalar::<Secp256k1>::zero());
        let evaluations = dkg_step2(&self.parameters, secret_polynomial);

        // Initialization - Zero sharings.
        // We follow the code in dkg.rs.
        let mut keep: HashMap<usize,KeepRefreshPhase1to2> = HashMap::with_capacity(self.parameters.share_count - 1);
        let mut transmit: Vec<TransmitRefreshPhase1to3> = Vec::with_capacity(self.parameters.share_count - 1);
        for i in 1..=self.parameters.share_count {
            if i == self.party_index { continue; }

            let (seed, commitment, salt) = ZeroShare::generate_seed_with_commitment();

            keep.insert(i, KeepRefreshPhase1to2 {
                seed,
                salt,
            });
            transmit.push( TransmitRefreshPhase1to3 {
                parties: PartiesMessage { sender: self.party_index, receiver: i },
                commitment,
            });
        }

        (evaluations, keep, transmit)
    }

    pub fn refresh_phase2(&self, refresh_sid: &[u8], poly_fragments: &Vec<Scalar<Secp256k1>>, kept: &HashMap<usize,KeepRefreshPhase1to2>) -> (Scalar<Secp256k1>, ProofCommitment, HashMap<usize,KeepRefreshPhase2to3>, Vec<TransmitRefreshPhase2to3>) {

        // DKG - Step 3.
        let (correction_value, proof_commitment) = dkg_step3(self.party_index, refresh_sid, poly_fragments);
    
        // Initialization - Zero sharings.
        // We follow the code in dkg.rs.
        let mut keep: HashMap<usize,KeepRefreshPhase2to3> = HashMap::with_capacity(self.parameters.share_count - 1);
        let mut transmit: Vec<TransmitRefreshPhase2to3> = Vec::with_capacity(self.parameters.share_count - 1);
        for (target_party, message_kept) in kept {
            keep.insert(*target_party, KeepRefreshPhase2to3 {
                seed: message_kept.seed,
            });
            transmit.push( TransmitRefreshPhase2to3 {
                parties: PartiesMessage { sender: self.party_index, receiver: *target_party },
                seed: message_kept.seed,
                salt: message_kept.salt.clone(),
            });
        }

        (correction_value, proof_commitment, keep, transmit)
    }

    pub fn refresh_phase3(&self, refresh_sid: &[u8], kept: &HashMap<usize,KeepRefreshPhase2to3>, received_phase1: &Vec<TransmitRefreshPhase1to3>, received_phase2: &Vec<TransmitRefreshPhase2to3>) -> Result<KeepRefreshPhase3to4, Abort> {

        // Initialization - Zero sharings.
        // We follow the code in dkg.rs.
        let mut seeds: Vec<zero_sharings::SeedPair> = Vec::with_capacity(self.parameters.share_count - 1);
        for (target_party, message_kept) in kept {
            for message_received_1 in received_phase1 {
                for message_received_2 in received_phase2 {

                    let my_index = message_received_1.parties.receiver;
                    let their_index = message_received_1.parties.sender;

                    // Confirm that the message is for us.
                    if my_index != self.party_index {
                    return Err(Abort::new(self.party_index, "Received a message not meant for us!"));
                    }

                    // We first check if the messages relate to the same party.
                    if *target_party != their_index || message_received_2.parties.sender != their_index { continue; }

                    let verification = ZeroShare::verify_seed(&message_received_2.seed, &message_received_1.commitment, &message_received_2.salt);
                    if !verification {
                        return Err(Abort::new(self.party_index, &format!("Initialization for zero sharings protocol failed because Party {} cheated when sending the seed!", message_received_1.parties.sender)));
                    }

                    seeds.push(ZeroShare::generate_seed_pair(my_index, their_index, &message_kept.seed, &message_received_2.seed));
                }
            }
        }

        // Having the seeds, we can update the data for multiplication.

        let mut new_mul_senders: HashMap<usize,MulSender> = HashMap::with_capacity(self.parameters.share_count - 1);
        let mut new_mul_receivers: HashMap<usize,MulReceiver> = HashMap::with_capacity(self.parameters.share_count - 1);

        for seed_pair in &seeds { // This is the same as running through the counterparties.

            let their_index = seed_pair.index_counterparty;
            let seed = seed_pair.seed;

            let mul_sender = self.mul_senders.get(&their_index).unwrap();
            let mul_receiver = self.mul_receivers.get(&their_index).unwrap();

            // We update the OT data.

            let mut new_ote_sender = mul_sender.ote_sender.clone();
            let mut new_ote_receiver = mul_receiver.ote_receiver.clone();

            for i in 0..(ot_extension::KAPPA) {
                
                // We expand the seed into r0_prime, r1_prime and b_prime, as in the paper.
                // There will be two sets of constants: one for the sender and one
                // for the receiver. For the salts, note that the sender comes first.

                // Then, we apply the trick described in the paper.
                
                // Sender
                let salt_r0 = [&(0usize).to_be_bytes(), &i.to_be_bytes(), &self.party_index.to_be_bytes(), &their_index.to_be_bytes(), refresh_sid].concat();
                let salt_r1 = [&(1usize).to_be_bytes(), &i.to_be_bytes(), &self.party_index.to_be_bytes(), &their_index.to_be_bytes(), refresh_sid].concat();
                let salt_b = [&(2usize).to_be_bytes(), &i.to_be_bytes(), &self.party_index.to_be_bytes(), &their_index.to_be_bytes(), refresh_sid].concat();

                let r0_prime = hash(&seed, &salt_r0);
                let r1_prime = hash(&seed, &salt_r1);
                let b_prime = (hash(&seed, &salt_b)[0] % 2) == 1; // We take the first digit.

                let b_double_prime = new_ote_sender.correlation[i] ^ b_prime;
                let r_prime_b_double_prime = if b_double_prime { r1_prime } else { r0_prime };

                let mut r_double_prime: HashOutput = [0; crate::SECURITY];
                for j in 0..crate::SECURITY {
                    r_double_prime[j] = new_ote_sender.seeds[i][j] ^ r_prime_b_double_prime[j];
                } 

                new_ote_sender.correlation[i] = b_double_prime;
                new_ote_sender.seeds[i] = r_double_prime; 

                // Receiver
                let salt_r0 = [&(0usize).to_be_bytes(), &i.to_be_bytes(), &their_index.to_be_bytes(), &self.party_index.to_be_bytes(), refresh_sid].concat();
                let salt_r1 = [&(1usize).to_be_bytes(), &i.to_be_bytes(), &their_index.to_be_bytes(), &self.party_index.to_be_bytes(), refresh_sid].concat();
                let salt_b = [&(2usize).to_be_bytes(), &i.to_be_bytes(), &their_index.to_be_bytes(), &self.party_index.to_be_bytes(), refresh_sid].concat();

                let r0_prime = hash(&seed, &salt_r0);
                let r1_prime = hash(&seed, &salt_r1);
                let b_prime = (hash(&seed, &salt_b)[0] % 2) == 1; // We take the first digit.

                let r_b_prime = if b_prime { new_ote_receiver.seeds1[i] } else { new_ote_receiver.seeds0[i] };
                let r_opposite_b_prime = if b_prime { new_ote_receiver.seeds0[i] } else { new_ote_receiver.seeds1[i] };

                let mut r0_double_prime: HashOutput = [0; crate::SECURITY];
                let mut r1_double_prime: HashOutput = [0; crate::SECURITY];
                for j in 0..crate::SECURITY {
                    r0_double_prime[j] = r_b_prime[j] ^ r0_prime[j];
                    r1_double_prime[j] = r_opposite_b_prime[j] ^ r1_prime[j];
                }

                new_ote_receiver.seeds0[i] = r0_double_prime;
                new_ote_receiver.seeds1[i] = r1_double_prime;

            }

            // We will not change the public gadget vector (well, it is "public" afterall).
            new_mul_senders.insert(their_index, MulSender { 
                public_gadget: mul_sender.public_gadget.clone(),
                ote_sender: new_ote_sender,
            });
            new_mul_receivers.insert(their_index, MulReceiver {
                public_gadget: mul_receiver.public_gadget.clone(),
                ote_receiver: new_ote_receiver,
            });

        }

        // This finishes the initialization for the zero sharing protocol.
        let zero_share = ZeroShare::initialize(seeds);

        // We save all the data for the next phase.
        let keep = KeepRefreshPhase3to4 {
            zero_share,
            new_mul_senders,
            new_mul_receivers,
        };

        Ok(keep)
    }

    pub fn refresh_phase4(&self, refresh_sid: &[u8], correction_value: &Scalar<Secp256k1>, proofs_commitments: &Vec<ProofCommitment>, kept: &KeepRefreshPhase3to4) -> Result<Party, Abort> {

        // DKG - Step 5 (modified).

        let verifying_pk = dkg_step5(&self.parameters, self.party_index, refresh_sid, proofs_commitments)?;

        // The public key calculated above should be the zero point on the curve.
        if !verifying_pk.is_zero() {
            return Err(Abort::new(self.party_index, "The auxiliary public key is not the zero point!"));
        }

        // For key derivation, we just update poly_point.
        let derivation_data = DerivationData {
            depth: self.derivation_data.depth,
            child_number: self.derivation_data.child_number,
            parent_fingerprint: self.derivation_data.parent_fingerprint,
            poly_point: &self.poly_point + correction_value,  // We update poly_point.
            pk: self.pk.clone(),
            chain_code: self.derivation_data.chain_code,
        };

        // We can finally create the new party.
        let party = Party {
            parameters: self.parameters.clone(),
            party_index: self.party_index,
            session_id: refresh_sid.to_vec(),  // We replace the old session id by the new one.
    
            poly_point: &self.poly_point + correction_value,  // We update poly_point.
            pk: self.pk.clone(),
    
            zero_share: kept.zero_share.clone(),
    
            mul_senders: kept.new_mul_senders.clone(),
            mul_receivers: kept.new_mul_receivers.clone(),

            derivation_data,
        };

        Ok(party)
    }

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
        let parties = re_key(&parameters, &session_id, &secret_key, None);

        // REFRESH (it follows test_dkg_initialization closely)

        let refresh_sid = rand::thread_rng().gen::<[u8; 32]>();

        // Phase 1
        let mut dkg_1: Vec<Vec<Scalar<Secp256k1>>> = Vec::with_capacity(parameters.share_count);
        let mut zero_kept_1to2: Vec<HashMap<usize,KeepInitZeroSharePhase1to2>> = Vec::with_capacity(parameters.share_count);
        let mut zero_transmit_1to3: Vec<Vec<TransmitInitZeroSharePhase1to3>> = Vec::with_capacity(parameters.share_count);
        let mut mul_kept_1to3: Vec<HashMap<usize,KeepInitMulPhase1to3>> = Vec::with_capacity(parameters.share_count);
        let mut mul_transmit_1to2: Vec<Vec<TransmitInitMulPhase1to2>> = Vec::with_capacity(parameters.share_count);
        let mut bip_kept_1to2: Vec<KeepDerivationPhase1to2> = Vec::with_capacity(parameters.share_count);
        let mut bip_transmit_1to3: Vec<TransmitDerivationPhase1to3> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {
            let (out1, out2, out3, out4, out5, out6, out7) = parties[i].refresh_complete_phase1(&refresh_sid);

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
        let mut correction_values: Vec<Scalar<Secp256k1>> = Vec::with_capacity(parameters.share_count);
        let mut proofs_commitments: Vec<ProofCommitment> = Vec::with_capacity(parameters.share_count);
        let mut zero_kept_2to3: Vec<HashMap<usize,KeepInitZeroSharePhase2to3>> = Vec::with_capacity(parameters.share_count);
        let mut zero_transmit_2to3: Vec<Vec<TransmitInitZeroSharePhase2to3>> = Vec::with_capacity(parameters.share_count);
        let mut mul_kept_2to4: Vec<HashMap<usize,KeepInitMulPhase2to4>> = Vec::with_capacity(parameters.share_count);
        let mut mul_transmit_2to3: Vec<Vec<TransmitInitMulPhase2to3>> = Vec::with_capacity(parameters.share_count);
        let mut bip_transmit_2to3: Vec<TransmitDerivationPhase2to3> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {

            let result = parties[i].refresh_complete_phase2(&refresh_sid, &poly_fragments[i], &zero_kept_1to2[i], &mul_received_1to2[i], &bip_kept_1to2[i]);
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                },
                Ok((out1, out2, out3, out4, out5, out6, out7)) => {
                    correction_values.push(out1);
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

            let result = parties[i].refresh_complete_phase3(&refresh_sid, &zero_kept_2to3[i], &zero_received_1to3[i], &zero_received_2to3[i], &mul_kept_1to3[i], &mul_received_2to3[i], &bip_transmit_1to3, &bip_transmit_2to3);
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

            let result = parties[i].refresh_complete_phase5(&refresh_sid, &mul_kept_3to5[i], &mul_received_4to5[i]);
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

            let result = parties[i].refresh_complete_phase6(&refresh_sid, &correction_values[i], &complete_kept_3to6[i], &mul_kept_4to6[i], &mul_kept_5to6[i], &mul_received_5to6[i]);
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
        let some_index = executing_parties[0];
        let result = parties[some_index - 1].sign_phase4(all_data.get(&some_index).unwrap(), &x_coord, &broadcast_3to4);
        if let Err(abort) = result {
            panic!("Party {} aborted: {:?}", abort.index, abort.description);
        }

    }

    #[test]
    // Test for alternative refresh.
    fn test_refresh() {

        let threshold = rand::thread_rng().gen_range(2..=5); // You can change the ranges here.
        let offset = rand::thread_rng().gen_range(0..=5);

        let parameters = Parameters { threshold, share_count: threshold + offset }; // You can fix the parameters if you prefer.

        // We use the re_key function to quickly sample the parties.
        let session_id = rand::thread_rng().gen::<[u8; 32]>();
        let secret_key = Scalar::<Secp256k1>::random();
        let parties = re_key(&parameters, &session_id, &secret_key, None);

        // REFRESH (faster version)

        let refresh_sid = rand::thread_rng().gen::<[u8; 32]>();

        // Phase 1
        let mut dkg_1: Vec<Vec<Scalar<Secp256k1>>> = Vec::with_capacity(parameters.share_count);
        let mut kept_1to2: Vec<HashMap<usize,KeepRefreshPhase1to2>> = Vec::with_capacity(parameters.share_count);
        let mut transmit_1to3: Vec<Vec<TransmitRefreshPhase1to3>> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {
            let (out1, out2, out3) = parties[i].refresh_phase1();

            dkg_1.push(out1);
            kept_1to2.push(out2);
            transmit_1to3.push(out3);
        }

        // Communication round 1
        let mut poly_fragments = vec![Vec::<Scalar<Secp256k1>>::with_capacity(parameters.share_count); parameters.share_count];
        for row_i in dkg_1 {
            for j in 0..parameters.share_count {
                poly_fragments[j].push(row_i[j].clone());
            }
        }

        let mut received_1to3: Vec<Vec<TransmitRefreshPhase1to3>> = Vec::with_capacity(parameters.share_count);
        for i in 1..=parameters.share_count {

            let mut new_row: Vec<TransmitRefreshPhase1to3> = Vec::with_capacity(parameters.share_count - 1);
            for party in &transmit_1to3 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i {
                        new_row.push(message.clone());
                    }
                }
            }
            received_1to3.push(new_row);

        }

        // Phase 2
        let mut correction_values: Vec<Scalar<Secp256k1>> = Vec::with_capacity(parameters.share_count);
        let mut proofs_commitments: Vec<ProofCommitment> = Vec::with_capacity(parameters.share_count);
        let mut kept_2to3: Vec<HashMap<usize,KeepRefreshPhase2to3>> = Vec::with_capacity(parameters.share_count);
        let mut transmit_2to3: Vec<Vec<TransmitRefreshPhase2to3>> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {

            let (out1, out2, out3, out4) = parties[i].refresh_phase2(&refresh_sid, &poly_fragments[i], &kept_1to2[i]);

            correction_values.push(out1);
            proofs_commitments.push(out2);
            kept_2to3.push(out3);
            transmit_2to3.push(out4);
        }

        // Communication round 2
        let mut received_2to3: Vec<Vec<TransmitRefreshPhase2to3>> = Vec::with_capacity(parameters.share_count);
        for i in 1..=parameters.share_count {

            // We don't need to transmit the commitments because proofs_commitments is already what we need.
            // In practice, this should be done here.

            let mut new_row: Vec<TransmitRefreshPhase2to3> = Vec::with_capacity(parameters.share_count - 1);
            for party in &transmit_2to3 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i {
                        new_row.push(message.clone());
                    }
                }
            }
            received_2to3.push(new_row);

        }

        // Phase 3
        let mut kept_3to4: Vec<KeepRefreshPhase3to4> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {

            let result = parties[i].refresh_phase3(&refresh_sid, &kept_2to3[i], &received_1to3[i], &received_2to3[i]);
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                },
                Ok(out) => {
                    kept_3to4.push(out);
                },
            }
        }

        // Communication round 3
        // This is Step 4 of DKG: we now transmit the proofs from proofs_commitments.
        // For this test, we don't need to do this here.

        // Phase 4
        let mut refreshed_parties: Vec<Party> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {

            let result = parties[i].refresh_phase4(&refresh_sid, &correction_values[i], &proofs_commitments, &kept_3to4[i]);
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
        let some_index = executing_parties[0];
        let result = parties[some_index - 1].sign_phase4(all_data.get(&some_index).unwrap(), &x_coord, &broadcast_3to4);
        if let Err(abort) = result {
            panic!("Party {} aborted: {:?}", abort.index, abort.description);
        }

    }

}