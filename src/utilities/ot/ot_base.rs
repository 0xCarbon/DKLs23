/// This file implements an oblivious transfer (OT) which will serve as a base
/// for the OT extension protocol.
/// 
/// As suggested in page 30 of DKLs23 (https://eprint.iacr.org/2023/765.pdf),
/// we implement the endemic OT protocol of Zhou et al., which can be found on
/// Section 3 of https://eprint.iacr.org/2022/1525.pdf.

use k256::{Scalar, AffinePoint, ProjectivePoint};
use k256::elliptic_curve::Field;
use rand::Rng;

use crate::SECURITY;
use crate::utilities::hashes::*;
use crate::utilities::proofs::{DLogProof, EncProof};
use crate::utilities::ot::ErrorOT;

// SENDER DATA

// Sender after initialization.

#[derive(Debug, Clone)]
pub struct OTSender {
    pub s: Scalar,
    pub proof: DLogProof,
}

// RECEIVER DATA

// Receiver after initialization.

pub type Seed = [u8; SECURITY];

#[derive(Debug, Clone)]
pub struct OTReceiver {
    pub seed: Seed,
}

// The following implements the protocol as in Section 3 of the paper.
//
// There are two phases for each party and one communication round between
// them. Both Phase 1 and Phase 2 can be done concurrently for the sender
// and the receiver.
//
// We also create an initalization function which should be executed during
// Phase 1. It saves some values that can be reused if the protocol is applied
// several times. As this will be our case for the OT extension, there are also
// "batch" variants for each of the phases.

impl OTSender {

    // Initialization - According to first paragraph on page 18,
    // the sender can reuse the secret s and the proof of discrete
    // logarithm. Thus, we isolate this part from the rest for efficiency.
    pub fn init(session_id: &[u8]) -> OTSender {
        
        let s = Scalar::random(rand::thread_rng());

        // In the paper, different protocols use different random oracles.
        // Thus, we will add a unique string to the session id here.
        let current_sid = [session_id, "DLogProof".as_bytes()].concat();
        let proof = DLogProof::prove(&s, &current_sid);

        OTSender {
            s,
            proof,
        }
    }

    // Phase 1 - The sender transmits z = s * generator and the proof
    // of discrete logarithm. Note that z is contained in the proof.
    pub fn run_phase1(&self) -> DLogProof {
        self.proof.clone()
    }

    // Since the sender is recycling the proof, we don't need a batch version.

    // Communication round
    // The sender transmits the proof.
    // He receives the receiver's seed and encryption proof (which contains u and v).

    // Phase 2 - We verify the receiver's data and compute the output.
    pub fn run_phase2(&self, session_id: &[u8], seed: &Seed, enc_proof: &EncProof) -> Result<(HashOutput, HashOutput), ErrorOT> {

        // We reconstruct h from the seed (as in the paper).
        // Instead of using a real identifier for the receiver,
        // we just take the letter 'R' for simplicity.
        // I guess we could omit it, but we leave it to "change the oracle".
        let msg_for_h = ["R".as_bytes(), seed].concat();
        let h = (AffinePoint::GENERATOR * hash_as_scalar(&msg_for_h, session_id)).to_affine();

        // We verify the proof.
        let current_sid = [session_id, "EncProof".as_bytes()].concat();
        let verification = enc_proof.verify(&current_sid);

        // h is already in enc_proof, but we check if the values agree.
        if !verification || (h != enc_proof.proof0.base_h) {
            return Err(ErrorOT::new("Receiver cheated in OT: Encryption proof failed!"));
        }

        // We compute the messages.
        // As before, instead of an identifier for the sender,
        // we just take the letter 'S' for simplicity.

        let (_,v) = enc_proof.get_u_and_v();

        let value_for_m0 = (v * &self.s).to_affine();
        let value_for_m1 = ((ProjectivePoint::from(v) - h) * &self.s).to_affine();

        let msg_for_m0 = ["S".as_bytes(), &point_to_bytes(&value_for_m0)].concat();
        let msg_for_m1 = ["S".as_bytes(), &point_to_bytes(&value_for_m1)].concat();

        let m0 = hash(&msg_for_m0, session_id);
        let m1 = hash(&msg_for_m1, session_id);

        Ok((m0, m1))
    }

    // Phase 2 batch version: used for multiple executions (e.g. OT extension).
    pub fn run_phase2_batch(&self, session_id: &[u8], seed: &Seed, enc_proofs: &Vec<EncProof>) -> Result<(Vec<HashOutput>, Vec<HashOutput>), ErrorOT> {
        
        let batch_size = enc_proofs.len();
        
        let mut vec_m0: Vec<HashOutput> = Vec::with_capacity(batch_size);
        let mut vec_m1: Vec<HashOutput> = Vec::with_capacity(batch_size);
        for i in 0..batch_size {

            // We use different ids for different iterations.
            let current_sid = [&i.to_be_bytes(), session_id].concat();

            let (m0, m1) = self.run_phase2(&current_sid, seed, &enc_proofs[i])?;

            vec_m0.push(m0);
            vec_m1.push(m1);
        }

        Ok((vec_m0, vec_m1))
    }
    
}

impl OTReceiver {

    // Initialization - According to first paragraph on page 18,
    // the sender can reuse the seed. Thus, we isolate this part
    // from the rest for efficiency.
    pub fn init() -> OTReceiver {

        let seed = rand::thread_rng().gen::<Seed>();

        OTReceiver {
            seed,
        }
    }

    // Phase 1 - We sample the secret values and provide proof.
    pub fn run_phase1(&self, session_id: &[u8], bit: bool) -> (Scalar, EncProof) {

        // We sample the secret scalar r.
        let r = Scalar::random(rand::thread_rng());

        // We compute h as in the paper.
        // Instead of using a real identifier for the receiver,
        // we just take the letter 'R' for simplicity.
        // I guess we could omit it, but we leave it to "change the oracle".
        let msg_for_h = ["R".as_bytes(), &self.seed].concat();
        let h = (AffinePoint::GENERATOR * hash_as_scalar(&msg_for_h, session_id)).to_affine();

        // We prove our data.
        // In the paper, different protocols use different random oracles.
        // Thus, we will add a unique string to the session id here.
        let current_sid = [session_id, "EncProof".as_bytes()].concat();
        let proof = EncProof::prove(&current_sid, &h, &r, bit);

        // r should be kept and proof should be sent.
        (r, proof)
    }

    // Phase 1 batch version: used for multiple executions (e.g. OT extension).
    pub fn run_phase1_batch(&self, session_id: &[u8], bits: &Vec<bool>) -> (Vec<Scalar>, Vec<EncProof>) {
        
        let batch_size = bits.len();
        
        let mut vec_r: Vec<Scalar> = Vec::with_capacity(batch_size);
        let mut vec_proof: Vec<EncProof> = Vec::with_capacity(batch_size);
        for i in 0..batch_size {

            // We use different ids for different iterations.
            let current_sid = [&i.to_be_bytes(), session_id].concat();

            let (r, proof) = self.run_phase1(&current_sid, bits[i]);

            vec_r.push(r);
            vec_proof.push(proof);
        }

        (vec_r, vec_proof)
    }

    // Communication round
    // The receiver transmits his seed and the proof.
    // He receives the sender's seed and proof of discrete logarithm (which contains z).

    // Phase 2 - We verify the sender's data and compute the output.
    // For the batch version, we split the phase into two steps: the
    // first depends only on the initialization values and can be done
    // once, while the second is different for each iteration.

    pub fn run_phase2_step1(&self, session_id: &[u8], dlog_proof: &DLogProof) -> Result<AffinePoint, ErrorOT> {

        // Verification of the proof.
        let current_sid = [session_id, "DLogProof".as_bytes()].concat();
        let verification = DLogProof::verify(dlog_proof, &current_sid);

        if !verification {
            return Err(ErrorOT::new("Sender cheated in OT: Proof of discrete logarithm failed!"));
        }

        let z = dlog_proof.point.clone();

        Ok(z)
    }

    pub fn run_phase2_step2(&self, session_id: &[u8], r: &Scalar, z: &AffinePoint) -> HashOutput {

        // We compute the message.
        // As before, instead of an identifier for the sender,
        // we just take the letter 'S' for simplicity.

        let value_for_mb = (*z * r).to_affine();

        let msg_for_mb = ["S".as_bytes(), &point_to_bytes(&value_for_mb)].concat();
        let mb = hash(&msg_for_mb, session_id);       

        // We could return the bit as in the paper, but the receiver has this information.
        mb
    }

    // Phase 2 batch version: used for multiple executions (e.g. OT extension).
    pub fn run_phase2_batch(&self, session_id: &[u8], vec_r: &Vec<Scalar>, dlog_proof: &DLogProof) -> Result<Vec<HashOutput>, ErrorOT> {
        
        // Step 1
        let z = self.run_phase2_step1(session_id, dlog_proof)?;

        // Step 2
        let batch_size = vec_r.len();
        
        let mut vec_mb: Vec<HashOutput> = Vec::with_capacity(batch_size);
        for i in 0..batch_size {

            // We use different ids for different iterations.
            let current_sid = [&i.to_be_bytes(), session_id].concat();

            let mb = self.run_phase2_step2(&current_sid, &vec_r[i], &z);

            vec_mb.push(mb);
        }

        Ok(vec_mb)
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ot_base() {
        let session_id = rand::thread_rng().gen::<[u8; 32]>();

        // Initialization
        let sender = OTSender::init(&session_id);
        let receiver = OTReceiver::init();

        // Phase 1 - Sender
        let dlog_proof = sender.run_phase1();

        // Phase 1 - Receiver
        let bit = rand::random();
        let (r, enc_proof) = receiver.run_phase1(&session_id, bit);

        // Communication round - The parties exchange the proofs.
        // The receiver also sends his seed.
        let seed = receiver.seed;

        // Phase 2 - Sender
        let result_sender = sender.run_phase2(&session_id, &seed, &enc_proof);

        if let Err(error) = result_sender {
            panic!("OT error: {:?}", error.description);
        }

        let (m0, m1) = result_sender.unwrap();

        // Phase 2 - Receiver
        let result_receiver = receiver.run_phase2_step1(&session_id, &dlog_proof);

        if let Err(error) = result_receiver {
            panic!("OT error: {:?}", error.description);
        }

        let z = result_receiver.unwrap();
        let mb = receiver.run_phase2_step2(&session_id, &r, &z);

        // Verification that the protocol did what it should do.
        // Depending on the choice the receiver made, he should receive one of the pads.
        if bit {
            assert_eq!(m1, mb);
        } else {
            assert_eq!(m0, mb);
        }
    }

    #[test]
    fn test_ot_base_batch() {
        let session_id = rand::thread_rng().gen::<[u8; 32]>();

        // Initialization (unique)
        let sender = OTSender::init(&session_id);
        let receiver = OTReceiver::init();

        let batch_size = 256;

        // Phase 1 - Sender (unique)
        let dlog_proof = sender.run_phase1();

        // Phase 1 - Receiver
        let mut bits: Vec<bool> = Vec::with_capacity(batch_size);
        for _ in 0..batch_size {
            bits.push(rand::random());
        }

        let (vec_r, enc_proofs) = receiver.run_phase1_batch(&session_id, &bits);

        // Communication round - The parties exchange the proofs.
        // The receiver also sends his seed.
        let seed = receiver.seed;

        // Phase 2 - Sender
        let result_sender = sender.run_phase2_batch(&session_id, &seed, &enc_proofs);

        if let Err(error) = result_sender {
            panic!("OT error: {:?}", error.description);
        }

        let (vec_m0, vec_m1) = result_sender.unwrap();

        // Phase 2 - Receiver
        let result_receiver = receiver.run_phase2_batch(&session_id, &vec_r, &dlog_proof);

        if let Err(error) = result_receiver {
            panic!("OT error: {:?}", error.description);
        }

        let vec_mb = result_receiver.unwrap();

        // Verification that the protocol did what it should do.
        // Depending on the choice the receiver made, he should receive one of the pads.
        for i in 0..batch_size {
            if bits[i] {
                assert_eq!(vec_m1[i], vec_mb[i]);
            } else {
                assert_eq!(vec_m0[i], vec_mb[i]);
            }
        }
    }
}