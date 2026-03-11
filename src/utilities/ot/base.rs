//! Base OT.
//!
//! This file implements an oblivious transfer (OT) which will serve as a base
//! for the OT extension protocol.
//!
//! As suggested in page 30 of `DKLs23` (<https://eprint.iacr.org/2023/765.pdf>),
//! we implement the endemic OT protocol of Zhou et al., which can be found on
//! Section 3 of <https://eprint.iacr.org/2022/1525.pdf>.
//!
//! There are two phases for each party and one communication round between
//! them. Both Phase 1 and Phase 2 can be done concurrently for the sender
//! and the receiver.
//
//! There is also an initialization function which should be executed during
//! Phase 1. It saves some values that can be reused if the protocol is applied
//! several times. As this will be our case for the OT extension, there are
//! "batch" variants for each of the phases.

use k256::elliptic_curve::Field;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use rand::RngExt;

use crate::utilities::hashes::{point_to_bytes, tagged_hash, tagged_hash_as_scalar, HashOutput};
use crate::utilities::oracle_tags::{TAG_OT_BASE_H, TAG_OT_BASE_MSG};
use crate::utilities::ot::ErrorOT;
use crate::utilities::proofs::{DLogProof, EncProof};
use crate::utilities::rng;
use crate::SECURITY;

// SENDER DATA

/// Sender's data and methods for the base OT protocol.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OTSender {
    pub s: Scalar,
    pub proof: DLogProof,
}

// RECEIVER DATA

/// Seed kept by the receiver.
pub type Seed = [u8; SECURITY as usize];

/// Receiver's data and methods for the base OT protocol.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OTReceiver {
    pub seed: Seed,
}

impl OTSender {
    // According to first paragraph on page 18,
    // the sender can reuse the secret s and the proof of discrete
    // logarithm. Thus, we isolate this part from the rest for efficiency.

    /// Initializes the protocol for a given session id.
    #[must_use]
    pub fn init(session_id: &[u8]) -> OTSender {
        // We sample a nonzero random scalar.
        let mut s = Scalar::ZERO;
        while s == Scalar::ZERO {
            s = Scalar::random(&mut rng::get_rng());
        }

        let proof = DLogProof::prove(&s, session_id);

        OTSender { s, proof }
    }

    // Phase 1 - The sender transmits z = s * generator and the proof
    // of discrete logarithm. Note that z is contained in the proof.

    /// Generates a proof to be sent to the receiver.
    #[must_use]
    pub fn run_phase1(&self) -> DLogProof {
        self.proof.clone()
    }

    // Since the sender is recycling the proof, we don't need a batch version.

    // Communication round
    // The sender transmits the proof.
    // He receives the receiver's seed and encryption proof (which contains u and v).

    // Phase 2 - We verify the receiver's data and compute the output.

    /// Using the seed and the encryption proof transmitted by the receiver,
    /// the two output messages are computed.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the encryption proof fails.
    pub fn run_phase2(
        &self,
        session_id: &[u8],
        seed: &Seed,
        enc_proof: &EncProof,
    ) -> Result<(HashOutput, HashOutput), ErrorOT> {
        // We reconstruct h from the seed (as in the paper).
        let h = (AffinePoint::GENERATOR
            * tagged_hash_as_scalar(TAG_OT_BASE_H, &[session_id, seed]))
        .to_affine();

        // We verify the proof.
        let verification = enc_proof.verify(session_id);

        // h is already in enc_proof, but we check if the values agree.
        if !verification || (h != enc_proof.proof0.base_h) {
            return Err(ErrorOT::new(
                "Receiver cheated in OT: Encryption proof failed!",
            ));
        }

        // We compute the messages.

        let (_, v) = enc_proof.get_u_and_v();

        let value_for_m0 = (v * self.s).to_affine();
        let value_for_m1 = ((ProjectivePoint::from(v) - h) * self.s).to_affine();

        let value_for_m0_bytes = point_to_bytes(&value_for_m0);
        let value_for_m1_bytes = point_to_bytes(&value_for_m1);

        let m0 = tagged_hash(TAG_OT_BASE_MSG, &[session_id, &value_for_m0_bytes]);
        let m1 = tagged_hash(TAG_OT_BASE_MSG, &[session_id, &value_for_m1_bytes]);

        Ok((m0, m1))
    }

    // Phase 2 batch version: used for multiple executions (e.g. OT extension).

    /// Executes `run_phase2` for each encryption proof in `enc_proofs`.
    ///
    /// # Errors
    ///
    /// Will return `Err` if one of the executions fails.
    pub fn run_phase2_batch(
        &self,
        session_id: &[u8],
        seed: &Seed,
        enc_proofs: &[EncProof],
    ) -> Result<(Vec<HashOutput>, Vec<HashOutput>), ErrorOT> {
        let batch_size =
            u16::try_from(enc_proofs.len()).map_err(|_| ErrorOT::new("Batch size exceeds maximum (65535)"))?;

        let mut vec_m0: Vec<HashOutput> = Vec::with_capacity(batch_size as usize);
        let mut vec_m1: Vec<HashOutput> = Vec::with_capacity(batch_size as usize);
        for i in 0..batch_size {
            // We use different ids for different iterations.
            let current_sid = [&i.to_be_bytes(), session_id].concat();

            let (m0, m1) = self.run_phase2(&current_sid, seed, &enc_proofs[i as usize])?;

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

    /// Initializes the protocol.
    #[must_use]
    pub fn init() -> OTReceiver {
        let seed = rng::get_rng().random::<Seed>();

        OTReceiver { seed }
    }

    // Phase 1 - We sample the secret values and provide proof.

    /// Given a choice bit, returns a secret scalar (to be kept)
    /// and an encryption proof (to be sent to the sender).
    #[must_use]
    pub fn run_phase1(&self, session_id: &[u8], bit: bool) -> (Scalar, EncProof) {
        // We sample the secret scalar r.
        let r = Scalar::random(&mut rng::get_rng());

        // We compute h as in the paper.
        let h = (AffinePoint::GENERATOR
            * tagged_hash_as_scalar(TAG_OT_BASE_H, &[session_id, &self.seed]))
        .to_affine();

        // We prove our data.
        let proof = EncProof::prove(session_id, &h, &r, bit);

        // r should be kept and proof should be sent.
        (r, proof)
    }

    // Phase 1 batch version: used for multiple executions (e.g. OT extension).

    /// Executes `run_phase1` for each choice bit in `bits`.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the batch size exceeds the maximum (65535).
    pub fn run_phase1_batch(
        &self,
        session_id: &[u8],
        bits: &[bool],
    ) -> Result<(Vec<Scalar>, Vec<EncProof>), ErrorOT> {
        let batch_size =
            u16::try_from(bits.len()).map_err(|_| ErrorOT::new("Batch size exceeds maximum (65535)"))?;

        let mut vec_r: Vec<Scalar> = Vec::with_capacity(batch_size as usize);
        let mut vec_proof: Vec<EncProof> = Vec::with_capacity(batch_size as usize);
        for i in 0..batch_size {
            // We use different ids for different iterations.
            let current_sid = [&i.to_be_bytes(), session_id].concat();

            let (r, proof) = self.run_phase1(&current_sid, bits[i as usize]);

            vec_r.push(r);
            vec_proof.push(proof);
        }

        Ok((vec_r, vec_proof))
    }

    // Communication round
    // The receiver transmits his seed and the proof.
    // He receives the sender's seed and proof of discrete logarithm (which contains z).

    // Phase 2 - We verify the sender's data and compute the output.
    // For the batch version, we split the phase into two steps: the
    // first depends only on the initialization values and can be done
    // once, while the second is different for each iteration.

    /// Verifies the discrete logarithm proof sent by the sender
    /// and returns the point concerned in the proof.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the proof fails.
    pub fn run_phase2_step1(
        &self,
        session_id: &[u8],
        dlog_proof: &DLogProof,
    ) -> Result<AffinePoint, ErrorOT> {
        // Verification of the proof.
        let verification = DLogProof::verify(dlog_proof, session_id);

        if !verification {
            return Err(ErrorOT::new(
                "Sender cheated in OT: Proof of discrete logarithm failed!",
            ));
        }

        let z = dlog_proof.point;

        Ok(z)
    }

    /// With the secret value `r` from Phase 1 and with the point `z`
    /// from the previous step, the output message is computed.
    #[must_use]
    pub fn run_phase2_step2(&self, session_id: &[u8], r: &Scalar, z: &AffinePoint) -> HashOutput {
        // We compute the message.

        let value_for_mb = (*z * r).to_affine();
        let value_for_mb_bytes = point_to_bytes(&value_for_mb);

        // We could return the bit as in the paper, but the receiver has this information.
        tagged_hash(TAG_OT_BASE_MSG, &[session_id, &value_for_mb_bytes])
    }

    // Phase 2 batch version: used for multiple executions (e.g. OT extension).

    /// Executes `run_phase2_step1` once and `run_phase2_step2` for every
    /// secret scalar in `vec_r` from Phase 1.
    ///
    /// # Errors
    ///
    /// Will return `Err` if one of the executions fails.
    pub fn run_phase2_batch(
        &self,
        session_id: &[u8],
        vec_r: &[Scalar],
        dlog_proof: &DLogProof,
    ) -> Result<Vec<HashOutput>, ErrorOT> {
        // Step 1
        let z = self.run_phase2_step1(session_id, dlog_proof)?;

        // Step 2
        let batch_size =
            u16::try_from(vec_r.len()).map_err(|_| ErrorOT::new("Batch size exceeds maximum (65535)"))?;

        let mut vec_mb: Vec<HashOutput> = Vec::with_capacity(batch_size as usize);
        for i in 0..batch_size {
            // We use different ids for different iterations.
            let current_sid = [&i.to_be_bytes(), session_id].concat();

            let mb = self.run_phase2_step2(&current_sid, &vec_r[i as usize], &z);

            vec_mb.push(mb);
        }

        Ok(vec_mb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ensures receiver rejects a tampered DLogProof from sender.
    #[test]
    fn test_ot_base_rejects_tampered_dlog_proof() {
        let session_id = rng::get_rng().random::<[u8; 32]>();

        let sender = OTSender::init(&session_id);
        let receiver = OTReceiver::init();

        let mut dlog_proof = sender.run_phase1();
        dlog_proof.proofs[0].challenge_response += Scalar::ONE;

        let result = receiver.run_phase2_step1(&session_id, &dlog_proof);
        let error = result.expect_err("tampered DLogProof should be rejected");
        assert!(error
            .description
            .contains("Sender cheated in OT: Proof of discrete logarithm failed!"));
    }

    /// Ensures sender rejects a tampered encryption proof from receiver.
    #[test]
    fn test_ot_base_rejects_tampered_enc_proof() {
        let session_id = rng::get_rng().random::<[u8; 32]>();

        let sender = OTSender::init(&session_id);
        let receiver = OTReceiver::init();

        let bit = rng::get_rng().random();
        let (_, mut enc_proof) = receiver.run_phase1(&session_id, bit);
        let seed = receiver.seed;

        enc_proof.challenge0 += Scalar::ONE;

        let result = sender.run_phase2(&session_id, &seed, &enc_proof);
        let error = result.expect_err("tampered EncProof should be rejected");
        assert!(error
            .description
            .contains("Receiver cheated in OT: Encryption proof failed!"));
    }

    /// Tests if the outputs for the OT base protocol
    /// satisfy the relations they are supposed to satisfy.
    #[test]
    fn test_ot_base() {
        let session_id = rng::get_rng().random::<[u8; 32]>();

        // Initialization
        let sender = OTSender::init(&session_id);
        let receiver = OTReceiver::init();

        // Phase 1 - Sender
        let dlog_proof = sender.run_phase1();

        // Phase 1 - Receiver
        let bit = rng::get_rng().random();
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

    /// Batch version for [`test_ot_base`].
    #[test]
    fn test_ot_base_batch() {
        let session_id = rng::get_rng().random::<[u8; 32]>();

        // Initialization (unique)
        let sender = OTSender::init(&session_id);
        let receiver = OTReceiver::init();

        let batch_size = 256;

        // Phase 1 - Sender (unique)
        let dlog_proof = sender.run_phase1();

        // Phase 1 - Receiver
        let mut bits: Vec<bool> = Vec::with_capacity(batch_size);
        for _ in 0..batch_size {
            bits.push(rng::get_rng().random());
        }

        let (vec_r, enc_proofs) = receiver.run_phase1_batch(&session_id, &bits).unwrap();

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
