//! Zero-knowledge proofs required by the protocols.
//!
//! This file implements some protocols for zero-knowledge proofs over the
//! curve secp256k1.
//!
//! The main protocol is for proofs of discrete logarithms. It is used during
//! key generation in the `DKLs23` protocol (<https://eprint.iacr.org/2023/765.pdf>).
//!
//! For the base OT in the OT extension, we use the endemic protocol of Zhou et al.
//! (see Section 3 of <https://eprint.iacr.org/2022/1525.pdf>). Thus, we also include
//! another zero knowledge proof employing the Chaum-Pedersen protocol, the
//! OR-composition and the Fiat-Shamir transform (as in their paper).
//!
//! # Discrete Logarithm Proof
//!
//! We implement Schnorr's protocol together with a randomized Fischlin transform
//! (see [`DLogProof`]).
//!
//! We base our implementation on Figures 23 and 27 of Zhou et al.
//!
//! For convenience, instead of writing the protocol directly, we wrote first an
//! implementation of the usual Schnorr's protocol, which is interactive (see [`InteractiveDLogProof`]).
//! Since it will be used for the non-interactive version, we made same particular choices
//! that would not make much sense if this interactive proof were used alone.
//!
//! # Encryption Proof
//!
//! The OT protocol of Zhou et al. uses an `ElGamal` encryption at some point
//! and it needs a zero-knowledge proof to verify its correctness.
//!
//! This implementation follows their paper: see page 17 and Appendix B.
//!
//! IMPORTANT: As specified in page 30 of `DKLs23`, we instantiate the protocols
//! above over the same elliptic curve group used in our main protocol.

use elliptic_curve::ops::Reduce;
use elliptic_curve::FieldBytes;
use rand::{Rng, RngExt};
use rustcrypto_ff::Field;
use rustcrypto_group::prime::PrimeCurveAffine;
use rustcrypto_group::Curve as GroupCurve;
use std::collections::HashSet;
use std::marker::PhantomData;

use crate::curve::DklsCurve;
use crate::utilities::hashes::{
    point_to_bytes, scalar_to_bytes, tagged_hash, tagged_hash_as_scalar, HashOutput,
};
use crate::utilities::oracle_tags::{
    TAG_DLOG_PROOF_COMMITMENT, TAG_DLOG_PROOF_FISCHLIN, TAG_ENCPROOF_FS,
};
use crate::utilities::rng;
use subtle::ConstantTimeEq;

/// Constants for the randomized Fischlin transform.
pub const R: u16 = 64;
pub const L: u16 = 4;
pub const T: u16 = 32;

// DISCRETE LOGARITHM PROOF.

/// Schnorr's protocol (interactive).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(
        serialize = "C::Scalar: serde::Serialize",
        deserialize = "C::Scalar: serde::Deserialize<'de>"
    ))
)]
pub struct InteractiveDLogProof<C: DklsCurve> {
    pub challenge: Vec<u8>,
    pub challenge_response: C::Scalar,
    #[cfg_attr(feature = "serde", serde(skip))]
    _curve: PhantomData<C>,
}

/// Convert a short challenge byte slice (at most T/8 bytes) to a scalar
/// by zero-extending to 32 bytes and reducing via `Reduce<FieldBytes<C>>`.
fn challenge_to_scalar<C: DklsCurve>(challenge: &[u8]) -> C::Scalar {
    let mut extended = vec![0u8; 32 - challenge.len()];
    extended.extend_from_slice(challenge);
    // FieldBytes<C> is 32 bytes for both secp256k1 and P-256.
    let field_bytes = FieldBytes::<C>::from_slice(&extended);
    <C::Scalar as Reduce<FieldBytes<C>>>::reduce(field_bytes)
}

impl<C: DklsCurve> InteractiveDLogProof<C> {
    /// Step 1 - Samples the random commitments.
    ///
    /// The `Scalar` is kept secret while the `AffinePoint` is transmitted.
    #[must_use]
    pub fn prove_step1(mut rng: impl Rng) -> (C::Scalar, C::AffinePoint) {
        // We sample a nonzero random scalar.
        let mut scalar_rand_commitment = <C::Scalar as Field>::ZERO;
        while scalar_rand_commitment == <C::Scalar as Field>::ZERO {
            scalar_rand_commitment = <C::Scalar as Field>::random(&mut rng);
        }

        let generator = <C::AffinePoint as PrimeCurveAffine>::generator();
        let point_rand_commitment = (generator * scalar_rand_commitment).to_affine();

        (scalar_rand_commitment, point_rand_commitment)
    }

    /// Step 2 - Computes the response for a given challenge.
    ///
    /// Here, `scalar` is the witness for the proof and `scalar_rand_commitment`
    /// is the secret value from the previous step.
    #[must_use]
    pub fn prove_step2(
        scalar: &C::Scalar,
        scalar_rand_commitment: &C::Scalar,
        challenge: &[u8],
    ) -> InteractiveDLogProof<C> {
        // For convenience, we are using a challenge in bytes.
        // We convert it back to a scalar.
        // The challenge will have T bits, so we first extend it to 256 bits.
        let challenge_scalar = challenge_to_scalar::<C>(challenge);

        // We compute the response.
        let challenge_response = *scalar_rand_commitment - (challenge_scalar * scalar);

        InteractiveDLogProof {
            challenge: challenge.to_vec(), // We save the challenge for the next protocol.
            challenge_response,
            _curve: PhantomData,
        }
    }

    /// Verification of a proof.
    ///
    /// The variable `point` is the point used for the proof.
    /// We didn't include it in the struct in order to not make unnecessary
    /// repetitions in the main protocol.
    ///
    /// Attention: the challenge should enter as a parameter here, but in the
    /// next protocol, it will come from the prover, so we decided to save it
    /// inside the struct.
    #[must_use]
    pub fn verify(&self, point: &C::AffinePoint, point_rand_commitment: &C::AffinePoint) -> bool {
        // Challenges are expected to be short (in this implementation they are 1 byte),
        // and must never exceed T/8 bytes.
        if self.challenge.is_empty() || self.challenge.len() > (T / 8) as usize {
            return false;
        }

        // For convenience, we are using a challenge in bytes.
        // We convert it back to a scalar.
        // The challenge will have T bits, so we first extend it to 256 bits.
        let challenge_scalar = challenge_to_scalar::<C>(&self.challenge);

        let generator = <C::AffinePoint as PrimeCurveAffine>::generator();

        // We compare the values that should agree.
        let point_verify =
            ((generator * self.challenge_response) + (*point * challenge_scalar)).to_affine();

        point_verify == *point_rand_commitment
    }
}

/// Schnorr's protocol (non-interactive via randomized Fischlin transform).
///
/// In order to remove interaction, we employ the "randomized Fischlin transform"
/// described in Figure 9 of <https://eprint.iacr.org/2022/393.pdf>. However, we will
/// follow the approach in Figure 27 of <https://eprint.iacr.org/2022/1525.pdf>.
/// It seems to come from Section 5.1 of the first paper.
///
/// There are some errors in this description (for example, `xi_i` and `xi_{i+r/2}`
/// are always the empty set), and thus we adapt Figure 9 of the first article. There is
/// still a problem: the paper says to choose `r` and `l` such that, in particular, `rl = 2^lambda`.
/// If `lambda = 256`, then `r` or `l` are astronomically large and the protocol becomes
/// computationally infeasible. We will use instead the condition `rl = lambda`.
/// We believe this is what the authors wanted, since this condition appears
/// in most of the rest of the first paper.
///
/// With `lambda = 256`, we chose `r = 64` and `l = 4` (higher values of `l` were too slow).
/// In this case, the constant `t` from the paper is equal to 32.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(
        serialize = "C::AffinePoint: serde::Serialize, C::Scalar: serde::Serialize",
        deserialize = "C::AffinePoint: serde::Deserialize<'de>, C::Scalar: serde::Deserialize<'de>"
    ))
)]
pub struct DLogProof<C: DklsCurve> {
    pub point: C::AffinePoint,
    pub rand_commitments: Vec<C::AffinePoint>,
    pub proofs: Vec<InteractiveDLogProof<C>>,
}

impl<C: DklsCurve> DLogProof<C> {
    /// Computes a proof for the witness `scalar`.
    #[must_use]
    pub fn prove(scalar: &C::Scalar, session_id: &[u8]) -> DLogProof<C> {
        // We execute Step 1 r times.
        let mut rand_commitments: Vec<C::AffinePoint> = Vec::with_capacity(R as usize);
        let mut states: Vec<C::Scalar> = Vec::with_capacity(R as usize);
        let mut rng = rng::get_rng();
        for _ in 0..R {
            let (state, rand_commitment) = InteractiveDLogProof::<C>::prove_step1(&mut rng);

            rand_commitments.push(rand_commitment);
            states.push(state);
        }

        // We save this vector in bytes.
        let rc_as_bytes = rand_commitments
            .clone()
            .into_iter()
            .map(|x| point_to_bytes::<C>(&x))
            .collect::<Vec<Vec<u8>>>()
            .concat();

        // Now, there is a "proof of work".
        // We have to find the good challenges.
        let mut first_proofs: Vec<InteractiveDLogProof<C>> = Vec::with_capacity((R / 2) as usize);
        let mut last_proofs: Vec<InteractiveDLogProof<C>> = Vec::with_capacity((R / 2) as usize);
        for i in 0..(R / 2) {
            // We will find different challenges until one of them works.
            // Since both hashes to be computed are of 2l bits, we expect
            // them to coincide after 2^{2l} tries (assuming everything is
            // uniformly random and independent). For l = 4, this is just
            // 256 tries. For safety, we will put a large margin and repeat
            // each while at most 2^16 times (so 2^32 tries in total).

            let mut flag = false;
            let mut first_counter = 0u16;
            while first_counter < u16::MAX && !flag {
                // We sample an array of T bits = T/8 bytes.
                let first_challenge = rng::get_rng().random::<[u8; (T / 8) as usize]>();

                // If this challenge was already sampled, we should go back.
                // However, with some tests, we saw that it is time consuming
                // to save the challenges (we have to reallocate memory all the
                // time when increasing the vector of used challenges).

                // Fortunately, note that our sample space has cardinality 2^t
                // (which is 2^32 in our case), and we repeat the loop 2^16 times.
                // Even if in all iterations we sample different values, the
                // probability of getting an older challenge in an additional
                // iteration is 2^16/2^32, which is small. Thus, we don't expect
                // a lot of repetitions.

                // We execute Step 2 at index i.
                let first_proof = InteractiveDLogProof::<C>::prove_step2(
                    scalar,
                    &states[i as usize],
                    &first_challenge,
                );

                // Let's take the first hash here.
                let generator = <C::AffinePoint as PrimeCurveAffine>::generator();
                let first_msg = [
                    &point_to_bytes::<C>(&generator),
                    &rc_as_bytes[..],
                    &i.to_be_bytes(),
                    &first_challenge,
                    &scalar_to_bytes::<C>(&first_proof.challenge_response),
                ]
                .concat();
                // The random oracle has to return an array of 2l bits = l/4 bytes, so we take a slice.
                let first_hash = &tagged_hash(TAG_DLOG_PROOF_FISCHLIN, &[session_id, &first_msg])
                    [0..(L / 4) as usize];

                // Now comes the search for the next challenge.
                let mut second_counter = 0u16;
                let mut rng = rng::get_rng();
                while second_counter < u16::MAX {
                    // We sample another array. Same considerations as before.
                    let second_challenge = rng.random::<[u8; (T / 8) as usize]>();

                    //if used_second_challenges.contains(&second_challenge) { continue; }

                    // We execute Step 2 at index i + R/2.
                    let second_proof = InteractiveDLogProof::<C>::prove_step2(
                        scalar,
                        &states[(i + (R / 2)) as usize],
                        &second_challenge,
                    );

                    // Second hash now.
                    let generator = <C::AffinePoint as PrimeCurveAffine>::generator();
                    let second_msg = [
                        &point_to_bytes::<C>(&generator),
                        &rc_as_bytes[..],
                        &(i + (R / 2)).to_be_bytes(),
                        &second_challenge,
                        &scalar_to_bytes::<C>(&second_proof.challenge_response),
                    ]
                    .concat();
                    let second_hash =
                        &tagged_hash(TAG_DLOG_PROOF_FISCHLIN, &[session_id, &second_msg])
                            [0..(L / 4) as usize];

                    // If the hashes are equal, we are successful and we can break both loops.
                    if *first_hash == *second_hash {
                        // We save the successful results.
                        first_proofs.push(first_proof);
                        last_proofs.push(second_proof);

                        // We update the flag to break the outer loop.
                        flag = true;

                        break;
                    }

                    // If we were not successful, we try again.
                    second_counter += 1;
                }

                // If we were not successful, we try again.
                first_counter += 1;
            }
        }

        // We put together the vectors.
        let proofs = [first_proofs, last_proofs].concat();

        // We save the point.
        let generator = <C::AffinePoint as PrimeCurveAffine>::generator();
        let point = (generator * scalar).to_affine();

        DLogProof {
            point,
            rand_commitments,
            proofs,
        }
    }

    /// Verification of a proof of discrete logarithm.
    ///
    /// Note that the point to be verified is in `proof`.
    #[must_use]
    pub fn verify(proof: &DLogProof<C>, session_id: &[u8]) -> bool {
        // We first verify that all vectors have the correct length.
        // If the prover is very unlucky, there is the possibility that
        // he doesn't return all the needed proofs.
        if proof.rand_commitments.len() != (R as usize) || proof.proofs.len() != (R as usize) {
            return false;
        }

        // We transform the random commitments into bytes.
        let vec_rc_as_bytes = proof
            .rand_commitments
            .clone()
            .into_iter()
            .map(|x| point_to_bytes::<C>(&x))
            .collect::<Vec<Vec<u8>>>();

        // All the proofs should be different (otherwise, it would be easier to forge a proof).
        // Here we compare the random commitments using a HashSet.
        let mut without_repetitions: HashSet<Vec<u8>> = HashSet::with_capacity(R as usize);
        if !vec_rc_as_bytes
            .clone()
            .into_iter()
            .all(move |x| without_repetitions.insert(x))
        {
            return false;
        }

        // We concatenate the vector of random commitments.
        let rc_as_bytes = vec_rc_as_bytes.concat();

        let generator = <C::AffinePoint as PrimeCurveAffine>::generator();
        for i in 0..(R / 2) {
            // We compare the hashes
            let first_msg = [
                &point_to_bytes::<C>(&generator),
                &rc_as_bytes[..],
                &i.to_be_bytes(),
                &proof.proofs[i as usize].challenge,
                &scalar_to_bytes::<C>(&proof.proofs[i as usize].challenge_response),
            ]
            .concat();
            let first_hash = &tagged_hash(TAG_DLOG_PROOF_FISCHLIN, &[session_id, &first_msg])
                [0..(L / 4) as usize];

            let second_msg = [
                &point_to_bytes::<C>(&generator),
                &rc_as_bytes[..],
                &(i + (R / 2)).to_be_bytes(),
                &proof.proofs[(i + (R / 2)) as usize].challenge,
                &scalar_to_bytes::<C>(&proof.proofs[(i + (R / 2)) as usize].challenge_response),
            ]
            .concat();
            let second_hash = &tagged_hash(TAG_DLOG_PROOF_FISCHLIN, &[session_id, &second_msg])
                [0..(L / 4) as usize];

            // Constant-time comparison to prevent timing side-channels
            // from leaking information about the proof structure.
            if !bool::from(first_hash.ct_eq(second_hash)) {
                return false;
            }

            // We verify both proofs.
            let verification_1 =
                proof.proofs[i as usize].verify(&proof.point, &proof.rand_commitments[i as usize]);
            let verification_2 = proof.proofs[(i + (R / 2)) as usize].verify(
                &proof.point,
                &proof.rand_commitments[(i + (R / 2)) as usize],
            );

            if !verification_1 || !verification_2 {
                return false;
            }
        }

        // If we got here, all the previous tests passed.
        true
    }

    /// Produces an instance of `DLogProof` (for the witness `scalar`)
    /// together with a commitment (its hash).
    ///
    /// The commitment is transmitted first and the proof is sent later
    /// when needed.
    #[must_use]
    pub fn prove_commit(scalar: &C::Scalar, session_id: &[u8]) -> (DLogProof<C>, HashOutput) {
        let proof = Self::prove(scalar, session_id);

        //Computes the commitment (it's the hash of DLogProof in bytes).
        let point_as_bytes = point_to_bytes::<C>(&proof.point);
        let rc_as_bytes = proof
            .rand_commitments
            .clone()
            .into_iter()
            .map(|x| point_to_bytes::<C>(&x))
            .collect::<Vec<Vec<u8>>>()
            .concat();
        let challenges_as_bytes = proof
            .proofs
            .clone()
            .into_iter()
            .map(|x| x.challenge)
            .collect::<Vec<Vec<u8>>>()
            .concat();
        let responses_as_bytes = proof
            .proofs
            .clone()
            .into_iter()
            .map(|x| scalar_to_bytes::<C>(&x.challenge_response))
            .collect::<Vec<Vec<u8>>>()
            .concat();

        let msg_for_commitment = [
            point_as_bytes,
            rc_as_bytes,
            challenges_as_bytes,
            responses_as_bytes,
        ]
        .concat();
        let commitment = tagged_hash(
            TAG_DLOG_PROOF_COMMITMENT,
            &[session_id, &msg_for_commitment],
        );

        (proof, commitment)
    }

    /// Verifies a proof and checks it against the commitment.
    #[must_use]
    pub fn decommit_verify(
        proof: &DLogProof<C>,
        commitment: &HashOutput,
        session_id: &[u8],
    ) -> bool {
        //Computes the expected commitment
        let point_as_bytes = point_to_bytes::<C>(&proof.point);
        let rc_as_bytes = proof
            .rand_commitments
            .clone()
            .into_iter()
            .map(|x| point_to_bytes::<C>(&x))
            .collect::<Vec<Vec<u8>>>()
            .concat();
        let challenges_as_bytes = proof
            .proofs
            .clone()
            .into_iter()
            .map(|x| x.challenge)
            .collect::<Vec<Vec<u8>>>()
            .concat();
        let responses_as_bytes = proof
            .proofs
            .clone()
            .into_iter()
            .map(|x| scalar_to_bytes::<C>(&x.challenge_response))
            .collect::<Vec<Vec<u8>>>()
            .concat();

        let msg_for_commitment = [
            point_as_bytes,
            rc_as_bytes,
            challenges_as_bytes,
            responses_as_bytes,
        ]
        .concat();
        let expected_commitment = tagged_hash(
            TAG_DLOG_PROOF_COMMITMENT,
            &[session_id, &msg_for_commitment],
        );

        bool::from(commitment.ct_eq(&expected_commitment)) && Self::verify(proof, session_id)
    }
}

// ENCRYPTION PROOF

/// Represents the random commitments for the Chaum-Pedersen protocol.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(
        serialize = "C::AffinePoint: serde::Serialize",
        deserialize = "C::AffinePoint: serde::Deserialize<'de>"
    ))
)]
pub struct RandomCommitments<C: DklsCurve> {
    pub rc_g: C::AffinePoint,
    pub rc_h: C::AffinePoint,
}

/// Chaum-Pedersen protocol (interactive version).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(
        serialize = "C::AffinePoint: serde::Serialize, C::Scalar: serde::Serialize",
        deserialize = "C::AffinePoint: serde::Deserialize<'de>, C::Scalar: serde::Deserialize<'de>"
    ))
)]
pub struct CPProof<C: DklsCurve> {
    pub base_g: C::AffinePoint, // Parameters for the proof.
    pub base_h: C::AffinePoint, // In the encryption proof, base_g = generator.
    pub point_u: C::AffinePoint,
    pub point_v: C::AffinePoint,

    pub challenge_response: C::Scalar,
}

impl<C: DklsCurve> CPProof<C> {
    // We need a proof that scalar * base_g = point_u and scalar * base_h = point_v.
    // As we will see later, the challenge will not be calculated only with the data
    // we now have. Thus, we have to write the interactive version here for the moment.
    // This means that the challenge is a parameter chosen by the verifier and is not
    // calculated via Fiat-Shamir.

    /// Step 1 - Samples the random commitments.
    ///
    /// The `Scalar` is kept secret while the `RandomCommitments` is transmitted.
    #[must_use]
    pub fn prove_step1(
        base_g: &C::AffinePoint,
        base_h: &C::AffinePoint,
    ) -> (C::Scalar, RandomCommitments<C>) {
        // We sample a nonzero random scalar.
        let mut scalar_rand_commitment = <C::Scalar as Field>::ZERO;
        while scalar_rand_commitment == <C::Scalar as Field>::ZERO {
            scalar_rand_commitment = <C::Scalar as Field>::random(&mut rng::get_rng());
        }

        let point_rand_commitment_g = (*base_g * scalar_rand_commitment).to_affine();
        let point_rand_commitment_h = (*base_h * scalar_rand_commitment).to_affine();

        let rand_commitments = RandomCommitments {
            rc_g: point_rand_commitment_g,
            rc_h: point_rand_commitment_h,
        };

        (scalar_rand_commitment, rand_commitments)
    }

    /// Step 2 - Compute the response for a given challenge.
    ///
    /// Here, `scalar` is the witness for the proof and `scalar_rand_commitment`
    /// is the secret value from the previous step.
    #[must_use]
    pub fn prove_step2(
        base_g: &C::AffinePoint,
        base_h: &C::AffinePoint,
        scalar: &C::Scalar,
        scalar_rand_commitment: &C::Scalar,
        challenge: &C::Scalar,
    ) -> CPProof<C> {
        // We get u and v.
        let point_u = (*base_g * scalar).to_affine();
        let point_v = (*base_h * scalar).to_affine();

        // We compute the response.
        let challenge_response = *scalar_rand_commitment - (*challenge * scalar);

        CPProof {
            base_g: *base_g,
            base_h: *base_h,
            point_u,
            point_v,

            challenge_response,
        }
    }

    /// Verification of a proof.
    ///
    /// Note that the data to be verified is in the variable `proof`.
    ///
    /// The verifier must know the challenge (in this interactive version, he chooses it).
    #[must_use]
    pub fn verify(&self, rand_commitments: &RandomCommitments<C>, challenge: &C::Scalar) -> bool {
        // We compare the values that should agree.
        let point_verify_g =
            ((self.base_g * self.challenge_response) + (self.point_u * challenge)).to_affine();
        let point_verify_h =
            ((self.base_h * self.challenge_response) + (self.point_v * challenge)).to_affine();

        (point_verify_g == rand_commitments.rc_g) && (point_verify_h == rand_commitments.rc_h)
    }

    /// Simulates a "fake" proof which passes the `verify` method.
    ///
    /// To do so, the prover samples the challenge and uses it to compute
    /// the other values. This method returns the challenge used, the commitments
    /// and the corresponding proof.
    ///
    /// This is needed during the OR-composition protocol (see [`EncProof`]).
    #[must_use]
    pub fn simulate(
        base_g: &C::AffinePoint,
        base_h: &C::AffinePoint,
        point_u: &C::AffinePoint,
        point_v: &C::AffinePoint,
    ) -> (RandomCommitments<C>, C::Scalar, CPProof<C>) {
        // We sample the challenge and the response first.
        let challenge = <C::Scalar as Field>::random(&mut rng::get_rng());

        let challenge_response = <C::Scalar as Field>::random(&mut rng::get_rng());

        // Now we compute the "random" commitments that work for this challenge.
        let point_rand_commitment_g =
            ((*base_g * challenge_response) + (*point_u * challenge)).to_affine();
        let point_rand_commitment_h =
            ((*base_h * challenge_response) + (*point_v * challenge)).to_affine();

        let rand_commitments = RandomCommitments {
            rc_g: point_rand_commitment_g,
            rc_h: point_rand_commitment_h,
        };

        let proof = CPProof {
            base_g: *base_g,
            base_h: *base_h,
            point_u: *point_u,
            point_v: *point_v,

            challenge_response,
        };

        (rand_commitments, challenge, proof)
    }
}

/// Encryption proof used during the Endemic OT protocol of Zhou et al.
///
/// See page 17 of <https://eprint.iacr.org/2022/1525.pdf>.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(
        serialize = "C::AffinePoint: serde::Serialize, C::Scalar: serde::Serialize",
        deserialize = "C::AffinePoint: serde::Deserialize<'de>, C::Scalar: serde::Deserialize<'de>"
    ))
)]
pub struct EncProof<C: DklsCurve> {
    /// EncProof is a proof that `proof0` or `proof1` really proves what it says.
    pub proof0: CPProof<C>,
    pub proof1: CPProof<C>,

    pub commitments0: RandomCommitments<C>,
    pub commitments1: RandomCommitments<C>,

    pub challenge0: C::Scalar,
    pub challenge1: C::Scalar,
}

impl<C: DklsCurve> EncProof<C> {
    /// Computes a proof for the witness `scalar`.
    ///
    /// The variable `bit` indicates which one of the proofs is really
    /// proved by `scalar`. The other one is simulated.
    #[must_use]
    pub fn prove(
        session_id: &[u8],
        base_h: &C::AffinePoint,
        scalar: &C::Scalar,
        bit: bool,
    ) -> EncProof<C> {
        // PRELIMINARIES

        // g is the generator in this case.
        let base_g = <C::AffinePoint as PrimeCurveAffine>::generator();

        // We compute u and v from Section 3 in the paper.
        // Be careful: these are not point_u and point_v from CPProof.

        // u is independent of the bit chosen.
        let u = (*base_h * scalar).to_affine();

        // v = h*bit + g*scalar.
        // The other possible value for v will be used in a simulated proof.
        // See below for a better explanation.
        //
        // Both branches are computed unconditionally to avoid timing
        // side-channels that could leak the OT choice bit.
        let base_h_proj = C::ProjectivePoint::from(*base_h);
        let g_times_scalar = base_g * scalar;
        let v_if_true = (g_times_scalar + base_h_proj).to_affine();
        let v_if_false = g_times_scalar.to_affine();
        let fake_v_if_true = v_if_true;
        let fake_v_if_false = (g_times_scalar - base_h_proj).to_affine();

        let (v, fake_v) = if bit {
            (v_if_true, fake_v_if_true)
        } else {
            (v_if_false, fake_v_if_false)
        };

        // STEP 1
        // We start our real proof and simulate the fake proof.

        // Real proof:
        // bit = 0 => We want to prove that (g,h,v,u) is a DDH tuple.
        // bit = 1 => We want to prove that (g,h,v-h,u) is a DDH tuple.

        // Fake proof: Simulate that (g,h,fake_v,u) is a DDH tuple (although it's not).
        // bit = 0 => We want to fake that (g,h,v-h,u) is a DDH tuple (i.e., fake_v = v-h).
        // bit = 1 -> We want to fake that (g,h,v,u) is a DDH tuple (i.e., fake_v = v).

        // Commitments for real proof.
        let (real_scalar_commitment, real_commitments) = CPProof::prove_step1(&base_g, base_h);

        // Fake proof.
        let (fake_commitments, fake_challenge, fake_proof) =
            CPProof::simulate(&base_g, base_h, &fake_v, &u);

        // STEP 2
        // Fiat-Shamir: We compute the "total" challenge based on the
        // values we want to prove and on the commitments above.

        let base_g_as_bytes = point_to_bytes::<C>(&base_g);
        let base_h_as_bytes = point_to_bytes::<C>(base_h);
        let u_as_bytes = point_to_bytes::<C>(&u);
        let v_as_bytes = point_to_bytes::<C>(&v);

        let r_rc_g_as_bytes = point_to_bytes::<C>(&real_commitments.rc_g);
        let r_rc_h_as_bytes = point_to_bytes::<C>(&real_commitments.rc_h);

        let f_rc_g_as_bytes = point_to_bytes::<C>(&fake_commitments.rc_g);
        let f_rc_h_as_bytes = point_to_bytes::<C>(&fake_commitments.rc_h);

        // The proof that comes first is always the one containing u and v.
        // If bit = 0, it is the real proof, otherwise it is the fake one.
        // For the message, we first put the commitments for the first proof
        // since the verifier does not know which proof is the real one.
        let msg_for_challenge = if bit {
            [
                base_g_as_bytes,
                base_h_as_bytes,
                u_as_bytes,
                v_as_bytes,
                f_rc_g_as_bytes,
                f_rc_h_as_bytes,
                r_rc_g_as_bytes,
                r_rc_h_as_bytes,
            ]
            .concat()
        } else {
            [
                base_g_as_bytes,
                base_h_as_bytes,
                u_as_bytes,
                v_as_bytes,
                r_rc_g_as_bytes,
                r_rc_h_as_bytes,
                f_rc_g_as_bytes,
                f_rc_h_as_bytes,
            ]
            .concat()
        };

        let challenge =
            tagged_hash_as_scalar::<C>(TAG_ENCPROOF_FS, &[session_id, &msg_for_challenge]);

        // STEP 3
        // We compute the real challenge for our real proof.
        // Note that it depends on the challenge above. This
        // is why we cannot simply fake both proofs. With this
        // challenge, we can finish the real proof.

        // ATTENTION: The original paper says that the challenge
        // should be the XOR of the real and fake challenges.
        // However, it is easier and essentially equivalent to
        // impose that challenge = real + fake as scalars.

        let real_challenge = challenge - fake_challenge;

        let real_proof = CPProof::prove_step2(
            &base_g,
            base_h,
            scalar,
            &real_scalar_commitment,
            &real_challenge,
        );

        // RETURN

        // The proof containing u and v goes first.
        // It is the real proof if bit = 0 and the false one otherwise.
        if bit {
            EncProof {
                proof0: fake_proof,
                proof1: real_proof,

                commitments0: fake_commitments,
                commitments1: real_commitments,

                challenge0: fake_challenge,
                challenge1: real_challenge,
            }
        } else {
            EncProof {
                proof0: real_proof,
                proof1: fake_proof,

                commitments0: real_commitments,
                commitments1: fake_commitments,

                challenge0: real_challenge,
                challenge1: fake_challenge,
            }
        }
    }

    /// Verification of an encryption proof.
    ///
    /// Note that the data to be verified is in `proof`.
    #[must_use]
    pub fn verify(&self, session_id: &[u8]) -> bool {
        // We check if the proofs are compatible.
        let generator = <C::AffinePoint as PrimeCurveAffine>::generator();
        if (self.proof0.base_g != generator)
        || (self.proof0.base_g != self.proof1.base_g)
        || (self.proof0.base_h != self.proof1.base_h)
        || (self.proof0.point_v != self.proof1.point_v) // This is u from Section 3 in the paper.
        || (self.proof0.point_u != (C::ProjectivePoint::from(self.proof1.point_u) + C::ProjectivePoint::from(self.proof1.base_h)).to_affine())
        // proof0 contains v and proof1 contains v-h.
        {
            return false;
        }

        // Reconstructing the challenge.

        let base_g_as_bytes = point_to_bytes::<C>(&self.proof0.base_g);
        let base_h_as_bytes = point_to_bytes::<C>(&self.proof0.base_h);

        // u and v are respectively point_v and point_u from the proof0.
        let u_as_bytes = point_to_bytes::<C>(&self.proof0.point_v);
        let v_as_bytes = point_to_bytes::<C>(&self.proof0.point_u);

        let rc0_g_as_bytes = point_to_bytes::<C>(&self.commitments0.rc_g);
        let rc0_h_as_bytes = point_to_bytes::<C>(&self.commitments0.rc_h);

        let rc1_g_as_bytes = point_to_bytes::<C>(&self.commitments1.rc_g);
        let rc1_h_as_bytes = point_to_bytes::<C>(&self.commitments1.rc_h);

        let msg_for_challenge = [
            base_g_as_bytes,
            base_h_as_bytes,
            u_as_bytes,
            v_as_bytes,
            rc0_g_as_bytes,
            rc0_h_as_bytes,
            rc1_g_as_bytes,
            rc1_h_as_bytes,
        ]
        .concat();
        let expected_challenge =
            tagged_hash_as_scalar::<C>(TAG_ENCPROOF_FS, &[session_id, &msg_for_challenge]);

        // The challenge should be the sum of the challenges used in the proofs.
        if expected_challenge != self.challenge0 + self.challenge1 {
            return false;
        }

        // Finally, we check if both proofs are valid.
        self.proof0.verify(&self.commitments0, &self.challenge0)
            && self.proof1.verify(&self.commitments1, &self.challenge1)
    }

    /// Extracts `u` and `v` from an instance of `EncProof`.
    ///
    /// Be careful: the notation for `u` and `v` here is the
    /// same as the one used in the paper by Zhou et al. at page 17.
    /// Unfortunately, `u` and `v` appear in the other order in
    /// their description of the Chaum-Pedersen protocol.
    /// Hence, `u` and `v` here are not the same as `point_u`
    /// and `point_v` in [`CPProof`].
    #[must_use]
    pub fn get_u_and_v(&self) -> (C::AffinePoint, C::AffinePoint) {
        (self.proof0.point_v, self.proof0.point_u)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::Secp256k1;

    type TestCurve = Secp256k1;
    type Scalar = <TestCurve as elliptic_curve::CurveArithmetic>::Scalar;
    type AffinePoint = <TestCurve as elliptic_curve::CurveArithmetic>::AffinePoint;
    type ProjectivePoint = <TestCurve as elliptic_curve::CurveArithmetic>::ProjectivePoint;

    // DLogProof

    /// Tests if proving and verifying work for [`DLogProof`].
    #[test]
    fn test_dlog_proof() {
        let scalar = <Scalar as Field>::random(&mut rng::get_rng());
        let session_id = rng::get_rng().random::<[u8; 32]>();
        let proof = DLogProof::<TestCurve>::prove(&scalar, &session_id);
        assert!(DLogProof::<TestCurve>::verify(&proof, &session_id));
    }

    /// Generates a [`DLogProof`] and changes it on purpose
    /// to see if the verify function detects.
    #[test]
    fn test_dlog_proof_fail_proof() {
        let scalar = <Scalar as Field>::random(&mut rng::get_rng());
        let session_id = rng::get_rng().random::<[u8; 32]>();
        let mut proof = DLogProof::<TestCurve>::prove(&scalar, &session_id);
        proof.proofs[0].challenge_response *= Scalar::from(2u32); //Changing the proof
        assert!(!(DLogProof::<TestCurve>::verify(&proof, &session_id)));
    }

    /// Ensures duplicated random commitments are rejected.
    #[test]
    fn test_dlog_proof_rejects_duplicate_rand_commitments() {
        let scalar = <Scalar as Field>::random(&mut rng::get_rng());
        let session_id = rng::get_rng().random::<[u8; 32]>();
        let mut proof = DLogProof::<TestCurve>::prove(&scalar, &session_id);
        proof.rand_commitments[1] = proof.rand_commitments[0];
        assert!(!DLogProof::<TestCurve>::verify(&proof, &session_id));
    }

    /// Ensures wrong proof/commitment vector lengths are rejected.
    #[test]
    fn test_dlog_proof_rejects_wrong_vector_lengths() {
        let scalar = <Scalar as Field>::random(&mut rng::get_rng());
        let session_id = rng::get_rng().random::<[u8; 32]>();

        let mut proof_short_commitments = DLogProof::<TestCurve>::prove(&scalar, &session_id);
        proof_short_commitments.rand_commitments.pop();
        assert!(!DLogProof::<TestCurve>::verify(
            &proof_short_commitments,
            &session_id
        ));

        let mut proof_short_proofs = DLogProof::<TestCurve>::prove(&scalar, &session_id);
        proof_short_proofs.proofs.pop();
        assert!(!DLogProof::<TestCurve>::verify(
            &proof_short_proofs,
            &session_id
        ));
    }

    /// Ensures session-id mismatches invalidate the proof.
    #[test]
    fn test_dlog_proof_rejects_mismatched_session_id() {
        let scalar = <Scalar as Field>::random(&mut rng::get_rng());
        let prove_sid = rng::get_rng().random::<[u8; 32]>();
        let mut verify_sid = prove_sid;
        verify_sid[0] ^= 1;
        let proof = DLogProof::<TestCurve>::prove(&scalar, &prove_sid);
        assert!(!DLogProof::<TestCurve>::verify(&proof, &verify_sid));
    }

    /// Tests if proving and verifying work for [`DLogProof`]
    /// in the case with commitment.
    #[test]
    fn test_dlog_proof_commit() {
        let scalar = <Scalar as Field>::random(&mut rng::get_rng());
        let session_id = rng::get_rng().random::<[u8; 32]>();
        let (proof, commitment) = DLogProof::<TestCurve>::prove_commit(&scalar, &session_id);
        assert!(DLogProof::<TestCurve>::decommit_verify(
            &proof,
            &commitment,
            &session_id
        ));
    }

    /// Generates a [`DLogProof`] with commitment and changes
    /// the proof on purpose to see if the verify function detects.
    #[test]
    fn test_dlog_proof_commit_fail_proof() {
        let scalar = <Scalar as Field>::random(&mut rng::get_rng());
        let session_id = rng::get_rng().random::<[u8; 32]>();
        let (mut proof, commitment) = DLogProof::<TestCurve>::prove_commit(&scalar, &session_id);
        proof.proofs[0].challenge_response *= Scalar::from(2u32); //Changing the proof
        assert!(!(DLogProof::<TestCurve>::decommit_verify(&proof, &commitment, &session_id)));
    }

    /// Generates a [`DLogProof`] with commitment and changes
    /// the commitment on purpose to see if the verify function detects.
    #[test]
    fn test_dlog_proof_commit_fail_commitment() {
        let scalar = <Scalar as Field>::random(&mut rng::get_rng());
        let session_id = rng::get_rng().random::<[u8; 32]>();
        let (proof, mut commitment) = DLogProof::<TestCurve>::prove_commit(&scalar, &session_id);
        if commitment[0] == 0 {
            commitment[0] = 1;
        } else {
            commitment[0] -= 1;
        } //Changing the commitment
        assert!(!(DLogProof::<TestCurve>::decommit_verify(&proof, &commitment, &session_id)));
    }

    // CPProof

    /// Tests if proving and verifying work for [`CPProof`].
    #[test]
    fn test_cp_proof() {
        let log_base_g = <Scalar as Field>::random(&mut rng::get_rng());
        let log_base_h = <Scalar as Field>::random(&mut rng::get_rng());
        let scalar = <Scalar as Field>::random(&mut rng::get_rng());

        let generator = <AffinePoint as PrimeCurveAffine>::generator();
        let base_g = (generator * log_base_g).to_affine();
        let base_h = (generator * log_base_h).to_affine();

        // Prover - Step 1.
        let (scalar_rand_commitment, rand_commitments) =
            CPProof::<TestCurve>::prove_step1(&base_g, &base_h);

        // Verifier - Gather the commitments and choose the challenge.
        let challenge = <Scalar as Field>::random(&mut rng::get_rng());

        // Prover - Step 2.
        let proof = CPProof::<TestCurve>::prove_step2(
            &base_g,
            &base_h,
            &scalar,
            &scalar_rand_commitment,
            &challenge,
        );

        // Verifier verifies the proof.
        let verification = proof.verify(&rand_commitments, &challenge);

        assert!(verification);
    }

    /// Tests if simulating a fake proof and verifying work for [`CPProof`].
    #[test]
    fn test_cp_proof_simulate() {
        let log_base_g = <Scalar as Field>::random(&mut rng::get_rng());
        let log_base_h = <Scalar as Field>::random(&mut rng::get_rng());
        let log_point_u = <Scalar as Field>::random(&mut rng::get_rng());
        let log_point_v = <Scalar as Field>::random(&mut rng::get_rng());

        let generator = <AffinePoint as PrimeCurveAffine>::generator();
        let base_g = (generator * log_base_g).to_affine();
        let base_h = (generator * log_base_h).to_affine();
        let point_u = (generator * log_point_u).to_affine();
        let point_v = (generator * log_point_v).to_affine();

        // Simulation.
        let (rand_commitments, challenge, proof) =
            CPProof::<TestCurve>::simulate(&base_g, &base_h, &point_u, &point_v);

        let verification = proof.verify(&rand_commitments, &challenge);

        assert!(verification);
    }

    /// Ensures simulated proofs fail when verified against a different statement.
    #[test]
    fn test_cp_proof_simulate_wrong_statement_fails() {
        let log_base_g = <Scalar as Field>::random(&mut rng::get_rng());
        let log_base_h = <Scalar as Field>::random(&mut rng::get_rng());
        let log_point_u = <Scalar as Field>::random(&mut rng::get_rng());
        let log_point_v = <Scalar as Field>::random(&mut rng::get_rng());

        let generator = <AffinePoint as PrimeCurveAffine>::generator();
        let base_g = (generator * log_base_g).to_affine();
        let base_h = (generator * log_base_h).to_affine();
        let point_u = (generator * log_point_u).to_affine();
        let point_v = (generator * log_point_v).to_affine();

        // We intentionally use a random statement and then tamper it further.
        let (rand_commitments, challenge, mut proof) =
            CPProof::<TestCurve>::simulate(&base_g, &base_h, &point_u, &point_v);
        proof.point_u =
            (ProjectivePoint::from(proof.point_u) + ProjectivePoint::GENERATOR).to_affine();

        assert!(!proof.verify(&rand_commitments, &challenge));
    }

    // EncProof

    /// Tests if proving and verifying work for [`EncProof`].
    #[test]
    fn test_enc_proof() {
        // We sample the initial values.
        let session_id = rng::get_rng().random::<[u8; 32]>();

        let log_base_h = <Scalar as Field>::random(&mut rng::get_rng());
        let generator = <AffinePoint as PrimeCurveAffine>::generator();
        let base_h = (generator * log_base_h).to_affine();

        let scalar = <Scalar as Field>::random(&mut rng::get_rng());

        let bit: bool = rng::get_rng().random();

        // Proving.
        let proof = EncProof::<TestCurve>::prove(&session_id, &base_h, &scalar, bit);

        // Verifying.
        let verification = proof.verify(&session_id);

        assert!(verification);
    }

    /// Ensures incompatible sub-proofs are rejected.
    #[test]
    fn test_enc_proof_rejects_incompatible_subproofs() {
        let session_id = rng::get_rng().random::<[u8; 32]>();
        let log_base_h = <Scalar as Field>::random(&mut rng::get_rng());
        let generator = <AffinePoint as PrimeCurveAffine>::generator();
        let base_h = (generator * log_base_h).to_affine();
        let scalar = <Scalar as Field>::random(&mut rng::get_rng());
        let bit: bool = rng::get_rng().random();

        let mut proof = EncProof::<TestCurve>::prove(&session_id, &base_h, &scalar, bit);
        proof.proof0.base_g = (generator * Scalar::from(2u32)).to_affine();

        assert!(!proof.verify(&session_id));
    }

    /// Ensures challenge-sum mismatch is rejected.
    #[test]
    fn test_enc_proof_rejects_challenge_sum_mismatch() {
        let session_id = rng::get_rng().random::<[u8; 32]>();
        let log_base_h = <Scalar as Field>::random(&mut rng::get_rng());
        let generator = <AffinePoint as PrimeCurveAffine>::generator();
        let base_h = (generator * log_base_h).to_affine();
        let scalar = <Scalar as Field>::random(&mut rng::get_rng());
        let bit: bool = rng::get_rng().random();

        let mut proof = EncProof::<TestCurve>::prove(&session_id, &base_h, &scalar, bit);
        proof.challenge0 += Scalar::ONE;

        assert!(!proof.verify(&session_id));
    }

    /// Tests that oversized interactive challenges are rejected during verification.
    #[test]
    fn test_interactive_dlog_proof_rejects_oversized_challenge() {
        let generator = <AffinePoint as PrimeCurveAffine>::generator();
        let proof: InteractiveDLogProof<TestCurve> = InteractiveDLogProof {
            challenge: vec![0u8; (T / 8 + 1) as usize],
            challenge_response: <Scalar as Field>::ZERO,
            _curve: PhantomData,
        };
        assert!(!proof.verify(&generator, &generator));
    }

    /// Tests that empty challenges are rejected during verification.
    #[test]
    fn test_interactive_dlog_proof_rejects_empty_challenge() {
        let generator = <AffinePoint as PrimeCurveAffine>::generator();
        let proof: InteractiveDLogProof<TestCurve> = InteractiveDLogProof {
            challenge: vec![],
            challenge_response: <Scalar as Field>::ZERO,
            _curve: PhantomData,
        };
        assert!(!proof.verify(&generator, &generator));
    }
}
