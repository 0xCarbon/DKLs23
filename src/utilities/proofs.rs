/// This file implements some protocols for zero-knowledge proofs over the
/// curve secp256k1.
///
/// The main protocol is for proofs of discrete logarithms. It is used during
/// key generation in the DKLs23 protocol (https://eprint.iacr.org/2023/765.pdf).
///
/// For the base OTs in the OT extension, we use the endemic protocol of Zhou et al.
/// (see Section 3 of https://eprint.iacr.org/2023/765.pdf). Thus, we also include
/// another zero knowledge proof employing the Chaum-Pedersen protocol, the
/// OR-composition and the Fiat-Shamir transform (as in their paper).
use k256::{AffinePoint, ProjectivePoint, Scalar, U256};
use k256::elliptic_curve::{ops::Reduce, Field};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::utilities::hashes::*;

// Constants for the randomized Fischlin transform.
pub const R: usize = 64;
pub const L: usize = 4;
pub const T: usize = 32;

// DISCRETE LOGARITHM PROOF
//
// We implement Schnorr's protocol together with a randomized Fischlin transform.
//
// We base our implementation on Figures 23 and 27 of https://eprint.iacr.org/2022/1525.pdf.
//
// For convinience, instead of writing the protocol directly, we wrote first an
// implementation of the usual Schnorr's protocol, which is interactive. Since
// it will be used for the non-interactive version, we made same particular choices
// that would not make much sense if this interactive proof were used alone.

// Schnorr's protocol (interactive).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InteractiveDLogProof {
    pub challenge: Vec<u8>,
    pub challenge_response: Scalar,
}

impl InteractiveDLogProof {
    // Step 1 - Sample the random commitments.
    pub fn prove_step1() -> (Scalar, AffinePoint) {

        // We sample a nonzero random scalar.
        let mut scalar_rand_commitment = Scalar::ZERO;
        while scalar_rand_commitment == Scalar::ZERO {
            scalar_rand_commitment = Scalar::random(rand::thread_rng());
        }

        let point_rand_commitment = (AffinePoint::GENERATOR * &scalar_rand_commitment).to_affine();

        (scalar_rand_commitment, point_rand_commitment)
    }

    // Step 2 - Compute the response for a given challenge.
    // Here, scalar is the witness for the proof.
    pub fn prove_step2(
        scalar: &Scalar,
        scalar_rand_commitment: &Scalar,
        challenge: &[u8],
    ) -> InteractiveDLogProof {
        // For convenience, we are using a challenge in bytes.
        // We convert it back to a scalar.
        // The challenge will have T bits, so we first extend it to 256 bits.
        let mut extended = vec![0u8; 32 - T / 8];
        extended.extend_from_slice(challenge);

        let challenge_scalar = Scalar::reduce(U256::from_be_slice(&extended));

        // We compute the response.
        let challenge_response = scalar_rand_commitment - &(challenge_scalar * scalar);

        InteractiveDLogProof {
            challenge: challenge.to_vec(), // We save the challenge for the next protocol.
            challenge_response,
        }
    }

    // Verification of a proof. "point" is the point used for the proof.
    // We didn't include it in the struct in order to not make unnecessary
    // repetitions in the next protocol.
    //
    // Attention: the challenge should enter as a parameter here, but in the
    // next protocol, it will come from the prover, so we decided to save it
    // inside the struct.
    pub fn verify(&self, point: &AffinePoint, point_rand_commitment: &AffinePoint) -> bool {
        // For convenience, we are using a challenge in bytes.
        // We convert it back to a scalar.
        // The challenge will have T bits, so we first extend it to 256 bits.
        let mut extended = vec![0u8; 32 - T / 8];
        extended.extend_from_slice(&self.challenge);

        let challenge_scalar = Scalar::reduce(U256::from_be_slice(&extended));

        // We compare the values that should agree.
        let point_verify = ((AffinePoint::GENERATOR * &self.challenge_response)
            + (*point * &challenge_scalar))
            .to_affine();

        point_verify == *point_rand_commitment
    }
}

// Schnorr's protocol (non-interactive via randomized Fischlin transform).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DLogProof {
    pub point: AffinePoint,
    pub rand_commitments: Vec<AffinePoint>,
    pub proofs: Vec<InteractiveDLogProof>,
}

impl DLogProof {
    // Non-interactive version of the previous proof.
    //
    // In order to do so, we employ the "randomized Fischlin transform" described
    // in Figure 9 of https://eprint.iacr.org/2022/393.pdf. However, we will
    // follow the approach in Figure 27 of https://eprint.iacr.org/2022/1525.pdf.
    // It seems to come from Section 5.1 of the first paper. There are some errors
    // in this description (for example, xi_i and xi_{i+r/2} are always the empty set),
    // and thus we adapt Figure 9 of the first article. There is still a problem:
    // the paper says to choose r and l such that, in particular, rl = 2^lambda.
    // If lambda = 256, then r or l are astronomically large and the protocol becomes
    // computationally infeasible. We will use instead the condition rl = lambda.
    // We believe this is what the authors wanted, since this condition appears
    // in most of the rest of the first paper.
    //
    // With lamdba = 256, we chose r = 64 and l = 4 (higher values of l were too slow).
    // In this case, the constant t from the paper is equal to 32.
    pub fn prove(scalar: &Scalar, session_id: &[u8]) -> DLogProof {
        // We execute Step 1 r times.
        let mut rand_commitments: Vec<AffinePoint> = Vec::with_capacity(R);
        let mut states: Vec<Scalar> = Vec::with_capacity(R);
        for _ in 0..R {
            let (state, rand_commitment) = InteractiveDLogProof::prove_step1();

            rand_commitments.push(rand_commitment);
            states.push(state);
        }

        // We save this vector in bytes.
        let rc_as_bytes = rand_commitments
            .clone()
            .into_iter()
            .map(|x| point_to_bytes(&x))
            .collect::<Vec<Vec<u8>>>()
            .concat();

        // Now, there is a "proof of work".
        // We have to find the good challenges.
        let mut first_proofs: Vec<InteractiveDLogProof> = Vec::with_capacity(R / 2);
        let mut last_proofs: Vec<InteractiveDLogProof> = Vec::with_capacity(R / 2);
        for i in 0..(R / 2) {
            // We will find different challenges until one of them works.
            // Since both hashes to be computed are of 2l bits, we expect
            // them to coincide after 2^{2l} tries (assuming everything is
            // uniformally random and independent). For l = 4, this is just
            // 256 tries. For safety, we will put a large margin and repeat
            // each while at most 2^16 times (so 2^32 tries in total).

            let mut flag = false;
            let mut first_counter = 0u16;
            while first_counter < u16::MAX && !flag {
                // We sample an array of T bits = T/8 bytes.
                let first_challenge = rand::thread_rng().gen::<[u8; T / 8]>();

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
                let first_proof =
                    InteractiveDLogProof::prove_step2(scalar, &states[i], &first_challenge);

                // Let's take the first hash here.
                let first_msg = [
                    &point_to_bytes(&AffinePoint::GENERATOR),
                    &rc_as_bytes[..],
                    &(i as u8).to_be_bytes(),
                    &first_challenge,
                    &scalar_to_bytes(&first_proof.challenge_response),
                ]
                .concat();
                // The random oracle has to return an array of 2l bits = l/4 bytes, so we take a slice.
                let first_hash = &hash(&first_msg, session_id)[0..(L / 4)];

                // Now comes the search for the next challenge.
                let mut second_counter = 0u16;
                while second_counter < u16::MAX {
                    // We sample another array. Same considerations as before.
                    let second_challenge = rand::thread_rng().gen::<[u8; T / 8]>();
                    //if used_second_challenges.contains(&second_challenge) { continue; }

                    // We execute Step 2 at index i + R/2.
                    let second_proof = InteractiveDLogProof::prove_step2(
                        scalar,
                        &states[i + (R / 2)],
                        &second_challenge,
                    );

                    // Second hash now.
                    let second_msg = [
                        &point_to_bytes(&AffinePoint::GENERATOR),
                        &rc_as_bytes[..],
                        &((i + (R / 2)) as u8).to_be_bytes(),
                        &second_challenge,
                        &scalar_to_bytes(&second_proof.challenge_response),
                    ]
                    .concat();
                    let second_hash = &hash(&second_msg, session_id)[0..(L / 4)];

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
        let point = (AffinePoint::GENERATOR * scalar).to_affine();

        DLogProof {
            point,
            rand_commitments,
            proofs,
        }
    }

    //Verification of a proof of discrete logarithm. Note that the point to be verified is in proof.
    pub fn verify(proof: &DLogProof, session_id: &[u8]) -> bool {
        // We first verify that all vectors have the correct length.
        // If the prover is very unlucky, there is the possibility that
        // he doesn't return all the needed proofs.
        if proof.rand_commitments.len() != R || proof.proofs.len() != R {
            return false;
        }

        // We transform the random commitments into bytes.
        let vec_rc_as_bytes = proof
            .rand_commitments
            .clone()
            .into_iter()
            .map(|x| point_to_bytes(&x))
            .collect::<Vec<Vec<u8>>>();

        // All the proofs should be different (otherwise, it would be easier to forge a proof).
        // Here we compare the random commitments using a HashSet.
        let mut without_repetitions: HashSet<Vec<u8>> = HashSet::with_capacity(R);
        if !vec_rc_as_bytes.clone().into_iter().all(move |x| without_repetitions.insert(x)) {
            return false;
        }

        // We concatenate the vector of random commitments.
        let rc_as_bytes = vec_rc_as_bytes.concat();

        for i in 0..(R / 2) {
            // We compare the hashes
            let first_msg = [
                &point_to_bytes(&AffinePoint::GENERATOR),
                &rc_as_bytes[..],
                &(i as u8).to_be_bytes(),
                &proof.proofs[i].challenge,
                &scalar_to_bytes(&proof.proofs[i].challenge_response),
            ]
            .concat();
            let first_hash = &hash(&first_msg, session_id)[0..(L / 4)];

            let second_msg = [
                &point_to_bytes(&AffinePoint::GENERATOR),
                &rc_as_bytes[..],
                &((i + (R / 2)) as u8).to_be_bytes(),
                &proof.proofs[i + (R / 2)].challenge,
                &scalar_to_bytes(&proof.proofs[i + (R / 2)].challenge_response),
            ]
            .concat();
            let second_hash = &hash(&second_msg, session_id)[0..(L / 4)];

            if *first_hash != *second_hash {
                return false;
            }

            // We verify both proofs.
            let verification_1 = proof.proofs[i].verify(&proof.point, &proof.rand_commitments[i]);
            let verification_2 = proof.proofs[i + (R / 2)]
                .verify(&proof.point, &proof.rand_commitments[i + (R / 2)]);

            if !verification_1 || !verification_2 {
                return false;
            }
        }

        // If we got here, all the previous tests passed.
        true
    }

    //Proof with commitment (which is a hash)
    pub fn prove_commit(scalar: &Scalar, session_id: &[u8]) -> (DLogProof, HashOutput) {
        let proof = Self::prove(scalar, session_id);

        //Computes the commitment (it's the hash of DLogProof in bytes).
        let point_as_bytes = point_to_bytes(&proof.point);
        let rc_as_bytes = proof
            .rand_commitments
            .clone()
            .into_iter()
            .map(|x| point_to_bytes(&x))
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
            .map(|x| scalar_to_bytes(&x.challenge_response))
            .collect::<Vec<Vec<u8>>>()
            .concat();

        let msg_for_commitment = [
            point_as_bytes,
            rc_as_bytes,
            challenges_as_bytes,
            responses_as_bytes,
        ]
        .concat();
        let commitment = hash(&msg_for_commitment, session_id);

        (proof, commitment)
    }

    //Verify a proof checking the commitment
    pub fn decommit_verify(proof: &DLogProof, commitment: &HashOutput, session_id: &[u8]) -> bool {
        //Computes the expected commitment
        let point_as_bytes = point_to_bytes(&proof.point);
        let rc_as_bytes = proof
            .rand_commitments
            .clone()
            .into_iter()
            .map(|x| point_to_bytes(&x))
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
            .map(|x| scalar_to_bytes(&x.challenge_response))
            .collect::<Vec<Vec<u8>>>()
            .concat();

        let msg_for_commitment = [
            point_as_bytes,
            rc_as_bytes,
            challenges_as_bytes,
            responses_as_bytes,
        ]
        .concat();
        let expected_commitment = hash(&msg_for_commitment, session_id);

        (*commitment == expected_commitment) && Self::verify(proof, session_id)
    }
}

// ENCRYPTION PROOF
//
// The OT protocol of Zhou et al. uses an ElGamal encryption at some point
// and it needs a zero-knowledge proof to verify its correctness.
//
// This implementation follows their paper (https://eprint.iacr.org/2022/1525.pdf):
// see page 17 and Appendix B.
//
//
// IMPORTANT: As specified in page 30 of DKLs23 (https://eprint.iacr.org/2023/765.pdf),
// we instantiate the protocols above over the same elliptic curve group
// used in our main protocol.

// We start with the Chaum-Pedersen protocol (interactive version).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RandomCommitments {
    pub rc_g: AffinePoint,
    pub rc_h: AffinePoint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CPProof {
    pub base_g: AffinePoint, // Parameters for the proof.
    pub base_h: AffinePoint, // In the encryption proof, base_g = generator.
    pub point_u: AffinePoint,
    pub point_v: AffinePoint,

    pub challenge_response: Scalar,
}

impl CPProof {
    // We need a proof that scalar * base_g = point_u and scalar * base_h = point_v.
    // As we will see later, the challenge will not be calculated only with the data
    // we now have. Thus, we have to write the interactive version here for the moment.
    // This means that the challenge is a parameter chosen by the verifier and is not
    // calculated via Fiat-Shamir.

    // Step 1 - Sample the random commitments.
    pub fn prove_step1(base_g: &AffinePoint, base_h: &AffinePoint) -> (Scalar, RandomCommitments) {
        
        // We sample a nonzero random scalar.
        let mut scalar_rand_commitment = Scalar::ZERO;
        while scalar_rand_commitment == Scalar::ZERO {
            scalar_rand_commitment = Scalar::random(rand::thread_rng());
        }

        let point_rand_commitment_g = (*base_g * &scalar_rand_commitment).to_affine();
        let point_rand_commitment_h = (*base_h * &scalar_rand_commitment).to_affine();

        let rand_commitments = RandomCommitments {
            rc_g: point_rand_commitment_g,
            rc_h: point_rand_commitment_h,
        };

        (scalar_rand_commitment, rand_commitments)
    }

    // Step 2 - Compute the response for a given challenge.
    // Here, scalar is the witness for the proof.
    pub fn prove_step2(
        base_g: &AffinePoint,
        base_h: &AffinePoint,
        scalar: &Scalar,
        scalar_rand_commitment: &Scalar,
        challenge: &Scalar,
    ) -> CPProof {
        // We get u and v.
        let point_u = (*base_g * scalar).to_affine();
        let point_v = (*base_h * scalar).to_affine();

        // We compute the response.
        let challenge_response = scalar_rand_commitment - &(challenge * scalar);

        CPProof {
            base_g: *base_g,
            base_h: *base_h,
            point_u,
            point_v,

            challenge_response,
        }
    }

    // Verification of a proof. Note that the data to be verified is in the variable proof.
    // The verifier must know the challenge (in the interactive version, he chooses it).
    pub fn verify(&self, rand_commitments: &RandomCommitments, challenge: &Scalar) -> bool {
        // We compare the values that should agree.
        let point_verify_g =
            ((self.base_g * &self.challenge_response) + (self.point_u * challenge)).to_affine();
        let point_verify_h =
            ((self.base_h * &self.challenge_response) + (self.point_v * challenge)).to_affine();

        (point_verify_g == rand_commitments.rc_g) && (point_verify_h == rand_commitments.rc_h)
    }

    // For the OR-composition, we will need to be able to simulate a proof without having
    // a witness. The only way to do this is to sample the challenge ourselves and use it
    // to compute the other values. We then return the challenge used, the commitments
    // and the corresponding proof.
    pub fn simulate(
        base_g: &AffinePoint,
        base_h: &AffinePoint,
        point_u: &AffinePoint,
        point_v: &AffinePoint,
    ) -> (RandomCommitments, Scalar, CPProof) {
        // We sample the challenge and the response first.
        let challenge = Scalar::random(rand::thread_rng());
        let challenge_response = Scalar::random(rand::thread_rng());

        // Now we compute the "random" commitments that work for this challenge.
        let point_rand_commitment_g =
            ((*base_g * &challenge_response) + (*point_u * &challenge)).to_affine();
        let point_rand_commitment_h =
            ((*base_h * &challenge_response) + (*point_v * &challenge)).to_affine();

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

// The actual proof for the OT protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncProof {
    pub proof0: CPProof, // EncProof is a proof that proof0 or proof1
    pub proof1: CPProof, // really proves what it says.

    pub commitments0: RandomCommitments,
    pub commitments1: RandomCommitments,

    pub challenge0: Scalar,
    pub challenge1: Scalar,
}

impl EncProof {
    pub fn prove(session_id: &[u8], base_h: &AffinePoint, scalar: &Scalar, bit: bool) -> EncProof {
        // PRELIMINARIES

        // g is the generator in this case.
        let base_g = AffinePoint::GENERATOR;

        // We compute u and v from Section 3 in the paper.
        // Be careful: these are not point_u and point_v from CPProof.

        // u is independent of the bit chosen.
        let u = (*base_h * scalar).to_affine();

        // v = h*bit + g*scalar.
        // The other possible value for v will be used in a simulated proof.
        // See below for a better explanation.
        let (v, fake_v) = if bit {
            (
                ((base_g * scalar) + base_h).to_affine(),
                ((base_g * scalar) + base_h).to_affine(),
            )
        } else {
            (
                (base_g * scalar).to_affine(),
                ((base_g * scalar) - base_h).to_affine(),
            )
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

        let base_h_as_bytes = point_to_bytes(base_h);
        let u_as_bytes = point_to_bytes(&u);
        let v_as_bytes = point_to_bytes(&v);

        let r_rc_g_as_bytes = point_to_bytes(&real_commitments.rc_g);
        let r_rc_h_as_bytes = point_to_bytes(&real_commitments.rc_h);

        let f_rc_g_as_bytes = point_to_bytes(&fake_commitments.rc_g);
        let f_rc_h_as_bytes = point_to_bytes(&fake_commitments.rc_h);

        // The proof that comes first is always the one containg u and v.
        // If bit = 0, it is the real proof, otherwise it is the fake one.
        // For the message, we first put the commitments for the first proof
        // since the verifier does not know which proof is the real one.
        let msg_for_challenge = if bit {
            [
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

        let challenge = hash_as_scalar(&msg_for_challenge, session_id);

        // STEP 3
        // We compute the real challenge for our real proof.
        // Note that it depends on the challenge above. This
        // is why we cannot simply fake both proofs. With this
        // challenge, we can finish the real proof.

        // ATTENTION: The original paper says that the challenge
        // should be the XOR of the real and fake challenges.
        // However, it is easier and essentially equivalent to
        // impose that challenge = real + fake as scalars.

        let real_challenge = &challenge - &fake_challenge;

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

    pub fn verify(&self, session_id: &[u8]) -> bool {
        // We check if the proofs are compatible.
        if (self.proof0.base_g != AffinePoint::GENERATOR)
        || (self.proof0.base_g != self.proof1.base_g)
        || (self.proof0.base_h != self.proof1.base_h)
        || (self.proof0.point_v != self.proof1.point_v) // This is u from Section 3 in the paper.
        || (self.proof0.point_u != (ProjectivePoint::from(self.proof1.point_u) + self.proof1.base_h).to_affine())
        // proof0 contains v and proof1 contains v-h.
        {
            return false;
        }

        // Reconstructing the challenge.

        let base_h_as_bytes = point_to_bytes(&self.proof0.base_h);

        // u and v are respectively point_v and point_u from the proof0.
        let u_as_bytes = point_to_bytes(&self.proof0.point_v);
        let v_as_bytes = point_to_bytes(&self.proof0.point_u);

        let rc0_g_as_bytes = point_to_bytes(&self.commitments0.rc_g);
        let rc0_h_as_bytes = point_to_bytes(&self.commitments0.rc_h);

        let rc1_g_as_bytes = point_to_bytes(&self.commitments1.rc_g);
        let rc1_h_as_bytes = point_to_bytes(&self.commitments1.rc_h);

        let msg_for_challenge = [
            base_h_as_bytes,
            u_as_bytes,
            v_as_bytes,
            rc0_g_as_bytes,
            rc0_h_as_bytes,
            rc1_g_as_bytes,
            rc1_h_as_bytes,
        ]
        .concat();
        let expected_challenge = hash_as_scalar(&msg_for_challenge, session_id);

        // The challenge should be the sum of the challenges used in the proofs.
        if expected_challenge != &self.challenge0 + &self.challenge1 {
            return false;
        }

        // Finally, we check if both proofs are valid.
        self.proof0.verify(&self.commitments0, &self.challenge0)
            && self.proof1.verify(&self.commitments1, &self.challenge1)
    }

    // For convenience and to avoid confusion with the change of order.
    pub fn get_u_and_v(&self) -> (AffinePoint, AffinePoint) {
        (self.proof0.point_v, self.proof0.point_u)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // DLogProof

    #[test]
    fn test_dlog_proof() {
        let scalar = Scalar::random(rand::thread_rng());
        let session_id = rand::thread_rng().gen::<[u8; 32]>();
        let proof = DLogProof::prove(&scalar, &session_id);
        assert!(DLogProof::verify(&proof, &session_id));
    }

    #[test]
    fn test_dlog_proof_fail_proof() {
        let scalar = Scalar::random(rand::thread_rng());
        let session_id = rand::thread_rng().gen::<[u8; 32]>();
        let mut proof = DLogProof::prove(&scalar, &session_id);
        proof.proofs[0].challenge_response =
            &proof.proofs[0].challenge_response * &Scalar::from(2u32); //Changing the proof
        assert!(!(DLogProof::verify(&proof, &session_id)));
    }

    #[test]
    fn test_dlog_proof_commit() {
        let scalar = Scalar::random(rand::thread_rng());
        let session_id = rand::thread_rng().gen::<[u8; 32]>();
        let (proof, commitment) = DLogProof::prove_commit(&scalar, &session_id);
        assert!(DLogProof::decommit_verify(&proof, &commitment, &session_id));
    }

    #[test]
    fn test_dlog_proof_commit_fail_proof() {
        let scalar = Scalar::random(rand::thread_rng());
        let session_id = rand::thread_rng().gen::<[u8; 32]>();
        let (mut proof, commitment) = DLogProof::prove_commit(&scalar, &session_id);
        proof.proofs[0].challenge_response =
            &proof.proofs[0].challenge_response * &Scalar::from(2u32); //Changing the proof
        assert!(!(DLogProof::decommit_verify(&proof, &commitment, &session_id)));
    }

    #[test]
    fn test_dlog_proof_commit_fail_commitment() {
        let scalar = Scalar::random(rand::thread_rng());
        let session_id = rand::thread_rng().gen::<[u8; 32]>();
        let (proof, mut commitment) = DLogProof::prove_commit(&scalar, &session_id);
        if commitment[0] == 0 {
            commitment[0] = 1;
        } else {
            commitment[0] -= 1;
        } //Changing the commitment
        assert!(!(DLogProof::decommit_verify(&proof, &commitment, &session_id)));
    }

    // CPProof

    #[test]
    fn test_cp_proof() {
        let log_base_g = Scalar::random(rand::thread_rng());
        let log_base_h = Scalar::random(rand::thread_rng());
        let scalar = Scalar::random(rand::thread_rng());

        let generator = AffinePoint::GENERATOR;
        let base_g = (generator * log_base_g).to_affine();
        let base_h = (generator * log_base_h).to_affine();

        // Prover - Step 1.
        let (scalar_rand_commitment, rand_commitments) = CPProof::prove_step1(&base_g, &base_h);

        // Verifier - Gather the commitments and choose the challenge.
        let challenge = Scalar::random(rand::thread_rng());

        // Prover - Step 2.
        let proof = CPProof::prove_step2(
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

    #[test]
    fn test_cp_proof_simulate() {
        let log_base_g = Scalar::random(rand::thread_rng());
        let log_base_h = Scalar::random(rand::thread_rng());
        let log_point_u = Scalar::random(rand::thread_rng());
        let log_point_v = Scalar::random(rand::thread_rng());

        let generator = AffinePoint::GENERATOR;
        let base_g = (generator * log_base_g).to_affine();
        let base_h = (generator * log_base_h).to_affine();
        let point_u = (generator * log_point_u).to_affine();
        let point_v = (generator * log_point_v).to_affine();

        // Simulation.
        let (rand_commitments, challenge, proof) =
            CPProof::simulate(&base_g, &base_h, &point_u, &point_v);

        let verification = proof.verify(&rand_commitments, &challenge);

        assert!(verification);
    }

    // EncProof

    #[test]
    fn test_enc_proof() {
        // We sample the initial values.
        let session_id = rand::thread_rng().gen::<[u8; 32]>();

        let log_base_h = Scalar::random(rand::thread_rng());
        let base_h = (AffinePoint::GENERATOR * log_base_h).to_affine();

        let scalar = Scalar::random(rand::thread_rng());

        let bit: bool = rand::random();

        // Proving.
        let proof = EncProof::prove(&session_id, &base_h, &scalar, bit);

        // Verifying.
        let verification = proof.verify(&session_id);

        assert!(verification);
    }
}
