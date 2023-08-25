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

use curv::elliptic::curves::{Secp256k1, Scalar, Point};
use crate::utilities::hashes::*;

// DISCRETE LOGARITHM PROOF
//
// We implement Schnorr's protocol together with a Fiat-Shamir transform.
//
// It is mostly based on curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof
// (see https://docs.rs/curv-kzen/latest/curv/cryptographic_primitives/proofs/sigma_dlog/struct.DLogProof.html).
//
// A similar implementation can be found in https://gitlab.com/neucrypt/mpecdsa/-/blob/release/src/zkpok.rs.
// See also https://github.com/coinbase/kryptology/blob/master/pkg/zkp/schnorr/schnorr.go.
//
// We remark that the DKLs19 paper (https://eprint.iacr.org/2019/523.pdf) attests that
// this is not the most secure implementation (cf. Section 2.3 of the paper).
//
// CONSIDERATIONS FOR THE FUTURE: Change the Fiat-Shamir by a Fischlin transform.

#[derive(Debug, Clone)]
pub struct DLogProof {
    pub point: Point<Secp256k1>,
    pub point_rand_commitment: Point<Secp256k1>,
    pub challenge_response: Scalar<Secp256k1>,
}

impl DLogProof {

    //Proof for discrete logarithm
    //It gives a proof that the sender knows the discrete logarithm of point = scalar * generator (which is scalar).
    pub fn prove(scalar: &Scalar<Secp256k1>, session_id: &[u8]) ->  DLogProof  {
        let generator = Point::<Secp256k1>::generator();
        let point = generator * scalar;

        let scalar_rand_commitment: Scalar<Secp256k1> = Scalar::<Secp256k1>::random();
        let point_rand_commitment = generator * &scalar_rand_commitment;

        //Conversion of points to bytes
        let point_as_bytes = point_to_bytes(&point);
        let point_rc_as_bytes = point_to_bytes(&point_rand_commitment);

        let msg_for_challenge = [point_as_bytes, point_rc_as_bytes].concat();
        let challenge = hash_as_scalar(&msg_for_challenge, session_id);

        let challenge_mul_scalar = challenge * scalar;
        let challenge_response = &scalar_rand_commitment - &challenge_mul_scalar;

        DLogProof {
            point,
            point_rand_commitment,
            challenge_response,
        }
    }

    //Verification of a proof of discrete logarithm. Note that the point to be verified is in proof.
    pub fn verify(proof: &DLogProof, session_id: &[u8]) -> bool {

        //First, we recompute the challenge from the proof
        let point_as_bytes = point_to_bytes(&proof.point);
        let point_rc_as_bytes = point_to_bytes(&proof.point_rand_commitment);

        let msg_for_challenge = [point_as_bytes, point_rc_as_bytes].concat();
        let challenge = hash_as_scalar(&msg_for_challenge, session_id);

        //We cannot calculate the challenge_response by ourselves (we don't have scalar neither scalar_rand_commitment),
        //but we can compute challenge_response * generator as point_rand_commitment - challenge * point.
        //Equivalently, we compute point_rand_commitment in an alternative way, which should agree with the known value.
        let generator = Point::<Secp256k1>::generator();
        let point_challenge = &proof.point * &challenge;
        let point_verifier = (generator * &proof.challenge_response) + point_challenge;

        point_verifier == proof.point_rand_commitment
    }

    //Proof with commitment (which is a hash)
    pub fn prove_commit(scalar: &Scalar<Secp256k1>, session_id: &[u8]) -> (DLogProof, HashOutput) {
        let proof = Self::prove(scalar, session_id);

        //Computes the commitment (it's the hash of the concatenation of point_rand_commitment and challenge_response).
        let point_rc_as_bytes = point_to_bytes(&proof.point_rand_commitment);
        let challenge_r_as_bytes = scalar_to_bytes(&proof.challenge_response);
        let msg_for_commitment = [point_rc_as_bytes, challenge_r_as_bytes].concat();
        let commitment = hash(&msg_for_commitment, session_id);

        (proof, commitment)
    }

    //Verify a proof checking the commitment
    pub fn decommit_verify(proof: &DLogProof, commitment: &HashOutput, session_id: &[u8]) -> bool {

        //Computes the expected commitment
        let point_rc_as_bytes = point_to_bytes(&proof.point_rand_commitment);
        let challenge_r_as_bytes = scalar_to_bytes(&proof.challenge_response);
        let msg_for_commitment = [point_rc_as_bytes, challenge_r_as_bytes].concat();
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
pub struct RandomCommitments {
    pub rc_g: Point<Secp256k1>,
    pub rc_h: Point<Secp256k1>,
}

pub struct CPProof {
    pub base_g: Point<Secp256k1>,   // Parameters for the proof.
    pub base_h: Point<Secp256k1>,   // In the encryption proof, base_g = generator.
    pub point_u: Point<Secp256k1>,
    pub point_v: Point<Secp256k1>,

    pub challenge_response: Scalar<Secp256k1>,
}

impl CPProof {

    // We need a proof that scalar * base_g = point_u and scalar * base_h = point_v.
    // As we will see later, the challenge will not be calculated only with the data
    // we now have. Thus, we have to write the interactive version here for the moment.
    // This means that the challenge is a parameter chosen by the verifier and is not
    // calculated via Fiat-Shamir.

    // Step 1 - Sample the random commitments.
    pub fn prove_step1(base_g: &Point<Secp256k1>, base_h: &Point<Secp256k1>) -> (Scalar<Secp256k1>, RandomCommitments) {
        let scalar_rand_commitment = Scalar::<Secp256k1>::random();

        let point_rand_commitment_g = base_g * &scalar_rand_commitment;
        let point_rand_commitment_h = base_h * &scalar_rand_commitment;

        let rand_commitments = RandomCommitments {
            rc_g: point_rand_commitment_g,
            rc_h: point_rand_commitment_h,
        };

        (scalar_rand_commitment, rand_commitments)
    }

    // Step 2 - Compute the response for a given challenge.
    // Here, scalar is the witness for the proof.
    pub fn prove_step2(base_g: &Point<Secp256k1>, base_h: &Point<Secp256k1>, scalar: &Scalar<Secp256k1>, scalar_rand_commitment: &Scalar<Secp256k1>, challenge: &Scalar<Secp256k1>) -> CPProof {

        // We get u and v.
        let point_u = base_g * scalar;
        let point_v = base_h * scalar;

        // We compute the response.
        let challenge_response = scalar_rand_commitment - (challenge * scalar);

        CPProof {
            base_g: base_g.clone(),
            base_h: base_h.clone(),
            point_u,
            point_v,

            challenge_response,
        }
    }

    // Verification of a proof. Note that the data to be verified is in the variable proof.
    // The verifier must know the challenge (in the interactive version, he chooses it).
    pub fn verify(&self, rand_commitments: &RandomCommitments, challenge: &Scalar<Secp256k1>) -> bool {

        // We compare the values that should agree.
        let point_verify_g = (&self.base_g * &self.challenge_response) + (&self.point_u * challenge);
        let point_verify_h = (&self.base_h * &self.challenge_response) + (&self.point_v * challenge);

        (point_verify_g == rand_commitments.rc_g) && (point_verify_h == rand_commitments.rc_h)
    }

    // For the OR-composition, we will need to be able to simulate a proof without having
    // a witness. The only way to do this is to sample the challenge ourselves and use it
    // to compute the other values. We then return the challenge used, the commitments
    // and the corresponding proof.
    pub fn simulate(base_g: &Point<Secp256k1>, base_h: &Point<Secp256k1>, point_u: &Point<Secp256k1>, point_v: &Point<Secp256k1>) -> (RandomCommitments, Scalar<Secp256k1>, CPProof){

        // We sample the challenge and the response first.
        let challenge = Scalar::<Secp256k1>::random();
        let challenge_response = Scalar::<Secp256k1>::random();

        // Now we compute the "random" commitments that work for this challenge.
        let point_rand_commitment_g = (base_g * &challenge_response) + (point_u * &challenge);
        let point_rand_commitment_h = (base_h * &challenge_response) + (point_v * &challenge);

        let rand_commitments = RandomCommitments {
            rc_g: point_rand_commitment_g,
            rc_h: point_rand_commitment_h,
        };

        let proof = CPProof {
            base_g: base_g.clone(),
            base_h: base_h.clone(),
            point_u: point_u.clone(),
            point_v: point_v.clone(),

            challenge_response,
        };

        (rand_commitments, challenge, proof)
    }

}

// The actual proof for the OT protocol.
pub struct EncProof {
    pub proof0: CPProof,    // EncProof is a proof that proof0 or proof1
    pub proof1: CPProof,    // really proves what it says.

    pub commitments0: RandomCommitments,
    pub commitments1: RandomCommitments,

    pub challenge0: Scalar<Secp256k1>,
    pub challenge1: Scalar<Secp256k1>,
}

impl EncProof {

    pub fn prove(session_id: &[u8], base_h: &Point<Secp256k1>, scalar: &Scalar<Secp256k1>, bit: bool) -> EncProof {
        
        // PRELIMINARIES

        // g is the generator in this case.
        let base_g = Point::<Secp256k1>::generator();

        // We compute u and v from Section 3 in the paper.
        // Be careful: these are not point_u and point_v from CPProof.
       
       // u is independent of the bit chosen.
        let u = base_h * scalar;
        
        // v = h*bit + g*scalar.
        // The other possible value for v will be used in a simulated proof.
        // See below for a better explanation.
        let (v, fake_v) = if bit {
            ((base_g * scalar) + base_h, (base_g * scalar) + base_h)
        } else {
            (base_g * scalar, (base_g * scalar) - base_h)
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
        let (fake_commitments, fake_challenge, fake_proof) = CPProof::simulate(&base_g, base_h, &fake_v, &u);

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
            [base_h_as_bytes, u_as_bytes, v_as_bytes, f_rc_g_as_bytes, f_rc_h_as_bytes, r_rc_g_as_bytes, r_rc_h_as_bytes].concat()
        } else {
            [base_h_as_bytes, u_as_bytes, v_as_bytes, r_rc_g_as_bytes, r_rc_h_as_bytes, f_rc_g_as_bytes, f_rc_h_as_bytes].concat()
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

        let real_proof = CPProof::prove_step2(&base_g, base_h, scalar, &real_scalar_commitment, &real_challenge);

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
        if (self.proof0.base_g != Point::<Secp256k1>::generator())
        || (self.proof0.base_g != self.proof1.base_g)
        || (self.proof0.base_h != self.proof1.base_h)
        || (self.proof0.point_v != self.proof1.point_v) // This is u from Section 3 in the paper.
        || (self.proof0.point_u != (&self.proof1.point_u + &self.proof1.base_h))    // proof0 contains v and proof1 contains v-h.
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

        let msg_for_challenge = [base_h_as_bytes, u_as_bytes, v_as_bytes, rc0_g_as_bytes, rc0_h_as_bytes, rc1_g_as_bytes, rc1_h_as_bytes].concat();
        let expected_challenge = hash_as_scalar(&msg_for_challenge, session_id);

        // The challenge should be the sum of the challenges used in the proofs.
        if expected_challenge != &self.challenge0 + &self.challenge1 {
            return false;
        }

        // Finally, we check if both proofs are valid.
        self.proof0.verify(&self.commitments0, &self.challenge0) && self.proof1.verify(&self.commitments1, &self.challenge1)
    }

    // For convenience and to avoid confusion with the change of order.
    pub fn get_u_and_v(&self) -> (Point<Secp256k1>, Point<Secp256k1>) {
        (self.proof0.point_v.clone(), self.proof0.point_u.clone())
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    // DLogProof

    #[test]
    fn test_dlog_proof() {
        let scalar = Scalar::random();
        let session_id = rand::thread_rng().gen::<[u8; 32]>();
        let proof = DLogProof::prove(&scalar, &session_id);
        assert!(DLogProof::verify(&proof, &session_id));
    }

    #[test]
    fn test_dlog_proof_fail_proof() {
        let scalar = Scalar::random();
        let session_id = rand::thread_rng().gen::<[u8; 32]>();
        let mut proof = DLogProof::prove(&scalar, &session_id);
        proof.challenge_response = proof.challenge_response * Scalar::from(2); //Changing the proof
        assert!(!(DLogProof::verify(&proof, &session_id)));
    }

    #[test]
    fn test_dlog_proof_commit() {
        let scalar = Scalar::random();
        let session_id = rand::thread_rng().gen::<[u8; 32]>();
        let (proof, commitment) = DLogProof::prove_commit(&scalar, &session_id);
        assert!(DLogProof::decommit_verify(&proof, &commitment, &session_id));
    }

    #[test]
    fn test_dlog_proof_commit_fail_proof() {
        let scalar = Scalar::random();
        let session_id = rand::thread_rng().gen::<[u8; 32]>();
        let (mut proof, commitment) = DLogProof::prove_commit(&scalar, &session_id);
        proof.challenge_response = proof.challenge_response * Scalar::from(2); //Changing the proof
        assert!(!(DLogProof::decommit_verify(&proof, &commitment, &session_id)));
    }

    #[test]
    fn test_dlog_proof_commit_fail_commitment() {
        let scalar = Scalar::random();
        let session_id = rand::thread_rng().gen::<[u8; 32]>();
        let (proof, mut commitment) = DLogProof::prove_commit(&scalar, &session_id);
        commitment[0] += 1; //Changing the commitment
        assert!(!(DLogProof::decommit_verify(&proof, &commitment, &session_id)));
    }

    // CPProof

    #[test]
    fn test_cp_proof() {
        let log_base_g = Scalar::<Secp256k1>::random();
        let log_base_h = Scalar::<Secp256k1>::random();
        let scalar = Scalar::<Secp256k1>::random();

        let generator = Point::<Secp256k1>::generator();
        let base_g = generator * log_base_g;
        let base_h = generator * log_base_h;

        // Prover - Step 1.
        let (scalar_rand_commitment, rand_commitments) = CPProof::prove_step1(&base_g, &base_h);

        // Verifier - Gather the commitments and choose the challenge.
        let challenge = Scalar::<Secp256k1>::random();

        // Prover - Step 2.
        let proof = CPProof::prove_step2(&base_g, &base_h, &scalar, &scalar_rand_commitment, &challenge);

        // Verifier verifies the proof.
        let verification = proof.verify(&rand_commitments, &challenge);

        assert!(verification);
    }

    #[test]
    fn test_cp_proof_simulate() {
        let log_base_g = Scalar::<Secp256k1>::random();
        let log_base_h = Scalar::<Secp256k1>::random();
        let log_point_u = Scalar::<Secp256k1>::random();
        let log_point_v = Scalar::<Secp256k1>::random();

        let generator = Point::<Secp256k1>::generator();
        let base_g = generator * log_base_g;
        let base_h = generator * log_base_h;
        let point_u = generator * log_point_u;
        let point_v = generator * log_point_v;

        // Simulation.
        let (rand_commitments, challenge, proof) = CPProof::simulate(&base_g, &base_h, &point_u, &point_v);

        let verification = proof.verify(&rand_commitments, &challenge);

        assert!(verification);
    }

    #[test]

    fn test_enc_proof() {

        // We sample the initial values.
        let session_id = rand::thread_rng().gen::<[u8; 32]>();

        let log_base_h = Scalar::<Secp256k1>::random();
        let base_h = Point::<Secp256k1>::generator() * log_base_h;

        let scalar = Scalar::<Secp256k1>::random();

        let bit: bool = rand::random();

        // Proving.
        let proof = EncProof::prove(&session_id, &base_h, &scalar, bit);

        // Verifying.
        let verification = proof.verify(&session_id);

        assert!(verification);
    }

}