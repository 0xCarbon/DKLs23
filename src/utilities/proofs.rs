/// This file implements a protocol with commitment for zero-knowledge proof of discrete logarithms over the
/// curve secp256k1
///
/// It is mostly based on curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof
/// (see https://docs.rs/curv-kzen/latest/curv/cryptographic_primitives/proofs/sigma_dlog/struct.DLogProof.html)
///
/// A similar implementation can be found in https://gitlab.com/neucrypt/mpecdsa/-/blob/release/src/zkpok.rs
/// See also https://github.com/coinbase/kryptology/blob/master/pkg/zkp/schnorr/schnorr.go
///
/// We remark that the DKLs19 paper (https://eprint.iacr.org/2019/523.pdf) attests that this is not the
/// most secure implementation (cf. Section 2.3 of the paper).

use curv::elliptic::curves::{Secp256k1, Scalar, Point};
use crate::utilities::hashes::*;

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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

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
}