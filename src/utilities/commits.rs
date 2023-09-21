/// This file implements the commitment functionality needed for `DKLs23`.
/// We follow the approach suggested on page 7 of the paper.

use crate::utilities::hashes::{HashOutput, hash, point_to_bytes};
use k256::AffinePoint;
use rand::Rng;

//Computational security parameter lambda_c from DKLs23 (divided by 8)
use crate::SECURITY;

//Given a message, this function generates a random salt of size 2*lambda_c
//and computes the corresponding commitment.
//The sender should first communicate the commitment. When he wants to decommit,
//he sends the message together with the salt.
#[must_use]
pub fn commit(msg: &[u8]) -> (HashOutput, Vec<u8>) {

    //The paper instructs the salt to have 2*lambda_c bits.
    let salt1 = rand::thread_rng().gen::<[u8; SECURITY as usize]>(); //This function doesn't work for higher SECURITY.
    let salt2 = rand::thread_rng().gen::<[u8; SECURITY as usize]>(); //However, we don't expect SECURITY to be changed.
    let salt = [salt1, salt2].concat();

    let commitment = hash(msg, &salt);

    (commitment, salt)
}

//After having received the commitment and later the message and the salt, the receiver
//should verify if these data are compatible.
#[must_use]
pub fn verify_commitment(msg: &[u8], commitment: &HashOutput, salt: &[u8]) -> bool {
    let expected_commitment = hash(msg, salt);
    *commitment == expected_commitment
}

//During the signing protocol, parties should be able to commit to points on the elliptic curve.
//Thus, for convenience, we adapt the previous functions to this case.
#[must_use]
pub fn commit_point(point: &AffinePoint) -> (HashOutput, Vec<u8>) {
    let point_as_bytes = point_to_bytes(point);
    commit(&point_as_bytes)
}

#[must_use]
pub fn verify_commitment_point(point: &AffinePoint, commitment: &HashOutput, salt: &[u8]) -> bool {
    let point_as_bytes = point_to_bytes(point);
    verify_commitment(&point_as_bytes, commitment, salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit_decommit() {
        let msg = rand::thread_rng().gen::<[u8; 32]>();
        let (commitment, salt) = commit(&msg);
        assert!(verify_commitment(&msg, &commitment, &salt));
    }

    #[test]
    fn test_commit_decommit_fail_msg() {
        let msg = rand::thread_rng().gen::<[u8; 32]>();
        let (commitment, salt) = commit(&msg);
        let msg = rand::thread_rng().gen::<[u8; 32]>(); //We change the message
        assert!(!(verify_commitment(&msg, &commitment, &salt)));  //The test can fail but with very low probability
    }

    #[test]
    fn test_commit_decommit_fail_commitment() {
        let msg = rand::thread_rng().gen::<[u8; 32]>();
        let (_, salt) = commit(&msg);
        let commitment = rand::thread_rng().gen::<HashOutput>(); //We change the commitment
        assert!(!(verify_commitment(&msg, &commitment, &salt)));           //The test can fail but with very low probability
    }

    #[test]
    fn test_commit_decommit_fail_salt() {
        let msg = rand::thread_rng().gen::<[u8; 32]>();
        let (commitment, _) = commit(&msg);
        let salt1 = rand::thread_rng().gen::<[u8; SECURITY as usize]>(); //We change the salt
        let salt2 = rand::thread_rng().gen::<[u8; SECURITY as usize]>();
        let salt = [salt1,salt2].concat();
        assert!(!(verify_commitment(&msg, &commitment, &salt)));   //The test can fail but with very low probability
    }

}