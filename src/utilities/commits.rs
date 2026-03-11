//! Commit and decommit protocols.
//!
//! This file implements the commitment functionality needed for `DKLs23`.
//! We follow the approach suggested on page 7 of their paper
//! (<https://eprint.iacr.org/2023/765.pdf>).

use crate::utilities::hashes::{point_to_bytes, tagged_hash, HashOutput};
use crate::utilities::oracle_tags::TAG_COMMITMENT;
use crate::utilities::rng;
use k256::AffinePoint;
use rand::RngExt;
use subtle::ConstantTimeEq;

// Computational security parameter lambda_c from DKLs23 (divided by 8)
use crate::SECURITY;

/// Commits to a given message.
///
/// Given a message, this function generates a random salt of size `2*lambda_c`
/// and computes the corresponding commitment.
///
/// The sender should first communicate the commitment. When he wants to decommit,
/// he sends the message together with the salt.
#[must_use]
pub fn commit(msg: &[u8]) -> (HashOutput, Vec<u8>) {
    //The paper instructs the salt to have 2*lambda_c bits.
    let mut salt = [0u8; 2 * SECURITY as usize];
    rng::get_rng().fill(&mut salt[..]);

    let commitment = tagged_hash(TAG_COMMITMENT, &[&salt, msg]);

    (commitment, salt.to_vec())
}

/// Verifies a commitment for a message.
///
/// After having received the commitment and later the message and the salt, the receiver
/// verifies if these data are compatible.
#[must_use]
pub fn verify_commitment(msg: &[u8], commitment: &HashOutput, salt: &[u8]) -> bool {
    let expected_commitment = tagged_hash(TAG_COMMITMENT, &[salt, msg]);
    commitment.ct_eq(&expected_commitment).into()
}

/// Commits to a given point.
///
///  This is the same as [`commit`], but it receives a point on the elliptic curve instead.
#[must_use]
pub fn commit_point(point: &AffinePoint) -> (HashOutput, Vec<u8>) {
    let point_as_bytes = point_to_bytes(point);
    commit(&point_as_bytes)
}

/// Verifies a commitment for a point.
///
/// This is the same as [`verify_commitment`], but it receives a point on the elliptic curve instead.
#[must_use]
pub fn verify_commitment_point(point: &AffinePoint, commitment: &HashOutput, salt: &[u8]) -> bool {
    let point_as_bytes = point_to_bytes(point);
    verify_commitment(&point_as_bytes, commitment, salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests if committing and de-committing work.
    #[test]
    fn test_commit_decommit() {
        let msg = rng::get_rng().random::<[u8; 32]>();
        let (commitment, salt) = commit(&msg);
        assert!(verify_commitment(&msg, &commitment, &salt));
    }

    /// Commits to a message and changes it on purpose
    /// to check that if [`verify_commitment`] returns `false`.
    #[test]
    fn test_commit_decommit_fail_msg() {
        let msg = rng::get_rng().random::<[u8; 32]>();
        let (commitment, salt) = commit(&msg);
        let msg = rng::get_rng().random::<[u8; 32]>(); //We change the message
        assert!(!(verify_commitment(&msg, &commitment, &salt))); //The test can fail but with very low probability
    }

    /// Commits to a message and changes the commitment on purpose
    /// to check that if [`verify_commitment`] returns `false`.
    #[test]
    fn test_commit_decommit_fail_commitment() {
        let msg = rng::get_rng().random::<[u8; 32]>();
        let (_, salt) = commit(&msg);
        let commitment = rng::get_rng().random::<HashOutput>(); //We change the commitment
        assert!(!(verify_commitment(&msg, &commitment, &salt))); //The test can fail but with very low probability
    }

    /// Commits to a message and changes the salt on purpose
    /// to check that if [`verify_commitment`] returns `false`.
    #[test]
    fn test_commit_decommit_fail_salt() {
        let msg = rng::get_rng().random::<[u8; 32]>();
        let (commitment, _) = commit(&msg);
        let mut salt = [0u8; 2 * SECURITY as usize];
        rng::get_rng().fill(&mut salt[..]);
        assert!(!(verify_commitment(&msg, &commitment, &salt))); //The test can fail but with very low probability
    }
}
