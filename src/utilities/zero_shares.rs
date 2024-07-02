//! Zero-sharing sampling functionality from `DKLs23`.
//!
//! This file implements the zero-sharing sampling functionality from the `DKLs23` protocol
//! (this is Functionality 3.4 on page 7 of their paper).
//!
//! The implementation follows the suggestion they give using the commitment functionality.

use crate::utilities::commits;
use crate::utilities::hashes::{hash_as_scalar, HashOutput};

use crate::utilities::rng;
use k256::Scalar;
use rand::Rng;
use serde::{Deserialize, Serialize};

// Computational security parameter lambda_c from DKLs23 (divided by 8)
use crate::SECURITY;
/// Byte array of `SECURITY` bytes.
pub type Seed = [u8; SECURITY as usize];

/// Represents the common seed a pair of parties shares.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedPair {
    /// Verifies if the party that owns this data has the lowest index in the pair.
    pub lowest_index: bool,
    pub index_counterparty: u8,
    pub seed: Seed,
}

/// Used to run the protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroShare {
    pub seeds: Vec<SeedPair>,
}

impl ZeroShare {
    // We implement the functions in the order they should be applied during the protocol.

    // INITIALIZATION

    /// Generates and commits a seed to another party using the commitment functionality.
    ///
    /// The variables `seed` and `salt` should be kept, while `commitment` is transmitted.
    /// At the time of de-commitment, these secret values are revealed.
    #[must_use]
    pub fn generate_seed_with_commitment() -> (Seed, HashOutput, Vec<u8>) {
        let seed = rng::get_rng().gen::<Seed>();
        let (commitment, salt) = commits::commit(&seed);
        (seed, commitment, salt)
    }

    /// Verifies a seed against the commitment.
    #[must_use]
    pub fn verify_seed(seed: &Seed, commitment: &HashOutput, salt: &[u8]) -> bool {
        commits::verify_commitment(seed, commitment, salt)
    }

    /// Transforms the two seeds generated by a pair into a single shared seed.
    #[must_use]
    pub fn generate_seed_pair(
        index_party: u8,
        index_counterparty: u8,
        seed_party: &Seed,
        seed_counterparty: &Seed,
    ) -> SeedPair {
        // Instead of adding the seeds, as suggested in DKLs23, we apply the XOR operation.
        let mut seed: Seed = [0u8; SECURITY as usize];
        for i in 0..SECURITY {
            seed[i as usize] = seed_party[i as usize] ^ seed_counterparty[i as usize];
        }

        // We save if we are the party with lowest index.
        // The case where index_party == index_counterparty shouldn't occur in practice.
        let lowest_index = index_party <= index_counterparty;

        SeedPair {
            lowest_index,
            index_counterparty,
            seed,
        }
    }

    /// Finishes the initialization procedure.
    ///
    /// All the `SeedPair`'s relating to the same party are gathered.
    #[must_use]
    pub fn initialize(seeds: Vec<SeedPair>) -> ZeroShare {
        ZeroShare { seeds }
    }

    // FUNCTIONALITY

    /// Executes the protocol.
    ///
    /// To compute the zero shares, the parties must agree on the same "random seed"
    /// for the "random number generator". This is achieved by using the current session id.
    /// Moreover, not all parties need to participate in this step, so we need to provide a
    /// list of counterparties.
    #[must_use]
    pub fn compute(&self, counterparties: &[u8], session_id: &[u8]) -> Scalar {
        let mut share = Scalar::ZERO;
        let seeds = self.seeds.clone();
        for seed_pair in seeds {
            // We ignore if this seed pair comes from a counterparty not in the current list of counterparties
            if !counterparties.contains(&seed_pair.index_counterparty) {
                continue;
            }

            // Seeds generate fragments that add up to the share that will be returned.
            let fragment = hash_as_scalar(&seed_pair.seed, session_id);

            // This sign guarantees that the shares from different parties add up to zero.
            if seed_pair.lowest_index {
                share -= fragment;
            } else {
                share += fragment;
            }
        }
        share
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests if the shares returned by the zero shares
    /// protocol indeed add up to zero.
    #[test]
    fn test_zero_shares() {
        let number_parties: u8 = 8; //This number can be changed. If so, change executing_parties below.

        //Parties generate the initial seeds and the commitments.
        let mut step1: Vec<Vec<(Seed, HashOutput, Vec<u8>)>> =
            Vec::with_capacity(number_parties as usize);
        for _ in 0..number_parties {
            let mut step1_party_i: Vec<(Seed, HashOutput, Vec<u8>)> =
                Vec::with_capacity(number_parties as usize);
            for _ in 0..number_parties {
                //Each party should skip his own iteration, but we ignore this now for simplicity.
                step1_party_i.push(ZeroShare::generate_seed_with_commitment());
            }
            step1.push(step1_party_i);
        }

        //Communication round
        //The parties exchange their seeds and verify the message.

        for i in 0..number_parties {
            for j in 0..number_parties {
                let (seed, commitment, salt) = step1[i as usize][j as usize].clone();
                assert!(ZeroShare::verify_seed(&seed, &commitment, &salt));
            }
        }

        //Each party creates his "seed pairs" and finishes the initialization.
        let mut zero_shares: Vec<ZeroShare> = Vec::with_capacity(number_parties as usize);
        for i in 0..number_parties {
            let mut seeds: Vec<SeedPair> = Vec::with_capacity((number_parties - 1) as usize);
            for j in 0..number_parties {
                if i == j {
                    continue;
                } //Now each party skip his iteration.
                let (seed_party, _, _) = step1[i as usize][j as usize];
                let (seed_counterparty, _, _) = step1[j as usize][i as usize];
                //We add 1 below because indexes for parties start at 1 and not 0.
                seeds.push(ZeroShare::generate_seed_pair(
                    i + 1,
                    j + 1,
                    &seed_party,
                    &seed_counterparty,
                ));
            }
            zero_shares.push(ZeroShare::initialize(seeds));
        }

        //We can finally execute the functionality.
        let session_id = rng::get_rng().gen::<[u8; 32]>();
        let executing_parties: Vec<u8> = vec![1, 3, 5, 7, 8]; //These are the parties running the protocol.
        let mut shares: Vec<Scalar> = Vec::with_capacity(executing_parties.len());
        for party in executing_parties.clone() {
            //Gather the counterparties
            let mut counterparties = executing_parties.clone();
            counterparties.retain(|index| *index != party);
            //Compute the share (there is a -1 because indexes for parties start at 1).
            let share = zero_shares[(party as usize) - 1].compute(&counterparties, &session_id);
            shares.push(share);
        }

        //Final check
        let sum: Scalar = shares.iter().sum();
        assert_eq!(sum, Scalar::ZERO);
    }
}
