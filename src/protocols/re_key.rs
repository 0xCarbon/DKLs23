/// This file implements a re-key function: if the user already has
/// an address, he can split his secret key into a threshold signature
/// scheme. Since he starts with the secret key, we consider him as a
/// "trusted dealer" that can manipulate all the data from DKLs23 to the
/// other parties. Hence, this function is computed locally and doesn't
/// need any communication.

use std::collections::HashMap;

use k256::{Scalar, AffinePoint};
use k256::elliptic_curve::Field;

use rand::Rng;

use crate::protocols::{Parameters, Party};
use crate::protocols::dkg::compute_eth_address;
use crate::protocols::derivation::{ChainCode, DerivationData};

use crate::utilities::hashes::*;
use crate::utilities::multiplication::{MulReceiver, MulSender};
use crate::utilities::ot::ot_extension::{self, OTEReceiver, OTESender};
use crate::utilities::zero_sharings::{self, ZeroShare};

// The main inputs here are the parameters and the secret key.
// We also include the session id here because the party that
// is creating the wallet must verify the id was not used before,
// and we cannot do this here.
// We also include an option to put a chain code if the original
// wallet followed BIP-32 for key derivation. 
pub fn re_key(parameters: &Parameters, session_id: &[u8], secret_key: &Scalar, option_chain_code: Option<ChainCode>) -> Vec<Party> {

    // Public key.
    let pk = (AffinePoint::GENERATOR * secret_key).to_affine();

    // We will compute "poly_point" for each party with this polynomial
    // via Shamir's secret sharing.
    let mut polynomial: Vec<Scalar> = Vec::with_capacity(parameters.threshold);
    polynomial.push(*secret_key);
    for _ in 1..parameters.threshold {
        polynomial.push(Scalar::random(rand::thread_rng()));
    }

    // Zero-sharing.

    // We compute the common seed each pair of parties must save.
    // The vector below should interpreted as follows: its first entry
    // is a vector containing the seeds for the pair of parties (1,2),
    // (1,3), ..., (1,n). The second entry contains the seeds for the pairs
    // (2,3), (2,4), ..., (2,n), and so on. The last entry contains the
    // seed for the pair (n-1, n).
    let mut common_seeds: Vec<Vec<zero_sharings::Seed>> = Vec::with_capacity(parameters.share_count - 1);
    for lower_index in 1..=(parameters.share_count - 1) {
        let mut seeds_with_lower_index: Vec<zero_sharings::Seed> = Vec::with_capacity(parameters.share_count - lower_index);
        for _ in (lower_index + 1)..=parameters.share_count {
            let seed = rand::thread_rng().gen::<zero_sharings::Seed>();
            seeds_with_lower_index.push(seed);
        }
        common_seeds.push(seeds_with_lower_index);
    }

    // We can now finish the initialization.
    let mut zero_shares: Vec<ZeroShare> = Vec::with_capacity(parameters.share_count);
    for party in 1..=parameters.share_count {

        let mut seeds: Vec<zero_sharings::SeedPair> = Vec::with_capacity(parameters.share_count - 1);
        
        // We compute the pairs for which we have the highest index.
        if party > 1 {
            for counterparty in 1..=(party - 1) {
                seeds.push(zero_sharings::SeedPair {
                    lowest_index: false,
                    index_counterparty: counterparty,
                    seed: common_seeds[counterparty - 1][party - counterparty - 1],
                });
            }
        }

        // We compute the pairs for which we have the lowest index.
        if party < parameters.share_count {
            for counterparty in (party + 1)..=parameters.share_count {
                seeds.push(zero_sharings::SeedPair {
                    lowest_index: true,
                    index_counterparty: counterparty,
                    seed: common_seeds[party - 1][counterparty - party - 1],
                });
            }
        }

        zero_shares.push(ZeroShare::initialize(seeds));
    }

    // Two-party multiplication.

    // These will store the result of initialization for each party.
    let mut all_mul_receivers: Vec<HashMap<usize,MulReceiver>> = vec![HashMap::with_capacity(parameters.share_count - 1); parameters.share_count];
    let mut all_mul_senders: Vec<HashMap<usize,MulSender>> = vec![HashMap::with_capacity(parameters.share_count - 1); parameters.share_count];

    for receiver in 1..=parameters.share_count {
        for sender in 1..=parameters.share_count {

            if sender == receiver { continue; }

            // We first compute the data for the OT extension.

            // Receiver: Sample the seeds.
            let mut seeds0: Vec<HashOutput> = Vec::with_capacity(ot_extension::KAPPA);
            let mut seeds1: Vec<HashOutput> = Vec::with_capacity(ot_extension::KAPPA);
            for _ in 0..ot_extension::KAPPA {
                seeds0.push(rand::thread_rng().gen::<HashOutput>());
                seeds1.push(rand::thread_rng().gen::<HashOutput>());
            }

            // Sender: Sample the correlation and choose the correct seed.
            // The choice bits are sampled randomly.
            let mut correlation: Vec<bool> = Vec::with_capacity(ot_extension::KAPPA);
            let mut seeds: Vec<HashOutput> = Vec::with_capacity(ot_extension::KAPPA);
            for i in 0..ot_extension::KAPPA {
                let current_bit: bool = rand::random();
                if current_bit {
                    seeds.push(seeds1[i]);
                } else {
                    seeds.push(seeds0[i]);
                }
                correlation.push(current_bit);
            }

            let ote_receiver = OTEReceiver {
                seeds0,
                seeds1,
            };

            let ote_sender = OTESender {
                correlation,
                seeds,
            };

            // We sample the public gadget vector.
            let mut public_gadget: Vec<Scalar> = Vec::with_capacity(ot_extension::BATCH_SIZE);
            for _ in 0..ot_extension::BATCH_SIZE {
                public_gadget.push(Scalar::random(rand::thread_rng()));
            }

            // We finish the initialization.
            let mul_receiver = MulReceiver {
                public_gadget: public_gadget.clone(),
                ote_receiver,
            };

            let mul_sender = MulSender {
                public_gadget,
                ote_sender,
            };

            // We save the results.
            all_mul_receivers[receiver - 1].insert(sender, mul_receiver);
            all_mul_senders[sender - 1].insert(receiver, mul_sender);
        }
    }

    // Key derivation - BIP-32.
    // We use the chain code given or we sample a new one.
    let chain_code = match option_chain_code {
        Some(cc) => { cc },
        None => { rand::thread_rng().gen::<ChainCode>() },
    };

    // We create the parties.
    let mut parties: Vec<Party> = Vec::with_capacity(parameters.share_count);
    for index in 1..=parameters.share_count {

        // poly_point is polynomial evaluated at index.
        let mut poly_point = Scalar::ZERO;
        let mut power_of_index = Scalar::ONE;
        for i in 0..parameters.threshold {
            poly_point += polynomial[i] * power_of_index;
            power_of_index *= Scalar::from(index as u64);
        }

        // Remark: There is a very tiny probability that poly_point is trivial.
        // However, the person that will receive this data should apply the
        // refresh protocol to guarantee their key share is really secret.
        // This reduces the probability even more, so we are not going to
        // introduce an "Abort" case here.

        let derivation_data = DerivationData {
            depth: 0,
            child_number: 0,            // These three values are initialized as zero for the master node.
            parent_fingerprint: [0;4],
            poly_point,
            pk,
            chain_code,
        };

        parties.push(Party {
            parameters: parameters.clone(),
            party_index: index,
            session_id: session_id.to_vec(),
            poly_point,
            pk,
            zero_share: zero_shares[index - 1].clone(),
            mul_senders: all_mul_senders[index - 1].clone(),
            mul_receivers: all_mul_receivers[index - 1].clone(),
            derivation_data,
            eth_address: compute_eth_address(&pk),
        });
    }

    parties
}

// For tests, see the file signing.rs. It uses the function above.