//! Splits a secret key into a threshold signature scheme.
//!
//! This file implements a re-key function: if the user already has
//! an address, he can split his secret key into a threshold signature
//! scheme. Since he starts with the secret key, we consider him as a
//! "trusted dealer" that can manipulate all the data from `DKLs23` to the
//! other parties. Hence, this function is computed locally and doesn't
//! need any communication.

use std::collections::BTreeMap;

use k256::elliptic_curve::Field;
use k256::{AffinePoint, Scalar};

use crate::utilities::rng;

use crate::protocols::derivation::{ChainCode, DerivData};
use crate::protocols::dkg::compute_eth_address;
use crate::protocols::{Parameters, Party};

use crate::utilities::multiplication::{MulReceiver, MulSender};
use crate::utilities::ot::{
    self,
    extension::{OTEReceiver, OTESender},
};
use crate::utilities::zero_shares::{self, ZeroShare};

use hkdf::Hkdf;
use k256::elliptic_curve::bigint::{Encoding, U512};
use k256::elliptic_curve::ops::Reduce;
use sha2::Sha256;

// ---------------- HKDF helpers ----------------

/// HKDF expand with automatic chunking (never exceeds 8160 bytes per call).
fn hkdf_expand(zk_seed: &[u8; 32], info: &[u8], out_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(None, zk_seed);
    let max_bytes = 255 * 32; // RFC 5869 (SHA-256)
    let mut out = Vec::with_capacity(out_len);

    let mut offset = 0usize;
    let mut ctr: u32 = 0;

    while offset < out_len {
        ctr += 1;
        let take = core::cmp::min(max_bytes, out_len - offset);

        // domain-separate each chunk: info || ctr_be
        let mut info_ctr = Vec::with_capacity(info.len() + 4);
        info_ctr.extend_from_slice(info);
        info_ctr.extend_from_slice(&ctr.to_be_bytes());

        let mut block = vec![0u8; take];
        hk.expand(&info_ctr, &mut block).expect("HKDF expand");
        out.extend_from_slice(&block);
        offset += take;
    }
    out
}

/// Expand `count` × 32-byte blocks (for seeds0/seeds1/…)
fn expand_hashoutputs(zk_seed: &[u8; 32], info: &[u8], count: usize) -> Vec<[u8; 32]> {
    let bytes = hkdf_expand(zk_seed, info, 32 * count);
    bytes
        .chunks_exact(32)
        .map(|c| {
            let mut a = [0u8; 32];
            a.copy_from_slice(c);
            a
        })
        .collect()
}

/// Expand to `count` booleans (for correlation bits)
fn expand_bools(zk_seed: &[u8; 32], info: &[u8], count: usize) -> Vec<bool> {
    let byte_len = (count + 7) / 8;
    let bytes = hkdf_expand(zk_seed, info, byte_len);
    let mut out = Vec::with_capacity(count);
    for (i, b) in bytes.iter().enumerate() {
        for bit in 0..8 {
            if i * 8 + bit >= count {
                break;
            }
            out.push(((b >> bit) & 1) == 1);
        }
    }
    out
}

/// Expand to `count` Scalars with guaranteed validity (reduce mod n; no rejection)
fn expand_scalars(zk_seed: &[u8; 32], info: &[u8], count: usize) -> Vec<Scalar> {
    let bytes = hkdf_expand(zk_seed, info, 32 * count);
    bytes
        .chunks_exact(32)
        .map(|c| {
            let mut wide = [0u8; 64];
            wide[32..].copy_from_slice(c); // put 32 bytes in low half
            let num = U512::from_be_bytes(wide); // needs `Encoding` in scope
            Scalar::reduce(num) // needs `Reduce` in scope
        })
        .collect()
}

/// Given a secret key, computes the data needed to make
/// `DKLs23` signatures under the corresponding public key.
///
/// The output is a vector of [`Party`]'s which should be
/// distributed to different users.
///
/// We also include an option to put a chain code if the original
/// wallet followed BIP-32 for key derivation ([read more](super::derivation)).
#[must_use]
pub fn re_key(
    parameters: &Parameters,
    session_id: &[u8],
    secret_key: &Scalar,
    option_chain_code: Option<ChainCode>,
    zk_seed: &[u8; 32],
) -> Vec<Party> {
    // Public key.
    let pk = (AffinePoint::GENERATOR * secret_key).to_affine();

    // We will compute "poly_point" for each party with this polynomial
    // via Shamir's secret sharing.
    let mut polynomial: Vec<Scalar> = Vec::with_capacity(parameters.threshold as usize);
    polynomial.push(*secret_key);
    for _ in 1..parameters.threshold {
        polynomial.push(Scalar::random(rng::get_rng()));
    }

    // Zero shares. (deterministic from zk_seed)

    // We compute the common seed each pair of parties must save.
    // The vector below should interpreted as follows: its first entry
    // is a vector containing the seeds for the pair of parties (1,2),
    // (1,3), ..., (1,n). The second entry contains the seeds for the pairs
    // (2,3), (2,4), ..., (2,n), and so on. The last entry contains the
    // seed for the pair (n-1, n).

    // Precompute a single seed per unordered pair (i,j) with i<j
    let mut pair_seed: BTreeMap<(u8, u8), [u8; 32]> = BTreeMap::new();
    for i in 1..=parameters.share_count {
        for j in (i + 1)..=parameters.share_count {
            let label = format!(
                "dkls23/zero-share/{}/pair/{}/{}",
                hex::encode(session_id),
                i,
                j
            );
            let mut s = [0u8; 32];
            s.copy_from_slice(&hkdf_expand(zk_seed, label.as_bytes(), 32));
            pair_seed.insert((i, j), s);
        }
    }

    // Build each party's ZeroShare from the shared pair seeds
    let mut zero_shares: Vec<ZeroShare> = Vec::with_capacity(parameters.share_count as usize);
    for party in 1..=parameters.share_count {
        let mut seeds: Vec<zero_shares::SeedPair> =
            Vec::with_capacity((parameters.share_count - 1) as usize);

        for counterparty in 1..=parameters.share_count {
            if counterparty == party {
                continue;
            }

            let (lo, hi) = if party < counterparty {
                (party, counterparty)
            } else {
                (counterparty, party)
            };

            let seed = *pair_seed.get(&(lo, hi)).expect("pair seed missing");
            seeds.push(zero_shares::SeedPair {
                lowest_index: party == lo,        // true if we are the lower index
                index_counterparty: counterparty, // the other party's index
                seed,
            });
        }

        zero_shares.push(ZeroShare::initialize(seeds));
    }

    // Two-party multiplication. (deterministic from zk_seed)

    // These will store the result of initialization for each party.
    let mut all_mul_receivers: Vec<BTreeMap<u8, MulReceiver>> =
        vec![BTreeMap::new(); parameters.share_count as usize];
    let mut all_mul_senders: Vec<BTreeMap<u8, MulSender>> =
        vec![BTreeMap::new(); parameters.share_count as usize];

    for receiver in 1..=parameters.share_count {
        for sender in 1..=parameters.share_count {
            if sender == receiver {
                continue;
            }

            // Base label per direction (receiver,sender)
            let base = format!(
                "dkls23/ot/{}/{}/{}",
                hex::encode(session_id),
                receiver,
                sender
            );

            // Receiver side: seeds0/seeds1
            let seeds0 = expand_hashoutputs(
                zk_seed,
                format!("{}/seeds0", base).as_bytes(),
                ot::extension::KAPPA as usize,
            );
            let seeds1 = expand_hashoutputs(
                zk_seed,
                format!("{}/seeds1", base).as_bytes(),
                ot::extension::KAPPA as usize,
            );
            let ote_receiver = OTEReceiver {
                seeds0: seeds0.clone(),
                seeds1: seeds1.clone(),
            };

            // Sender side: correlation + seeds (selected from seeds0/seeds1)
            let correlation = expand_bools(
                zk_seed,
                format!("{}/corr", base).as_bytes(),
                ot::extension::KAPPA as usize,
            );

            let mut seeds = Vec::with_capacity(ot::extension::KAPPA as usize);
            for i in 0..ot::extension::KAPPA as usize {
                if correlation[i] {
                    seeds.push(seeds1[i]);
                } else {
                    seeds.push(seeds0[i]);
                }
            }
            let ote_sender = OTESender { correlation, seeds };

            // Public gadget (shared length, but derived per direction)
            let public_gadget = expand_scalars(
                zk_seed,
                format!("{}/gadget", base).as_bytes(),
                ot::extension::BATCH_SIZE as usize,
            );

            let mul_receiver = MulReceiver {
                public_gadget: public_gadget.clone(),
                ote_receiver,
            };

            let mul_sender = MulSender {
                public_gadget,
                ote_sender,
            };

            // We save the results.
            all_mul_receivers[(receiver - 1) as usize].insert(sender, mul_receiver);
            all_mul_senders[(sender - 1) as usize].insert(receiver, mul_sender);
        }
    }

    // Key derivation - BIP-32. (deterministic unless provided)
    // We use the chain code given or we sample a new one.
    let chain_code = match option_chain_code {
        Some(cc) => cc,
        None => {
            let mut cc = [0u8; 32];
            cc.copy_from_slice(&hkdf_expand(zk_seed, b"dkls23/chain-code", 32));
            cc
        }
    };

    // We create the parties.
    let mut parties: Vec<Party> = Vec::with_capacity(parameters.share_count as usize);
    for index in 1..=parameters.share_count {
        // poly_point is polynomial evaluated at index.
        let mut poly_point = Scalar::ZERO;
        let mut power_of_index = Scalar::ONE;
        for i in 0..parameters.threshold {
            poly_point += polynomial[i as usize] * power_of_index;
            power_of_index *= Scalar::from(u32::from(index));
        }

        // Remark: There is a very tiny probability that poly_point is trivial.
        // However, the person that will receive this data should apply the
        // refresh protocol to guarantee their key share is really secret.
        // This reduces the probability even more, so we are not going to
        // introduce an "Abort" case here.

        let derivation_data = DerivData {
            depth: 0,
            child_number: 0, // These three values are initialized as zero for the master node.
            parent_fingerprint: [0; 4],
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
            zero_share: zero_shares[(index - 1) as usize].clone(),
            mul_senders: all_mul_senders[(index - 1) as usize].clone(),
            mul_receivers: all_mul_receivers[(index - 1) as usize].clone(),
            derivation_data,
            eth_address: compute_eth_address(&pk),
        });
    }

    parties
}

// For tests, see the file signing.rs. It uses the function above.
