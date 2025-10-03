//! Loads a single party from existing polynomial point and parameters.
//!
//! This file implements a load_party function: if the user already has
//! a polynomial point (secret share) from a previous key generation or
//! re-keying process, they can reconstruct their Party struct with all
//! the necessary cryptographic data for DKLs23 threshold signatures.

use std::collections::BTreeMap;

use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, Scalar};

use crate::protocols::derivation::{ChainCode, DerivData};
use crate::protocols::dkg::compute_eth_address;
use crate::protocols::{Parameters, Party};

use crate::utilities::multiplication::{MulReceiver, MulSender};
use crate::utilities::ot::{
    self,
    extension::{OTEReceiver, OTESender},
};
use crate::utilities::zero_shares::{self, ZeroShare};

use crate::utilities::hkdf_helper::*;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::FieldBytes;

/// Loads a single party from existing polynomial point and parameters.
///
/// This function reconstructs a [`Party`] struct from a previously generated
/// polynomial point (secret share) and the same parameters and seeds used
/// during the original key generation or re-keying process.
///
/// # Arguments
/// * `parameters` - The threshold signature parameters (threshold, share_count)
/// * `session_id` - The session identifier used in the original setup
/// * `poly_point` - The polynomial evaluation point (secret share) for this party
/// * `party_index` - The index of this party (1-based)
/// * `pk` - The public key corresponding to the original secret
/// * `zk_seed` - The same deterministic seed used in the original setup
/// * `chain_code` - Optional chain code for BIP-32 derivation
#[must_use]
pub fn load_party(
    parameters: &Parameters,
    session_id: &[u8],
    key_share: &[u8; 32],
    party_index: u8,
    pubkey: &[u8; 33],
    zk_seed: &[u8; 32],
    chain_code: Option<ChainCode>,
) -> Party {
    // Convert key_share to Scalar
    let poly_point = Scalar::from_repr(FieldBytes::from(*key_share)).expect("valid scalar");

    // Convert pubkey to AffinePoint
    let pk = AffinePoint::from_encoded_point(
        &k256::EncodedPoint::from_bytes(pubkey).expect("valid point"),
    )
    .expect("valid public key");

    // -------- Zero shares (deterministic from zk_seed) --------

    // Precompute seeds for all pairs involving this party
    let mut seeds: Vec<zero_shares::SeedPair> =
        Vec::with_capacity((parameters.share_count - 1) as usize);

    for counterparty in 1..=parameters.share_count {
        if counterparty == party_index {
            continue;
        }

        let (lo, hi) = if party_index < counterparty {
            (party_index, counterparty)
        } else {
            (counterparty, party_index)
        };

        let label = format!(
            "dkls23/zero-share/{}/pair/{}/{}",
            hex::encode(session_id),
            lo,
            hi
        );
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&hkdf_expand(zk_seed, label.as_bytes(), 32));

        seeds.push(zero_shares::SeedPair {
            lowest_index: party_index == lo,  // true if we are the lower index
            index_counterparty: counterparty, // the other party's index
            seed,
        });
    }

    let zero_share = ZeroShare::initialize(seeds);

    // -------- Two-party multiplication (deterministic from zk_seed) --------
    let mut mul_receivers: BTreeMap<u8, MulReceiver> = BTreeMap::new();
    let mut mul_senders: BTreeMap<u8, MulSender> = BTreeMap::new();

    // This party as receiver
    for sender in 1..=parameters.share_count {
        if sender == party_index {
            continue;
        }

        let base = format!(
            "dkls23/ot/{}/{}/{}",
            hex::encode(session_id),
            party_index,
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
        let ote_receiver = OTEReceiver { seeds0, seeds1 };

        let public_gadget = expand_scalars(
            zk_seed,
            format!("{}/gadget", base).as_bytes(),
            ot::extension::BATCH_SIZE as usize,
        );

        let mul_receiver = MulReceiver {
            public_gadget,
            ote_receiver,
        };

        mul_receivers.insert(sender, mul_receiver);
    }

    // This party as sender
    for receiver in 1..=parameters.share_count {
        if receiver == party_index {
            continue;
        }

        let base = format!(
            "dkls23/ot/{}/{}/{}",
            hex::encode(session_id),
            receiver,
            party_index
        );

        // Sender side: correlation + seeds
        let correlation = expand_bools(
            zk_seed,
            format!("{}/corr", base).as_bytes(),
            ot::extension::KAPPA as usize,
        );

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

        let mut seeds = Vec::with_capacity(ot::extension::KAPPA as usize);
        for i in 0..ot::extension::KAPPA as usize {
            if correlation[i] {
                seeds.push(seeds1[i]);
            } else {
                seeds.push(seeds0[i]);
            }
        }

        let ote_sender = OTESender { correlation, seeds };

        let public_gadget = expand_scalars(
            zk_seed,
            format!("{}/gadget", base).as_bytes(),
            ot::extension::BATCH_SIZE as usize,
        );

        let mul_sender = MulSender {
            public_gadget,
            ote_sender,
        };

        mul_senders.insert(receiver, mul_sender);
    }

    // -------- Chain code (deterministic unless provided) --------
    let chain_code = match chain_code {
        Some(cc) => cc,
        None => {
            let mut cc = [0u8; 32];
            cc.copy_from_slice(&hkdf_expand(zk_seed, b"dkls23/chain-code", 32));
            cc
        }
    };

    // -------- Build Party --------
    let derivation_data = DerivData {
        depth: 0,
        child_number: 0,
        parent_fingerprint: [0; 4],
        poly_point,
        pk,
        chain_code,
    };

    Party {
        parameters: parameters.clone(),
        party_index,
        session_id: session_id.to_vec(),
        poly_point,
        pk,
        zk_seed: *zk_seed,
        zero_share,
        mul_senders,
        mul_receivers,
        derivation_data,
        eth_address: compute_eth_address(&pk),
    }
}
