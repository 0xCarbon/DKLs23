/// This file implements a key derivation mechanism for threshold wallets
/// based on BIP-32 (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).
/// Each party can derive their key share individually so that the secret
/// key reconstructed corresponds to the derivation (via BIP-32) of the
/// original secret key.
///
/// We follow mainly this repository:
/// // https://github.com/rust-bitcoin/rust-bitcoin/blob/master/bitcoin/src/bip32.rs.
///
/// ATTENTION: Since no party has the full secret key, it is not convenient
/// to do hardened derivation. Thus, we only implement normal derivation.
use bitcoin_hashes::{hash160, sha512, Hash, HashEngine, Hmac, HmacEngine};

use k256::elliptic_curve::{ops::Reduce, point::AffineCoordinates, Curve};
use k256::{AffinePoint, Scalar, Secp256k1, U256};
use serde::{Deserialize, Serialize};

use crate::protocols::Party;

use super::dkg::compute_eth_address;

pub type Fingerprint = [u8; 4];
pub type ChainCode = [u8; 32];

// A struct for errors in this file.
#[derive(Clone)]
pub struct ErrorDerivation {
    pub description: String,
}

impl ErrorDerivation {
    pub fn new(description: &str) -> ErrorDerivation {
        ErrorDerivation {
            description: String::from(description),
        }
    }
}

// This struct contains all the data needed for derivation.
// The values that are really needed are only the last three,
// but we also include the other ones if someone wants to retrieve
// the full extended public key as in BIP-32. The only field
// missing is the one for the network, but it can be easily
// inferred from context.
#[derive(Clone, Serialize, Deserialize)]
pub struct DerivationData {
    pub depth: u8,
    pub child_number: u32,
    pub parent_fingerprint: Fingerprint,
    pub poly_point: Scalar,
    pub pk: AffinePoint,
    pub chain_code: ChainCode,
}

impl DerivationData {
    // Adaptation of function ckd_pub_tweak from the repository:
    // https://github.com/rust-bitcoin/rust-bitcoin/blob/master/bitcoin/src/bip32.rs.
    pub fn child_tweak(
        &self,
        child_number: u32,
    ) -> Result<(Scalar, ChainCode, Fingerprint), ErrorDerivation> {
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(&self.chain_code[..]);

        let pk_as_bytes = serialize_point_compressed(&self.pk);
        hmac_engine.input(&pk_as_bytes);
        hmac_engine.input(&child_number.to_be_bytes());

        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

        let number_for_tweak = U256::from_be_slice(&hmac_result[..32]);
        if number_for_tweak.ge(&Secp256k1::ORDER) {
            return Err(ErrorDerivation::new(
                "Very improbable: Child index results in value not allowed by BIP-32!",
            ));
        }

        let tweak = Scalar::reduce(number_for_tweak);
        let chain_code: ChainCode = hmac_result[32..]
            .try_into()
            .expect("Half of hmac is guaranteed to be 32 bytes!");

        // We also calculate the fingerprint here for convenience.
        let mut engine = hash160::Hash::engine();
        engine.input(&pk_as_bytes);
        let fingerprint: Fingerprint = hash160::Hash::from_engine(engine)[0..4]
            .try_into()
            .expect("4 is the fingerprint length!");

        Ok((tweak, chain_code, fingerprint))
    }

    pub fn derive_child(&self, child_number: u32) -> Result<DerivationData, ErrorDerivation> {
        if self.depth == 255 {
            return Err(ErrorDerivation::new("We are already at maximum depth!"));
        }

        if child_number >= 0x80000000 {
            return Err(ErrorDerivation::new(
                "Child index should be between 0 and 2^31 - 1!",
            ));
        }

        let (tweak, new_chain_code, parent_fingerprint) = self.child_tweak(child_number)?;

        // If every party shifts their poly_point by the same tweak,
        // the resulting secret key also shifts by the same amount.
        // Note that the tweak depends only on public data.
        let new_poly_point = &self.poly_point + &tweak;
        let new_pk = ((AffinePoint::GENERATOR * &tweak) + self.pk).to_affine();

        if new_pk == AffinePoint::IDENTITY {
            return Err(ErrorDerivation::new(
                "Very improbable: Child index results in value not allowed by BIP-32!",
            ));
        }

        Ok(DerivationData {
            depth: self.depth + 1,
            child_number,
            parent_fingerprint,
            poly_point: new_poly_point,
            pk: new_pk,
            chain_code: new_chain_code,
        })
    }

    pub fn derive_from_path(&self, path: &str) -> Result<DerivationData, ErrorDerivation> {
        let path_parsed = parse_path(path)?;

        let mut final_data = self.clone();
        for child_number in path_parsed {
            final_data = final_data.derive_child(child_number)?;
        }

        Ok(final_data)
    }
}

// We implement the derivation functions for Party as well.

impl Party {
    pub fn derive_child(&self, child_number: u32) -> Result<Party, ErrorDerivation> {
        let new_derivation_data = self.derivation_data.derive_child(child_number)?;

        // We don't change information relating other parties,
        // we only update our key share, our public key and the address.
        let new_address = compute_eth_address(&new_derivation_data.pk);

        Ok(Party {
            parameters: self.parameters.clone(),
            party_index: self.party_index,
            session_id: self.session_id.clone(),

            poly_point: new_derivation_data.poly_point,
            pk: new_derivation_data.pk,

            zero_share: self.zero_share.clone(),

            mul_senders: self.mul_senders.clone(),
            mul_receivers: self.mul_receivers.clone(),

            derivation_data: new_derivation_data,

            eth_address: new_address,
        })
    }

    pub fn derive_from_path(&self, path: &str) -> Result<Party, ErrorDerivation> {
        let new_derivation_data = self.derivation_data.derive_from_path(path)?;

        // We don't change information relating other parties,
        // we only update our key share, our public key and the address.
        let new_address = compute_eth_address(&new_derivation_data.pk);

        Ok(Party {
            parameters: self.parameters.clone(),
            party_index: self.party_index,
            session_id: self.session_id.clone(),

            poly_point: new_derivation_data.poly_point,
            pk: new_derivation_data.pk,

            zero_share: self.zero_share.clone(),

            mul_senders: self.mul_senders.clone(),
            mul_receivers: self.mul_receivers.clone(),

            derivation_data: new_derivation_data,

            eth_address: new_address,
        })
    }
}

// This function serializes an affine point on the elliptic curve into compressed form.
pub fn serialize_point_compressed(point: &AffinePoint) -> Vec<u8> {
    let x_as_bytes = point.x().as_slice().to_vec();
    let prefix = if point.y_is_odd().into() {
        vec![3]
    } else {
        vec![2]
    };

    [prefix, x_as_bytes].concat()
}

// We take a path as in BIP-32 (for normal derivation),
// and transform it into a vector of child numbers.
pub fn parse_path(path: &str) -> Result<Vec<u32>, ErrorDerivation> {
    let mut parts = path.split('/');

    if parts.next().unwrap() != "m" {
        return Err(ErrorDerivation::new("Invalid path format!"));
    }

    let path_parsed: Vec<u32> = parts
        .map(|x| str::parse::<u32>(x).map_err(|_| ErrorDerivation::new("Invalid path format!")))
        .collect::<Result<_, _>>()?;

    if path_parsed.len() > 255 {
        return Err(ErrorDerivation::new("The path is too long!"));
    }

    for index in &path_parsed {
        if *index >= 0x80000000 {
            return Err(ErrorDerivation::new(
                "Child index should be between 0 and 2^31 - 1!",
            ));
        }
    }

    Ok(path_parsed)
}

#[cfg(test)]
mod tests {

    use super::*;

    use crate::protocols::re_key::re_key;
    use crate::protocols::signing::*;
    use crate::protocols::Parameters;

    use crate::utilities::hashes::*;

    use hex;
    use k256::elliptic_curve::Field;
    use rand::Rng;
    use std::collections::HashMap;

    #[test]
    fn test_derivation() {
        // The following values were calculated at random with: https://bitaps.com/bip32.
        // You should test other values as well.
        let sk = Scalar::reduce(U256::from_be_hex(
            "7119a4064db44307dbb97dcc1a34fac7cf152cc35ad65dbc97649e3e250a22d3",
        ));
        let pk = (AffinePoint::GENERATOR * &sk).to_affine();
        let chain_code: ChainCode =
            hex::decode("5190725e347a7ef19bb857525bfbc491f80ec355864b95661129dc1e5970002f")
                .unwrap()
                .try_into()
                .unwrap();

        let data = DerivationData {
            depth: 0,
            child_number: 0,
            parent_fingerprint: [0u8; 4],
            poly_point: sk,
            pk,
            chain_code,
        };

        let path = "m/0/1/2/3";
        let try_derive = data.derive_from_path(path);

        match try_derive {
            Err(error) => {
                panic!("Error: {:?}", error.description);
            }
            Ok(child) => {
                assert_eq!(child.depth, 4);
                assert_eq!(child.child_number, 3);
                assert_eq!(hex::encode(child.parent_fingerprint), "7586c333");
                assert_eq!(
                    hex::encode(scalar_to_bytes(&child.poly_point)),
                    "c4e854f80cac8d8c8d1fc4830c76761a6bea70568c773ddf6b73da911f940fb1"
                );
                assert_eq!(
                    hex::encode(serialize_point_compressed(&child.pk)),
                    "0221120b5ae5375ddc16605a2a265c61b59a04911ab699fcecf7568f8c19b15fc2"
                );
                assert_eq!(
                    hex::encode(child.chain_code),
                    "5901a52851d8e2864ef676308f0c9449fb0ec050151af259582ef2faf75f046d"
                );
            }
        }
    }

    #[test]
    // This test verifies if the key shares continue working.
    fn test_derivation_and_signing() {
        let threshold = rand::thread_rng().gen_range(2..=5); // You can change the ranges here.
        let offset = rand::thread_rng().gen_range(0..=5);

        let parameters = Parameters {
            threshold,
            share_count: threshold + offset,
        }; // You can fix the parameters if you prefer.

        // We use the re_key function to quickly sample the parties.
        let session_id = rand::thread_rng().gen::<[u8; 32]>();
        let secret_key = Scalar::random(rand::thread_rng());
        let parties = re_key(&parameters, &session_id, &secret_key, None);

        // DERIVATION

        let path = "m/0/1/2/3";

        let mut derived_parties: Vec<Party> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {
            let result = parties[i].derive_from_path(path);
            match result {
                Err(error) => {
                    panic!("Error for Party {}: {:?}", i, error.description);
                }
                Ok(party) => {
                    derived_parties.push(party);
                }
            }
        }

        let parties = derived_parties;

        // SIGNING (as in test_signing)

        let sign_id = rand::thread_rng().gen::<[u8; 32]>();
        let message_to_sign = "Message to sign!".as_bytes();

        // For simplicity, we are testing only the first parties.
        let executing_parties: Vec<usize> = Vec::from_iter(1..=parameters.threshold);

        // Each party prepares their data for this signing session.
        let mut all_data: HashMap<usize, SignData> = HashMap::with_capacity(parameters.threshold);
        for party_index in executing_parties.clone() {
            //Gather the counterparties
            let mut counterparties = executing_parties.clone();
            counterparties.retain(|index| *index != party_index);

            all_data.insert(
                party_index,
                SignData {
                    sign_id: sign_id.to_vec(),
                    counterparties,
                    message_to_sign: message_to_sign.to_vec(),
                },
            );
        }

        // Phase 1
        let mut unique_kept_1to2: HashMap<usize, UniqueKeep1to2> =
            HashMap::with_capacity(parameters.threshold);
        let mut kept_1to2: HashMap<usize, HashMap<usize, KeepPhase1to2>> =
            HashMap::with_capacity(parameters.threshold);
        let mut transmit_1to2: HashMap<usize, Vec<TransmitPhase1to2>> =
            HashMap::with_capacity(parameters.threshold);
        for party_index in executing_parties.clone() {
            let (unique_keep, keep, transmit) =
                parties[party_index - 1].sign_phase1(all_data.get(&party_index).unwrap());

            unique_kept_1to2.insert(party_index, unique_keep);
            kept_1to2.insert(party_index, keep);
            transmit_1to2.insert(party_index, transmit);
        }

        // Communication round 1
        let mut received_1to2: HashMap<usize, Vec<TransmitPhase1to2>> =
            HashMap::with_capacity(parameters.threshold);
        for party_index in executing_parties.clone() {
            let mut new_row: Vec<TransmitPhase1to2> = Vec::with_capacity(parameters.threshold - 1);
            for (_, messages) in &transmit_1to2 {
                for message in messages {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == party_index {
                        new_row.push(message.clone());
                    }
                }
            }
            received_1to2.insert(party_index, new_row);
        }

        // Phase 2
        let mut unique_kept_2to3: HashMap<usize, UniqueKeep2to3> =
            HashMap::with_capacity(parameters.threshold);
        let mut kept_2to3: HashMap<usize, HashMap<usize, KeepPhase2to3>> =
            HashMap::with_capacity(parameters.threshold);
        let mut transmit_2to3: HashMap<usize, Vec<TransmitPhase2to3>> =
            HashMap::with_capacity(parameters.threshold);
        for party_index in executing_parties.clone() {
            let result = parties[party_index - 1].sign_phase2(
                all_data.get(&party_index).unwrap(),
                unique_kept_1to2.get(&party_index).unwrap(),
                kept_1to2.get(&party_index).unwrap(),
                received_1to2.get(&party_index).unwrap(),
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                }
                Ok((unique_keep, keep, transmit)) => {
                    unique_kept_2to3.insert(party_index, unique_keep);
                    kept_2to3.insert(party_index, keep);
                    transmit_2to3.insert(party_index, transmit);
                }
            }
        }

        // Communication round 2
        let mut received_2to3: HashMap<usize, Vec<TransmitPhase2to3>> =
            HashMap::with_capacity(parameters.threshold);
        for party_index in executing_parties.clone() {
            let mut new_row: Vec<TransmitPhase2to3> = Vec::with_capacity(parameters.threshold - 1);
            for (_, messages) in &transmit_2to3 {
                for message in messages {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == party_index {
                        new_row.push(message.clone());
                    }
                }
            }
            received_2to3.insert(party_index, new_row);
        }

        // Phase 3
        let mut x_coords: Vec<String> = Vec::with_capacity(parameters.threshold);
        let mut broadcast_3to4: Vec<Broadcast3to4> = Vec::with_capacity(parameters.threshold);
        for party_index in executing_parties.clone() {
            let result = parties[party_index - 1].sign_phase3(
                all_data.get(&party_index).unwrap(),
                unique_kept_2to3.get(&party_index).unwrap(),
                kept_2to3.get(&party_index).unwrap(),
                received_2to3.get(&party_index).unwrap(),
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                }
                Ok((x_coord, broadcast)) => {
                    x_coords.push(x_coord);
                    broadcast_3to4.push(broadcast);
                }
            }
        }

        // We verify all parties got the same x coordinate.
        let x_coord = x_coords[0].clone(); // We take the first one as reference.
        for i in 1..parameters.threshold {
            assert_eq!(x_coord, x_coords[i]);
        }

        // Communication round 3
        // This is a broadcast to all parties. The desired result is already broadcast_3to4.

        // Phase 4
        let some_index = executing_parties[0];
        let result = parties[some_index - 1].sign_phase4(
            all_data.get(&some_index).unwrap(),
            &x_coord,
            &broadcast_3to4,
        );
        if let Err(abort) = result {
            panic!("Party {} aborted: {:?}", abort.index, abort.description);
        }
    }
}
