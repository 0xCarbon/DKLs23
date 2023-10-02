use std::collections::HashMap;

use k256::{AffinePoint, Scalar};
use serde::{Deserialize, Serialize};

use crate::protocols::derivation::DerivData;
use crate::utilities::multiplication::{MulReceiver, MulSender};
use crate::utilities::zero_shares::ZeroShare;

pub mod derivation;
pub mod dkg;
pub mod re_key;
pub mod refresh;
pub mod signing;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Parameters {
    pub threshold: u8,   //t
    pub share_count: u8, //n
}

// This struct represents a party after key generation ready to sign a message.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Party {
    pub parameters: Parameters,
    pub party_index: u8,
    pub session_id: Vec<u8>,

    pub poly_point: Scalar, // It behaves as the secret key share
    pub pk: AffinePoint,    // Public key

    pub zero_share: ZeroShare, // Used for computing shares of zero during signing.

    pub mul_senders: HashMap<u8, MulSender>, // Initializations for two-party multiplication.
    pub mul_receivers: HashMap<u8, MulReceiver>, // The key in the HashMap represents the other party.

    pub derivation_data: DerivData, // Data for BIP-32 derivation.

    pub eth_address: String, // Ethereum address calculated from the public key.
}

impl Party {
    #[must_use]
    pub fn new(
        parameters: Parameters,
        party_index: u8,
        session_id: Vec<u8>,
        poly_point: Scalar,
        pk: AffinePoint,
        zero_share: ZeroShare,
        mul_senders: HashMap<u8, MulSender>,
        mul_receivers: HashMap<u8, MulReceiver>,
        derivation_data: DerivData,
        eth_address: String,
    ) -> Party {
        Party {
            parameters,
            party_index,
            session_id,

            poly_point,
            pk,

            zero_share,

            mul_senders,
            mul_receivers,

            derivation_data,

            eth_address,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Abort {
    pub index: u8,
    pub description: String,
}

impl Abort {
    #[must_use]
    pub fn new(index: u8, description: &str) -> Abort {
        Abort {
            index,
            description: String::from(description),
        }
    }
}

// This struct saves the sender and receiver of a message.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PartiesMessage {
    pub sender: u8,
    pub receiver: u8,
}

impl PartiesMessage {
    #[must_use]
    pub fn reverse(&self) -> PartiesMessage {
        PartiesMessage {
            sender: self.receiver,
            receiver: self.sender,
        }
    }
}
