use std::collections::HashMap;

use curv::elliptic::curves::{Secp256k1, Scalar, Point};

use crate::utilities::multiplication::{MulSender, MulReceiver};
use crate::utilities::zero_sharings::ZeroShare;
use crate::protocols::derivation::DerivationData;

pub mod derivation;
pub mod dkg;
pub mod re_key;
//pub mod refresh;
pub mod signing;

#[derive(Clone)]
pub struct Parameters {
    pub threshold: usize,     //t
    pub share_count: usize,   //n
}

// This struct represents a party after key generation ready to sign a message.
#[derive(Clone)]
pub struct Party {
    pub parameters: Parameters,
    pub party_index: usize,
    pub session_id: Vec<u8>,

    pub poly_point: Scalar<Secp256k1>,  // It behaves as the secrect key share
    pub pk: Point<Secp256k1>,           // Public key

    pub zero_share: ZeroShare,          // Used for computing shares of zero during signing.

    pub mul_senders: HashMap<usize, MulSender>,     // Initializations for two-party multiplication.
    pub mul_receivers: HashMap<usize,MulReceiver>,  // The key in the HashMap represents the other party.

    pub derivation_data: DerivationData,    // Data for BIP-32 derivation.
}

#[derive(Debug,Clone)]
pub struct Abort {
    pub index: usize,
    pub description: String,
}

impl Abort {
    pub fn new(index: usize, description: &str) -> Abort {
        Abort { 
            index,
            description: String::from(description),
        }
    }
}

// This struct saves the sender and receiver of a message.
#[derive(Clone)]
pub struct PartiesMessage {
    pub sender: usize,
    pub receiver: usize,
}

impl PartiesMessage {
    pub fn reverse(&self) -> PartiesMessage {
        PartiesMessage { sender: self.receiver, receiver: self.sender }
    }
}
