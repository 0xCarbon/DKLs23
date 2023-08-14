use std::collections::HashMap;

use curv::elliptic::curves::{Secp256k1, Scalar, Point};

use crate::utilities::multiplication::{MulSender, MulReceiver};
use crate::utilities::zero_sharings::ZeroShare;

pub mod dkg;
pub mod re_key;
pub mod refresh;
pub mod signing;

#[derive(Clone)]
pub struct Parameters {
    threshold: usize,     //t
    share_count: usize,   //n
}

// This struct represents a party after key generation ready to sign a message.
#[derive(Clone)]
pub struct Party {
    parameters: Parameters,
    party_index: usize,
    session_id: Vec<u8>,

    poly_point: Scalar<Secp256k1>,  // It behaves as the secrect key share
    pk: Point<Secp256k1>,           // Public key

    zero_share: ZeroShare,          // Used for computing shares of zero during signing.

    mul_senders: HashMap<usize, MulSender>,     // Initializations for two-party multiplication.
    mul_receivers: HashMap<usize,MulReceiver>,  // The key in the HashMap represents the other party.
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
    sender: usize,
    receiver: usize,
}

impl PartiesMessage {
    pub fn reverse(&self) -> PartiesMessage {
        PartiesMessage { sender: self.receiver, receiver: self.sender }
    }
}
