//! `DKLs23` main protocols and related ones.
//!
//! Some structs appearing in most of the protocols are defined here.
use std::collections::BTreeMap;

use k256::{AffinePoint, Scalar};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::protocols::derivation::DerivData;
use crate::utilities::multiplication::{MulReceiver, MulSender};
use crate::utilities::zero_shares::ZeroShare;

pub mod derivation;
pub mod dkg;
pub mod re_key;
pub mod refresh;
pub mod signing;

/// Contains the values `t` and  `n` from `DKLs23`.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Parameters {
    pub threshold: u8,   //t
    pub share_count: u8, //n
}

/// Represents a party after key generation ready to sign a message.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Party {
    pub parameters: Parameters,
    pub party_index: u8,
    pub session_id: Vec<u8>,

    /// Behaves as the secret key share.
    pub poly_point: Scalar,
    /// Public key.
    pub pk: AffinePoint,

    /// Used for computing shares of zero during signing.
    pub zero_share: ZeroShare,

    /// Initializations for two-party multiplication.
    /// The key in the `BTreeMap` represents the other party.
    pub mul_senders: BTreeMap<u8, MulSender>,
    pub mul_receivers: BTreeMap<u8, MulReceiver>,

    /// Data for BIP-32 derivation.
    pub derivation_data: DerivData,

    /// Ethereum address calculated from the public key.
    pub eth_address: String,
}

impl Zeroize for Party {
    fn zeroize(&mut self) {
        self.session_id.zeroize();
        self.poly_point.zeroize();
        self.zero_share.zeroize();
        // Zeroize each value in the BTreeMaps, then clear the maps.
        for sender in self.mul_senders.values_mut() {
            sender.zeroize();
        }
        self.mul_senders.clear();
        for receiver in self.mul_receivers.values_mut() {
            receiver.zeroize();
        }
        self.mul_receivers.clear();
        self.derivation_data.zeroize();
        self.eth_address.zeroize();
    }
}

impl Drop for Party {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Classifies the severity and required response for an abort.
///
/// The `DKLs23` protocol reuses base OT correlations across signing sessions.
/// If the COTe consistency check fails, information about this reused state
/// is leaked. The paper mandates that the offending counterparty must be
/// **permanently banned** from all future sessions. Failure to do so
/// enables a key extraction attack over multiple sessions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AbortKind {
    /// The protocol failed but can be retried safely.
    /// No long-term state was compromised.
    Recoverable,
    /// The identified counterparty cheated in a way that leaks information
    /// about reusable OT state. This party **MUST** be permanently excluded
    /// from all future signing and refresh sessions. Continuing to interact
    /// with this party enables private key extraction.
    BanCounterparty(u8),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Abort {
    /// Index of the party generating the abort message.
    pub index: u8,
    /// Indicates whether the abort requires permanently banning a counterparty.
    pub kind: AbortKind,
    pub description: String,
}

impl Abort {
    /// Creates a recoverable `Abort`.
    #[must_use]
    pub fn new(index: u8, description: &str) -> Abort {
        Abort {
            index,
            kind: AbortKind::Recoverable,
            description: String::from(description),
        }
    }

    /// Creates an `Abort` that requires permanently banning a counterparty.
    ///
    /// This MUST be used when the COTe consistency check or the multiplication
    /// protocol's verification step fails. The counterparty identified here
    /// has either cheated or been compromised, and continuing to sign with
    /// them leaks information enabling key extraction.
    #[must_use]
    pub fn ban(index: u8, counterparty: u8, description: &str) -> Abort {
        Abort {
            index,
            kind: AbortKind::BanCounterparty(counterparty),
            description: String::from(description),
        }
    }
}

/// Saves the sender and receiver of a message.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PartiesMessage {
    pub sender: u8,
    pub receiver: u8,
}

impl PartiesMessage {
    /// Swaps the sender with the receiver, returning another instance of `PartiesMessage`.
    #[must_use]
    pub fn reverse(&self) -> PartiesMessage {
        PartiesMessage {
            sender: self.receiver,
            receiver: self.sender,
        }
    }
}
