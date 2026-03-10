//! `DKLs23` main protocols and related ones.
//!
//! Some structs appearing in most of the protocols are defined here.
use std::collections::BTreeMap;
use std::fmt;

use k256::{AffinePoint, Scalar};
use zeroize::Zeroize;

use crate::protocols::derivation::DerivData;
pub use crate::protocols::dkg::compute_eth_address;
use crate::utilities::multiplication::{MulReceiver, MulSender};
use crate::utilities::zero_shares::ZeroShare;

pub mod derivation;
pub mod dkg;
pub mod dkg_session;
#[cfg(feature = "serde")]
pub mod messages;
pub mod re_key;
pub mod refresh;
pub mod sign_session;
pub mod signature;
pub mod signing;

/// Error returned when attempting to construct a `PartyIndex` from `0`.
#[derive(Debug, Clone)]
pub struct InvalidPartyIndex;

impl fmt::Display for InvalidPartyIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "party index must be > 0")
    }
}

impl std::error::Error for InvalidPartyIndex {}

/// Strongly-typed 1-based participant identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
#[cfg_attr(feature = "serde", serde(try_from = "u8", into = "u8"))]
pub struct PartyIndex(u8);

impl PartyIndex {
    pub fn new(value: u8) -> Result<Self, InvalidPartyIndex> {
        if value == 0 {
            Err(InvalidPartyIndex)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub fn as_u8(&self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for PartyIndex {
    type Error = InvalidPartyIndex;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<PartyIndex> for u8 {
    fn from(pi: PartyIndex) -> Self {
        pi.0
    }
}

impl fmt::Display for PartyIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Contains the values `t` and  `n` from `DKLs23`.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Parameters {
    pub threshold: u8,   //t
    pub share_count: u8, //n
}

/// Represents a party after key generation ready to sign a message.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Party {
    pub parameters: Parameters,
    pub party_index: PartyIndex,
    pub session_id: Vec<u8>,

    /// Behaves as the secret key share.
    pub poly_point: Scalar,
    /// Public key.
    pub pk: AffinePoint,

    /// Used for computing shares of zero during signing.
    pub zero_share: ZeroShare,

    /// Initializations for two-party multiplication.
    /// The key in the `BTreeMap` represents the other party.
    pub mul_senders: BTreeMap<PartyIndex, MulSender>,
    pub mul_receivers: BTreeMap<PartyIndex, MulReceiver>,

    /// Data for BIP-32 derivation.
    pub derivation_data: DerivData,

    /// Ethereum address calculated from the public key.
    pub eth_address: String,
}

impl Zeroize for Party {
    fn zeroize(&mut self) {
        // `parameters`, `party_index`, and `pk` are public values — not zeroized.
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

/// Aggregates the group public key, per-participant verification shares,
/// and threshold parameters produced by DKG or re-key.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PublicKeyPackage {
    verifying_key: AffinePoint,
    verifying_shares: BTreeMap<PartyIndex, AffinePoint>,
    parameters: Parameters,
}

impl PublicKeyPackage {
    #[must_use]
    pub fn new(
        verifying_key: AffinePoint,
        verifying_shares: BTreeMap<PartyIndex, AffinePoint>,
        parameters: Parameters,
    ) -> Self {
        Self {
            verifying_key,
            verifying_shares,
            parameters,
        }
    }

    #[must_use]
    pub fn verifying_key(&self) -> &AffinePoint {
        &self.verifying_key
    }

    #[must_use]
    pub fn verifying_share(&self, party: PartyIndex) -> Option<&AffinePoint> {
        self.verifying_shares.get(&party)
    }

    #[must_use]
    pub fn threshold(&self) -> u8 {
        self.parameters.threshold
    }

    #[must_use]
    pub fn share_count(&self) -> u8 {
        self.parameters.share_count
    }

    #[must_use]
    pub fn ethereum_address(&self) -> String {
        compute_eth_address(&self.verifying_key)
    }

    #[must_use]
    pub fn verify_share(&self, party: PartyIndex, verification_share: &AffinePoint) -> bool {
        self.verifying_shares
            .get(&party)
            .is_some_and(|stored| stored == verification_share)
    }
}

/// Classifies the severity and required response for an abort.
///
/// The `DKLs23` protocol reuses base OT correlations across signing sessions.
/// If the COTe consistency check fails, information about this reused state
/// is leaked. The paper mandates that the offending counterparty must be
/// **permanently banned** from all future sessions. Failure to do so
/// enables a key extraction attack over multiple sessions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AbortKind {
    /// The protocol failed but can be retried safely.
    /// No long-term state was compromised.
    Recoverable,
    /// The identified counterparty cheated in a way that leaks information
    /// about reusable OT state. This party **MUST** be permanently excluded
    /// from all future signing and refresh sessions. Continuing to interact
    /// with this party enables private key extraction.
    BanCounterparty(PartyIndex),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Abort {
    /// Index of the party generating the abort message.
    pub index: PartyIndex,
    /// Indicates whether the abort requires permanently banning a counterparty.
    pub kind: AbortKind,
    pub description: String,
}

impl Abort {
    /// Creates a recoverable `Abort`.
    #[must_use]
    pub fn new(index: PartyIndex, description: &str) -> Abort {
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
    pub fn ban(index: PartyIndex, counterparty: PartyIndex, description: &str) -> Abort {
        Abort {
            index,
            kind: AbortKind::BanCounterparty(counterparty),
            description: String::from(description),
        }
    }
}

/// Saves the sender and receiver of a message.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PartiesMessage {
    pub sender: PartyIndex,
    pub receiver: PartyIndex,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn party_index_rejects_zero() {
        assert!(PartyIndex::new(0).is_err());
        assert!(PartyIndex::try_from(0u8).is_err());
    }

    #[test]
    fn party_index_accepts_nonzero() {
        for i in 1..=u8::MAX {
            assert!(PartyIndex::new(i).is_ok());
        }
    }

    #[test]
    fn party_index_round_trip() {
        for i in 1..=u8::MAX {
            let pi = PartyIndex::new(i).unwrap();
            assert_eq!(pi.as_u8(), i);
            assert_eq!(u8::from(pi), i);
        }
    }

    #[test]
    fn party_index_serde_json_transparent() {
        let pi = PartyIndex::new(5).unwrap();
        let json = serde_json::to_string(&pi).unwrap();
        assert_eq!(json, "5");

        let deserialized: PartyIndex = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, pi);
    }

    #[test]
    fn party_index_serde_rejects_zero() {
        let result: Result<PartyIndex, _> = serde_json::from_str("0");
        assert!(result.is_err());
    }

    #[test]
    fn party_index_btreemap_ordering() {
        let mut map = BTreeMap::new();
        map.insert(PartyIndex::new(3).unwrap(), "c");
        map.insert(PartyIndex::new(1).unwrap(), "a");
        map.insert(PartyIndex::new(2).unwrap(), "b");

        let keys: Vec<u8> = map.keys().map(|k| k.as_u8()).collect();
        assert_eq!(keys, vec![1, 2, 3]);
    }
}
