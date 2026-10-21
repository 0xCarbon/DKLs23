//! `DKLs23` signing protocol.
//!
//! This file implements the signing phase of Protocol 3.6 from `DKLs23`
//! (<https://eprint.iacr.org/2023/765.pdf>). It is the core of this repository.
//!
//! # Nomenclature
//!
//! For the messages structs, we will use the following nomenclature:
//!
//! **Transmit** messages refer to only one counterparty, hence
//! we must produce a whole vector of them. Each message in this
//! vector contains the party index to whom we should send it.
//!
//! **Broadcast** messages refer to all counterparties at once,
//! hence we only need to produce a unique instance of it.
//! This message is broadcasted to all parties.
//!
//! ATTENTION: we broadcast the message to ourselves as well!
//!
//! **Keep** messages refer to only one counterparty, hence
//! we must keep a whole vector of them. In this implementation,
//! we use a `BTreeMap` instead of a vector, where one can put
//! some party index in the key to retrieve the corresponding data.
//!
//! **Unique keep** messages refer to all counterparties at once,
//! hence we only need to keep a unique instance of it.
//!
//! The keep-state types in this module, along with [`Party::sign_phase1`]
//! through [`Party::sign_phase4`], are public low-level APIs for advanced
//! resumable/stateless orchestration. [`crate::protocols::sign_session::SignSession`]
//! remains the preferred high-level API.

use elliptic_curve::ops::Reduce;
use elliptic_curve::point::AffineCoordinates;
use elliptic_curve::scalar::IsHigh;
use ff::{Field, PrimeField};
use group::Curve;
use group::CurveAffine;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, ZeroizeOnDrop};

use hex;

use crate::curve::DklsCurve;
use crate::protocols::{Abort, AbortReason, PartiesMessage, Party, PartyIndex};

use crate::utilities::commits::{commit, verify_commitment};
use crate::utilities::hashes::{point_to_bytes, scalar_to_bytes, tagged_hash, HashOutput};
use crate::utilities::multiplication::{ErrorMul, MulDataToKeepReceiver, MulDataToReceiver};
use crate::utilities::oracle_tags::{
    TAG_SIGN_MUL_SESSION, TAG_SIGN_PAIR_SETUP, TAG_SIGN_SESSION_BINDING, TAG_SIGN_ZERO_SESSION,
};
use crate::utilities::ot::extension::{OTEDataToSender, OteNonce};
use crate::utilities::rng;

/// Data needed to start the signature and is used during the phases.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignData {
    /// Identifies this signing session; all signers must use the same value.
    /// A fresh value per attempt is recommended. Reusing one (for example on a
    /// retry after an abort) does not leak key material, because each
    /// multiplication's OT extension also mixes in fresh randomness from both
    /// parties, and a message answering a stale attempt is detected as a
    /// recoverable `SessionBindingMismatch`.
    pub sign_id: Vec<u8>,
    /// Vector containing the indices of the parties participating in the protocol (without us).
    pub counterparties: Vec<PartyIndex>,
    /// Hash of message being signed.
    pub message_hash: HashOutput,
}

// STRUCTS FOR MESSAGES TO TRANSMIT IN COMMUNICATION ROUNDS.

/// Transmit - Signing.
///
/// The message is produced/sent during Phase 1 and used in Phase 2.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransmitPhase1to2 {
    pub parties: PartiesMessage,
    /// Binds the message to its signing session (see `session_binding`).
    pub session_binding: HashOutput,
    pub commitment: HashOutput,
    #[zeroize(skip)]
    pub mul_transmit: OTEDataToSender,
}

/// Transmit - Signing.
///
/// The message is produced/sent during Phase 2 and used in Phase 3.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(
        serialize = "C::AffinePoint: serde::Serialize, C::Scalar: serde::Serialize",
        deserialize = "C::AffinePoint: serde::Deserialize<'de>, C::Scalar: serde::Deserialize<'de>"
    ))
)]
pub struct TransmitPhase2to3<C: DklsCurve> {
    pub parties: PartiesMessage,
    /// Binds the message to its signing session (see `session_binding`).
    pub session_binding: HashOutput,
    #[zeroize(skip)]
    pub gamma_u: C::AffinePoint,
    #[zeroize(skip)]
    pub gamma_v: C::AffinePoint,
    pub psi: C::Scalar,
    #[zeroize(skip)]
    pub public_share: C::AffinePoint,
    #[zeroize(skip)]
    pub instance_point: C::AffinePoint,
    pub salt: Vec<u8>,
    #[zeroize(skip)]
    pub mul_transmit: MulDataToReceiver<C>,
}

/// Broadcast - Signing.
///
/// The message is produced/sent during Phase 3 and used in Phase 4.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(
        serialize = "C::AffinePoint: serde::Serialize, C::Scalar: serde::Serialize",
        deserialize = "C::AffinePoint: serde::Deserialize<'de>, C::Scalar: serde::Deserialize<'de>"
    ))
)]
pub struct Broadcast3to4<C: DklsCurve> {
    pub u: C::Scalar,
    pub w: C::Scalar,
}

// STRUCTS FOR MESSAGES TO KEEP BETWEEN PHASES.

/// Keep - Signing.
///
/// The message is produced during Phase 1 and used in Phase 2.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(
        serialize = "C::AffinePoint: serde::Serialize, C::Scalar: serde::Serialize",
        deserialize = "C::AffinePoint: serde::Deserialize<'de>, C::Scalar: serde::Deserialize<'de>"
    ))
)]
pub struct KeepPhase1to2<C: DklsCurve> {
    pub salt: Vec<u8>,
    pub chi: C::Scalar,
    pub mul_keep: MulDataToKeepReceiver<C>,
}

/// Keep - Signing.
///
/// The message is produced during Phase 2 and used in Phase 3.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(
        serialize = "C::AffinePoint: serde::Serialize, C::Scalar: serde::Serialize",
        deserialize = "C::AffinePoint: serde::Deserialize<'de>, C::Scalar: serde::Deserialize<'de>"
    ))
)]
pub struct KeepPhase2to3<C: DklsCurve> {
    pub c_u: C::Scalar,
    pub c_v: C::Scalar,
    pub commitment: HashOutput,
    pub mul_keep: MulDataToKeepReceiver<C>,
    pub chi: C::Scalar,
    /// The counterparty's OT extension nonce from the phase-1 message we
    /// answered, which its phase-2 message must name as its own.
    pub counterparty_ote_nonce: OteNonce,
}

/// Unique keep - Signing.
///
/// The message is produced during Phase 1 and used in Phase 2.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(
        serialize = "C::AffinePoint: serde::Serialize, C::Scalar: serde::Serialize",
        deserialize = "C::AffinePoint: serde::Deserialize<'de>, C::Scalar: serde::Deserialize<'de>"
    ))
)]
pub struct UniqueKeep1to2<C: DklsCurve> {
    pub instance_key: C::Scalar,
    #[zeroize(skip)]
    pub instance_point: C::AffinePoint,
    pub inversion_mask: C::Scalar,
    pub zeta: C::Scalar,
}

/// Unique keep - Signing.
///
/// The message is produced during Phase 2 and used in Phase 3.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(
        serialize = "C::AffinePoint: serde::Serialize, C::Scalar: serde::Serialize",
        deserialize = "C::AffinePoint: serde::Deserialize<'de>, C::Scalar: serde::Deserialize<'de>"
    ))
)]
pub struct UniqueKeep2to3<C: DklsCurve> {
    pub instance_key: C::Scalar,
    #[zeroize(skip)]
    pub instance_point: C::AffinePoint,
    pub inversion_mask: C::Scalar,
    pub key_share: C::Scalar,
    #[zeroize(skip)]
    pub public_share: C::AffinePoint,
}

// MessageTag implementations.
#[cfg(feature = "serde")]
mod message_tags {
    use super::*;
    use crate::protocols::messages::MessageTag;

    impl MessageTag for TransmitPhase1to2 {
        const TAG: u8 = 0x10;
    }
    impl<C: DklsCurve> MessageTag for TransmitPhase2to3<C>
    where
        C::AffinePoint: serde::Serialize + serde::de::DeserializeOwned,
        C::Scalar: serde::Serialize + serde::de::DeserializeOwned,
    {
        const TAG: u8 = 0x11;
    }
    impl<C: DklsCurve> MessageTag for Broadcast3to4<C>
    where
        C::AffinePoint: serde::Serialize + serde::de::DeserializeOwned,
        C::Scalar: serde::Serialize + serde::de::DeserializeOwned,
    {
        const TAG: u8 = 0x12;
    }
}

// SIGNING PROTOCOL
// We now follow Protocol 3.6 of DKLs23.

/// Implementations related to the `DKLs23` signing protocol ([read more](self)).
impl<C: DklsCurve> Party<C> {
    /// The signer set (us and the counterparties), sorted.
    fn signers(data: &SignData, us: PartyIndex) -> Vec<u8> {
        let mut signers: Vec<u8> = data
            .counterparties
            .iter()
            .map(PartyIndex::as_u8)
            .chain([us.as_u8()])
            .collect();
        signers.sort_unstable();
        signers
    }

    /// Session id of the two-party multiplication in which `receiver` is the
    /// multiplication receiver and `sender` the sender.
    ///
    /// Covers the DKG session id, the sign id, the key in use (chain code and
    /// public key), the message hash and the signer set. Keys derived from
    /// the same shares (BIP-32 children, BOLT 3 keys) reuse the OT state, so
    /// the public key keeps each of their signing sessions under a distinct
    /// id; the message hash and signer set keep a reused sign id from
    /// repeating the id when either changes.
    fn mul_session_id(
        &self,
        data: &SignData,
        receiver: PartyIndex,
        sender: PartyIndex,
    ) -> HashOutput {
        tagged_hash(
            TAG_SIGN_MUL_SESSION,
            &[
                &self.session_id,
                &data.sign_id,
                &self.derivation_data.chain_code,
                &point_to_bytes::<C>(&self.pk),
                &data.message_hash,
                &Self::signers(data, self.party_index),
                &[receiver.as_u8(), sender.as_u8()],
            ],
        )
    }

    /// Session id of the zero-share computation, covering the same values as
    /// [`Self::mul_session_id`] except the multiplication roles.
    fn zero_session_id(&self, data: &SignData) -> HashOutput {
        tagged_hash(
            TAG_SIGN_ZERO_SESSION,
            &[
                &self.session_id,
                &data.sign_id,
                &self.derivation_data.chain_code,
                &point_to_bytes::<C>(&self.pk),
                &data.message_hash,
                &Self::signers(data, self.party_index),
            ],
        )
    }

    /// Binds a signing message to its session.
    ///
    /// Covers the DKG session id, the sign id, the chain code and public key
    /// (the key being used), the message hash, the signer set, the phase and
    /// the direction. A phase-2 message also covers the OT extension nonces of
    /// the phase-1 messages of both directions (`attempt_nonces`: the one it
    /// answers, then the sender's own), which are fresh in every attempt, so a
    /// message mixing attempts with the same sign id is caught too. A receiver
    /// compares it with its own value before any OT or multiplication work,
    /// so a message from a different session or attempt is reported as a
    /// recoverable mismatch instead of a failed OT check.
    ///
    /// It also covers the pair's multiplication setup (`pair_setup_digest`),
    /// so parties whose pairwise initializations differ (for example, one of
    /// them adopted a message from another run of the same session id) get a
    /// recoverable mismatch, not a failed OT check.
    fn session_binding(
        &self,
        data: &SignData,
        phase: u8,
        sender: PartyIndex,
        receiver: PartyIndex,
        attempt_nonces: &[u8],
    ) -> HashOutput {
        tagged_hash(
            TAG_SIGN_SESSION_BINDING,
            &[
                &self.session_id,
                &data.sign_id,
                &self.derivation_data.chain_code,
                &point_to_bytes::<C>(&self.pk),
                &data.message_hash,
                &Self::signers(data, self.party_index),
                &[phase, sender.as_u8(), receiver.as_u8()],
                attempt_nonces,
                &self.pair_setup_digest(if sender == self.party_index {
                    receiver
                } else {
                    sender
                }),
            ],
        )
    }

    /// Checks that both multiplication states with `counterparty` exist and
    /// are well formed. A malformed local state is not the counterparty's
    /// fault, so it is checked before anything derived from it.
    fn check_pair_state(&self, counterparty: PartyIndex) -> Result<(), Abort> {
        let missing = || {
            Abort::recoverable(
                self.party_index,
                AbortReason::MissingMulState { counterparty },
            )
        };
        let invalid = |error: ErrorMul| {
            Abort::recoverable(
                self.party_index,
                AbortReason::InvalidLocalState {
                    counterparty,
                    detail: error.description,
                },
            )
        };
        let sender = self.mul_senders.get(&counterparty).ok_or_else(missing)?;
        let receiver = self.mul_receivers.get(&counterparty).ok_or_else(missing)?;
        sender.check_state().map_err(invalid)?;
        receiver.check_state(None).map_err(invalid)
    }

    /// Digest of the multiplication setup with `counterparty`: the public
    /// gadgets of both directions, the lower index's receiver first, so both
    /// parties get the same value. Each gadget derives from the init message
    /// of its direction, so a pair whose initializations come from different
    /// runs gets different digests. Empty if a state is missing (the caller
    /// then aborts on the lookup).
    fn pair_setup_digest(&self, counterparty: PartyIndex) -> Vec<u8> {
        let (Some(receiver), Some(sender)) = (
            self.mul_receivers.get(&counterparty),
            self.mul_senders.get(&counterparty),
        ) else {
            return Vec::new();
        };
        let (first, second) = if self.party_index < counterparty {
            (&receiver.public_gadget, &sender.public_gadget)
        } else {
            (&sender.public_gadget, &receiver.public_gadget)
        };
        let gadget_bytes = |gadget: &Vec<C::Scalar>| -> Vec<u8> {
            gadget.iter().flat_map(scalar_to_bytes::<C>).collect()
        };
        tagged_hash(
            TAG_SIGN_PAIR_SETUP,
            &[&gadget_bytes(first), &gadget_bytes(second)],
        )
        .to_vec()
    }

    /// Phase 1 for signing: Steps 4, 5 and 6 from
    /// Protocol 3.6 in <https://eprint.iacr.org/2023/765.pdf>.
    ///
    /// The outputs should be kept or transmitted according to the conventions
    /// [here](self).
    ///
    /// # Errors
    ///
    /// Will return `Err` if the number of counterparties is wrong, if any
    /// party index is out of range, or if the counterparty list contains our
    /// own index.
    #[allow(clippy::type_complexity)]
    pub fn sign_phase1(
        &self,
        data: &SignData,
    ) -> Result<
        (
            UniqueKeep1to2<C>,
            BTreeMap<PartyIndex, KeepPhase1to2<C>>,
            Vec<TransmitPhase1to2>,
        ),
        Abort,
    > {
        // Step 4 - Check if we have the correct number of counter parties.
        if data.counterparties.len() != (self.parameters.threshold - 1) as usize {
            return Err(Abort::recoverable(
                self.party_index,
                AbortReason::WrongCounterpartyCount {
                    expected: (self.parameters.threshold - 1) as usize,
                    got: data.counterparties.len(),
                },
            ));
        }

        // Validate party index ranges and uniqueness.
        if self.party_index.as_u8() > self.parameters.share_count {
            return Err(Abort::recoverable(
                self.party_index,
                AbortReason::InvalidPartyIndex {
                    index: self.party_index,
                },
            ));
        }
        let mut seen_counterparties: BTreeSet<PartyIndex> = BTreeSet::new();
        for counterparty in &data.counterparties {
            if counterparty.as_u8() > self.parameters.share_count {
                return Err(Abort::recoverable(
                    self.party_index,
                    AbortReason::InvalidPartyIndex {
                        index: *counterparty,
                    },
                ));
            }
            if !seen_counterparties.insert(*counterparty) {
                return Err(Abort::recoverable(
                    self.party_index,
                    AbortReason::DuplicateCounterparty {
                        index: *counterparty,
                    },
                ));
            }
            if *counterparty == self.party_index {
                return Err(Abort::recoverable(
                    self.party_index,
                    AbortReason::SelfInCounterparties,
                ));
            }
            if !self.mul_senders.contains_key(counterparty)
                || !self.mul_receivers.contains_key(counterparty)
            {
                return Err(Abort::recoverable(
                    self.party_index,
                    AbortReason::MissingMulState {
                        counterparty: *counterparty,
                    },
                ));
            }
        }

        // Step 5 - Sample secret data.
        let instance_key = C::Scalar::random(&mut rng::get_rng());
        let inversion_mask = C::Scalar::random(&mut rng::get_rng());

        let generator = <C::AffinePoint as CurveAffine>::generator();
        let instance_point = (generator * instance_key).to_affine();

        // Step 6 - Prepare the messages to keep and to send.

        let mut keep: BTreeMap<PartyIndex, KeepPhase1to2<C>> = BTreeMap::new();
        let mut transmit: Vec<TransmitPhase1to2> =
            Vec::with_capacity((self.parameters.threshold - 1) as usize);
        for counterparty in &data.counterparties {
            // Two-party multiplication functionality.
            // We start as the receiver.

            // First, let us compute a session id for it.
            // As in Protocol 3.6 of DKLs23, we include the indexes from the parties.
            self.check_pair_state(*counterparty)?;
            let mul_sid = self.mul_session_id(data, self.party_index, *counterparty);

            // We run the first phase.
            let mul_receiver = self.mul_receivers.get(counterparty).ok_or_else(|| {
                Abort::recoverable(
                    self.party_index,
                    AbortReason::MissingMulState {
                        counterparty: *counterparty,
                    },
                )
            })?;
            // Phase 1 receives nothing, so it only fails on local state.
            let (chi, mul_keep, mul_transmit) =
                mul_receiver.run_phase1(&mul_sid).map_err(|error| {
                    Abort::recoverable(
                        self.party_index,
                        AbortReason::InvalidLocalState {
                            counterparty: *counterparty,
                            detail: error.description,
                        },
                    )
                })?;

            // Commit functionality. We commit to the instance point and to
            // psi, which phase 2 sends to this counterparty and which is
            // already fixed here, so that neither can change between phases.
            let psi = inversion_mask - chi;
            let (commitment, salt) =
                commit(&instance_commitment_message::<C>(&instance_point, &psi));

            // We gather the messages.
            keep.insert(
                *counterparty,
                KeepPhase1to2 {
                    salt,
                    chi,
                    mul_keep,
                },
            );
            transmit.push(TransmitPhase1to2 {
                parties: PartiesMessage {
                    sender: self.party_index,
                    receiver: *counterparty,
                },
                session_binding: self.session_binding(
                    data,
                    1,
                    self.party_index,
                    *counterparty,
                    &[],
                ),
                commitment,
                mul_transmit,
            });
        }

        // Zero-shares functionality.
        // We put it here because it doesn't depend on counter parties.

        // We first compute a session id.
        // Now, different to DKLs23, we won't put the indexes from the parties
        // because the sign id refers only to this set of parties.
        let zero_sid = self.zero_session_id(data);

        let zeta = self
            .zero_share
            .compute::<C>(&data.counterparties, &zero_sid);

        // "Unique" because it is only one message referring to all counter parties.
        let unique_keep = UniqueKeep1to2 {
            instance_key,
            instance_point,
            inversion_mask,
            zeta,
        };

        // We now return all these values.
        Ok((unique_keep, keep, transmit))
    }

    // Communication round 1
    // Transmit the messages.

    /// Phase 2 for signing: Step 7 from
    /// Protocol 3.6 in <https://eprint.iacr.org/2023/765.pdf>.
    ///
    /// The inputs come from the previous phase. The messages received
    /// should be gathered in a vector (in any order).
    ///
    /// The outputs should be kept or transmitted according to the conventions
    /// [here](self).
    ///
    /// # Errors
    ///
    /// Will return `Err` if the multiplication protocol fails.
    ///
    /// # Panics
    ///
    /// Will panic if the list of keys in the `BTreeMap`'s are incompatible
    /// with the party indices in the vector `received`.
    #[allow(clippy::type_complexity)]
    pub fn sign_phase2(
        &self,
        data: &SignData,
        unique_kept: &UniqueKeep1to2<C>,
        kept: &BTreeMap<PartyIndex, KeepPhase1to2<C>>,
        received: &[TransmitPhase1to2],
    ) -> Result<
        (
            UniqueKeep2to3<C>,
            BTreeMap<PartyIndex, KeepPhase2to3<C>>,
            Vec<TransmitPhase2to3<C>>,
        ),
        Abort,
    > {
        // Step 7

        // Compute the values that only depend on us.

        // We find the Lagrange coefficient associated to us.
        // It is the same as the one calculated during DKG.
        let mut l_numerator = <C::Scalar as Field>::ONE;
        let mut l_denominator = <C::Scalar as Field>::ONE;
        for counterparty in &data.counterparties {
            l_numerator *= C::Scalar::from(u64::from(counterparty.as_u8()));
            l_denominator *= C::Scalar::from(u64::from(counterparty.as_u8()))
                - C::Scalar::from(u64::from(self.party_index.as_u8()));
        }
        let l_denominator_inverse = match Option::<C::Scalar>::from(l_denominator.invert()) {
            Some(inv) => inv,
            None => {
                return Err(Abort::recoverable(
                    self.party_index,
                    AbortReason::LagrangeCoefficientFailed,
                ));
            }
        };
        let l = l_numerator * l_denominator_inverse;

        // These are sk_i and pk_i from the paper.
        let key_share = (self.poly_point * l) + unique_kept.zeta;
        let generator = <C::AffinePoint as CurveAffine>::generator();
        let public_share = (generator * key_share).to_affine();

        // This is the input for the multiplication protocol.
        let input = vec![unique_kept.instance_key, key_share];

        // Now, we compute the variables related to each counter party.
        let mut keep: BTreeMap<PartyIndex, KeepPhase2to3<C>> = BTreeMap::new();
        let mut transmit: Vec<TransmitPhase2to3<C>> =
            Vec::with_capacity((self.parameters.threshold - 1) as usize);
        if received.len() != data.counterparties.len() {
            return Err(Abort::recoverable(
                self.party_index,
                AbortReason::WrongMessageCount {
                    expected: data.counterparties.len(),
                    got: received.len(),
                },
            ));
        }
        let mut seen_senders: BTreeSet<PartyIndex> = BTreeSet::new();
        for message in received {
            // Validate sender identity before processing (defense-in-depth against misrouting).
            let counterparty = message.parties.sender;
            if !data.counterparties.contains(&counterparty) {
                return Err(Abort::recoverable(
                    self.party_index,
                    AbortReason::UnexpectedSender {
                        sender: counterparty,
                    },
                ));
            }
            if message.parties.receiver != self.party_index {
                return Err(Abort::recoverable(
                    self.party_index,
                    AbortReason::MisroutedMessage {
                        expected_receiver: self.party_index,
                        actual_receiver: message.parties.receiver,
                    },
                ));
            }
            if !seen_senders.insert(counterparty) {
                return Err(Abort::recoverable(
                    self.party_index,
                    AbortReason::DuplicateSender {
                        sender: counterparty,
                    },
                ));
            }
            self.check_pair_state(counterparty)?;
            if message.session_binding
                != self.session_binding(data, 1, counterparty, self.party_index, &[])
            {
                return Err(Abort::recoverable(
                    self.party_index,
                    AbortReason::SessionBindingMismatch { counterparty },
                ));
            }
            let current_kept = kept.get(&counterparty).ok_or_else(|| {
                Abort::recoverable(
                    self.party_index,
                    AbortReason::MissingMulState { counterparty },
                )
            })?;

            // We continue the multiplication protocol to get the values
            // c^u and c^v from the paper. We are now the sender.

            // Let us retrieve the session id for multiplication.
            // Note that the roles are now reversed.
            let mul_sid = self.mul_session_id(data, counterparty, self.party_index);

            let mul_sender = self.mul_senders.get(&counterparty).ok_or_else(|| {
                Abort::recoverable(
                    self.party_index,
                    AbortReason::MissingMulState { counterparty },
                )
            })?;
            // A malformed local state is not the counterparty's fault.
            mul_sender.check_state().map_err(|error| {
                Abort::recoverable(
                    self.party_index,
                    AbortReason::InvalidLocalState {
                        counterparty,
                        detail: error.description,
                    },
                )
            })?;
            let mul_result = mul_sender.run(&mul_sid, &input, &message.mul_transmit);

            let c_u: C::Scalar;
            let c_v: C::Scalar;
            let mul_transmit: MulDataToReceiver<C>;
            match mul_result {
                Err(error) => {
                    return Err(Abort::ban(
                        self.party_index,
                        counterparty,
                        AbortReason::MultiplicationVerificationFailed {
                            counterparty,
                            detail: error.description.clone(),
                        },
                    ));
                }
                Ok((c_values, data_to_receiver)) => {
                    c_u = c_values[0];
                    c_v = c_values[1];
                    mul_transmit = data_to_receiver;
                }
            }

            // We compute the remaining values.
            let gamma_u = (generator * c_u).to_affine();
            let gamma_v = (generator * c_v).to_affine();

            let psi = unique_kept.inversion_mask - current_kept.chi;

            keep.insert(
                counterparty,
                KeepPhase2to3 {
                    c_u,
                    c_v,
                    commitment: message.commitment,
                    mul_keep: current_kept.mul_keep.clone(),
                    chi: current_kept.chi,
                    counterparty_ote_nonce: message.mul_transmit.nonce,
                },
            );
            transmit.push(TransmitPhase2to3 {
                parties: PartiesMessage {
                    sender: self.party_index,
                    receiver: counterparty,
                },
                session_binding: self.session_binding(
                    data,
                    2,
                    self.party_index,
                    counterparty,
                    &[message.mul_transmit.nonce, current_kept.mul_keep.ote_nonce].concat(),
                ),
                // Check-adjust
                gamma_u,
                gamma_v,
                psi,
                public_share,
                // Decommit
                instance_point: unique_kept.instance_point,
                salt: current_kept.salt.clone(),
                // Multiply
                mul_transmit,
            });
        }

        // Common values to keep for the next phase.
        let unique_keep = UniqueKeep2to3 {
            instance_key: unique_kept.instance_key,
            instance_point: unique_kept.instance_point,
            inversion_mask: unique_kept.inversion_mask,
            key_share,
            public_share,
        };

        Ok((unique_keep, keep, transmit))
    }

    // Communication round 2
    // Transmit the messages.

    /// Phase 3 for signing: Steps 8 and 9 from
    /// Protocol 3.6 in <https://eprint.iacr.org/2023/765.pdf>.
    ///
    /// The inputs come from the previous phase. The messages received
    /// should be gathered in a vector (in any order).
    ///
    /// The first output is already the value `r` from the ECDSA signature.
    /// The second output should be broadcasted according to the conventions
    /// [here](self).
    ///
    /// # Errors
    ///
    /// Will return `Err` if some commitment doesn't verify, if the multiplication
    /// protocol fails or if one of the consistency checks is false. The error
    /// will also happen if the total instance point is trivial (very unlikely).
    ///
    /// # Panics
    ///
    /// Will panic if the list of keys in the `BTreeMap`'s are incompatible
    /// with the party indices in the vector `received`.
    pub fn sign_phase3(
        &self,
        data: &SignData,
        unique_kept: &UniqueKeep2to3<C>,
        kept: &BTreeMap<PartyIndex, KeepPhase2to3<C>>,
        received: &[TransmitPhase2to3<C>],
    ) -> Result<(String, Broadcast3to4<C>), Abort> {
        // Steps 8 and 9

        // The following values will represent the sums calculated in this step.
        let mut expected_public_key = unique_kept.public_share;
        let mut total_instance_point = unique_kept.instance_point;

        let mut first_sum_u_v = unique_kept.inversion_mask;

        let mut second_sum_u = <C::Scalar as Field>::ZERO;
        let mut second_sum_v = <C::Scalar as Field>::ZERO;

        if received.len() != data.counterparties.len() {
            return Err(Abort::recoverable(
                self.party_index,
                AbortReason::WrongMessageCount {
                    expected: data.counterparties.len(),
                    got: received.len(),
                },
            ));
        }
        let mut seen_senders: BTreeSet<PartyIndex> = BTreeSet::new();
        for message in received {
            // Validate sender identity before processing (defense-in-depth against misrouting).
            let counterparty = message.parties.sender;
            if !data.counterparties.contains(&counterparty) {
                return Err(Abort::recoverable(
                    self.party_index,
                    AbortReason::UnexpectedSender {
                        sender: counterparty,
                    },
                ));
            }
            if message.parties.receiver != self.party_index {
                return Err(Abort::recoverable(
                    self.party_index,
                    AbortReason::MisroutedMessage {
                        expected_receiver: self.party_index,
                        actual_receiver: message.parties.receiver,
                    },
                ));
            }
            let identity = <C::AffinePoint as CurveAffine>::identity();
            if message.instance_point == identity {
                return Err(Abort::recoverable(
                    self.party_index,
                    AbortReason::TrivialInstancePoint { counterparty },
                ));
            }
            if !seen_senders.insert(counterparty) {
                return Err(Abort::recoverable(
                    self.party_index,
                    AbortReason::DuplicateSender {
                        sender: counterparty,
                    },
                ));
            }
            let current_kept = kept.get(&counterparty).ok_or_else(|| {
                Abort::recoverable(
                    self.party_index,
                    AbortReason::MissingMulState { counterparty },
                )
            })?;
            self.check_pair_state(counterparty)?;
            if message.session_binding
                != self.session_binding(
                    data,
                    2,
                    counterparty,
                    self.party_index,
                    &[
                        current_kept.mul_keep.ote_nonce,
                        current_kept.counterparty_ote_nonce,
                    ]
                    .concat(),
                )
            {
                return Err(Abort::recoverable(
                    self.party_index,
                    AbortReason::SessionBindingMismatch { counterparty },
                ));
            }

            // Checking the committed values.
            let verification = verify_commitment(
                &instance_commitment_message::<C>(&message.instance_point, &message.psi),
                &current_kept.commitment,
                &message.salt,
            );
            if !verification {
                return Err(Abort::recoverable(
                    self.party_index,
                    AbortReason::CommitmentMismatch { counterparty },
                ));
            }

            // Finishing the multiplication protocol.
            // We are now the receiver.

            // Let us retrieve the session id for multiplication.
            // Note that we reverse the roles again.
            let mul_sid = self.mul_session_id(data, self.party_index, counterparty);

            let mul_receiver = self.mul_receivers.get(&counterparty).ok_or_else(|| {
                Abort::recoverable(
                    self.party_index,
                    AbortReason::MissingMulState { counterparty },
                )
            })?;
            // A malformed local state is not the counterparty's fault.
            mul_receiver
                .check_state(Some(&current_kept.mul_keep))
                .map_err(|error| {
                    Abort::recoverable(
                        self.party_index,
                        AbortReason::InvalidLocalState {
                            counterparty,
                            detail: error.description,
                        },
                    )
                })?;
            let mul_result =
                mul_receiver.run_phase2(&mul_sid, &current_kept.mul_keep, &message.mul_transmit);

            let d_u: C::Scalar;
            let d_v: C::Scalar;
            match mul_result {
                Err(error) => {
                    return Err(Abort::ban(
                        self.party_index,
                        counterparty,
                        AbortReason::MultiplicationVerificationFailed {
                            counterparty,
                            detail: error.description.clone(),
                        },
                    ));
                }
                Ok(d_values) => {
                    d_u = d_values[0];
                    d_v = d_values[1];
                }
            }

            // First consistency checks.
            let generator = <C::AffinePoint as CurveAffine>::generator();

            if (message.instance_point * current_kept.chi) != ((generator * d_u) + message.gamma_u)
            {
                return Err(Abort::ban(
                    self.party_index,
                    counterparty,
                    AbortReason::GammaUInconsistency { counterparty },
                ));
            }

            // In the paper, they write "Lagrange(P, j, 0) · P(j)". For the math
            // to be consistent, we believe it should be "pk_j" instead.
            // This agrees with the alternative computation of gamma_v at the
            // end of page 21 in the paper.
            if (message.public_share * current_kept.chi) != ((generator * d_v) + message.gamma_v) {
                return Err(Abort::ban(
                    self.party_index,
                    counterparty,
                    AbortReason::OtConsistencyCheckFailed { counterparty },
                ));
            }

            // We add the current summand to our sums.
            expected_public_key =
                (C::ProjectivePoint::from(expected_public_key) + message.public_share).to_affine();
            total_instance_point = (C::ProjectivePoint::from(total_instance_point)
                + message.instance_point)
                .to_affine();

            first_sum_u_v += &message.psi;

            second_sum_u = second_sum_u + current_kept.c_u + d_u;
            second_sum_v = second_sum_v + current_kept.c_v + d_v;
        }

        // Second consistency check.
        if expected_public_key != self.pk {
            return Err(Abort::recoverable(
                self.party_index,
                AbortReason::PolynomialInconsistency,
            ));
        }

        // We introduce another consistency check: the total instance point
        // should not be the point at infinity (this is not specified on
        // DKLs23 but actually on ECDSA itself). In any case, the probability
        // of this happening is very low.
        if total_instance_point == <C::AffinePoint as CurveAffine>::identity() {
            return Err(Abort::recoverable(
                self.party_index,
                AbortReason::PolynomialInconsistency,
            ));
        }

        // Compute u_i, v_i and w_i from the paper.
        let u = (unique_kept.instance_key * first_sum_u_v) + second_sum_u;
        let v = (unique_kept.key_share * first_sum_u_v) + second_sum_v;

        let x_coord = hex::encode(total_instance_point.x());
        // There is no salt because the hash function here is always the same.
        let msg_scalar = reduce_hash_bytes::<C>(&data.message_hash);
        let rx_scalar = reduce_hex_bytes::<C>(&x_coord);
        let w = (msg_scalar * unique_kept.inversion_mask) + (v * rx_scalar);

        let broadcast = Broadcast3to4 { u, w };

        // We also return the x-coordinate of the instance point.
        // This is half of the final signature.

        Ok((x_coord, broadcast))
    }

    // Communication round 3
    // Broadcast the messages (including to ourselves).

    /// Phase 4 for signing: Step 10 from
    /// Protocol 3.6 in <https://eprint.iacr.org/2023/765.pdf>.
    ///
    /// The inputs come from the previous phase. The messages received
    /// should be gathered in a vector (in any order). Note that our
    /// broadcasted message from the previous round should also appear
    /// here.
    ///
    /// The first output is the value `s` from the ECDSA signature.
    /// The second output is the recovery id from the ECDSA signature.
    /// Note that the parameter 'v' isn't this value, but it is used to compute it.
    /// To know how to compute it, check the EIP which standardizes the transaction format
    /// that you're using. For example: EIP-155, EIP-2930, EIP-1559.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the final ECDSA signature is invalid
    /// or if the denominator in signature assembly is zero.
    pub fn sign_phase4(
        &self,
        data: &SignData,
        x_coord: &str,
        received: &[Broadcast3to4<C>],
        normalize: bool,
    ) -> Result<(String, u8), Abort> {
        // Step 10

        let mut numerator = <C::Scalar as Field>::ZERO;
        let mut denominator = <C::Scalar as Field>::ZERO;
        for message in received {
            numerator += &message.w;
            denominator += &message.u;
        }

        let denominator_inverse = match Option::<C::Scalar>::from(denominator.invert()) {
            Some(inv) => inv,
            None => {
                return Err(Abort::recoverable(
                    self.party_index,
                    AbortReason::ZeroDenominator,
                ));
            }
        };
        let mut s = numerator * denominator_inverse;

        // Normalize signature into "low S" form as described in
        // BIP-0062 Dealing with Malleability: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
        if normalize && s.is_high().into() {
            s = -s;
        }

        let s_bytes: elliptic_curve::FieldBytes<C> = s.into();
        let signature = hex::encode(s_bytes);

        let verification =
            verify_ecdsa_signature::<C>(&data.message_hash, &self.pk, x_coord, &signature);
        if !verification {
            return Err(Abort::recoverable(
                self.party_index,
                AbortReason::SignatureVerificationFailed,
            ));
        }

        // First calculate R (signature point) in order to retrieve its y coordinate.
        // This is necessary because we need to check if y is even or odd to calculate the
        // recovery id. We compute R in the same way that we did in verify_ecdsa_signature:
        // R = (G * msg_hash + pk * r_x) / s
        let rx_scalar = reduce_hex_bytes::<C>(x_coord);
        let msg_scalar = reduce_hash_bytes::<C>(&data.message_hash);
        let generator = <C::AffinePoint as CurveAffine>::generator();
        let first = generator * msg_scalar;
        let second = self.pk * rx_scalar;
        let s_inverse = s.invert().unwrap();
        let signature_point = ((first + second) * s_inverse).to_affine();

        // Compute recovery id from the signature point R.
        //
        // y-parity: determined from the compressed SEC1 prefix byte (0x02=even, 0x03=odd).
        let compressed = group::GroupEncoding::to_bytes(&signature_point);
        let is_y_odd = compressed.as_ref()[0] == 0x03;

        // is_x_reduced: true when R.x (as a field element) >= the curve order n,
        // meaning Scalar::reduce(&R.x) lost information. This is negligibly rare
        // but must be correct for downstream key-recovery flows.
        let x_bytes_original = {
            let mut bytes = vec![0u8; elliptic_curve::FieldBytes::<C>::default().len()];
            hex::decode_to_slice(x_coord, &mut bytes).expect("valid hex");
            bytes
        };
        let rx_repr = rx_scalar.to_repr();
        let rx_repr_slice: &[u8] = rx_repr.as_ref();
        let is_x_reduced = x_bytes_original.as_slice() != rx_repr_slice;

        // Recovery ID: bit 0 = y_is_odd, bit 1 = x_is_reduced
        let rec_id = (is_y_odd as u8) | ((is_x_reduced as u8) << 1);

        Ok((signature, rec_id))
    }
}

/// The message a signer commits to in phase 1 for one counterparty: its
/// instance point and the psi it will send to that counterparty in phase 2.
fn instance_commitment_message<C: DklsCurve>(
    instance_point: &C::AffinePoint,
    psi: &C::Scalar,
) -> Vec<u8> {
    [
        point_to_bytes::<C>(instance_point),
        scalar_to_bytes::<C>(psi),
    ]
    .concat()
}

/// Parses a hex string as a canonical scalar for curve `C` (value must be < curve order n).
///
/// Returns `None` if the hex string is invalid or represents a value >= n.
/// This enforces strict ECDSA range requirements for signature verification.
fn parse_hex_to_scalar<C: DklsCurve>(hex_value: &str) -> Option<C::Scalar> {
    let mut bytes = vec![0u8; elliptic_curve::FieldBytes::<C>::default().len()];
    if hex::decode_to_slice(hex_value, &mut bytes).is_err() {
        return None;
    }
    let field_bytes: &elliptic_curve::FieldBytes<C> = bytes.as_slice().try_into().ok()?;
    Option::from(<C::Scalar as PrimeField>::from_repr(*field_bytes))
}

/// Reduces a 32-byte hash output into a scalar for curve `C`.
fn reduce_hash_bytes<C: DklsCurve>(hash: &HashOutput) -> C::Scalar {
    let field_bytes: &elliptic_curve::FieldBytes<C> = hash
        .as_slice()
        .try_into()
        .expect("hash output length matches field size");
    <C::Scalar as Reduce<elliptic_curve::FieldBytes<C>>>::reduce(field_bytes)
}

/// Reduces a hex string into a scalar for curve `C`.
fn reduce_hex_bytes<C: DklsCurve>(hex_value: &str) -> C::Scalar {
    let mut bytes = vec![0u8; elliptic_curve::FieldBytes::<C>::default().len()];
    hex::decode_to_slice(hex_value, &mut bytes).expect("valid hex");
    let field_bytes: &elliptic_curve::FieldBytes<C> = bytes
        .as_slice()
        .try_into()
        .expect("decoded hex length matches field size");
    <C::Scalar as Reduce<elliptic_curve::FieldBytes<C>>>::reduce(field_bytes)
}

/// Usual verifying function from ECDSA.
///
/// It receives a message already in bytes.
#[must_use]
pub fn verify_ecdsa_signature<C: DklsCurve>(
    msg: &HashOutput,
    pk: &C::AffinePoint,
    x_coord: &str,
    signature: &str,
) -> bool {
    // No signature is valid under the identity: it is not a public key.
    if *pk == <C::AffinePoint as CurveAffine>::identity() {
        return false;
    }
    let rx_as_scalar = match parse_hex_to_scalar::<C>(x_coord) {
        Some(value) => value,
        None => return false,
    };
    let s_as_scalar = match parse_hex_to_scalar::<C>(signature) {
        Some(value) => value,
        None => return false,
    };

    // Verify if the numbers are non-zero (valid ECDSA range check).
    if rx_as_scalar == <C::Scalar as Field>::ZERO || s_as_scalar == <C::Scalar as Field>::ZERO {
        return false;
    }

    let inverse_s = match Option::<C::Scalar>::from(s_as_scalar.invert()) {
        Some(inv) => inv,
        None => return false,
    };

    let msg_scalar = reduce_hash_bytes::<C>(msg);
    let first = msg_scalar * inverse_s;
    let second = rx_as_scalar * inverse_s;

    let generator = <C::AffinePoint as CurveAffine>::generator();
    let point_to_check = ((generator * first) + (*pk * second)).to_affine();
    let identity = <C::AffinePoint as CurveAffine>::identity();
    if point_to_check == identity {
        return false;
    }

    let x_bytes = point_to_check.x();
    let x_field_bytes: &elliptic_curve::FieldBytes<C> = (&x_bytes[..])
        .try_into()
        .expect("x coordinate length matches field size");
    let x_check = <C::Scalar as Reduce<elliptic_curve::FieldBytes<C>>>::reduce(x_field_bytes);

    x_check == rx_as_scalar
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::dkg::*;
    use crate::protocols::re_key::re_key;
    use crate::protocols::*;
    use crate::utilities::hashes::tagged_hash;
    use elliptic_curve::sec1::ToSec1Point;
    use elliptic_curve::Curve as _;
    use elliptic_curve::CurveArithmetic;
    use k256::{AffinePoint, ProjectivePoint, Scalar, Secp256k1, U256};
    use rand::RngExt;

    type TestCurve = k256::Secp256k1;

    fn no_address(_pk: &<TestCurve as CurveArithmetic>::AffinePoint) -> String {
        String::new()
    }

    /// Tests if the signing protocol generates a valid ECDSA signature.
    ///
    /// In this case, parties are sampled via the [`re_key`] function.
    #[test]
    fn test_signing() {
        // Disclaimer: this implementation is not the most efficient,
        // we are only testing if everything works! Note as well that
        // parties are being simulated one after the other, but they
        // should actually execute the protocol simultaneously.

        let threshold = rng::get_rng().random_range(2..=5); // You can change the ranges here.
        let offset = rng::get_rng().random_range(0..=5);

        let parameters = Parameters {
            threshold,
            share_count: threshold + offset,
        }; // You can fix the parameters if you prefer.

        // We use the re_key function to quickly sample the parties.
        let session_id = rng::get_rng().random::<[u8; crate::utilities::ID_LEN]>();
        let secret_key = Scalar::random(&mut rng::get_rng());
        let (parties, _) =
            re_key::<TestCurve>(&parameters, &session_id, &secret_key, None, no_address);

        // SIGNING

        let sign_id = rng::get_rng().random::<[u8; crate::utilities::ID_LEN]>();
        let message_to_sign = tagged_hash(b"test-sign", &[b"Message to sign!"]);

        // For simplicity, we are testing only the first parties.
        let executing_parties: Vec<PartyIndex> = (1..=parameters.threshold)
            .map(|i| PartyIndex::new(i).unwrap())
            .collect();

        // Each party prepares their data for this signing session.
        let mut all_data: BTreeMap<PartyIndex, SignData> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            //Gather the counterparties
            let mut counterparties = executing_parties.clone();
            counterparties.retain(|index| *index != party_index);

            all_data.insert(
                party_index,
                SignData {
                    sign_id: sign_id.to_vec(),
                    counterparties,
                    message_hash: message_to_sign,
                },
            );
        }

        // Phase 1
        let mut unique_kept_1to2: BTreeMap<PartyIndex, UniqueKeep1to2<TestCurve>> = BTreeMap::new();
        let mut kept_1to2: BTreeMap<PartyIndex, BTreeMap<PartyIndex, KeepPhase1to2<TestCurve>>> =
            BTreeMap::new();
        let mut transmit_1to2: BTreeMap<PartyIndex, Vec<TransmitPhase1to2>> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            let (unique_keep, keep, transmit) = parties[(party_index.as_u8() - 1) as usize]
                .sign_phase1(all_data.get(&party_index).unwrap())
                .unwrap();

            unique_kept_1to2.insert(party_index, unique_keep);
            kept_1to2.insert(party_index, keep);
            transmit_1to2.insert(party_index, transmit);
        }

        // Communication round 1
        let mut received_1to2: BTreeMap<PartyIndex, Vec<TransmitPhase1to2>> = BTreeMap::new();

        for &party_index in &executing_parties {
            let messages_for_party: Vec<TransmitPhase1to2> = transmit_1to2
                .values()
                .flatten()
                .filter(|message| message.parties.receiver == party_index)
                .cloned()
                .collect();

            received_1to2.insert(party_index, messages_for_party);
        }

        // Phase 2
        let mut unique_kept_2to3: BTreeMap<PartyIndex, UniqueKeep2to3<TestCurve>> = BTreeMap::new();
        let mut kept_2to3: BTreeMap<PartyIndex, BTreeMap<PartyIndex, KeepPhase2to3<TestCurve>>> =
            BTreeMap::new();
        let mut transmit_2to3: BTreeMap<PartyIndex, Vec<TransmitPhase2to3<TestCurve>>> =
            BTreeMap::new();
        for party_index in executing_parties.clone() {
            let result = parties[(party_index.as_u8() - 1) as usize].sign_phase2(
                all_data.get(&party_index).unwrap(),
                unique_kept_1to2.get(&party_index).unwrap(),
                kept_1to2.get(&party_index).unwrap(),
                received_1to2.get(&party_index).unwrap(),
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description());
                }
                Ok((unique_keep, keep, transmit)) => {
                    unique_kept_2to3.insert(party_index, unique_keep);
                    kept_2to3.insert(party_index, keep);
                    transmit_2to3.insert(party_index, transmit);
                }
            }
        }

        // Communication round 2
        let mut received_2to3: BTreeMap<PartyIndex, Vec<TransmitPhase2to3<TestCurve>>> =
            BTreeMap::new();

        for &party_index in &executing_parties {
            let messages_for_party: Vec<TransmitPhase2to3<TestCurve>> = transmit_2to3
                .values()
                .flatten()
                .filter(|message| message.parties.receiver == party_index)
                .cloned()
                .collect();

            received_2to3.insert(party_index, messages_for_party);
        }

        // Phase 3
        let mut x_coords: Vec<String> = Vec::with_capacity(parameters.threshold as usize);
        let mut broadcast_3to4: Vec<Broadcast3to4<TestCurve>> =
            Vec::with_capacity(parameters.threshold as usize);
        for party_index in executing_parties.clone() {
            let result = parties[(party_index.as_u8() - 1) as usize].sign_phase3(
                all_data.get(&party_index).unwrap(),
                unique_kept_2to3.get(&party_index).unwrap(),
                kept_2to3.get(&party_index).unwrap(),
                received_2to3.get(&party_index).unwrap(),
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description());
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
            assert_eq!(x_coord, x_coords[i as usize]);
        }

        // Communication round 3
        // This is a broadcast to all parties. The desired result is already broadcast_3to4.

        // Phase 4
        // It is essentially independent of the party, so we compute just once.
        let some_index = executing_parties[0];
        let result = parties[(some_index.as_u8() - 1) as usize].sign_phase4(
            all_data.get(&some_index).unwrap(),
            &x_coord,
            &broadcast_3to4,
            true,
        );
        if let Err(abort) = result {
            panic!("Party {} aborted: {:?}", abort.index, abort.description());
        }
        // We could call verify_ecdsa_signature here, but it is already called during Phase 4.
    }

    /// Tests if the signing protocol generates a valid ECDSA signature
    /// and that it is the same one as we would get if we knew the
    /// secret key shared by the parties.
    ///
    /// In this case, parties are sampled via the [`re_key`] function.
    #[test]
    fn test_signing_against_ecdsa() {
        let threshold = rng::get_rng().random_range(2..=5); // You can change the ranges here.
        let offset = rng::get_rng().random_range(0..=5);

        let parameters = Parameters {
            threshold,
            share_count: threshold + offset,
        }; // You can fix the parameters if you prefer.

        // We use the re_key function to quickly sample the parties.
        let session_id = rng::get_rng().random::<[u8; crate::utilities::ID_LEN]>();
        let secret_key = Scalar::random(&mut rng::get_rng());
        let (parties, _) =
            re_key::<TestCurve>(&parameters, &session_id, &secret_key, None, no_address);

        // SIGNING (as in test_signing)

        let sign_id = rng::get_rng().random::<[u8; crate::utilities::ID_LEN]>();
        let message_to_sign = tagged_hash(b"test-sign", &[b"Message to sign!"]);

        // For simplicity, we are testing only the first parties.
        let executing_parties: Vec<PartyIndex> = (1..=parameters.threshold)
            .map(|i| PartyIndex::new(i).unwrap())
            .collect();

        // Each party prepares their data for this signing session.
        let mut all_data: BTreeMap<PartyIndex, SignData> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            //Gather the counterparties
            let mut counterparties = executing_parties.clone();
            counterparties.retain(|index| *index != party_index);

            all_data.insert(
                party_index,
                SignData {
                    sign_id: sign_id.to_vec(),
                    counterparties,
                    message_hash: message_to_sign,
                },
            );
        }

        // Phase 1
        let mut unique_kept_1to2: BTreeMap<PartyIndex, UniqueKeep1to2<TestCurve>> = BTreeMap::new();
        let mut kept_1to2: BTreeMap<PartyIndex, BTreeMap<PartyIndex, KeepPhase1to2<TestCurve>>> =
            BTreeMap::new();
        let mut transmit_1to2: BTreeMap<PartyIndex, Vec<TransmitPhase1to2>> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            let (unique_keep, keep, transmit) = parties[(party_index.as_u8() - 1) as usize]
                .sign_phase1(all_data.get(&party_index).unwrap())
                .unwrap();

            unique_kept_1to2.insert(party_index, unique_keep);
            kept_1to2.insert(party_index, keep);
            transmit_1to2.insert(party_index, transmit);
        }

        // Communication round 1
        let mut received_1to2: BTreeMap<PartyIndex, Vec<TransmitPhase1to2>> = BTreeMap::new();

        for &party_index in &executing_parties {
            let messages_for_party: Vec<TransmitPhase1to2> = transmit_1to2
                .values()
                .flatten()
                .filter(|message| message.parties.receiver == party_index)
                .cloned()
                .collect();

            received_1to2.insert(party_index, messages_for_party);
        }

        // Phase 2
        let mut unique_kept_2to3: BTreeMap<PartyIndex, UniqueKeep2to3<TestCurve>> = BTreeMap::new();
        let mut kept_2to3: BTreeMap<PartyIndex, BTreeMap<PartyIndex, KeepPhase2to3<TestCurve>>> =
            BTreeMap::new();
        let mut transmit_2to3: BTreeMap<PartyIndex, Vec<TransmitPhase2to3<TestCurve>>> =
            BTreeMap::new();
        for party_index in executing_parties.clone() {
            let result = parties[(party_index.as_u8() - 1) as usize].sign_phase2(
                all_data.get(&party_index).unwrap(),
                unique_kept_1to2.get(&party_index).unwrap(),
                kept_1to2.get(&party_index).unwrap(),
                received_1to2.get(&party_index).unwrap(),
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description());
                }
                Ok((unique_keep, keep, transmit)) => {
                    unique_kept_2to3.insert(party_index, unique_keep);
                    kept_2to3.insert(party_index, keep);
                    transmit_2to3.insert(party_index, transmit);
                }
            }
        }

        // Communication round 2
        let mut received_2to3: BTreeMap<PartyIndex, Vec<TransmitPhase2to3<TestCurve>>> =
            BTreeMap::new();

        for &party_index in &executing_parties {
            let messages_for_party: Vec<TransmitPhase2to3<TestCurve>> = transmit_2to3
                .values()
                .flatten()
                .filter(|message| message.parties.receiver == party_index)
                .cloned()
                .collect();

            received_2to3.insert(party_index, messages_for_party);
        }

        // Phase 3
        let mut x_coords: Vec<String> = Vec::with_capacity(parameters.threshold as usize);
        let mut broadcast_3to4: Vec<Broadcast3to4<TestCurve>> =
            Vec::with_capacity(parameters.threshold as usize);
        for party_index in executing_parties.clone() {
            let result = parties[(party_index.as_u8() - 1) as usize].sign_phase3(
                all_data.get(&party_index).unwrap(),
                unique_kept_2to3.get(&party_index).unwrap(),
                kept_2to3.get(&party_index).unwrap(),
                received_2to3.get(&party_index).unwrap(),
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description());
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
            assert_eq!(x_coord, x_coords[i as usize]);
        }

        // Communication round 3
        // This is a broadcast to all parties. The desired result is already broadcast_3to4.

        // Phase 4
        // It is essentially independent of the party, so we compute just once.
        let some_index = executing_parties[0];
        let result = parties[(some_index.as_u8() - 1) as usize].sign_phase4(
            all_data.get(&some_index).unwrap(),
            &x_coord,
            &broadcast_3to4,
            false,
        );
        let signature = match result {
            Err(abort) => {
                panic!("Party {} aborted: {:?}", abort.index, abort.description());
            }
            Ok(s) => s,
        };
        // We could call verify_ecdsa_signature here, but it is already called during Phase 4.

        // ECDSA (computations that would be done if there were only one person)

        // Let us retrieve the total instance/ephemeral key.
        let mut total_instance_key = Scalar::ZERO;
        for (_, kept) in unique_kept_1to2 {
            total_instance_key += kept.instance_key;
        }

        // Compare the total "instance point" with the parties' calculations.
        let total_instance_point = (AffinePoint::GENERATOR * total_instance_key).to_affine();
        let expected_x_coord = hex::encode(total_instance_point.x());
        assert_eq!(x_coord, expected_x_coord);

        // The hash of the message:
        let hashed_message = Scalar::reduce(&U256::from_be_slice(&message_to_sign));
        assert_eq!(
            hashed_message,
            Scalar::reduce(&U256::from_be_hex(
                "c73f9dea26b12228c23b66686b090b61bd6a61a80c665e058320eb7c2433c9ac"
            ))
        );

        // Now we can find the signature in the usual way.
        let expected_signature_as_scalar = total_instance_key.invert().unwrap()
            * (hashed_message
                + (secret_key * Scalar::reduce(&U256::from_be_hex(&expected_x_coord))));
        let expected_signature = hex::encode(expected_signature_as_scalar.to_bytes());

        // Calculate the expected recovery id
        let x_as_int = U256::from_be_hex(&expected_x_coord);
        let is_x_reduced = x_as_int >= Secp256k1::ORDER;
        let is_y_odd = total_instance_point.to_sec1_point(false).y().unwrap()
            [crate::utilities::ID_LEN - 1]
            & 1
            == 1;
        let expected_rec_id = (is_y_odd as u8) | ((is_x_reduced as u8) << 1);

        // We compare the results.
        assert_eq!(signature.0, expected_signature);
        assert_eq!(signature.1, expected_rec_id);
    }

    /// Tests DKG and signing together. The main purpose is to
    /// verify whether the initialization protocols from DKG are working.
    ///
    /// It is a combination of `test_dkg_initialization` and [`test_signing`].
    #[test]
    fn test_dkg_and_signing() {
        // DKG (as in test_dkg_initialization)

        let threshold = rng::get_rng().random_range(2..=5); // You can change the ranges here.
        let offset = rng::get_rng().random_range(0..=5);

        let parameters = Parameters {
            threshold,
            share_count: threshold + offset,
        }; // You can fix the parameters if you prefer.
        let session_id = rng::get_rng().random::<[u8; crate::utilities::ID_LEN]>();

        // Each party prepares their data for this DKG.
        let mut all_data: Vec<SessionData> = Vec::with_capacity(parameters.share_count as usize);
        for i in 0..parameters.share_count {
            all_data.push(SessionData {
                parameters: parameters.clone(),
                party_index: PartyIndex::new(i + 1).unwrap(),
                session_id: session_id.to_vec(),
            });
        }

        // Phase 1
        let mut dkg_1: Vec<Vec<Scalar>> = Vec::with_capacity(parameters.share_count as usize);
        for i in 0..parameters.share_count {
            let out1 = phase1::<TestCurve>(&all_data[i as usize]);

            dkg_1.push(out1);
        }

        // Communication round 1 - Each party receives a fragment from each counterparty.
        // They also produce a fragment for themselves.
        let mut poly_fragments = vec![
            Vec::<Scalar>::with_capacity(parameters.share_count as usize);
            parameters.share_count as usize
        ];
        for row_i in dkg_1 {
            for j in 0..parameters.share_count {
                poly_fragments[j as usize].push(row_i[j as usize]);
            }
        }

        // Phase 2
        let mut poly_points: Vec<Scalar> = Vec::with_capacity(parameters.share_count as usize);
        let mut proofs_commitments: Vec<ProofCommitment<TestCurve>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut zero_kept_2to3: Vec<BTreeMap<PartyIndex, KeepInitZeroSharePhase2to3>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut zero_transmit_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut bip_kept_2to3: Vec<UniqueKeepDerivationPhase2to3> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut bip_broadcast_2to4: BTreeMap<PartyIndex, BroadcastDerivationPhase2to4> =
            BTreeMap::new();
        for i in 0..parameters.share_count {
            let (out1, out2, out3, out4, out5, out6) =
                phase2(&all_data[i as usize], &poly_fragments[i as usize]);

            poly_points.push(out1);
            proofs_commitments.push(out2);
            zero_kept_2to3.push(out3);
            zero_transmit_2to4.push(out4);
            bip_kept_2to3.push(out5);
            bip_broadcast_2to4.insert(PartyIndex::new(i + 1).unwrap(), out6); // This variable should be grouped into a BTreeMap.
        }

        // Communication round 2
        let mut zero_received_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> =
            Vec::with_capacity(parameters.share_count as usize);
        for i in 1..=parameters.share_count {
            // We don't need to transmit the commitments because proofs_commitments is already what we need.
            // In practice, this should be done here.

            let i_idx = PartyIndex::new(i).unwrap();
            let mut new_row: Vec<TransmitInitZeroSharePhase2to4> =
                Vec::with_capacity((parameters.share_count - 1) as usize);
            for party in &zero_transmit_2to4 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i_idx {
                        new_row.push(message.clone());
                    }
                }
            }
            zero_received_2to4.push(new_row);
        }

        // bip_transmit_2to4 is already in the format we need.
        // In practice, the messages received should be grouped into a BTreeMap.

        // Phase 3
        let mut zero_kept_3to4: Vec<BTreeMap<PartyIndex, KeepInitZeroSharePhase3to4>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut zero_transmit_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut mul_kept_3to4: Vec<BTreeMap<PartyIndex, KeepInitMulPhase3to4<TestCurve>>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut mul_transmit_3to4: Vec<Vec<TransmitInitMulPhase3to4<TestCurve>>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut bip_broadcast_3to4: BTreeMap<PartyIndex, BroadcastDerivationPhase3to4> =
            BTreeMap::new();
        for i in 0..parameters.share_count {
            let (out1, out2, out3, out4, out5) = phase3(
                &all_data[i as usize],
                &zero_kept_2to3[i as usize],
                &bip_kept_2to3[i as usize],
            );

            zero_kept_3to4.push(out1);
            zero_transmit_3to4.push(out2);
            mul_kept_3to4.push(out3);
            mul_transmit_3to4.push(out4);
            bip_broadcast_3to4.insert(PartyIndex::new(i + 1).unwrap(), out5); // This variable should be grouped into a BTreeMap.
        }

        // Communication round 3
        let mut zero_received_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut mul_received_3to4: Vec<Vec<TransmitInitMulPhase3to4<TestCurve>>> =
            Vec::with_capacity(parameters.share_count as usize);
        for i in 1..=parameters.share_count {
            // We don't need to transmit the proofs because proofs_commitments is already what we need.
            // In practice, this should be done here.

            let i_idx = PartyIndex::new(i).unwrap();
            let mut new_row: Vec<TransmitInitZeroSharePhase3to4> =
                Vec::with_capacity((parameters.share_count - 1) as usize);
            for party in &zero_transmit_3to4 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i_idx {
                        new_row.push(message.clone());
                    }
                }
            }
            zero_received_3to4.push(new_row);

            let mut new_row: Vec<TransmitInitMulPhase3to4<TestCurve>> =
                Vec::with_capacity((parameters.share_count - 1) as usize);
            for party in &mul_transmit_3to4 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i_idx {
                        new_row.push(message.clone());
                    }
                }
            }
            mul_received_3to4.push(new_row);
        }

        // bip_transmit_3to4 is already in the format we need.
        // In practice, the messages received should be grouped into a BTreeMap.

        // Phase 4
        let mut parties: Vec<Party<TestCurve>> =
            Vec::with_capacity(parameters.share_count as usize);
        for i in 0..parameters.share_count {
            let result = phase4(
                &all_data[i as usize],
                &poly_points[i as usize],
                &proofs_commitments,
                &zero_kept_3to4[i as usize],
                &zero_received_2to4[i as usize],
                &zero_received_3to4[i as usize],
                &mul_kept_3to4[i as usize],
                &mul_received_3to4[i as usize],
                &bip_broadcast_2to4,
                &bip_broadcast_3to4,
                no_address,
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description());
                }
                Ok((party, _)) => {
                    parties.push(party);
                }
            }
        }

        // We check if the public keys and chain codes are the same.
        let expected_pk = parties[0].pk;
        let expected_chain_code = parties[0].derivation_data.chain_code;
        for party in &parties {
            assert_eq!(expected_pk, party.pk);
            assert_eq!(expected_chain_code, party.derivation_data.chain_code);
        }

        // SIGNING (as in test_signing)

        let sign_id = rng::get_rng().random::<[u8; crate::utilities::ID_LEN]>();
        let message_to_sign = tagged_hash(b"test-sign", &[b"Message to sign!"]);

        // For simplicity, we are testing only the first parties.
        let executing_parties: Vec<PartyIndex> = (1..=parameters.threshold)
            .map(|i| PartyIndex::new(i).unwrap())
            .collect();

        // Each party prepares their data for this signing session.
        let mut all_data: BTreeMap<PartyIndex, SignData> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            //Gather the counterparties
            let mut counterparties = executing_parties.clone();
            counterparties.retain(|index| *index != party_index);

            all_data.insert(
                party_index,
                SignData {
                    sign_id: sign_id.to_vec(),
                    counterparties,
                    message_hash: message_to_sign,
                },
            );
        }

        // Phase 1
        let mut unique_kept_1to2: BTreeMap<PartyIndex, UniqueKeep1to2<TestCurve>> = BTreeMap::new();
        let mut kept_1to2: BTreeMap<PartyIndex, BTreeMap<PartyIndex, KeepPhase1to2<TestCurve>>> =
            BTreeMap::new();
        let mut transmit_1to2: BTreeMap<PartyIndex, Vec<TransmitPhase1to2>> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            let (unique_keep, keep, transmit) = parties[(party_index.as_u8() - 1) as usize]
                .sign_phase1(all_data.get(&party_index).unwrap())
                .unwrap();

            unique_kept_1to2.insert(party_index, unique_keep);
            kept_1to2.insert(party_index, keep);
            transmit_1to2.insert(party_index, transmit);
        }

        // Communication round 1
        let mut received_1to2: BTreeMap<PartyIndex, Vec<TransmitPhase1to2>> = BTreeMap::new();

        for &party_index in &executing_parties {
            let messages_for_party: Vec<TransmitPhase1to2> = transmit_1to2
                .values()
                .flatten()
                .filter(|message| message.parties.receiver == party_index)
                .cloned()
                .collect();

            received_1to2.insert(party_index, messages_for_party);
        }

        // Phase 2
        let mut unique_kept_2to3: BTreeMap<PartyIndex, UniqueKeep2to3<TestCurve>> = BTreeMap::new();
        let mut kept_2to3: BTreeMap<PartyIndex, BTreeMap<PartyIndex, KeepPhase2to3<TestCurve>>> =
            BTreeMap::new();
        let mut transmit_2to3: BTreeMap<PartyIndex, Vec<TransmitPhase2to3<TestCurve>>> =
            BTreeMap::new();
        for party_index in executing_parties.clone() {
            let result = parties[(party_index.as_u8() - 1) as usize].sign_phase2(
                all_data.get(&party_index).unwrap(),
                unique_kept_1to2.get(&party_index).unwrap(),
                kept_1to2.get(&party_index).unwrap(),
                received_1to2.get(&party_index).unwrap(),
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description());
                }
                Ok((unique_keep, keep, transmit)) => {
                    unique_kept_2to3.insert(party_index, unique_keep);
                    kept_2to3.insert(party_index, keep);
                    transmit_2to3.insert(party_index, transmit);
                }
            }
        }

        // Communication round 2
        let mut received_2to3: BTreeMap<PartyIndex, Vec<TransmitPhase2to3<TestCurve>>> =
            BTreeMap::new();

        for &party_index in &executing_parties {
            let messages_for_party: Vec<TransmitPhase2to3<TestCurve>> = transmit_2to3
                .values()
                .flatten()
                .filter(|message| message.parties.receiver == party_index)
                .cloned()
                .collect();

            received_2to3.insert(party_index, messages_for_party);
        }

        // Phase 3
        let mut x_coords: Vec<String> = Vec::with_capacity(parameters.threshold as usize);
        let mut broadcast_3to4: Vec<Broadcast3to4<TestCurve>> =
            Vec::with_capacity(parameters.threshold as usize);
        for party_index in executing_parties.clone() {
            let result = parties[(party_index.as_u8() - 1) as usize].sign_phase3(
                all_data.get(&party_index).unwrap(),
                unique_kept_2to3.get(&party_index).unwrap(),
                kept_2to3.get(&party_index).unwrap(),
                received_2to3.get(&party_index).unwrap(),
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description());
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
            assert_eq!(x_coord, x_coords[i as usize]);
        }

        // Communication round 3
        // This is a broadcast to all parties. The desired result is already broadcast_3to4.

        // Phase 4
        // It is essentially independent of the party, so we compute just once.
        let some_index = executing_parties[0];
        let result = parties[(some_index.as_u8() - 1) as usize].sign_phase4(
            all_data.get(&some_index).unwrap(),
            &x_coord,
            &broadcast_3to4,
            true,
        );
        if let Err(abort) = result {
            panic!("Party {} aborted: {:?}", abort.index, abort.description());
        }
        // We could call verify_ecdsa_signature here, but it is already called during Phase 4.
    }

    /// Tests if sign_phase4 handles zero denominator without panicking.
    #[test]
    fn test_sign_phase4_zero_denominator_returns_abort() {
        let parameters = Parameters {
            threshold: 2,
            share_count: 2,
        };
        let session_id = rng::get_rng().random::<[u8; crate::utilities::ID_LEN]>();
        let secret_key = Scalar::random(&mut rng::get_rng());
        let (parties, _) =
            re_key::<TestCurve>(&parameters, &session_id, &secret_key, None, no_address);

        let data = SignData {
            sign_id: rng::get_rng()
                .random::<[u8; crate::utilities::ID_LEN]>()
                .to_vec(),
            counterparties: vec![PartyIndex::new(2).unwrap()],
            message_hash: tagged_hash(b"test-sign", &[b"Message to sign!"]),
        };

        let received = vec![Broadcast3to4 {
            u: Scalar::ZERO,
            w: Scalar::ONE,
        }];
        let result = parties[0].sign_phase4(&data, "01", &received, true);
        let abort = result.expect_err("zero denominator should return abort");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(matches!(abort.reason, AbortReason::ZeroDenominator));
    }

    /// Tests that malformed hex inputs are rejected without panicking.
    #[test]
    fn test_verify_ecdsa_signature_rejects_malformed_hex() {
        use k256::AffinePoint;
        let message = tagged_hash(b"test-sign", &[b"Message to sign!"]);
        let pk = AffinePoint::GENERATOR;

        assert!(!verify_ecdsa_signature::<TestCurve>(
            &message, &pk, "zz", "11"
        ));
        assert!(!verify_ecdsa_signature::<TestCurve>(&message, &pk, "", ""));
        assert!(!verify_ecdsa_signature::<TestCurve>(
            &message,
            &pk,
            "010203",
            "not-a-hex-string"
        ));
    }

    /// Tests if phase 1 rejects duplicate counterparties.
    #[test]
    fn test_sign_phase1_rejects_duplicate_counterparty() {
        let parameters = Parameters {
            threshold: 3,
            share_count: 3,
        };
        let session_id = rng::get_rng().random::<[u8; crate::utilities::ID_LEN]>();
        let secret_key = Scalar::random(&mut rng::get_rng());
        let (parties, _) =
            re_key::<TestCurve>(&parameters, &session_id, &secret_key, None, no_address);

        let data = SignData {
            sign_id: rng::get_rng()
                .random::<[u8; crate::utilities::ID_LEN]>()
                .to_vec(),
            counterparties: vec![PartyIndex::new(2).unwrap(), PartyIndex::new(2).unwrap()],
            message_hash: tagged_hash(b"test-sign", &[b"Message to sign!"]),
        };

        let abort = parties[0]
            .sign_phase1(&data)
            .expect_err("duplicate counterparty should be rejected");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(matches!(
            abort.reason,
            AbortReason::DuplicateCounterparty { .. }
        ));
    }

    /// Tests if phase 1 rejects missing multiplication state.
    #[test]
    fn test_sign_phase1_rejects_missing_mul_state() {
        let (parties, all_data, _, _, _) = setup_two_party_signing_phase1();
        let mut party = parties[0].clone();
        party.mul_senders.remove(&PartyIndex::new(2).unwrap());

        let abort = party
            .sign_phase1(
                all_data
                    .get(&PartyIndex::new(1).unwrap())
                    .expect("party data should exist"),
            )
            .expect_err("missing multiplication state should be rejected");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(matches!(abort.reason, AbortReason::MissingMulState { .. }));
    }

    #[allow(clippy::type_complexity)]
    fn setup_two_party_signing_phase1() -> (
        Vec<Party<TestCurve>>,
        BTreeMap<PartyIndex, SignData>,
        BTreeMap<PartyIndex, UniqueKeep1to2<TestCurve>>,
        BTreeMap<PartyIndex, BTreeMap<PartyIndex, KeepPhase1to2<TestCurve>>>,
        BTreeMap<PartyIndex, Vec<TransmitPhase1to2>>,
    ) {
        let parameters = Parameters {
            threshold: 2,
            share_count: 2,
        };
        let session_id = rng::get_rng().random::<[u8; crate::utilities::ID_LEN]>();
        let secret_key = Scalar::random(&mut rng::get_rng());
        let (parties, _) =
            re_key::<TestCurve>(&parameters, &session_id, &secret_key, None, no_address);

        let sign_id = rng::get_rng().random::<[u8; crate::utilities::ID_LEN]>();
        let message_to_sign = tagged_hash(b"test-sign", &[b"Message to sign!"]);

        let mut all_data: BTreeMap<PartyIndex, SignData> = BTreeMap::new();
        all_data.insert(
            PartyIndex::new(1).unwrap(),
            SignData {
                sign_id: sign_id.to_vec(),
                counterparties: vec![PartyIndex::new(2).unwrap()],
                message_hash: message_to_sign,
            },
        );
        all_data.insert(
            PartyIndex::new(2).unwrap(),
            SignData {
                sign_id: sign_id.to_vec(),
                counterparties: vec![PartyIndex::new(1).unwrap()],
                message_hash: message_to_sign,
            },
        );

        let mut unique_kept_1to2: BTreeMap<PartyIndex, UniqueKeep1to2<TestCurve>> = BTreeMap::new();
        let mut kept_1to2: BTreeMap<PartyIndex, BTreeMap<PartyIndex, KeepPhase1to2<TestCurve>>> =
            BTreeMap::new();
        let mut transmit_1to2: BTreeMap<PartyIndex, Vec<TransmitPhase1to2>> = BTreeMap::new();
        for party_index in [PartyIndex::new(1).unwrap(), PartyIndex::new(2).unwrap()] {
            let (unique_keep, keep, transmit) = match parties[(party_index.as_u8() - 1) as usize]
                .sign_phase1(all_data.get(&party_index).unwrap())
            {
                Ok(result) => result,
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description());
                }
            };

            unique_kept_1to2.insert(party_index, unique_keep);
            kept_1to2.insert(party_index, keep);
            transmit_1to2.insert(party_index, transmit);
        }

        let mut received_1to2: BTreeMap<PartyIndex, Vec<TransmitPhase1to2>> = BTreeMap::new();
        for party_index in [PartyIndex::new(1).unwrap(), PartyIndex::new(2).unwrap()] {
            let messages_for_party: Vec<TransmitPhase1to2> = transmit_1to2
                .values()
                .flatten()
                .filter(|message| message.parties.receiver == party_index)
                .cloned()
                .collect();
            received_1to2.insert(party_index, messages_for_party);
        }

        (
            parties,
            all_data,
            unique_kept_1to2,
            kept_1to2,
            received_1to2,
        )
    }

    #[allow(clippy::type_complexity)]
    fn run_two_party_phase2(
        parties: &[Party<TestCurve>],
        all_data: &BTreeMap<PartyIndex, SignData>,
        unique_kept_1to2: &BTreeMap<PartyIndex, UniqueKeep1to2<TestCurve>>,
        kept_1to2: &BTreeMap<PartyIndex, BTreeMap<PartyIndex, KeepPhase1to2<TestCurve>>>,
        received_1to2: &BTreeMap<PartyIndex, Vec<TransmitPhase1to2>>,
    ) -> (
        BTreeMap<PartyIndex, UniqueKeep2to3<TestCurve>>,
        BTreeMap<PartyIndex, BTreeMap<PartyIndex, KeepPhase2to3<TestCurve>>>,
        BTreeMap<PartyIndex, Vec<TransmitPhase2to3<TestCurve>>>,
    ) {
        let mut unique_kept_2to3: BTreeMap<PartyIndex, UniqueKeep2to3<TestCurve>> = BTreeMap::new();
        let mut kept_2to3: BTreeMap<PartyIndex, BTreeMap<PartyIndex, KeepPhase2to3<TestCurve>>> =
            BTreeMap::new();
        let mut transmit_2to3: BTreeMap<PartyIndex, Vec<TransmitPhase2to3<TestCurve>>> =
            BTreeMap::new();
        for party_index in [PartyIndex::new(1).unwrap(), PartyIndex::new(2).unwrap()] {
            let result = parties[(party_index.as_u8() - 1) as usize].sign_phase2(
                all_data.get(&party_index).unwrap(),
                unique_kept_1to2.get(&party_index).unwrap(),
                kept_1to2.get(&party_index).unwrap(),
                received_1to2.get(&party_index).unwrap(),
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description());
                }
                Ok((unique_keep, keep, transmit)) => {
                    unique_kept_2to3.insert(party_index, unique_keep);
                    kept_2to3.insert(party_index, keep);
                    transmit_2to3.insert(party_index, transmit);
                }
            }
        }

        let mut received_2to3: BTreeMap<PartyIndex, Vec<TransmitPhase2to3<TestCurve>>> =
            BTreeMap::new();
        for party_index in [PartyIndex::new(1).unwrap(), PartyIndex::new(2).unwrap()] {
            let messages_for_party: Vec<TransmitPhase2to3<TestCurve>> = transmit_2to3
                .values()
                .flatten()
                .filter(|message| message.parties.receiver == party_index)
                .cloned()
                .collect();
            received_2to3.insert(party_index, messages_for_party);
        }

        (unique_kept_2to3, kept_2to3, received_2to3)
    }

    fn run_two_party_phase3(
        parties: &[Party<TestCurve>],
        all_data: &BTreeMap<PartyIndex, SignData>,
        unique_kept_2to3: &BTreeMap<PartyIndex, UniqueKeep2to3<TestCurve>>,
        kept_2to3: &BTreeMap<PartyIndex, BTreeMap<PartyIndex, KeepPhase2to3<TestCurve>>>,
        received_2to3: &BTreeMap<PartyIndex, Vec<TransmitPhase2to3<TestCurve>>>,
    ) -> (String, Vec<Broadcast3to4<TestCurve>>) {
        let mut x_coords: Vec<String> = Vec::with_capacity(2);
        let mut broadcasts: Vec<Broadcast3to4<TestCurve>> = Vec::with_capacity(2);
        for party_index in [PartyIndex::new(1).unwrap(), PartyIndex::new(2).unwrap()] {
            let result = parties[(party_index.as_u8() - 1) as usize].sign_phase3(
                all_data.get(&party_index).unwrap(),
                unique_kept_2to3.get(&party_index).unwrap(),
                kept_2to3.get(&party_index).unwrap(),
                received_2to3.get(&party_index).unwrap(),
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description());
                }
                Ok((x_coord, broadcast)) => {
                    x_coords.push(x_coord);
                    broadcasts.push(broadcast);
                }
            }
        }

        assert_eq!(x_coords[0], x_coords[1]);
        (x_coords[0].clone(), broadcasts)
    }

    /// Tests if phase 2 rejects messages from unknown senders.
    #[test]
    fn test_sign_phase2_rejects_unknown_sender() {
        let (parties, all_data, unique_kept_1to2, kept_1to2, received_1to2) =
            setup_two_party_signing_phase1();

        let mut tampered = received_1to2
            .get(&PartyIndex::new(1).unwrap())
            .unwrap()
            .clone();
        tampered[0].parties.sender = PartyIndex::new(3).unwrap();

        let result = parties[0].sign_phase2(
            all_data.get(&PartyIndex::new(1).unwrap()).unwrap(),
            unique_kept_1to2.get(&PartyIndex::new(1).unwrap()).unwrap(),
            kept_1to2.get(&PartyIndex::new(1).unwrap()).unwrap(),
            &tampered,
        );
        let abort = result.expect_err("unknown sender should be rejected");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(matches!(abort.reason, AbortReason::UnexpectedSender { .. }));
    }

    /// Tests if phase 2 rejects messages addressed to a different receiver.
    #[test]
    fn test_sign_phase2_rejects_wrong_receiver() {
        let (parties, all_data, unique_kept_1to2, kept_1to2, received_1to2) =
            setup_two_party_signing_phase1();

        let mut tampered = received_1to2
            .get(&PartyIndex::new(1).unwrap())
            .unwrap()
            .clone();
        tampered[0].parties.receiver = PartyIndex::new(2).unwrap();

        let result = parties[0].sign_phase2(
            all_data.get(&PartyIndex::new(1).unwrap()).unwrap(),
            unique_kept_1to2.get(&PartyIndex::new(1).unwrap()).unwrap(),
            kept_1to2.get(&PartyIndex::new(1).unwrap()).unwrap(),
            &tampered,
        );
        let abort = result.expect_err("wrong receiver should be rejected");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(matches!(abort.reason, AbortReason::MisroutedMessage { .. }));
    }

    /// Tests if phase 2 rejects message vectors with unexpected size.
    #[test]
    fn test_sign_phase2_rejects_wrong_message_count() {
        let (parties, all_data, unique_kept_1to2, kept_1to2, _) = setup_two_party_signing_phase1();

        let result = parties[0].sign_phase2(
            all_data.get(&PartyIndex::new(1).unwrap()).unwrap(),
            unique_kept_1to2.get(&PartyIndex::new(1).unwrap()).unwrap(),
            kept_1to2.get(&PartyIndex::new(1).unwrap()).unwrap(),
            &[],
        );
        let abort = result.expect_err("wrong message count should be rejected");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(matches!(
            abort.reason,
            AbortReason::WrongMessageCount { .. }
        ));
    }

    /// Tests if phase 3 rejects invalid decommitment data.
    #[test]
    fn test_sign_phase3_rejects_invalid_commitment_decommit() {
        let (parties, all_data, unique_kept_1to2, kept_1to2, received_1to2) =
            setup_two_party_signing_phase1();
        let (unique_kept_2to3, kept_2to3, received_2to3) = run_two_party_phase2(
            &parties,
            &all_data,
            &unique_kept_1to2,
            &kept_1to2,
            &received_1to2,
        );

        let mut tampered = received_2to3
            .get(&PartyIndex::new(1).unwrap())
            .unwrap()
            .clone();
        assert!(
            !tampered[0].salt.is_empty(),
            "phase-3 decommit salt should be non-empty"
        );
        tampered[0].salt[0] ^= 1;

        let result = parties[0].sign_phase3(
            all_data.get(&PartyIndex::new(1).unwrap()).unwrap(),
            unique_kept_2to3.get(&PartyIndex::new(1).unwrap()).unwrap(),
            kept_2to3.get(&PartyIndex::new(1).unwrap()).unwrap(),
            &tampered,
        );
        let abort = result.expect_err("invalid decommit should be rejected");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(matches!(
            abort.reason,
            AbortReason::CommitmentMismatch { .. }
        ));
    }

    /// Tests if phase 3 rejects message vectors with unexpected size.
    #[test]
    fn test_sign_phase3_rejects_wrong_message_count() {
        let (parties, all_data, unique_kept_1to2, kept_1to2, received_1to2) =
            setup_two_party_signing_phase1();
        let (unique_kept_2to3, kept_2to3, _) = run_two_party_phase2(
            &parties,
            &all_data,
            &unique_kept_1to2,
            &kept_1to2,
            &received_1to2,
        );

        let result = parties[0].sign_phase3(
            all_data.get(&PartyIndex::new(1).unwrap()).unwrap(),
            unique_kept_2to3.get(&PartyIndex::new(1).unwrap()).unwrap(),
            kept_2to3.get(&PartyIndex::new(1).unwrap()).unwrap(),
            &[],
        );
        let abort = result.expect_err("wrong message count should be rejected");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(matches!(
            abort.reason,
            AbortReason::WrongMessageCount { .. }
        ));
    }

    /// Every key derived from the same shares (BIP-32 child, BOLT 3 key),
    /// sign id, message hash and signer set gives the multiplication and the
    /// zero shares their own session id, and the multiplication id depends on
    /// the roles.
    #[test]
    fn test_signing_session_ids_are_distinct_per_key() {
        let parameters = Parameters::new(2, 3).unwrap();
        let session_id = rng::get_rng().random::<[u8; crate::utilities::ID_LEN]>();
        let secret_key = Scalar::random(&mut rng::get_rng());
        let (parties, _) =
            re_key::<TestCurve>(&parameters, &session_id, &secret_key, None, no_address);
        let base = &parties[0];
        let per_commitment_point = (ProjectivePoint::GENERATOR * Scalar::from(5u64)).to_affine();
        let keys = [
            base.clone(),
            base.derive_child(0, no_address).unwrap(),
            base.bolt3_derive(&per_commitment_point, no_address)
                .unwrap(),
            base.bolt3_derive_revocation(&per_commitment_point, &Scalar::from(5u64), no_address)
                .unwrap(),
        ];

        let one = PartyIndex::new(1).unwrap();
        let two = PartyIndex::new(2).unwrap();
        let data = SignData {
            sign_id: vec![7u8; crate::utilities::ID_LEN],
            counterparties: vec![two],
            message_hash: [3u8; 32],
        };
        let mut other_sign_id = data.clone();
        other_sign_id.sign_id[0] ^= 1;
        let mut other_message = data.clone();
        other_message.message_hash[0] ^= 1;
        let mut other_signers = data.clone();
        other_signers.counterparties = vec![PartyIndex::new(3).unwrap()];

        let mut mul_ids = BTreeSet::new();
        let mut zero_ids = BTreeSet::new();
        for key in &keys {
            for sign_data in [&data, &other_sign_id, &other_message, &other_signers] {
                assert!(mul_ids.insert(key.mul_session_id(sign_data, one, two)));
                assert!(mul_ids.insert(key.mul_session_id(sign_data, two, one)));
                assert!(zero_ids.insert(key.zero_session_id(sign_data)));
            }
        }
    }

    /// Runs party 2's phase 1 under `party_two_data` and feeds its message to
    /// party 1's phase 2, which runs under the original session data.
    fn phase2_with_party_two_data(party_two_data: impl FnOnce(&mut SignData)) -> Result<(), Abort> {
        let (parties, all_data, unique_kept_1to2, kept_1to2, _) = setup_two_party_signing_phase1();
        let party_one = PartyIndex::new(1).unwrap();
        let party_two = PartyIndex::new(2).unwrap();

        let mut data = all_data.get(&party_two).unwrap().clone();
        party_two_data(&mut data);
        let (_, _, messages) = parties[1].sign_phase1(&data).unwrap();

        parties[0]
            .sign_phase2(
                all_data.get(&party_one).unwrap(),
                unique_kept_1to2.get(&party_one).unwrap(),
                kept_1to2.get(&party_one).unwrap(),
                &messages,
            )
            .map(|_| ())
    }

    /// A peer in a different signing session is a session mismatch, not
    /// cheating: it must not ban an honest counterparty.
    #[test]
    fn test_sign_phase2_sign_id_mismatch_is_recoverable() {
        let abort = phase2_with_party_two_data(|data| data.sign_id[0] ^= 1)
            .expect_err("a different sign_id must abort");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(matches!(
            abort.reason,
            AbortReason::SessionBindingMismatch { counterparty } if counterparty.as_u8() == 2
        ));
    }

    /// Parties signing different messages abort at phase 2, before any
    /// multiplication work, instead of producing an invalid signature.
    #[test]
    fn test_sign_phase2_message_hash_mismatch_is_recoverable() {
        let abort = phase2_with_party_two_data(|data| data.message_hash[0] ^= 1)
            .expect_err("a different message hash must abort");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(matches!(
            abort.reason,
            AbortReason::SessionBindingMismatch { .. }
        ));
    }

    /// A phase-2 message whose session binding does not match is rejected as
    /// recoverable before the multiplication protocol is finished: invalid
    /// multiplication data from another session must not cause a ban.
    #[test]
    fn test_sign_phase3_session_binding_mismatch_is_recoverable() {
        let (parties, all_data, unique_kept_1to2, kept_1to2, received_1to2) =
            setup_two_party_signing_phase1();
        let (unique_kept_2to3, kept_2to3, received_2to3) = run_two_party_phase2(
            &parties,
            &all_data,
            &unique_kept_1to2,
            &kept_1to2,
            &received_1to2,
        );
        let party_one = PartyIndex::new(1).unwrap();

        let mut tampered = received_2to3.get(&party_one).unwrap().clone();
        tampered[0].session_binding[0] ^= 1;
        tampered[0].mul_transmit.verify_r[0] ^= 1;

        let abort = parties[0]
            .sign_phase3(
                all_data.get(&party_one).unwrap(),
                unique_kept_2to3.get(&party_one).unwrap(),
                kept_2to3.get(&party_one).unwrap(),
                &tampered,
            )
            .expect_err("a mismatched session binding must abort");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(matches!(
            abort.reason,
            AbortReason::SessionBindingMismatch { .. }
        ));
    }

    /// A retry with the same sign id: party 1 answers party 2's phase-1
    /// message from an earlier attempt. Party 2 must see a recoverable session
    /// mismatch, not a failed multiplication check that bans party 1.
    #[test]
    fn test_stale_phase1_message_from_earlier_attempt_is_recoverable() {
        // Attempt B: both parties run phase 1.
        let (parties, all_data, unique_kept_1to2, kept_1to2, received_1to2) =
            setup_two_party_signing_phase1();
        let party_one = PartyIndex::new(1).unwrap();
        let party_two = PartyIndex::new(2).unwrap();

        // Attempt A of party 2, same sign id, delivered to party 1 instead.
        let (_, _, stale) = parties[1]
            .sign_phase1(all_data.get(&party_two).unwrap())
            .unwrap();
        let (_, _, from_party_one) = parties[0]
            .sign_phase2(
                all_data.get(&party_one).unwrap(),
                unique_kept_1to2.get(&party_one).unwrap(),
                kept_1to2.get(&party_one).unwrap(),
                &stale,
            )
            .unwrap();

        // Party 2 continues attempt B.
        let (unique_kept_2to3, kept_2to3, from_party_two) = parties[1]
            .sign_phase2(
                all_data.get(&party_two).unwrap(),
                unique_kept_1to2.get(&party_two).unwrap(),
                kept_1to2.get(&party_two).unwrap(),
                received_1to2.get(&party_two).unwrap(),
            )
            .unwrap();
        let abort = parties[1]
            .sign_phase3(
                all_data.get(&party_two).unwrap(),
                &unique_kept_2to3,
                &kept_2to3,
                &from_party_one,
            )
            .expect_err("a message built on a stale attempt must abort");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(matches!(
            abort.reason,
            AbortReason::SessionBindingMismatch { counterparty } if counterparty == party_one
        ));

        // Party 1 holds the stale attempt's commitment from party 2, but party
        // 2 answers attempt B: a session mismatch as well, not a decommitment
        // failure.
        let (unique_kept_1_2to3, kept_1_2to3, _) = parties[0]
            .sign_phase2(
                all_data.get(&party_one).unwrap(),
                unique_kept_1to2.get(&party_one).unwrap(),
                kept_1to2.get(&party_one).unwrap(),
                &stale,
            )
            .unwrap();
        let abort = parties[0]
            .sign_phase3(
                all_data.get(&party_one).unwrap(),
                &unique_kept_1_2to3,
                &kept_1_2to3,
                &from_party_two,
            )
            .expect_err("a message from another attempt must abort");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(matches!(
            abort.reason,
            AbortReason::SessionBindingMismatch { counterparty } if counterparty == party_two
        ));
    }

    /// Signing twice with identical sign data succeeds both times, with
    /// independent nonces.
    #[test]
    fn test_repeated_sign_data_signs_twice() {
        let mut signatures = Vec::new();
        let (parties, all_data, unique_kept_1to2, kept_1to2, received_1to2) =
            setup_two_party_signing_phase1();
        for attempt in 0..2 {
            let (unique_kept_1to2, kept_1to2, received_1to2) = if attempt == 0 {
                (
                    unique_kept_1to2.clone(),
                    kept_1to2.clone(),
                    received_1to2.clone(),
                )
            } else {
                rerun_two_party_phase1(&parties, &all_data)
            };
            let (unique_kept_2to3, kept_2to3, received_2to3) = run_two_party_phase2(
                &parties,
                &all_data,
                &unique_kept_1to2,
                &kept_1to2,
                &received_1to2,
            );
            let (x_coord, broadcasts) = run_two_party_phase3(
                &parties,
                &all_data,
                &unique_kept_2to3,
                &kept_2to3,
                &received_2to3,
            );
            let party_one = PartyIndex::new(1).unwrap();
            let data = all_data.get(&party_one).unwrap();
            let (signature, _) = parties[0]
                .sign_phase4(data, &x_coord, &broadcasts, true)
                .unwrap();
            assert!(verify_ecdsa_signature::<TestCurve>(
                &data.message_hash,
                &parties[0].pk,
                &x_coord,
                &signature
            ));
            signatures.push((x_coord, signature));
        }
        assert_ne!(signatures[0], signatures[1]);
    }

    /// Runs phase 1 again for both parties with the same sign data.
    #[allow(clippy::type_complexity)]
    fn rerun_two_party_phase1(
        parties: &[Party<TestCurve>],
        all_data: &BTreeMap<PartyIndex, SignData>,
    ) -> (
        BTreeMap<PartyIndex, UniqueKeep1to2<TestCurve>>,
        BTreeMap<PartyIndex, BTreeMap<PartyIndex, KeepPhase1to2<TestCurve>>>,
        BTreeMap<PartyIndex, Vec<TransmitPhase1to2>>,
    ) {
        let mut unique_kept = BTreeMap::new();
        let mut kept = BTreeMap::new();
        let mut sent: Vec<TransmitPhase1to2> = Vec::new();
        for (i, party) in parties.iter().enumerate() {
            let index = PartyIndex::new(i as u8 + 1).unwrap();
            let (unique_keep, keep, transmit) =
                party.sign_phase1(all_data.get(&index).unwrap()).unwrap();
            unique_kept.insert(index, unique_keep);
            kept.insert(index, keep);
            sent.extend(transmit);
        }
        let mut received: BTreeMap<PartyIndex, Vec<TransmitPhase1to2>> = BTreeMap::new();
        for message in sent {
            received
                .entry(message.parties.receiver)
                .or_default()
                .push(message);
        }
        (unique_kept, kept, received)
    }

    /// No signature verifies under the identity "public key": with
    /// m = 1, s = 1 and r = x(G), the verifier would otherwise compute G.
    #[test]
    fn test_verify_rejects_identity_public_key() {
        let mut message = [0u8; 32];
        message[31] = 1;
        let r = hex::encode(AffinePoint::GENERATOR.x());
        let mut s = [0u8; 32];
        s[31] = 1;
        assert!(!verify_ecdsa_signature::<TestCurve>(
            &message,
            &AffinePoint::IDENTITY,
            &r,
            &hex::encode(s)
        ));
    }

    #[test]
    #[should_panic(expected = "the secret key must not be zero")]
    fn test_re_key_rejects_zero_secret() {
        let parameters = Parameters::new(2, 3).unwrap();
        let _ = re_key::<TestCurve>(&parameters, &[1u8; 32], &Scalar::ZERO, None, no_address);
    }

    /// Phase 1 commits to psi: a phase-2 message carrying a different psi
    /// than the one committed is rejected in phase 3.
    #[test]
    fn test_sign_phase3_rejects_psi_differing_from_commitment() {
        let (parties, all_data, unique_kept_1to2, kept_1to2, received_1to2) =
            setup_two_party_signing_phase1();
        let (unique_kept_2to3, kept_2to3, received_2to3) = run_two_party_phase2(
            &parties,
            &all_data,
            &unique_kept_1to2,
            &kept_1to2,
            &received_1to2,
        );
        let party_one = PartyIndex::new(1).unwrap();

        let mut tampered = received_2to3.get(&party_one).unwrap().clone();
        tampered[0].psi += Scalar::ONE;

        let abort = parties[0]
            .sign_phase3(
                all_data.get(&party_one).unwrap(),
                unique_kept_2to3.get(&party_one).unwrap(),
                kept_2to3.get(&party_one).unwrap(),
                &tampered,
            )
            .expect_err("a psi differing from the commitment must abort");
        assert!(matches!(
            abort.reason,
            AbortReason::CommitmentMismatch { .. }
        ));
    }

    /// A malformed (e.g. corrupted on disk) local multiplication state is a
    /// recoverable local error, not a panic or a ban of the counterparty.
    #[test]
    fn test_malformed_local_mul_state_is_recoverable() {
        // The receiver's state in phase 1.
        let (mut parties, all_data, _, _, _) = setup_two_party_signing_phase1();
        let party_one = PartyIndex::new(1).unwrap();
        let party_two = PartyIndex::new(2).unwrap();
        parties[0]
            .mul_receivers
            .get_mut(&party_two)
            .unwrap()
            .ote_receiver
            .seeds0
            .pop();
        let abort = parties[0]
            .sign_phase1(all_data.get(&party_one).unwrap())
            .expect_err("a malformed local state must abort");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(matches!(
            abort.reason,
            AbortReason::InvalidLocalState { .. }
        ));

        let (mut parties, all_data, unique_kept_1to2, kept_1to2, received_1to2) =
            setup_two_party_signing_phase1();
        let party_one = PartyIndex::new(1).unwrap();
        let party_two = PartyIndex::new(2).unwrap();
        parties[0]
            .mul_senders
            .get_mut(&party_two)
            .unwrap()
            .public_gadget
            .pop();

        let abort = parties[0]
            .sign_phase2(
                all_data.get(&party_one).unwrap(),
                unique_kept_1to2.get(&party_one).unwrap(),
                kept_1to2.get(&party_one).unwrap(),
                received_1to2.get(&party_one).unwrap(),
            )
            .expect_err("a malformed local state must abort");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(matches!(
            abort.reason,
            AbortReason::InvalidLocalState { .. }
        ));

        // The same for the receiver's kept data in phase 3.
        let (parties, all_data, unique_kept_1to2, kept_1to2, received_1to2) =
            setup_two_party_signing_phase1();
        let (unique_kept_2to3, mut kept_2to3, received_2to3) = run_two_party_phase2(
            &parties,
            &all_data,
            &unique_kept_1to2,
            &kept_1to2,
            &received_1to2,
        );
        kept_2to3
            .get_mut(&party_one)
            .unwrap()
            .get_mut(&party_two)
            .unwrap()
            .mul_keep
            .choice_bits
            .pop();
        let abort = parties[0]
            .sign_phase3(
                all_data.get(&party_one).unwrap(),
                unique_kept_2to3.get(&party_one).unwrap(),
                kept_2to3.get(&party_one).unwrap(),
                received_2to3.get(&party_one).unwrap(),
            )
            .expect_err("malformed kept data must abort");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(matches!(
            abort.reason,
            AbortReason::InvalidLocalState { .. }
        ));
    }

    /// Tampered OT data under a correct session binding is still cheating.
    #[test]
    fn test_sign_phase2_bans_on_tampered_ot_data() {
        let (parties, all_data, unique_kept_1to2, kept_1to2, received_1to2) =
            setup_two_party_signing_phase1();
        let party_one = PartyIndex::new(1).unwrap();

        let mut tampered = received_1to2.get(&party_one).unwrap().clone();
        tampered[0].mul_transmit.u[0][0] ^= 1;

        let abort = parties[0]
            .sign_phase2(
                all_data.get(&party_one).unwrap(),
                unique_kept_1to2.get(&party_one).unwrap(),
                kept_1to2.get(&party_one).unwrap(),
                &tampered,
            )
            .expect_err("tampered OT data must abort");
        assert_eq!(
            abort.kind,
            AbortKind::BanCounterparty(PartyIndex::new(2).unwrap())
        );
    }

    /// Encodes a message as a frame and decodes it back, checking that the
    /// re-encoding is identical.
    #[cfg(feature = "serde")]
    fn frame_round_trip<T: crate::protocols::messages::MessageTag>(message: &T) -> T {
        use crate::protocols::messages::{PhaseInput, PhaseOutput};

        let mut output = PhaseOutput::new();
        output.add_p2p(1, message).unwrap();
        let input = PhaseInput {
            broadcasts: BTreeMap::new(),
            p2p: BTreeMap::from([(2, output.p2p[&1].clone())]),
        };
        let decoded: T = input.get_p2p(2).unwrap();

        let mut again = PhaseOutput::new();
        again.add_p2p(1, &decoded).unwrap();
        assert_eq!(again.p2p[&1], output.p2p[&1]);
        decoded
    }

    /// Signing completes with every message passed through the postcard
    /// frame encoding.
    #[cfg(feature = "serde")]
    #[test]
    fn test_signing_messages_survive_frame_encoding() {
        let (parties, all_data, unique_kept_1to2, kept_1to2, received_1to2) =
            setup_two_party_signing_phase1();
        let received_1to2: BTreeMap<_, Vec<_>> = received_1to2
            .into_iter()
            .map(|(index, messages)| (index, messages.iter().map(frame_round_trip).collect()))
            .collect();
        let (unique_kept_2to3, kept_2to3, received_2to3) = run_two_party_phase2(
            &parties,
            &all_data,
            &unique_kept_1to2,
            &kept_1to2,
            &received_1to2,
        );
        let received_2to3: BTreeMap<_, Vec<_>> = received_2to3
            .into_iter()
            .map(|(index, messages)| (index, messages.iter().map(frame_round_trip).collect()))
            .collect();
        let (x_coord, broadcasts) = run_two_party_phase3(
            &parties,
            &all_data,
            &unique_kept_2to3,
            &kept_2to3,
            &received_2to3,
        );
        let broadcasts: Vec<_> = broadcasts.iter().map(frame_round_trip).collect();

        let party_one = PartyIndex::new(1).unwrap();
        let data = all_data.get(&party_one).unwrap();
        let (signature, _) = parties[0]
            .sign_phase4(data, &x_coord, &broadcasts, true)
            .unwrap();
        assert!(verify_ecdsa_signature::<TestCurve>(
            &data.message_hash,
            &parties[0].pk,
            &x_coord,
            &signature
        ));
    }

    /// Tests if phase 3 emits a ban abort on gamma_u inconsistency.
    #[test]
    fn test_sign_phase3_bans_on_inconsistent_gamma_u() {
        let (parties, all_data, unique_kept_1to2, kept_1to2, received_1to2) =
            setup_two_party_signing_phase1();
        let (unique_kept_2to3, kept_2to3, received_2to3) = run_two_party_phase2(
            &parties,
            &all_data,
            &unique_kept_1to2,
            &kept_1to2,
            &received_1to2,
        );

        let mut tampered = received_2to3
            .get(&PartyIndex::new(1).unwrap())
            .unwrap()
            .clone();
        tampered[0].gamma_u =
            (ProjectivePoint::from(tampered[0].gamma_u) + ProjectivePoint::GENERATOR).to_affine();

        let result = parties[0].sign_phase3(
            all_data.get(&PartyIndex::new(1).unwrap()).unwrap(),
            unique_kept_2to3.get(&PartyIndex::new(1).unwrap()).unwrap(),
            kept_2to3.get(&PartyIndex::new(1).unwrap()).unwrap(),
            &tampered,
        );
        let abort = result.expect_err("inconsistent gamma_u should be rejected");
        assert_eq!(
            abort.kind,
            AbortKind::BanCounterparty(PartyIndex::new(2).unwrap())
        );
        assert!(matches!(
            abort.reason,
            AbortReason::GammaUInconsistency { .. }
        ));
    }

    /// Tests if phase 4 rejects tampered broadcast values that invalidate signature assembly.
    #[test]
    fn test_sign_phase4_rejects_tampered_broadcast() {
        let (parties, all_data, unique_kept_1to2, kept_1to2, received_1to2) =
            setup_two_party_signing_phase1();
        let (unique_kept_2to3, kept_2to3, received_2to3) = run_two_party_phase2(
            &parties,
            &all_data,
            &unique_kept_1to2,
            &kept_1to2,
            &received_1to2,
        );
        let (x_coord, mut broadcasts) = run_two_party_phase3(
            &parties,
            &all_data,
            &unique_kept_2to3,
            &kept_2to3,
            &received_2to3,
        );

        broadcasts[0].w += Scalar::ONE;

        let result = parties[0].sign_phase4(
            all_data.get(&PartyIndex::new(1).unwrap()).unwrap(),
            &x_coord,
            &broadcasts,
            true,
        );
        let abort = result.expect_err("tampered broadcast should fail signature validation");
        assert_eq!(abort.kind, AbortKind::Recoverable);
        assert!(matches!(
            abort.reason,
            AbortReason::SignatureVerificationFailed
        ));
    }
}
