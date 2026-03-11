use std::collections::BTreeMap;

use crate::protocols::signature::EcdsaSignature;
use crate::protocols::signing::{
    Broadcast3to4, KeepPhase1to2, KeepPhase2to3, SignData, TransmitPhase1to2, TransmitPhase2to3,
    UniqueKeep1to2, UniqueKeep2to3,
};
use crate::protocols::{Abort, AbortReason, Party, PartyIndex};

pub struct SignSession<'a> {
    party: &'a Party,
    data: SignData,
    phase1_to_2: Option<(UniqueKeep1to2, BTreeMap<PartyIndex, KeepPhase1to2>)>,
    phase2_to_3: Option<(UniqueKeep2to3, BTreeMap<PartyIndex, KeepPhase2to3>)>,
    x_coord: Option<String>,
}

impl<'a> SignSession<'a> {
    pub(crate) fn new(
        party: &'a Party,
        data: SignData,
    ) -> Result<(Self, Vec<TransmitPhase1to2>), Abort> {
        let (unique_kept, kept, transmit) = party.sign_phase1(&data)?;
        let session = Self {
            party,
            data,
            phase1_to_2: Some((unique_kept, kept)),
            phase2_to_3: None,
            x_coord: None,
        };
        Ok((session, transmit))
    }

    pub(crate) fn phase2(
        &mut self,
        received: &[TransmitPhase1to2],
    ) -> Result<Vec<TransmitPhase2to3>, Abort> {
        let (unique_kept, kept) = self.phase1_to_2.take().ok_or_else(|| {
            Abort::recoverable(
                self.party.party_index,
                AbortReason::PhaseCalledOutOfOrder {
                    phase: "phase2 called out of order".into(),
                },
            )
        })?;
        let (new_unique, new_kept, transmit) =
            self.party
                .sign_phase2(&self.data, &unique_kept, &kept, received)?;
        self.phase2_to_3 = Some((new_unique, new_kept));
        Ok(transmit)
    }

    pub(crate) fn phase3(
        &mut self,
        received: &[TransmitPhase2to3],
    ) -> Result<Broadcast3to4, Abort> {
        let (unique_kept, kept) = self.phase2_to_3.take().ok_or_else(|| {
            Abort::recoverable(
                self.party.party_index,
                AbortReason::PhaseCalledOutOfOrder {
                    phase: "phase3 called out of order".into(),
                },
            )
        })?;
        let (x_coord, broadcast) =
            self.party
                .sign_phase3(&self.data, &unique_kept, &kept, received)?;
        self.x_coord = Some(x_coord);
        Ok(broadcast)
    }

    pub(crate) fn phase4(
        mut self,
        received: &[Broadcast3to4],
        normalize: bool,
    ) -> Result<EcdsaSignature, Abort> {
        let x_coord = self.x_coord.take().ok_or_else(|| {
            Abort::recoverable(
                self.party.party_index,
                AbortReason::PhaseCalledOutOfOrder {
                    phase: "phase4 called out of order".into(),
                },
            )
        })?;
        let (s_hex, recovery_id) = self
            .party
            .sign_phase4(&self.data, &x_coord, received, normalize)?;

        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        hex::decode_to_slice(&x_coord, &mut r).map_err(|e| {
            Abort::recoverable(
                self.party.party_index,
                AbortReason::InvalidHex {
                    detail: format!("invalid r hex: {e}"),
                },
            )
        })?;
        hex::decode_to_slice(&s_hex, &mut s).map_err(|e| {
            Abort::recoverable(
                self.party.party_index,
                AbortReason::InvalidHex {
                    detail: format!("invalid s hex: {e}"),
                },
            )
        })?;
        Ok(EcdsaSignature { r, s, recovery_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::Field;
    use k256::Scalar;

    use crate::protocols::re_key::re_key;
    use crate::protocols::signing::{verify_ecdsa_signature, SignData};
    use crate::protocols::Parameters;
    use crate::utilities::hashes::tagged_hash;
    use crate::utilities::rng;
    use rand::RngExt;

    #[test]
    fn test_sign_session_happy_path() {
        let threshold = rng::get_rng().random_range(2..=5);
        let offset = rng::get_rng().random_range(0..=5);
        let parameters = Parameters {
            threshold,
            share_count: threshold + offset,
        };

        let session_id = rng::get_rng().random::<[u8; 32]>();
        let secret_key = Scalar::random(&mut rng::get_rng());
        let (parties, _) = re_key(&parameters, &session_id, &secret_key, None);

        let sign_id = rng::get_rng().random::<[u8; 32]>();
        let message_to_sign = tagged_hash(b"test-sign", &["Message to sign!".as_bytes()]);
        let executing_parties: Vec<u8> = Vec::from_iter(1..=parameters.threshold);

        // Build SignData per party.
        let mut all_data: BTreeMap<u8, SignData> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            let counterparties: Vec<PartyIndex> = executing_parties
                .iter()
                .filter(|&&i| i != party_index)
                .map(|&i| PartyIndex::new(i).unwrap())
                .collect();
            all_data.insert(
                party_index,
                SignData {
                    sign_id: sign_id.to_vec(),
                    counterparties,
                    message_hash: message_to_sign,
                },
            );
        }

        // Phase 1 — create sessions.
        let mut sessions: BTreeMap<u8, SignSession> = BTreeMap::new();
        let mut transmit_1to2: BTreeMap<u8, Vec<TransmitPhase1to2>> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            let (session, transmit) = SignSession::new(
                &parties[(party_index - 1) as usize],
                all_data.get(&party_index).unwrap().clone(),
            )
            .unwrap();
            sessions.insert(party_index, session);
            transmit_1to2.insert(party_index, transmit);
        }

        // Route round 1 messages.
        let mut received_1to2: BTreeMap<u8, Vec<TransmitPhase1to2>> = BTreeMap::new();
        for &party_index in &executing_parties {
            let pi = PartyIndex::new(party_index).unwrap();
            let msgs: Vec<TransmitPhase1to2> = transmit_1to2
                .values()
                .flatten()
                .filter(|m| m.parties.receiver == pi)
                .cloned()
                .collect();
            received_1to2.insert(party_index, msgs);
        }

        // Phase 2.
        let mut transmit_2to3: BTreeMap<u8, Vec<TransmitPhase2to3>> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            let transmit = sessions
                .get_mut(&party_index)
                .unwrap()
                .phase2(received_1to2.get(&party_index).unwrap())
                .unwrap();
            transmit_2to3.insert(party_index, transmit);
        }

        // Route round 2 messages.
        let mut received_2to3: BTreeMap<u8, Vec<TransmitPhase2to3>> = BTreeMap::new();
        for &party_index in &executing_parties {
            let pi = PartyIndex::new(party_index).unwrap();
            let msgs: Vec<TransmitPhase2to3> = transmit_2to3
                .values()
                .flatten()
                .filter(|m| m.parties.receiver == pi)
                .cloned()
                .collect();
            received_2to3.insert(party_index, msgs);
        }

        // Phase 3.
        let mut broadcasts: Vec<Broadcast3to4> = Vec::with_capacity(parameters.threshold as usize);
        for party_index in executing_parties.clone() {
            let broadcast = sessions
                .get_mut(&party_index)
                .unwrap()
                .phase3(received_2to3.get(&party_index).unwrap())
                .unwrap();
            broadcasts.push(broadcast);
        }

        // Phase 4 — consume sessions.
        let some_index = executing_parties[0];
        let session = sessions.remove(&some_index).unwrap();
        let signature = session.phase4(&broadcasts, true).unwrap();

        // Verify the EcdsaSignature fields are populated.
        assert_ne!(signature.r, [0u8; 32]);
        assert_ne!(signature.s, [0u8; 32]);

        // Cross-check with verify_ecdsa_signature.
        let r_hex = hex::encode(signature.r);
        let s_hex = hex::encode(signature.s);
        assert!(verify_ecdsa_signature(
            &message_to_sign,
            &parties[0].pk,
            &r_hex,
            &s_hex,
        ));
    }

    #[test]
    fn test_sign_session_phase_order_error() {
        let parameters = Parameters {
            threshold: 2,
            share_count: 2,
        };
        let session_id = rng::get_rng().random::<[u8; 32]>();
        let secret_key = Scalar::random(&mut rng::get_rng());
        let (parties, _) = re_key(&parameters, &session_id, &secret_key, None);

        let data = SignData {
            sign_id: rng::get_rng().random::<[u8; 32]>().to_vec(),
            counterparties: vec![PartyIndex::new(2).unwrap()],
            message_hash: tagged_hash(b"test-sign", &["Message to sign!".as_bytes()]),
        };

        let (mut session, _) = SignSession::new(&parties[0], data).unwrap();

        // Skip phase2, call phase3 directly — should fail.
        let result = session.phase3(&[]);
        assert!(result.is_err());
    }
}
