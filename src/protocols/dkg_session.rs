use std::collections::BTreeMap;
use std::fmt;

use k256::Scalar;
use zeroize::Zeroize;

use crate::protocols::dkg::{
    self, BroadcastDerivationPhase2to4, BroadcastDerivationPhase3to4, KeepInitMulPhase3to4,
    KeepInitZeroSharePhase2to3, KeepInitZeroSharePhase3to4, ProofCommitment, SessionData,
    TransmitInitMulPhase3to4, TransmitInitZeroSharePhase2to4, TransmitInitZeroSharePhase3to4,
    UniqueKeepDerivationPhase2to3,
};
use crate::protocols::{Abort, AbortReason, Parameters, Party, PartyIndex, PublicKeyPackage};

pub struct DkgSession {
    data: SessionData,
    poly_point: Option<Scalar>,
    proof_commitment: Option<ProofCommitment>,
    zero_kept_2to3: Option<BTreeMap<PartyIndex, KeepInitZeroSharePhase2to3>>,
    bip_kept_2to3: Option<UniqueKeepDerivationPhase2to3>,
    zero_kept_3to4: Option<BTreeMap<PartyIndex, KeepInitZeroSharePhase3to4>>,
    mul_kept_3to4: Option<BTreeMap<PartyIndex, KeepInitMulPhase3to4>>,
}

impl DkgSession {
    #[must_use]
    pub fn new(parameters: Parameters, party_index: PartyIndex, session_id: Vec<u8>) -> Self {
        DkgSession {
            data: SessionData {
                parameters,
                party_index,
                session_id,
            },
            poly_point: None,
            proof_commitment: None,
            zero_kept_2to3: None,
            bip_kept_2to3: None,
            zero_kept_3to4: None,
            mul_kept_3to4: None,
        }
    }

    #[must_use]
    pub fn phase1(&self) -> Vec<Scalar> {
        dkg::phase1(&self.data)
    }

    pub(crate) fn phase2(
        &mut self,
        poly_fragments: &[Scalar],
    ) -> Result<
        (
            ProofCommitment,
            Vec<TransmitInitZeroSharePhase2to4>,
            BroadcastDerivationPhase2to4,
        ),
        Abort,
    > {
        if self.poly_point.is_some() {
            return Err(Abort::recoverable(
                self.data.party_index,
                AbortReason::PhaseCalledOutOfOrder { phase: "phase2 already called on this session".into() },
            ));
        }

        let (poly_point, proof_commitment, zero_keep, zero_transmit, bip_keep, bip_broadcast) =
            dkg::phase2(&self.data, poly_fragments);

        self.poly_point = Some(poly_point);
        self.proof_commitment = Some(proof_commitment.clone());
        self.zero_kept_2to3 = Some(zero_keep);
        self.bip_kept_2to3 = Some(bip_keep);

        Ok((proof_commitment, zero_transmit, bip_broadcast))
    }

    pub(crate) fn phase3(
        &mut self,
    ) -> Result<
        (
            Vec<TransmitInitZeroSharePhase3to4>,
            Vec<TransmitInitMulPhase3to4>,
            BroadcastDerivationPhase3to4,
        ),
        Abort,
    > {
        let zero_kept = self
            .zero_kept_2to3
            .as_ref()
            .ok_or_else(|| Abort::recoverable(self.data.party_index, AbortReason::PhaseCalledOutOfOrder { phase: "phase3 called before phase2".into() }))?;
        let bip_kept = self
            .bip_kept_2to3
            .as_ref()
            .ok_or_else(|| Abort::recoverable(self.data.party_index, AbortReason::PhaseCalledOutOfOrder { phase: "phase3 called before phase2".into() }))?;

        let (zero_keep_3to4, zero_transmit, mul_keep, mul_transmit, bip_broadcast) =
            dkg::phase3(&self.data, zero_kept, bip_kept);

        if let Some(ref mut map) = self.zero_kept_2to3 {
            for v in map.values_mut() {
                v.seed.zeroize();
                v.salt.zeroize();
            }
            map.clear();
        }
        self.zero_kept_2to3 = None;

        if let Some(ref mut bip) = self.bip_kept_2to3 {
            bip.aux_chain_code.zeroize();
            bip.cc_salt.zeroize();
        }
        self.bip_kept_2to3 = None;
        self.zero_kept_3to4 = Some(zero_keep_3to4);
        self.mul_kept_3to4 = Some(mul_keep);

        Ok((zero_transmit, mul_transmit, bip_broadcast))
    }

    pub(crate) fn phase4(
        self,
        proofs_commitments: &[ProofCommitment],
        zero_received_phase2: &[TransmitInitZeroSharePhase2to4],
        zero_received_phase3: &[TransmitInitZeroSharePhase3to4],
        mul_received: &[TransmitInitMulPhase3to4],
        bip_received_phase2: &BTreeMap<PartyIndex, BroadcastDerivationPhase2to4>,
        bip_received_phase3: &BTreeMap<PartyIndex, BroadcastDerivationPhase3to4>,
    ) -> Result<(Party, PublicKeyPackage), Abort> {
        let poly_point = self
            .poly_point
            .as_ref()
            .ok_or_else(|| Abort::recoverable(self.data.party_index, AbortReason::PhaseCalledOutOfOrder { phase: "phase4 called before phase2".into() }))?;
        let zero_kept = self
            .zero_kept_3to4
            .as_ref()
            .ok_or_else(|| Abort::recoverable(self.data.party_index, AbortReason::PhaseCalledOutOfOrder { phase: "phase4 called before phase3".into() }))?;
        let mul_kept = self
            .mul_kept_3to4
            .as_ref()
            .ok_or_else(|| Abort::recoverable(self.data.party_index, AbortReason::PhaseCalledOutOfOrder { phase: "phase4 called before phase3".into() }))?;

        dkg::phase4(
            &self.data,
            poly_point,
            proofs_commitments,
            zero_kept,
            zero_received_phase2,
            zero_received_phase3,
            mul_kept,
            mul_received,
            bip_received_phase2,
            bip_received_phase3,
        )
    }
}

impl fmt::Debug for DkgSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let phase = if self.mul_kept_3to4.is_some() {
            "phase3 complete"
        } else if self.poly_point.is_some() {
            "phase2 complete"
        } else {
            "initialized"
        };
        f.debug_struct("DkgSession")
            .field("party_index", &self.data.party_index)
            .field("threshold", &self.data.parameters.threshold)
            .field("share_count", &self.data.parameters.share_count)
            .field("state", &phase)
            .finish()
    }
}

impl Zeroize for DkgSession {
    fn zeroize(&mut self) {
        self.data.session_id.zeroize();

        if let Some(ref mut pp) = self.poly_point {
            pp.zeroize();
        }
        self.poly_point = None;
        self.proof_commitment = None;

        if let Some(ref mut map) = self.zero_kept_2to3 {
            for v in map.values_mut() {
                v.seed.zeroize();
                v.salt.zeroize();
            }
            map.clear();
        }
        self.zero_kept_2to3 = None;

        if let Some(ref mut bip) = self.bip_kept_2to3 {
            bip.aux_chain_code.zeroize();
            bip.cc_salt.zeroize();
        }
        self.bip_kept_2to3 = None;

        if let Some(ref mut map) = self.zero_kept_3to4 {
            for v in map.values_mut() {
                v.seed.zeroize();
            }
            map.clear();
        }
        self.zero_kept_3to4 = None;

        if let Some(ref mut map) = self.mul_kept_3to4 {
            for v in map.values_mut() {
                v.ot_sender.s.zeroize();
                v.ot_receiver.seed.zeroize();
                v.nonce.zeroize();
                v.vec_r.zeroize();
                v.correlation.zeroize();
            }
            map.clear();
        }
        self.mul_kept_3to4 = None;
    }
}

impl Drop for DkgSession {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::AbortReason;
    use crate::utilities::rng;
    use rand::RngExt;

    const SESSION_ID_LEN: usize = 32;

    #[test]
    fn test_dkg_session_full_flow() {
        let threshold = rng::get_rng().random_range(2..=5);
        let offset = rng::get_rng().random_range(0..=5);

        let parameters = Parameters {
            threshold,
            share_count: threshold + offset,
        };
        let session_id = rng::get_rng().random::<[u8; SESSION_ID_LEN]>();

        let n = parameters.share_count as usize;

        // Create sessions for each party.
        let mut sessions: Vec<DkgSession> = (0..parameters.share_count)
            .map(|i| {
                DkgSession::new(
                    parameters.clone(),
                    PartyIndex::new(i + 1).unwrap(),
                    session_id.to_vec(),
                )
            })
            .collect();

        // Phase 1
        let mut dkg_1: Vec<Vec<Scalar>> = Vec::with_capacity(n);
        for session in &sessions {
            dkg_1.push(session.phase1());
        }

        // Communication round 1: transpose poly fragments.
        let mut poly_fragments = vec![Vec::<Scalar>::with_capacity(n); n];
        for row in dkg_1 {
            for j in 0..parameters.share_count {
                poly_fragments[j as usize].push(row[j as usize]);
            }
        }

        // Phase 2
        let mut proofs_commitments: Vec<ProofCommitment> = Vec::with_capacity(n);
        let mut zero_transmit_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> =
            Vec::with_capacity(n);
        let mut bip_broadcast_2to4: BTreeMap<PartyIndex, BroadcastDerivationPhase2to4> =
            BTreeMap::new();

        for (i, session) in sessions.iter_mut().enumerate() {
            let (proof_commitment, zero_transmit, bip_broadcast) =
                session.phase2(&poly_fragments[i]).unwrap();

            proofs_commitments.push(proof_commitment);
            zero_transmit_2to4.push(zero_transmit);
            bip_broadcast_2to4.insert(PartyIndex::new(i as u8 + 1).unwrap(), bip_broadcast);
        }

        // Communication round 2: route zero-share messages.
        let mut zero_received_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> =
            Vec::with_capacity(n);
        for i in 1..=parameters.share_count {
            let pi = PartyIndex::new(i).unwrap();
            let mut row = Vec::with_capacity(n - 1);
            for party in &zero_transmit_2to4 {
                for message in party {
                    if message.parties.receiver == pi {
                        row.push(message.clone());
                    }
                }
            }
            zero_received_2to4.push(row);
        }

        // Phase 3
        let mut zero_transmit_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> =
            Vec::with_capacity(n);
        let mut mul_transmit_3to4: Vec<Vec<TransmitInitMulPhase3to4>> = Vec::with_capacity(n);
        let mut bip_broadcast_3to4: BTreeMap<PartyIndex, BroadcastDerivationPhase3to4> =
            BTreeMap::new();

        for (i, session) in sessions.iter_mut().enumerate() {
            let (zero_transmit, mul_transmit, bip_broadcast) = session.phase3().unwrap();

            zero_transmit_3to4.push(zero_transmit);
            mul_transmit_3to4.push(mul_transmit);
            bip_broadcast_3to4.insert(PartyIndex::new(i as u8 + 1).unwrap(), bip_broadcast);
        }

        // Communication round 3: route zero-share and mul messages.
        let mut zero_received_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> =
            Vec::with_capacity(n);
        let mut mul_received_3to4: Vec<Vec<TransmitInitMulPhase3to4>> = Vec::with_capacity(n);
        for i in 1..=parameters.share_count {
            let pi = PartyIndex::new(i).unwrap();
            let mut zero_row = Vec::with_capacity(n - 1);
            for party in &zero_transmit_3to4 {
                for message in party {
                    if message.parties.receiver == pi {
                        zero_row.push(message.clone());
                    }
                }
            }
            zero_received_3to4.push(zero_row);

            let mut mul_row = Vec::with_capacity(n - 1);
            for party in &mul_transmit_3to4 {
                for message in party {
                    if message.parties.receiver == pi {
                        mul_row.push(message.clone());
                    }
                }
            }
            mul_received_3to4.push(mul_row);
        }

        // Phase 4
        let mut parties: Vec<Party> = Vec::with_capacity(n);
        for (i, session) in sessions.into_iter().enumerate() {
            let (party, _pkg) = session
                .phase4(
                    &proofs_commitments,
                    &zero_received_2to4[i],
                    &zero_received_3to4[i],
                    &mul_received_3to4[i],
                    &bip_broadcast_2to4,
                    &bip_broadcast_3to4,
                )
                .unwrap_or_else(|abort| {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description())
                });
            parties.push(party);
        }

        let expected_pk = parties[0].pk;
        let expected_chain_code = parties[0].derivation_data.chain_code;
        for party in &parties {
            assert_eq!(expected_pk, party.pk);
            assert_eq!(expected_chain_code, party.derivation_data.chain_code);
        }
    }

    #[test]
    fn test_dkg_session_phase_ordering() {
        let parameters = Parameters {
            threshold: 2,
            share_count: 2,
        };
        let session_id = rng::get_rng().random::<[u8; SESSION_ID_LEN]>();
        let pi = PartyIndex::new(1).unwrap();

        // phase3 before phase2
        let mut session = DkgSession::new(parameters.clone(), pi, session_id.to_vec());
        let result = session.phase3();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().reason,
            AbortReason::PhaseCalledOutOfOrder { ref phase } if phase.contains("phase3 called before phase2")
        ));

        // phase4 before phase2
        let session = DkgSession::new(parameters.clone(), pi, session_id.to_vec());
        let result = session.phase4(&[], &[], &[], &[], &BTreeMap::new(), &BTreeMap::new());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().reason,
            AbortReason::PhaseCalledOutOfOrder { ref phase } if phase.contains("phase4 called before phase2")
        ));

        // phase4 after phase2 but before phase3
        let mut session = DkgSession::new(parameters, pi, session_id.to_vec());
        let fragments = session.phase1();
        session.phase2(&fragments).unwrap();
        let result = session.phase4(&[], &[], &[], &[], &BTreeMap::new(), &BTreeMap::new());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().reason,
            AbortReason::PhaseCalledOutOfOrder { ref phase } if phase.contains("phase4 called before phase3")
        ));
    }

    #[test]
    fn test_dkg_session_double_phase2() {
        let parameters = Parameters {
            threshold: 2,
            share_count: 2,
        };
        let session_id = rng::get_rng().random::<[u8; SESSION_ID_LEN]>();
        let pi = PartyIndex::new(1).unwrap();

        let mut session = DkgSession::new(parameters.clone(), pi, session_id.to_vec());

        let fragments = session.phase1();
        session.phase2(&fragments).unwrap();

        let result = session.phase2(&fragments);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().reason,
            AbortReason::PhaseCalledOutOfOrder { .. }
        ));
    }
}
