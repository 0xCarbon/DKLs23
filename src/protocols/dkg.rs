/// This file implements Protocol 9.1 in https://eprint.iacr.org/2023/602.pdf,
/// as instructed in DKLs23 (https://eprint.iacr.org/2023/765.pdf). It is
/// the distributed key generation which setups the main signing protocol.
///
/// During the protocol, we also initialize the functionalities that will
/// be used during signing. Their implementations can be found in the files
/// zero_sharings.rs and multiplication.rs.
use std::collections::HashMap;

use hex;
use k256::elliptic_curve::{point::AffineCoordinates, Field};
use k256::{AffinePoint, Scalar};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::protocols::derivation::{ChainCode, DerivationData};
use crate::protocols::{Abort, Parameters, PartiesMessage, Party};

use crate::utilities::commits;
use crate::utilities::hashes::HashOutput;
use crate::utilities::multiplication::{MulReceiver, MulSender};
use crate::utilities::ot::ot_base;
use crate::utilities::proofs::{DLogProof, EncProof};
use crate::utilities::zero_sharings::{self, ZeroShare};

// This struct is used during key generation
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProofCommitment {
    pub index: usize,
    pub proof: DLogProof,
    pub commitment: HashOutput,
}

// This struct contains the data needed to start
// key generation and that are used during the phases.
#[derive(Clone, Deserialize, Serialize)]
pub struct SessionData {
    pub parameters: Parameters,
    pub party_index: usize,
    pub session_id: Vec<u8>,
}

// For the initialization structs, we will use the following nomenclature:

// "Transmit" messages refer to only one counterparty, hence
// we must send a whole vector of them.

// "Broadcast" messages refer to all counterparties at once,
// hence we only need to send a unique instance of it.
// ATTENTION: we broadcast the message to ourselves as well.

// "Keep" messages refer to only one counterparty, hence
// we must keep a whole vector of them.

// "Unique keep" messages refer to all counterparties at once,
// hence we only need to keep a unique instance of it.

////////// INITIALIZING ZERO SHARING PROTOCOL.

// Transmit
#[derive(Clone, Serialize, Deserialize)]
pub struct TransmitInitZeroSharePhase2to4 {
    pub parties: PartiesMessage,
    pub commitment: HashOutput,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TransmitInitZeroSharePhase3to4 {
    pub parties: PartiesMessage,
    pub seed: zero_sharings::Seed,
    pub salt: Vec<u8>,
}

// Keep
#[derive(Clone, Serialize, Deserialize)]
pub struct KeepInitZeroSharePhase2to3 {
    pub seed: zero_sharings::Seed,
    pub salt: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeepInitZeroSharePhase3to4 {
    pub seed: zero_sharings::Seed,
}

////////// INITIALIZING TWO-PARTY MULTIPLICATION PROTOCOL.

// Transmit
#[derive(Clone, Serialize, Deserialize)]
pub struct TransmitInitMulPhase3to4 {
    pub parties: PartiesMessage,

    pub dlog_proof: DLogProof,
    pub nonce: Scalar,

    pub enc_proofs: Vec<EncProof>,
    pub seed: ot_base::Seed,
}

// Keep
#[derive(Clone, Serialize, Deserialize)]
pub struct KeepInitMulPhase3to4 {
    pub ot_sender: ot_base::OTSender,
    pub nonce: Scalar,

    pub ot_receiver: ot_base::OTReceiver,
    pub correlation: Vec<bool>,
    pub vec_r: Vec<Scalar>,
}

////////// INITIALIZING KEY DERIVATION (VIA BIP-32).

// Broadcast
#[derive(Clone, Serialize, Deserialize)]
pub struct BroadcastDerivationPhase2to4 {
    pub sender_index: usize,
    pub cc_commitment: HashOutput,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BroadcastDerivationPhase3to4 {
    pub sender_index: usize,
    pub aux_chain_code: ChainCode,
    pub cc_salt: Vec<u8>,
}

// Unique keep
#[derive(Clone, Serialize, Deserialize)]
pub struct UniqueKeepDerivationPhase2to3 {
    pub aux_chain_code: ChainCode,
    pub cc_salt: Vec<u8>,
}

///////////////////////////////////////////////////////////////////////////////

// DISTRIBUTED KEY GENERATION (DKG)

// STEPS
// We implement each step of the protocol.

// Step 1 - Generate random polynomial of degree t-1.
pub fn dkg_step1(parameters: &Parameters) -> Vec<Scalar> {
    // We represent the polynomial by its coefficients.
    let mut polynomial: Vec<Scalar> = Vec::with_capacity(parameters.threshold);
    for _ in 0..parameters.threshold {
        polynomial.push(Scalar::random(rand::thread_rng()));
    }

    polynomial
}

// Step 2 - Evaluate the polynomial from the previous step at every point.
pub fn dkg_step2(parameters: &Parameters, polynomial: Vec<Scalar>) -> Vec<Scalar> {
    let mut points: Vec<Scalar> = Vec::with_capacity(parameters.share_count);

    for j in 1..=parameters.share_count {
        // We compute the polynomial evaluated at j.
        let mut evaluation_at_j = Scalar::ZERO;
        let mut power_of_j = Scalar::ONE;
        for i in 0..parameters.threshold {
            evaluation_at_j += polynomial[i] * power_of_j;
            power_of_j *= Scalar::from(j as u64);
        }

        points.push(evaluation_at_j);
    }

    points
}

// Step 3 - Compute poly_point (p(i) in the paper) and the corresponding "public key" (P(i) in the paper).
// It also commits to a zero-knowledge proof that p(i) is the discrete logarithm of P(i).
// The session id is used for the proof.
pub fn dkg_step3(
    party_index: usize,
    session_id: &[u8],
    poly_fragments: &Vec<Scalar>,
) -> (Scalar, ProofCommitment) {
    let poly_point: Scalar = poly_fragments.iter().sum();

    let (proof, commitment) = DLogProof::prove_commit(&poly_point, session_id);
    let proof_commitment = ProofCommitment {
        index: party_index,
        proof,
        commitment,
    };

    (poly_point, proof_commitment)
}

// Step 4 is a communication round (see the description below).

// Step 5 - Each party validates the other proofs. They also recover the "public keys fragements" from the other parties.
// Finally, a consistency check is done. In the process, the publick key is computed (Step 6).
pub fn dkg_step5(
    parameters: &Parameters,
    party_index: usize,
    session_id: &[u8],
    proofs_commitments: &Vec<ProofCommitment>,
) -> Result<AffinePoint, Abort> {
    let mut commited_points: Vec<AffinePoint> = Vec::with_capacity(parameters.share_count); //The "public key fragments"
                                                                                            // Verify the proofs and gather the commited points.
    for party_j in proofs_commitments {
        if party_j.index != party_index {
            let verification =
                DLogProof::decommit_verify(&party_j.proof, &party_j.commitment, session_id);
            if !verification {
                return Err(Abort::new(
                    party_index,
                    &format!("Proof from Party {} failed!", party_j.index),
                ));
            }
        }
        commited_points.push(party_j.proof.point);
    }

    // Initializes what will be the public key.
    let mut pk = AffinePoint::IDENTITY;

    // Verify that all points come from the same polyonimal. To do so, for each contiguous set of parties,
    // perform Shamir reconstruction in the exponent and check if the results agree.
    // The common value calculated is the public key.
    for i in 1..=(parameters.share_count - parameters.threshold + 1) {
        let mut current_pk = AffinePoint::IDENTITY;
        for j in i..=(i + parameters.threshold - 1) {
            // We find the Lagrange coefficient l(j) corresponding to j (and the contiguous set of parties).
            // It is such that the sum of l(j) * p(j) over all j is p(0), where p is the polyonimal from Step 3.
            let mut lj_numerator = Scalar::ONE;
            let mut lj_denominator = Scalar::ONE;
            for k in i..=(i + parameters.threshold - 1) {
                if k != j {
                    lj_numerator *= Scalar::from(k as u64);
                    lj_denominator *= Scalar::from(k as u64) - Scalar::from(j as u64);
                }
            }
            let lj = lj_numerator * (lj_denominator.invert().unwrap());

            let lj_times_point = commited_points[j - 1] * &lj; // j-1 because index starts at 0
            current_pk = (lj_times_point + current_pk).to_affine();
        }
        // The first value is taken as the public key. It should coincide with the next values.
        if i == 1 {
            pk = current_pk;
        } else if pk != current_pk {
            return Err(Abort::new(
                party_index,
                &format!(
                    "Verification for public key reconstruction failed in iteration {}",
                    i
                ),
            ));
        }
    }
    Ok(pk)
}

// Step 6 was done during the previous step.

// PHASES
// We group the steps in phases. A phase consists of all steps that can be executed in order without the need of communication.
// Phases should be intercalated with communication rounds: broadcasts and/or private messages containg the session id.

// We also include here the initialization procedures of Functionalities 3.4 and 3.5 of DKLs23 (https://eprint.iacr.org/2023/765.pdf).
// The first one comes from the file zero_sharings.rs and needs two communication rounds (hence, it starts on Phase 2).
// The second one comes from the file multiplication.rs and needs one communication round (hence, it starts on Phase 3).

// For key derivation (following BIP-32: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki), parties must agree
// on a common chain code for their shared master key. Using the commitment functionality, we need two communication rounds,
// so this part starts only on Phase 2.

// Phase 1 = Steps 1 and 2
// Input (DKG): Parameters for the key generation.
// Output (DKG): Evaluation of a random polynomial at every party index.
pub fn dkg_phase1(data: &SessionData) -> Vec<Scalar> {
    // DKG
    let secret_polynomial = dkg_step1(&data.parameters);
    

    dkg_step2(&data.parameters, secret_polynomial)
}

// Communication round 1
// DKG: Party i keeps the i-th point and sends the j-th point to Party j for j != i.
// At the end, Party i should have received all fragements indexed by i.
// They should add up to p(i), where p is a polynomial not depending on i.

// Phase 2 = Step 3
// Input (DKG): Fragments received from communication and session id.
// Input (Init): Session data.
// Output (DKG): p(i) and a proof of discrete logarithm with commitment.
// Output (Init): Some data to keep and to transmit.
pub fn dkg_phase2(
    data: &SessionData,
    poly_fragments: &Vec<Scalar>,
) -> (
    Scalar,
    ProofCommitment,
    HashMap<usize, KeepInitZeroSharePhase2to3>,
    Vec<TransmitInitZeroSharePhase2to4>,
    UniqueKeepDerivationPhase2to3,
    BroadcastDerivationPhase2to4,
) {
    // DKG
    let (poly_point, proof_commitment) =
        dkg_step3(data.party_index, &data.session_id, poly_fragments);

    // Initialization - Zero sharings.

    // We will use HashMap to keep messages: the key indicates the party to whom the message refers.
    let mut zero_keep: HashMap<usize, KeepInitZeroSharePhase2to3> =
        HashMap::with_capacity(data.parameters.share_count - 1);
    let mut zero_transmit: Vec<TransmitInitZeroSharePhase2to4> =
        Vec::with_capacity(data.parameters.share_count - 1);
    for i in 1..=data.parameters.share_count {
        if i == data.party_index {
            continue;
        }

        // Generate initial seeds.
        let (seed, commitment, salt) = ZeroShare::generate_seed_with_commitment();

        // We first send the commitments. We keep the rest to send later.
        let keep = KeepInitZeroSharePhase2to3 { seed, salt };
        let transmit = TransmitInitZeroSharePhase2to4 {
            parties: PartiesMessage {
                sender: data.party_index,
                receiver: i,
            },
            commitment,
        };

        zero_keep.insert(i, keep);
        zero_transmit.push(transmit);
    }

    // Initialization - BIP-32.
    // Each party samples a random auxiliary chain code.
    let aux_chain_code = rand::thread_rng().gen::<ChainCode>();
    let (cc_commitment, cc_salt) = commits::commit(&aux_chain_code);

    let bip_keep = UniqueKeepDerivationPhase2to3 {
        aux_chain_code,
        cc_salt,
    };
    // For simplicity, this message should be sent to us too.
    let bip_broadcast = BroadcastDerivationPhase2to4 {
        sender_index: data.party_index,
        cc_commitment,
    };

    (
        poly_point,
        proof_commitment,
        zero_keep,
        zero_transmit,
        bip_keep,
        bip_broadcast,
    )
}

// Communication round 2
// DKG: Party i broadcasts his commitment to the proof and receive the other commitments.
//
// Init: Each party transmits messages for the zero sharing protocol (one for each party)
// and broadcasts a message for key derivation (the same for every party).

// Phase 3 = No steps in DKG (just initialization)
// Input (Init): Session data and the values kept from previous round.
// Output (Init): Some data to keep and to transmit.
pub fn dkg_phase3(
    data: &SessionData,
    zero_kept: &HashMap<usize, KeepInitZeroSharePhase2to3>,
    bip_kept: &UniqueKeepDerivationPhase2to3,
) -> (
    HashMap<usize, KeepInitZeroSharePhase3to4>,
    Vec<TransmitInitZeroSharePhase3to4>,
    HashMap<usize, KeepInitMulPhase3to4>,
    Vec<TransmitInitMulPhase3to4>,
    BroadcastDerivationPhase3to4,
) {
    // Initialization - Zero sharings.
    let mut zero_keep: HashMap<usize, KeepInitZeroSharePhase3to4> =
        HashMap::with_capacity(data.parameters.share_count - 1);
    let mut zero_transmit: Vec<TransmitInitZeroSharePhase3to4> =
        Vec::with_capacity(data.parameters.share_count - 1);
    for (target_party, message_kept) in zero_kept {
        // The messages kept contain the seed and the salt.
        // They have to be transmitted to the target party.
        // We keep the seed with us for the next phase.
        let keep = KeepInitZeroSharePhase3to4 {
            seed: message_kept.seed,
        };
        let transmit = TransmitInitZeroSharePhase3to4 {
            parties: PartiesMessage {
                sender: data.party_index,
                receiver: *target_party,
            },
            seed: message_kept.seed,
            salt: message_kept.salt.clone(),
        };

        zero_keep.insert(*target_party, keep);
        zero_transmit.push(transmit);
    }

    // Initialization - Two-party multiplication.
    // Each party prepares initialization both as
    // a receiver and as a sender.
    let mut mul_keep: HashMap<usize, KeepInitMulPhase3to4> =
        HashMap::with_capacity(data.parameters.share_count - 1);
    let mut mul_transmit: Vec<TransmitInitMulPhase3to4> =
        Vec::with_capacity(data.parameters.share_count - 1);
    for i in 1..=data.parameters.share_count {
        if i == data.party_index {
            continue;
        }

        // RECEIVER
        // We are the receiver and i = sender.

        // We first compute a new session id.
        // As in Protocol 3.6 of DKLs23, we include the indexes from the parties.
        let mul_sid_receiver = [
            &(data.party_index as u8).to_be_bytes(),
            &(i as u8).to_be_bytes(),
            &data.session_id[..],
        ]
        .concat();

        let (ot_sender, dlog_proof, nonce) = MulReceiver::init_phase1(&mul_sid_receiver);

        // SENDER
        // We are the sender and i = receiver.

        // New session id as above.
        // Note that the indexes are now in the opposite order.
        let mul_sid_sender = [
            &(i as u8).to_be_bytes(),
            &(data.party_index as u8).to_be_bytes(),
            &data.session_id[..],
        ]
        .concat();

        let (ot_receiver, correlation, vec_r, enc_proofs) = MulSender::init_phase1(&mul_sid_sender);

        // We gather these values.

        let transmit = TransmitInitMulPhase3to4 {
            parties: PartiesMessage {
                sender: data.party_index,
                receiver: i,
            },

            // Us = Receiver
            dlog_proof,
            nonce,

            // Us = Sender
            enc_proofs,
            seed: ot_receiver.seed,
        };
        let keep = KeepInitMulPhase3to4 {
            // Us = Receiver
            ot_sender,
            nonce,

            // Us = Sender
            ot_receiver,
            correlation,
            vec_r,
        };

        mul_keep.insert(i, keep);
        mul_transmit.push(transmit);
    }

    // Initialization - BIP-32.
    // After having transmitted the commitment, we broadcast
    // our auxiliary chain code and the corresponding salt.
    // For simplicity, this message should be sent to us too.
    let bip_broadcast = BroadcastDerivationPhase3to4 {
        sender_index: data.party_index,
        aux_chain_code: bip_kept.aux_chain_code,
        cc_salt: bip_kept.cc_salt.clone(),
    };

    (
        zero_keep,
        zero_transmit,
        mul_keep,
        mul_transmit,
        bip_broadcast,
    )
}

// Communication round 3
// DKG: We execute Step 4 of the protocol: after having received all commitments, each party broadcasts his proof.
//
// Init: Each party transmits messages for the zero sharing and multiplication protocols (one for each party)
// and broadcasts a message for key derivation (the same for every party).

// Phase 4 = Steps 5 and 6
// Input (DKG): Proofs and commitments received from communication + parameters, party index, session id, poly_point.
// Input (Init): Parameters, values kept and transmited in previous phases.
// Output: Instance of Party ready to sign.
pub fn dkg_phase4(
    data: &SessionData,
    poly_point: &Scalar,
    proofs_commitments: &Vec<ProofCommitment>,
    zero_kept: &HashMap<usize, KeepInitZeroSharePhase3to4>,
    zero_received_phase2: &Vec<TransmitInitZeroSharePhase2to4>,
    zero_received_phase3: &Vec<TransmitInitZeroSharePhase3to4>,
    mul_kept: &HashMap<usize, KeepInitMulPhase3to4>,
    mul_received: &Vec<TransmitInitMulPhase3to4>,
    bip_received_phase2: &HashMap<usize, BroadcastDerivationPhase2to4>,
    bip_received_phase3: &HashMap<usize, BroadcastDerivationPhase3to4>,
) -> Result<Party, Abort> {
    // DKG
    let pk = dkg_step5(
        &data.parameters,
        data.party_index,
        &data.session_id,
        proofs_commitments,
    )?;

    // The public key cannot be the point at infinity.
    // This is pratically impossible, but easy to check.
    // We also verify that pk is not the generator point, because
    // otherwise it would be trivial to find the "total" secret key.
    if pk == AffinePoint::IDENTITY || pk == AffinePoint::GENERATOR {
        return Err(Abort::new(
            data.party_index,
            "Initialization failed because the resulting public key was trivial! (Very improbable)",
        ));
    }

    // Our key share (that is, poly_point), should not be trivial.
    // Note that the other parties can deduce the triviality from
    // the corresponding proof in proofs_commitments.
    if *poly_point == Scalar::ZERO || *poly_point == Scalar::ONE {
        return Err(Abort::new(
            data.party_index,
            "Initialization failed because the resulting key share was trivial! (Very improbable)",
        ));
    }

    // Initialization - Zero sharings.
    let mut seeds: Vec<zero_sharings::SeedPair> =
        Vec::with_capacity(data.parameters.share_count - 1);
    for (target_party, message_kept) in zero_kept {
        for message_received_2 in zero_received_phase2 {
            for message_received_3 in zero_received_phase3 {
                let my_index = message_received_2.parties.receiver;
                let their_index = message_received_2.parties.sender;

                // Confirm that the message is for us.
                if my_index != data.party_index {
                    return Err(Abort::new(
                        data.party_index,
                        "Received a message not meant for me!",
                    ));
                }

                // We first check if the messages relate to the same party.
                if *target_party != their_index || message_received_3.parties.sender != their_index
                {
                    continue;
                }

                // We verify the commitment.
                let verification = ZeroShare::verify_seed(
                    &message_received_3.seed,
                    &message_received_2.commitment,
                    &message_received_3.salt,
                );
                if !verification {
                    return Err(Abort::new(data.party_index, &format!("Initialization for zero sharings protocol failed because Party {} cheated when sending the seed!", their_index)));
                }

                // We form the final seed pairs.
                seeds.push(ZeroShare::generate_seed_pair(
                    my_index,
                    their_index,
                    &message_kept.seed,
                    &message_received_3.seed,
                ));
            }
        }
    }

    // This finishes the initialization.
    let zero_share = ZeroShare::initialize(seeds);

    // Initialization - Two-party multiplication.
    let mut mul_receivers: HashMap<usize, MulReceiver> =
        HashMap::with_capacity(data.parameters.share_count - 1);
    let mut mul_senders: HashMap<usize, MulSender> =
        HashMap::with_capacity(data.parameters.share_count - 1);
    for (target_party, message_kept) in mul_kept {
        for message_received in mul_received {
            let my_index = message_received.parties.receiver;
            let their_index = message_received.parties.sender;

            // Confirm that the message is for us.
            if my_index != data.party_index {
                return Err(Abort::new(
                    data.party_index,
                    "Received a message not meant for me!",
                ));
            }

            // We first check if the messages relate to the same party.
            if their_index != *target_party {
                continue;
            }

            // RECEIVER
            // We are the receiver and target_party = sender.

            // We retrieve the id used for multiplication. Note that the first party
            // is the receiver and the second, the sender.
            let mul_sid_receiver = [
                &(my_index as u8).to_be_bytes(),
                &(their_index as u8).to_be_bytes(),
                &data.session_id[..],
            ]
            .concat();

            let receiver_result = MulReceiver::init_phase2(
                &message_kept.ot_sender,
                &mul_sid_receiver,
                &message_received.seed,
                &message_received.enc_proofs,
                &message_kept.nonce,
            );

            let mul_receiver: MulReceiver;
            match receiver_result {
                Ok(r) => {
                    mul_receiver = r;
                }
                Err(error) => {
                    return Err(Abort::new(data.party_index, &format!("Initialization for multiplication protocol failed because of Party {}: {:?}", their_index, error.description)));
                }
            }

            // SENDER
            // We are the sender and target_party = receiver.

            // We retrieve the id used for multiplication. Note that the first party
            // is the receiver and the second, the sender.
            let mul_sid_sender = [
                &(their_index as u8).to_be_bytes(),
                &(my_index as u8).to_be_bytes(),
                &data.session_id[..],
            ]
            .concat();

            let sender_result = MulSender::init_phase2(
                &message_kept.ot_receiver,
                &mul_sid_sender,
                message_kept.correlation.clone(),
                &message_kept.vec_r,
                &message_received.dlog_proof,
                &message_received.nonce,
            );

            let mul_sender: MulSender;
            match sender_result {
                Ok(s) => {
                    mul_sender = s;
                }
                Err(error) => {
                    return Err(Abort::new(data.party_index, &format!("Initialization for multiplication protocol failed because of Party {}: {:?}", their_index, error.description)));
                }
            }

            // We finish the initialization.
            mul_receivers.insert(their_index, mul_receiver);
            mul_senders.insert(their_index, mul_sender.clone());
        }
    }

    // Initialization - BIP-32.
    // We check the commitments and create the final chain code.
    // It will be given by the XOR of the auxiliary chain codes.
    let mut chain_code: ChainCode = [0; 32];
    for i in 1..=data.parameters.share_count {
        // We take the messages in the correct order (that's why the HashMap).
        let verification = commits::verify_commitment(
            &bip_received_phase3.get(&i).unwrap().aux_chain_code,
            &bip_received_phase2.get(&i).unwrap().cc_commitment,
            &bip_received_phase3.get(&i).unwrap().cc_salt,
        );
        if !verification {
            return Err(Abort::new(data.party_index, &format!("Initialization for key derivation failed because Party {} cheated when sending the auxiliary chain code!", i+1)));
        }

        // We XOR this auxiliary chain code to the final result.
        let current_aux_chain_code = bip_received_phase3.get(&i).unwrap().aux_chain_code;
        for j in 0..32 {
            chain_code[j] ^= current_aux_chain_code[j];
        }
    }

    // We can finally finish key generation!

    let derivation_data = DerivationData {
        depth: 0,
        child_number: 0, // These three values are initialized as zero for the master node.
        parent_fingerprint: [0; 4],
        poly_point: *poly_point,
        pk,
        chain_code,
    };

    let eth_address = compute_eth_address(&pk); // We compute the Ethereum address.

    let party = Party {
        parameters: data.parameters.clone(),
        party_index: data.party_index,
        session_id: data.session_id.clone(),

        poly_point: *poly_point,
        pk,

        zero_share,

        mul_senders,
        mul_receivers,

        derivation_data,

        eth_address,
    };

    Ok(party)
}

// For convenience, we are going to include the Ethereum address.
pub fn compute_eth_address(pk: &AffinePoint) -> String {
    // Here, we will compute the address using the compressed form of pk.
    let x_as_bytes = pk.x().as_slice().to_vec();
    let prefix = if pk.y_is_odd().into() {
        vec![3]
    } else {
        vec![2]
    };

    let compressed_pk = [prefix, x_as_bytes].concat();

    // We compute the keccak256 of the point.
    let mut hasher = Keccak256::new();
    hasher.update(compressed_pk);

    // We save the last 20 bytes represented in hexadecimal.
    let address_bytes = &hasher.finalize()[12..];
    let mut address = hex::encode(address_bytes);

    // We insert 0x in the beginning.
    address.insert(0, 'x');
    address.insert(0, '0');

    address
}

#[cfg(test)]
mod tests {

    use super::*;
    use k256::elliptic_curve::ops::Reduce;
    use k256::U256;
    use rand::Rng;

    // DISTRIBUTED KEY GENERATION (without initializations)

    // We are not testing in the moment the initializations for zero shares
    // and multiplication here because they are only used during signing.

    // The initializations are checked after these tests (see below).

    #[test]
    // 2-of-2 scenario.
    fn test_dkg_t2_n2() {
        let parameters = Parameters {
            threshold: 2,
            share_count: 2,
        };
        let session_id = rand::thread_rng().gen::<[u8; 32]>();

        // Phase 1 (Steps 1 and 2)
        let p1_phase1 = dkg_step2(&parameters, dkg_step1(&parameters)); //p1 = Party 1
        let p2_phase1 = dkg_step2(&parameters, dkg_step1(&parameters)); //p2 = Party 2

        assert_eq!(p1_phase1.len(), 2);
        assert_eq!(p2_phase1.len(), 2);

        // Communication round 1
        let p1_poly_fragments = vec![p1_phase1[0], p2_phase1[0]];
        let p2_poly_fragments = vec![p1_phase1[1], p2_phase1[1]];

        // Phase 2 (Step 3)
        let p1_phase2 = dkg_step3(1, &session_id, &p1_poly_fragments);
        let p2_phase2 = dkg_step3(2, &session_id, &p2_poly_fragments);

        let (_, p1_proof_commitment) = p1_phase2;
        let (_, p2_proof_commitment) = p2_phase2;

        // Communication rounds 2 and 3
        // For tests, they can be done simultaneously
        let proofs_commitments = vec![p1_proof_commitment, p2_proof_commitment];

        // Phase 4 (Step 5)
        let p1_result = dkg_step5(&parameters, 1, &session_id, &proofs_commitments);
        let p2_result = dkg_step5(&parameters, 2, &session_id, &proofs_commitments);

        assert!(p1_result.is_ok());
        assert!(p2_result.is_ok());
    }

    #[test]
    // General t-of-n scenario
    fn test_dkg_random() {
        let threshold = rand::thread_rng().gen_range(2..=5); // You can change the ranges here.
        let offset = rand::thread_rng().gen_range(0..=5);

        let parameters = Parameters {
            threshold,
            share_count: threshold + offset,
        }; // You can fix the parameters if you prefer.
        let session_id = rand::thread_rng().gen::<[u8; 32]>();

        // Phase 1 (Steps 1 and 2)
        // Matrix of polynomial points
        let mut phase1: Vec<Vec<Scalar>> = Vec::with_capacity(parameters.share_count);
        for _ in 0..parameters.share_count {
            let party_phase1 = dkg_step2(&parameters, dkg_step1(&parameters));
            assert_eq!(party_phase1.len(), parameters.share_count);
            phase1.push(party_phase1);
        }

        // Communication round 1
        // We transpose the matrix
        let mut poly_fragments =
            vec![Vec::<Scalar>::with_capacity(parameters.share_count); parameters.share_count];
        for row_i in phase1 {
            for j in 0..parameters.share_count {
                poly_fragments[j].push(row_i[j]);
            }
        }

        // Phase 2 (Step 3) + Communication rounds 2 and 3
        let mut proofs_commitments: Vec<ProofCommitment> =
            Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {
            let party_i_phase2 = dkg_step3(i + 1, &session_id, &poly_fragments[i]);
            let (_, party_i_proof_commitment) = party_i_phase2;
            proofs_commitments.push(party_i_proof_commitment);
        }

        // Phase 4 (Step 5)
        let mut result_parties: Vec<Result<AffinePoint, Abort>> =
            Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {
            result_parties.push(dkg_step5(
                &parameters,
                i + 1,
                &session_id,
                &proofs_commitments,
            ));
        }

        for result in result_parties {
            assert!(result.is_ok());
        }
    }

    #[test]
    // We remove the randomness from Phase 1. This allows us to compute the public key.
    fn test1_dkg_t2_n2_fixed_polynomials() {
        let parameters = Parameters {
            threshold: 2,
            share_count: 2,
        };
        let session_id = rand::thread_rng().gen::<[u8; 32]>();

        // We will define the fragments directly
        let p1_poly_fragments = vec![Scalar::from(1u32), Scalar::from(3u32)];
        let p2_poly_fragments = vec![Scalar::from(2u32), Scalar::from(4u32)];

        // In this case, the secret polynomial p is of degree 1 and satisfies p(1) = 1+3 = 4 and p(2) = 2+4 = 6
        // In particular, we must have p(0) = 2, which is the "hypothetical" secret key.
        // For this reason, we should expect the public key to be 2 * generator.

        // Phase 2 (Step 3)
        let p1_phase2 = dkg_step3(1, &session_id, &p1_poly_fragments);
        let p2_phase2 = dkg_step3(2, &session_id, &p2_poly_fragments);

        let (_, p1_proof_commitment) = p1_phase2;
        let (_, p2_proof_commitment) = p2_phase2;

        // Communication rounds 2 and 3
        // For tests, they can be done simultaneously
        let proofs_commitments = vec![p1_proof_commitment, p2_proof_commitment];

        // Phase 4 (Step 5)
        let p1_result = dkg_step5(&parameters, 1, &session_id, &proofs_commitments);
        let p2_result = dkg_step5(&parameters, 2, &session_id, &proofs_commitments);

        assert!(p1_result.is_ok());
        assert!(p2_result.is_ok());

        let p1_pk = p1_result.unwrap();
        let p2_pk = p2_result.unwrap();

        // Verifying the public key
        let expected_pk = (AffinePoint::GENERATOR * Scalar::from(2u32)).to_affine();
        assert_eq!(p1_pk, expected_pk);
        assert_eq!(p2_pk, expected_pk);
    }

    #[test]
    fn test2_dkg_t2_n2_fixed_polynomials() {
        let parameters = Parameters {
            threshold: 2,
            share_count: 2,
        };
        let session_id = rand::thread_rng().gen::<[u8; 32]>();

        // We will define the fragments directly
        let p1_poly_fragments = vec![Scalar::from(12u32), Scalar::from(2u32)];
        let p2_poly_fragments = vec![Scalar::from(2u32), Scalar::from(3u32)];

        // In this case, the secret polynomial p is of degree 1 and satisfies p(1) = 12+2 = 14 and p(2) = 2+3 = 5
        // In particular, we must have p(0) = 23, which is the "hypothetical" secret key.
        // For this reason, we should expect the public key to be 23 * generator.

        // Phase 2 (Step 3)
        let p1_phase2 = dkg_step3(1, &session_id, &p1_poly_fragments);
        let p2_phase2 = dkg_step3(2, &session_id, &p2_poly_fragments);

        let (_, p1_proof_commitment) = p1_phase2;
        let (_, p2_proof_commitment) = p2_phase2;

        // Communication rounds 2 and 3
        // For tests, they can be done simultaneously
        let proofs_commitments = vec![p1_proof_commitment, p2_proof_commitment];

        // Phase 4 (Step 5)
        let p1_result = dkg_step5(&parameters, 1, &session_id, &proofs_commitments);
        let p2_result = dkg_step5(&parameters, 2, &session_id, &proofs_commitments);

        assert!(p1_result.is_ok());
        assert!(p2_result.is_ok());

        let p1_pk = p1_result.unwrap();
        let p2_pk = p2_result.unwrap();

        // Verifying the public key
        let expected_pk = (AffinePoint::GENERATOR * Scalar::from(23u32)).to_affine();
        assert_eq!(p1_pk, expected_pk);
        assert_eq!(p2_pk, expected_pk);
    }

    #[test]
    fn test_dkg_t3_n5_fixed_polynomials() {
        let parameters = Parameters {
            threshold: 3,
            share_count: 5,
        };
        let session_id = rand::thread_rng().gen::<[u8; 32]>();

        // We will define the fragments directly
        let poly_fragments = vec![
            vec![
                Scalar::from(5u32),
                Scalar::from(1u32),
                Scalar::from(5u32).negate(),
                Scalar::from(2u32).negate(),
                Scalar::from(3u32).negate(),
            ],
            vec![
                Scalar::from(9u32),
                Scalar::from(3u32),
                Scalar::from(4u32).negate(),
                Scalar::from(5u32).negate(),
                Scalar::from(7u32).negate(),
            ],
            vec![
                Scalar::from(15u32),
                Scalar::from(7u32),
                Scalar::from(1u32).negate(),
                Scalar::from(10u32).negate(),
                Scalar::from(13u32).negate(),
            ],
            vec![
                Scalar::from(23u32),
                Scalar::from(13u32),
                Scalar::from(4u32),
                Scalar::from(17u32).negate(),
                Scalar::from(21u32).negate(),
            ],
            vec![
                Scalar::from(33u32),
                Scalar::from(21u32),
                Scalar::from(11u32),
                Scalar::from(26u32).negate(),
                Scalar::from(31u32).negate(),
            ],
        ];

        // In this case, the secret polynomial p is of degree 2 and satisfies:
        // p(1) = -4, p(2) = -4, p(3) = -2, p(4) = 2, p(5) = 8.
        // Hence we must have p(x) = x^2 - 3x - 2.
        // In particular, we must have p(0) = -2, which is the "hypothetical" secret key.
        // For this reason, we should expect the public key to be (-2) * generator.

        // Phase 2 (Step 3) + Communication rounds 2 and 3
        let mut proofs_commitments: Vec<ProofCommitment> =
            Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {
            let party_i_phase2 = dkg_step3(i + 1, &session_id, &poly_fragments[i]);
            let (_, party_i_proof_commitment) = party_i_phase2;
            proofs_commitments.push(party_i_proof_commitment);
        }

        // Phase 4 (Step 5)
        let mut results: Vec<Result<AffinePoint, Abort>> =
            Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {
            results.push(dkg_step5(
                &parameters,
                i + 1,
                &session_id,
                &proofs_commitments,
            ));
        }

        let mut public_keys: Vec<AffinePoint> = Vec::with_capacity(parameters.share_count);
        for result in results {
            match result {
                Ok(pk) => {
                    public_keys.push(pk);
                }
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                }
            }
        }

        // Verifying the public key
        let expected_pk = (AffinePoint::GENERATOR * Scalar::from(2u32).negate()).to_affine();
        for pk in public_keys {
            assert_eq!(pk, expected_pk);
        }
    }

    // DISTRIBUTED KEY GENERATION (with initializations)

    // We now test if the initialization procedures don't abort.
    // The verification that they really work is done in signing.rs.

    // Disclaimer: this implementation is not the most efficient,
    // we are only testing if everything works! Note as well that
    // parties are being simulated one after the other, but they
    // should actually execute the protocol simultaneously.

    #[test]
    fn test_dkg_initialization() {
        let threshold = rand::thread_rng().gen_range(2..=5); // You can change the ranges here.
        let offset = rand::thread_rng().gen_range(0..=5);

        let parameters = Parameters {
            threshold,
            share_count: threshold + offset,
        }; // You can fix the parameters if you prefer.
        let session_id = rand::thread_rng().gen::<[u8; 32]>();

        // Each party prepares their data for this DKG.
        let mut all_data: Vec<SessionData> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {
            all_data.push(SessionData {
                parameters: parameters.clone(),
                party_index: i + 1,
                session_id: session_id.to_vec(),
            });
        }

        // Phase 1
        let mut dkg_1: Vec<Vec<Scalar>> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {
            let out1 = dkg_phase1(&all_data[i]);

            dkg_1.push(out1);
        }

        // Communication round 1 - Each party receives a fragment from each counterparty.
        // They also produce a fragment for themselves.
        let mut poly_fragments =
            vec![Vec::<Scalar>::with_capacity(parameters.share_count); parameters.share_count];
        for row_i in dkg_1 {
            for j in 0..parameters.share_count {
                poly_fragments[j].push(row_i[j]);
            }
        }

        // Phase 2
        let mut poly_points: Vec<Scalar> = Vec::with_capacity(parameters.share_count);
        let mut proofs_commitments: Vec<ProofCommitment> =
            Vec::with_capacity(parameters.share_count);
        let mut zero_kept_2to3: Vec<HashMap<usize, KeepInitZeroSharePhase2to3>> =
            Vec::with_capacity(parameters.share_count);
        let mut zero_transmit_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> =
            Vec::with_capacity(parameters.share_count);
        let mut bip_kept_2to3: Vec<UniqueKeepDerivationPhase2to3> =
            Vec::with_capacity(parameters.share_count);
        let mut bip_broadcast_2to4: HashMap<usize, BroadcastDerivationPhase2to4> =
            HashMap::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {
            let (out1, out2, out3, out4, out5, out6) = dkg_phase2(&all_data[i], &poly_fragments[i]);

            poly_points.push(out1);
            proofs_commitments.push(out2);
            zero_kept_2to3.push(out3);
            zero_transmit_2to4.push(out4);
            bip_kept_2to3.push(out5);
            bip_broadcast_2to4.insert(i + 1, out6); // This variable should be grouped into a HashMap.
        }

        // Communication round 2
        let mut zero_received_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> =
            Vec::with_capacity(parameters.share_count);
        for i in 1..=parameters.share_count {
            // We don't need to transmit the commitments because proofs_commitments is already what we need.
            // In practice, this should be done here.

            let mut new_row: Vec<TransmitInitZeroSharePhase2to4> =
                Vec::with_capacity(parameters.share_count - 1);
            for party in &zero_transmit_2to4 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i {
                        new_row.push(message.clone());
                    }
                }
            }
            zero_received_2to4.push(new_row);
        }

        // bip_transmit_2to4 is already in the format we need.
        // In practice, the messages received should be grouped into a HashMap.

        // Phase 3
        let mut zero_kept_3to4: Vec<HashMap<usize, KeepInitZeroSharePhase3to4>> =
            Vec::with_capacity(parameters.share_count);
        let mut zero_transmit_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> =
            Vec::with_capacity(parameters.share_count);
        let mut mul_kept_3to4: Vec<HashMap<usize, KeepInitMulPhase3to4>> =
            Vec::with_capacity(parameters.share_count);
        let mut mul_transmit_3to4: Vec<Vec<TransmitInitMulPhase3to4>> =
            Vec::with_capacity(parameters.share_count);
        let mut bip_broadcast_3to4: HashMap<usize, BroadcastDerivationPhase3to4> =
            HashMap::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {
            let (out1, out2, out3, out4, out5) =
                dkg_phase3(&all_data[i], &zero_kept_2to3[i], &bip_kept_2to3[i]);

            zero_kept_3to4.push(out1);
            zero_transmit_3to4.push(out2);
            mul_kept_3to4.push(out3);
            mul_transmit_3to4.push(out4);
            bip_broadcast_3to4.insert(i + 1, out5); // This variable should be grouped into a HashMap.
        }

        // Communication round 3
        let mut zero_received_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> =
            Vec::with_capacity(parameters.share_count);
        let mut mul_received_3to4: Vec<Vec<TransmitInitMulPhase3to4>> =
            Vec::with_capacity(parameters.share_count);
        for i in 1..=parameters.share_count {
            // We don't need to transmit the proofs because proofs_commitments is already what we need.
            // In practice, this should be done here.

            let mut new_row: Vec<TransmitInitZeroSharePhase3to4> =
                Vec::with_capacity(parameters.share_count - 1);
            for party in &zero_transmit_3to4 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i {
                        new_row.push(message.clone());
                    }
                }
            }
            zero_received_3to4.push(new_row);

            let mut new_row: Vec<TransmitInitMulPhase3to4> =
                Vec::with_capacity(parameters.share_count - 1);
            for party in &mul_transmit_3to4 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i {
                        new_row.push(message.clone());
                    }
                }
            }
            mul_received_3to4.push(new_row);
        }

        // bip_transmit_3to4 is already in the format we need.
        // In practice, the messages received should be grouped into a HashMap.

        // Phase 4
        let mut parties: Vec<Party> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {
            let result = dkg_phase4(
                &all_data[i],
                &poly_points[i],
                &proofs_commitments,
                &zero_kept_3to4[i],
                &zero_received_2to4[i],
                &zero_received_3to4[i],
                &mul_kept_3to4[i],
                &mul_received_3to4[i],
                &bip_broadcast_2to4,
                &bip_broadcast_3to4,
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                }
                Ok(party) => {
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
    }

    #[test]
    fn test_compute_eth_address() {
        // You should test different values using, for example,
        // https://paulmillr.com/noble/ and https://emn178.github.io/online-tools/keccak_256.html.
        let sk = Scalar::reduce(U256::from_be_hex(
            "cc545f6edbac6c62def9205033629e553acb1fceb95c171cf389c636ce4613a2",
        ));
        let pk = (AffinePoint::GENERATOR * sk).to_affine();

        let address = compute_eth_address(&pk);
        assert_eq!(
            address,
            "0x8be92babaa139ecf60145f822520b68cebb44711".to_string()
        );
    }
}
