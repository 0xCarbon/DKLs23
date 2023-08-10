/// This file implements Protocol 9.1 in https://eprint.iacr.org/2023/602.pdf,
/// as instructed in DKLs23 (https://eprint.iacr.org/2023/765.pdf). It is
/// the distributed key generation which setups the main signing protocol.
/// 
/// During the protocol, we also initialize the functionalities that will
/// be used during signing. Their implementations can be found in the files
/// zero_sharings.rs and multiplication.rs.

use std::collections::HashMap;

use curv::elliptic::curves::{Secp256k1, Scalar, Point};
use curv::cryptographic_primitives::secret_sharing::Polynomial;

use crate::protocols::{Abort, Parameters, Party, PartiesMessage};

use crate::utilities::hashes::HashOutput;
use crate::utilities::proofs::DLogProof;
use crate::utilities::zero_sharings::{self, ZeroShare};
use crate::utilities::ot::ot_base;
use crate::utilities::multiplication::{MulSender, MulReceiver};

// This struct is used during key generation
#[derive(Debug, Clone)]
pub struct ProofCommitment {
    index: usize,
    proof: DLogProof,
    commitment: HashOutput,
}

////////// STRUCTS FOR MESSAGES TO TRANSMIT IN COMMUNICATION ROUNDS.

// Initializing zero sharing protocol. 
#[derive(Clone)]
pub struct TransmitInitZeroSharePhase1to3 {
    pub parties: PartiesMessage,
    commitment: HashOutput,
}

#[derive(Clone)]
pub struct TransmitInitZeroSharePhase2to3 {
    pub parties: PartiesMessage,
    seed: zero_sharings::Seed,
    salt: Vec<u8>,
}

// Initializating two-party multiplication protocol.
#[derive(Clone)]
pub struct TransmitInitMulPhase1to2 {
    pub parties: PartiesMessage,
    proof: DLogProof,
    nonce: Scalar<Secp256k1>,
}

#[derive(Clone)]
pub struct TransmitInitMulPhase2to3 {
    pub parties: PartiesMessage,
    encoded: Vec<Point<Secp256k1>>,
}

#[derive(Clone)]
pub struct TransmitInitMulPhase3to4 {
    pub parties: PartiesMessage,
    challenge: Vec<HashOutput>,
}

#[derive(Clone)]
pub struct TransmitInitMulPhase4to5 {
    pub parties: PartiesMessage,
    response: Vec<HashOutput>,

}

#[derive(Clone)]
pub struct TransmitInitMulPhase5to6 {
    pub parties: PartiesMessage,
    sender_hashes: Vec<ot_base::SenderHashData>,
}

////////// STRUCTS FOR MESSAGES TO KEEP BETWEEN PHASES.

// Initializing zero sharing protocol. 
#[derive(Clone)]
pub struct KeepInitZeroSharePhase1to2 {
    seed: zero_sharings::Seed,
    salt: Vec<u8>,
}

#[derive(Clone)]
pub struct KeepInitZeroSharePhase2to3 {
    seed: zero_sharings::Seed,
}

#[derive(Clone)]
pub struct KeepInitZeroSharePhase3to6 {
    zero_share: ZeroShare,
}

// Initializating two-party multiplication protocol.
#[derive(Clone)]
pub struct KeepInitMulPhase1to3 {
    base_sender: ot_base::Sender,
    nonce: Scalar<Secp256k1>,
}

#[derive(Clone)]
pub struct KeepInitMulPhase2to4 {
    base_receiver: ot_base::Receiver,
    receiver_output: Vec<ot_base::ReceiverOutput>,
    mul_sender: MulSender,
}

#[derive(Clone)]
pub struct KeepInitMulPhase3to5 {
    base_sender: ot_base::Sender,
    sender_hashes: Vec<ot_base::SenderHashData>,
    double_hash: Vec<HashOutput>,
    mul_receiver: MulReceiver,
}

#[derive(Clone)]
pub struct KeepInitMulPhase4to6 {
    base_receiver: ot_base::Receiver,
    receiver_output: Vec<ot_base::ReceiverOutput>,
    receiver_hashes: Vec<ot_base::ReceiverHashData>,
    mul_sender: MulSender,
}

#[derive(Clone)]
pub struct KeepInitMulPhase5to6 {
    mul_receiver: MulReceiver,
}

///////////////////////////////////////////////////////////////////////////////

// DISTRIBUTED KEY GENERATION (DKG)

// STEPS
// We implement each step of the protocol.

// Step 1 - Generate random polynomial of degree t-1.
pub fn dkg_step1(parameters: &Parameters) -> Polynomial<Secp256k1> {
    Polynomial::sample_exact((parameters.threshold - 1) as u16)
}

// Step 2 - Evaluate the polynomial from the previous step at every point.
pub fn dkg_step2(parameters: &Parameters, polynomial: Polynomial<Secp256k1>) -> Vec<Scalar<Secp256k1>> {
    let mut points: Vec<Scalar<Secp256k1>> = Vec::with_capacity(parameters.share_count);

    for j in 1..=parameters.share_count {
        points.push(polynomial.evaluate(&Scalar::<Secp256k1>::from(j as u16)));
    }
        
    points
}

// Step 3 - Compute poly_point (p(i) in the paper) and the corresponding "public key" (P(i) in the paper).
// It also commits to a zero-knowledge proof that p(i) is the discrete logarithm of P(i).
// The session id is used for the proof.
pub fn dkg_step3(party_index: usize, session_id: &[u8], poly_fragments: &Vec<Scalar<Secp256k1>>) -> (Scalar<Secp256k1>, ProofCommitment) {
    let poly_point: Scalar<Secp256k1> = poly_fragments.iter().sum();

    let (proof, commitment) = DLogProof::prove_commit(&poly_point, session_id);
    let proof_commitment = ProofCommitment { index: party_index, proof, commitment };

    (poly_point, proof_commitment)
}

// Step 4 is a communication round (see the description below).

// Step 5 - Each party validates the other proofs. They also recover the "public keys fragements" from the other parties.
// Finally, a consistency check is done. In the process, the publick key is computed (Step 6).
pub fn dkg_step5(parameters: &Parameters, party_index: usize, session_id: &[u8], proofs_commitments: &Vec<ProofCommitment>) -> Result<Point<Secp256k1>,Abort> {
        
    let mut commited_points: Vec<Point<Secp256k1>> = Vec::with_capacity(parameters.share_count); //The "public key fragments"

    // Verify the proofs and gather the commited points.        
    for party_j in proofs_commitments {
        if party_j.index != party_index {
            let verification = DLogProof::decommit_verify(&party_j.proof, &party_j.commitment, session_id);
            if !verification {
                return Err(Abort::new(party_index, &format!("Proof from Party {} failed!", party_j.index)));
            }
        }
        commited_points.push(party_j.proof.point.clone());
    }

    // Initializes what will be the public key.
    let mut pk = Point::<Secp256k1>::zero();

    // Verify that all points come from the same polyonimal. To do so, for each contiguous set of parties,
    // perform Shamir reconstruction in the exponent and check if the results agree.
    // The common value calculated is the public key.
    for i in 1..=(parameters.share_count - parameters.threshold + 1) {
        let mut current_pk = Point::<Secp256k1>::zero();
        for j in i..=(i + parameters.threshold - 1) {

            // We find the Lagrange coefficient l(j) corresponding to j (and the contiguous set of parties).
            // It is such that the sum of l(j) * p(j) over all j is p(0), where p is the polyonimal from Step 3.
            let mut lj_numerator = Scalar::<Secp256k1>::from(1);
            let mut lj_denominator = Scalar::<Secp256k1>::from(1);
            for k in i..=(i + parameters.threshold - 1) {
                if k != j {
                    lj_numerator = lj_numerator * Scalar::<Secp256k1>::from(k as u16);
                    lj_denominator = lj_denominator * (Scalar::<Secp256k1>::from(k as u16) - Scalar::<Secp256k1>::from(j as u16));
                }
            }
            let lj = lj_numerator * (lj_denominator.invert().unwrap());
                
            let lj_times_point = lj * &commited_points[j-1]; // j-1 because index starts at 0
            current_pk = current_pk + lj_times_point;
        }
        // The first value is taken as the public key. It should coincide with the next values.
        if i == 1 {
            pk = current_pk;
        } else if pk != current_pk {
            return Err(Abort::new(party_index, &format!("Verification for public key reconstruction failed in iteration {}", i)));
        }
    }
    Ok(pk)
}

// Step 6 was done during the previous step.

// PHASES
// We group the steps in phases. A phase consists of all steps that can be executed in order without the need of communication.
// Phases should be intercalated with communication rounds: broadcasts and/or private messages containg the session id.

// We also include here the initialization procedures of Functionalities 3.4 and 3.5 of DKLs23 (https://eprint.iacr.org/2023/765.pdf).
// The first one comes from the file zero_sharings.rs and needs two communication rounds.
// The second one comes from the file multiplication.rs and needs five communication rounds.

// Phase 1 = Steps 1 and 2
// Input (DKG): Parameters for the key generation.
// Input (Init): Party index and session id.
// Output (DKG): Evaluation of a random polynomial at every party index.
// Output (Init): Some data to keep and to transmit.
pub fn dkg_phase1(parameters: &Parameters, party_index: usize, session_id: &[u8]) -> (Vec<Scalar<Secp256k1>>, HashMap<usize,KeepInitZeroSharePhase1to2>, Vec<TransmitInitZeroSharePhase1to3>, HashMap<usize,KeepInitMulPhase1to3>, Vec<TransmitInitMulPhase1to2>) {
    
    // DKG
    let secret_polynomial = dkg_step1(parameters);
    let evaluations = dkg_step2(parameters, secret_polynomial);

    // Initialization - Zero sharings.

    // We will use HashMap to keep messages: the key indicates the party to whom the message refers.
    let mut zero_keep: HashMap<usize,KeepInitZeroSharePhase1to2> = HashMap::with_capacity(parameters.share_count - 1);
    let mut zero_transmit: Vec<TransmitInitZeroSharePhase1to3> = Vec::with_capacity(parameters.share_count - 1);
    for i in 0..parameters.share_count {
        if i == party_index { continue; }

        // Generate initial seeds.
        let (seed, commitment, salt) = ZeroShare::generate_seed_with_commitment();

        // We first send the commitments. We keep the rest to send later.
        let keep = KeepInitZeroSharePhase1to2 {
            seed,
            salt,
        };
        let transmit = TransmitInitZeroSharePhase1to3 {
            parties: PartiesMessage { sender: party_index, receiver: i },
            commitment,
        };

        zero_keep.insert(i, keep);
        zero_transmit.push(transmit);
    }

    // Initialization - Two-party multiplication.
    // Each party prepares initialization as a receiver.
    let mut mul_keep: HashMap<usize,KeepInitMulPhase1to3> = HashMap::with_capacity(parameters.share_count - 1);
    let mut mul_transmit: Vec<TransmitInitMulPhase1to2> = Vec::with_capacity(parameters.share_count - 1);
    for i in 0..parameters.share_count {
        if i == party_index { continue; }

        // We first compute a new session id.
        // As in Protocol 3.6 of DKLs23, we include the indexes from the parties.
        let mul_sid = [&party_index.to_be_bytes(), &i.to_be_bytes(), session_id].concat();

        let (base_sender, proof, nonce) = MulReceiver::init_phase1(&mul_sid);

        let keep = KeepInitMulPhase1to3 {
            base_sender,
            nonce: nonce.clone(),
        };
        let transmit = TransmitInitMulPhase1to2 {
            parties: PartiesMessage { sender: party_index, receiver: i },
            proof,
            nonce,
        };

        mul_keep.insert(i, keep);
        mul_transmit.push(transmit);
    }

    (evaluations, zero_keep, zero_transmit, mul_keep, mul_transmit)
}

// Communication round 1
// DKG: Party i keeps the i-th point and sends the j-th point to Party j for j != i.
// At the end, Party i should have received all fragements indexed by i.
// They should add up to p(i), where p is a polynomial not depending on i.
//
// Init: Each party transmits messages for zero sharing and multiplication protocols.

// Phase 2 = Step 3
// Input (DKG): Fragments received from communication and session id.
// Input (Init): Parameters, values kept and transmited in Phase 1.
// Output (DKG): p(i) and a proof of discrete logarithm with commitment.
// Output (Init): Some data to keep and to transmit.
pub fn dkg_phase2(parameters: &Parameters, party_index: usize, session_id: &[u8], poly_fragments: &Vec<Scalar<Secp256k1>>, zero_kept: &HashMap<usize,KeepInitZeroSharePhase1to2>, mul_received: &Vec<TransmitInitMulPhase1to2>) -> Result<(Scalar<Secp256k1>, ProofCommitment, HashMap<usize,KeepInitZeroSharePhase2to3>, Vec<TransmitInitZeroSharePhase2to3>, HashMap<usize,KeepInitMulPhase2to4>, Vec<TransmitInitMulPhase2to3>),Abort> {
    
    // DKG
    let (poly_point, proof_commitment) = dkg_step3(party_index, session_id, poly_fragments);

    // Initialization - Zero sharings.
    let mut zero_keep: HashMap<usize,KeepInitZeroSharePhase2to3> = HashMap::with_capacity(parameters.share_count - 1);
    let mut zero_transmit: Vec<TransmitInitZeroSharePhase2to3> = Vec::with_capacity(parameters.share_count - 1);
    for (target_party, message_kept) in zero_kept {
        
        // The messages kept contain the seed and the salt.
        // They have to be transmitted to the target party.
        // We keep the seed with us for the next phase.
        let keep = KeepInitZeroSharePhase2to3 {
            seed: message_kept.seed,
        };
        let transmit = TransmitInitZeroSharePhase2to3 {
            parties: PartiesMessage { sender: party_index, receiver: *target_party },
            seed: message_kept.seed,
            salt: message_kept.salt.clone(),
        };

        zero_keep.insert(*target_party, keep);
        zero_transmit.push(transmit);
    }

    // Initialization - Two-party multiplication.
    // We now act as the sender.
    let mut mul_keep: HashMap<usize,KeepInitMulPhase2to4> = HashMap::with_capacity(parameters.share_count - 1);
    let mut mul_transmit: Vec<TransmitInitMulPhase2to3> = Vec::with_capacity(parameters.share_count - 1);
    for message_received in mul_received {

        let my_index = message_received.parties.receiver;
        let their_index = message_received.parties.sender;

        // We retrieve the id used for multiplication. Note that the first party
        // is the receiver and the second, the sender.
        let mul_sid = [&their_index.to_be_bytes(), &my_index.to_be_bytes(), session_id].concat();

        // Although we are acting as a sender for the multiplication protocol,
        // we act as a receiver for the OT base protocol. Here, we verify if
        // the base OT's sender did everything correctly.
        let try_receiver = MulSender::init_phase1(&mul_sid, &message_received.proof);
        let base_receiver: ot_base::Receiver;
        match try_receiver {
            Ok(r) => { base_receiver = r; },
            Err(error) => { return Err(Abort::new(party_index, &format!("Initialization for multiplication protocol failed because of Party {}: {:?}", their_index, error.description))); },
        }

        // This finishes the initialization for the base OT. We now execute it.
        let (mul_sender, receiver_output, encoded) = MulSender::init_phase2(&base_receiver, &mul_sid, &message_received.nonce);

        let keep = KeepInitMulPhase2to4 {
            base_receiver,
            receiver_output,
            mul_sender,
        };
        let transmit = TransmitInitMulPhase2to3 {
            parties: message_received.parties.reverse(), // We reply to the previous message.
            encoded,
        };

        mul_keep.insert(their_index, keep);
        mul_transmit.push(transmit);
    }

    Ok((poly_point, proof_commitment, zero_keep, zero_transmit, mul_keep, mul_transmit))
}

// Communication round 2
// DKG: Party i broadcasts his commitment to the proof and receive the other commitments.
//
// Init: Each party transmits messages for zero sharing and multiplication protocols.

// Phase 3 = No steps in DKG (just initialization)
// Input (Init): Parameters, session id, values kept and transmited in Phases 1 and 2.
// Output (Init): Instance of ZeroShare initialized and some data to keep and to transmit for multiplication.
pub fn dkg_phase3(parameters: &Parameters, session_id: &[u8], zero_kept: &HashMap<usize,KeepInitZeroSharePhase2to3>, zero_received_phase1: &Vec<TransmitInitZeroSharePhase1to3>, zero_received_phase2: &Vec<TransmitInitZeroSharePhase2to3>, mul_kept: &HashMap<usize,KeepInitMulPhase1to3>, mul_received: &Vec<TransmitInitMulPhase2to3>) -> Result<(KeepInitZeroSharePhase3to6, HashMap<usize,KeepInitMulPhase3to5>, Vec<TransmitInitMulPhase3to4>), Abort> {

    // Initialization - Zero sharings.
    let mut seeds: Vec<zero_sharings::SeedPair> = Vec::with_capacity(parameters.share_count - 1);
    for (target_party, message_kept) in zero_kept {
        for message_received_1 in zero_received_phase1 {
            for message_received_2 in zero_received_phase2 {

                let my_index = message_received_1.parties.receiver;
                let their_index = message_received_1.parties.sender;

                // We first check if the messages relate to the same party.
                if *target_party != their_index || message_received_2.parties.sender != their_index { continue; }

                // We verify the commitment.
                let verification = ZeroShare::verify_seed(&message_received_2.seed, &message_received_1.commitment, &message_received_2.salt);
                if !verification {
                    return Err(Abort::new(my_index, &format!("Initialization for zero sharings protocol failed because Party {} cheated when sending the seed!", message_received_1.parties.sender)));
                }

                // We form the final seed pairs.
                seeds.push(ZeroShare::generate_seed_pair(my_index, their_index, &message_kept.seed, &message_received_2.seed));
            }
        }
    }

    // This finishes the initialization. We keep this data to the last phase.
    let zero_share = ZeroShare::initialize(seeds);
    let zero_keep = KeepInitZeroSharePhase3to6 {
        zero_share,
    };

    // Initialization - Two-party multiplication.
    // We now act as the receiver.
    let mut mul_keep: HashMap<usize,KeepInitMulPhase3to5> = HashMap::with_capacity(parameters.share_count - 1);
    let mut mul_transmit: Vec<TransmitInitMulPhase3to4> = Vec::with_capacity(parameters.share_count - 1);
    for (target_party, message_kept) in mul_kept {
        for message_received in mul_received {

            let my_index = message_received.parties.receiver;
            let their_index = message_received.parties.sender;

            // We first check if the messages relate to the same party.
            if their_index != *target_party { continue; }

            // We retrieve the id used for multiplication. Note that the first party
            // is the receiver and the second, the sender.
            let mul_sid = [&my_index.to_be_bytes(), &their_index.to_be_bytes(), session_id].concat();

            // We continue executing the base OT.
            let (mul_receiver, sender_hashes, double_hash, challenge) = MulReceiver::init_phase2(&message_kept.base_sender, &mul_sid, &message_received.encoded, &message_kept.nonce);

            let keep = KeepInitMulPhase3to5 {
                base_sender: message_kept.base_sender.clone(),
                sender_hashes,
                double_hash,
                mul_receiver,
            };
            let transmit = TransmitInitMulPhase3to4 {
                parties: message_received.parties.reverse(), // We reply to the previous message.
                challenge,
            };

            mul_keep.insert(their_index, keep);
            mul_transmit.push(transmit);
        }
    }

    Ok((zero_keep, mul_keep, mul_transmit))
}

// Communication round 3
// DKG: We execute Step 4 of the protocol: after having received all commitments, each party broadcasts his proof.
//
// Init: Each party transmits messages for the multiplication protocol (we finished initializing the other one).

// Phase 4 = Steps 5 and 6
// Input (DKG): Proofs and commitments received from communication + parameters, party index, session id, poly_point.
// Input (Init): Parameters, values kept and transmited in Phases 2 and 3.
// Output (DKG): The resulting public key (but there may be an abortion during the process).
// Output (Init): Some data to keep and to transmit.
pub fn dkg_phase4(parameters: &Parameters, party_index: usize, session_id: &[u8], proofs_commitments: &Vec<ProofCommitment>, mul_kept: &HashMap<usize,KeepInitMulPhase2to4>, mul_received: &Vec<TransmitInitMulPhase3to4>) -> Result<(Point<Secp256k1>, HashMap<usize,KeepInitMulPhase4to6>, Vec<TransmitInitMulPhase4to5>),Abort> {
    
    // DKG
    let result_step5 = dkg_step5(parameters, party_index, session_id, proofs_commitments);
    let pk: Point<Secp256k1>;

    match result_step5 {
        Ok(point) => { pk = point; },
        Err(abort) => { return Err(abort); }
    }

    // Initialization - Two-party multiplication.
    // We now act as the sender.
    let mut mul_keep: HashMap<usize,KeepInitMulPhase4to6> = HashMap::with_capacity(parameters.share_count - 1);
    let mut mul_transmit: Vec<TransmitInitMulPhase4to5> = Vec::with_capacity(parameters.share_count - 1);
    for (target_party, message_kept) in mul_kept {
        for message_received in mul_received {

            let my_index = message_received.parties.receiver;
            let their_index = message_received.parties.sender;

            // We first check if the messages relate to the same party.
            if their_index != *target_party { continue; }

            // We retrieve the id used for multiplication. Note that the first party
            // is the receiver and the second, the sender.
            let mul_sid = [&their_index.to_be_bytes(), &my_index.to_be_bytes(), session_id].concat();

            // We continue executing the base OT.
            let (receiver_hashes, response) = MulSender::init_phase3(&message_kept.base_receiver, &mul_sid, &message_kept.receiver_output, &message_received.challenge);

            let keep = KeepInitMulPhase4to6 {
                base_receiver: message_kept.base_receiver.clone(),
                receiver_output: message_kept.receiver_output.clone(),
                receiver_hashes,
                mul_sender: message_kept.mul_sender.clone(),
            };
            let transmit = TransmitInitMulPhase4to5 {
                parties: message_received.parties.reverse(), // We reply to the previous message.
                response,
            };

            mul_keep.insert(their_index, keep);
            mul_transmit.push(transmit);
        }
    }

    Ok((pk, mul_keep, mul_transmit))
}

// Communication round 4
// DKG: No more messages to transmit.
//
// Init: Each party transmits messages for the multiplication protocol.

// Phase 5 = No steps in DKG (just initialization)
// Input (Init): Parameters, values kept and transmited in Phases 3 and 4.
// Output (Init): Some data to keep and to transmit.
pub fn dkg_phase5(parameters: &Parameters, mul_kept: &HashMap<usize,KeepInitMulPhase3to5>, mul_received: &Vec<TransmitInitMulPhase4to5>) -> Result<(HashMap<usize,KeepInitMulPhase5to6>, Vec<TransmitInitMulPhase5to6>),Abort> {

    // Initialization - Two-party multiplication.
    // We now act as the receiver.
    let mut mul_keep: HashMap<usize,KeepInitMulPhase5to6> = HashMap::with_capacity(parameters.share_count - 1);
    let mut mul_transmit: Vec<TransmitInitMulPhase5to6> = Vec::with_capacity(parameters.share_count - 1);
    for (target_party, message_kept) in mul_kept {
        for message_received in mul_received {

            let my_index = message_received.parties.receiver;
            let their_index = message_received.parties.sender;

            // We first check if the messages relate to the same party.
            if their_index != *target_party { continue; }

            let sender_result = MulReceiver::init_phase3(&message_kept.base_sender, &message_kept.double_hash, &message_received.response);
            if let Err(error) = sender_result {
                return Err(Abort::new(my_index, &format!("Initialization for multiplication protocol failed because of Party {}: {:?}", their_index, error.description)));
            }

            let keep = KeepInitMulPhase5to6 {
                mul_receiver: message_kept.mul_receiver.clone(),
            };
            let transmit = TransmitInitMulPhase5to6 {
                parties: message_received.parties.reverse(), // We reply to the previous message.
                sender_hashes: message_kept.sender_hashes.clone(),
            };

            mul_keep.insert(their_index, keep);
            mul_transmit.push(transmit);
        }
    }

    Ok((mul_keep, mul_transmit))
}

// Communication round 5
// DKG: No more messages to transmit.
//
// Init: Each party transmits messages for the multiplication protocol.

// Phase 6 = We finish everything and create a party ready to sign.
// Input: Data needed to create an instance of Party and previous messages.
// Output: Party.
pub fn dkg_phase6(parameters: &Parameters, party_index: usize, session_id: &[u8], poly_point: &Scalar<Secp256k1>, pk: &Point<Secp256k1>, zero_kept: &KeepInitZeroSharePhase3to6, mul_kept_phase4: &HashMap<usize,KeepInitMulPhase4to6>, mul_kept_phase5: &HashMap<usize,KeepInitMulPhase5to6>, mul_received: &Vec<TransmitInitMulPhase5to6>) -> Result<Party,Abort>{

    // Initialization - Two-party multiplication.
    // We now act as the sender.
    let mut mul_senders: HashMap<usize,MulSender> = HashMap::with_capacity(parameters.share_count - 1);
    for (target_party, message_kept) in mul_kept_phase4 {
        for message_received in mul_received {

            let my_index = message_received.parties.receiver;
            let their_index = message_received.parties.sender;

            // We first check if the messages relate to the same party.
            if their_index != *target_party { continue; }

            // We retrieve the id used for multiplication. Note that the first party
            // is the receiver and the second, the sender.
            let mul_sid = [&their_index.to_be_bytes(), &my_index.to_be_bytes(), session_id].concat();

            let receiver_result = MulSender::init_phase4(&message_kept.base_receiver, &mul_sid, &message_kept.receiver_output, &message_kept.receiver_hashes, &message_received.sender_hashes);
            if let Err(error) = receiver_result {
                return Err(Abort::new(my_index, &format!("Initialization for multiplication protocol failed because of Party {}: {:?}", their_index, error.description)));
            }

            mul_senders.insert(their_index, message_kept.mul_sender.clone());
        }
    }

    let mut mul_receivers: HashMap<usize,MulReceiver> = HashMap::with_capacity(parameters.share_count - 1);
    for (target_party, message_kept) in mul_kept_phase5 {
        mul_receivers.insert(*target_party, message_kept.mul_receiver.clone());
    }

    // We can finally finish key generation!

    let party = Party {
        parameters: parameters.clone(),
        party_index,
        session_id: session_id.to_vec(),

        poly_point: poly_point.clone(),
        pk: pk.clone(),

        zero_share: zero_kept.zero_share.clone(),

        mul_senders,
        mul_receivers,
    };

    Ok(party)
}

///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {

    use super::*;
    use rand::Rng;

    // DISTRIBUTED KEY GENERATION (without initializations)

    // We are not testing in the moment the initializations for zero shares
    // and multiplication here because they are only used during signing.

    // The initializations are checked after these tests (see below).

    #[test]
    // 2-of-2 scenario.
    fn test_dkg_t2_n2() {
        let parameters = Parameters { threshold: 2, share_count: 2};
        let session_id = rand::thread_rng().gen::<[u8; 32]>();

        // Phase 1 (Steps 1 and 2)
        let p1_phase1 = dkg_step2(&parameters, dkg_step1(&parameters)); //p1 = Party 1
        let p2_phase1 = dkg_step2(&parameters, dkg_step1(&parameters)); //p2 = Party 2

        assert_eq!(p1_phase1.len(), 2);
        assert_eq!(p2_phase1.len(), 2);

        // Communication round 1
        let p1_poly_fragments = vec![p1_phase1[0].clone(), p2_phase1[0].clone()];
        let p2_poly_fragments = vec![p1_phase1[1].clone(), p2_phase1[1].clone()];

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

        let parameters = Parameters { threshold, share_count: threshold + offset }; // You can fix the parameters if you prefer.
        let session_id = rand::thread_rng().gen::<[u8; 32]>();

        // Phase 1 (Steps 1 and 2)
        // Matrix of polynomial points
        let mut phase1: Vec<Vec<Scalar<Secp256k1>>> = Vec::with_capacity(parameters.share_count);
        for _ in 0..parameters.share_count {
            let party_phase1 = dkg_step2(&parameters, dkg_step1(&parameters));
            assert_eq!(party_phase1.len(), parameters.share_count);
            phase1.push(party_phase1);
        }
    
        // Communication round 1
        // We transpose the matrix
        let mut poly_fragments = vec![Vec::<Scalar<Secp256k1>>::with_capacity(parameters.share_count); parameters.share_count];
        for row_i in phase1 {
            for j in 0..parameters.share_count {
                poly_fragments[j].push(row_i[j].clone());
            }
        }

        // Phase 2 (Step 3) + Communication rounds 2 and 3
        let mut proofs_commitments: Vec<ProofCommitment> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {
            let party_i_phase2 = dkg_step3(i+1, &session_id, &poly_fragments[i]);
            let (_, party_i_proof_commitment) = party_i_phase2;
            proofs_commitments.push(party_i_proof_commitment);
        }

        // Phase 4 (Step 5)
        let mut result_parties: Vec<Result<Point<Secp256k1>,Abort>> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {
            result_parties.push(dkg_step5(&parameters, i+1, &session_id, &proofs_commitments));
        }

        for result in result_parties {
            assert!(result.is_ok());
        }
    } 

    #[test]
    // We remove the randomness from Phase 1. This allows us to compute the public key.
    fn test1_dkg_t2_n2_fixed_polynomials() {
        let parameters = Parameters { threshold: 2, share_count: 2 };
        let session_id = rand::thread_rng().gen::<[u8; 32]>();

        // We will define the fragments directly
        let p1_poly_fragments = vec![Scalar::<Secp256k1>::from(1), Scalar::<Secp256k1>::from(3)];
        let p2_poly_fragments = vec![Scalar::<Secp256k1>::from(2), Scalar::<Secp256k1>::from(4)];

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
        let expected_pk = Point::<Secp256k1>::generator() * Scalar::<Secp256k1>::from(2); 
        assert_eq!(p1_pk, expected_pk);
        assert_eq!(p2_pk, expected_pk);
    }

    #[test]
    fn test2_dkg_t2_n2_fixed_polynomials() {
        let parameters = Parameters { threshold: 2, share_count: 2 };
        let session_id = rand::thread_rng().gen::<[u8; 32]>();

        // We will define the fragments directly
        let p1_poly_fragments = vec![Scalar::<Secp256k1>::from(12), Scalar::<Secp256k1>::from(-2)];
        let p2_poly_fragments = vec![Scalar::<Secp256k1>::from(2), Scalar::<Secp256k1>::from(3)];

        // In this case, the secret polynomial p is of degree 1 and satisfies p(1) = 12+(-2) = 10 and p(2) = 2+3 = 5
        // In particular, we must have p(0) = 15, which is the "hypothetical" secret key.
        // For this reason, we should expect the public key to be 15 * generator.

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
        let expected_pk = Point::<Secp256k1>::generator() * Scalar::<Secp256k1>::from(15); 
        assert_eq!(p1_pk, expected_pk);
        assert_eq!(p2_pk, expected_pk);
    }

    #[test]
    fn test_dkg_t3_n5_fixed_polynomials() {
        let parameters = Parameters { threshold: 3, share_count: 5 };
        let session_id = rand::thread_rng().gen::<[u8; 32]>();

        // We will define the fragments directly
        let poly_fragments = vec![vec![Scalar::from(5),Scalar::from(1),Scalar::from(-5),Scalar::from(-2),Scalar::from(-3)],
                                                               vec![Scalar::from(9),Scalar::from(3),Scalar::from(-4),Scalar::from(-5),Scalar::from(-7)], 
                                                               vec![Scalar::from(15),Scalar::from(7),Scalar::from(-1),Scalar::from(-10),Scalar::from(-13)], 
                                                               vec![Scalar::from(23),Scalar::from(13),Scalar::from(4),Scalar::from(-17),Scalar::from(-21)], 
                                                               vec![Scalar::from(33),Scalar::from(21),Scalar::from(11),Scalar::from(-26),Scalar::from(-31)], 
                                                            ];

        // In this case, the secret polynomial p is of degree 2 and satisfies: 
        // p(1) = -4, p(2) = -4, p(3) = -2, p(4) = 2, p(5) = 8.
        // Hence we must have p(x) = x^2 - 3x - 2.
        // In particular, we must have p(0) = -2, which is the "hypothetical" secret key.
        // For this reason, we should expect the public key to be (-2) * generator.

        // Phase 2 (Step 3) + Communication rounds 2 and 3
        let mut proofs_commitments: Vec<ProofCommitment> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {
            let party_i_phase2 = dkg_step3(i+1, &session_id, &poly_fragments[i]);
            let (_, party_i_proof_commitment) = party_i_phase2;
            proofs_commitments.push(party_i_proof_commitment);
        }

        // Phase 4 (Step 5)
        let mut results: Vec<Result<Point<Secp256k1>,Abort>> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {
            results.push(dkg_step5(&parameters, i+1, &session_id, &proofs_commitments));
        }

        let mut public_keys: Vec<Point<Secp256k1>> = Vec::with_capacity(parameters.share_count);
        for result in results {
            match result {
                Ok(pk) => { public_keys.push(pk); },
                Err(abort) => { panic!("Party {} aborted: {:?}", abort.index, abort.description); },
            }
        }
        
        // Verifying the public key
        let expected_pk = Point::<Secp256k1>::generator() * Scalar::<Secp256k1>::from(-2);
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

        let parameters = Parameters { threshold, share_count: threshold + offset }; // You can fix the parameters if you prefer.
        let session_id = rand::thread_rng().gen::<[u8; 32]>();

        // Phase 1
        let mut dkg_1: Vec<Vec<Scalar<Secp256k1>>> = Vec::with_capacity(parameters.share_count);
        let mut zero_kept_1to2: Vec<HashMap<usize,KeepInitZeroSharePhase1to2>> = Vec::with_capacity(parameters.share_count);
        let mut zero_transmit_1to3: Vec<Vec<TransmitInitZeroSharePhase1to3>> = Vec::with_capacity(parameters.share_count);
        let mut mul_kept_1to3: Vec<HashMap<usize,KeepInitMulPhase1to3>> = Vec::with_capacity(parameters.share_count);
        let mut mul_transmit_1to2: Vec<Vec<TransmitInitMulPhase1to2>> = Vec::with_capacity(parameters.share_count);
        for i in 1..=parameters.share_count {
            let (out1, out2, out3, out4, out5) = dkg_phase1(&parameters, i, &session_id);

            dkg_1.push(out1);
            zero_kept_1to2.push(out2);
            zero_transmit_1to3.push(out3);
            mul_kept_1to3.push(out4);
            mul_transmit_1to2.push(out5);
        }

        // Communication round 1
        let mut poly_fragments = vec![Vec::<Scalar<Secp256k1>>::with_capacity(parameters.share_count); parameters.share_count];
        for row_i in dkg_1 {
            for j in 0..parameters.share_count {
                poly_fragments[j].push(row_i[j].clone());
            }
        }

        let mut zero_received_1to3: Vec<Vec<TransmitInitZeroSharePhase1to3>> = Vec::with_capacity(parameters.share_count);
        let mut mul_received_1to2: Vec<Vec<TransmitInitMulPhase1to2>> = Vec::with_capacity(parameters.share_count);
        for i in 1..=parameters.share_count {

            let mut new_row: Vec<TransmitInitZeroSharePhase1to3> = Vec::with_capacity(parameters.share_count - 1);
            for party in &zero_transmit_1to3 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i {
                        new_row.push(message.clone());
                    }
                }
            }
            zero_received_1to3.push(new_row);

            let mut new_row: Vec<TransmitInitMulPhase1to2> = Vec::with_capacity(parameters.share_count - 1);
            for party in &mul_transmit_1to2 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i {
                        new_row.push(message.clone());
                    }
                }
            }
            mul_received_1to2.push(new_row);

        }

        // Phase 2
        let mut poly_points: Vec<Scalar<Secp256k1>> = Vec::with_capacity(parameters.share_count);
        let mut proofs_commitments: Vec<ProofCommitment> = Vec::with_capacity(parameters.share_count);
        let mut zero_kept_2to3: Vec<HashMap<usize,KeepInitZeroSharePhase2to3>> = Vec::with_capacity(parameters.share_count);
        let mut zero_transmit_2to3: Vec<Vec<TransmitInitZeroSharePhase2to3>> = Vec::with_capacity(parameters.share_count);
        let mut mul_kept_2to4: Vec<HashMap<usize,KeepInitMulPhase2to4>> = Vec::with_capacity(parameters.share_count);
        let mut mul_transmit_2to3: Vec<Vec<TransmitInitMulPhase2to3>> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {

            let result = dkg_phase2(&parameters, i+1, &session_id, &poly_fragments[i], &zero_kept_1to2[i], &mul_received_1to2[i]);
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                },
                Ok((out1, out2, out3, out4, out5, out6)) => {
                    poly_points.push(out1);
                    proofs_commitments.push(out2);
                    zero_kept_2to3.push(out3);
                    zero_transmit_2to3.push(out4);
                    mul_kept_2to4.push(out5);
                    mul_transmit_2to3.push(out6);
                },
            }
        }

        // Communication round 2
        let mut zero_received_2to3: Vec<Vec<TransmitInitZeroSharePhase2to3>> = Vec::with_capacity(parameters.share_count);
        let mut mul_received_2to3: Vec<Vec<TransmitInitMulPhase2to3>> = Vec::with_capacity(parameters.share_count);
        for i in 1..=parameters.share_count {

            // We don't need to transmit the commitments because proofs_commitments is already what we need.
            // In practice, this should be done here.

            let mut new_row: Vec<TransmitInitZeroSharePhase2to3> = Vec::with_capacity(parameters.share_count - 1);
            for party in &zero_transmit_2to3 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i {
                        new_row.push(message.clone());
                    }
                }
            }
            zero_received_2to3.push(new_row);

            let mut new_row: Vec<TransmitInitMulPhase2to3> = Vec::with_capacity(parameters.share_count - 1);
            for party in &mul_transmit_2to3 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i {
                        new_row.push(message.clone());
                    }
                }
            }
            mul_received_2to3.push(new_row);

        }

        // Phase 3
        let mut zero_kept_3to6: Vec<KeepInitZeroSharePhase3to6> = Vec::with_capacity(parameters.share_count);
        let mut mul_kept_3to5: Vec<HashMap<usize,KeepInitMulPhase3to5>> = Vec::with_capacity(parameters.share_count);
        let mut mul_transmit_3to4: Vec<Vec<TransmitInitMulPhase3to4>> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {

            let result = dkg_phase3(&parameters, &session_id, &zero_kept_2to3[i], &zero_received_1to3[i], &zero_received_2to3[i], &mul_kept_1to3[i], &mul_received_2to3[i]);
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                },
                Ok((out1, out2, out3)) => {
                    zero_kept_3to6.push(out1);
                    mul_kept_3to5.push(out2);
                    mul_transmit_3to4.push(out3);
                },
            }
        }

        // Communication round 3
        let mut mul_received_3to4: Vec<Vec<TransmitInitMulPhase3to4>> = Vec::with_capacity(parameters.share_count);
        for i in 1..=parameters.share_count {

           // We don't need to transmit the proofs because proofs_commitments is already what we need.
           // In practice, this should be done here.

            let mut new_row: Vec<TransmitInitMulPhase3to4> = Vec::with_capacity(parameters.share_count - 1);
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

        // Phase 4
        let mut public_keys: Vec<Point<Secp256k1>> = Vec::with_capacity(parameters.share_count);
        let mut mul_kept_4to6: Vec<HashMap<usize,KeepInitMulPhase4to6>> = Vec::with_capacity(parameters.share_count);
        let mut mul_transmit_4to5: Vec<Vec<TransmitInitMulPhase4to5>> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {

            let result = dkg_phase4(&parameters, i+1, &session_id, &proofs_commitments, &mul_kept_2to4[i], &mul_received_3to4[i]);
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                },
                Ok((out1, out2, out3)) => {
                    public_keys.push(out1);
                    mul_kept_4to6.push(out2);
                    mul_transmit_4to5.push(out3);
                },
            }
        }

        // Communication round 4
        let mut mul_received_4to5: Vec<Vec<TransmitInitMulPhase4to5>> = Vec::with_capacity(parameters.share_count);
        for i in 1..=parameters.share_count {

            let mut new_row: Vec<TransmitInitMulPhase4to5> = Vec::with_capacity(parameters.share_count - 1);
            for party in &mul_transmit_4to5 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i {
                        new_row.push(message.clone());
                    }
                }
            }
            mul_received_4to5.push(new_row);

        }

        // Phase 5
        let mut mul_kept_5to6: Vec<HashMap<usize,KeepInitMulPhase5to6>> = Vec::with_capacity(parameters.share_count);
        let mut mul_transmit_5to6: Vec<Vec<TransmitInitMulPhase5to6>> = Vec::with_capacity(parameters.share_count);
        for i in 0..parameters.share_count {

            let result = dkg_phase5(&parameters, &mul_kept_3to5[i], &mul_received_4to5[i]);
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                },
                Ok((out1, out2)) => {
                    mul_kept_5to6.push(out1);
                    mul_transmit_5to6.push(out2);
                },
            }
        }

        // Communication round 5
        let mut mul_received_5to6: Vec<Vec<TransmitInitMulPhase5to6>> = Vec::with_capacity(parameters.share_count);
        for i in 1..=parameters.share_count {

            let mut new_row: Vec<TransmitInitMulPhase5to6> = Vec::with_capacity(parameters.share_count - 1);
            for party in &mul_transmit_5to6 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i {
                        new_row.push(message.clone());
                    }
                }
            }
            mul_received_5to6.push(new_row);

        }

        // Phase 6
        for i in 0..parameters.share_count {

            let result = dkg_phase6(&parameters, i+1, &session_id, &poly_points[i], &public_keys[i], &zero_kept_3to6[i], &mul_kept_4to6[i], &mul_kept_5to6[i], &mul_received_5to6[i]);
            if let Err(abort) = result {
                panic!("Party {} aborted: {:?}", abort.index, abort.description);
            }
        }

    }
}