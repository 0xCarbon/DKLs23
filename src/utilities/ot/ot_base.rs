/// This file implements an oblivious transfer (OT) which will serve as a base
/// for the OT extension protocol.
/// 
/// We chose to proceed as the authors did when they implemented their 2019 paper
/// (see https://gitlab.com/neucrypt/mpecdsa). Hence, we are implementing the Protocol 7
/// of the original version of DKLs18 (see https://eprint.iacr.org/2018/499.pdf), the
/// so-called "Verified Simplest OT". As explained in the paper, we do the implementation
/// as a Random OT protocol. 
/// 
/// Besides the aforedmentioned implementation, we also followed this code:
/// https://github.com/coinbase/kryptology/blob/master/pkg/ot/base/simplest/ot.go
/// 
/// FOR THE FUTURE: In their corrected version of the DKLs18 paper (https://eprint.iacr.org/2018/499.pdf),
/// the authors suggest some replacements for their VSOT protocol for better performance
/// and better round counts. The DKLs23 paper (https://eprint.iacr.org/2023/765.pdf) especifically
/// suggests the endemic OT protocol of Zhou et al.: https://eprint.iacr.org/2022/1525.pdf.

use curv::elliptic::curves::{Scalar, Point, Secp256k1};

use crate::SECURITY;
use crate::utilities::hashes::*;
use crate::utilities::proofs::DLogProof;
use crate::utilities::ot::ErrorOT;

//SENDER STRUCTS

//Sender after initialization
#[derive(Debug, Clone)]
pub struct Sender {
    pub sk: Scalar<Secp256k1>,
    pub pk: Point<Secp256k1>,
}

//Output after running the protocol
#[derive(Debug, Clone)]
pub struct SenderOutput {
    pub pad0: HashOutput,
    pub pad1: HashOutput,
}

//Some hashes computed during the protocol which are used more than once.
//Another hash could be here, but we prefered to gather only what the sender
//would have to send to the receiver.
#[derive(Debug, Clone)]
pub struct SenderHashData {
    pub hash_pad0: HashOutput,
    pub hash_pad1: HashOutput,
}

//RECEIVER STRUCTS

//Receiver after initialization
#[derive(Debug, Clone)]
pub struct Receiver {
    pub pk: Point<Secp256k1>,
}

//Output after running the protocol
#[derive(Debug, Clone)]
pub struct ReceiverOutput {
    pub choice_bit: bool,
    pub pad: HashOutput,
}

//Some hashes computed during the protocol which are used more than once.
#[derive(Debug, Clone)]
pub struct ReceiverHashData {
    pub hash_pad: HashOutput,
    pub challenge: HashOutput,
}

/// VERIFIED SIMPLEST OBLIVIOUS TRANSFER (VSOT)
/// Implementation of Protocol 7 in the original DKLs18 paper (https://eprint.iacr.org/2018/499.pdf)
/// 
/// We implement each step of the protocol separately and then we gather them in phases.

impl Sender {

    // STEPS

    /// Step 1 - The sender produces a random scalar.
    /// This already generates an instance of Sender.
    pub fn step1initialize() -> Sender {
        let sk = Scalar::<Secp256k1>::random();
        let pk = Point::<Secp256k1>::generator() * &sk;
        
        Sender {
            sk,
            pk,
        }
    }

    /// Step 2 - The sender should transmit his public key together with a proof that
    /// he has the secret key.
    pub fn step2prove(&self, session_id: &[u8]) -> DLogProof {
        DLogProof::prove(&self.sk, session_id)
    }

    // Step 3 - No action for the sender.

    /// Step 4 - The sender computes the pads rho^0 and rho^1 from the paper.
    /// This is his output for this (random) oblivious transfer protocol.
    pub fn step4computepads(&self, session_id: &[u8], encoded_choice_bit: &Point<Secp256k1>) -> SenderOutput {
        let point0 = encoded_choice_bit * &self.sk;
        let point1 = &point0 - (&self.pk * &self.sk);

        let point0_as_bytes = point_to_bytes(&point0);
        let point1_as_bytes = point_to_bytes(&point1);

        let pad0 = hash(&point0_as_bytes, session_id);
        let pad1 = hash(&point1_as_bytes, session_id);

        SenderOutput {
            pad0,
            pad1,
        }
    }

    /// Step 5 - The sender computes the challenge for the receiver.
    /// Meanwhile, some hashes that will be used later are also computed.
    /// The sender hash data will be transmitted to the receiver, but we don't
    /// need to send the double hash, so we keep it in another place.
    pub fn step5computechallenge(&self, session_id: &[u8], pads: &SenderOutput) -> (SenderHashData, HashOutput, HashOutput) {
        let hash_pad0 = hash(&pads.pad0, session_id);
        let hash_pad1 = hash(&pads.pad1, session_id);

        //For the second hash, the implementation from DKLs19 updates the id tag. PENSAR NISSO!
        let double_hash_pad0 = hash(&hash_pad0, session_id);
        let double_hash_pad1 = hash(&hash_pad1, session_id);

        //The challenge is the XOR between the two double hashes.
        let mut challenge = [0u8; SECURITY];
        for i in 0..SECURITY {
            challenge[i] = double_hash_pad0[i] ^ double_hash_pad1[i];
        }

        let hashes = SenderHashData {
            hash_pad0,
            hash_pad1,
        };

        (hashes, double_hash_pad0, challenge)
    }

    // Step 6 - No action for the sender.

    /// Step 7 - The sender verifies if the receiver's response makes sense.
    pub fn step7openchallenge(&self, double_hash_pad0: &HashOutput, response: &HashOutput) -> Result<(),ErrorOT> {
        if double_hash_pad0 != response {
            return Err(ErrorOT::new("Receiver cheated in OT: Challenge verification failed!"));
        }

        Ok(())
    }

    // Step 8 - No action for the sender.

    // PHASES
    // We group the steps in phases. A phase consists of all steps that can be
    // executed in order without the need of communication.
    // Phases should be intercalated with communication rounds: broadcasts and/or
    // private messages containg the session id.
    // Remark: our phases are not the same as the phases from the paper.

    // Except for the first phase, we provide a "batch" version that reproduce the
    // protocol multiple times. It will be used for the OT extension.

    /// Phase 1 = Steps 1 and 2 ("Public key" phase in the paper)
    /// Input: Session id
    /// Output: Sender ready to participate and a proof of knowledge
    pub fn phase1initialize(session_id: &[u8]) -> (Sender, DLogProof) {
        let sender = Self::step1initialize();
        let proof = sender.step2prove(session_id);

        (sender, proof)
    }

    // Communication round 1
    // The sender transmits the proof to the receiver.
    // The receiver verifies the proof and finishes the initialization.

    // Communication round 2
    // When ready, the receiver sends his encoded choice bit.

    /// Phase 2 = Steps 4 and 5
    /// Input: Sender, session id and encoded choice bit
    /// Output: Protocol's output and hash data (containing the challenge)
    pub fn phase2output(&self, session_id: &[u8], encoded_choice_bit: &Point<Secp256k1>) -> (SenderOutput, SenderHashData, HashOutput, HashOutput) {
        let pads = self.step4computepads(session_id, encoded_choice_bit);
        let (hashes, double_hash_pad0, challenge) = self.step5computechallenge(session_id, &pads);

        (pads, hashes, double_hash_pad0, challenge)
    }

    pub fn phase2batch(&self, batch_size: usize, session_id: &[u8], vec_encoded_choice_bit: &Vec<Point<Secp256k1>>) -> (Vec<SenderOutput>, Vec<SenderHashData>, Vec<HashOutput>, Vec<HashOutput>) {
        let mut vec_pads: Vec<SenderOutput> = Vec::with_capacity(batch_size);
        let mut vec_hashes: Vec<SenderHashData> = Vec::with_capacity(batch_size);
        let mut vec_double: Vec<HashOutput> = Vec::with_capacity(batch_size);
        let mut vec_challenge: Vec<HashOutput> = Vec::with_capacity(batch_size);
        for i in 0..batch_size {
            
            // We use different ids for different iterations.
            let current_sid = [&i.to_be_bytes(), session_id].concat();

            let (pads, hashes, double, challenge) = self.phase2output(&current_sid, &vec_encoded_choice_bit[i]);
            vec_pads.push(pads);
            vec_hashes.push(hashes);
            vec_double.push(double);
            vec_challenge.push(challenge);
        }
        (vec_pads, vec_hashes, vec_double, vec_challenge)
    }

    // Communication round 3
    // The sender transmits the challenge to the receiver.

    // Communication round 4
    // The receiver computes the response and sends it.

    /// Phase 3 = Step 7
    /// Input: Sender, hash data (just double hash) and receiver's response
    /// Output: Abort message (if verification fails)
    pub fn phase3verify(&self, double_hash_pad0: &HashOutput, response: &HashOutput) -> Result<(),ErrorOT> {
        self.step7openchallenge(double_hash_pad0, response)
    }

    pub fn phase3batch(&self, batch_size: usize, vec_double_hash_pad0: &Vec<HashOutput>, vec_response: &Vec<HashOutput>) -> Result<(),ErrorOT> {
        for i in 0..batch_size {
            let result = self.phase3verify(&vec_double_hash_pad0[i], &vec_response[i]);
            if let Err(error) = result {
                return Err(ErrorOT::new(&format!("Batch, iteration {}: {:?}", i, error.description)));
            }
        }
        Ok(())
    }

    // Communication round 5
    // The sends transmits his hash data (the instance of SenderHashData).
    // The receiver does the last verification and finishes the protocol.

}

impl Receiver {

    // STEPS

    // Step 1 - No action for the receiver.

    /// Step 2 - The receiver verifies the sender's proof.
    /// This already generates an instance of Receiver.
    pub fn step2initialize(session_id: &[u8], proof: &DLogProof) -> Result<Receiver,ErrorOT> {
        let verification = DLogProof::verify(proof, session_id);
        if !verification {
            return Err(ErrorOT::new("Sender cheated in OT: Proof of discrete logarithm failed!"));
        }

        let pk = proof.point.clone();
        let receiver = Receiver {
            pk,
        };

        Ok(receiver)
    }

    /// Step 3 - Given a choice bit, the receiver encodes it (the point A from the paper)
    /// and computes his pad, which will be his output for the protocol.
    pub fn step3padtransfer(&self, session_id: &[u8], choice_bit: bool) -> (ReceiverOutput, Point<Secp256k1>) {
        let a = Scalar::<Secp256k1>::random();
        
        let choice0 = Point::<Secp256k1>::generator() * &a;
        let choice1 = &choice0 + &self.pk;

        let encoded_choice_bit: Point<Secp256k1>;
        if choice_bit {
            encoded_choice_bit = choice1;
        } else{
            encoded_choice_bit = choice0;
        }

        let point_pad = &self.pk * &a;
        let point_pad_as_bytes = point_to_bytes(&point_pad); 
        let pad = hash(&point_pad_as_bytes, session_id);

        let output = ReceiverOutput {
            choice_bit,
            pad,
        };

        (output, encoded_choice_bit)
    }

    // Steps 4 and 5 - No action for the receiver.

    /// Step 6 - The receiver computes his response for the sender's challenge.
    /// Meanwhile, some hashes that will be used later are also computed. 
    pub fn step6respond(&self, session_id: &[u8], output: &ReceiverOutput, challenge: &HashOutput) -> (ReceiverHashData, HashOutput) {
        let hash_pad = hash(&output.pad, session_id);

        //For the second hash, the implementation from DKLs19 updates the id tag. PENSAR NISSO!
        let double_hash_pad = hash(&hash_pad, session_id);

        let mut response = double_hash_pad;
        if output.choice_bit {
            for i in 0..SECURITY {
                response[i] = response[i] ^ challenge[i];
            }
        }

        let hashes = ReceiverHashData {
            hash_pad,
            challenge: challenge.clone(),  //The receiver saves the challenge he received.
        };

        (hashes, response)
    }

    // Step 7 - No action for the receiver.

    /// Step 8 - The receiver verifies if the sender computed correctly the
    /// pads and the challenge.
    pub fn step8verification(&self, session_id: &[u8], output: &ReceiverOutput, hashes: &ReceiverHashData, sender_hashes: &SenderHashData) -> Result<(),ErrorOT> {
        let expected_hash_pad: HashOutput;
        if output.choice_bit {
            expected_hash_pad = sender_hashes.hash_pad1.clone();
        } else {
            expected_hash_pad = sender_hashes.hash_pad0.clone();
        }

        if hashes.hash_pad != expected_hash_pad {
            return Err(ErrorOT::new("Sender cheated in OT: Pad verification failed!"));
        }

        let double_hash_pad0 = hash(&sender_hashes.hash_pad0, session_id);
        let double_hash_pad1 = hash(&sender_hashes.hash_pad1, session_id);

        let mut expected_challenge = [0u8; SECURITY];
        for i in 0..SECURITY {
            expected_challenge[i] = double_hash_pad0[i] ^ double_hash_pad1[i];
        }

        if hashes.challenge != expected_challenge {
            return  Err(ErrorOT::new("Sender cheated in OT: Challenge reconstruction failed!"));
        }

        Ok(())
    }

    // PHASES
    // We group the steps in phases. A phase consists of all steps that can be
    // executed in order without the need of communication.
    // Phases should be intercalated with communication rounds: broadcasts and/or
    // private messages containg the session id.
    // Remark: our phases are not the same as the phases from the paper.

    // Except for the first phase, we provide a "batch" version that reproduce the
    // protocol multiple times. It will be used for the OT extension.

    // Communication round 1
    // The receiver receives a proof from the sender.

    /// Phase 1 = Step 2
    /// Input: Session id and sender's proof
    /// Output: Receiver ready to participate (if the proof is sound)
    pub fn phase1initialize(session_id: &[u8], proof: &DLogProof) -> Result<Receiver,ErrorOT> {
        Self::step2initialize(session_id, proof)
    }

    // This finishes the initialization.
    // When ready, the receiver chooses to begin the actual protocol.

    /// Phase 2 = Step 3
    /// Input: Receiver, session id and choice bit
    /// Output: Protocol's output and encoded choice bit
    pub fn phase2padtransfer(&self, session_id: &[u8], choice_bit: bool) -> (ReceiverOutput, Point<Secp256k1>) {
        self.step3padtransfer(session_id, choice_bit)
    }

    pub fn phase2batch(&self, batch_size: usize, session_id: &[u8], vec_choice_bit: &Vec<bool>) -> (Vec<ReceiverOutput>, Vec<Point<Secp256k1>>) {
        let mut vec_output: Vec<ReceiverOutput> = Vec::with_capacity(batch_size);
        let mut vec_encoded: Vec<Point<Secp256k1>> = Vec::with_capacity(batch_size);
        for i in 0..batch_size {
            
            // We use different ids for different iterations.
            let current_sid = [&i.to_be_bytes(), session_id].concat();

            let (output, encoded) = self.phase2padtransfer(&current_sid, vec_choice_bit[i]);
            vec_output.push(output);
            vec_encoded.push(encoded);
        }
        (vec_output, vec_encoded)
    }

    // Communication round 2
    // The receiver sends his choice bit encoded.

    // Communication round 3
    // The sender computes the challenge and sends it.

    /// Phase 3 = Step 6
    /// Input: Receiver, session id, protocol's output and sender's challenge
    /// Output: Hash data and a response
    pub fn phase3respond(&self, session_id: &[u8], output: &ReceiverOutput, challenge: &HashOutput) -> (ReceiverHashData, HashOutput) {
        self.step6respond(session_id, output, challenge)
    }

    pub fn phase3batch(&self, batch_size: usize, session_id: &[u8], vec_output: &Vec<ReceiverOutput>, vec_challenge: &Vec<HashOutput>) -> (Vec<ReceiverHashData>, Vec<HashOutput>) {
        let mut vec_hashes: Vec<ReceiverHashData> = Vec::with_capacity(batch_size);
        let mut vec_response: Vec<HashOutput> = Vec::with_capacity(batch_size);
        for i in 0..batch_size {
            
            // We use different ids for different iterations.
            let current_sid = [&i.to_be_bytes(), session_id].concat();
            
            let (hashes, response) = self.phase3respond(&current_sid, &vec_output[i], &vec_challenge[i]);
            vec_hashes.push(hashes);
            vec_response.push(response);
        }
        (vec_hashes, vec_response)
    }

    // Communication round 4
    // The receiver sends his response to the challenge.

    // Communication round 5
    // The sender verifies the response and sends his hash data

    /// Phase 4 = Step 8
    /// Input: Receiver, session id, protocol's output and both hash datas
    /// Output: Abort message (if verification fails)
    pub fn phase4verification(&self, session_id: &[u8], output: &ReceiverOutput, hashes: &ReceiverHashData, sender_hashes: &SenderHashData) -> Result<(),ErrorOT> {
        self.step8verification(session_id, output, hashes, sender_hashes)
    }

    pub fn phase4batch(&self, batch_size: usize, session_id: &[u8], vec_output: &Vec<ReceiverOutput>, vec_hashes: &Vec<ReceiverHashData>, vec_sender_hashes: &Vec<SenderHashData>) -> Result<(),ErrorOT> {
        for i in 0..batch_size {
            
            // We use different ids for different iterations.
            let current_sid = [&i.to_be_bytes(), session_id].concat();

            let result = self.phase4verification(&current_sid, &vec_output[i], &vec_hashes[i], &vec_sender_hashes[i]);
            if let Err(error) = result {
                return Err(ErrorOT::new(&format!("Batch, iteration {}: {:?}", i, error.description)));
            }
        }
        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    // This function initializes an OT setup (Phase 1 for sender and receiver)
    // It is "ideal" in the sense that it pretends to be both the sender and the receiver,
    // so it cannot be used for real applications.
    fn ideal_initialization(session_id: &[u8]) -> Result<(Sender, Receiver),ErrorOT> {
        let (sender, proof) = Sender::phase1initialize(session_id);
        let try_receiver = Receiver::phase1initialize(session_id, &proof);

        match try_receiver {
            Ok(receiver) => { Ok((sender, receiver)) },
            Err(error) => { Err(error) },
        }
    }

    // This function executes that main part of the protocol.
    // As before, this should not be used for real applications.
    fn ideal_functionality(session_id: &[u8], sender: &Sender, receiver: &Receiver, choice_bit: bool) -> Result<(SenderOutput, ReceiverOutput),ErrorOT> {

        //Phase 2 - Receiver
        let (receiver_output, encoded_choice_bit) = receiver.phase2padtransfer(session_id, choice_bit);

        //Receiver transmits encoded_choice_bit

        //Phase 2 - Sender
        let (sender_output, sender_hashes, sender_double_hash, challenge) = sender.phase2output(session_id, &encoded_choice_bit);

        //Sender transmits challenge

        //Phase 3 - Receiver
        let (receiver_hashes, response) = receiver.phase3respond(session_id, &receiver_output, &challenge);

        //Receiver transmits response

        //Phase 3 - Sender
        let sender_result = sender.phase3verify(&sender_double_hash, &response);

        if let Err(error) = sender_result {
            return Err(error);
        }

        //Sender transmits sender_hashes

        //Phase 4 - Receiver
        let receiver_result = receiver.phase4verification(session_id, &receiver_output, &receiver_hashes, &sender_hashes);

        if let Err(error) = receiver_result {
            return Err(error);
        }

        Ok((sender_output,receiver_output))
    }

    // Batch version for the previous function.
    fn ideal_functionality_batch(session_id: &[u8], sender: &Sender, receiver: &Receiver, choice_bits: &Vec<bool>) -> Result<(Vec<SenderOutput>, Vec<ReceiverOutput>),ErrorOT> {

        let batch_size = choice_bits.len();

        //Phase 2 - Receiver
        let (vec_receiver_output, vec_encoded_choice_bit) = receiver.phase2batch(batch_size, session_id, choice_bits);

        //Receiver transmits encoded_choice_bit

        //Phase 2 - Sender
        let (vec_sender_output, vec_sender_hashes, vec_sender_double_hash, vec_challenge) = sender.phase2batch(batch_size, session_id, &vec_encoded_choice_bit);

        //Sender transmits challenge

        //Phase 3 - Receiver
        let (vec_receiver_hashes, vec_response) = receiver.phase3batch(batch_size, session_id, &vec_receiver_output, &vec_challenge);

        //Receiver transmits response

        //Phase 3 - Sender
        let sender_result = sender.phase3batch(batch_size, &vec_sender_double_hash, &vec_response);

        if let Err(error) = sender_result {
            return Err(error);
        }

        //Sender transmits sender_hashes

        //Phase 4 - Receiver
        let receiver_result = receiver.phase4batch(batch_size, session_id, &vec_receiver_output, &vec_receiver_hashes, &vec_sender_hashes);

        if let Err(error) = receiver_result {
            return Err(error);
        }

        Ok((vec_sender_output,vec_receiver_output))
    }

    #[test]
    fn test_ot_base() {
        let session_id = rand::thread_rng().gen::<[u8; 32]>();

        //Initialize and verify if it worked
        let init_result = ideal_initialization(&session_id);

        let sender: Sender;
        let receiver: Receiver;
        match init_result {
            Ok((s,r)) => {
                sender = s;
                receiver = r;
            },
            Err(error) => {
                panic!("OT error: {:?}", error.description);
            },
        }

        //Execute the protocol and verify if it did what it should do.
        let choice_bit = rand::random();
        let func_result = ideal_functionality(&session_id, &sender, &receiver, choice_bit);
        match func_result {
            Ok((sender_output, receiver_output)) => {
                //Depending on the choice the receiver made, he should receive one of the pads.
                if receiver_output.choice_bit {
                    assert_eq!(sender_output.pad1, receiver_output.pad);
                } else {
                    assert_eq!(sender_output.pad0, receiver_output.pad);
                }
            },
            Err(error) => {
                panic!("OT error: {:?}", error.description);
            },
        }
    }

    #[test]
    fn test_ot_base_batch() {
        let session_id = rand::thread_rng().gen::<[u8; 32]>();

        //Initialize and verify if it worked
        let init_result = ideal_initialization(&session_id);

        let sender: Sender;
        let receiver: Receiver;
        match init_result {
            Ok((s,r)) => {
                sender = s;
                receiver = r;
            },
            Err(error) => {
                panic!("OT error: {:?}", error.description);
            },
        }

        //Execute the protocol and verify if it did what it should do.
        let batch_size = 256;
        let mut vec_choice_bit: Vec<bool> = Vec::with_capacity(batch_size);
        for _ in 0..batch_size {
            vec_choice_bit.push(rand::random());
        }

        let func_result = ideal_functionality_batch(&session_id, &sender, &receiver, &vec_choice_bit);
        match func_result {
            Ok((vec_sender_output, vec_receiver_output)) => {
                for i in 0..batch_size {
                    //Depending on the choice the receiver made, he should receive one of the pads.
                    if vec_receiver_output[i].choice_bit {
                        assert_eq!(vec_sender_output[i].pad1, vec_receiver_output[i].pad);
                    } else {
                        assert_eq!(vec_sender_output[i].pad0, vec_receiver_output[i].pad);
                    }
                }
            },
            Err(error) => {
                panic!("OT error: {:?}", error.description);
            },
        }
    }
}