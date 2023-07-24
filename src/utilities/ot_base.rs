use curv::elliptic::curves::{Scalar, Point, Secp256k1};

use crate::SECURITY;
use crate::utilities::hashes::*;
use crate::utilities::proofs::DLogProof;

pub struct ErrorOT {
    pub description: String,
}

impl ErrorOT {
    pub fn new(description: &str) -> ErrorOT {
        ErrorOT {
            description: String::from(description),
        }
    }
}

pub struct Sender {
    sk: Scalar<Secp256k1>,
    pub pk: Point<Secp256k1>,
}

pub struct Receiver {
    pub pk: Point<Secp256k1>,
}

impl Sender {

    //Steps 1 and 2
    pub fn steps1and2_initialize(session_id: &[u8]) -> (Sender, DLogProof) {
        let sk = Scalar::<Secp256k1>::random();
        let pk = Point::<Secp256k1>::generator() * &sk;

        let proof = DLogProof::prove(&sk, session_id);
        let sender = Sender {
            sk,
            pk,
        };

        (sender, proof)
    }

    //Step 3 - No action for the sender.

    //Step 4
    pub fn step4_computepads(&self, session_id: &[u8], encoded_choice_bit: &Point<Secp256k1>) -> (HashOutput, HashOutput) {
        let point0 = encoded_choice_bit * &self.sk;
        let point1 = &point0 - (&self.pk * &self.sk);

        let point0_as_bytes = point_to_bytes(&point0);
        let point1_as_bytes = point_to_bytes(&point1);

        let pad0 = hash(&point0_as_bytes, session_id);
        let pad1 = hash(&point1_as_bytes, session_id);

        (pad0, pad1)
    }

    //Step 5
    pub fn ste5_computechallenge(&self, session_id: &[u8], pad0: &HashOutput, pad1: &HashOutput) -> (HashOutput, HashOutput, HashOutput, HashOutput) {
        let hash_pad0 = hash(pad0, session_id);
        let hash_pad1 = hash(pad1, session_id);

        //For the second hash, the implementation from DKLs19 updates the id tag. PENSAR NISSO!
        let double_hash_pad0 = hash(&hash_pad0, session_id);
        let double_hash_pad1 = hash(&hash_pad1, session_id);

        let mut challenge = [0u8; SECURITY];
        for i in 0..SECURITY {
            challenge[i] = double_hash_pad0[i] ^ double_hash_pad1[i];
        }

        (hash_pad0, hash_pad1, double_hash_pad0, challenge)
    }

    //Step 6 - No action for the sender.

    //Step 7
    pub fn step7_openchallenge(&self, double_hash_pad0: &HashOutput, response: &HashOutput) -> Result<(),ErrorOT> {
        if double_hash_pad0 != response {
            return Err(ErrorOT::new("Receiver cheated: Challenge verification failed!"));
        }

        Ok(())
    }

    //Step 8 - No action for the sender.

}

impl Receiver {

    //Step 1 - No action for the receiver.

    //Step 2
    pub fn step2_initialize(session_id: &[u8], proof: &DLogProof) -> Result<Receiver,ErrorOT> {
        let verification = DLogProof::verify(proof, session_id);
        if !verification {
            return Err(ErrorOT::new("Sender cheated: Proof of discrete logarithm failed!"));
        }

        let pk = proof.point.clone();
        let receiver = Receiver {
            pk,
        };

        Ok(receiver)
    }

    //Step 3
    pub fn step3_padtransfer(&self, session_id: &[u8], choice_bit: bool) -> (Point<Secp256k1>, HashOutput) {
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

        (encoded_choice_bit, pad)
    }

    //Steps 4 and 5 - No action for the receiver.

    //Step 6
    pub fn step6_respondchallenge(&self, session_id: &[u8], choice_bit: bool, pad: &HashOutput, challenge: &HashOutput) -> (HashOutput, HashOutput) {
        let hash_pad = hash(pad, session_id);

        //For the second hash, the implementation from DKLs19 updates the id tag. PENSAR NISSO!
        let double_hash_pad = hash(&hash_pad, session_id);

        let mut response = double_hash_pad;
        if choice_bit {
            for i in 0..SECURITY {
                response[i] = response[i] ^ challenge[i];
            }
        }

        (hash_pad, response)
    }

    //Step 7 - No action for the receiver.

    //Step 8
    pub fn step8_verification(&self, session_id: &[u8], choice_bit: bool, hash_pad: &HashOutput, hash_pad0_sender: &HashOutput, hash_pad1_sender: &HashOutput, challenge: &HashOutput) -> Result<(),ErrorOT> {
        let expected_hash_pad: HashOutput;
        if choice_bit {
            expected_hash_pad = hash_pad1_sender.clone();
        } else {
            expected_hash_pad = hash_pad0_sender.clone();
        }

        if *hash_pad != expected_hash_pad {
            return Err(ErrorOT::new("Sender cheated: Pad verification failed!"));
        }

        let double_hash_pad0 = hash(hash_pad0_sender, session_id);
        let double_hash_pad1 = hash(hash_pad1_sender, session_id);

        let mut expected_challenge = [0u8; SECURITY];
        for i in 0..SECURITY {
            expected_challenge[i] = double_hash_pad0[i] ^ double_hash_pad1[i];
        }

        if *challenge != expected_challenge {
            return  Err(ErrorOT::new("Sender cheated: Challenge reconstruction failed!"));
        }

        Ok(())
    }
}