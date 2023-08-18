/// This file implements an Oblivious Transfer Extension (OTE) that realizes
/// Functionality 3 in DKLs19 (https://eprint.iacr.org/2019/523.pdf). It is
/// used for the multiplication protocol (see multiplication.rs).
/// 
/// As DKLs23 suggested, we use Roy's SoftSpokenOT (https://eprint.iacr.org/2022/192.pdf).
/// However, we do not follow this paper directly. Instead, we use the KOS paper
/// available at https://eprint.iacr.org/2015/546.pdf. In the corrected version,
/// they present an alternative for their original protocol (which was used by DKLs,
/// but was not as secure as expected) using SoftSpokenOT (see Fig. 10 in KOS).
/// 
/// In order to reduce the round count, we apply the Fiat-Shamir heuristic, as DKLs23
/// instructs. We also include an additional phase in the protocol given by KOS. It
/// comes from Protocol 9 of the DKLs18 paper (https://eprint.iacr.org/2018/499.pdf).
/// It is needed to transform the outputs to the desired form.

use curv::elliptic::curves::{Scalar, Point, Secp256k1};

use crate::{RAW_SECURITY, STAT_SECURITY};

use crate::utilities::hashes::*;
use crate::utilities::proofs::DLogProof;

use crate::utilities::ot::ErrorOT;
use crate::utilities::ot::ot_base::*;

// You should not change these numbers!
// If you do, some parts of the code must be changed.
pub const KAPPA: usize = RAW_SECURITY;
pub const OT_SECURITY: usize = 128 + STAT_SECURITY; //Number used by DKLs in implementations. It has to divide BATCH_SIZE!
pub const BATCH_SIZE: usize = RAW_SECURITY + 2*STAT_SECURITY;
pub const EXTENDED_BATCH_SIZE: usize = BATCH_SIZE + OT_SECURITY;

pub type PRGOutput = [u8; EXTENDED_BATCH_SIZE/8]; //EXTENDED_BATCH_SIZE has to be divisible by 8.
pub type FieldElement = [u8; OT_SECURITY/8];      //The same for OT_SECURITY

#[derive(Clone)]
pub struct OTESender {
    pub correlation: Vec<bool>, //We will deal with bits separetely
    pub seeds: Vec<HashOutput>,
}

#[derive(Clone)]
pub struct OTEReceiver {
    pub seeds0: Vec<HashOutput>,
    pub seeds1: Vec<HashOutput>,
}

// This struct is for better readability of the code.
#[derive(Clone)]
pub struct OTEDataToSender {
    pub u: Vec<PRGOutput>,
    pub verify_x: FieldElement,
    pub verify_t: Vec<FieldElement>,
}

impl OTESender {
    
    // INITIALIZE
    
    // According to KOS (Fig. 10), the initialization is done by applying the OT protocol
    // KAPPA times and considering the outputs as "seeds".
    
    // Attention: The roles are reversed during this part!
    // Hence, a sender in the extension initializes as a receiver in the base OT. 

    pub fn init_phase1(session_id: &[u8], proof: &DLogProof) -> Result<Receiver, ErrorOT> {
        Receiver::phase1initialize(session_id, proof)
    }

    pub fn init_phase2(receiver: &Receiver, session_id: &[u8]) -> (OTESender, Vec<ReceiverOutput>, Vec<Point<Secp256k1>>) {
        
        // The choice bits are sampled randomly.
        let mut correlation:Vec<bool> = Vec::with_capacity(KAPPA);
        for _ in 0..KAPPA {
            correlation.push(rand::random());
        }

        let (output, encoded) = receiver.phase2batch(KAPPA, session_id, &correlation);

        // The outputs from the base OT become the sender's seeds.
        let mut seeds: Vec<HashOutput> = Vec::with_capacity(KAPPA);
        for i in 0..KAPPA {
            seeds.push(output[i].pad);
        }

        let ote_sender = OTESender {
            correlation,
            seeds,
        };

        (ote_sender, output, encoded)
    }

    pub fn init_phase3(receiver: &Receiver, session_id: &[u8], output: &Vec<ReceiverOutput>, challenge: &Vec<HashOutput>) -> (Vec<ReceiverHashData>, Vec<HashOutput>) {
        receiver.phase3batch(KAPPA, session_id, output, challenge)
    }

    pub fn init_phase4(receiver: &Receiver, session_id: &[u8], output: &Vec<ReceiverOutput>, hashes: &Vec<ReceiverHashData>, sender_hashes: &Vec<SenderHashData>) -> Result<(),ErrorOT> {
        receiver.phase4batch(KAPPA, session_id, output, hashes, sender_hashes)
    }

    // PROTOCOL
    // We now follow the main steps in Fig. 10 of KOS.

    // Input: Correlation for the points (as in Functionality 3 of DKLs19) and values transmitted by the receiver.
    // Output: Protocol's output and a value to be sent to the receiver.
    pub fn run(&self, session_id: &[u8], input_correlation: &Vec<Scalar<Secp256k1>>, data: &OTEDataToSender) -> Result<(Vec<Scalar<Secp256k1>>, Vec<Scalar<Secp256k1>>), ErrorOT> {

        // EXTEND

        // Step 1 - No action for the sender.

        // Step 2 - Extend the seed with the pseudorandom generator (PRG).
        // The PRG will be implemented via hash functions.
        let mut extended_seeds: Vec<PRGOutput> = Vec::with_capacity(KAPPA);
        for i in 0..KAPPA {
            let mut prg: Vec<u8> = Vec::with_capacity(EXTENDED_BATCH_SIZE/8); //It may use more capacity.
            
            // The PRG will given by concatenating "chunks" of hash outputs.
            // The reason for this is that we need more than 256 bits.
            let mut count = 0usize;
            while prg.len() < EXTENDED_BATCH_SIZE/8 {

                // To change the "random oracle", we include the index and a counter into the salt.
                let salt = [&i.to_be_bytes(), &count.to_be_bytes(), session_id].concat();
                count = count + 1;

                let chunk = hash(&self.seeds[i], &salt);

                prg.extend_from_slice(&chunk);
            }

            // We remove extra bytes
            let mut prg_output = [0; EXTENDED_BATCH_SIZE/8];
            prg_output.clone_from_slice(&prg[0..EXTENDED_BATCH_SIZE/8]);

            extended_seeds.push(prg_output);
        }

        // Step 3 - No action for the sender.

        // Step 4 - Compute the q from Fig. 10 in KOS.
        // It is computed with the matrix u sent by the receiver.
        let mut q: Vec<PRGOutput> = Vec::with_capacity(KAPPA);
        for i in 0..KAPPA {
            let mut q_i = [0; EXTENDED_BATCH_SIZE/8];
            for j in 0..EXTENDED_BATCH_SIZE/8 {
                q_i[j] = ((self.correlation[i] as u8) * data.u[i][j]) ^ extended_seeds[i][j];
            }
            q.push(q_i);
        }

        // CONSISTENCY CHECK

        // Step 1 - At this point, the sender would sample some random values to the receiver.
        // In order to reduce the round count, we adopt DKLs23 suggestion on page 30 and
        // modify this step via the Fiat-Shamir heuristic. Hence, this random value will not
        // be random but it will come from the data that the receiver has to transmit to
        // to the sender. In this case, we will simply hash the matrix u.

        // The constant m in KOS Fig. 10 is BATCH_SIZE/OT_SECURITY = 2. Thus, we need two
        // pseudorandom numbers chi1 and chi2. They have OT_SECURITY = 208 bits.
        // We can generate them with a hash.

        // This time, we are hashing the same message twice, so we put the tags 1 and 2 in the salt.
        let salt1 = [&(1usize).to_be_bytes(), session_id].concat();
        let salt2 = [&(2usize).to_be_bytes(), session_id].concat();

        // We concatenate the rows of the matrix u.
        let msg = data.u.concat();

        // We apply the hash and remove extra bytes.
        let mut chi1 = [0u8; OT_SECURITY/8];
        let mut chi2 = [0u8; OT_SECURITY/8];
        chi1.clone_from_slice(&hash(&msg, &salt1)[0..OT_SECURITY/8]);
        chi2.clone_from_slice(&hash(&msg, &salt2)[0..OT_SECURITY/8]);

        // Step 2 - No action for the sender.

        // Step 3 - Verify the values sent by the receiver against our data.
        // We start by computing the verifying vector q (as in KOS, Fig. 10).
        let mut verify_q: Vec<FieldElement> = Vec::with_capacity(KAPPA);
        for i in 0..KAPPA {

            // The summation sign on the protocol is just the sum of the following two terms:
            let prod_qi_1 = field_mul(&q[i][0..OT_SECURITY/8], &chi1);
            let prod_qi_2 = field_mul(&q[i][(OT_SECURITY/8)..(2*OT_SECURITY/8)], &chi2);

            //We sum the terms to get q_i.
            let mut verify_qi = [0u8;OT_SECURITY/8];
            for k in 0..OT_SECURITY/8 {
                verify_qi[k] = prod_qi_1[k] ^ prod_qi_2[k] ^ q[i][(2*OT_SECURITY/8) + k];
            }

            verify_q.push(verify_qi);
        }

        // We compute the same thing with the receiver's information.
        let mut verify_sender: Vec<FieldElement> = Vec::with_capacity(KAPPA);
        for i in 0..KAPPA {
            let mut verify_sender_i = [0u8;OT_SECURITY/8];
            for k in 0..OT_SECURITY/8 {
                verify_sender_i[k] = data.verify_t[i][k] ^ ((self.correlation[i] as u8) * data.verify_x[k]);
            }

            verify_sender.push(verify_sender_i);
        }

        // The two values must agree.
        if verify_q != verify_sender {
            return Err(ErrorOT::new("Receiver cheated in OTE: Consistency check failed!"));
        }

        // TRANSPOSE AND RANDOMIZE

        // Step 1 - We compute the transpose of q and take the first BATCH_SIZE rows.

        let transposed_q = cut_and_transpose(&q);

        // Step 2 - No action for the sender.

        // Step 3 - We compute the final messages. For the final part, it will be better
        // if we compute them in the form Scalar<Secp256k1>.

        // For convenience, we write the correlation in "compressed form" as an array of u8.
        // We interpreted the correlation as a little-endian representation of a number.
        let mut compressed_correlation: Vec<u8> = Vec::with_capacity(KAPPA/8);
        for i in 0..KAPPA/8 {
            compressed_correlation.push(((self.correlation[i*8+0] as u8) << 0)
									   |((self.correlation[i*8+1] as u8) << 1)
									   |((self.correlation[i*8+2] as u8) << 2)
								       |((self.correlation[i*8+3] as u8) << 3)
									   |((self.correlation[i*8+4] as u8) << 4)
									   |((self.correlation[i*8+5] as u8) << 5)
									   |((self.correlation[i*8+6] as u8) << 6)
									   |((self.correlation[i*8+7] as u8) << 7));

        }

        let mut v0: Vec<Scalar<Secp256k1>> = Vec::with_capacity(BATCH_SIZE);
        let mut v1: Vec<Scalar<Secp256k1>> = Vec::with_capacity(BATCH_SIZE);
        for j in 0..BATCH_SIZE {

            // For v1, we compute transposed_q[j] ^ correlation.
            let mut transposed_qj_plus_correlation = [0u8;KAPPA/8];
            for i in 0..KAPPA/8 {
                transposed_qj_plus_correlation[i] = transposed_q[j][i] ^ compressed_correlation[i];
            } 

            let salt = [&j.to_be_bytes(), session_id].concat();
            
            v0.push(hash_as_scalar(&transposed_q[j], &salt));
            v1.push(hash_as_scalar(&transposed_qj_plus_correlation, &salt));
        }

        // TRANSFER
        // We finished implementing Fig. 10 in KOS for the sender, which gives us
        // a random OT protocol. Now, for our use in DKLs23, we implement the
        // "Transfer" phase in Protocol 9 of DKLs18 (https://eprint.iacr.org/2018/499.pdf).

        // Step 1 - We compute t_A and tau, as in the paper.
        // Note that t_A is just the message v0 we computed above.

        let mut tau: Vec<Scalar<Secp256k1>> = Vec::with_capacity(BATCH_SIZE);
        for j in 0..BATCH_SIZE {
            let tau_j = &v1[j] - &v0[j] + &input_correlation[j];
            tau.push(tau_j);
        }

        // Step 2 - No action for the sender.

        // v0 is the output for the sender.
        // tau has to be sent to the receiver.
        Ok((v0, tau))
    }

}

impl OTEReceiver {

    // INITIALIZE
    
    // According to KOS (Fig. 10), the initialization is done by applying the OT protocol
    // KAPPA times and considering the outputs as "seeds".
    
    // Attention: The roles are reversed during this part!
    // Hence, a receiver in the extension initializes as a sender in the base OT.

    pub fn init_phase1(session_id: &[u8]) -> (Sender, DLogProof) {
        Sender::phase1initialize(session_id)
    }

    pub fn init_phase2(sender: &Sender, session_id: &[u8], encoded: &Vec<Point<Secp256k1>>) -> (OTEReceiver, Vec<SenderHashData>, Vec<HashOutput>, Vec<HashOutput>) {
        let (output, hashes, double, challenge) = sender.phase2batch(KAPPA, session_id, encoded);

        // The outputs from the base OT become the receiver's seeds.
        let mut seeds0: Vec<HashOutput> = Vec::with_capacity(KAPPA);
        let mut seeds1: Vec<HashOutput> = Vec::with_capacity(KAPPA);
        for i in 0..KAPPA {
            seeds0.push(output[i].pad0);
            seeds1.push(output[i].pad1);
        }

        let ote_receiver = OTEReceiver {
            seeds0,
            seeds1,
        };

        (ote_receiver, hashes, double, challenge)
    }

    pub fn init_phase3(sender: &Sender, double: &Vec<HashOutput>, response: &Vec<HashOutput>) -> Result<(),ErrorOT> {
        sender.phase3batch(KAPPA, double, response)
    }

    // PROTOCOL
    // We now follow the main steps in Fig. 10 of KOS.

    // Input: Choice bits.
    // Output: Extended seeds (used in the next phase) and values to be sent to the sender.
    pub fn run_phase1(&self, session_id: &[u8], choice_bits: &Vec<bool>) -> (Vec<PRGOutput>, OTEDataToSender) {

        // EXTEND

        // Step 1 - Extend the choice bits by adding random noise.
        let mut random_choice_bits: Vec<bool> = Vec::with_capacity(OT_SECURITY);
        for _ in 0..OT_SECURITY {
            random_choice_bits.push(rand::random());
        }
        let extended_choice_bits = [choice_bits.clone(),random_choice_bits].concat();

        // For convenience, we also keep the choice bits in "compressed form" as an array of u8.
        // We interpreted extended_choice_bits as a little-endian representation of a number.
        let mut compressed_extended_bits: Vec<u8> = Vec::with_capacity(EXTENDED_BATCH_SIZE/8);
        for i in 0..EXTENDED_BATCH_SIZE/8 {
            compressed_extended_bits.push(((extended_choice_bits[i*8+0] as u8) << 0)
									     |((extended_choice_bits[i*8+1] as u8) << 1)
									     |((extended_choice_bits[i*8+2] as u8) << 2)
									     |((extended_choice_bits[i*8+3] as u8) << 3)
									     |((extended_choice_bits[i*8+4] as u8) << 4)
									     |((extended_choice_bits[i*8+5] as u8) << 5)
									     |((extended_choice_bits[i*8+6] as u8) << 6)
									     |((extended_choice_bits[i*8+7] as u8) << 7));

        }

        // Step 2 - Extend the seeds with the pseudorandom generator (PRG).
        // The PRG will be implemented via hash functions.
        let mut extended_seeds0: Vec<PRGOutput> = Vec::with_capacity(KAPPA);
        let mut extended_seeds1: Vec<PRGOutput> = Vec::with_capacity(KAPPA);
        for i in 0..KAPPA {
            let mut prg0: Vec<u8> = Vec::with_capacity(EXTENDED_BATCH_SIZE/8); //It may use more capacity.
            let mut prg1: Vec<u8> = Vec::with_capacity(EXTENDED_BATCH_SIZE/8);
            
            // The PRG will given by concatenating "chunks" of hash outputs.
            // The reason for this is that we need more than 256 bits.
            let mut count = 0usize;
            while prg0.len() < EXTENDED_BATCH_SIZE/8 {

                // To change the "random oracle", we include the index and a counter into the salt.
                let salt = [&i.to_be_bytes(), &count.to_be_bytes(), session_id].concat();
                count = count + 1;

                let chunk0 = hash(&self.seeds0[i], &salt);
                let chunk1 = hash(&self.seeds1[i], &salt);

                prg0.extend_from_slice(&chunk0);
                prg1.extend_from_slice(&chunk1);
            }

            // We remove extra bytes
            let mut prg0_output = [0; EXTENDED_BATCH_SIZE/8];
            let mut prg1_output = [0; EXTENDED_BATCH_SIZE/8];
            prg0_output.clone_from_slice(&prg0[0..EXTENDED_BATCH_SIZE/8]);
            prg1_output.clone_from_slice(&prg1[0..EXTENDED_BATCH_SIZE/8]);

            extended_seeds0.push(prg0_output);
            extended_seeds1.push(prg1_output);
        }

        // Step 3 - Compute the matrix u from Fig. 10 in KOS.
        // This matrix will be sent to the sender.
        let mut u: Vec<PRGOutput> = Vec::with_capacity(KAPPA);
        for i in 0..KAPPA {
            let mut u_i = [0; EXTENDED_BATCH_SIZE/8];
            for j in 0..EXTENDED_BATCH_SIZE/8 {
                u_i[j] = extended_seeds0[i][j] ^ extended_seeds1[i][j] ^ compressed_extended_bits[j];
            }
            u.push(u_i);
        }

        // Step 4 - No action for the receiver.

        // CONSISTENCY CHECK

        // Step 1 - At this point, the sender would sample some random values to the receiver.
        // In order to reduce the round count, we adopt DKLs23 suggestion on page 30 and
        // modify this step via the Fiat-Shamir heuristic. Hence, this random value will not
        // be random but it will come from the data that the receiver has to transmit to
        // to the sender. In this case, we will simply hash the matrix u.

        // The constant m in KOS Fig. 10 is BATCH_SIZE/OT_SECURITY = 2. Thus, we need two
        // pseudorandom numbers chi1 and chi2. They have OT_SECURITY = 208 bits.
        // We can generate them with a hash.

        // This time, we are hashing the same message twice, so we put the tags 1 and 2 in the salt.
        let salt1 = [&(1usize).to_be_bytes(), session_id].concat();
        let salt2 = [&(2usize).to_be_bytes(), session_id].concat();

        // We concatenate the rows of the matrix u.
        let msg = u.concat();

        // We apply the hash and remove extra bytes.
        let mut chi1 = [0u8; OT_SECURITY/8];
        let mut chi2 = [0u8; OT_SECURITY/8];
        chi1.clone_from_slice(&hash(&msg, &salt1)[0..OT_SECURITY/8]);
        chi2.clone_from_slice(&hash(&msg, &salt2)[0..OT_SECURITY/8]);        

        // Step 2 - We compute the verification values to the sender.

        // The summation sign on the protocol is just the sum of the following two terms:
        let prod_x_1 = field_mul(&compressed_extended_bits[0..OT_SECURITY/8], &chi1);
        let prod_x_2 = field_mul(&compressed_extended_bits[(OT_SECURITY/8)..(2*OT_SECURITY/8)], &chi2);

        // We sum the terms to get x.
        let mut verify_x = [0u8;OT_SECURITY/8];
        for k in 0..OT_SECURITY/8 {
            verify_x[k] = prod_x_1[k] ^ prod_x_2[k] ^ compressed_extended_bits[(2*OT_SECURITY/8) + k];
        }

        let mut verify_t: Vec<FieldElement> = Vec::with_capacity(KAPPA);
        for i in 0..KAPPA {

            // The summation sign on the protocol is just the sum of the following two terms:
            let prod_ti_1 = field_mul(&extended_seeds0[i][0..OT_SECURITY/8], &chi1);
            let prod_ti_2 = field_mul(&extended_seeds0[i][(OT_SECURITY/8)..(2*OT_SECURITY/8)], &chi2);

            //We sum the terms to get t_i.
            let mut verify_ti = [0u8;OT_SECURITY/8];
            for k in 0..OT_SECURITY/8 {
                verify_ti[k] = prod_ti_1[k] ^ prod_ti_2[k] ^ extended_seeds0[i][(2*OT_SECURITY/8) + k];
            }

            verify_t.push(verify_ti);
        }

        // Step 3 - No action for the receiver.

        // These values are transmited to the sender.
        let data_to_sender = OTEDataToSender {
            u,
            verify_x,
            verify_t,
        };

        // extended_seeds0 has to be kept for the next phase.        
        (extended_seeds0, data_to_sender)
    }

    // Input: Previous inputs and value tau sent by the sender.
    // Output: Protocol's output.
    pub fn run_phase2(&self, session_id: &[u8], choice_bits: &Vec<bool>, extended_seeds: &Vec<PRGOutput>, tau: &Vec<Scalar<Secp256k1>>) -> Vec<Scalar<Secp256k1>> {
        
        // TRANSPOSE AND RANDOMIZE

        // Step 1 - We compute the transpose of extended_seeds and take the first BATCH_SIZE rows.

        let transposed_t = cut_and_transpose(extended_seeds);

        // Step 2 - We compute the final message. For the final part, it will be better
        // if we compute it in the form Scalar<Secp256k1>.

        let mut v: Vec<Scalar<Secp256k1>> = Vec::with_capacity(BATCH_SIZE);
        for j in 0..BATCH_SIZE {
            let salt = [&j.to_be_bytes(), session_id].concat();
            v.push(hash_as_scalar(&transposed_t[j], &salt));
        }

        // Step 3 - No action for the receiver.

        // TRANSFER
        // We finished implementing Fig. 10 in KOS for the receiver, which gives us
        // a random OT protocol. Now, for our use in DKLs23, we implement the
        // "Transfer" phase in Protocol 9 of DKLs18 (https://eprint.iacr.org/2018/499.pdf).

        // Step 1 - No action for the receiver.

        // Step 2 - We compute t_B as in the paper. We use the value tau sent by the sender.

        let mut t_b: Vec<Scalar<Secp256k1>> = Vec::with_capacity(BATCH_SIZE);
        for j in 0..BATCH_SIZE {
            let mut t_b_j = -&v[j];
            if choice_bits[j] {
                t_b_j = &tau[j] + &t_b_j;
            }
            t_b.push(t_b_j);
        }

        // The output for the receiver is t_b
        t_b
    }

}

// EXTRA FUNCTIONS

/// This function receives a KAPPA by EXTENDED_BATCH_SIZE matrix of booleans,
/// takes the first BATCH_SIZE columns and compute the transpose matrix, which
/// has BATCH_SIZE rows and KAPPA columns.
/// 
/// The only problem is that the rows in the input and output are grouped in
/// bytes, so we have to take some care. For this conversion, we think of
/// the rows as a little-endian representation of a number. For example, the row
/// [1110000010100000] corresponds to [7, 5] in bytes (and not [224,160]). 
/// 
/// This code was essentially copied from the function "transposeBooleanMatrix" here:
/// https://github.com/coinbase/kryptology/blob/master/pkg/ot/extension/kos/kos.go.
pub fn cut_and_transpose(input: &Vec<PRGOutput>) -> Vec<HashOutput> {

    // We initialize the output as a zero matrix.
    let mut output: Vec<HashOutput> = vec![[0u8;KAPPA/8];BATCH_SIZE];
    
    for row_byte in 0.. KAPPA/8 {
        for row_bit_within_byte in 0..8 {
            // The next loop should go up to EXTENDED_BATCH_SIZE/8 if we wanted
            // to compute the actual transpose, so it is here that we do the cut.
            for column_byte in 0..BATCH_SIZE/8 {
                for column_bit_within_byte in 0..8 {

                    // If we see input as a matrix of booleans, we want to
                    // take the element input[row_bit][column_bit].
                    let row_bit = (row_byte << 3) + row_bit_within_byte;
                    let column_bit = (column_byte << 3) + column_bit_within_byte;

                    // In every row, the columns are packed in bytes.
                    // We access the row_bit-th row, then the column_byte-th byte,
                    // and then we extract the desired bit.
                    let entry = (input[row_bit][column_byte] >> column_bit_within_byte) & 0x01;

                    // If we see output as a matrix of booleans, we want to
                    // write output[column_bit][row_bit] = entry;
                    // However, each row of output is also packed in bytes.
                    // Hence, we access the column_bit-th row, then the row_byte-th byte,
                    // and finally we put our bit in the correct place.
                    let shifted_entry = entry << row_bit_within_byte;
                    output[column_bit][row_byte] |= shifted_entry;
                }
            }
        }
    }

    output
}

/// This function implements multiplication in the finite field of order 2^208.
/// 
/// We follow https://github.com/coinbase/kryptology/blob/master/pkg/ot/extension/kos/kos.go.
/// 
/// It is based on Algorithm 2.34 ("Right-to-left comb method for polynomial multiplication")
/// and Figure 2.9 (for reduction modulo the irreducible polynomial) of the book
/// Guide to Elliptic Curve Cryptography by Hankerson, Menezes and Vanstone.
pub fn field_mul(left: &[u8], right: &[u8]) -> FieldElement {

    if (left.len() != OT_SECURITY/8) || (right.len() != OT_SECURITY/8) {
        panic!("Binary field multiplication: Entries don't have the correct length!");
    }

    // Constants W and t from Section 2.3 in the book.  
    const W: usize = 64;
    const T: usize = 4;

    let mut a = [0u64; T];
    let mut b = [0u64; T+1]; //b has extra space because it will be shifted.
    let mut c = [0u64; 2*T];

    // Conversion of [u8; 26] to [u64; 4].
    for i in 0..OT_SECURITY/8 {
        a[i>>3] |= (left[i] as u64) << ((i & 0x07) << 3);
        b[i>>3] |= (right[i] as u64) << ((i & 0x07) << 3);
    }

    // Algorithm 2.34 (page 49)
    for k in 0..W {

        for j in 0..T {

            //If the k-th bit of a[j] is 1, we add b to c (with the correct shift).
            if (a[j] >> k) % 2 == 1 {
                for i in 0..(T+1) {
                    c[j+i] ^= b[i];
                }
            }
        }

        // We shift b one digit to the left (not necessary in the last iteration)
        if k != W-1 {
            for i in (1..=T).rev() {
			    b[i] = b[i]<<1 | b[i-1]>>63;
		    }
        }
		b[0] <<= 1;
    }

    // For the moment, c is just the usual product of the two polynomials.
    // We have to reduce it modulo the polynomial f(X) = X^208 + X^9 + X^3 + X + 1
    // (according to Table A.1 on page 259).

    // We adapt the idea presented on page 54.

    for i in (T..(2*T)).rev() {
        let t = c[i];

        // The current block is reduced. Note that 208 = 3*64 + 16.
        // Hence, we skip 3 blocks and in the fourth block we put 16
        // bits of t (this is the t << 48 part). The remaining digits
        // go to the third block (this is the t >> 16 part).
        // Actually, this happens for every monomial in f(X), except
        // for X^208. Note that the difference between consecutive
        // numbers below is the same as the differences in the sequence
        // (9,3,1,0), which are the exponents in the monomials.
        c[i-4] ^= (t << 57) ^ (t << 51) ^ (t << 49) ^ (t << 48);
        c[i-3] ^= (t >>  7) ^ (t >> 13) ^ (t >> 15) ^ (t >> 16);

        // Erase the block that was reduced.
        c[i] = 0;  
    }
    // The block c[T-1] doesn't need to be reduced in its entirety,
    // only its first 64 - 16 = 48 bits.
    let t = c[T-1] >> 16;
    c[0] ^= (t << 9) ^ (t << 3) ^ (t << 1) ^ t;

    // We save only the last 16 bits (note that 0xFFFF = 0b11...11 with 16 one's).
    c[T-1] &= 0xFFFF;

    // At this point, c is the product of a and b in the finite field.

    // We convert the result to the original format.
    let mut result = [0u8; OT_SECURITY/8];
    for i in 0..OT_SECURITY/8 {
        result[i] = (c[i>>3] >> ((i & 0x07) << 3)) as u8;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn test_field_mul() {
        for _ in 0..100 {
            let initial = rand::thread_rng().gen::<FieldElement>();

            //Raising an element to the power 2^208 must not change it. 
            let mut result = initial.clone();
            for _ in 0..OT_SECURITY {
                result = field_mul(&result, &result);
            }

            assert_eq!(initial, result);
        }
    }

    // This function initializes an OTE setup.
    // It is "ideal" in the sense that it pretends to be both the sender and the receiver,
    // so it cannot be used for real applications.
    fn ideal_initialization_ote(session_id: &[u8]) -> Result<(OTESender, OTEReceiver), ErrorOT> {

        // Initializing base OT.
        let (base_sender, proof) = OTEReceiver::init_phase1(session_id);
        let try_receiver = OTESender::init_phase1(session_id, &proof);
        let base_receiver: Receiver;
        match try_receiver {
            Ok(r) => { base_receiver = r; },
            Err(error) => { return Err(error); },
        }

        // Running base OT.
        // We adapt the test funcion "ideal_functionality_batch" in the tests module for ot_base.rs.
        // See that function for a description of what is happening.
        let (ote_sender, receiver_output, encoded) = OTESender::init_phase2(&base_receiver, session_id);

        let (ote_receiver, sender_hashes, double_hash, challenge) = OTEReceiver::init_phase2(&base_sender, session_id, &encoded);

        let (receiver_hashes, response) = OTESender::init_phase3(&base_receiver, session_id, &receiver_output, &challenge);

        let sender_result = OTEReceiver::init_phase3(&base_sender, &double_hash, &response);

        if let Err(error) = sender_result {
            return Err(error);
        }

        let receiver_result = OTESender::init_phase4(&base_receiver, session_id, &receiver_output, &receiver_hashes, &sender_hashes);

        if let Err(error) = receiver_result {
            return Err(error);
        }

        Ok((ote_sender, ote_receiver))
    }

    // This function executes that main part of the protocol.
    // As before, this should not be used for real applications.
    fn ideal_functionality_ote(session_id: &[u8], ote_sender: &OTESender, ote_receiver: &OTEReceiver, sender_input_correlation: &Vec<Scalar<Secp256k1>>, receiver_choice_bits: &Vec<bool>) -> Result<(Vec<Scalar<Secp256k1>>, Vec<Scalar<Secp256k1>>), ErrorOT> {

        let (extended_seeds, data_to_sender) = ote_receiver.run_phase1(session_id, receiver_choice_bits);

        // Receiver keeps exteded_seeds and transmits data_to_sender.

        let sender_result = ote_sender.run(session_id, sender_input_correlation, &data_to_sender);

        let sender_output: Vec<Scalar<Secp256k1>>;
        let tau: Vec<Scalar<Secp256k1>>;
        match sender_result {
            Ok((v0, t)) => { (sender_output, tau) = (v0,t); },
            Err(error) => { return Err(error); },
        }

        // Sender transmits tau.

        let receiver_output = ote_receiver.run_phase2(session_id, receiver_choice_bits, &extended_seeds, &tau);

        Ok((sender_output, receiver_output))
    }

    #[test]
    fn test_ot_extension() {
        let session_id = rand::thread_rng().gen::<[u8; 32]>();

        //Initialize and verify if it worked.
        let init_result = ideal_initialization_ote(&session_id);

        let ote_sender: OTESender;
        let ote_receiver: OTEReceiver;
        match init_result {
            Ok((s,r)) => {
                ote_sender = s;
                ote_receiver = r;
            },
            Err(error) => {
                panic!("OTE error: {:?}", error.description);
            },
        }

        //Execute the protocol and verify if it did what it should do.
        let mut sender_input_correlation: Vec<Scalar<Secp256k1>> = Vec::with_capacity(BATCH_SIZE);
        let mut receiver_choice_bits: Vec<bool> = Vec::with_capacity(BATCH_SIZE);
        for _ in 0..BATCH_SIZE {
            sender_input_correlation.push(Scalar::<Secp256k1>::random());
            receiver_choice_bits.push(rand::random());
        }

        let func_result = ideal_functionality_ote(&session_id, &ote_sender, &ote_receiver, &sender_input_correlation, &receiver_choice_bits);
        match func_result {
            Ok((sender_output, receiver_output)) => {
                for i in 0..BATCH_SIZE {
                    //Depending on the choice the receiver made, the sum of the outputs should
                    //be equal to 0 or to the correlation the sender chose. 
                    let sum = &sender_output[i] + &receiver_output[i];
                    if receiver_choice_bits[i] {
                        assert_eq!(sum, sender_input_correlation[i]);
                    } else {
                        assert_eq!(sum, Scalar::<Secp256k1>::zero());
                    }
                }
            },
            Err(error) => {
                panic!("OTE error: {:?}", error.description);
            },
        }
    }
}