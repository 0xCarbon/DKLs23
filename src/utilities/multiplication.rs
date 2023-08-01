use curv::elliptic::curves::{Scalar, Point, Secp256k1};

use crate::utilities::hashes::*;
use crate::utilities::proofs::DLogProof;

use crate::utilities::ot::ErrorOT;
use crate::utilities::ot::ot_base::*;
use crate::utilities::ot::ot_extension::{OTESender, OTEReceiver, BATCH_SIZE, PRGOutput, FieldElement};

// Constant l from Functionality 3.5 in DKLs23 used in Protocol 3.6.
const L: usize = 2;

pub struct MulSender {
    public_gadget: Vec<Scalar<Secp256k1>>,
    ote_sender: OTESender,
}

pub struct MulReceiver {
    public_gadget: Vec<Scalar<Secp256k1>>,
    ote_receiver: OTEReceiver,
}

impl MulSender {
    
    // INITIALIZE

    // As in DKLs19 (https://eprint.iacr.org/2019/523.pdf), the initialization of the
    // multiplication protocol is the same as for our OT extension protocol.
    // Thus, we repeat the phases from the file ot_extension.rs.
    // The only difference is that we include the sampling for the public gadget vector.

    pub fn init_phase1(session_id: &[u8], proof: &DLogProof) -> Result<Receiver, ErrorOT> {
        OTESender::init_phase1(session_id, proof)
    }

    // The nonce will be sent by the receiver for the computation of the public gadget vector.
    pub fn init_phase2(receiver: &Receiver, session_id: &[u8], nonce: &Scalar<Secp256k1>) -> (MulSender, Vec<ReceiverOutput>, Vec<Point<Secp256k1>>) {
        let (ote_sender, output, encoded) = OTESender::init_phase2(receiver, session_id);

        // We compute the public gadget vector from the nonce, in the same way as in
        // https://gitlab.com/neucrypt/mpecdsa/-/blob/release/src/mul.rs.
        let mut public_gadget: Vec<Scalar<Secp256k1>> = Vec::with_capacity(BATCH_SIZE);
        let mut counter = nonce.clone();
        for _ in 0..BATCH_SIZE {
            counter = counter + Scalar::<Secp256k1>::from(1);
            public_gadget.push(hash_as_scalar(&scalar_to_bytes(&counter), session_id));
        }

        let mul_sender = MulSender {
            public_gadget,
            ote_sender,
        };

        (mul_sender, output, encoded)
    }

    pub fn init_phase3(receiver: &Receiver, session_id: &[u8], output: &Vec<ReceiverOutput>, challenge: &Vec<HashOutput>) -> (Vec<ReceiverHashData>, Vec<HashOutput>) {
        OTESender::init_phase3(receiver, session_id, output, challenge)
    }

    pub fn init_phase4(receiver: &Receiver, session_id: &[u8], output: &Vec<ReceiverOutput>, hashes: &Vec<ReceiverHashData>, sender_hashes: &Vec<SenderHashData>) -> Result<(),ErrorOT> {
        OTESender::init_phase4(receiver, session_id, output, hashes, sender_hashes)
    }

    // PROTOCOL

    pub fn run(&self, session_id: &[u8], input: &Vec<Scalar<Secp256k1>>, u: &Vec<PRGOutput>, verify_x: &FieldElement, verify_t: &Vec<FieldElement>) -> Result<(Vec<Scalar<Secp256k1>>, Vec<Vec<Scalar<Secp256k1>>>, Vec<Vec<Scalar<Secp256k1>>>, HashOutput, Vec<Scalar<Secp256k1>>, Vec<Scalar<Secp256k1>>), ErrorOT> {

        // RANDOMIZED MULTIPLICATION

        // Step 1 - No action for the sender.

        // Step 2 - We sample the pads a_tilde and the check values a_hat.
        // We also set the correlation for the OT protocol.

        // There are L pads and L check_values.
        let mut a_tilde: Vec<Scalar<Secp256k1>> = Vec::with_capacity(L);
        let mut a_hat: Vec<Scalar<Secp256k1>> = Vec::with_capacity(L);
        for _ in 0..L {
            a_tilde.push(Scalar::<Secp256k1>::random());
            a_hat.push(Scalar::<Secp256k1>::random());
        }

        // For the correlation, let us first explain the case L = 1.
        // In this case, there are actually two correlations: one is
        // made with BATCH_SIZE copies of a_tilde and the other with
        // BATCH_SIZE copies of a_hat. We use two correlations in order
        // to get two outputs, as in DKLs19. Both of them will be used
        // in the OT extension with the same choice bits from the receiver.
        //
        // Now, by DKLs23, we hardcoded l = 1 in DKLs19. At the same time,
        // DKLs23 has its parameter L. To adapt the old protocol, we repeat
        // Step 2 in DKLs23 L times, so in the end we get 2*L correlations.
        let mut correlation_tilde: Vec<Vec<Scalar<Secp256k1>>> = Vec::with_capacity(L);
        let mut correlation_hat: Vec<Vec<Scalar<Secp256k1>>> = Vec::with_capacity(L);
        for i in 0..L {
            let correlation_tilde_i = vec![a_tilde[i].clone();BATCH_SIZE];
            let correlation_hat_i = vec![a_hat[i].clone();BATCH_SIZE];

            correlation_tilde.push(correlation_tilde_i);
            correlation_hat.push(correlation_hat_i);
        }

        // Step 3 - We execute the OT protocol.

        // It is here that we use the "force-reuse" technique that
        // DKLs23 mentions on page 8. As they say: "Alice performs the
        // steps of the protocol for each input in her vector, but uses
        // a single batch of Bob’s OT instances for all of them,
        // concatenating the corresponding OT payloads to form one batch
        // of payloads with lengths proportionate to her input vector length."
        //
        // Hence, the data u, verify_x and verify_t sent by the receiver will
        // be used 2*L times with the 2*L correlations from the previous step.

        // These are the sender's output from the OT protocol.
        let mut z_tilde: Vec<Vec<Scalar<Secp256k1>>> = Vec::with_capacity(L);
        let mut z_hat: Vec<Vec<Scalar<Secp256k1>>> = Vec::with_capacity(L);

        // These values will be used by the receiver to finish the OT protocol.
        let mut tau_tilde: Vec<Vec<Scalar<Secp256k1>>> = Vec::with_capacity(L);
        let mut tau_hat: Vec<Vec<Scalar<Secp256k1>>> = Vec::with_capacity(L);

        for i in 0..L {
            
            //Running OT protocol for tilde values.
            let result = self.ote_sender.run(session_id, &correlation_tilde[i], u, verify_x, verify_t);
    
            match result {
                Ok((output,tau)) => {
                    z_tilde.push(output);
                    tau_tilde.push(tau);
                },
                Err(error) => { 
                    return Err(error);
                },
            }

            //Running OT protocol for hat values.
            let result = self.ote_sender.run(session_id, &correlation_hat[i], u, verify_x, verify_t);
    
            match result {
                Ok((output,tau)) => {
                    z_hat.push(output);
                    tau_hat.push(tau);
                },
                Err(error) => { 
                    return Err(error);
                },
            }
        }

        // Step 4 - We compute the shared random values.

        // As a transcript from Step 3, we use u, verify_x and verify_t.
        let transcript = [u.concat(), verify_x.to_vec(), verify_t.concat()].concat();

        // At this point, the constant L from DKLs23 behaves as the
        // constant l from DKLs19.
        let mut chi_tilde: Vec<Scalar<Secp256k1>> = Vec::with_capacity(L);
        let mut chi_hat: Vec<Scalar<Secp256k1>> = Vec::with_capacity(L);
        for i in 0..L {
            
            // We compute the salts according to i and the varible.
            let salt_tilde = [&(1usize).to_be_bytes(), &i.to_be_bytes(), session_id].concat();
            let salt_hat = [&(2usize).to_be_bytes(), &i.to_be_bytes(), session_id].concat();

            chi_tilde.push(hash_as_scalar(&transcript, &salt_tilde));
            chi_hat.push(hash_as_scalar(&transcript, &salt_hat));
        }

        // Step 5 - We compute the verification value.
        // We use Section 5.1 in DKLs23 for an optimization of the
        // protocol in DKLs19.

        // We have to compute a matrix r and a vector u.
        // Only a hash of r will be sent to the receiver,
        // so we'll compute r directly in bytes.
        // The variable below saves each row of r in bytes.
        let mut rows_r_as_bytes: Vec<Vec<u8>> = Vec::with_capacity(L);
        let mut verify_u: Vec<Scalar<Secp256k1>> = Vec::with_capacity(L);
        for i in 0..L {

            // We compute the i-th row of the matrix r in bytes.
            let mut entries_as_bytes: Vec<Vec<u8>> = Vec::with_capacity(BATCH_SIZE);
            for j in 0..BATCH_SIZE {
                let entry = (&chi_tilde[i] * &z_tilde[i][j]) + (&chi_hat[i] * &z_hat[i][j]);
                let entry_as_bytes = scalar_to_bytes(&entry);
                entries_as_bytes.push(entry_as_bytes);
            }
            let row_i_as_bytes = entries_as_bytes.concat();
            rows_r_as_bytes.push(row_i_as_bytes);

            // We compute the i-th entry of the vector u.
            let entry = (&chi_tilde[i] * &a_tilde[i]) + (&chi_hat[i] * &a_hat[i]);
            verify_u.push(entry);
        }
        let r_as_bytes = rows_r_as_bytes.concat();

        // We transform r into a hash.
        let verify_r: HashOutput = hash(&r_as_bytes, session_id);

        // Step 6 - No action for the sender.

        // INPUT AND ADJUSTMENT

        // Step 7 - We compute the difference gamma_A.

        let mut gamma: Vec<Scalar<Secp256k1>> = Vec::with_capacity(L);
        for i in 0..L {
            let difference = &input[i] - &a_tilde[i];
            gamma.push(difference);
        }

        // Step 8 - Finally, we compute the protocol's output.
        // Recall that we hardcoded gamma_B = 0.

        let mut output: Vec<Scalar<Secp256k1>> = Vec::with_capacity(L);
        for i in 0..L {
            let mut summation = Scalar::<Secp256k1>::zero();
            for j in 0..BATCH_SIZE {
                summation = summation + (&self.public_gadget[j] * &z_tilde[i][j]);
            }
            output.push(summation);
        }

        // We now return all values.

        // output is kept by the sender as the protocol's output.
        // tau_tilde and tau_hat are transmitted to the receiver
        // for him to finish the OT protocol.
        // verify_r and verify_u are also trasmitted so that the
        // receiver can verify the multiplication.
        // gamma is transmitted so that the receiver can finish
        // the protocol.

        Ok((output, tau_tilde, tau_hat, verify_r, verify_u, gamma))
    }

}

impl MulReceiver {

    // INITIALIZE

    // As in DKLs19 (https://eprint.iacr.org/2019/523.pdf), the initialization of the
    // multiplication protocol is the same as for our OT extension protocol.
    // Thus, we repeat the phases from the file ot_extension.rs.
    // The only difference is that we include the sampling for the public gadget vector.

    pub fn init_phase1(session_id: &[u8]) -> (Sender, DLogProof, Scalar<Secp256k1>) {
        let (sender, proof) = OTEReceiver::init_phase1(session_id);

        // For the choice of the public gadget vector, we will use the same approach
        // as in https://gitlab.com/neucrypt/mpecdsa/-/blob/release/src/mul.rs.
        // We sample a nonce that will be used by both parties to compute a common vector.
        let nonce = Scalar::<Secp256k1>::random();

        (sender, proof, nonce)
    }

    pub fn init_phase2(sender: &Sender, session_id: &[u8], encoded: &Vec<Point<Secp256k1>>, nonce: &Scalar<Secp256k1>) -> (MulReceiver, Vec<SenderHashData>, Vec<HashOutput>, Vec<HashOutput>) {
        let (ote_receiver, hashes, double, challenge) = OTEReceiver::init_phase2(sender, session_id, encoded);

        // We compute the public gadget vector from the nonce, in the same way as in
        // https://gitlab.com/neucrypt/mpecdsa/-/blob/release/src/mul.rs.
        let mut public_gadget: Vec<Scalar<Secp256k1>> = Vec::with_capacity(BATCH_SIZE);
        let mut counter = nonce.clone();
        for _ in 0..BATCH_SIZE {
            counter = counter + Scalar::<Secp256k1>::from(1);
            public_gadget.push(hash_as_scalar(&scalar_to_bytes(&counter), session_id));
        }

        let mul_receiver = MulReceiver {
            public_gadget,
            ote_receiver,
        };

        (mul_receiver, hashes, double, challenge)
    }

    pub fn init_phase3(sender: &Sender, double: &Vec<HashOutput>, response: &Vec<HashOutput>) -> Result<(),ErrorOT> {
        OTEReceiver::init_phase3(sender, double, response)
    }

    // PROTOCOL

    pub fn run_phase1(&self, session_id: &[u8]) -> (Vec<bool>, Scalar<Secp256k1>, Vec<PRGOutput>, Vec<Scalar<Secp256k1>>, Vec<Scalar<Secp256k1>>, Vec<PRGOutput>, FieldElement, Vec<FieldElement>) {

        // RANDOMIZED MULTIPLICATION

        // Step 1 - We sample the choice bits and compute the pad b_tilde.

        // Since we are hardcoding gamma_B = 0, b_tilde will serve as the
        // number b that the receiver inputs into the protocol. Hence, we
        // will denote b_tilde simply as b.

        let mut choice_bits: Vec<bool> = Vec::with_capacity(BATCH_SIZE);
        let mut b = Scalar::<Secp256k1>::zero();
        for i in 0..BATCH_SIZE {
            let current_bit: bool = rand::random();
            if current_bit {
                b = b + &self.public_gadget[i];
            }
            choice_bits.push(current_bit);
        }

        // Step 2 - No action for the receiver.

        // Step 3 (Incomplete) - We start the OT extension protocol.

        // Note that this protocol has one more round, so the receiver
        // cannot get the output immediately. This will only be computed
        // at the beginning of the next phase for the receiver.

        let (extended_seeds, u, verify_x, verify_t) = self.ote_receiver.run_phase1(session_id, &choice_bits);

        // Step 4 - We compute the shared random values.

        // As a transcript from Step 3, we use u, verify_x and verify_t.
        let transcript = [u.concat(), verify_x.to_vec(), verify_t.concat()].concat();

        // At this point, the constant L from DKLs23 behaves as the
        // constant l from DKLs19.
        let mut chi_tilde: Vec<Scalar<Secp256k1>> = Vec::with_capacity(L);
        let mut chi_hat: Vec<Scalar<Secp256k1>> = Vec::with_capacity(L);
        for i in 0..L {
            
            // We compute the salts according to i and the varible.
            let salt_tilde = [&(1usize).to_be_bytes(), &i.to_be_bytes(), session_id].concat();
            let salt_hat = [&(2usize).to_be_bytes(), &i.to_be_bytes(), session_id].concat();

            chi_tilde.push(hash_as_scalar(&transcript, &salt_tilde));
            chi_hat.push(hash_as_scalar(&transcript, &salt_hat));
        }

        // Step 5 - No action for the receiver, but he will receive
        // some values for the next step, so we stop here.

        // The first five values are kept for the next phase.
        // The last three are trasmitted to the sender.  
        (choice_bits, b, extended_seeds, chi_tilde, chi_hat, u, verify_x, verify_t)
    }

    pub fn run_phase2(&self, session_id: &[u8], choice_bits: &Vec<bool>, extended_seeds: &Vec<PRGOutput>, tau_tilde: &Vec<Vec<Scalar<Secp256k1>>>, tau_hat: &Vec<Vec<Scalar<Secp256k1>>>, chi_tilde: &Vec<Scalar<Secp256k1>>, chi_hat: &Vec<Scalar<Secp256k1>>, verify_r: &HashOutput, verify_u: &Vec<Scalar<Secp256k1>>, b: Scalar<Secp256k1>, gamma_sender: &Vec<Scalar<Secp256k1>>) -> Result<Vec<Scalar<Secp256k1>>,ErrorOT> {

        // Step 3 (Conclusion) - We conclude the OT protocol.

        // The sender applied the protocol 2*L times with our data,
        // so we will have 2*L outputs. They are separated in two
        // variables: z_tilde and z_hat.

        let mut z_tilde: Vec<Vec<Scalar<Secp256k1>>> = Vec::with_capacity(L);
        let mut z_hat: Vec<Vec<Scalar<Secp256k1>>> = Vec::with_capacity(L);
        for i in 0..L {
            let output_tilde = self.ote_receiver.run_phase2(session_id, choice_bits, extended_seeds, &tau_tilde[i]);
            let output_hat = self.ote_receiver.run_phase2(session_id, choice_bits, extended_seeds, &tau_hat[i]);

            z_tilde.push(output_tilde);
            z_hat.push(output_hat);
        }

        // Step 6 - We verify if the data sent by the sender is consistent.
        
        // We use Section 5.1 in DKLs23 for an optimization of the
        // protocol in DKLs19.

        // We have to compute a matrix r and a vector u.
        // Only a hash of r will be sent to us so we'll
        // reconstruct r directly in bytes.
        // The variable below saves each row of r in bytes.
        let mut rows_r_as_bytes: Vec<Vec<u8>> = Vec::with_capacity(L);
        for i in 0..L {

            // We compute the i-th row of the matrix r in bytes.
            let mut entries_as_bytes: Vec<Vec<u8>> = Vec::with_capacity(BATCH_SIZE);
            for j in 0..BATCH_SIZE {

                // The entry depends on the choice bits.
                let mut entry = (-(&chi_tilde[i] * &z_tilde[i][j])) - (&chi_hat[i] * &z_hat[i][j]);
                if choice_bits[j] {
                    entry = entry + &verify_u[i];
                }

                let entry_as_bytes = scalar_to_bytes(&entry);
                entries_as_bytes.push(entry_as_bytes);
            }
            let row_i_as_bytes = entries_as_bytes.concat();
            rows_r_as_bytes.push(row_i_as_bytes);
        }
        let r_as_bytes = rows_r_as_bytes.concat();

        // We transform r into a hash.
        let expected_verify_r: HashOutput = hash(&r_as_bytes, session_id);

        // We compare the values.
        if *verify_r != expected_verify_r {
            return Err(ErrorOT::new("Sender cheated in multiplication protocol!"));
        }

        // INPUT AND ADJUSTMENT

        // Step 7 - No action for the receiver.
        // (Remember that we hardcoded gamma_B = 0.)

        // Step 8 - Finally, we compute the protocol's output.
        // Recall that we hardcoded gamma_B = 0.

        let mut output: Vec<Scalar<Secp256k1>> = Vec::with_capacity(L);
        for i in 0..L {
            let mut summation = Scalar::<Secp256k1>::zero();
            for j in 0..BATCH_SIZE {
                summation = summation + (&self.public_gadget[j] * &z_tilde[i][j]);
            }
            let final_sum = (&b * &gamma_sender[i]) + summation; 
            output.push(final_sum);
        }

        Ok(output)
    }

}