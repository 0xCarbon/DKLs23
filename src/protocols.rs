use curv::elliptic::curves::{Secp256k1, Scalar, Point};
use curv::cryptographic_primitives::secret_sharing::Polynomial;

use crate::utilities::hashes::HashOutput;
use crate::utilities::proofs::DLogProof;

#[derive(Debug, Clone)]
pub struct Parameters {
    pub threshold: u16,     //t
    pub share_count: u16,   //n
}

//This struct represents a party after key generation ready to sign a message.
#[derive(Debug, Clone)]
pub struct Party {
    pub parameters: Parameters,
    pub party_index: u16,

    session_id: Vec<u8>,            //DECIDIR O TAMANHO DISSO. DECIDIR COMO CRIAR E USAR OS SESSIONS IDS (veja o arquivo de hash)
    poly_point: Scalar<Secp256k1>,  //It behaves as the secrect key share
    pk: Point<Secp256k1>,           //Public key
}

#[derive(Debug, Clone)]
pub struct Abort {
    pub index: u16,
    pub description: String,
}

//This struct is used during key generation
#[derive(Debug, Clone)]
pub struct ProofCommitment {
    index: u16,
    proof: DLogProof,
    commitment: HashOutput,
}

impl Parameters {
    pub fn new(threshold: u16, share_count: u16) -> Parameters {
        Parameters {
            threshold,
            share_count, 
        }
    }
}

impl Party {
    pub fn new(parameters: &Parameters, party_index: u16, session_id: &[u8], poly_point: &Scalar<Secp256k1>, pk: &Point<Secp256k1>) -> Party {
        Party {
            parameters: parameters.clone(),
            party_index,
            session_id: Vec::from(session_id),
            poly_point: poly_point.clone(),
            pk: pk.clone(),
        }
    }
}

impl Abort {
    pub fn new(index: u16, description: &str) -> Abort {
        Abort { 
            index,
            description: String::from(description),
        }
    }
}

impl ProofCommitment {
    pub fn new(index: u16, proof: DLogProof, commitment:HashOutput) -> ProofCommitment {
        ProofCommitment {
            index,
            proof,
            commitment,
        }
    }
}

///////////////////////////////////////////////////////////////////////////////

/// DISTRIBUTED KEY GENERATION (DKG)
/// Implementation of Protocol 9.1 in https://eprint.iacr.org/2023/602.pdf, as instructed
/// in DKLs23 (https://eprint.iacr.org/2023/765.pdf).

/// STEPS
/// We implement each step of the protocol.

/// Step 1 - Generate random polynomial of degree t-1.
pub fn dkg_step1(parameters: &Parameters) -> Polynomial<Secp256k1> {
    Polynomial::sample_exact(parameters.threshold - 1)
}

/// Step 2 - Evaluate the polynomial from the previous step at every point.
pub fn dkg_step2(parameters: &Parameters, polynomial: Polynomial<Secp256k1>) -> Vec<Scalar<Secp256k1>> {
    let mut points: Vec<Scalar<Secp256k1>> = Vec::with_capacity(parameters.share_count as usize);

    for j in 1..=parameters.share_count {
        points.push(polynomial.evaluate(&Scalar::<Secp256k1>::from(j)));
    }
        
    points
}

/// Step 3 - Compute poly_point (p(i) in the paper) and the corresponding "public key" (P(i) in the paper).
/// It also commits to a zero-knowledge proof that p(i) is the discrete logarithm of P(i).
/// The session id is used for the proof.
pub fn dkg_step3(party_index: u16, session_id: &[u8], poly_fragments: &Vec<Scalar<Secp256k1>>) -> (Scalar<Secp256k1>, ProofCommitment) {
    let poly_point: Scalar<Secp256k1> = poly_fragments.iter().sum();

    let (proof, commitment) = DLogProof::prove_commit(&poly_point, session_id);
    let proof_commitment = ProofCommitment::new(party_index, proof, commitment);

    (poly_point, proof_commitment)
}

/// Step 4 is a communication round (see the description below).

/// Step 5 - Each party validates the other proofs. They also recover the "public keys fragements" from the other parties.
/// Finally, a consistency check is done. In the process, the publick key is computed (Step 6).
pub fn dkg_step5(parameters: &Parameters, party_index: u16, session_id: &[u8], proofs_commitments: &Vec<ProofCommitment>) -> Result<Point<Secp256k1>,Abort> {
        
    let mut commited_points: Vec<Point<Secp256k1>> = Vec::with_capacity(parameters.share_count as usize); //The "public key fragments"

    //Verify the proofs and gather the commited points        
    for party_j in proofs_commitments {
        if party_j.index != party_index {
            let verification = DLogProof::decommit_verify(&party_j.proof, &party_j.commitment, session_id);
            if !verification {
                return Err(Abort::new(party_index, &format!("Proof from Party {} failed!", party_j.index)));
            }
        }
        commited_points.push(party_j.proof.point.clone());
    }

    //Initializes what will be the public key
    let mut pk = Point::<Secp256k1>::zero();

    //Verify that all points come from the same polyonimal. To do so, for each contiguous set of parties,
    //perform Shamir reconstruction in the exponent and check if the results agree.
    //The common value calculated is the public key.
    for i in 1..=(parameters.share_count - parameters.threshold + 1) {
        let mut current_pk = Point::<Secp256k1>::zero();
        for j in i..=(i + parameters.threshold - 1) {

            //We find the Lagrange coefficient l(j) corresponding to j (and the contiguous set of parties).
            //It is such that the sum of l(j) * p(j) over all j is p(0), where p is the polyonimal from Step 3.
            let mut lj_numerator = Scalar::<Secp256k1>::from(1);
            let mut lj_denominator = Scalar::<Secp256k1>::from(1);
            for k in i..=(i + parameters.threshold - 1) {
                if k != j {
                    lj_numerator = lj_numerator * Scalar::<Secp256k1>::from(k);
                    lj_denominator = lj_denominator * (Scalar::<Secp256k1>::from(k) - Scalar::<Secp256k1>::from(j));
                }
            }
            let lj = lj_numerator * (lj_denominator.invert().unwrap());
                
            let lj_times_point = lj * &commited_points[(j-1) as usize]; //j-1 because index starts at 0
            current_pk = current_pk + lj_times_point;
        }
        //The first value is taken as the public key. It should coincide with the next values.
        if i == 1 {
            pk = current_pk;
        } else if pk != current_pk {
            return Err(Abort::new(party_index, &format!("Verification for public key reconstruction failed in iteration {}", i)));
        }
    }
    Ok(pk)
}

/// Step 6 was done during the previous step.

/// PHASES
/// We group the steps in phases. A phase consists of all steps that can be executed in order without the need of communication.
/// Phases should be intercalated with communication rounds: broadcasts and/or private messages containg the session id.

/// Phase 1 = Steps 1 and 2
/// Input: Parameters for the key generation
/// Output: Evaluation of a random polynomial at every party index
pub fn dkg_phase1(parameters: &Parameters) -> Vec<Scalar<Secp256k1>> {
    let secret_polynomial = dkg_step1(parameters);
    dkg_step2(parameters, secret_polynomial)
}

/// Communication round 1
/// Party i keeps the i-th point and sends the j-th point to Party j for j != i.
/// At the end, Party i should have received all fragements indexed by i.
/// They should add up to p(i), where p is a polynomial not depending on i.

/// Phase 2 = Step 3
/// Input: Fragments received from communication and session id
/// Output: p(i) and a proof of discrete logarithm with commitment
pub fn dkg_phase2(party_index: u16, session_id: &[u8], poly_fragments: &Vec<Scalar<Secp256k1>>) -> (Scalar<Secp256k1>, ProofCommitment) {
    dkg_step3(party_index, session_id, poly_fragments)
}

/// Communication round 2
/// Party i broadcasts his commitment to the proof and receive the other commitments.

/// Communication round 3
/// We execute Step 4 of the protocol: after receving all commitments, each party broadcasts his proof.

/// Phase 3 = Steps 5 and 6 + Creation of Party
/// Input: Proofs and commitments received from communication + parameters, party index, session id, poly_point
/// Output: The resulting Party (but there may be an abortion during the process)
pub fn dkg_phase3 (parameters: &Parameters, party_index: u16, session_id: &[u8], poly_point: &Scalar<Secp256k1>, proofs_commitments: &Vec<ProofCommitment>) -> Result<Party,Abort> {
    let result_step5 = dkg_step5(parameters, party_index, session_id, proofs_commitments);
    let pk: Point<Secp256k1>;

    match result_step5 {
        Ok(point) => { pk = point; },
        Err(abort) => { return Err(abort); }
    }

    Ok(Party::new(parameters, party_index, session_id, poly_point, &pk))
}

///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {

    use super::*;
    use rand::Rng;

    //DISTRIBUTED KEY GENERATION

    #[test]
    //2-of-2 scenario.
    fn test_dkg_t2_n2() {
        let parameters = Parameters::new(2, 2);
        let session_id = rand::thread_rng().gen::<[u8; 32]>();

        //Phase 1
        let p1_phase1 = dkg_phase1(&parameters); //p1 = Party 1
        let p2_phase1 = dkg_phase1(&parameters); //p2 = Party 2

        assert_eq!(p1_phase1.len(), 2);
        assert_eq!(p2_phase1.len(), 2);

        //Communication round 1
        let p1_poly_fragments = vec![p1_phase1[0].clone(), p2_phase1[0].clone()];
        let p2_poly_fragments = vec![p1_phase1[1].clone(), p2_phase1[1].clone()];

        //Phase 2
        let p1_phase2 = dkg_phase2(1, &session_id, &p1_poly_fragments);
        let p2_phase2 = dkg_phase2(2, &session_id, &p2_poly_fragments);

        let (p1_poly_point, p1_proof_commitment) = p1_phase2;
        let (p2_poly_point, p2_proof_commitment) = p2_phase2;

        //Communication rounds 2 and 3
        //For tests, they can be done simultaneously
        let proofs_commitments = vec![p1_proof_commitment, p2_proof_commitment];

        //Phase 3
        let p1 = dkg_phase3(&parameters, 1, &session_id, &p1_poly_point, &proofs_commitments);
        let p2 = dkg_phase3(&parameters, 2, &session_id, &p2_poly_point, &proofs_commitments);

        assert!(p1.is_ok());
        assert!(p2.is_ok());
    }

    #[test]
    //3-of-5 scenario
    fn test_dkg_t3_n5() {
        let parameters = Parameters::new(3, 5);
        let session_id = rand::thread_rng().gen::<[u8; 32]>();

        //Phase 1
        //Matrix of polynomial points
        let mut phase1: Vec<Vec<Scalar<Secp256k1>>> = Vec::with_capacity(parameters.share_count as usize);
        for _ in 0..parameters.share_count {
            let party_phase1 = dkg_phase1(&parameters);
            assert_eq!(party_phase1.len(), parameters.share_count as usize);
            phase1.push(party_phase1);
        }
    
        //Communication round 1
        //We transpose the matrix
        let mut poly_fragments = vec![Vec::<Scalar<Secp256k1>>::with_capacity(parameters.share_count as usize); parameters.share_count as usize];
        for row_i in phase1 {
            for j in 0..parameters.share_count as usize {
                poly_fragments[j].push(row_i[j].clone());
            }
        }

        //Phase 2 + Communication rounds 2 and 3
        let mut poly_points: Vec<Scalar<Secp256k1>> = Vec::with_capacity(parameters.share_count as usize);
        let mut proofs_commitments: Vec<ProofCommitment> = Vec::with_capacity(parameters.share_count as usize);
        for i in 0..parameters.share_count {
            let party_i_phase2 = dkg_phase2(i+1, &session_id, &poly_fragments[i as usize]);
            let (party_i_poly_point, party_i_proof_commitment) = party_i_phase2;
            poly_points.push(party_i_poly_point);
            proofs_commitments.push(party_i_proof_commitment);
        }

        //Phase 3
        let mut parties: Vec<Result<Party,Abort>> = Vec::with_capacity(parameters.share_count as usize);
        for i in 0..parameters.share_count {
            parties.push(dkg_phase3(&parameters, i+1, &session_id, &poly_points[i as usize], &proofs_commitments));
        }

        for party in parties {
            assert!(party.is_ok());
        }
    } 

    #[test]
    //We remove the randomness from Phase 1. This allows us to compute the public key.
    fn test1_dkg_t2_n2_fixed_polynomials() {
        let parameters = Parameters::new(2, 2);
        let session_id = rand::thread_rng().gen::<[u8; 32]>();

        //We will define the fragments directly
        let p1_poly_fragments = vec![Scalar::<Secp256k1>::from(1), Scalar::<Secp256k1>::from(3)];
        let p2_poly_fragments = vec![Scalar::<Secp256k1>::from(2), Scalar::<Secp256k1>::from(4)];

        //In this case, the secret polynomial p is of degree 1 and satisfies p(1) = 1+3 = 4 and p(2) = 2+4 = 6
        //In particular, we must have p(0) = 2, which is the "hypothetical" secret key.
        //For this reason, we should expect the public key to be 2 * generator.

        //Phase 2
        let p1_phase2 = dkg_phase2(1, &session_id, &p1_poly_fragments);
        let p2_phase2 = dkg_phase2(2, &session_id, &p2_poly_fragments);

        let (p1_poly_point, p1_proof_commitment) = p1_phase2;
        let (p2_poly_point, p2_proof_commitment) = p2_phase2;

        //Communication rounds 2 and 3
        //For tests, they can be done simultaneously
        let proofs_commitments = vec![p1_proof_commitment, p2_proof_commitment];

        //Phase 3
        let p1 = dkg_phase3(&parameters, 1, &session_id, &p1_poly_point, &proofs_commitments);
        let p2 = dkg_phase3(&parameters, 2, &session_id, &p2_poly_point, &proofs_commitments);

        assert!(p1.is_ok());
        assert!(p2.is_ok());

        let p1 = p1.unwrap();
        let p2 = p2.unwrap();
        
        //Verifying the public key
        let expected_pk = Point::<Secp256k1>::generator() * Scalar::<Secp256k1>::from(2); 
        assert_eq!(p1.pk, expected_pk);
        assert_eq!(p2.pk, expected_pk);
    }

    #[test]
    fn test2_dkg_t2_n2_fixed_polynomials() {
        let parameters = Parameters::new(2, 2);
        let session_id = rand::thread_rng().gen::<[u8; 32]>();

        //We will define the fragments directly
        let p1_poly_fragments = vec![Scalar::<Secp256k1>::from(12), Scalar::<Secp256k1>::from(-2)];
        let p2_poly_fragments = vec![Scalar::<Secp256k1>::from(2), Scalar::<Secp256k1>::from(3)];

        //In this case, the secret polynomial p is of degree 1 and satisfies p(1) = 12+(-2) = 10 and p(2) = 2+3 = 5
        //In particular, we must have p(0) = 15, which is the "hypothetical" secret key.
        //For this reason, we should expect the public key to be 15 * generator.

        //Phase 2
        let p1_phase2 = dkg_phase2(1, &session_id, &p1_poly_fragments);
        let p2_phase2 = dkg_phase2(2, &session_id, &p2_poly_fragments);

        let (p1_poly_point, p1_proof_commitment) = p1_phase2;
        let (p2_poly_point, p2_proof_commitment) = p2_phase2;

        //Communication rounds 2 and 3
        let proofs_commitments = vec![p1_proof_commitment, p2_proof_commitment];

        //Phase 3
        let p1 = dkg_phase3(&parameters, 1, &session_id, &p1_poly_point, &proofs_commitments);
        let p2 = dkg_phase3(&parameters, 2, &session_id, &p2_poly_point, &proofs_commitments);

        assert!(p1.is_ok());
        assert!(p2.is_ok());

        let p1 = p1.unwrap();
        let p2 = p2.unwrap();
        
        //Verifying the public key
        let expected_pk = Point::<Secp256k1>::generator() * Scalar::<Secp256k1>::from(15); 
        assert_eq!(p1.pk, expected_pk);
        assert_eq!(p2.pk, expected_pk);
    }

    #[test]
    fn test_dkg_t3_n5_fixed_polynomials() {
        let parameters = Parameters::new(3, 5);
        let session_id = rand::thread_rng().gen::<[u8; 32]>();

        //We will define the fragments directly
        let poly_fragments = vec![vec![Scalar::from(5),Scalar::from(1),Scalar::from(-5),Scalar::from(-2),Scalar::from(-3)],
                                                               vec![Scalar::from(9),Scalar::from(3),Scalar::from(-4),Scalar::from(-5),Scalar::from(-7)], 
                                                               vec![Scalar::from(15),Scalar::from(7),Scalar::from(-1),Scalar::from(-10),Scalar::from(-13)], 
                                                               vec![Scalar::from(23),Scalar::from(13),Scalar::from(4),Scalar::from(-17),Scalar::from(-21)], 
                                                               vec![Scalar::from(33),Scalar::from(21),Scalar::from(11),Scalar::from(-26),Scalar::from(-31)], 
                                                            ];

        //In this case, the secret polynomial p is of degree 2 and satisfies: 
        //p(1) = -4, p(2) = -4, p(3) = -2, p(4) = 2, p(5) = 8.
        //Hence we must have p(x) = x^2 - 3x - 2.
        //In particular, we must have p(0) = -2, which is the "hypothetical" secret key.
        //For this reason, we should expect the public key to be (-2) * generator.

        //Phase 2 + Communication rounds 2 and 3
        let mut poly_points: Vec<Scalar<Secp256k1>> = Vec::with_capacity(parameters.share_count as usize);
        let mut proofs_commitments: Vec<ProofCommitment> = Vec::with_capacity(parameters.share_count as usize);
        for i in 0..parameters.share_count {
            let party_i_phase2 = dkg_phase2(i+1, &session_id, &poly_fragments[i as usize]);
            let (party_i_poly_point, party_i_proof_commitment) = party_i_phase2;
            poly_points.push(party_i_poly_point);
            proofs_commitments.push(party_i_proof_commitment);
        }

        //Phase 3
        let mut results: Vec<Result<Party,Abort>> = Vec::with_capacity(parameters.share_count as usize);
        for i in 0..parameters.share_count {
            results.push(dkg_phase3(&parameters, i+1, &session_id, &poly_points[i as usize], &proofs_commitments));
        }

        let mut parties: Vec<Party> = Vec::with_capacity(parameters.share_count as usize);
        for result in results {
            match result {
                Ok(party) => { parties.push(party); },
                Err(abort) => { panic!("Party {} aborted: {:?}", abort.index, abort.description); },
            }
        }
        
        //Verifying the public key
        let expected_pk = Point::<Secp256k1>::generator() * Scalar::<Secp256k1>::from(-2);
        for party in parties {
            assert_eq!(party.pk, expected_pk);
        }
    }

}