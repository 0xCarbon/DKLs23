use k256::{AffinePoint, Scalar};
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::protocols::derivation::DerivData;
use crate::protocols::dkg::compute_eth_address;
use crate::protocols::re_key::re_key_with_rng;
use crate::protocols::{Parameters, Party, PartyIndex};

#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CompactExport {
    #[zeroize(skip)]
    pub version: u8,
    #[zeroize(skip)]
    pub parameters: Parameters,
    #[zeroize(skip)]
    pub party_index: PartyIndex,
    pub session_id: Vec<u8>,
    pub poly_point: Scalar,
    #[zeroize(skip)]
    pub pk: AffinePoint,
    pub derivation_data: DerivData,
    pub reconstruction_seed: [u8; crate::SECURITY as usize],
}

impl CompactExport {
    pub fn reconstruct(&self) -> Result<Party, &'static str> {
        if self.version != 1 {
            return Err("unsupported CompactExport version");
        }
        let mut rng = rand::rngs::StdRng::from_seed(self.reconstruction_seed);
        let (mut parties, _) = re_key_with_rng(
            &self.parameters,
            &self.session_id,
            &self.poly_point,
            None,
            &mut rng,
        );

        let idx = (self.party_index.as_u8() - 1) as usize;
        if idx >= parties.len() {
            return Err("party_index out of bounds");
        }

        let mut party = parties.swap_remove(idx);
        party.pk = self.pk;
        party.poly_point = self.poly_point;
        party.derivation_data = self.derivation_data.clone();
        party.eth_address = compute_eth_address(&self.pk);
        Ok(party)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::re_key::re_key;
    use crate::utilities::rng;
    use k256::elliptic_curve::Field;
    use rand::RngExt;

    #[test]
    fn test_compact_export_roundtrip() {
        let parameters = Parameters {
            threshold: 2,
            share_count: 3,
        };
        let session_id = rng::get_rng().random::<[u8; crate::utilities::ID_LEN]>();
        let secret_key = Scalar::random(&mut rng::get_rng());
        let (parties, _) = re_key(&parameters, &session_id, &secret_key, None);

        let original = &parties[0];
        let compact = original
            .compact_export()
            .expect("compact_export should succeed");

        assert_eq!(compact.version, 1);
        assert_eq!(compact.party_index, original.party_index);
        assert_eq!(compact.session_id, original.session_id);
        assert_eq!(compact.poly_point, original.poly_point);
        assert_eq!(compact.pk, original.pk);

        let reconstructed = compact.reconstruct().expect("reconstruct should succeed");
        assert_eq!(reconstructed.poly_point, original.poly_point);
        assert_eq!(reconstructed.pk, original.pk);
        assert_eq!(reconstructed.party_index, original.party_index);
        assert_eq!(reconstructed.session_id, original.session_id);
    }

    #[test]
    fn test_compact_export_size() {
        let parameters = Parameters {
            threshold: 2,
            share_count: 3,
        };
        let session_id = rng::get_rng().random::<[u8; crate::utilities::ID_LEN]>();
        let secret_key = Scalar::random(&mut rng::get_rng());
        let (parties, _) = re_key(&parameters, &session_id, &secret_key, None);

        let original = &parties[0];
        let compact = original
            .compact_export()
            .expect("compact_export should succeed");

        let compact_bytes = bincode::serialize(&compact).expect("serialize compact");
        let party_bytes = bincode::serialize(original).expect("serialize party");

        const MAX_COMPACT_EXPORT_SIZE: usize = 300;
        assert!(
            compact_bytes.len() < MAX_COMPACT_EXPORT_SIZE,
            "CompactExport should be < {} bytes, got {}",
            MAX_COMPACT_EXPORT_SIZE,
            compact_bytes.len()
        );
        assert!(
            compact_bytes.len() * 10 < party_bytes.len(),
            "CompactExport ({}) should be >10x smaller than Party ({})",
            compact_bytes.len(),
            party_bytes.len()
        );
    }
}
