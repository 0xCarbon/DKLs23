use crate::protocols::Party;
use crate::protocols::PartyStore;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;

pub fn get_party_store(party: &Party) -> PartyStore {
    let key_share: [u8; 32] = party.poly_point.to_repr().into();
    let party_index = party.party_index;
    let pubkey: [u8; 33] = party
        .pk
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    let zk_seed = party.zk_seed;
    let chain_code = party.derivation_data.chain_code;

    PartyStore {
        key_share,
        party_index,
        pubkey,
        zk_seed,
        chain_code,
    }
}
