use crate::protocols::load_party::load_party;
use crate::protocols::Parameters;
use crate::protocols::Party;
use crate::protocols::PartyStore;

pub fn load_party_store(party_store: &PartyStore) -> Party {
    let key_share = &party_store.key_share;
    let party_index = party_store.party_index;
    let pubkey = &party_store.pubkey;
    let zk_seed = &party_store.zk_seed;

    load_party(
        &Parameters {
            threshold: 2,
            share_count: 2,
        },
        &vec![0],
        key_share,
        party_index,
        pubkey,
        zk_seed,
        None,
    )
}
