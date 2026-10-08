//! poseidon-many 0x1 0x2 ... -> prints poseidon_hash_many([..]) as 0x-hex.
use starknet_crypto::{poseidon_hash_many, Felt};

fn main() {
    let felts: Vec<Felt> = std::env::args()
        .skip(1)
        .map(|a| Felt::from_hex(&a).expect("hex felt"))
        .collect();
    println!("{:#x}", poseidon_hash_many(&felts));
}
