/// Spike 2 fixture: a Poseidon hash chain of length `n`.
///
/// Deliberately simple but representative: Poseidon is the hash used by the
/// messagezk circuit (Merkle proofs + commitment), and `n` lets us scale the
/// trace size to see how verifier cost responds.
#[executable]
fn main(n: u32) -> felt252 {
    let mut h: felt252 = 0;
    let mut i: u32 = 0;
    while i != n {
        h = core::poseidon::poseidon_hash_span(array![h, i.into()].span());
        i += 1;
    }
    h
}
