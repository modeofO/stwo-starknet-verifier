//! Depth-20 incremental Poseidon Merkle helpers — verbatim port of
//! messagezk `contracts/src/merkle_tree.cairo` (github.com/modeofO/
//! messagezk). The zkmsg circuit (fixtures/messagezk_scan) folds paths
//! with the same `hash_pair`, and the Rust client (tools/zkmsg) mirrors
//! both against shared golden vectors.

use core::poseidon::PoseidonTrait;
use core::hash::HashStateTrait;

pub fn hash_pair(left: felt252, right: felt252) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(left);
    state = state.update(right);
    state.finalize()
}

pub const TREE_DEPTH: u32 = 20;

pub fn zero_hash(level: u32) -> felt252 {
    if level == 0 {
        return 0;
    }
    let prev = zero_hash(level - 1);
    hash_pair(prev, prev)
}

pub fn verify_proof(root: felt252, leaf: felt252, leaf_index: u32, proof: Span<felt252>) -> bool {
    assert(proof.len() == TREE_DEPTH, 'proof must have 20 elements');
    let mut current = leaf;
    let mut index = leaf_index;
    let mut i: u32 = 0;

    while i < TREE_DEPTH {
        let sibling = *proof.at(i);
        if index % 2 == 0 {
            current = hash_pair(current, sibling);
        } else {
            current = hash_pair(sibling, current);
        }
        index = index / 2;
        i += 1;
    };

    current == root
}
