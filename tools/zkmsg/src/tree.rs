//! Depth-20 incremental Poseidon Merkle tree — the exact client-side
//! mirror of MessageStoreV3's on-chain tree (contracts/messagezk_store/
//! src/store.cairo `insert_leaf` / `zero_hash`): zero leaf = 0,
//! zero_hash(l) = hash_pair(zero_hash(l-1), zero_hash(l-1)), sparse
//! node storage, path = sibling per level bottom-up.
//!
//! The client uses it to (a) rebuild the tree from on-chain registration
//! events for local verification, and (b) fabricate valid witness trees
//! for tests and the milestone-1 gate.

use std::collections::HashMap;

use starknet_types_core::felt::Felt;

use crate::crypto::hash_pair;

pub const TREE_DEPTH: u32 = 20;

pub struct MerkleTree {
    nodes: HashMap<(u32, u32), Felt>,
    next_leaf: u32,
    zeros: Vec<Felt>,
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleTree {
    pub fn new() -> Self {
        let mut zeros = vec![Felt::ZERO];
        for level in 1..=TREE_DEPTH as usize {
            let prev = zeros[level - 1];
            zeros.push(hash_pair(&prev, &prev));
        }
        Self { nodes: HashMap::new(), next_leaf: 0, zeros }
    }

    fn node(&self, level: u32, index: u32) -> Felt {
        *self.nodes.get(&(level, index)).unwrap_or(&self.zeros[level as usize])
    }

    /// Inserts a leaf and returns its index — the contract's walk verbatim.
    pub fn insert(&mut self, leaf: Felt) -> u32 {
        let leaf_index = self.next_leaf;
        assert!(leaf_index < 1 << TREE_DEPTH, "tree is full");
        self.nodes.insert((0, leaf_index), leaf);

        let mut index = leaf_index;
        let mut current = leaf;
        for level in 0..TREE_DEPTH {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            let sibling = self.node(level, sibling_index);
            current = if index % 2 == 0 {
                hash_pair(&current, &sibling)
            } else {
                hash_pair(&sibling, &current)
            };
            index /= 2;
            self.nodes.insert((level + 1, index), current);
        }

        self.next_leaf = leaf_index + 1;
        leaf_index
    }

    pub fn root(&self) -> Felt {
        self.node(TREE_DEPTH, 0)
    }

    #[allow(dead_code)]
    pub fn n_leaves(&self) -> u32 {
        self.next_leaf
    }

    /// Sibling path bottom-up — the contract's `get_merkle_path`.
    pub fn path(&self, leaf_index: u32) -> Vec<Felt> {
        let mut path = Vec::with_capacity(TREE_DEPTH as usize);
        let mut index = leaf_index;
        for level in 0..TREE_DEPTH {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            path.push(self.node(level, sibling_index));
            index /= 2;
        }
        path
    }
}

/// Folds a path — the circuit's `verify_merkle` (and the contract's
/// `verify_proof`), used in tests and pre-send sanity checks.
pub fn fold_path(leaf: &Felt, leaf_index: u32, path: &[Felt]) -> Felt {
    assert_eq!(path.len(), TREE_DEPTH as usize, "path must have 20 elements");
    let mut current = *leaf;
    let mut index = leaf_index;
    for sibling in path {
        current = if index % 2 == 0 {
            hash_pair(&current, sibling)
        } else {
            hash_pair(sibling, &current)
        };
        index /= 2;
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_root_is_zero_hash_20() {
        let tree = MerkleTree::new();
        // zero_hash(20) by direct fold.
        let mut z = Felt::ZERO;
        for _ in 0..TREE_DEPTH {
            z = hash_pair(&z, &z);
        }
        assert_eq!(tree.root(), z);
    }

    #[test]
    fn single_leaf_path_verifies() {
        let mut tree = MerkleTree::new();
        let leaf = Felt::from(42u32);
        let index = tree.insert(leaf);
        assert_eq!(index, 0);
        assert_eq!(fold_path(&leaf, index, &tree.path(index)), tree.root());
    }

    #[test]
    fn two_leaves_both_paths_verify() {
        let mut tree = MerkleTree::new();
        let (a, b) = (Felt::from(42u32), Felt::from(99u32));
        let ia = tree.insert(a);
        let ib = tree.insert(b);
        assert_eq!((ia, ib), (0, 1));
        assert_eq!(fold_path(&a, ia, &tree.path(ia)), tree.root());
        assert_eq!(fold_path(&b, ib, &tree.path(ib)), tree.root());
    }

    /// The milestone-1 gate tree: leaves = pubkeys of scalars 5 and 7 —
    /// the root must equal the value the gate proof carried (also the
    /// value starknet.js computed; addendum doc).
    #[test]
    fn milestone1_gate_tree_root() {
        let mut tree = MerkleTree::new();
        tree.insert(crate::crypto::ec_mul_gen_x(&Felt::from(5u32)));
        tree.insert(crate::crypto::ec_mul_gen_x(&Felt::from(7u32)));
        assert_eq!(
            tree.root(),
            Felt::from_hex("0x225510ca702ebc9c1dad406f8cd08923fd3f8aea5a0ed58eb753265421522cd")
                .unwrap(),
        );
    }
}
