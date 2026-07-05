//! The messagezk scan circuit, ported for the lane-1 recursion route
//! (docs/superpowers/specs/2026-07-05-zkmsg-lane1-port-design.md).
//!
//! Source: messagezk `circuit/src/lib.cairo` (github.com/modeofO/messagezk),
//! crypto verbatim. One structural change for the privacy bootloader model:
//! program ARGUMENTS are witness and OUTPUTS are public, so the public
//! tuple `(commitment, ephemeral_pubkey, merkle_root)` moves from asserted
//! parameters to returned values — `commitment` and `ephemeral_pubkey` are
//! COMPUTED (their original assert sites become definitions), `merkle_root`
//! stays an input (the membership reference) and is echoed as an output so
//! the fact binds it.

use core::ec::{EcPointTrait, EcStateTrait, stark_curve};
use core::poseidon::{PoseidonTrait, hades_permutation};
use core::hash::HashStateTrait;

const TREE_DEPTH: u32 = 20;

// Merkle node hash: matches the on-chain tree, which uses the Poseidon
// builder (poseidon_hash_span over the two children).
fn hash_pair(left: felt252, right: felt252) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(left);
    state = state.update(right);
    state.finalize()
}

// Two-element Poseidon hash: matches the client's `computePoseidonHash(a, b)`
// (Hades permutation over the state [a, b, 2]) used to form the commitment.
fn poseidon2(a: felt252, b: felt252) -> felt252 {
    let (r, _, _) = hades_permutation(a, b, 2);
    r
}

fn verify_merkle(root: felt252, leaf: felt252, leaf_index: u32, proof: Span<felt252>) {
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

    assert(current == root, 'merkle proof invalid');
}

fn ec_mul(scalar: felt252) -> felt252 {
    let gen = EcPointTrait::new_nz(stark_curve::GEN_X, stark_curve::GEN_Y).unwrap();
    let mut state = EcStateTrait::init();
    state.add_mul(scalar, gen);
    let result = state.finalize_nz().unwrap();
    let (x, _) = result.coordinates();
    x
}

fn ecdh(priv_key: felt252, pub_x: felt252) -> felt252 {
    let pub_point = EcPointTrait::new_nz_from_x(pub_x).unwrap();
    let mut state = EcStateTrait::init();
    state.add_mul(priv_key, pub_point);
    let result = state.finalize_nz().unwrap();
    let (x, _) = result.coordinates();
    x
}

#[executable]
fn main(
    merkle_root: felt252,
    // Private inputs (bootloader witness — never public).
    sender_scan_priv: felt252,
    recipient_scan_pub: felt252,
    ephemeral_priv: felt252,
    sender_leaf_index: u32,
    recipient_leaf_index: u32,
    // Merkle proofs (20 elements each, flattened).
    s0: felt252, s1: felt252, s2: felt252, s3: felt252, s4: felt252,
    s5: felt252, s6: felt252, s7: felt252, s8: felt252, s9: felt252,
    s10: felt252, s11: felt252, s12: felt252, s13: felt252, s14: felt252,
    s15: felt252, s16: felt252, s17: felt252, s18: felt252, s19: felt252,
    r0: felt252, r1: felt252, r2: felt252, r3: felt252, r4: felt252,
    r5: felt252, r6: felt252, r7: felt252, r8: felt252, r9: felt252,
    r10: felt252, r11: felt252, r12: felt252, r13: felt252, r14: felt252,
    r15: felt252, r16: felt252, r17: felt252, r18: felt252, r19: felt252,
) -> (felt252, felt252, felt252) {
    let sender_proof = array![
        s0, s1, s2, s3, s4, s5, s6, s7, s8, s9,
        s10, s11, s12, s13, s14, s15, s16, s17, s18, s19,
    ];
    let recipient_proof = array![
        r0, r1, r2, r3, r4, r5, r6, r7, r8, r9,
        r10, r11, r12, r13, r14, r15, r16, r17, r18, r19,
    ];

    // 1. Derive sender's scan pubkey and verify sender membership.
    let sender_scan_pub = ec_mul(sender_scan_priv);
    verify_merkle(merkle_root, sender_scan_pub, sender_leaf_index, sender_proof.span());

    // 2. Verify recipient membership.
    verify_merkle(merkle_root, recipient_scan_pub, recipient_leaf_index, recipient_proof.span());

    // 3. Derive the ephemeral pubkey (public output — was an asserted arg).
    let ephemeral_pubkey = ec_mul(ephemeral_priv);

    // 4. ECDH shared secret and the commitment (public output — was asserted).
    let shared_x = ecdh(ephemeral_priv, recipient_scan_pub);
    let commitment = poseidon2(shared_x, 0);

    (commitment, ephemeral_pubkey, merkle_root)
}
