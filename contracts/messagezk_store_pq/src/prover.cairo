//! The zkmsg v2 send statement as a SNIP-36 virtual-transaction contract.
//!
//! `prove_send` only ever runs inside the virtual Starknet OS on the sender's
//! device. Its private arguments — the sender's scan private key, KEM key
//! digest, leaf index and Merkle path — never reach the chain: the sequencer
//! sees only the proof and its facts. The statement is:
//!
//!   * the sender's leaf poseidon([LEAF_V2, x(priv·G), kem_digest]) is under
//!     `merkle_root`.
//!
//! That is all. v1 also proved the recipient's membership and derived the
//! commitment from ECDH inside the proof; in v2 the commitment is a tag from
//! the hybrid ML-KEM-768 + ECDH key schedule, which cannot be proven here
//! cheaply, so `commitment` and `ephemeral_pubkey` pass through. They are still
//! bound: the public result leaves as the single L2→L1 message of the virtual
//! block, `to_address` 0 and payload
//! `[store, commitment, ephemeral_pubkey, merkle_root, content_hash]`, and the
//! store recomputes `poseidon([prover, 0, 5, ...payload])` from the proof
//! facts. A proof authorises exactly one (commitment, ciphertext) pair.

use core::ec::{EcPointTrait, EcStateTrait, stark_curve};
use crate::merkle::verify_proof;

/// Leaf domain tag. Keeps a leaf from ever being read as an internal node
/// (`hash_pair` is poseidon over two felts; a leaf is over three).
pub const LEAF_V2: felt252 = 'zkmsg-leaf-v2';

#[starknet::interface]
pub trait IZkmsgSendProverV2<T> {
    fn prove_send(
        ref self: T,
        store: felt252,
        content_hash: felt252,
        commitment: felt252,
        ephemeral_pubkey: felt252,
        merkle_root: felt252,
        sender_scan_priv: felt252,
        sender_kem_digest: felt252,
        sender_leaf_index: u32,
        sender_path: Span<felt252>,
    );
}

/// leaf = poseidon_hash_many([LEAF_V2, scan_pubkey, kem_digest]).
pub fn leaf_v2(scan_pubkey: felt252, kem_digest: felt252) -> felt252 {
    core::poseidon::poseidon_hash_span(array![LEAF_V2, scan_pubkey, kem_digest].span())
}

pub fn scan_pubkey_of(scan_priv: felt252) -> felt252 {
    let gen = EcPointTrait::new_nz(stark_curve::GEN_X, stark_curve::GEN_Y).unwrap();
    let mut state = EcStateTrait::init();
    state.add_mul(scan_priv, gen);
    let (x, _) = state.finalize_nz().expect('point at infinity').coordinates();
    x
}

/// The payload `prove_send` emits; shared with the store and the tests.
pub fn send_payload(
    store: felt252,
    commitment: felt252,
    ephemeral_pubkey: felt252,
    merkle_root: felt252,
    content_hash: felt252,
) -> Array<felt252> {
    array![store, commitment, ephemeral_pubkey, merkle_root, content_hash]
}

#[starknet::contract]
pub mod ZkmsgSendProverV2 {
    use starknet::syscalls::send_message_to_l1_syscall;
    use starknet::SyscallResultTrait;
    use super::{leaf_v2, scan_pubkey_of, send_payload, verify_proof};

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl ZkmsgSendProverV2Impl of super::IZkmsgSendProverV2<ContractState> {
        fn prove_send(
            ref self: ContractState,
            store: felt252,
            content_hash: felt252,
            commitment: felt252,
            ephemeral_pubkey: felt252,
            merkle_root: felt252,
            sender_scan_priv: felt252,
            sender_kem_digest: felt252,
            sender_leaf_index: u32,
            sender_path: Span<felt252>,
        ) {
            let leaf = leaf_v2(scan_pubkey_of(sender_scan_priv), sender_kem_digest);
            assert(
                verify_proof(merkle_root, leaf, sender_leaf_index, sender_path),
                'sender not a member',
            );
            send_message_to_l1_syscall(
                0,
                send_payload(store, commitment, ephemeral_pubkey, merkle_root, content_hash)
                    .span(),
            )
                .unwrap_syscall();
        }
    }
}
