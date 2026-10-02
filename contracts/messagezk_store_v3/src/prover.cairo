//! The zkmsg v3 send statement as a SNIP-36 virtual-transaction contract.
//!
//! `prove_send` only ever runs inside the virtual Starknet OS on the sender's
//! device. Its private arguments — the sender's scan pubkey, KEM key digest,
//! membership secret `m`, leaf index and Merkle path — never reach the chain:
//! the sequencer sees only the proof and its facts. The statement is:
//!
//!   * the leaf poseidon([LEAF_V3, R, kem_digest, poseidon([MEMBER_V3, m])])
//!     is under `merkle_root`.
//!
//! Only Poseidon and the path fold: no elliptic-curve step, so membership
//! rests on Poseidon preimage resistance (believed post-quantum) instead of
//! the discrete log of the public scan key (v2). The scan private key no
//! longer enters the proof at all. `R` and `kem_digest` are witness values
//! bound by the leaf; `m` is what only the member knows.
//!
//! `commitment` and `ephemeral_pubkey` pass through, bound by the single
//! L2→L1 message: `to_address` 0 and payload
//! `[store, commitment, ephemeral_pubkey, merkle_root, content_hash]`, whose
//! hash the store recomputes from the proof facts (unchanged from v2).

use crate::merkle::verify_proof;

/// Domain tag of the membership commitment.
pub const MEMBER_V3: felt252 = 'zkmsg-member-v3';
/// Leaf domain tag. A four-element leaf cannot be read as a two-element
/// internal node or a three-element v2 leaf.
pub const LEAF_V3: felt252 = 'zkmsg-leaf-v3';

#[starknet::interface]
pub trait IZkmsgSendProverV3<T> {
    fn prove_send(
        ref self: T,
        store: felt252,
        content_hash: felt252,
        commitment: felt252,
        ephemeral_pubkey: felt252,
        merkle_root: felt252,
        sender_scan_pub: felt252,
        sender_kem_digest: felt252,
        member_secret: felt252,
        sender_leaf_index: u32,
        sender_path: Span<felt252>,
    );
}

/// m_commit = poseidon_hash_many([MEMBER_V3, m]).
pub fn member_commit(member_secret: felt252) -> felt252 {
    core::poseidon::poseidon_hash_span(array![MEMBER_V3, member_secret].span())
}

/// leaf = poseidon_hash_many([LEAF_V3, R, kem_digest, m_commit]).
pub fn leaf_v3(scan_pubkey: felt252, kem_digest: felt252, m_commit: felt252) -> felt252 {
    core::poseidon::poseidon_hash_span(array![LEAF_V3, scan_pubkey, kem_digest, m_commit].span())
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
pub mod ZkmsgSendProverV3 {
    use starknet::syscalls::send_message_to_l1_syscall;
    use starknet::SyscallResultTrait;
    use super::{leaf_v3, member_commit, send_payload, verify_proof};

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl ZkmsgSendProverV3Impl of super::IZkmsgSendProverV3<ContractState> {
        fn prove_send(
            ref self: ContractState,
            store: felt252,
            content_hash: felt252,
            commitment: felt252,
            ephemeral_pubkey: felt252,
            merkle_root: felt252,
            sender_scan_pub: felt252,
            sender_kem_digest: felt252,
            member_secret: felt252,
            sender_leaf_index: u32,
            sender_path: Span<felt252>,
        ) {
            let leaf = leaf_v3(sender_scan_pub, sender_kem_digest, member_commit(member_secret));
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
