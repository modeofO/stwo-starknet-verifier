//! The zkmsg v4 send statement: v3 membership plus a rate-limit nullifier.
//!
//! Runs only inside the virtual Starknet OS on the sender's device. On top
//! of v3's "the leaf poseidon([LEAF_V3, R, kem_digest, poseidon([MEMBER_V3,
//! m])]) is under `merkle_root`", it proves
//!
//!   * `slot < quota`, and
//!   * nullifier = poseidon([NULLIFIER_V4, store, m, epoch, slot]).
//!
//! `m` and `slot` stay private, so the nullifier names neither the member nor
//! which of their `quota` slots this is; the store refuses a nullifier twice.
//! A member therefore gets at most `quota` sends per epoch, and nobody can
//! tell two sends of one member from sends of two members.
//!
//! `epoch` and `quota` are public and travel in the payload. The prover does
//! not trust them: the store recomputes the message hash with the epoch IT
//! derives from the facts' base block number and the quota IT was built
//! with, so a proof made with any other value simply does not match.
//!
//! The single L2->L1 message: `to_address` 0 and payload
//! `[store, commitment, ephemeral_pubkey, merkle_root, content_hash,
//!   nullifier, epoch, quota]`.
//!
//! The leaf is v3's unchanged, so registration (and the registry rebuild) is
//! v3's.

use crate::merkle::verify_proof;

/// Domain tag of the membership commitment (v3's).
pub const MEMBER_V3: felt252 = 'zkmsg-member-v3';
/// Leaf domain tag (v3's).
pub const LEAF_V3: felt252 = 'zkmsg-leaf-v3';
/// Domain tag of the rate-limit nullifier.
pub const NULLIFIER_V4: felt252 = 'zkmsg-nullifier-v4';

#[starknet::interface]
pub trait IZkmsgSendProverV4<T> {
    fn prove_send(
        ref self: T,
        store: felt252,
        content_hash: felt252,
        commitment: felt252,
        ephemeral_pubkey: felt252,
        merkle_root: felt252,
        epoch: u64,
        quota: u32,
        // --- witness ---
        sender_scan_pub: felt252,
        sender_kem_digest: felt252,
        member_secret: felt252,
        slot: u32,
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

/// nullifier = poseidon_hash_many([NULLIFIER_V4, store, m, epoch, slot]).
/// `store` separates deployments; `m` never leaves the device.
pub fn nullifier_v4(store: felt252, member_secret: felt252, epoch: u64, slot: u32) -> felt252 {
    core::poseidon::poseidon_hash_span(
        array![NULLIFIER_V4, store, member_secret, epoch.into(), slot.into()].span(),
    )
}

/// The payload `prove_send` emits; shared with the store and the tests.
pub fn send_payload_v4(
    store: felt252,
    commitment: felt252,
    ephemeral_pubkey: felt252,
    merkle_root: felt252,
    content_hash: felt252,
    nullifier: felt252,
    epoch: u64,
    quota: u32,
) -> Array<felt252> {
    array![
        store, commitment, ephemeral_pubkey, merkle_root, content_hash, nullifier, epoch.into(),
        quota.into(),
    ]
}

#[starknet::contract]
pub mod ZkmsgSendProverV4 {
    use starknet::SyscallResultTrait;
    use starknet::syscalls::send_message_to_l1_syscall;
    use super::{leaf_v3, member_commit, nullifier_v4, send_payload_v4, verify_proof};

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl ZkmsgSendProverV4Impl of super::IZkmsgSendProverV4<ContractState> {
        fn prove_send(
            ref self: ContractState,
            store: felt252,
            content_hash: felt252,
            commitment: felt252,
            ephemeral_pubkey: felt252,
            merkle_root: felt252,
            epoch: u64,
            quota: u32,
            sender_scan_pub: felt252,
            sender_kem_digest: felt252,
            member_secret: felt252,
            slot: u32,
            sender_leaf_index: u32,
            sender_path: Span<felt252>,
        ) {
            assert(slot < quota, 'slot over quota');
            let leaf = leaf_v3(sender_scan_pub, sender_kem_digest, member_commit(member_secret));
            assert(
                verify_proof(merkle_root, leaf, sender_leaf_index, sender_path),
                'sender not a member',
            );
            let nullifier = nullifier_v4(store, member_secret, epoch, slot);
            send_message_to_l1_syscall(
                0,
                send_payload_v4(
                    store,
                    commitment,
                    ephemeral_pubkey,
                    merkle_root,
                    content_hash,
                    nullifier,
                    epoch,
                    quota,
                )
                    .span(),
            )
                .unwrap_syscall();
        }
    }
}
