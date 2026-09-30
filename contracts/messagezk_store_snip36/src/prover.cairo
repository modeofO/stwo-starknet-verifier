//! The zkmsg send statement as a SNIP-36 virtual-transaction contract.
//!
//! `prove_send` only ever runs inside the virtual Starknet OS on the sender's
//! device. Its calldata is the witness — scan private key, ephemeral private
//! key, both Merkle paths — and never reaches the chain: the sequencer sees
//! only the proof and its facts. The statement is fixtures/messagezk_scan's,
//! with the same crypto:
//!
//!   * the sender's scan pubkey x(priv·G) and the recipient's scan pubkey are
//!     both leaves under `merkle_root`;
//!   * ephemeral_pubkey = x(eph·G);
//!   * commitment = hades(x(eph·R), 0, 2)[0].
//!
//! The public result leaves as the single L2→L1 message of the virtual block:
//! `to_address` 0 (an L1 address must fit 160 bits, so the store is bound in
//! the payload instead) and payload
//! `[store, commitment, ephemeral_pubkey, merkle_root, content_hash]`.
//! The proof facts carry `poseidon([prover, 0, 5, ...payload])`, which the
//! store recomputes from public data. Binding `content_hash` means a proof
//! authorises exactly one ciphertext, which the lane-1 route never did.

use core::ec::{EcPointTrait, EcStateTrait, stark_curve};
use core::poseidon::hades_permutation;
use crate::merkle::verify_proof;

#[starknet::interface]
pub trait IZkmsgSendProver<T> {
    fn prove_send(
        ref self: T,
        store: felt252,
        content_hash: felt252,
        merkle_root: felt252,
        sender_scan_priv: felt252,
        recipient_scan_pub: felt252,
        ephemeral_priv: felt252,
        sender_leaf_index: u32,
        recipient_leaf_index: u32,
        sender_path: Span<felt252>,
        recipient_path: Span<felt252>,
    );
}

fn ec_mul_x(scalar: felt252, point_x: Option<felt252>) -> felt252 {
    let point = match point_x {
        Option::Some(x) => EcPointTrait::new_nz_from_x(x).expect('bad recipient pubkey'),
        Option::None => EcPointTrait::new_nz(stark_curve::GEN_X, stark_curve::GEN_Y).unwrap(),
    };
    let mut state = EcStateTrait::init();
    state.add_mul(scalar, point);
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
pub mod ZkmsgSendProver {
    use starknet::syscalls::send_message_to_l1_syscall;
    use starknet::SyscallResultTrait;
    use super::{ec_mul_x, hades_permutation, send_payload, verify_proof};

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl ZkmsgSendProverImpl of super::IZkmsgSendProver<ContractState> {
        fn prove_send(
            ref self: ContractState,
            store: felt252,
            content_hash: felt252,
            merkle_root: felt252,
            sender_scan_priv: felt252,
            recipient_scan_pub: felt252,
            ephemeral_priv: felt252,
            sender_leaf_index: u32,
            recipient_leaf_index: u32,
            sender_path: Span<felt252>,
            recipient_path: Span<felt252>,
        ) {
            let sender_scan_pub = ec_mul_x(sender_scan_priv, Option::None);
            assert(
                verify_proof(merkle_root, sender_scan_pub, sender_leaf_index, sender_path),
                'sender not a member',
            );
            assert(
                verify_proof(merkle_root, recipient_scan_pub, recipient_leaf_index, recipient_path),
                'recipient not a member',
            );

            let ephemeral_pubkey = ec_mul_x(ephemeral_priv, Option::None);
            let shared_x = ec_mul_x(ephemeral_priv, Option::Some(recipient_scan_pub));
            let (commitment, _, _) = hades_permutation(shared_x, 0, 2);

            send_message_to_l1_syscall(
                0,
                send_payload(store, commitment, ephemeral_pubkey, merkle_root, content_hash)
                    .span(),
            )
                .unwrap_syscall();
        }
    }
}
