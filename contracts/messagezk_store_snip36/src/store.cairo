//! MessageStore on the SNIP-36 route.
//!
//! MessageStoreV3 (../messagezk_store) with one change: `send_message` no
//! longer asks a fact registry whether a wrapped proof was verified in earlier
//! transactions. The sequencer verifies the proof natively (SNIP-36), and this
//! contract reads what was proven from the transaction's own `proof_facts`:
//!
//!   [PROOF1, VIRTUAL_SNOS, program_hash, VIRTUAL_SNOS0, base_block_number,
//!    base_block_hash, os_config_hash, n_l2_to_l1_messages, message_hash...]
//!
//! The OS itself enforces the version markers, the program-hash allowlist,
//! the config hash and the base block hash before any contract runs. What is
//! left here is binding: exactly one proven message, sent by the pinned
//! prover contract, whose payload is this store and this send.
//!
//! Registration, the depth-20 tree, the 20-root history and both events are
//! V3's, verbatim, so clients sync and scan the two stores the same way. No
//! owner, no setters: a route change is a redeploy.

use starknet::ContractAddress;

#[starknet::interface]
pub trait IMessageStoreSnip36<TContractState> {
    /// Registers the caller under `handle` with their scan pubkey as the
    /// tree leaf. One registration per address; handles are first-come.
    fn register(ref self: TContractState, handle: felt252, scan_pubkey: felt252);

    /// Publishes a message. The transaction must carry a SNIP-36 proof whose
    /// single L2->L1 message is the prover's attestation of exactly this
    /// (commitment, ephemeral_pubkey, merkle_root, content); `merkle_root`
    /// must be the current root or one of the last 20.
    fn send_message(
        ref self: TContractState,
        commitment: felt252,
        ephemeral_pubkey: felt252,
        merkle_root: felt252,
        content: ByteArray,
    );

    fn get_user(self: @TContractState, handle: felt252) -> (ContractAddress, felt252, u32);
    fn get_merkle_root(self: @TContractState) -> felt252;
    fn get_merkle_path(self: @TContractState, leaf_index: u32) -> Array<felt252>;
    fn get_leaf_index(self: @TContractState, owner: ContractAddress) -> u32;
    fn get_scan_pubkey(self: @TContractState, owner: ContractAddress) -> felt252;
    fn is_known_root(self: @TContractState, root: felt252) -> bool;
    fn n_messages(self: @TContractState) -> u64;
    /// The pinned prover contract (for consumer/auditor inspection).
    fn prover(self: @TContractState) -> ContractAddress;
}

/// Poseidon over the Cairo serialization of `content` — what the prover's
/// payload carries in place of the ciphertext itself.
pub fn content_hash(content: @ByteArray) -> felt252 {
    let mut serialized: Array<felt252> = array![];
    content.serialize(ref serialized);
    core::poseidon::poseidon_hash_span(serialized.span())
}

/// The message hash the virtual OS writes into the proof facts:
/// poseidon([from_address, to_address, payload_size, ...payload]).
pub fn message_hash(from_address: felt252, to_address: felt252, payload: Span<felt252>) -> felt252 {
    let mut preimage: Array<felt252> = array![from_address, to_address, payload.len().into()];
    for item in payload {
        preimage.append(*item);
    }
    core::poseidon::poseidon_hash_span(preimage.span())
}

pub const PROOF_VERSION_V1: felt252 = 'PROOF1';
pub const VIRTUAL_SNOS: felt252 = 'VIRTUAL_SNOS';
pub const VIRTUAL_OS_OUTPUT_VERSION: felt252 = 'VIRTUAL_SNOS0';

#[starknet::contract]
pub mod MessageStoreSnip36 {
    use starknet::{ContractAddress, SyscallResultTrait, get_caller_address, get_contract_address};
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::syscalls::get_execution_info_v3_syscall;
    use core::num::traits::Zero;
    use crate::merkle::{TREE_DEPTH, hash_pair, zero_hash};
    use crate::prover::send_payload;
    use super::{
        PROOF_VERSION_V1, VIRTUAL_OS_OUTPUT_VERSION, VIRTUAL_SNOS, content_hash, message_hash,
    };

    const ROOT_HISTORY_SIZE: u8 = 20;
    const MAX_LEAVES: felt252 = 1048576; // 2^20

    // proof_facts layout (see the module doc).
    const FACTS_LEN_ONE_MESSAGE: u32 = 9;
    const IDX_VERSION: u32 = 0;
    const IDX_VARIANT: u32 = 1;
    const IDX_OUTPUT_VERSION: u32 = 3;
    const IDX_N_MESSAGES: u32 = 7;
    const IDX_MESSAGE_HASH: u32 = 8;

    #[storage]
    struct Storage {
        // Pinned verification route (immutable after construction).
        prover: ContractAddress,
        // User registry + incremental Merkle tree (V3, verbatim).
        registered: Map<ContractAddress, bool>,
        scan_pubkeys: Map<ContractAddress, felt252>,
        handles: Map<felt252, ContractAddress>,
        leaf_indices: Map<ContractAddress, u32>,
        tree_nodes: Map<felt252, felt252>,
        next_leaf_index: u32,
        merkle_root: felt252,
        root_history: Map<u8, felt252>,
        root_history_index: u8,
        // Messages.
        message_nonce: u64,
        consumed_commitments: Map<felt252, bool>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        UserRegistered: UserRegistered,
        MessageSent: MessageSent,
    }

    #[derive(Drop, starknet::Event)]
    struct UserRegistered {
        #[key]
        owner: ContractAddress,
        handle: felt252,
        scan_pubkey: felt252,
        leaf_index: u32,
    }

    #[derive(Drop, starknet::Event)]
    struct MessageSent {
        #[key]
        commitment: felt252,
        ephemeral_pubkey: felt252,
        nonce: u64,
        content: ByteArray,
    }

    #[constructor]
    fn constructor(ref self: ContractState, prover: ContractAddress) {
        assert(!prover.is_zero(), 'zero prover');
        self.prover.write(prover);
    }

    fn tree_key(level: u32, index: u32) -> felt252 {
        let level_felt: felt252 = level.into();
        let index_felt: felt252 = index.into();
        level_felt * MAX_LEAVES + index_felt
    }

    fn read_node(self: @ContractState, level: u32, index: u32) -> felt252 {
        let value = self.tree_nodes.read(tree_key(level, index));
        if value == 0 {
            zero_hash(level)
        } else {
            value
        }
    }

    /// v2's incremental insert, verbatim: write the leaf, walk up
    /// recomputing parents, rotate the root into the history ring.
    fn insert_leaf(ref self: ContractState, leaf: felt252) -> u32 {
        let leaf_index = self.next_leaf_index.read();
        assert(leaf_index < 1048576, 'tree is full');

        self.tree_nodes.write(tree_key(0, leaf_index), leaf);

        let mut current_index = leaf_index;
        let mut current_hash = leaf;
        let mut level: u32 = 0;
        while level < TREE_DEPTH {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            let sibling_hash = read_node(@self, level, sibling_index);
            let parent_hash = if current_index % 2 == 0 {
                hash_pair(current_hash, sibling_hash)
            } else {
                hash_pair(sibling_hash, current_hash)
            };
            current_index = current_index / 2;
            self.tree_nodes.write(tree_key(level + 1, current_index), parent_hash);
            current_hash = parent_hash;
            level += 1;
        }

        self.merkle_root.write(current_hash);
        let history_index = self.root_history_index.read();
        self.root_history.write(history_index, current_hash);
        self.root_history_index.write((history_index + 1) % ROOT_HISTORY_SIZE);
        self.next_leaf_index.write(leaf_index + 1);

        leaf_index
    }

    fn is_known_root_internal(self: @ContractState, root: felt252) -> bool {
        if root == self.merkle_root.read() {
            return true;
        }
        let mut i: u8 = 0;
        let mut found = false;
        while i != ROOT_HISTORY_SIZE {
            if self.root_history.read(i) == root && root != 0 {
                found = true;
                break;
            }
            i += 1;
        }
        found
    }

    /// Checks the transaction's proof facts attest exactly this send.
    fn assert_proven(
        self: @ContractState,
        commitment: felt252,
        ephemeral_pubkey: felt252,
        merkle_root: felt252,
        content: @ByteArray,
    ) {
        let facts = get_execution_info_v3_syscall().unwrap_syscall().tx_info.proof_facts;
        assert(facts.len() == FACTS_LEN_ONE_MESSAGE, 'expected one proven message');
        // The OS already rejects anything else; checked again so a future
        // proof variant cannot be read with this layout.
        assert(*facts.at(IDX_VERSION) == PROOF_VERSION_V1, 'unsupported proof version');
        assert(*facts.at(IDX_VARIANT) == VIRTUAL_SNOS, 'not a virtual OS proof');
        assert(*facts.at(IDX_OUTPUT_VERSION) == VIRTUAL_OS_OUTPUT_VERSION, 'unknown OS output');
        assert(*facts.at(IDX_N_MESSAGES) == 1, 'expected one proven message');

        let this: felt252 = get_contract_address().into();
        let payload = send_payload(
            this, commitment, ephemeral_pubkey, merkle_root, content_hash(content),
        );
        let expected = message_hash(self.prover.read().into(), 0, payload.span());
        assert(*facts.at(IDX_MESSAGE_HASH) == expected, 'no proof for this send');
    }

    #[abi(embed_v0)]
    impl StoreImpl of super::IMessageStoreSnip36<ContractState> {
        fn register(ref self: ContractState, handle: felt252, scan_pubkey: felt252) {
            let caller = get_caller_address();
            assert(!self.registered.read(caller), 'already registered');
            assert(handle != 0, 'zero handle');
            assert(scan_pubkey != 0, 'zero scan pubkey');
            assert(self.handles.read(handle).is_zero(), 'handle taken');

            self.registered.write(caller, true);
            self.scan_pubkeys.write(caller, scan_pubkey);
            self.handles.write(handle, caller);
            let leaf_index = insert_leaf(ref self, scan_pubkey);
            self.leaf_indices.write(caller, leaf_index);
            self.emit(UserRegistered { owner: caller, handle, scan_pubkey, leaf_index });
        }

        fn send_message(
            ref self: ContractState,
            commitment: felt252,
            ephemeral_pubkey: felt252,
            merkle_root: felt252,
            content: ByteArray,
        ) {
            assert(!self.consumed_commitments.read(commitment), 'commitment consumed');
            assert(is_known_root_internal(@self, merkle_root), 'unknown merkle root');
            assert_proven(@self, commitment, ephemeral_pubkey, merkle_root, @content);

            self.consumed_commitments.write(commitment, true);
            let nonce = self.message_nonce.read();
            self.message_nonce.write(nonce + 1);
            self.emit(MessageSent { commitment, ephemeral_pubkey, nonce, content });
        }

        fn get_user(self: @ContractState, handle: felt252) -> (ContractAddress, felt252, u32) {
            let owner = self.handles.read(handle);
            assert(!owner.is_zero(), 'unknown handle');
            (owner, self.scan_pubkeys.read(owner), self.leaf_indices.read(owner))
        }

        fn get_merkle_root(self: @ContractState) -> felt252 {
            self.merkle_root.read()
        }

        fn get_merkle_path(self: @ContractState, leaf_index: u32) -> Array<felt252> {
            let mut path: Array<felt252> = array![];
            let mut current_index = leaf_index;
            let mut level: u32 = 0;
            while level < TREE_DEPTH {
                let sibling_index = if current_index % 2 == 0 {
                    current_index + 1
                } else {
                    current_index - 1
                };
                path.append(read_node(self, level, sibling_index));
                current_index = current_index / 2;
                level += 1;
            }
            path
        }

        fn get_leaf_index(self: @ContractState, owner: ContractAddress) -> u32 {
            // Guard the Map default (0) being indistinguishable from the
            // legitimate first leaf.
            assert(self.registered.read(owner), 'not registered');
            self.leaf_indices.read(owner)
        }

        fn get_scan_pubkey(self: @ContractState, owner: ContractAddress) -> felt252 {
            assert(self.registered.read(owner), 'not registered');
            self.scan_pubkeys.read(owner)
        }

        fn is_known_root(self: @ContractState, root: felt252) -> bool {
            is_known_root_internal(self, root)
        }

        fn n_messages(self: @ContractState) -> u64 {
            self.message_nonce.read()
        }

        fn prover(self: @ContractState) -> ContractAddress {
            self.prover.read()
        }
    }
}
