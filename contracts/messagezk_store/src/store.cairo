//! MessageStore v3 — messagezk's consumer contract on the lane-1 route.
//!
//! v2 (the live Sepolia `0x03b105fc…e041`) delegates proof checking to a
//! swappable `IStwoVerifier` that is currently UNSET (junk accepted) and
//! whose `set_verifier` is un-gated — the rug vector the handoff doc warns
//! about. v3 closes both: the verification route is the lane-1
//! `StwoFactRegistry` fact check, and everything it depends on —
//! `(registry, program_hash, inner_root)` — is pinned at construction.
//! No owner, no setters, immutable by design; a route change is a
//! redeploy, visibly a different contract.
//!
//! A send's fact is `compute_fact(program_hash, [commitment,
//! ephemeral_pubkey, merkle_root], inner_root)` (stwo_fact_binding) — the
//! same tuple, in the same order, that fixtures/messagezk_scan RETURNS as
//! its bootloader outputs. Registered facts are world-readable, so a
//! consumed-commitment guard stops third parties replaying someone
//! else's tuple with junk content.

use starknet::ContractAddress;

#[starknet::interface]
pub trait IMessageStoreV3<TContractState> {
    /// Registers the caller under `handle` with their scan pubkey as the
    /// tree leaf. One registration per address; handles are first-come.
    fn register(ref self: TContractState, handle: felt252, scan_pubkey: felt252);

    /// Publishes a message. The (commitment, ephemeral_pubkey, merkle_root)
    /// tuple must have a registered lane-1 fact; `merkle_root` must be the
    /// current root or one of the last 20 (proof generation takes minutes —
    /// registrations landing in between must not invalidate the send).
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
    /// The pinned verification route (for consumer/auditor inspection).
    fn verification_route(self: @TContractState) -> (ContractAddress, felt252, Span<u32>);
}

#[starknet::interface]
pub trait IStwoFactRegistry<TContractState> {
    fn is_valid(self: @TContractState, fact: felt252) -> bool;
}

#[starknet::contract]
pub mod MessageStoreV3 {
    use starknet::{ContractAddress, get_caller_address};
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use core::num::traits::Zero;
    use stwo_fact_binding::compute_fact;
    use crate::merkle::{TREE_DEPTH, hash_pair, zero_hash};
    use super::{IStwoFactRegistryDispatcher, IStwoFactRegistryDispatcherTrait};

    const ROOT_HISTORY_SIZE: u8 = 20;
    const MAX_LEAVES: felt252 = 1048576; // 2^20

    #[storage]
    struct Storage {
        // Pinned verification route (immutable after construction).
        registry: ContractAddress,
        program_hash: felt252,
        inner_root: Map<u8, u32>,
        // User registry + incremental Merkle tree (ported from v2).
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
    fn constructor(
        ref self: ContractState,
        registry: ContractAddress,
        program_hash: felt252,
        inner_root: [u32; 8],
    ) {
        assert(!registry.is_zero(), 'zero registry');
        assert(program_hash != 0, 'zero program hash');
        self.registry.write(registry);
        self.program_hash.write(program_hash);
        let mut i: u8 = 0;
        for word in inner_root.span() {
            self.inner_root.write(i, *word);
            i += 1;
        }
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

    fn read_inner_root(self: @ContractState) -> [u32; 8] {
        [
            self.inner_root.read(0), self.inner_root.read(1), self.inner_root.read(2),
            self.inner_root.read(3), self.inner_root.read(4), self.inner_root.read(5),
            self.inner_root.read(6), self.inner_root.read(7),
        ]
    }

    #[abi(embed_v0)]
    impl StoreImpl of super::IMessageStoreV3<ContractState> {
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

            let fact = compute_fact(
                self.program_hash.read(),
                array![commitment, ephemeral_pubkey, merkle_root].span(),
                read_inner_root(@self),
            );
            let registry = IStwoFactRegistryDispatcher {
                contract_address: self.registry.read(),
            };
            assert(registry.is_valid(fact), 'no proof for this send');

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

        fn verification_route(self: @ContractState) -> (ContractAddress, felt252, Span<u32>) {
            let [w0, w1, w2, w3, w4, w5, w6, w7] = read_inner_root(self);
            (
                self.registry.read(),
                self.program_hash.read(),
                array![w0, w1, w2, w3, w4, w5, w6, w7].span(),
            )
        }
    }
}
