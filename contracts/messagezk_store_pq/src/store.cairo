//! zkmsg v2 MessageStore on the SNIP-36 route.
//!
//! ../messagezk_store_snip36's MessageStoreSnip36 with the v2 identity
//! (docs/superpowers/specs/2026-10-01-zkmsg-pq-hybrid-kem-design.md):
//!
//!   * `register` also takes the caller's ML-KEM-768 encapsulation key (1184
//!     bytes). The store keeps only its digest, poseidon over the ByteArray
//!     serialization (the same hash as `content_hash`); the key itself is
//!     published once, in `UserRegistered`.
//!   * The tree leaf is poseidon([LEAF_V2, scan_pubkey, kem_digest]).
//!   * `send_message` is unchanged in shape; `content` is `kem_ct ‖ blob`.
//!
//! The sequencer verifies the send's proof natively (SNIP-36), and this
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
//! The depth-20 tree and the root history ring are V3's. No owner, no
//! setters: a route change is a redeploy.

use starknet::ContractAddress;

#[starknet::interface]
pub trait IMessageStoreV2PQ<TContractState> {
    /// Registers the caller under `handle` with their scan pubkey and ML-KEM
    /// encapsulation key (exactly 1184 bytes). One registration per address;
    /// handles are first-come.
    fn register(
        ref self: TContractState, handle: felt252, scan_pubkey: felt252, kem_pubkey: ByteArray,
    );

    /// Publishes a message. The transaction must carry a SNIP-36 proof whose
    /// single L2->L1 message is the prover's attestation of exactly this
    /// (commitment, ephemeral_pubkey, merkle_root, content); `merkle_root`
    /// must be the current root or one of the last ROOT_HISTORY_SIZE.
    fn send_message(
        ref self: TContractState,
        commitment: felt252,
        ephemeral_pubkey: felt252,
        merkle_root: felt252,
        content: ByteArray,
    );

    /// (owner, scan_pubkey, kem_digest, leaf_index).
    fn get_user(
        self: @TContractState, handle: felt252,
    ) -> (ContractAddress, felt252, felt252, u32);
    fn get_merkle_root(self: @TContractState) -> felt252;
    fn get_merkle_path(self: @TContractState, leaf_index: u32) -> Array<felt252>;
    fn get_leaf_index(self: @TContractState, owner: ContractAddress) -> u32;
    fn get_scan_pubkey(self: @TContractState, owner: ContractAddress) -> felt252;
    /// Owner-keyed like `get_scan_pubkey`: `register` allows one handle per
    /// account, so an owner maps to exactly one digest.
    fn get_kem_digest(self: @TContractState, owner: ContractAddress) -> felt252;
    fn is_known_root(self: @TContractState, root: felt252) -> bool;
    fn n_messages(self: @TContractState) -> u64;
    /// The pinned prover contract (for consumer/auditor inspection).
    fn prover(self: @TContractState) -> ContractAddress;
}

/// Poseidon over the Cairo serialization of a ByteArray.
pub fn bytearray_hash(bytes: @ByteArray) -> felt252 {
    let mut serialized: Array<felt252> = array![];
    bytes.serialize(ref serialized);
    core::poseidon::poseidon_hash_span(serialized.span())
}

/// What the prover's payload carries in place of the ciphertext itself.
pub fn content_hash(content: @ByteArray) -> felt252 {
    bytearray_hash(content)
}

/// The digest of an ML-KEM encapsulation key that the leaf binds.
pub fn kem_digest(kem_pubkey: @ByteArray) -> felt252 {
    bytearray_hash(kem_pubkey)
}

/// ML-KEM-768 encapsulation key length (FIPS 203).
pub const KEM_PUBKEY_LEN: u32 = 1184;
/// Shortest v2 content: kem_ct (1088) ‖ nonce (12) ‖ GCM tag (16).
pub const MIN_CONTENT_LEN: u32 = 1088 + 12 + 16;

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
pub mod MessageStoreV2PQ {
    use starknet::{ContractAddress, SyscallResultTrait, get_caller_address, get_contract_address};
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::syscalls::get_execution_info_v3_syscall;
    use core::num::traits::Zero;
    use crate::merkle::{TREE_DEPTH, hash_pair, zero_hash};
    use crate::prover::{leaf_v2, send_payload};
    use super::{
        KEM_PUBKEY_LEN, MIN_CONTENT_LEN, PROOF_VERSION_V1, VIRTUAL_OS_OUTPUT_VERSION, VIRTUAL_SNOS,
        content_hash, kem_digest, message_hash,
    };

    const ROOT_HISTORY_SIZE: u8 = 64;
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
        // User registry + incremental Merkle tree.
        registered: Map<ContractAddress, bool>,
        scan_pubkeys: Map<ContractAddress, felt252>,
        kem_digests: Map<ContractAddress, felt252>,
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

    /// `leaf_index` precedes `kem_pubkey` so data[0..3] keep v1's layout
    /// (handle, scan_pubkey, leaf_index) and the ByteArray trails.
    #[derive(Drop, starknet::Event)]
    struct UserRegistered {
        #[key]
        owner: ContractAddress,
        handle: felt252,
        scan_pubkey: felt252,
        leaf_index: u32,
        kem_pubkey: ByteArray,
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

    /// The incremental insert (V3's, verbatim): write the leaf, walk up
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
    impl StoreImpl of super::IMessageStoreV2PQ<ContractState> {
        fn register(
            ref self: ContractState, handle: felt252, scan_pubkey: felt252, kem_pubkey: ByteArray,
        ) {
            let caller = get_caller_address();
            assert(!self.registered.read(caller), 'already registered');
            assert(handle != 0, 'zero handle');
            assert(scan_pubkey != 0, 'zero scan pubkey');
            assert(kem_pubkey.len() == KEM_PUBKEY_LEN, 'kem pubkey must be 1184 bytes');
            assert(self.handles.read(handle).is_zero(), 'handle taken');

            let digest = kem_digest(@kem_pubkey);
            self.registered.write(caller, true);
            self.scan_pubkeys.write(caller, scan_pubkey);
            self.kem_digests.write(caller, digest);
            self.handles.write(handle, caller);
            let leaf_index = insert_leaf(ref self, leaf_v2(scan_pubkey, digest));
            self.leaf_indices.write(caller, leaf_index);
            self
                .emit(
                    UserRegistered { owner: caller, handle, scan_pubkey, leaf_index, kem_pubkey },
                );
        }

        fn send_message(
            ref self: ContractState,
            commitment: felt252,
            ephemeral_pubkey: felt252,
            merkle_root: felt252,
            content: ByteArray,
        ) {
            assert(content.len() >= MIN_CONTENT_LEN, 'content too short');
            assert(!self.consumed_commitments.read(commitment), 'commitment consumed');
            assert(is_known_root_internal(@self, merkle_root), 'unknown merkle root');
            assert_proven(@self, commitment, ephemeral_pubkey, merkle_root, @content);

            self.consumed_commitments.write(commitment, true);
            let nonce = self.message_nonce.read();
            self.message_nonce.write(nonce + 1);
            self.emit(MessageSent { commitment, ephemeral_pubkey, nonce, content });
        }

        fn get_user(
            self: @ContractState, handle: felt252,
        ) -> (ContractAddress, felt252, felt252, u32) {
            let owner = self.handles.read(handle);
            assert(!owner.is_zero(), 'unknown handle');
            (
                owner,
                self.scan_pubkeys.read(owner),
                self.kem_digests.read(owner),
                self.leaf_indices.read(owner),
            )
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

        fn get_kem_digest(self: @ContractState, owner: ContractAddress) -> felt252 {
            assert(self.registered.read(owner), 'not registered');
            self.kem_digests.read(owner)
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
