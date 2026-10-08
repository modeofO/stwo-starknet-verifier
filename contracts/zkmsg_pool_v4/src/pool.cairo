//! zkmsg v4: the message store IS the shared pool account.
//!
//! Every send is published by THIS contract as the transaction's sender and
//! paid from its own STRK balance, so no member's account signs, pays for or
//! appears in a send. Authorization is the SNIP-36 proof in the transaction's
//! `proof_facts` plus a fresh nullifier; there is no signature.
//!
//! Why store and account are one contract: blockifier forbids
//! `call_contract` to any contract other than the account itself in
//! `__validate__` (crates/blockifier/src/execution/syscalls/
//! hint_processor.rs:530-537), so a separate pool account could not read the
//! store's roots, commitments or nullifiers while validating. Here they are
//! the account's own storage.
//!
//! The invariant that keeps the pool from being drained: whatever passes
//! `__validate__` cannot revert in `__execute__`. A validate failure is a
//! rejection (no fee); an execute revert is charged. So `__validate__` runs
//! the full admission rule set (`admit`) plus the fee policy, and execute
//! runs `admit` again on the same state before writing.
//!
//!   * exactly one call: this contract's `send_message`;
//!   * proof facts: one virtual-OS message whose hash is
//!     poseidon([prover, 0, 8, store, commitment, E, root, content_hash,
//!     nullifier, epoch, quota]) with the epoch derived from the facts' base
//!     block and the quota this store was built with;
//!   * root known, commitment unused, nullifier unspent, epoch fresh;
//!   * content length within [MIN, MAX] (MAX keeps the MessageSent event
//!     under the 300-felt event data limit, another execute-revert source);
//!   * fee fields within policy (src/policy.cairo).
//!
//! Registration is v3's and is called by members from their own accounts
//! (registration is public by design). Funding: anyone transfers STRK here.
//! No owner, no withdraw: the only call this account will ever pay for is
//! `send_message`.

use starknet::ContractAddress;
use starknet::account::Call;
use crate::policy::FeePolicy;

#[starknet::interface]
pub trait IZkmsgPoolV4<TContractState> {
    fn register(
        ref self: TContractState,
        handle: felt252,
        scan_pubkey: felt252,
        kem_pubkey: ByteArray,
        m_commit: felt252,
    );

    /// Publishes a proven send. Normally reached through the pool's own
    /// `__execute__`; a member may also call it from their own account (and
    /// pay, and be named) — the rules are the same.
    fn send_message(
        ref self: TContractState,
        commitment: felt252,
        ephemeral_pubkey: felt252,
        merkle_root: felt252,
        nullifier: felt252,
        content: ByteArray,
    );

    /// Every admission rule without writing; reads the CURRENT transaction's
    /// proof facts. For clients' pre-flight `starknet_call` with simulated
    /// facts, and for tests.
    fn check_send(
        self: @TContractState,
        commitment: felt252,
        ephemeral_pubkey: felt252,
        merkle_root: felt252,
        nullifier: felt252,
        content_hash: felt252,
    );

    fn get_user(
        self: @TContractState, handle: felt252,
    ) -> (ContractAddress, felt252, felt252, felt252, u32);
    fn get_merkle_root(self: @TContractState) -> felt252;
    fn get_merkle_path(self: @TContractState, leaf_index: u32) -> Array<felt252>;
    fn is_known_root(self: @TContractState, root: felt252) -> bool;
    fn is_nullifier_spent(self: @TContractState, nullifier: felt252) -> bool;
    fn is_commitment_consumed(self: @TContractState, commitment: felt252) -> bool;
    fn n_messages(self: @TContractState) -> u64;
    fn prover(self: @TContractState) -> ContractAddress;
    /// (epoch_blocks, max_epoch_lag, quota).
    fn rate_limit(self: @TContractState) -> (u64, u64, u32);
    fn fee_policy(self: @TContractState) -> FeePolicy;
}

/// The SRC-6 account entry points the protocol calls.
#[starknet::interface]
pub trait IPoolAccount<TContractState> {
    fn __validate__(self: @TContractState, calls: Array<Call>) -> felt252;
    fn __execute__(ref self: TContractState, calls: Array<Call>) -> Array<Span<felt252>>;
    fn __validate_declare__(self: @TContractState, class_hash: felt252) -> felt252;
}

/// Poseidon over the Cairo serialization of a ByteArray.
pub fn bytearray_hash(bytes: @ByteArray) -> felt252 {
    let mut serialized: Array<felt252> = array![];
    bytes.serialize(ref serialized);
    core::poseidon::poseidon_hash_span(serialized.span())
}

pub fn content_hash(content: @ByteArray) -> felt252 {
    bytearray_hash(content)
}

pub fn kem_digest(kem_pubkey: @ByteArray) -> felt252 {
    bytearray_hash(kem_pubkey)
}

pub const KEM_PUBKEY_LEN: u32 = 1184;
/// Shortest content: kem_ct (1088) ‖ nonce (12) ‖ GCM tag (16).
pub const MIN_CONTENT_LEN: u32 = 1088 + 12 + 16;
/// Longest content. MessageSent's data is [E, nonce, ...ByteArray], and a
/// ByteArray of n bytes serializes to n/31 + 3 felts; the protocol caps event
/// data at 300 felts (versioned constants `tx_event_limits.max_data_length`),
/// so anything past 9175 bytes would revert in execute. 8 KiB leaves margin
/// and fits the gateway's 5000-felt calldata cap.
pub const MAX_CONTENT_LEN: u32 = 8192;

/// A `send_message` call decoded from account calldata.
#[derive(Drop, PartialEq, Debug)]
pub struct SendCall {
    pub commitment: felt252,
    pub ephemeral_pubkey: felt252,
    pub merkle_root: felt252,
    pub nullifier: felt252,
    pub content: ByteArray,
}

/// The only call the pool pays for: exactly one, to `this`, selector
/// `send_message`, with calldata that decodes exactly (no trailing felts:
/// they would be archival data the pool pays for).
pub fn decode_pool_calls(calls: Span<Call>, this: ContractAddress) -> SendCall {
    assert(calls.len() == 1, 'pool takes exactly one call');
    let call = calls.at(0);
    assert(*call.to == this, 'pool only calls itself');
    assert(*call.selector == selector!("send_message"), 'pool only sends messages');
    let mut calldata = *call.calldata;
    let send: Option<(felt252, felt252, felt252, felt252, ByteArray)> = Serde::deserialize(
        ref calldata,
    );
    let (commitment, ephemeral_pubkey, merkle_root, nullifier, content) = send
        .expect('bad send calldata');
    assert(calldata.is_empty(), 'trailing calldata');
    SendCall { commitment, ephemeral_pubkey, merkle_root, nullifier, content }
}

#[starknet::contract(account)]
pub mod ZkmsgPoolV4 {
    use core::num::traits::Zero;
    use starknet::account::Call;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::syscalls::get_execution_info_v3_syscall;
    use starknet::{
        ContractAddress, SyscallResultTrait, VALIDATED, get_caller_address, get_contract_address,
    };
    use crate::facts::{
        VALIDATE_BLOCK_ROUNDING, epoch_is_fresh, epoch_of, message_hash, parse_send_facts,
    };
    use crate::merkle::{TREE_DEPTH, hash_pair, zero_hash};
    use crate::policy::{FeePolicy, check_fee_fields};
    use crate::prover::{leaf_v3, send_payload_v4};
    use super::{
        KEM_PUBKEY_LEN, MAX_CONTENT_LEN, MIN_CONTENT_LEN, content_hash, decode_pool_calls,
        kem_digest,
    };

    const ROOT_HISTORY_SIZE: u8 = 64;
    const MAX_LEAVES: felt252 = 1048576; // 2^20

    #[storage]
    struct Storage {
        prover: ContractAddress,
        epoch_blocks: u64,
        max_epoch_lag: u64,
        quota: u32,
        fee_policy: FeePolicy,
        registered: Map<ContractAddress, bool>,
        scan_pubkeys: Map<ContractAddress, felt252>,
        kem_digests: Map<ContractAddress, felt252>,
        m_commits: Map<ContractAddress, felt252>,
        handles: Map<felt252, ContractAddress>,
        leaf_indices: Map<ContractAddress, u32>,
        tree_nodes: Map<felt252, felt252>,
        next_leaf_index: u32,
        merkle_root: felt252,
        root_history: Map<u8, felt252>,
        root_history_index: u8,
        message_nonce: u64,
        consumed_commitments: Map<felt252, bool>,
        spent_nullifiers: Map<felt252, bool>,
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
        m_commit: felt252,
        kem_pubkey: ByteArray,
    }

    /// v3's layout (the nullifier is in the calldata, not repeated here).
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
        prover: ContractAddress,
        epoch_blocks: u64,
        max_epoch_lag: u64,
        quota: u32,
        fee_policy: FeePolicy,
    ) {
        assert(!prover.is_zero(), 'zero prover');
        // A multiple of the validate rounding keeps the rounded "now" from
        // ever sitting in an earlier epoch than a real base block.
        assert(
            epoch_blocks != 0 && epoch_blocks % VALIDATE_BLOCK_ROUNDING == 0,
            'epoch not a multiple of 100',
        );
        assert(quota != 0, 'zero quota');
        assert(fee_policy.max_fee != 0 && fee_policy.min_l2_gas != 0, 'empty fee policy');
        self.prover.write(prover);
        self.epoch_blocks.write(epoch_blocks);
        self.max_epoch_lag.write(max_epoch_lag);
        self.quota.write(quota);
        self.fee_policy.write(fee_policy);
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

    fn check_content_len(content: @ByteArray) {
        assert(content.len() >= MIN_CONTENT_LEN, 'content too short');
        assert(content.len() <= MAX_CONTENT_LEN, 'content too long');
    }

    /// The single admission rule set, shared by validate, `check_send` and
    /// execute. Reads only own storage and execution info, so it is legal in
    /// `__validate__`.
    fn admit(
        self: @ContractState,
        commitment: felt252,
        ephemeral_pubkey: felt252,
        merkle_root: felt252,
        nullifier: felt252,
        content_hash: felt252,
    ) {
        assert(!self.consumed_commitments.read(commitment), 'commitment consumed');
        assert(!self.spent_nullifiers.read(nullifier), 'nullifier spent');
        assert(is_known_root_internal(self, merkle_root), 'unknown merkle root');

        let info = get_execution_info_v3_syscall().unwrap_syscall();
        let facts = parse_send_facts(info.tx_info.proof_facts);

        let epoch_blocks = self.epoch_blocks.read();
        let epoch = epoch_of(facts.base_block_number, epoch_blocks);
        assert(
            epoch_is_fresh(
                epoch, info.block_info.block_number, epoch_blocks, self.max_epoch_lag.read(),
            ),
            'stale epoch',
        );

        let payload = send_payload_v4(
            get_contract_address().into(),
            commitment,
            ephemeral_pubkey,
            merkle_root,
            content_hash,
            nullifier,
            epoch,
            self.quota.read(),
        );
        let expected = message_hash(self.prover.read().into(), 0, payload.span());
        assert(facts.message_hash == expected, 'no proof for this send');
    }

    fn publish(
        ref self: ContractState,
        commitment: felt252,
        ephemeral_pubkey: felt252,
        merkle_root: felt252,
        nullifier: felt252,
        content: ByteArray,
    ) {
        check_content_len(@content);
        admit(@self, commitment, ephemeral_pubkey, merkle_root, nullifier, content_hash(@content));
        self.consumed_commitments.write(commitment, true);
        self.spent_nullifiers.write(nullifier, true);
        let nonce = self.message_nonce.read();
        self.message_nonce.write(nonce + 1);
        self.emit(MessageSent { commitment, ephemeral_pubkey, nonce, content });
    }

    #[abi(embed_v0)]
    impl AccountImpl of super::IPoolAccount<ContractState> {
        fn __validate__(self: @ContractState, calls: Array<Call>) -> felt252 {
            assert(get_caller_address().is_zero(), 'protocol only');
            let tx = get_execution_info_v3_syscall().unwrap_syscall().tx_info;
            check_fee_fields(
                tx.version,
                tx.resource_bounds,
                tx.tip,
                tx.signature.len(),
                tx.paymaster_data.len(),
                tx.account_deployment_data.len(),
                tx.nonce_data_availability_mode,
                tx.fee_data_availability_mode,
                self.fee_policy.read(),
            );
            let send = decode_pool_calls(calls.span(), get_contract_address());
            check_content_len(@send.content);
            admit(
                self,
                send.commitment,
                send.ephemeral_pubkey,
                send.merkle_root,
                send.nullifier,
                content_hash(@send.content),
            );
            VALIDATED
        }

        fn __execute__(ref self: ContractState, calls: Array<Call>) -> Array<Span<felt252>> {
            assert(get_caller_address().is_zero(), 'protocol only');
            let send = decode_pool_calls(calls.span(), get_contract_address());
            publish(
                ref self,
                send.commitment,
                send.ephemeral_pubkey,
                send.merkle_root,
                send.nullifier,
                send.content,
            );
            array![array![].span()]
        }

        fn __validate_declare__(self: @ContractState, class_hash: felt252) -> felt252 {
            panic!("pool does not declare")
        }
    }

    #[abi(embed_v0)]
    impl PoolImpl of super::IZkmsgPoolV4<ContractState> {
        fn register(
            ref self: ContractState,
            handle: felt252,
            scan_pubkey: felt252,
            kem_pubkey: ByteArray,
            m_commit: felt252,
        ) {
            let caller = get_caller_address();
            // The pool itself is never a member: its own `__execute__` only
            // reaches `send_message`, but be explicit.
            assert(caller != get_contract_address(), 'pool cannot register');
            assert(!self.registered.read(caller), 'already registered');
            assert(handle != 0, 'zero handle');
            assert(scan_pubkey != 0, 'zero scan pubkey');
            assert(kem_pubkey.len() == KEM_PUBKEY_LEN, 'kem pubkey must be 1184 bytes');
            assert(m_commit != 0, 'zero m_commit');
            assert(self.handles.read(handle).is_zero(), 'handle taken');
            let digest = kem_digest(@kem_pubkey);
            self.registered.write(caller, true);
            self.scan_pubkeys.write(caller, scan_pubkey);
            self.kem_digests.write(caller, digest);
            self.m_commits.write(caller, m_commit);
            self.handles.write(handle, caller);
            let leaf_index = insert_leaf(ref self, leaf_v3(scan_pubkey, digest, m_commit));
            self.leaf_indices.write(caller, leaf_index);
            self
                .emit(
                    UserRegistered {
                        owner: caller, handle, scan_pubkey, leaf_index, m_commit, kem_pubkey,
                    },
                );
        }

        fn send_message(
            ref self: ContractState,
            commitment: felt252,
            ephemeral_pubkey: felt252,
            merkle_root: felt252,
            nullifier: felt252,
            content: ByteArray,
        ) {
            publish(ref self, commitment, ephemeral_pubkey, merkle_root, nullifier, content);
        }

        fn check_send(
            self: @ContractState,
            commitment: felt252,
            ephemeral_pubkey: felt252,
            merkle_root: felt252,
            nullifier: felt252,
            content_hash: felt252,
        ) {
            admit(self, commitment, ephemeral_pubkey, merkle_root, nullifier, content_hash);
        }

        fn get_user(
            self: @ContractState, handle: felt252,
        ) -> (ContractAddress, felt252, felt252, felt252, u32) {
            let owner = self.handles.read(handle);
            assert(!owner.is_zero(), 'unknown handle');
            (
                owner,
                self.scan_pubkeys.read(owner),
                self.kem_digests.read(owner),
                self.m_commits.read(owner),
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

        fn is_known_root(self: @ContractState, root: felt252) -> bool {
            is_known_root_internal(self, root)
        }

        fn is_nullifier_spent(self: @ContractState, nullifier: felt252) -> bool {
            self.spent_nullifiers.read(nullifier)
        }

        fn is_commitment_consumed(self: @ContractState, commitment: felt252) -> bool {
            self.consumed_commitments.read(commitment)
        }

        fn n_messages(self: @ContractState) -> u64 {
            self.message_nonce.read()
        }

        fn prover(self: @ContractState) -> ContractAddress {
            self.prover.read()
        }

        fn rate_limit(self: @ContractState) -> (u64, u64, u32) {
            (self.epoch_blocks.read(), self.max_epoch_lag.read(), self.quota.read())
        }

        fn fee_policy(self: @ContractState) -> FeePolicy {
            self.fee_policy.read()
        }
    }
}
