//! zkmsg v4: the message store IS the shared pool account, paid by tickets.
//!
//! Every send is published by THIS contract as the transaction's sender and
//! paid from its own STRK balance, so no member's account signs, pays for or
//! appears in a send. Authorization is the SNIP-36 proof in the transaction's
//! `proof_facts`; there is no signature.
//!
//! Why store and account are one contract: blockifier forbids
//! `call_contract` to any contract other than the account itself in
//! `__validate__` (crates/blockifier/src/execution/syscalls/
//! hint_processor.rs:530-537), so a separate pool account could not read the
//! store's roots, commitments or nullifiers while validating.
//!
//! FUNDING: users only. The pool never spends more than users paid in.
//!
//!   * `buy_tickets(leaves)` takes `ticket_price` STRK per leaf from the
//!     caller and appends each leaf poseidon([TICKET_V4, t]) to the ticket
//!     tree. Any quantity, any time, from any account.
//!   * A send proves (inside prove_send) knowledge of some ticket's `t` under
//!     a known ticket root and reveals only its ticket nullifier.
//!   * `__validate__` caps the transaction's worst-case fee at the ticket
//!     price (policy.max_fee <= ticket_price, checked at construction) and
//!     SPENDS the ticket nullifier right there. Validate writes survive an
//!     execute revert (blockifier account_transaction.rs:719, "if execution
//!     later fails, only keep the validation diff"), so even an unforeseen
//!     revert is paid for by a burnt ticket. Hence:
//!       total fees charged <= (tickets spent) * ticket_price
//!                          <= (tickets bought) * ticket_price = STRK paid in.
//!   * Surplus (ticket price - actual fee) stays in the pool. No refunds: a
//!     refund would need a destination, which re-links the send.
//!
//! The invariant that keeps sends from wasting tickets: whatever passes
//! `__validate__` does not revert in `__execute__`. Validate runs the full
//! admission rule set (`admit`) plus the fee policy:
//!
//!   * exactly one call: this contract's `send_message`;
//!   * proof facts: one virtual-OS message whose hash is
//!     poseidon([prover, 0, 10, store, commitment, E, root, content_hash,
//!     nullifier, epoch, quota, ticket_root, ticket_nullifier]) with the
//!     epoch derived from the facts' base block and the quota this store
//!     was built with;
//!   * member root known, envelope (commitment, content) unused, member
//!     nullifier unspent, epoch fresh, ticket root known, ticket unspent;
//!   * content length within [MIN, MAX] (MAX keeps the MessageSent event
//!     under the 300-felt event data limit, another execute-revert source);
//!   * fee fields within policy (src/policy.cairo).
//!
//! Registration is v3's, called by members from their own accounts.
//! No owner, no withdraw: the only call this account will ever pay for is
//! its own `send_message`.

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

    /// Buys one ticket per leaf at `ticket_price` STRK each (the caller must
    /// have approved the pool). Leaves are poseidon([TICKET_V4, t]).
    fn buy_tickets(ref self: TContractState, leaves: Array<felt252>);

    /// Publishes a proven send. Only the pool's own `__execute__` reaches it
    /// (after `__validate__` spent the ticket).
    fn send_message(
        ref self: TContractState,
        commitment: felt252,
        ephemeral_pubkey: felt252,
        merkle_root: felt252,
        nullifier: felt252,
        ticket_root: felt252,
        ticket_nullifier: felt252,
        content: ByteArray,
    );

    /// Every admission rule without writing; reads the CURRENT transaction's
    /// proof facts. For clients' simulation and for tests.
    fn check_send(
        self: @TContractState,
        commitment: felt252,
        ephemeral_pubkey: felt252,
        merkle_root: felt252,
        nullifier: felt252,
        ticket_root: felt252,
        ticket_nullifier: felt252,
        content_hash: felt252,
    );

    fn get_user(
        self: @TContractState, handle: felt252,
    ) -> (ContractAddress, felt252, felt252, felt252, u32);
    fn get_merkle_root(self: @TContractState) -> felt252;
    fn get_merkle_path(self: @TContractState, leaf_index: u32) -> Array<felt252>;
    fn is_known_root(self: @TContractState, root: felt252) -> bool;
    fn get_ticket_root(self: @TContractState) -> felt252;
    fn get_ticket_path(self: @TContractState, ticket_index: u32) -> Array<felt252>;
    fn is_known_ticket_root(self: @TContractState, root: felt252) -> bool;
    fn is_ticket_spent(self: @TContractState, ticket_nullifier: felt252) -> bool;
    fn n_tickets(self: @TContractState) -> u32;
    fn ticket_price(self: @TContractState) -> u128;
    fn is_nullifier_spent(self: @TContractState, nullifier: felt252) -> bool;
    /// Whether this exact envelope (commitment + content) was published.
    fn is_envelope_consumed(
        self: @TContractState, commitment: felt252, content_hash: felt252,
    ) -> bool;
    fn n_messages(self: @TContractState) -> u64;
    fn prover(self: @TContractState) -> ContractAddress;
    /// (epoch_blocks, max_epoch_lag, quota).
    fn rate_limit(self: @TContractState) -> (u64, u64, u32);
    fn fee_policy(self: @TContractState) -> FeePolicy;
}

/// The SRC-6 account entry points the protocol calls. `__validate__` takes
/// `ref self`: it spends the ticket.
#[starknet::interface]
pub trait IPoolAccount<TContractState> {
    fn __validate__(ref self: TContractState, calls: Array<Call>) -> felt252;
    fn __execute__(ref self: TContractState, calls: Array<Call>) -> Array<Span<felt252>>;
    fn __validate_declare__(self: @TContractState, class_hash: felt252) -> felt252;
}

#[starknet::interface]
pub trait IERC20<T> {
    fn transfer_from(
        ref self: T, sender: ContractAddress, recipient: ContractAddress, amount: u256,
    ) -> bool;
    fn balance_of(self: @T, account: ContractAddress) -> u256;
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

/// What the store refuses to publish twice: the commitment TOGETHER with
/// the content it tags. Keyed on the commitment alone, any member who saw a
/// pending send could prove and land the same commitment over other content
/// first, and the real send would be refused (red team 04-crypto F9). Now
/// that copy publishes beside it (and fails the recipient's decryption)
/// while the real one still lands; only an exact copy, which delivers the
/// real message anyway, is refused. Replays of one proof are already stopped
/// by its member and ticket nullifiers.
pub fn envelope_key(commitment: felt252, content_hash: felt252) -> felt252 {
    core::poseidon::poseidon_hash_span(array![commitment, content_hash].span())
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
/// Tickets per `buy_tickets` call (bounds the call's gas).
pub const MAX_TICKETS_PER_BUY: u32 = 32;

/// A `send_message` call decoded from account calldata.
#[derive(Drop, PartialEq, Debug)]
pub struct SendCall {
    pub commitment: felt252,
    pub ephemeral_pubkey: felt252,
    pub merkle_root: felt252,
    pub nullifier: felt252,
    pub ticket_root: felt252,
    pub ticket_nullifier: felt252,
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
    let send: Option<(felt252, felt252, felt252, felt252, felt252, felt252, ByteArray)> =
        Serde::deserialize(
        ref calldata,
    );
    let (
        commitment,
        ephemeral_pubkey,
        merkle_root,
        nullifier,
        ticket_root,
        ticket_nullifier,
        content,
    ) =
        send
        .expect('bad send calldata');
    assert(calldata.is_empty(), 'trailing calldata');
    SendCall {
        commitment,
        ephemeral_pubkey,
        merkle_root,
        nullifier,
        ticket_root,
        ticket_nullifier,
        content,
    }
}

#[starknet::contract(account)]
pub mod ZkmsgPoolV4 {
    use core::num::traits::Zero;
    use starknet::account::Call;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::syscalls::{call_contract_syscall, get_execution_info_v3_syscall};
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
        IERC20Dispatcher, IERC20DispatcherTrait, KEM_PUBKEY_LEN, MAX_CONTENT_LEN,
        MAX_TICKETS_PER_BUY, MIN_CONTENT_LEN, SendCall, content_hash, decode_pool_calls, envelope_key,
        kem_digest,
    };

    const ROOT_HISTORY_SIZE: u8 = 64;
    const MAX_LEAVES: u32 = 1048576; // 2^20
    const MEMBERS: u8 = 0;
    const TICKETS: u8 = 1;

    #[storage]
    struct Storage {
        prover: ContractAddress,
        strk: ContractAddress,
        ticket_price: u128,
        epoch_blocks: u64,
        max_epoch_lag: u64,
        quota: u32,
        fee_policy: FeePolicy,
        // Members.
        registered: Map<ContractAddress, bool>,
        scan_pubkeys: Map<ContractAddress, felt252>,
        kem_digests: Map<ContractAddress, felt252>,
        m_commits: Map<ContractAddress, felt252>,
        handles: Map<felt252, ContractAddress>,
        leaf_indices: Map<ContractAddress, u32>,
        root_history: Map<u8, felt252>,
        root_history_index: u8,
        // Both trees: (tree, level, index) -> node; tree -> next leaf, root.
        tree_nodes: Map<(u8, u32, u32), felt252>,
        next_leaf: Map<u8, u32>,
        roots: Map<u8, felt252>,
        // Tickets: the tree is append-only and a ticket stays a ticket, so
        // every root it ever had stays acceptable (no eviction race).
        known_ticket_roots: Map<felt252, bool>,
        spent_tickets: Map<felt252, bool>,
        // Messages.
        message_nonce: u64,
        consumed_envelopes: Map<felt252, bool>,
        spent_nullifiers: Map<felt252, bool>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        UserRegistered: UserRegistered,
        TicketBought: TicketBought,
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

    /// One per ticket, so clients rebuild the ticket tree from events alone.
    #[derive(Drop, starknet::Event)]
    struct TicketBought {
        leaf: felt252,
        index: u32,
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
        prover: ContractAddress,
        strk: ContractAddress,
        ticket_price: u128,
        epoch_blocks: u64,
        max_epoch_lag: u64,
        quota: u32,
        fee_policy: FeePolicy,
    ) {
        assert(!prover.is_zero() && !strk.is_zero(), 'zero address');
        // A multiple of the validate rounding keeps the rounded "now" from
        // ever sitting in an earlier epoch than a real base block.
        assert(
            epoch_blocks != 0 && epoch_blocks % VALIDATE_BLOCK_ROUNDING == 0,
            'epoch not a multiple of 100',
        );
        assert(quota != 0, 'zero quota');
        assert(fee_policy.max_fee != 0 && fee_policy.min_l2_gas != 0, 'empty fee policy');
        // The solvency invariant: one send can never cost more than the
        // one ticket it burns.
        assert(fee_policy.max_fee <= ticket_price, 'max fee over ticket price');
        self.prover.write(prover);
        self.strk.write(strk);
        self.ticket_price.write(ticket_price);
        self.epoch_blocks.write(epoch_blocks);
        self.max_epoch_lag.write(max_epoch_lag);
        self.quota.write(quota);
        self.fee_policy.write(fee_policy);
        self.roots.write(MEMBERS, zero_hash(TREE_DEPTH));
        self.roots.write(TICKETS, zero_hash(TREE_DEPTH));
    }

    fn read_node(self: @ContractState, tree: u8, level: u32, index: u32) -> felt252 {
        let value = self.tree_nodes.read((tree, level, index));
        if value == 0 {
            zero_hash(level)
        } else {
            value
        }
    }

    /// The incremental insert (v3's walk), for either tree.
    fn insert_leaf(ref self: ContractState, tree: u8, leaf: felt252) -> (u32, felt252) {
        let leaf_index = self.next_leaf.read(tree);
        assert(leaf_index < MAX_LEAVES, 'tree is full');
        self.tree_nodes.write((tree, 0, leaf_index), leaf);
        let mut current_index = leaf_index;
        let mut current_hash = leaf;
        let mut level: u32 = 0;
        while level < TREE_DEPTH {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            let sibling_hash = read_node(@self, tree, level, sibling_index);
            let parent_hash = if current_index % 2 == 0 {
                hash_pair(current_hash, sibling_hash)
            } else {
                hash_pair(sibling_hash, current_hash)
            };
            current_index = current_index / 2;
            self.tree_nodes.write((tree, level + 1, current_index), parent_hash);
            current_hash = parent_hash;
            level += 1;
        }
        self.roots.write(tree, current_hash);
        self.next_leaf.write(tree, leaf_index + 1);
        (leaf_index, current_hash)
    }

    fn path(self: @ContractState, tree: u8, leaf_index: u32) -> Array<felt252> {
        let mut out: Array<felt252> = array![];
        let mut current_index = leaf_index;
        let mut level: u32 = 0;
        while level < TREE_DEPTH {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            out.append(read_node(self, tree, level, sibling_index));
            current_index = current_index / 2;
            level += 1;
        }
        out
    }

    fn is_known_root_internal(self: @ContractState, root: felt252) -> bool {
        if root == self.roots.read(MEMBERS) {
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

    /// The admission rule set, shared by validate, `check_send` and execute.
    /// Reads only own storage and execution info, so it is legal in
    /// `__validate__`. The ticket's unspent-ness is checked by the caller:
    /// validate requires it unspent (then spends it), execute requires it
    /// already spent by this transaction's validate.
    fn admit(self: @ContractState, send: @SendCall, content_hash: felt252) {
        assert(
            !self.consumed_envelopes.read(envelope_key(*send.commitment, content_hash)),
            'envelope consumed',
        );
        assert(!self.spent_nullifiers.read(*send.nullifier), 'nullifier spent');
        assert(is_known_root_internal(self, *send.merkle_root), 'unknown merkle root');
        assert(self.known_ticket_roots.read(*send.ticket_root), 'unknown ticket root');

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
            *send.commitment,
            *send.ephemeral_pubkey,
            *send.merkle_root,
            content_hash,
            *send.nullifier,
            epoch,
            self.quota.read(),
            *send.ticket_root,
            *send.ticket_nullifier,
        );
        let expected = message_hash(self.prover.read().into(), 0, payload.span());
        assert(facts.message_hash == expected, 'no proof for this send');
    }

    #[abi(embed_v0)]
    impl AccountImpl of super::IPoolAccount<ContractState> {
        fn __validate__(ref self: ContractState, calls: Array<Call>) -> felt252 {
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
            assert(!self.spent_tickets.read(send.ticket_nullifier), 'ticket spent');
            admit(@self, @send, content_hash(@send.content));
            // Burn the ticket now: this write survives an execute revert, so
            // whatever this transaction ends up costing is paid by it.
            self.spent_tickets.write(send.ticket_nullifier, true);
            VALIDATED
        }

        fn __execute__(ref self: ContractState, calls: Array<Call>) -> Array<Span<felt252>> {
            assert(get_caller_address().is_zero(), 'protocol only');
            // Validate already allowed exactly this one call to ourselves.
            let call = calls.at(0);
            array![call_contract_syscall(*call.to, *call.selector, *call.calldata).unwrap_syscall()]
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
            let (leaf_index, root) = insert_leaf(
                ref self, MEMBERS, leaf_v3(scan_pubkey, digest, m_commit),
            );
            let history_index = self.root_history_index.read();
            self.root_history.write(history_index, root);
            self.root_history_index.write((history_index + 1) % ROOT_HISTORY_SIZE);
            self.leaf_indices.write(caller, leaf_index);
            self
                .emit(
                    UserRegistered {
                        owner: caller, handle, scan_pubkey, leaf_index, m_commit, kem_pubkey,
                    },
                );
        }

        fn buy_tickets(ref self: ContractState, leaves: Array<felt252>) {
            let n = leaves.len();
            assert(n != 0 && n <= MAX_TICKETS_PER_BUY, 'buy 1..32 tickets');
            let this = get_contract_address();
            // The pool's own __execute__ only reaches send_message, but a
            // ticket bought with the pool's own STRK would mint free sends.
            assert(get_caller_address() != this, 'pool cannot buy');
            let price: u256 = self.ticket_price.read().into();
            let paid = IERC20Dispatcher { contract_address: self.strk.read() }
                .transfer_from(get_caller_address(), this, price * n.into());
            assert(paid, 'payment failed');
            for leaf in leaves {
                assert(leaf != 0, 'zero ticket');
                let (index, root) = insert_leaf(ref self, TICKETS, leaf);
                self.known_ticket_roots.write(root, true);
                self.emit(TicketBought { leaf, index });
            }
        }

        fn send_message(
            ref self: ContractState,
            commitment: felt252,
            ephemeral_pubkey: felt252,
            merkle_root: felt252,
            nullifier: felt252,
            ticket_root: felt252,
            ticket_nullifier: felt252,
            content: ByteArray,
        ) {
            assert(get_caller_address() == get_contract_address(), 'send through the pool');
            check_content_len(@content);
            let send = SendCall {
                commitment,
                ephemeral_pubkey,
                merkle_root,
                nullifier,
                ticket_root,
                ticket_nullifier,
                content,
            };
            // Spent by this transaction's own __validate__.
            assert(self.spent_tickets.read(ticket_nullifier), 'ticket not burnt');
            let hash = content_hash(@send.content);
            admit(@self, @send, hash);
            self.consumed_envelopes.write(envelope_key(commitment, hash), true);
            self.spent_nullifiers.write(nullifier, true);
            let nonce = self.message_nonce.read();
            self.message_nonce.write(nonce + 1);
            self.emit(MessageSent { commitment, ephemeral_pubkey, nonce, content: send.content });
        }

        fn check_send(
            self: @ContractState,
            commitment: felt252,
            ephemeral_pubkey: felt252,
            merkle_root: felt252,
            nullifier: felt252,
            ticket_root: felt252,
            ticket_nullifier: felt252,
            content_hash: felt252,
        ) {
            assert(!self.spent_tickets.read(ticket_nullifier), 'ticket spent');
            let send = SendCall {
                commitment,
                ephemeral_pubkey,
                merkle_root,
                nullifier,
                ticket_root,
                ticket_nullifier,
                content: Default::default(),
            };
            admit(self, @send, content_hash);
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
            self.roots.read(MEMBERS)
        }

        fn get_merkle_path(self: @ContractState, leaf_index: u32) -> Array<felt252> {
            path(self, MEMBERS, leaf_index)
        }

        fn is_known_root(self: @ContractState, root: felt252) -> bool {
            is_known_root_internal(self, root)
        }

        fn get_ticket_root(self: @ContractState) -> felt252 {
            self.roots.read(TICKETS)
        }

        fn get_ticket_path(self: @ContractState, ticket_index: u32) -> Array<felt252> {
            path(self, TICKETS, ticket_index)
        }

        fn is_known_ticket_root(self: @ContractState, root: felt252) -> bool {
            self.known_ticket_roots.read(root)
        }

        fn is_ticket_spent(self: @ContractState, ticket_nullifier: felt252) -> bool {
            self.spent_tickets.read(ticket_nullifier)
        }

        fn n_tickets(self: @ContractState) -> u32 {
            self.next_leaf.read(TICKETS)
        }

        fn ticket_price(self: @ContractState) -> u128 {
            self.ticket_price.read()
        }

        fn is_nullifier_spent(self: @ContractState, nullifier: felt252) -> bool {
            self.spent_nullifiers.read(nullifier)
        }

        fn is_envelope_consumed(
            self: @ContractState, commitment: felt252, content_hash: felt252,
        ) -> bool {
            self.consumed_envelopes.read(envelope_key(commitment, content_hash))
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
