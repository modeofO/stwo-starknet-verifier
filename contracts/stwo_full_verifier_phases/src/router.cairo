//! The verification router — the production contract that drives the
//! N-phase machine across transactions (docs/lane2-design.md).
//!
//! The machine classes are stateless library classes; the router owns the
//! only storage: one checkpoint slot per (caller, proof_id) holding
//! `(tag, poseidon(state))`, plus the write-once staged-section store.
//! Every transaction re-supplies the previous serialized state (calldata,
//! not storage), the router checks its hash and tag, library-calls the
//! fixed class for that step, stores the new tagged hash and returns the
//! new state for the caller to echo next.
//!
//! Write-once sequencing falls out of the tag chain: `begin` requires an
//! empty slot, every other step requires the slot to hold exactly the tag
//! its input state type carries, and each step overwrites the slot — so a
//! phase can never be re-run against a stale state (its tag has moved on)
//! and a state can never be fed to a phase of the wrong type (tag
//! mismatch). The intra-phase ordering (claim/lookup chunk counts, the
//! N-family OODS sequence, query groups) is enforced by the machine
//! states themselves.
//!
//! ## The staged-section store
//!
//! Two proof sections exceed the ~4,996-felt usable calldata cap and are
//! consumed by MANY transactions, so they arrive once via `stage` (packed
//! v2, lane-1 `stage_proof` precedent; ≤ ~3,990 slots per staging tx under
//! the 4,000-entry state-diff cap) and are read back from storage:
//!
//! - `SECTION_SAMPLED` (~2.6k slots, 1 staging tx): read by `oods_begin`,
//!   every `oods_group`, `oods_finalize` and every fused `group` tx.
//!   Binding: the machine's `d_sampled` checkpoint digest (saved by
//!   `oods_begin` from the transcript-bound mix).
//! - `SECTION_FRI` (~8k slots, 3 staging txs): read by `fri_commit` and
//!   `finalize`. Binding: `d_fri` rides the checkpoint from `fri_commit`
//!   to `finalize` (plus the lane-1 query-equality re-derivation).
//!
//! Slots are keyed by (caller, proof_id, section), so staging cannot be
//! griefed by third parties; a caller overwriting their own staged bytes
//! after a phase consumed them just fails the digest binding. Everything
//! else (head, program chunks, per-group rows + witnesses, the state echo)
//! fits calldata directly — rows and witnesses are self-authenticating
//! (Merkle-verified on arrival), so storing them would buy nothing.
//!
//! `finalize` registers the fact with the shared `StwoSharedFactRegistry`
//! (constructor-pinned address; the router must be on the registry's
//! governed route list). The fact is `poseidon(program_hash, output_hash)`.

use starknet::ContractAddress;

/// Checkpoint tags — one per machine state type.
pub const TAG_NONE: felt252 = 0;
pub const TAG_CLAIM: felt252 = 1;
pub const TAG_LOOKUP: felt252 = 2;
pub const TAG_OODS: felt252 = 3;
pub const TAG_OODS_EVAL: felt252 = 4;
pub const TAG_FRI_COMMIT: felt252 = 5;
pub const TAG_GROUP: felt252 = 6;
pub const TAG_DONE: felt252 = 7;

/// Staged-section ids.
pub const SECTION_SAMPLED: felt252 = 'sampled';
pub const SECTION_FRI: felt252 = 'fri';

#[starknet::interface]
pub trait IStwoVerifierRouter<TContractState> {
    /// Stages `slots` of a packed section at slot `offset` under the
    /// caller's `proof_id`. Sections: [`SECTION_SAMPLED`], [`SECTION_FRI`].
    fn stage(
        ref self: TContractState,
        proof_id: felt252,
        section: felt252,
        offset: u32,
        slots: Span<felt252>,
    );
    fn begin(
        ref self: TContractState,
        proof_id: felt252,
        head_packed: Span<felt252>,
        head_n: u32,
        program_len: u32,
    ) -> Array<felt252>;
    fn claim_chunk(
        ref self: TContractState,
        proof_id: felt252,
        state: Span<felt252>,
        entries_packed: Span<felt252>,
        entries_n: u32,
    ) -> Array<felt252>;
    fn claim_finalize(
        ref self: TContractState,
        proof_id: felt252,
        state: Span<felt252>,
        head_packed: Span<felt252>,
        head_n: u32,
    ) -> Array<felt252>;
    fn lookup_chunk(
        ref self: TContractState,
        proof_id: felt252,
        state: Span<felt252>,
        entries_packed: Span<felt252>,
        entries_n: u32,
    ) -> Array<felt252>;
    fn lookup_finalize(
        ref self: TContractState,
        proof_id: felt252,
        state: Span<felt252>,
        head_packed: Span<felt252>,
        head_n: u32,
    ) -> Array<felt252>;
    fn oods_begin(
        ref self: TContractState,
        proof_id: felt252,
        state: Span<felt252>,
        head_packed: Span<felt252>,
        head_n: u32,
        sampled_slots: u32,
        sampled_n: u32,
    ) -> Array<felt252>;
    fn oods_group(
        ref self: TContractState,
        proof_id: felt252,
        group_index: u32,
        state: Span<felt252>,
        head_packed: Span<felt252>,
        head_n: u32,
        sampled_slots: u32,
        sampled_n: u32,
    ) -> Array<felt252>;
    fn oods_finalize(
        ref self: TContractState,
        proof_id: felt252,
        state: Span<felt252>,
        head_packed: Span<felt252>,
        head_n: u32,
        sampled_slots: u32,
        sampled_n: u32,
    ) -> Array<felt252>;
    fn fri_commit(
        ref self: TContractState,
        proof_id: felt252,
        state: Span<felt252>,
        head_packed: Span<felt252>,
        head_n: u32,
        fri_slots: u32,
        fri_n: u32,
    ) -> Array<felt252>;
    fn group(
        ref self: TContractState,
        proof_id: felt252,
        state: Span<felt252>,
        head_packed: Span<felt252>,
        head_n: u32,
        sampled_slots: u32,
        sampled_n: u32,
        rows_packed: Span<felt252>,
        rows_n: u32,
        witnesses_packed: Span<felt252>,
        witnesses_n: u32,
    ) -> Array<felt252>;
    fn finalize(
        ref self: TContractState,
        proof_id: felt252,
        state: Span<felt252>,
        head_packed: Span<felt252>,
        head_n: u32,
        fri_slots: u32,
        fri_n: u32,
    ) -> (felt252, felt252);
    /// The (tag, state_hash) checkpoint for (caller, proof_id).
    fn checkpoint(
        self: @TContractState, caller: ContractAddress, proof_id: felt252,
    ) -> (felt252, felt252);
    /// The shared fact registry this router registers into.
    fn registry(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod StwoVerifierRouter {
    use core::poseidon::poseidon_hash_span;
    use starknet::storage::{
        Map, StoragePathEntry, StoragePointerReadAccess, StoragePointerWriteAccess,
    };
    use starknet::{ClassHash, ContractAddress, get_caller_address};
    use crate::fact_registry::{
        IStwoSharedFactRegistryDispatcher, IStwoSharedFactRegistryDispatcherTrait,
    };
    use crate::unpack_proof_v2;
    use crate::{
        IStwoMachineClaimLibraryDispatcher, IStwoMachineClaimDispatcherTrait,
        IStwoMachineFriLibraryDispatcher, IStwoMachineFriDispatcherTrait,
        IStwoMachineGroupLibraryDispatcher, IStwoMachineGroupDispatcherTrait,
        IStwoMachineLookupLibraryDispatcher, IStwoMachineLookupDispatcherTrait,
        IStwoOodsBeginLibraryDispatcher, IStwoOodsBeginDispatcherTrait,
        IStwoOodsFinalizeLibraryDispatcher, IStwoOodsFinalizeDispatcherTrait,
        IStwoOodsGroupLibraryDispatcher, IStwoOodsGroupDispatcherTrait,
    };
    use super::{
        IStwoVerifierRouter, SECTION_FRI, SECTION_SAMPLED, TAG_CLAIM, TAG_DONE, TAG_FRI_COMMIT,
        TAG_GROUP, TAG_LOOKUP, TAG_NONE, TAG_OODS, TAG_OODS_EVAL,
    };

    #[storage]
    struct Storage {
        claim_class: ClassHash,
        lookup_class: ClassHash,
        oods_begin_class: ClassHash,
        n_oods_groups: u32,
        oods_group_classes: Map<u32, ClassHash>,
        oods_finalize_class: ClassHash,
        group_class: ClassHash,
        fri_class: ClassHash,
        /// The shared fact registry (this router must be one of its routes).
        registry: ContractAddress,
        /// (caller, proof_id) -> (tag, poseidon(state)).
        checkpoints: Map<(ContractAddress, felt252), (felt252, felt252)>,
        /// Staged packed sections: (caller, proof_id, section, slot) -> felt.
        staged: Map<(ContractAddress, felt252, felt252, u32), felt252>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        Step: Step,
    }

    /// One machine transaction completed; `state_hash` is what the next
    /// transaction's echoed state must hash to.
    #[derive(Drop, starknet::Event)]
    struct Step {
        #[key]
        caller: ContractAddress,
        #[key]
        proof_id: felt252,
        tag: felt252,
        state_hash: felt252,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        claim_class: ClassHash,
        lookup_class: ClassHash,
        oods_begin_class: ClassHash,
        oods_group_classes: Span<ClassHash>,
        oods_finalize_class: ClassHash,
        group_class: ClassHash,
        fri_class: ClassHash,
        registry: ContractAddress,
    ) {
        self.claim_class.write(claim_class);
        self.lookup_class.write(lookup_class);
        self.oods_begin_class.write(oods_begin_class);
        self.n_oods_groups.write(oods_group_classes.len());
        let mut index = 0;
        for class in oods_group_classes {
            self.oods_group_classes.entry(index).write(*class);
            index += 1;
        }
        self.oods_finalize_class.write(oods_finalize_class);
        self.group_class.write(group_class);
        self.fri_class.write(fri_class);
        self.registry.write(registry);
    }

    /// Checks the echoed state against the caller's checkpoint slot.
    fn consume(
        self: @ContractState, proof_id: felt252, expected_tag: felt252, state: Span<felt252>,
    ) {
        let caller = get_caller_address();
        let (tag, state_hash) = self.checkpoints.entry((caller, proof_id)).read();
        assert(tag == expected_tag, 'router: tag');
        assert(state_hash == poseidon_hash_span(state), 'router: state');
    }

    /// Stores the new tagged checkpoint and emits the step event.
    fn advance(
        ref self: ContractState, proof_id: felt252, tag: felt252, state: Span<felt252>,
    ) {
        let caller = get_caller_address();
        let state_hash = poseidon_hash_span(state);
        self.checkpoints.entry((caller, proof_id)).write((tag, state_hash));
        self.emit(Step { caller, proof_id, tag, state_hash });
    }

    fn unpack(packed: Span<felt252>, n: u32) -> Span<felt252> {
        unpack_proof_v2(packed, n).span()
    }

    /// Reads a staged section back (slots 0..n_slots) and unpacks it.
    fn read_section(
        self: @ContractState, proof_id: felt252, section: felt252, n_slots: u32, n_values: u32,
    ) -> Span<felt252> {
        let caller = get_caller_address();
        let mut packed: Array<felt252> = array![];
        let mut i = 0;
        while i != n_slots {
            packed.append(self.staged.entry((caller, proof_id, section, i)).read());
            i += 1;
        }
        unpack(packed.span(), n_values)
    }

    #[abi(embed_v0)]
    impl RouterImpl of IStwoVerifierRouter<ContractState> {
        fn stage(
            ref self: ContractState,
            proof_id: felt252,
            section: felt252,
            offset: u32,
            slots: Span<felt252>,
        ) {
            assert(
                section == SECTION_SAMPLED || section == SECTION_FRI, 'router: section',
            );
            let caller = get_caller_address();
            let mut i = offset;
            for slot in slots {
                self.staged.entry((caller, proof_id, section, i)).write(*slot);
                i += 1;
            }
        }

        fn begin(
            ref self: ContractState,
            proof_id: felt252,
            head_packed: Span<felt252>,
            head_n: u32,
            program_len: u32,
        ) -> Array<felt252> {
            // Write-once: a proof_id can only ever be started once per caller.
            let caller = get_caller_address();
            let (tag, _) = self.checkpoints.entry((caller, proof_id)).read();
            assert(tag == TAG_NONE, 'router: proof id in use');
            let head = unpack(head_packed, head_n);
            let out = IStwoMachineClaimLibraryDispatcher { class_hash: self.claim_class.read() }
                .begin(head, program_len);
            advance(ref self, proof_id, TAG_CLAIM, out.span());
            out
        }

        fn claim_chunk(
            ref self: ContractState,
            proof_id: felt252,
            state: Span<felt252>,
            entries_packed: Span<felt252>,
            entries_n: u32,
        ) -> Array<felt252> {
            consume(@self, proof_id, TAG_CLAIM, state);
            let entries = unpack(entries_packed, entries_n);
            let out = IStwoMachineClaimLibraryDispatcher { class_hash: self.claim_class.read() }
                .claim_chunk(state, entries);
            advance(ref self, proof_id, TAG_CLAIM, out.span());
            out
        }

        fn claim_finalize(
            ref self: ContractState,
            proof_id: felt252,
            state: Span<felt252>,
            head_packed: Span<felt252>,
            head_n: u32,
        ) -> Array<felt252> {
            consume(@self, proof_id, TAG_CLAIM, state);
            let head = unpack(head_packed, head_n);
            let out = IStwoMachineClaimLibraryDispatcher { class_hash: self.claim_class.read() }
                .claim_finalize(state, head);
            advance(ref self, proof_id, TAG_LOOKUP, out.span());
            out
        }

        fn lookup_chunk(
            ref self: ContractState,
            proof_id: felt252,
            state: Span<felt252>,
            entries_packed: Span<felt252>,
            entries_n: u32,
        ) -> Array<felt252> {
            consume(@self, proof_id, TAG_LOOKUP, state);
            let entries = unpack(entries_packed, entries_n);
            let out = IStwoMachineLookupLibraryDispatcher {
                class_hash: self.lookup_class.read(),
            }
                .lookup_chunk(state, entries);
            advance(ref self, proof_id, TAG_LOOKUP, out.span());
            out
        }

        fn lookup_finalize(
            ref self: ContractState,
            proof_id: felt252,
            state: Span<felt252>,
            head_packed: Span<felt252>,
            head_n: u32,
        ) -> Array<felt252> {
            consume(@self, proof_id, TAG_LOOKUP, state);
            let head = unpack(head_packed, head_n);
            let out = IStwoMachineLookupLibraryDispatcher {
                class_hash: self.lookup_class.read(),
            }
                .lookup_finalize(state, head);
            advance(ref self, proof_id, TAG_OODS, out.span());
            out
        }

        fn oods_begin(
            ref self: ContractState,
            proof_id: felt252,
            state: Span<felt252>,
            head_packed: Span<felt252>,
            head_n: u32,
            sampled_slots: u32,
            sampled_n: u32,
        ) -> Array<felt252> {
            consume(@self, proof_id, TAG_OODS, state);
            let head = unpack(head_packed, head_n);
            let sampled = read_section(@self, proof_id, SECTION_SAMPLED, sampled_slots, sampled_n);
            let out = IStwoOodsBeginLibraryDispatcher {
                class_hash: self.oods_begin_class.read(),
            }
                .oods_begin(state, head, sampled);
            advance(ref self, proof_id, TAG_OODS_EVAL, out.span());
            out
        }

        fn oods_group(
            ref self: ContractState,
            proof_id: felt252,
            group_index: u32,
            state: Span<felt252>,
            head_packed: Span<felt252>,
            head_n: u32,
            sampled_slots: u32,
            sampled_n: u32,
        ) -> Array<felt252> {
            consume(@self, proof_id, TAG_OODS_EVAL, state);
            assert(group_index < self.n_oods_groups.read(), 'router: group index');
            let head = unpack(head_packed, head_n);
            let sampled = read_section(@self, proof_id, SECTION_SAMPLED, sampled_slots, sampled_n);
            // The family-order counter inside the state enforces that the
            // groups run in sequence, exactly once each.
            let out = IStwoOodsGroupLibraryDispatcher {
                class_hash: self.oods_group_classes.entry(group_index).read(),
            }
                .run(state, head, sampled);
            advance(ref self, proof_id, TAG_OODS_EVAL, out.span());
            out
        }

        fn oods_finalize(
            ref self: ContractState,
            proof_id: felt252,
            state: Span<felt252>,
            head_packed: Span<felt252>,
            head_n: u32,
            sampled_slots: u32,
            sampled_n: u32,
        ) -> Array<felt252> {
            consume(@self, proof_id, TAG_OODS_EVAL, state);
            let head = unpack(head_packed, head_n);
            let sampled = read_section(@self, proof_id, SECTION_SAMPLED, sampled_slots, sampled_n);
            let out = IStwoOodsFinalizeLibraryDispatcher {
                class_hash: self.oods_finalize_class.read(),
            }
                .oods_finalize(state, head, sampled);
            advance(ref self, proof_id, TAG_FRI_COMMIT, out.span());
            out
        }

        fn fri_commit(
            ref self: ContractState,
            proof_id: felt252,
            state: Span<felt252>,
            head_packed: Span<felt252>,
            head_n: u32,
            fri_slots: u32,
            fri_n: u32,
        ) -> Array<felt252> {
            consume(@self, proof_id, TAG_FRI_COMMIT, state);
            let head = unpack(head_packed, head_n);
            let fri = read_section(@self, proof_id, SECTION_FRI, fri_slots, fri_n);
            let out = IStwoMachineFriLibraryDispatcher { class_hash: self.fri_class.read() }
                .fri_commit(state, head, fri);
            advance(ref self, proof_id, TAG_GROUP, out.span());
            out
        }

        fn group(
            ref self: ContractState,
            proof_id: felt252,
            state: Span<felt252>,
            head_packed: Span<felt252>,
            head_n: u32,
            sampled_slots: u32,
            sampled_n: u32,
            rows_packed: Span<felt252>,
            rows_n: u32,
            witnesses_packed: Span<felt252>,
            witnesses_n: u32,
        ) -> Array<felt252> {
            consume(@self, proof_id, TAG_GROUP, state);
            let head = unpack(head_packed, head_n);
            let sampled = read_section(@self, proof_id, SECTION_SAMPLED, sampled_slots, sampled_n);
            let rows = unpack(rows_packed, rows_n);
            let witnesses = unpack(witnesses_packed, witnesses_n);
            let out = IStwoMachineGroupLibraryDispatcher {
                class_hash: self.group_class.read(),
            }
                .group(state, head, sampled, rows, witnesses);
            advance(ref self, proof_id, TAG_GROUP, out.span());
            out
        }

        fn finalize(
            ref self: ContractState,
            proof_id: felt252,
            state: Span<felt252>,
            head_packed: Span<felt252>,
            head_n: u32,
            fri_slots: u32,
            fri_n: u32,
        ) -> (felt252, felt252) {
            consume(@self, proof_id, TAG_GROUP, state);
            let head = unpack(head_packed, head_n);
            let fri = read_section(@self, proof_id, SECTION_FRI, fri_slots, fri_n);
            let (program_hash, output_hash) = IStwoMachineFriLibraryDispatcher {
                class_hash: self.fri_class.read(),
            }
                .finalize(state, head, fri);
            advance(ref self, proof_id, TAG_DONE, [program_hash, output_hash].span());

            let fact = poseidon_hash_span([program_hash, output_hash].span());
            IStwoSharedFactRegistryDispatcher { contract_address: self.registry.read() }
                .register_fact(fact);
            (program_hash, output_hash)
        }

        fn checkpoint(
            self: @ContractState, caller: ContractAddress, proof_id: felt252,
        ) -> (felt252, felt252) {
            self.checkpoints.entry((caller, proof_id)).read()
        }

        fn registry(self: @ContractState) -> ContractAddress {
            self.registry.read()
        }
    }
}
