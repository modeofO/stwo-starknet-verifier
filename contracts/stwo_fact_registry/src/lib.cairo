//! Stwo FactRegistry — lane 1 of the two-lane verification architecture.
//!
//! Accepts Stwo multiverifier circuit proofs (the recursion route: an
//! application program is proven under the privacy simple bootloader, that
//! proof is verified inside the cairo-verifier circuit, and a multiverifier
//! circuit proof of that verification is what lands here).
//!
//! Verification runs in two transactions because the monolithic verifier
//! (~1.4e9 L2 gas) exceeds Starknet's 1.21e9 per-invoke cap, and the
//! verification code itself exceeds the 81,920-felt CASM cap when combined
//! in one class. The phases live in two *library classes*
//! (`stwo_verifier_phases`), invoked via `library_call`; their class hashes
//! are fixed at construction and cannot be changed (a swappable verifier is
//! a rug vector).
//!
//! Flow (3 transactions per fact):
//!   1. `stage_proof` — stage the packed proof's tail (the part beyond the
//!      5,000-felt calldata limit of the phase-1 transaction).
//!   2. `verify_phase1` — head via calldata + staged tail: prologue, OODS,
//!      tree Merkle decommitments, FRI answers; stores a small checkpoint.
//!   3. `verify_phase2` — the proof's FRI section via calldata: FRI
//!      decommitment bound to the checkpoint; registers the fact.
//!
//! The registered fact is `poseidon(output_hash words)`, where `output_hash`
//! is `blake2s(multiverifier_preprocessed_root ‖ output_values)`, binding
//! the application program hash and outputs via a blake2s chain (see
//! docs/spike3-results.md). Consumers check `is_valid(fact)`.

#[starknet::interface]
pub trait IStwoFactRegistry<TContractState> {
    /// Stages `slots` of the packed proof at slot `offset` under the
    /// caller's `proof_id`. Chunks are keyed by caller, so uploads cannot
    /// be griefed by third parties. Packing format: 7 little-endian u32
    /// limbs per felt252 slot, `0xFFFFFFFF` escapes a u64 (low, high) pair.
    fn stage_proof(
        ref self: TContractState, proof_id: felt252, offset: u32, slots: Span<felt252>,
    );

    /// Verification phase 1 over head-via-calldata + staged tail (slots
    /// 0..n_tail_slots). Stores a checkpoint keyed by (caller, proof_id)
    /// and returns the felt-stream offset of the proof's `fri_proof` field
    /// (the client passes the stream from that offset, minus the trailing
    /// channel_salt, to phase 2).
    fn verify_phase1(
        ref self: TContractState,
        proof_id: felt252,
        head: Span<felt252>,
        n_tail_slots: u32,
        n_values: u32,
    ) -> u32;

    /// Verification phase 2: FRI decommitment over the packed `fri_proof`
    /// section (calldata), bound to the phase-1 checkpoint. Registers and
    /// returns the fact on success.
    fn verify_phase2(
        ref self: TContractState, proof_id: felt252, fri_slots: Span<felt252>, n_fri_values: u32,
    ) -> felt252;

    /// True iff `fact` was registered by a successful verification.
    fn is_valid(self: @TContractState, fact: felt252) -> bool;

    /// The immutable phase library class hashes.
    fn verifier_classes(self: @TContractState) -> (starknet::ClassHash, starknet::ClassHash);
}

/// Derives the registry fact from the output-hash words: `poseidon(w0…w7)`.
pub fn fact_from_words(words: [u32; 8]) -> felt252 {
    let [w0, w1, w2, w3, w4, w5, w6, w7] = words;
    core::poseidon::poseidon_hash_span(
        array![
            w0.into(), w1.into(), w2.into(), w3.into(), w4.into(), w5.into(), w6.into(),
            w7.into(),
        ]
            .span(),
    )
}

#[starknet::contract]
mod StwoFactRegistry {
    use starknet::storage::{
        Map, StoragePathEntry, StoragePointerReadAccess, StoragePointerWriteAccess,
    };
    use starknet::{ClassHash, ContractAddress, get_caller_address};
    use stwo_verifier_phases::{
        IStwoPhase1DispatcherTrait, IStwoPhase1LibraryDispatcher, IStwoPhase2DispatcherTrait,
        IStwoPhase2LibraryDispatcher,
    };
    use super::{IStwoFactRegistry, fact_from_words};

    #[storage]
    struct Storage {
        /// Immutable phase library class hashes (set at construction).
        phase1_class: ClassHash,
        phase2_class: ClassHash,
        /// Staged proof slots: (uploader, proof_id, slot index) -> felt.
        proof_words: Map<(ContractAddress, felt252, u32), felt252>,
        /// Registered facts.
        facts: Map<felt252, bool>,
        /// Serialized phase-1 checkpoints: length + words.
        checkpoint_len: Map<(ContractAddress, felt252), u32>,
        checkpoint_words: Map<(ContractAddress, felt252, u32), felt252>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        FactRegistered: FactRegistered,
    }

    /// A proof was verified and its fact registered.
    #[derive(Drop, starknet::Event)]
    struct FactRegistered {
        #[key]
        fact: felt252,
        prover: ContractAddress,
        proof_id: felt252,
    }

    #[constructor]
    fn constructor(ref self: ContractState, phase1_class: ClassHash, phase2_class: ClassHash) {
        self.phase1_class.write(phase1_class);
        self.phase2_class.write(phase2_class);
    }

    #[abi(embed_v0)]
    impl StwoFactRegistryImpl of IStwoFactRegistry<ContractState> {
        fn stage_proof(
            ref self: ContractState, proof_id: felt252, offset: u32, slots: Span<felt252>,
        ) {
            let caller = get_caller_address();
            let mut i = offset;
            for slot in slots {
                self.proof_words.entry((caller, proof_id, i)).write(*slot);
                i += 1;
            }
        }

        fn verify_phase1(
            ref self: ContractState,
            proof_id: felt252,
            head: Span<felt252>,
            n_tail_slots: u32,
            n_values: u32,
        ) -> u32 {
            let caller = get_caller_address();

            let mut packed = array![];
            for slot in head {
                packed.append(*slot);
            }
            let mut i = 0;
            while i != n_tail_slots {
                packed.append(self.proof_words.entry((caller, proof_id, i)).read());
                i += 1;
            }

            let phase1 = IStwoPhase1LibraryDispatcher { class_hash: self.phase1_class.read() };
            let serialized = phase1.run_phase1(packed.span(), n_values);

            // The checkpoint's last field is `fri_value_offset` (see
            // resumable::Checkpoint); surface it as the return value.
            let fri_value_offset: u32 = (*serialized[serialized.len() - 1]).try_into().unwrap();

            self.checkpoint_len.entry((caller, proof_id)).write(serialized.len());
            let mut j = 0;
            for word in serialized.span() {
                self.checkpoint_words.entry((caller, proof_id, j)).write(*word);
                j += 1;
            }

            fri_value_offset
        }

        fn verify_phase2(
            ref self: ContractState, proof_id: felt252, fri_slots: Span<felt252>, n_fri_values: u32,
        ) -> felt252 {
            let caller = get_caller_address();

            let len = self.checkpoint_len.entry((caller, proof_id)).read();
            assert(len != 0, 'no phase1 checkpoint');
            let mut serialized = array![];
            let mut i = 0;
            while i != len {
                serialized.append(self.checkpoint_words.entry((caller, proof_id, i)).read());
                i += 1;
            }

            let phase2 = IStwoPhase2LibraryDispatcher { class_hash: self.phase2_class.read() };
            let output_hash = phase2.run_phase2(fri_slots, n_fri_values, serialized.span());

            let fact = fact_from_words(output_hash);
            self.facts.entry(fact).write(true);
            // Consume the checkpoint.
            self.checkpoint_len.entry((caller, proof_id)).write(0);
            self.emit(FactRegistered { fact, prover: caller, proof_id });
            fact
        }

        fn is_valid(self: @ContractState, fact: felt252) -> bool {
            self.facts.entry(fact).read()
        }

        fn verifier_classes(self: @ContractState) -> (ClassHash, ClassHash) {
            (self.phase1_class.read(), self.phase2_class.read())
        }
    }
}
