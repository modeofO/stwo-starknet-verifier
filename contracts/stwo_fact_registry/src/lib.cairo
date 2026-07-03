//! Stwo FactRegistry — lane 1 of the two-lane verification architecture.
//!
//! Accepts Stwo multiverifier circuit proofs (the recursion route: an
//! application program is proven under the privacy simple bootloader, that
//! proof is verified inside the cairo-verifier circuit, and a multiverifier
//! circuit proof of that verification is what lands here). Because proofs
//! (~36k felts) exceed the per-transaction calldata limit (5,000 felts), they
//! are staged into storage across multiple transactions, then verified and
//! registered in a single transaction.
//!
//! The registered fact is `poseidon(output_hash words)`, where `output_hash`
//! is the verifier's output `blake2s(multiverifier_preprocessed_root ‖
//! output_values)`. Consumer contracts recompute the expected output hash
//! chain (binding the application program hash and its outputs — see
//! docs/spike3-results.md) and check `is_valid(fact)`.

use stwo_circuit_air::VerificationOutput;

/// The escape marker of the packed-proof encoding (see `unpack_proof`).
const ESCAPE: u32 = 0xFFFFFFFF;

#[starknet::interface]
pub trait IStwoFactRegistry<TContractState> {
    /// Stages `slots` of a *packed* serialized `CircuitProof` at slot
    /// `offset` under the caller's `proof_id`. Chunks are keyed by caller,
    /// so uploads cannot be griefed by third parties.
    ///
    /// Packing format (storage syscalls dominate gas, and proof streams are
    /// almost entirely u32-valued): each slot holds 7 little-endian 32-bit
    /// limbs (`slot = Σ limb_i · 2^(32·i)`). A limb of `0xFFFFFFFF` is an
    /// escape: the next two limbs are the low/high halves of a u64 value.
    /// Values ≥ 2^64 do not occur in circuit-proof streams.
    fn stage_proof(
        ref self: TContractState, proof_id: felt252, offset: u32, slots: Span<felt252>,
    );

    /// Unpacks the staged proof (`n_slots` slots holding `n_values` proof
    /// felts), verifies it with the Stwo circuit verifier, registers and
    /// returns the fact. Panics if the proof is invalid or malformed.
    fn verify_and_register(
        ref self: TContractState, proof_id: felt252, n_slots: u32, n_values: u32,
    ) -> felt252;

    /// Like `verify_and_register`, but takes the head of the packed proof
    /// directly as calldata and reads only `n_tail_slots` staged slots
    /// (stored at indices 0..n_tail_slots) for the remainder.
    ///
    /// Rationale: storage reads dominate the all-storage variant's gas
    /// (Starknet's per-invoke cap is 1.21e9 L2 gas and reading ~5k slots
    /// costs ~3e8), while calldata is nearly free — but the per-transaction
    /// calldata limit (5,000 felts) is just below a whole packed proof
    /// (~5,147 slots). Splitting head-via-calldata / tail-via-storage yields
    /// a two-transaction flow: one small staging tx, one verify tx.
    fn verify_and_register_from_calldata(
        ref self: TContractState,
        proof_id: felt252,
        head: Span<felt252>,
        n_tail_slots: u32,
        n_values: u32,
    ) -> felt252;

    /// True iff `fact` was registered by a successful verification.
    fn is_valid(self: @TContractState, fact: felt252) -> bool;
}

/// Decodes the packed limb stream back into the proof's felt252 stream.
pub fn unpack_proof(packed: Span<felt252>, n_values: u32) -> Array<felt252> {
    // First pass: split each slot into 7 little-endian u32 limbs. Work on the
    // slot's two u128 halves — u128 div-rem is far cheaper than u256's.
    let nz32: NonZero<u128> = 0x100000000_u128.try_into().unwrap();
    let mut limbs: Array<u32> = array![];
    for slot in packed {
        let v: u256 = (*slot).into();
        // Low half: limbs 0-3.
        let (q, l0) = DivRem::div_rem(v.low, nz32);
        let (q, l1) = DivRem::div_rem(q, nz32);
        let (l3, l2) = DivRem::div_rem(q, nz32);
        // High half: limbs 4-6 (bits 224+ are always zero).
        let (q, l4) = DivRem::div_rem(v.high, nz32);
        let (l6, l5) = DivRem::div_rem(q, nz32);
        limbs.append(l0.try_into().unwrap());
        limbs.append(l1.try_into().unwrap());
        limbs.append(l2.try_into().unwrap());
        limbs.append(l3.try_into().unwrap());
        limbs.append(l4.try_into().unwrap());
        limbs.append(l5.try_into().unwrap());
        limbs.append(l6.try_into().unwrap());
    }

    // Second pass: rebuild values, honoring the u64 escape encoding.
    let limbs = limbs.span();
    let mut values: Array<felt252> = array![];
    let mut i: usize = 0;
    while values.len() != n_values {
        let limb = *limbs[i];
        if limb == ESCAPE {
            let lo: felt252 = (*limbs[i + 1]).into();
            let hi: felt252 = (*limbs[i + 2]).into();
            values.append(lo + hi * 0x100000000);
            i += 3;
        } else {
            values.append(limb.into());
            i += 1;
        }
    }
    values
}

/// Derives the registry fact from a verification output:
/// `poseidon(w0, …, w7)` over the 8 little-endian u32 words of
/// `blake2s(multiverifier_preprocessed_root ‖ output_values)`.
pub fn fact_from_output(output: @VerificationOutput) -> felt252 {
    let [w0, w1, w2, w3, w4, w5, w6, w7] = (*output.output_hash.hash).unbox();
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
    use starknet::{ContractAddress, get_caller_address};
    use stwo_circuit_air::{CircuitProof, get_verification_output, verify_circuit};
    use super::{IStwoFactRegistry, fact_from_output, unpack_proof};

    #[storage]
    struct Storage {
        /// Staged proof words: (uploader, proof_id, word index) -> felt.
        proof_words: Map<(ContractAddress, felt252, u32), felt252>,
        /// Registered facts.
        facts: Map<felt252, bool>,
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

        fn verify_and_register(
            ref self: ContractState, proof_id: felt252, n_slots: u32, n_values: u32,
        ) -> felt252 {
            let caller = get_caller_address();

            let mut packed = array![];
            let mut i = 0;
            while i != n_slots {
                packed.append(self.proof_words.entry((caller, proof_id, i)).read());
                i += 1;
            }
            let fact = verify_packed(packed.span(), n_values);
            self.facts.entry(fact).write(true);
            self.emit(FactRegistered { fact, prover: caller, proof_id });
            fact
        }

        fn is_valid(self: @ContractState, fact: felt252) -> bool {
            self.facts.entry(fact).read()
        }

        fn verify_and_register_from_calldata(
            ref self: ContractState,
            proof_id: felt252,
            head: Span<felt252>,
            n_tail_slots: u32,
            n_values: u32,
        ) -> felt252 {
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

            let fact = verify_packed(packed.span(), n_values);
            self.facts.entry(fact).write(true);
            self.emit(FactRegistered { fact, prover: caller, proof_id });
            fact
        }
    }

    /// Unpacks, deserializes, verifies, and derives the fact.
    fn verify_packed(packed: Span<felt252>, n_values: u32) -> felt252 {
        let serialized = unpack_proof(packed, n_values);
        let mut span = serialized.span();
        let proof: CircuitProof = Serde::deserialize(ref span)
            .expect('proof deserialization failed');
        assert(span.is_empty(), 'trailing proof data');

        let output = get_verification_output(@proof);
        verify_circuit(:proof);
        fact_from_output(@output)
    }
}
