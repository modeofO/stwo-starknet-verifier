//! Lane 2: resumable verification of the full Cairo verifier
//! (poseidon252 configuration). See docs/lane2-design.md.

pub mod claim_mix;
pub mod fri_chunks;
pub mod lookup_chunks;
pub mod machine;
pub mod resumable_full;
pub mod sponge;

#[starknet::interface]
pub trait IStwoFullPhaseA<TContractState> {
    /// Runs phase A over the unpacked proof stream and returns the
    /// serialized [`resumable_full::FullCheckpoint`].
    fn run_phase_a(self: @TContractState, packed: Span<felt252>, n_values: u32) -> Array<felt252>;
}

#[starknet::interface]
pub trait IStwoFullPhaseB<TContractState> {
    /// Runs phase B; returns (program_hash, output_hash) on success.
    fn run_phase_b(
        self: @TContractState, packed: Span<felt252>, n_values: u32, checkpoint: Span<felt252>,
    ) -> (felt252, felt252);
}

/// Library-class wrapper for phase A. NOT deployable as a single invoke —
/// this target exists to measure Sierra/CASM class sizes against the
/// declare caps while the sub-phasing work proceeds (docs/lane2-design.md).
#[starknet::contract]
mod StwoFullPhaseA {
    use super::{IStwoFullPhaseA, resumable_full, unpack_proof_v2};

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl StwoFullPhaseAImpl of IStwoFullPhaseA<ContractState> {
        fn run_phase_a(
            self: @ContractState, packed: Span<felt252>, n_values: u32,
        ) -> Array<felt252> {
            let values = unpack_proof_v2(packed, n_values);
            let checkpoint = resumable_full::phase_a(values.span());
            let mut serialized = array![];
            Serde::serialize(@checkpoint, ref serialized);
            serialized
        }
    }
}

/// Library-class wrapper for phase B (same size-probe caveat as phase A).
#[starknet::contract]
mod StwoFullPhaseB {
    use super::{IStwoFullPhaseB, resumable_full, unpack_proof_v2};

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl StwoFullPhaseBImpl of IStwoFullPhaseB<ContractState> {
        fn run_phase_b(
            self: @ContractState, packed: Span<felt252>, n_values: u32, checkpoint: Span<felt252>,
        ) -> (felt252, felt252) {
            let mut cp_span = checkpoint;
            let checkpoint: resumable_full::FullCheckpoint = Serde::deserialize(ref cp_span)
                .expect('checkpoint deser');
            let values = unpack_proof_v2(packed, n_values);
            let out = resumable_full::phase_b(values.span(), checkpoint);
            (out.program_hash, out.output_hash)
        }
    }
}

// ---------------------------------------------------------------------------
// Machine class wrappers (docs/lane2-design.md, machine plan v2): the phase
// families of `machine.cairo`, one library class each, to measure Sierra/CASM
// class sizes against the declare caps. Production wiring (packed sections,
// write-once checkpoint storage, registry route) comes on top of these.

#[starknet::interface]
pub trait IStwoMachineClaim<TContractState> {
    fn begin(
        self: @TContractState, head: Span<felt252>, program_len: u32,
    ) -> Array<felt252>;
    fn claim_chunk(
        self: @TContractState, state: Span<felt252>, entries: Span<felt252>,
    ) -> Array<felt252>;
    fn claim_finalize(
        self: @TContractState, state: Span<felt252>, head: Span<felt252>,
    ) -> Array<felt252>;
}

#[starknet::interface]
pub trait IStwoMachineLookup<TContractState> {
    fn lookup_chunk(
        self: @TContractState, state: Span<felt252>, entries: Span<felt252>,
    ) -> Array<felt252>;
    fn lookup_finalize(
        self: @TContractState, state: Span<felt252>, head: Span<felt252>,
    ) -> Array<felt252>;
}

#[starknet::interface]
pub trait IStwoMachineOods<TContractState> {
    fn oods_mix(
        self: @TContractState,
        state: Span<felt252>,
        head: Span<felt252>,
        sampled: Span<felt252>,
    ) -> Array<felt252>;
}

#[starknet::interface]
pub trait IStwoMachineGroup<TContractState> {
    fn group(
        self: @TContractState,
        state: Span<felt252>,
        head: Span<felt252>,
        sampled: Span<felt252>,
        rows: Span<felt252>,
        witnesses: Span<felt252>,
    ) -> Array<felt252>;
}

#[starknet::interface]
pub trait IStwoMachineFri<TContractState> {
    fn fri_commit(
        self: @TContractState, state: Span<felt252>, head: Span<felt252>, fri: Span<felt252>,
    ) -> Array<felt252>;
    fn finalize(
        self: @TContractState, state: Span<felt252>, head: Span<felt252>, fri: Span<felt252>,
    ) -> (felt252, felt252);
}

fn serialize_state<T, +Serde<T>, +Drop<T>>(state: T) -> Array<felt252> {
    let mut serialized = array![];
    Serde::serialize(@state, ref serialized);
    serialized
}

fn deserialize_state<T, +Serde<T>>(mut span: Span<felt252>) -> T {
    Serde::deserialize(ref span).expect('state deser')
}

#[starknet::contract]
mod StwoMachineClaim {
    use stwo_verifier_utils::MemorySection;
    use super::{IStwoMachineClaim, deserialize_state, machine, serialize_state};

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl StwoMachineClaimImpl of IStwoMachineClaim<ContractState> {
        fn begin(
            self: @ContractState, head: Span<felt252>, program_len: u32,
        ) -> Array<felt252> {
            serialize_state(machine::machine_begin(head, program_len))
        }
        fn claim_chunk(
            self: @ContractState, state: Span<felt252>, mut entries: Span<felt252>,
        ) -> Array<felt252> {
            let section: MemorySection = Serde::deserialize(ref entries).expect('entries');
            serialize_state(machine::machine_claim_chunk(deserialize_state(state), section))
        }
        fn claim_finalize(
            self: @ContractState, state: Span<felt252>, head: Span<felt252>,
        ) -> Array<felt252> {
            serialize_state(machine::machine_claim_finalize(deserialize_state(state), head))
        }
    }
}

#[starknet::contract]
mod StwoMachineLookup {
    use stwo_verifier_utils::MemorySection;
    use super::{IStwoMachineLookup, deserialize_state, machine, serialize_state};

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl StwoMachineLookupImpl of IStwoMachineLookup<ContractState> {
        fn lookup_chunk(
            self: @ContractState, state: Span<felt252>, mut entries: Span<felt252>,
        ) -> Array<felt252> {
            let section: MemorySection = Serde::deserialize(ref entries).expect('entries');
            serialize_state(machine::machine_lookup_chunk(deserialize_state(state), section))
        }
        fn lookup_finalize(
            self: @ContractState, state: Span<felt252>, head: Span<felt252>,
        ) -> Array<felt252> {
            serialize_state(machine::machine_lookup_finalize(deserialize_state(state), head))
        }
    }
}

#[starknet::contract]
mod StwoMachineOods {
    use super::{IStwoMachineOods, deserialize_state, machine, serialize_state};

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl StwoMachineOodsImpl of IStwoMachineOods<ContractState> {
        fn oods_mix(
            self: @ContractState,
            state: Span<felt252>,
            head: Span<felt252>,
            sampled: Span<felt252>,
        ) -> Array<felt252> {
            serialize_state(machine::machine_oods_mix(deserialize_state(state), head, sampled))
        }
    }
}

#[starknet::contract]
mod StwoMachineGroup {
    use stwo_verifier_core::fields::m31::M31;
    use stwo_verifier_core::pcs::verifier::QueriedValues;
    use super::{IStwoMachineGroup, deserialize_state, machine, serialize_state};

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl StwoMachineGroupImpl of IStwoMachineGroup<ContractState> {
        fn group(
            self: @ContractState,
            state: Span<felt252>,
            head: Span<felt252>,
            sampled: Span<felt252>,
            mut rows: Span<felt252>,
            mut witnesses: Span<felt252>,
        ) -> Array<felt252> {
            let rows: QueriedValues = Serde::deserialize(ref rows).expect('rows');
            let witnesses: Array<Span<felt252>> = Serde::deserialize(ref witnesses)
                .expect('witnesses');
            serialize_state(
                machine::machine_group(deserialize_state(state), head, sampled, rows, witnesses),
            )
        }
    }
}

#[starknet::contract]
mod StwoMachineFri {
    use super::{IStwoMachineFri, deserialize_state, machine, serialize_state};

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl StwoMachineFriImpl of IStwoMachineFri<ContractState> {
        fn fri_commit(
            self: @ContractState, state: Span<felt252>, head: Span<felt252>, fri: Span<felt252>,
        ) -> Array<felt252> {
            serialize_state(machine::machine_fri_commit(deserialize_state(state), head, fri))
        }
        fn finalize(
            self: @ContractState, state: Span<felt252>, head: Span<felt252>, fri: Span<felt252>,
        ) -> (felt252, felt252) {
            let out = machine::machine_finalize(deserialize_state(state), head, fri);
            (out.program_hash, out.output_hash)
        }
    }
}

/// Escape markers of the packed-proof v2 encoding (see `unpack_proof_v2`).
const U64_ESCAPE: u32 = 0xFFFFFFFF;
const FELT_ESCAPE: u32 = 0xFFFFFFFE;

/// Decodes the v2 packed limb stream back into the proof's felt252 stream:
/// 7 little-endian u32 limbs per felt252 slot; a limb of `0xFFFFFFFF`
/// escapes a (low, high) u64 pair; a limb of `0xFFFFFFFE` escapes a full
/// felt252 as 8 little-endian u32 limbs (poseidon proof streams carry full
/// felt252 hashes). Mirrors `scripts/pack_proof.py --v2`.
pub fn unpack_proof_v2(packed: Span<felt252>, n_values: u32) -> Array<felt252> {
    let nz32: NonZero<u128> = 0x100000000_u128.try_into().unwrap();
    let mut limbs: Array<u32> = array![];
    for slot in packed {
        let v: u256 = (*slot).into();
        let (q, l0) = DivRem::div_rem(v.low, nz32);
        let (q, l1) = DivRem::div_rem(q, nz32);
        let (l3, l2) = DivRem::div_rem(q, nz32);
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

    let limbs = limbs.span();
    let mut values: Array<felt252> = array![];
    let mut i: usize = 0;
    while values.len() != n_values {
        let limb = *limbs[i];
        if limb == U64_ESCAPE {
            let lo: felt252 = (*limbs[i + 1]).into();
            let hi: felt252 = (*limbs[i + 2]).into();
            values.append(lo + hi * 0x100000000);
            i += 3;
        } else if limb == FELT_ESCAPE {
            let mut v: felt252 = 0;
            let mut k: usize = 8;
            while k != 0 {
                v = v * 0x100000000 + (*limbs[i + k]).into();
                k -= 1;
            }
            values.append(v);
            i += 9;
        } else {
            values.append(limb.into());
            i += 1;
        }
    }
    values
}
