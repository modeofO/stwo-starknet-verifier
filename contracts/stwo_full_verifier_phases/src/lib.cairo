//! Lane 2: resumable verification of the full Cairo verifier
//! (poseidon252 configuration). See docs/lane2-design.md.

#[cfg(feature: "poseidon252_verifier")]
pub mod claim_mix;
#[cfg(not(feature: "poseidon252_verifier"))]
pub mod claim_mix_blake;
pub mod channel_compat;
pub mod fact_registry;
pub mod fri_chunks;
pub mod lookup_chunks;
pub mod machine;
pub mod oods_chunks;
pub mod pack;
pub mod resumable_full;
pub mod router;
pub mod split;
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
    use stwo_verifier_core::pcs::verifier::QueriedValues;
    use stwo_verifier_core::Hash;
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
            let witnesses: Array<Span<Hash>> = Serde::deserialize(ref witnesses)
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

// ---------------------------------------------------------------------------
// OODS chunk classes: begin + one class per component family (the split of
// the 762k-felt StwoMachineOods; families can be merged into fewer classes
// wherever the summed sizes stay under the caps) + finalize.

#[starknet::interface]
pub trait IStwoOodsBegin<TContractState> {
    fn oods_begin(
        self: @TContractState, state: Span<felt252>, head: Span<felt252>, sampled: Span<felt252>,
    ) -> Array<felt252>;
}

/// One OODS component-family group transaction.
#[starknet::interface]
pub trait IStwoOodsGroup<TContractState> {
    fn run(
        self: @TContractState, state: Span<felt252>, head: Span<felt252>, sampled: Span<felt252>,
    ) -> Array<felt252>;
}

#[starknet::interface]
pub trait IStwoOodsFinalize<TContractState> {
    fn oods_finalize(
        self: @TContractState, state: Span<felt252>, head: Span<felt252>, sampled: Span<felt252>,
    ) -> Array<felt252>;
}

#[starknet::contract]
mod StwoOodsBegin {
    use super::{IStwoOodsBegin, deserialize_state, oods_chunks, serialize_state};

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl Impl of IStwoOodsBegin<ContractState> {
        fn oods_begin(
            self: @ContractState,
            state: Span<felt252>,
            head: Span<felt252>,
            sampled: Span<felt252>,
        ) -> Array<felt252> {
            serialize_state(oods_chunks::oods_begin(deserialize_state(state), head, sampled))
        }
    }
}

// Group classes G00..G14 cover the 49/56-family sequence consecutively
// (family index map in oods_chunks.cairo) — the measured-optimal merge of
// the earlier one-sub-air F00..F19 classes: every class fits all three
// declare caps on the qm31 build with the worst fill at 95% of the
// 4,089,446-byte class cap (G05), and every remaining adjacent pair-merge
// exceeds a cap (the ~11-15k-felt shared prologue/epilogue dedup credit
// per merge is already taken). The four oversized component evals remain
// two-half seam forks (src/split/): their A and B parts may land in
// different classes, with the seam carry riding the checkpoint between
// transactions, or in the same class, where the carry just flows through
// `ctx` between family calls. G07 is cfg-split like the old F12: the
// blake build fans the builtins sub-air into 8 per-component families.
//
//   G00 F00+F01    opcodes add..assert_eq_double_deref   (fams 0..5)
//   G01 F02A       blake_compress half A                 (6)
//   G02 F02B+F03+F04  compress B + call..jump_rel_imm    (7..15)
//   G03 F05A+F05B  mul, mul_small                        (16..17)
//   G04 F06..F09A1 qm31, ret, verify_instruction, round A1 (18..21)
//   G05 F09A2+A3   blake_round A2, A3                    (22..23)
//   G06 F09B..F11  round B, blake_g, sigma, xor32, xor12 (24..28)
//   G07 F12+F13A1  builtins (1|8 fams) + aggregator A1   (29..30+SHIFT)
//   G08 F13A2      aggregator A2 (hades permutation)     (31+SHIFT)
//   G09 F13A3+B+F14  aggregator A3, B, 3_partial_rounds  (32..34+SHIFT)
//   G10 F15        full_round_chain                      (35+SHIFT)
//   G11 F16A       cube_252 half A                       (36+SHIFT)
//   G12 F16B1      cube_252 B1                           (37+SHIFT)
//   G13 F16B2+F17  cube_252 B2, round_keys, rc252w27     (38..40+SHIFT)
//   G14 F18+F19    memory, range_checks, xor4/7/8/9      (41..48+SHIFT)
#[starknet::contract]
mod StwoOodsG00 {
    use super::{IStwoOodsGroup, deserialize_state, oods_chunks, serialize_state};
    #[storage]
    struct Storage {}
    #[abi(embed_v0)]
    impl Impl of IStwoOodsGroup<ContractState> {
        fn run(
            self: @ContractState,
            state: Span<felt252>,
            head: Span<felt252>,
            sampled: Span<felt252>,
        ) -> Array<felt252> {
            let (state, mut ctx) = oods_chunks::oods_group_prologue(
                deserialize_state(state), head, sampled, 0,
            );
            oods_chunks::family_add_opcode(ref ctx);
            oods_chunks::family_add_opcode_small(ref ctx);
            oods_chunks::family_add_ap_opcode(ref ctx);
            oods_chunks::family_assert_eq_opcode(ref ctx);
            oods_chunks::family_assert_eq_opcode_imm(ref ctx);
            oods_chunks::family_assert_eq_opcode_double_deref(ref ctx);
            serialize_state(oods_chunks::oods_group_epilogue(state, ctx, 6))
        }
    }
}

#[starknet::contract]
mod StwoOodsG01 {
    use super::{IStwoOodsGroup, deserialize_state, oods_chunks, serialize_state};
    #[storage]
    struct Storage {}
    #[abi(embed_v0)]
    impl Impl of IStwoOodsGroup<ContractState> {
        fn run(
            self: @ContractState,
            state: Span<felt252>,
            head: Span<felt252>,
            sampled: Span<felt252>,
        ) -> Array<felt252> {
            let (state, mut ctx) = oods_chunks::oods_group_prologue(
                deserialize_state(state), head, sampled, 6,
            );
            oods_chunks::family_blake_compress_opcode_a(ref ctx);
            serialize_state(oods_chunks::oods_group_epilogue(state, ctx, 1))
        }
    }
}

#[starknet::contract]
mod StwoOodsG02 {
    use super::{IStwoOodsGroup, deserialize_state, oods_chunks, serialize_state};
    #[storage]
    struct Storage {}
    #[abi(embed_v0)]
    impl Impl of IStwoOodsGroup<ContractState> {
        fn run(
            self: @ContractState,
            state: Span<felt252>,
            head: Span<felt252>,
            sampled: Span<felt252>,
        ) -> Array<felt252> {
            let (state, mut ctx) = oods_chunks::oods_group_prologue(
                deserialize_state(state), head, sampled, 7,
            );
            oods_chunks::family_blake_compress_opcode_b(ref ctx);
            oods_chunks::family_call_opcode_abs(ref ctx);
            oods_chunks::family_call_opcode_rel_imm(ref ctx);
            oods_chunks::family_jnz_opcode_non_taken(ref ctx);
            oods_chunks::family_jnz_opcode_taken(ref ctx);
            oods_chunks::family_jump_opcode_abs(ref ctx);
            oods_chunks::family_jump_opcode_double_deref(ref ctx);
            oods_chunks::family_jump_opcode_rel(ref ctx);
            oods_chunks::family_jump_opcode_rel_imm(ref ctx);
            serialize_state(oods_chunks::oods_group_epilogue(state, ctx, 9))
        }
    }
}

#[starknet::contract]
mod StwoOodsG03 {
    use super::{IStwoOodsGroup, deserialize_state, oods_chunks, serialize_state};
    #[storage]
    struct Storage {}
    #[abi(embed_v0)]
    impl Impl of IStwoOodsGroup<ContractState> {
        fn run(
            self: @ContractState,
            state: Span<felt252>,
            head: Span<felt252>,
            sampled: Span<felt252>,
        ) -> Array<felt252> {
            let (state, mut ctx) = oods_chunks::oods_group_prologue(
                deserialize_state(state), head, sampled, 16,
            );
            oods_chunks::family_mul_opcode(ref ctx);
            oods_chunks::family_mul_opcode_small(ref ctx);
            serialize_state(oods_chunks::oods_group_epilogue(state, ctx, 2))
        }
    }
}

#[starknet::contract]
mod StwoOodsG04 {
    use super::{IStwoOodsGroup, deserialize_state, oods_chunks, serialize_state};
    #[storage]
    struct Storage {}
    #[abi(embed_v0)]
    impl Impl of IStwoOodsGroup<ContractState> {
        fn run(
            self: @ContractState,
            state: Span<felt252>,
            head: Span<felt252>,
            sampled: Span<felt252>,
        ) -> Array<felt252> {
            let (state, mut ctx) = oods_chunks::oods_group_prologue(
                deserialize_state(state), head, sampled, 18,
            );
            oods_chunks::family_qm_31_add_mul_opcode(ref ctx);
            oods_chunks::family_ret_opcode(ref ctx);
            oods_chunks::family_verify_instruction(ref ctx);
            oods_chunks::family_blake_round_a1(ref ctx);
            serialize_state(oods_chunks::oods_group_epilogue(state, ctx, 4))
        }
    }
}

#[starknet::contract]
mod StwoOodsG05 {
    use super::{IStwoOodsGroup, deserialize_state, oods_chunks, serialize_state};
    #[storage]
    struct Storage {}
    #[abi(embed_v0)]
    impl Impl of IStwoOodsGroup<ContractState> {
        fn run(
            self: @ContractState,
            state: Span<felt252>,
            head: Span<felt252>,
            sampled: Span<felt252>,
        ) -> Array<felt252> {
            let (state, mut ctx) = oods_chunks::oods_group_prologue(
                deserialize_state(state), head, sampled, 22,
            );
            oods_chunks::family_blake_round_a2(ref ctx);
            oods_chunks::family_blake_round_a3(ref ctx);
            serialize_state(oods_chunks::oods_group_epilogue(state, ctx, 2))
        }
    }
}

#[starknet::contract]
mod StwoOodsG06 {
    use super::{IStwoOodsGroup, deserialize_state, oods_chunks, serialize_state};
    #[storage]
    struct Storage {}
    #[abi(embed_v0)]
    impl Impl of IStwoOodsGroup<ContractState> {
        fn run(
            self: @ContractState,
            state: Span<felt252>,
            head: Span<felt252>,
            sampled: Span<felt252>,
        ) -> Array<felt252> {
            let (state, mut ctx) = oods_chunks::oods_group_prologue(
                deserialize_state(state), head, sampled, 24,
            );
            oods_chunks::family_blake_round_b(ref ctx);
            oods_chunks::family_blake_g(ref ctx);
            oods_chunks::family_blake_round_sigma(ref ctx);
            oods_chunks::family_triple_xor_32(ref ctx);
            oods_chunks::family_verify_bitwise_xor_12(ref ctx);
            serialize_state(oods_chunks::oods_group_epilogue(state, ctx, 5))
        }
    }
}

#[cfg(feature: "poseidon252_verifier")]
#[starknet::contract]
mod StwoOodsG07 {
    use super::{IStwoOodsGroup, deserialize_state, oods_chunks, serialize_state};
    #[storage]
    struct Storage {}
    #[abi(embed_v0)]
    impl Impl of IStwoOodsGroup<ContractState> {
        fn run(
            self: @ContractState,
            state: Span<felt252>,
            head: Span<felt252>,
            sampled: Span<felt252>,
        ) -> Array<felt252> {
            let (state, mut ctx) = oods_chunks::oods_group_prologue(
                deserialize_state(state), head, sampled, 29,
            );
            oods_chunks::family_builtins(ref ctx);
            oods_chunks::family_poseidon_aggregator_a1(ref ctx);
            serialize_state(oods_chunks::oods_group_epilogue(state, ctx, 2))
        }
    }
}

#[cfg(not(feature: "poseidon252_verifier"))]
#[starknet::contract]
mod StwoOodsG07 {
    use super::{IStwoOodsGroup, deserialize_state, oods_chunks, serialize_state};
    #[storage]
    struct Storage {}
    #[abi(embed_v0)]
    impl Impl of IStwoOodsGroup<ContractState> {
        fn run(
            self: @ContractState,
            state: Span<felt252>,
            head: Span<felt252>,
            sampled: Span<felt252>,
        ) -> Array<felt252> {
            let (state, mut ctx) = oods_chunks::oods_group_prologue(
                deserialize_state(state), head, sampled, 29,
            );
            oods_chunks::family_add_mod_builtin(ref ctx);
            oods_chunks::family_bitwise_builtin(ref ctx);
            oods_chunks::family_mul_mod_builtin(ref ctx);
            oods_chunks::family_pedersen_builtin(ref ctx);
            oods_chunks::family_poseidon_builtin(ref ctx);
            oods_chunks::family_range_check_96_builtin(ref ctx);
            oods_chunks::family_range_check_128_builtin(ref ctx);
            oods_chunks::family_ec_op_builtin(ref ctx);
            oods_chunks::family_poseidon_aggregator_a1(ref ctx);
            serialize_state(oods_chunks::oods_group_epilogue(state, ctx, 9))
        }
    }
}

#[starknet::contract]
mod StwoOodsG08 {
    use super::{IStwoOodsGroup, deserialize_state, oods_chunks, serialize_state};
    #[storage]
    struct Storage {}
    #[abi(embed_v0)]
    impl Impl of IStwoOodsGroup<ContractState> {
        fn run(
            self: @ContractState,
            state: Span<felt252>,
            head: Span<felt252>,
            sampled: Span<felt252>,
        ) -> Array<felt252> {
            let (state, mut ctx) = oods_chunks::oods_group_prologue(
                deserialize_state(state), head, sampled, 31 + oods_chunks::FAMILY_SHIFT,
            );
            oods_chunks::family_poseidon_aggregator_a2(ref ctx);
            serialize_state(oods_chunks::oods_group_epilogue(state, ctx, 1))
        }
    }
}

#[starknet::contract]
mod StwoOodsG09 {
    use super::{IStwoOodsGroup, deserialize_state, oods_chunks, serialize_state};
    #[storage]
    struct Storage {}
    #[abi(embed_v0)]
    impl Impl of IStwoOodsGroup<ContractState> {
        fn run(
            self: @ContractState,
            state: Span<felt252>,
            head: Span<felt252>,
            sampled: Span<felt252>,
        ) -> Array<felt252> {
            let (state, mut ctx) = oods_chunks::oods_group_prologue(
                deserialize_state(state), head, sampled, 32 + oods_chunks::FAMILY_SHIFT,
            );
            oods_chunks::family_poseidon_aggregator_a3(ref ctx);
            oods_chunks::family_poseidon_aggregator_b(ref ctx);
            oods_chunks::family_poseidon_3_partial_rounds_chain(ref ctx);
            serialize_state(oods_chunks::oods_group_epilogue(state, ctx, 3))
        }
    }
}

#[starknet::contract]
mod StwoOodsG10 {
    use super::{IStwoOodsGroup, deserialize_state, oods_chunks, serialize_state};
    #[storage]
    struct Storage {}
    #[abi(embed_v0)]
    impl Impl of IStwoOodsGroup<ContractState> {
        fn run(
            self: @ContractState,
            state: Span<felt252>,
            head: Span<felt252>,
            sampled: Span<felt252>,
        ) -> Array<felt252> {
            let (state, mut ctx) = oods_chunks::oods_group_prologue(
                deserialize_state(state), head, sampled, 35 + oods_chunks::FAMILY_SHIFT,
            );
            oods_chunks::family_poseidon_full_round_chain(ref ctx);
            serialize_state(oods_chunks::oods_group_epilogue(state, ctx, 1))
        }
    }
}

#[starknet::contract]
mod StwoOodsG11 {
    use super::{IStwoOodsGroup, deserialize_state, oods_chunks, serialize_state};
    #[storage]
    struct Storage {}
    #[abi(embed_v0)]
    impl Impl of IStwoOodsGroup<ContractState> {
        fn run(
            self: @ContractState,
            state: Span<felt252>,
            head: Span<felt252>,
            sampled: Span<felt252>,
        ) -> Array<felt252> {
            let (state, mut ctx) = oods_chunks::oods_group_prologue(
                deserialize_state(state), head, sampled, 36 + oods_chunks::FAMILY_SHIFT,
            );
            oods_chunks::family_cube_252_a(ref ctx);
            serialize_state(oods_chunks::oods_group_epilogue(state, ctx, 1))
        }
    }
}

#[starknet::contract]
mod StwoOodsG12 {
    use super::{IStwoOodsGroup, deserialize_state, oods_chunks, serialize_state};
    #[storage]
    struct Storage {}
    #[abi(embed_v0)]
    impl Impl of IStwoOodsGroup<ContractState> {
        fn run(
            self: @ContractState,
            state: Span<felt252>,
            head: Span<felt252>,
            sampled: Span<felt252>,
        ) -> Array<felt252> {
            let (state, mut ctx) = oods_chunks::oods_group_prologue(
                deserialize_state(state), head, sampled, 37 + oods_chunks::FAMILY_SHIFT,
            );
            oods_chunks::family_cube_252_b1(ref ctx);
            serialize_state(oods_chunks::oods_group_epilogue(state, ctx, 1))
        }
    }
}

#[starknet::contract]
mod StwoOodsG13 {
    use super::{IStwoOodsGroup, deserialize_state, oods_chunks, serialize_state};
    #[storage]
    struct Storage {}
    #[abi(embed_v0)]
    impl Impl of IStwoOodsGroup<ContractState> {
        fn run(
            self: @ContractState,
            state: Span<felt252>,
            head: Span<felt252>,
            sampled: Span<felt252>,
        ) -> Array<felt252> {
            let (state, mut ctx) = oods_chunks::oods_group_prologue(
                deserialize_state(state), head, sampled, 38 + oods_chunks::FAMILY_SHIFT,
            );
            oods_chunks::family_cube_252_b2(ref ctx);
            oods_chunks::family_poseidon_round_keys(ref ctx);
            oods_chunks::family_range_check_252_width_27(ref ctx);
            serialize_state(oods_chunks::oods_group_epilogue(state, ctx, 3))
        }
    }
}

#[starknet::contract]
mod StwoOodsG14 {
    use super::{IStwoOodsGroup, deserialize_state, oods_chunks, serialize_state};
    #[storage]
    struct Storage {}
    #[abi(embed_v0)]
    impl Impl of IStwoOodsGroup<ContractState> {
        fn run(
            self: @ContractState,
            state: Span<felt252>,
            head: Span<felt252>,
            sampled: Span<felt252>,
        ) -> Array<felt252> {
            let (state, mut ctx) = oods_chunks::oods_group_prologue(
                deserialize_state(state), head, sampled, 41 + oods_chunks::FAMILY_SHIFT,
            );
            oods_chunks::family_memory_address_to_id(ref ctx);
            oods_chunks::family_memory_id_to_big(ref ctx);
            oods_chunks::family_memory_id_to_small(ref ctx);
            oods_chunks::family_range_checks(ref ctx);
            oods_chunks::family_verify_bitwise_xor_4(ref ctx);
            oods_chunks::family_verify_bitwise_xor_7(ref ctx);
            oods_chunks::family_verify_bitwise_xor_8(ref ctx);
            oods_chunks::family_verify_bitwise_xor_9(ref ctx);
            serialize_state(oods_chunks::oods_group_epilogue(state, ctx, 8))
        }
    }
}

#[starknet::contract]
mod StwoOodsFinalize {
    use super::{IStwoOodsFinalize, deserialize_state, oods_chunks, serialize_state};

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl Impl of IStwoOodsFinalize<ContractState> {
        fn oods_finalize(
            self: @ContractState,
            state: Span<felt252>,
            head: Span<felt252>,
            sampled: Span<felt252>,
        ) -> Array<felt252> {
            serialize_state(oods_chunks::oods_finalize(deserialize_state(state), head, sampled))
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
