//! Chunked OODS equivalence over the REAL fixture proof: oods_begin →
//! per-family group transactions (with checkpoint serde round-trips) →
//! oods_finalize must produce exactly the FriCommitPhaseState that the
//! monolithic `machine_oods_mix` produces from the same OodsPhaseState.

use core::array::SpanTrait;
use core::cmp::min;
use snforge_std::fs::{FileTrait, read_txt};
use stwo_cairo_air::claim::CairoInteractionClaim;
use stwo_cairo_air::claims::CairoClaim;
use stwo_full_verifier_phases::machine::{
    FriCommitPhaseState, HEAD_PROGRAM_ENTRIES, machine_begin, machine_claim_chunk,
    machine_claim_finalize, machine_lookup_chunk, machine_lookup_finalize, machine_oods_mix,
    OodsPhaseState,
};
use stwo_full_verifier_phases::oods_chunks::{
    family_add_ap_opcode, family_add_opcode, family_add_opcode_small, family_assert_eq_opcode,
    family_assert_eq_opcode_double_deref, family_assert_eq_opcode_imm,
    family_blake_compress_opcode_a, family_blake_compress_opcode_b, family_blake_g,
    family_blake_round_a, family_blake_round_b, family_blake_round_sigma, family_builtins,
    family_call_opcode_abs, family_call_opcode_rel_imm, family_cube_252_a, family_cube_252_b,
    family_jnz_opcode_non_taken, family_jnz_opcode_taken, family_jump_opcode_abs,
    family_jump_opcode_double_deref, family_jump_opcode_rel, family_jump_opcode_rel_imm,
    family_memory_address_to_id, family_memory_id_to_big, family_memory_id_to_small,
    family_mul_opcode, family_mul_opcode_small, family_poseidon_3_partial_rounds_chain,
    family_poseidon_aggregator_a, family_poseidon_aggregator_b, family_poseidon_full_round_chain,
    family_poseidon_round_keys, family_qm_31_add_mul_opcode, family_range_check_252_width_27,
    family_range_checks, family_ret_opcode, family_triple_xor_32, family_verify_bitwise_xor_12,
    family_verify_bitwise_xor_4, family_verify_bitwise_xor_7, family_verify_bitwise_xor_8,
    family_verify_bitwise_xor_9, family_verify_instruction, N_FAMILIES, oods_begin,
    oods_finalize, oods_group_epilogue, oods_group_prologue, OodsEvalState,
};
use stwo_full_verifier_phases::unpack_proof_v2;
use stwo_verifier_core::fields::m31::M31;
use stwo_verifier_core::fields::qm31::{QM31, QM31Serde, qm31_const};
use stwo_verifier_core::fri::FriProof;
use stwo_verifier_core::pcs::PcsConfig;
use stwo_verifier_core::vcs::MerkleHasher;
use stwo_verifier_core::vcs::verifier::MerkleDecommitment;
use stwo_verifier_core::Hash;
use stwo_verifier_utils::MemorySection;

const N_VALUES: u32 = 301_143;
const CHUNK_ENTRIES: u32 = 540;
const FELTS_PER_ENTRY: u32 = 9;

#[derive(Drop)]
struct Streams {
    head: Array<felt252>,
    program: MemorySection,
    sampled: Span<felt252>,
}

/// Same carving as test_machine's build_streams (fri section not needed).
fn build_streams(values: Span<felt252>) -> Streams {
    let total = SpanTrait::len(values);
    let mut span = values;
    let claim: CairoClaim = Serde::deserialize(ref span).expect('claim');
    let claim_end = total - SpanTrait::len(span);
    let _pow: u64 = Serde::deserialize(ref span).expect('pow');
    let _icl: CairoInteractionClaim = Serde::deserialize(ref span).expect('icl');
    let _config: PcsConfig = Serde::deserialize(ref span).expect('config');
    let _commitments: Span<Hash> = Serde::deserialize(ref span).expect('commitments');
    let commitments_end = total - SpanTrait::len(span);
    let _sampled: Span<Span<Span<QM31>>> = Serde::deserialize(ref span).expect('sampled');
    let sampled_end = total - SpanTrait::len(span);
    let _decommitments: Array<MerkleDecommitment<MerkleHasher>> = Serde::deserialize(ref span)
        .expect('decommitments');
    let _queried: Array<Span<M31>> = Serde::deserialize(ref span).expect('queried');
    let queried_end = total - SpanTrait::len(span);

    let claim_felts = values.slice(0, claim_end);
    let program_len: u32 = (*claim_felts[0]).try_into().unwrap();
    let mut head: Array<felt252> = array![HEAD_PROGRAM_ENTRIES.into()];
    head.append_span(claim_felts.slice(1, HEAD_PROGRAM_ENTRIES * FELTS_PER_ENTRY));
    let rest_offset = 1 + program_len * FELTS_PER_ENTRY;
    head.append_span(claim_felts.slice(rest_offset, claim_end - rest_offset));
    head.append_span(values.slice(claim_end, commitments_end - claim_end));
    head.append(*values[queried_end]); // queries PoW nonce
    head.append(*values[total - 1]); // channel salt

    Streams {
        head,
        program: claim.public_data.public_memory.program,
        sampled: values.slice(commitments_end, sampled_end - commitments_end),
    }
}

fn roundtrip<T, +Serde<T>, +Drop<T>>(state: T) -> T {
    let mut felts = array![];
    Serde::serialize(@state, ref felts);
    let mut span = felts.span();
    Serde::deserialize(ref span).expect('checkpoint roundtrip')
}

/// Drives the machine to the OODS phase boundary over the fixture.
fn setup_oods_state(streams: @Streams) -> OodsPhaseState {
    let program = *streams.program;
    let n_entries = program.len();
    let head = streams.head.span();

    let mut claim_state = machine_begin(head, n_entries);
    let mut offset = 0_u32;
    while offset != n_entries {
        let n = min(n_entries - offset, CHUNK_ENTRIES);
        claim_state = machine_claim_chunk(claim_state, program.slice(offset, n));
        offset += n;
    }
    let mut lookup_state = machine_claim_finalize(claim_state, head);
    let mut offset = 0_u32;
    while offset != n_entries {
        let n = min(n_entries - offset, CHUNK_ENTRIES);
        lookup_state = machine_lookup_chunk(lookup_state, program.slice(offset, n));
        offset += n;
    }
    machine_lookup_finalize(lookup_state, head)
}

#[test]
fn test_chunked_oods_matches_monolithic() {
    let file = FileTrait::new("tests/data/poseidon_chain_n100_full_proof_packed_v2.txt");
    let slots = read_txt(@file);
    let values = unpack_proof_v2(slots.span(), N_VALUES);
    let streams = build_streams(values.span());
    let head = streams.head.span();
    let sampled = streams.sampled;

    // Two identical OODS-phase states (serde clone).
    let oods_state = setup_oods_state(@streams);
    let mut felts = array![];
    Serde::serialize(@oods_state, ref felts);
    let mut span_a = felts.span();
    let state_a: OodsPhaseState = Serde::deserialize(ref span_a).expect('clone a');
    let mut span_b = felts.span();
    let state_b: OodsPhaseState = Serde::deserialize(ref span_b).expect('clone b');

    // Monolithic reference.
    let expected = machine_oods_mix(state_a, head, sampled);

    // Chunked: begin → group txs over the 44-family sequence (each oversized
    // component eval split into half A / half B, with the seam carry riding
    // the checkpoint) → finalize, with a checkpoint round-trip between every
    // transaction — in particular between every half-A and its half-B.
    let mut state = roundtrip(oods_begin(state_b, head, sampled));

    // Opcode sub-airs 0..5.
    let (state_after, mut ctx) = oods_group_prologue(state, head, sampled, 0);
    family_add_opcode(ref ctx);
    family_add_opcode_small(ref ctx);
    family_add_ap_opcode(ref ctx);
    family_assert_eq_opcode(ref ctx);
    family_assert_eq_opcode_imm(ref ctx);
    family_assert_eq_opcode_double_deref(ref ctx);
    state = roundtrip(oods_group_epilogue(state_after, ctx, 6));

    // blake_compress halves (6, 7) — the carry crosses the checkpoint.
    let (state_after, mut ctx) = oods_group_prologue(state, head, sampled, 6);
    family_blake_compress_opcode_a(ref ctx);
    state = roundtrip(oods_group_epilogue(state_after, ctx, 1));
    let result = drive_tail_from_blake_compress_b(state, head, sampled);

    assert!(result.d_head == expected.d_head);
    assert!(result.digest_pre_draw == expected.digest_pre_draw);
    assert!(result.digest_pre_fri == expected.digest_pre_fri, "transcript seam");
    assert!(result.d_sampled == expected.d_sampled);
    assert!(result.ood_x == expected.ood_x);
    assert!(result.ood_y == expected.ood_y);
    assert!(result.program_fact_hash == expected.program_fact_hash);
}

/// Drives blake_compress half B (family 7) through the last group and
/// finalize, with a checkpoint round-trip between every transaction.
fn drive_tail_from_blake_compress_b(
    mut state: OodsEvalState, head: Span<felt252>, sampled: Span<felt252>,
) -> FriCommitPhaseState {
    let (state_after, mut ctx) = oods_group_prologue(state, head, sampled, 7);
    family_blake_compress_opcode_b(ref ctx);
    state = roundtrip(oods_group_epilogue(state_after, ctx, 1));

    // Opcode sub-airs 8..10.
    let (state_after, mut ctx) = oods_group_prologue(state, head, sampled, 8);
    family_call_opcode_abs(ref ctx);
    family_call_opcode_rel_imm(ref ctx);
    family_jnz_opcode_non_taken(ref ctx);
    state = roundtrip(oods_group_epilogue(state_after, ctx, 3));

    // Opcode sub-airs 11..15.
    let (state_after, mut ctx) = oods_group_prologue(state, head, sampled, 11);
    family_jnz_opcode_taken(ref ctx);
    family_jump_opcode_abs(ref ctx);
    family_jump_opcode_double_deref(ref ctx);
    family_jump_opcode_rel(ref ctx);
    family_jump_opcode_rel_imm(ref ctx);
    state = roundtrip(oods_group_epilogue(state_after, ctx, 5));

    // Opcode sub-airs 16..19.
    let (state_after, mut ctx) = oods_group_prologue(state, head, sampled, 16);
    family_mul_opcode(ref ctx);
    family_mul_opcode_small(ref ctx);
    family_qm_31_add_mul_opcode(ref ctx);
    family_ret_opcode(ref ctx);
    state = roundtrip(oods_group_epilogue(state_after, ctx, 4));

    // verify_instruction (20).
    let (state_after, mut ctx) = oods_group_prologue(state, head, sampled, 20);
    family_verify_instruction(ref ctx);
    state = roundtrip(oods_group_epilogue(state_after, ctx, 1));

    // blake context: blake_round halves (21, 22) then the rest (23..26).
    let (state_after, mut ctx) = oods_group_prologue(state, head, sampled, 21);
    family_blake_round_a(ref ctx);
    state = roundtrip(oods_group_epilogue(state_after, ctx, 1));
    let (state_after, mut ctx) = oods_group_prologue(state, head, sampled, 22);
    family_blake_round_b(ref ctx);
    state = roundtrip(oods_group_epilogue(state_after, ctx, 1));
    let (state_after, mut ctx) = oods_group_prologue(state, head, sampled, 23);
    family_blake_g(ref ctx);
    state = roundtrip(oods_group_epilogue(state_after, ctx, 1));
    let (state_after, mut ctx) = oods_group_prologue(state, head, sampled, 24);
    family_blake_round_sigma(ref ctx);
    family_triple_xor_32(ref ctx);
    family_verify_bitwise_xor_12(ref ctx);
    state = roundtrip(oods_group_epilogue(state_after, ctx, 3));

    // builtins (27).
    let (state_after, mut ctx) = oods_group_prologue(state, head, sampled, 27);
    family_builtins(ref ctx);
    state = roundtrip(oods_group_epilogue(state_after, ctx, 1));

    // poseidon context: aggregator halves (28, 29), chains (30, 31),
    // cube_252 halves (32, 33), tail (34, 35).
    let (state_after, mut ctx) = oods_group_prologue(state, head, sampled, 28);
    family_poseidon_aggregator_a(ref ctx);
    state = roundtrip(oods_group_epilogue(state_after, ctx, 1));
    let (state_after, mut ctx) = oods_group_prologue(state, head, sampled, 29);
    family_poseidon_aggregator_b(ref ctx);
    state = roundtrip(oods_group_epilogue(state_after, ctx, 1));
    let (state_after, mut ctx) = oods_group_prologue(state, head, sampled, 30);
    family_poseidon_3_partial_rounds_chain(ref ctx);
    state = roundtrip(oods_group_epilogue(state_after, ctx, 1));
    let (state_after, mut ctx) = oods_group_prologue(state, head, sampled, 31);
    family_poseidon_full_round_chain(ref ctx);
    state = roundtrip(oods_group_epilogue(state_after, ctx, 1));
    let (state_after, mut ctx) = oods_group_prologue(state, head, sampled, 32);
    family_cube_252_a(ref ctx);
    state = roundtrip(oods_group_epilogue(state_after, ctx, 1));
    let (state_after, mut ctx) = oods_group_prologue(state, head, sampled, 33);
    family_cube_252_b(ref ctx);
    state = roundtrip(oods_group_epilogue(state_after, ctx, 1));
    let (state_after, mut ctx) = oods_group_prologue(state, head, sampled, 34);
    family_poseidon_round_keys(ref ctx);
    family_range_check_252_width_27(ref ctx);
    state = roundtrip(oods_group_epilogue(state_after, ctx, 2));

    // memory + range_checks (36..39).
    let (state_after, mut ctx) = oods_group_prologue(state, head, sampled, 36);
    family_memory_address_to_id(ref ctx);
    family_memory_id_to_big(ref ctx);
    family_memory_id_to_small(ref ctx);
    family_range_checks(ref ctx);
    state = roundtrip(oods_group_epilogue(state_after, ctx, 4));

    // The xor tail (40..43).
    let (state_after, mut ctx) = oods_group_prologue(state, head, sampled, 40);
    family_verify_bitwise_xor_4(ref ctx);
    family_verify_bitwise_xor_7(ref ctx);
    family_verify_bitwise_xor_8(ref ctx);
    family_verify_bitwise_xor_9(ref ctx);
    state = roundtrip(oods_group_epilogue(state_after, ctx, 4));
    assert!(state.families_done == N_FAMILIES);

    oods_finalize(state, head, sampled)
}

/// Tampering one carried seam value (a blake_compress numerator) between
/// half A's and half B's transactions must break the OODS equation.
#[test]
#[should_panic(expected: "Invalid OODS eval")]
fn test_oods_carry_tamper_rejected() {
    let file = FileTrait::new("tests/data/poseidon_chain_n100_full_proof_packed_v2.txt");
    let slots = read_txt(@file);
    let values = unpack_proof_v2(slots.span(), N_VALUES);
    let streams = build_streams(values.span());
    let head = streams.head.span();
    let sampled = streams.sampled;

    let oods_state = setup_oods_state(@streams);
    let mut state = oods_begin(oods_state, head, sampled);

    let (state_after, mut ctx) = oods_group_prologue(state, head, sampled, 0);
    family_add_opcode(ref ctx);
    family_add_opcode_small(ref ctx);
    family_add_ap_opcode(ref ctx);
    family_assert_eq_opcode(ref ctx);
    family_assert_eq_opcode_imm(ref ctx);
    family_assert_eq_opcode_double_deref(ref ctx);
    state = oods_group_epilogue(state_after, ctx, 6);

    let (state_after, mut ctx) = oods_group_prologue(state, head, sampled, 6);
    family_blake_compress_opcode_a(ref ctx);
    state = oods_group_epilogue(state_after, ctx, 1);

    // Flip one QM31 in the carried seam state.
    let OodsEvalState {
        d_head,
        d_sampled,
        digest_pre_draw,
        digest_post_comp_commit,
        random_coeff,
        ood_x,
        ood_y,
        sum,
        families_done,
        sums_done,
        trace_done,
        interaction_done,
        pp_used_mask,
        carry,
        program_fact_hash,
    } = state;
    let mut tampered: Array<QM31> = array![];
    let mut index = 0;
    for value in carry.span() {
        if index == 1 {
            tampered.append(*value + qm31_const::<1, 0, 0, 0>());
        } else {
            tampered.append(*value);
        }
        index += 1;
    }
    let state = OodsEvalState {
        d_head,
        d_sampled,
        digest_pre_draw,
        digest_post_comp_commit,
        random_coeff,
        ood_x,
        ood_y,
        sum,
        families_done,
        sums_done,
        trace_done,
        interaction_done,
        pp_used_mask,
        carry: tampered,
        program_fact_hash,
    };

    drive_tail_from_blake_compress_b(state, head, sampled);
}

#[test]
#[should_panic(expected: "family order")]
fn test_oods_group_order_enforced() {
    let file = FileTrait::new("tests/data/poseidon_chain_n100_full_proof_packed_v2.txt");
    let slots = read_txt(@file);
    let values = unpack_proof_v2(slots.span(), N_VALUES);
    let streams = build_streams(values.span());
    let head = streams.head.span();
    let sampled = streams.sampled;

    let oods_state = setup_oods_state(@streams);
    let mut state = oods_begin(oods_state, head, sampled);

    let (state_after, mut ctx) = oods_group_prologue(state, head, sampled, 0);
    family_add_opcode(ref ctx);
    state = oods_group_epilogue(state_after, ctx, 1);

    // Skipping family 1 must be rejected (the prologue panics; the
    // epilogue call just consumes the PanicDestruct-only ctx type).
    let (state, ctx) = oods_group_prologue(state, head, sampled, 2);
    let _ = oods_group_epilogue(state, ctx, 0);
}
