//! Chunked OODS evaluation — splitting `machine_oods_mix`'s
//! `eval_composition_polynomial_at_point` (the 762k-Sierra-felt component
//! zoo, the last oversized class) into per-component-family transactions:
//!
//!   `oods_begin` → `oods_group` × N (each class links only its families)
//!   → `oods_finalize`
//!
//! The vendored eval body is a flat sequence of
//! `family.evaluate_constraints_at_point(ref sum, ref pp_masks,
//! ref trace_masks, ref interaction_masks, random_coeff, …)` calls; `sum`
//! is a running accumulator and the two trace mask spans are consumed
//! sequentially, so a family group can run in its own transaction if the
//! checkpoint carries `(sum, columns consumed so far, claimed sums
//! consumed so far)` and each transaction fast-forwards its freshly
//! re-supplied (digest-bound) sampled values to those offsets. The family
//! components are rebuilt per transaction from the head's claim + the
//! re-drawn lookup elements — construction consumes `claimed_sums`
//! sequentially too, hence the third counter.
//!
//! Two structural checks of the monolithic eval are preserved across the
//! split:
//! - **family order/completeness**: each group transaction asserts it
//!   starts at `families_done` and finalize requires all
//!   [`N_FAMILIES`] ran, so the concatenated mask consumption is exactly
//!   the monolithic sequence;
//! - **preprocessed mask usage** (`validate_mask_usage`): every sampled
//!   preprocessed column must be used by some component — otherwise the
//!   prover could add junk FRI-quotient terms. Usage is per-column and
//!   spans transactions, so each group transaction ORs its used-column
//!   bitmask into the checkpoint (u128; column count asserted ≤ 128 —
//!   the fixture has 105) and finalize compares against the columns that
//!   actually carry a sample. Trace/interaction full consumption is
//!   checked via the counters, mirroring the `is_empty` asserts.
//!
//! Family order (must match BOTH the vendored eval sequence and
//! `CairoAirNewImpl::new`'s claimed-sums consumption; poseidon252 +
//! poseidon_outputs_packing variant). The three families whose composite
//! classes exceeded the Sierra cap (opcodes 232k, blake 107k, poseidon
//! 350k) are split one level deeper — their sub-airs are themselves flat
//! `try_new → evaluate` sequences:
//!   0..18  the 19 opcode sub-airs (add, add_small, add_ap, assert_eq,
//!          assert_eq_imm, assert_eq_double_deref, blake_compress,
//!          call_abs, call_rel_imm, jnz_non_taken, jnz_taken, jump_abs,
//!          jump_double_deref, jump_rel, jump_rel_imm, mul, mul_small,
//!          qm31_add_mul, ret),
//!   19     verify_instruction,
//!   20..24 blake context sub-airs (blake_round gate: blake_round,
//!          blake_g, blake_round_sigma, triple_xor_32, xor_12),
//!   25     builtins,
//!   26..31 poseidon context sub-airs (poseidon_aggregator gate:
//!          aggregator, 3_partial_rounds_chain, full_round_chain,
//!          cube_252, round_keys, range_check_252_width_27),
//!   32     memory_address_to_id, 33 memory_id_to_big,
//!   34     memory_id_to_small, 35 range_checks,
//!   36..39 verify_bitwise_xor_4/7/8/9.
//!
//! Equivalence with `machine_oods_mix` over the real proof is asserted in
//! `tests/test_oods_chunks.cairo`.

use core::array::SpanTrait;
use core::dict::SquashedFelt252DictTrait;
use core::nullable::{FromNullableResult, match_nullable};
use core::box::BoxImpl;
use core::num::traits::Zero;
use core::poseidon::poseidon_hash_span;
use stwo_cairo_air::builtins::BuiltinComponentsImpl;
use stwo_cairo_air::components;
use stwo_cairo_air::components::memory_id_to_big::LARGE_MEMORY_VALUE_ID_BASE;
use stwo_cairo_air::range_checks::RangeChecksComponentsImpl;
use stwo_constraint_framework::{
    AirComponent, CommonLookupElements, LookupElementsImpl, PreprocessedMaskValues,
    PreprocessedMaskValuesImpl,
};
use stwo_verifier_core::channel::poseidon252::new_channel;
use stwo_verifier_core::channel::ChannelTrait;
use stwo_verifier_core::circle::{ChannelGetRandomCirclePointImpl, CirclePoint};
use stwo_verifier_core::fields::Invertible;
use stwo_verifier_core::fields::m31::P_U32;
use stwo_verifier_core::fields::qm31::{QM31, QM31Serde};
use stwo_verifier_core::pcs::verifier::mix_sampled_values;
use stwo_verifier_core::poly::circle::{CanonicCosetImpl, CanonicCosetTrait};
use stwo_verifier_core::utils::{OptionImpl, pow2};
use stwo_verifier_core::verifier::{VerificationError, try_extract_composition_eval};
use stwo_verifier_core::Hash;
use crate::machine::{
    check_head, FriCommitPhaseState, Head, log_trace_degree_bound_of, OodsPhaseState,
    rebuild_all_trees,
};

/// Number of component families in the vendored eval sequence.
pub const N_FAMILIES: u32 = 40;

/// Checkpoint state between OODS group transactions.
#[derive(Drop, Serde)]
pub struct OodsEvalState {
    pub d_head: felt252,
    pub d_sampled: felt252,
    pub digest_pre_draw: felt252,
    /// Channel digest right after the composition commit mix (the site
    /// finalize resumes from for `mix_sampled_values`).
    pub digest_post_comp_commit: felt252,
    pub random_coeff: QM31,
    pub ood_x: QM31,
    pub ood_y: QM31,
    pub sum: QM31,
    pub families_done: u32,
    pub sums_done: u32,
    pub trace_done: u32,
    pub interaction_done: u32,
    pub pp_used_mask: u128,
    pub program_fact_hash: felt252,
}

/// The in-transaction working set a group class threads through its family
/// evals. Contains a `Felt252Dict` (the preprocessed masks), so it is
/// PanicDestruct-only: every normal path must consume it via
/// [`oods_group_epilogue`].
#[derive(PanicDestruct)]
pub struct OodsGroupCtx {
    pub head: Head,
    pub elements: CommonLookupElements,
    pub pp: PreprocessedMaskValues,
    pub trace: Span<Span<QM31>>,
    pub interaction: Span<Span<QM31>>,
    pub claimed_sums: Span<QM31>,
    pub sum: QM31,
    pub random_coeff: QM31,
    pub trace_total: u32,
    pub interaction_total: u32,
    pub sums_total: u32,
}

fn u128_bit(index: u32) -> u128 {
    let mut bit: u128 = 1;
    for _ in 0..index {
        bit = bit * 2;
    }
    bit
}

fn split_masks(
    mut sampled_felts: Span<felt252>,
) -> (Span<Span<QM31>>, Span<Span<QM31>>, Span<Span<QM31>>) {
    let sampled_values: Span<Span<Span<QM31>>> = Serde::deserialize(ref sampled_felts)
        .expect('sampled deser');
    assert(SpanTrait::is_empty(sampled_felts), 'sampled trailing data');
    let trees: @Box<[Span<Span<QM31>>; 4]> = sampled_values.try_into().unwrap();
    let [pp, trace, interaction, _composition] = trees.unbox();
    (pp, trace, interaction)
}

/// Bit per preprocessed column that carries a sample — what the union of
/// all groups' usage must equal (the split form of `validate_usage`).
fn expected_pp_mask(mut pp: Span<Span<QM31>>) -> u128 {
    let mut mask: u128 = 0;
    let mut index: u32 = 0;
    for column in pp {
        if !SpanTrait::is_empty(*column) {
            mask = mask | u128_bit(index);
        }
        index += 1;
    }
    mask
}

// ---------------------------------------------------------------------------
// Tx: oods_begin — composition coeff draw, composition commit, OODS point.

pub fn oods_begin(
    state: OodsPhaseState, head: Span<felt252>, sampled_felts: Span<felt252>,
) -> OodsEvalState {
    let OodsPhaseState { d_head, digest_pre_draw, digest_post_prologue, program_fact_hash } =
        state;
    let h = check_head(head, d_head);
    // Mirrors the poseidon_outputs_packing CairoAirNewImpl::new precondition.
    assert!(
        h.claim.partial_ec_mul_generic.is_none(), "Partial EC Mul Generic is not supported.",
    );

    // Establish the sampled-section digest; the u128 usage mask must cover
    // every preprocessed column.
    let (pp, _trace, _interaction) = split_masks(sampled_felts);
    assert!(SpanTrait::len(pp) <= 128, "more than 128 preprocessed columns");

    let mut channel = new_channel(digest_post_prologue);
    let random_coeff = channel.draw_secure_felt();
    let commitments: @Box<[Hash; 4]> = h.commitments.try_into().unwrap();
    let [_pp_root, _trace_root, _interaction_root, composition_commitment] = commitments.unbox();
    channel.mix_commitment(composition_commitment);
    let ood_point = channel.get_random_point();

    OodsEvalState {
        d_head,
        d_sampled: poseidon_hash_span(sampled_felts),
        digest_pre_draw,
        digest_post_comp_commit: channel.digest,
        random_coeff,
        ood_x: ood_point.x,
        ood_y: ood_point.y,
        sum: Zero::zero(),
        families_done: 0,
        sums_done: 0,
        trace_done: 0,
        interaction_done: 0,
        pp_used_mask: 0,
        program_fact_hash,
    }
}

// ---------------------------------------------------------------------------
// Group tx prologue/epilogue — each group CLASS composes:
//   prologue → its family evals → epilogue.

pub fn oods_group_prologue(
    state: OodsEvalState,
    head: Span<felt252>,
    sampled_felts: Span<felt252>,
    first_family: u32,
) -> (OodsEvalState, OodsGroupCtx) {
    // Groups must run in the vendored eval order, exactly once each.
    assert!(state.families_done == first_family, "family order");
    let h = check_head(head, state.d_head);
    assert(poseidon_hash_span(sampled_felts) == state.d_sampled, 'sampled binding');

    let (pp, trace, interaction) = split_masks(sampled_felts);
    let pp_dict = PreprocessedMaskValuesImpl::new(pp);

    // Fast-forward the sequentially-consumed streams to this group's
    // offsets.
    let trace_total = SpanTrait::len(trace);
    let interaction_total = SpanTrait::len(interaction);
    let sums_all = h.interaction_claim.claimed_sums.span();
    let sums_total = SpanTrait::len(sums_all);
    let trace_ff = trace.slice(state.trace_done, trace_total - state.trace_done);
    let interaction_ff = interaction
        .slice(state.interaction_done, interaction_total - state.interaction_done);
    let sums_ff = sums_all.slice(state.sums_done, sums_total - state.sums_done);

    // Deterministic per-tx redraw of the lookup elements.
    let mut draw_channel = new_channel(state.digest_pre_draw);
    let elements = LookupElementsImpl::draw(ref draw_channel);

    let sum = state.sum;
    let random_coeff = state.random_coeff;
    let ctx = OodsGroupCtx {
        head: h,
        elements,
        pp: pp_dict,
        trace: trace_ff,
        interaction: interaction_ff,
        claimed_sums: sums_ff,
        sum,
        random_coeff,
        trace_total,
        interaction_total,
        sums_total,
    };
    (state, ctx)
}

pub fn oods_group_epilogue(
    state: OodsEvalState, ctx: OodsGroupCtx, n_families: u32,
) -> OodsEvalState {
    let OodsGroupCtx {
        head: _,
        elements: _,
        pp,
        trace,
        interaction,
        claimed_sums,
        sum,
        random_coeff: _,
        trace_total,
        interaction_total,
        sums_total,
    } = ctx;

    // This transaction's preprocessed-column usage bits.
    let PreprocessedMaskValues { values } = pp;
    let mut used_mask: u128 = 0;
    for entry in values.squash().into_entries() {
        let (index, _first, last) = entry;
        match match_nullable(last) {
            FromNullableResult::Null => {},
            FromNullableResult::NotNull(boxed) => {
                let (_value, used): (QM31, bool) = boxed.unbox();
                if used {
                    used_mask = used_mask | u128_bit(index.try_into().unwrap());
                }
            },
        }
    }

    let OodsEvalState {
        d_head,
        d_sampled,
        digest_pre_draw,
        digest_post_comp_commit,
        random_coeff,
        ood_x,
        ood_y,
        sum: _,
        families_done,
        sums_done: _,
        trace_done: _,
        interaction_done: _,
        pp_used_mask,
        program_fact_hash,
    } = state;
    OodsEvalState {
        d_head,
        d_sampled,
        digest_pre_draw,
        digest_post_comp_commit,
        random_coeff,
        ood_x,
        ood_y,
        sum,
        families_done: families_done + n_families,
        sums_done: sums_total - SpanTrait::len(claimed_sums),
        trace_done: trace_total - SpanTrait::len(trace),
        interaction_done: interaction_total - SpanTrait::len(interaction),
        pp_used_mask: pp_used_mask | used_mask,
        program_fact_hash,
    }
}

// ---------------------------------------------------------------------------
// The 13 family evals (construction + eval verbatim from the vendored
// CairoAirNewImpl::new / eval_composition_polynomial_at_point pair).


pub fn family_verify_instruction(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    let component = components::verify_instruction::NewComponentImpl::try_new(
        @head.claim.verify_instruction, ref claimed_sums, @elements,
    )
        .unwrap();
    component
        .evaluate_constraints_at_point(
            ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
        );
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}


pub fn family_builtins(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    let components = BuiltinComponentsImpl::new(@head.claim, @elements, ref claimed_sums);
    components
        .evaluate_constraints_at_point(
            ref sum, ref pp, ref trace, ref interaction, random_coeff,
            @head.claim.public_data,
        );
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}


pub fn family_memory_address_to_id(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    let component = components::memory_address_to_id::NewComponentImpl::try_new(
        @head.claim.memory_address_to_id, ref claimed_sums, @elements,
    )
        .unwrap();
    component
        .evaluate_constraints_at_point(
            ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
        );
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_memory_id_to_big(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    // Construction mirrors CairoAirNewImpl::new's id_to_big loop, including
    // the id-overflow assert.
    let claim_memory_id_to_big = (@head.claim.memory_id_to_big).as_snap().unwrap();
    let mut components_arr = array![];
    let mut offset: u32 = LARGE_MEMORY_VALUE_ID_BASE;
    for i in 0..claim_memory_id_to_big.big_log_sizes.len() {
        let log_size = claim_memory_id_to_big.big_log_sizes[i];
        let claimed_sum = *claimed_sums.pop_front().unwrap();
        components_arr
            .append(
                components::memory_id_to_big::NewBigComponentImpl::new(
                    *log_size, offset, claimed_sum, @elements,
                ),
            );
        offset = offset + pow2(*log_size);
    }
    assert!(offset <= P_U32);
    for component in components_arr.span() {
        component
            .evaluate_constraints_at_point(
                ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
            );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_memory_id_to_small(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    let component = components::memory_id_to_small::NewComponentImpl::try_new(
        @head.claim.memory_id_to_small, ref claimed_sums, @elements,
    )
        .unwrap();
    component
        .evaluate_constraints_at_point(
            ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
        );
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_range_checks(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    let components = RangeChecksComponentsImpl::new(@head.claim, @elements, ref claimed_sums);
    components
        .evaluate_constraints_at_point(
            ref sum, ref pp, ref trace, ref interaction, random_coeff,
        );
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_verify_bitwise_xor_4(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    let component = components::verify_bitwise_xor_4::NewComponentImpl::try_new(
        @head.claim.verify_bitwise_xor_4, ref claimed_sums, @elements,
    )
        .unwrap();
    component
        .evaluate_constraints_at_point(
            ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
        );
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_verify_bitwise_xor_7(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    let component = components::verify_bitwise_xor_7::NewComponentImpl::try_new(
        @head.claim.verify_bitwise_xor_7, ref claimed_sums, @elements,
    )
        .unwrap();
    component
        .evaluate_constraints_at_point(
            ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
        );
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_verify_bitwise_xor_8(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    let component = components::verify_bitwise_xor_8::NewComponentImpl::try_new(
        @head.claim.verify_bitwise_xor_8, ref claimed_sums, @elements,
    )
        .unwrap();
    component
        .evaluate_constraints_at_point(
            ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
        );
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_verify_bitwise_xor_9(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    let component = components::verify_bitwise_xor_9::NewComponentImpl::try_new(
        @head.claim.verify_bitwise_xor_9, ref claimed_sums, @elements,
    )
        .unwrap();
    component
        .evaluate_constraints_at_point(
            ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
        );
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

// ---------------------------------------------------------------------------
// Opcode sub-airs (vendored OpcodeComponentsImpl order; each try_new is
// a no-op consuming nothing when the opcode is absent from the claim).

pub fn family_add_opcode(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    // Mirrors OpcodeComponentsImpl::new's precondition.
    assert!(head.claim.generic_opcode.is_none(), "The generic opcode is not supported.");
    if let Some(component) = components::add_opcode::NewComponentImpl::try_new(
        @head.claim.add_opcode, ref claimed_sums, @elements,
    ) {
        component
                .evaluate_constraints_at_point(
                    ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
                );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_add_opcode_small(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if let Some(component) = components::add_opcode_small::NewComponentImpl::try_new(
        @head.claim.add_opcode_small, ref claimed_sums, @elements,
    ) {
        component
                .evaluate_constraints_at_point(
                    ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
                );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_add_ap_opcode(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if let Some(component) = components::add_ap_opcode::NewComponentImpl::try_new(
        @head.claim.add_ap_opcode, ref claimed_sums, @elements,
    ) {
        component
                .evaluate_constraints_at_point(
                    ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
                );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_assert_eq_opcode(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if let Some(component) = components::assert_eq_opcode::NewComponentImpl::try_new(
        @head.claim.assert_eq_opcode, ref claimed_sums, @elements,
    ) {
        component
                .evaluate_constraints_at_point(
                    ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
                );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_assert_eq_opcode_imm(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if let Some(component) = components::assert_eq_opcode_imm::NewComponentImpl::try_new(
        @head.claim.assert_eq_opcode_imm, ref claimed_sums, @elements,
    ) {
        component
                .evaluate_constraints_at_point(
                    ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
                );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_assert_eq_opcode_double_deref(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if let Some(component) = components::assert_eq_opcode_double_deref::NewComponentImpl::try_new(
        @head.claim.assert_eq_opcode_double_deref, ref claimed_sums, @elements,
    ) {
        component
                .evaluate_constraints_at_point(
                    ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
                );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_blake_compress_opcode(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if let Some(component) = components::blake_compress_opcode::NewComponentImpl::try_new(
        @head.claim.blake_compress_opcode, ref claimed_sums, @elements,
    ) {
        component
                .evaluate_constraints_at_point(
                    ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
                );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_call_opcode_abs(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if let Some(component) = components::call_opcode_abs::NewComponentImpl::try_new(
        @head.claim.call_opcode_abs, ref claimed_sums, @elements,
    ) {
        component
                .evaluate_constraints_at_point(
                    ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
                );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_call_opcode_rel_imm(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if let Some(component) = components::call_opcode_rel_imm::NewComponentImpl::try_new(
        @head.claim.call_opcode_rel_imm, ref claimed_sums, @elements,
    ) {
        component
                .evaluate_constraints_at_point(
                    ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
                );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_jnz_opcode_non_taken(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if let Some(component) = components::jnz_opcode_non_taken::NewComponentImpl::try_new(
        @head.claim.jnz_opcode_non_taken, ref claimed_sums, @elements,
    ) {
        component
                .evaluate_constraints_at_point(
                    ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
                );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_jnz_opcode_taken(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if let Some(component) = components::jnz_opcode_taken::NewComponentImpl::try_new(
        @head.claim.jnz_opcode_taken, ref claimed_sums, @elements,
    ) {
        component
                .evaluate_constraints_at_point(
                    ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
                );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_jump_opcode_abs(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if let Some(component) = components::jump_opcode_abs::NewComponentImpl::try_new(
        @head.claim.jump_opcode_abs, ref claimed_sums, @elements,
    ) {
        component
                .evaluate_constraints_at_point(
                    ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
                );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_jump_opcode_double_deref(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if let Some(component) = components::jump_opcode_double_deref::NewComponentImpl::try_new(
        @head.claim.jump_opcode_double_deref, ref claimed_sums, @elements,
    ) {
        component
                .evaluate_constraints_at_point(
                    ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
                );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_jump_opcode_rel(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if let Some(component) = components::jump_opcode_rel::NewComponentImpl::try_new(
        @head.claim.jump_opcode_rel, ref claimed_sums, @elements,
    ) {
        component
                .evaluate_constraints_at_point(
                    ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
                );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_jump_opcode_rel_imm(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if let Some(component) = components::jump_opcode_rel_imm::NewComponentImpl::try_new(
        @head.claim.jump_opcode_rel_imm, ref claimed_sums, @elements,
    ) {
        component
                .evaluate_constraints_at_point(
                    ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
                );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_mul_opcode(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if let Some(component) = components::mul_opcode::NewComponentImpl::try_new(
        @head.claim.mul_opcode, ref claimed_sums, @elements,
    ) {
        component
                .evaluate_constraints_at_point(
                    ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
                );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_mul_opcode_small(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if let Some(component) = components::mul_opcode_small::NewComponentImpl::try_new(
        @head.claim.mul_opcode_small, ref claimed_sums, @elements,
    ) {
        component
                .evaluate_constraints_at_point(
                    ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
                );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_qm_31_add_mul_opcode(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if let Some(component) = components::qm_31_add_mul_opcode::NewComponentImpl::try_new(
        @head.claim.qm_31_add_mul_opcode, ref claimed_sums, @elements,
    ) {
        component
                .evaluate_constraints_at_point(
                    ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
                );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_ret_opcode(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if let Some(component) = components::ret_opcode::NewComponentImpl::try_new(
        @head.claim.ret_opcode, ref claimed_sums, @elements,
    ) {
        component
                .evaluate_constraints_at_point(
                    ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
                );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

// ---------------------------------------------------------------------------
// Blake context sub-airs (all-or-nothing on blake_round, as vendored).

pub fn family_blake_round(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if head.claim.blake_round.is_some() {
        let component = components::blake_round::NewComponentImpl::try_new(
            @head.claim.blake_round, ref claimed_sums, @elements,
        )
            .unwrap();
            component
            .evaluate_constraints_at_point(
                ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
            );
    } else {
        assert!(head.claim.blake_g.is_none());
        assert!(head.claim.blake_round_sigma.is_none());
        assert!(head.claim.triple_xor_32.is_none());
        assert!(head.claim.verify_bitwise_xor_12.is_none());
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_blake_g(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if head.claim.blake_round.is_some() {
        let component = components::blake_g::NewComponentImpl::try_new(
            @head.claim.blake_g, ref claimed_sums, @elements,
        )
            .unwrap();
            component
            .evaluate_constraints_at_point(
                ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
            );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_blake_round_sigma(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if head.claim.blake_round.is_some() {
        let component = components::blake_round_sigma::NewComponentImpl::try_new(
            @head.claim.blake_round_sigma, ref claimed_sums, @elements,
        )
            .unwrap();
            component
            .evaluate_constraints_at_point(
                ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
            );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_triple_xor_32(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if head.claim.blake_round.is_some() {
        let component = components::triple_xor_32::NewComponentImpl::try_new(
            @head.claim.triple_xor_32, ref claimed_sums, @elements,
        )
            .unwrap();
            component
            .evaluate_constraints_at_point(
                ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
            );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_verify_bitwise_xor_12(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if head.claim.blake_round.is_some() {
        let component = components::verify_bitwise_xor_12::NewComponentImpl::try_new(
            @head.claim.verify_bitwise_xor_12, ref claimed_sums, @elements,
        )
            .unwrap();
            component
            .evaluate_constraints_at_point(
                ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
            );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

// ---------------------------------------------------------------------------
// Poseidon context sub-airs (all-or-nothing on poseidon_aggregator).

pub fn family_poseidon_aggregator(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if head.claim.poseidon_aggregator.is_some() {
        let component = components::poseidon_aggregator::NewComponentImpl::try_new(
            @head.claim.poseidon_aggregator, ref claimed_sums, @elements,
        )
            .unwrap();
            component
            .evaluate_constraints_at_point(
                ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
            );
    } else {
        assert!(head.claim.poseidon_3_partial_rounds_chain.is_none());
        assert!(head.claim.poseidon_full_round_chain.is_none());
        assert!(head.claim.cube_252.is_none());
        assert!(head.claim.poseidon_round_keys.is_none());
        assert!(head.claim.range_check_252_width_27.is_none());
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_poseidon_3_partial_rounds_chain(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if head.claim.poseidon_aggregator.is_some() {
        let component = components::poseidon_3_partial_rounds_chain::NewComponentImpl::try_new(
            @head.claim.poseidon_3_partial_rounds_chain, ref claimed_sums, @elements,
        )
            .unwrap();
            component
            .evaluate_constraints_at_point(
                ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
            );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_poseidon_full_round_chain(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if head.claim.poseidon_aggregator.is_some() {
        let component = components::poseidon_full_round_chain::NewComponentImpl::try_new(
            @head.claim.poseidon_full_round_chain, ref claimed_sums, @elements,
        )
            .unwrap();
            component
            .evaluate_constraints_at_point(
                ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
            );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_cube_252(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if head.claim.poseidon_aggregator.is_some() {
        let component = components::cube_252::NewComponentImpl::try_new(
            @head.claim.cube_252, ref claimed_sums, @elements,
        )
            .unwrap();
            component
            .evaluate_constraints_at_point(
                ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
            );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_poseidon_round_keys(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if head.claim.poseidon_aggregator.is_some() {
        let component = components::poseidon_round_keys::NewComponentImpl::try_new(
            @head.claim.poseidon_round_keys, ref claimed_sums, @elements,
        )
            .unwrap();
            component
            .evaluate_constraints_at_point(
                ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
            );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

pub fn family_range_check_252_width_27(ref ctx: OodsGroupCtx) {
    let OodsGroupCtx {
        head, elements, mut pp, mut trace, mut interaction, mut claimed_sums, mut sum,
        random_coeff, trace_total, interaction_total, sums_total,
    } = ctx;
    if head.claim.poseidon_aggregator.is_some() {
        let component = components::range_check_252_width_27::NewComponentImpl::try_new(
            @head.claim.range_check_252_width_27, ref claimed_sums, @elements,
        )
            .unwrap();
            component
            .evaluate_constraints_at_point(
                ref sum, ref pp, ref trace, ref interaction, random_coeff, [].span(),
            );
    }
    ctx = OodsGroupCtx {
        head, elements, pp, trace, interaction, claimed_sums, sum, random_coeff, trace_total,
        interaction_total, sums_total,
    };
}

// ---------------------------------------------------------------------------
// Tx: oods_finalize — completeness checks, the OODS equation, sampled mix.

pub fn oods_finalize(
    state: OodsEvalState, head: Span<felt252>, sampled_felts: Span<felt252>,
) -> FriCommitPhaseState {
    let OodsEvalState {
        d_head,
        d_sampled,
        digest_pre_draw,
        digest_post_comp_commit,
        random_coeff: _,
        ood_x,
        ood_y,
        sum,
        families_done,
        sums_done,
        trace_done,
        interaction_done,
        pp_used_mask,
        program_fact_hash,
    } = state;
    assert!(families_done == N_FAMILIES, "family groups incomplete");
    let h = check_head(head, d_head);
    assert(poseidon_hash_span(sampled_felts) == d_sampled, 'sampled binding');

    // The split form of validate_mask_usage: every stream fully consumed,
    // every sampled preprocessed column used by some family.
    let (pp, trace, interaction) = split_masks(sampled_felts);
    assert!(trace_done == SpanTrait::len(trace), "trace masks not consumed");
    assert!(
        interaction_done == SpanTrait::len(interaction), "interaction masks not consumed",
    );
    assert!(
        sums_done == h.interaction_claim.claimed_sums.len(), "claimed sums not consumed",
    );
    assert!(pp_used_mask == expected_pp_mask(pp), "preprocessed masks not used");

    // The OODS equation over the accumulated sum.
    let mut sampled_span = sampled_felts;
    let sampled_values: Span<Span<Span<QM31>>> = Serde::deserialize(ref sampled_span)
        .expect('sampled deser');
    let log_blowup_factor = h.pcs_config.fri_config.log_blowup_factor;
    let commitment_scheme = rebuild_all_trees(@h);
    let log_trace_degree_bound = log_trace_degree_bound_of(@commitment_scheme, log_blowup_factor);
    let ood_point = CirclePoint { x: ood_x, y: ood_y };
    let composition_oods_eval = try_extract_composition_eval(
        sampled_values, ood_point, log_trace_degree_bound,
    )
        .unwrap_or_else(
            || panic!("{}", VerificationError::InvalidStructure('Invalid sampled_values')),
        );
    let max_trace_domain = CanonicCosetImpl::new(log_trace_degree_bound);
    let denominator_inv = max_trace_domain.eval_vanishing(ood_point).inverse();
    assert!(
        composition_oods_eval == sum * denominator_inv,
        "{}",
        VerificationError::OodsNotMatching,
    );

    let mut channel = new_channel(digest_post_comp_commit);
    mix_sampled_values(sampled_values, ref channel);

    FriCommitPhaseState {
        d_head,
        digest_pre_draw,
        digest_pre_fri: channel.digest,
        d_sampled,
        ood_x,
        ood_y,
        program_fact_hash,
    }
}
