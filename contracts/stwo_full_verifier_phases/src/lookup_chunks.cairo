//! Chunked `lookup_sum` — the remaining big block of phase A
//! (docs/lane2-design.md, cost map block 2b: 3.67M steps, dominated by the
//! public-memory logup over the 2,597 program entries).
//!
//! The monolithic `lookup_sum` is
//!
//!     Σ_entries (addr_to_id⁻¹ + id_to_value⁻¹)   over public memory entries
//!   + final_state term − initial_state term
//!   + Σ components' claimed sums,
//!
//! a flat field sum whose entry terms are independent — so it chunks by
//! program-entry ranges with a single QM31 accumulator crossing transactions
//! in the checkpoint. Each chunk transaction re-derives the terms of its
//! entries by calling the *vendored* `sum_public_memory_entries` verbatim
//! over a `PublicMemoryEntries` built from just its chunk (the per-entry
//! addresses are `initial_pc + offset`, so a chunk needs only its base
//! address). The lookup elements are drawn from the checkpointed pre-draw
//! digest in every transaction (deterministic redraw, same as phase B).
//!
//! The non-program terms (output section, safe-call ids, segment pointers,
//! the initial/final state terms and the claimed sums) are covered by
//! `lookup_sum_rest`, which runs in the finalize transaction over the small
//! claim. It builds the vendored `get_entries` over a `PublicMemory` whose
//! program section is empty — valid because non-program entry addresses
//! (`initial_ap`, `final_ap - n_segments`, …) do not depend on the program
//! section.
//!
//! Equivalence with the monolithic `lookup_sum` over the real fixture claim
//! is asserted in `tests/test_lookup_chunks.cairo`. In the production
//! machine the chunk bytes are bound by the claim-mix pipeline (the same
//! program entries feed `claim_mix_absorb_program_entries` in the same
//! transaction), so no extra binding digest is needed.
//!
//! `verify_claim` needs no chunking at all: it reads the first 6 program
//! entries (`verify_program`), the builtin/segment claims and the component
//! claims — all "small claim" data. The vendored function runs verbatim in
//! the begin transaction over a claim whose program span holds only the
//! first chunk; `tests/test_lookup_chunks.cairo` proves a 6-entry prefix
//! claim passes it.

use core::num::traits::Zero;
use stwo_cairo_air::cairo_air::OPCODES_RELATION_ID;
use stwo_cairo_air::claim::CairoInteractionClaim;
use stwo_cairo_air::{
    CasmState, PublicData, PublicMemory, PublicMemoryImpl, sum_public_memory_entries,
};
use stwo_constraint_framework::{CommonLookupElements, LookupElementsImpl};
use stwo_verifier_core::fields::Invertible;
use stwo_verifier_core::fields::qm31::QM31;
use stwo_verifier_utils::{MemorySection, PublicMemoryEntriesTrait};

/// Logup contribution of one program-entry chunk. `chunk_base_address` is
/// `initial_pc + <entry offset of the chunk's first entry>` (the vendored
/// `get_entries` loads the program at `initial_pc` with consecutive
/// addresses).
pub fn lookup_sum_program_chunk(
    chunk: @MemorySection, chunk_base_address: u32, elements: @CommonLookupElements,
) -> QM31 {
    let mut entries = PublicMemoryEntriesTrait::empty();
    entries.add_memory_section(chunk, chunk_base_address);
    sum_public_memory_entries(entries, elements)
}

/// All non-program `lookup_sum` terms: output/safe-call/segment entries,
/// the initial and final state terms, and the components' claimed sums.
/// Everything here is small-claim data — it rides the finalize transaction.
pub fn lookup_sum_rest(
    public_data: @PublicData,
    elements: @CommonLookupElements,
    interaction_claim: @CairoInteractionClaim,
) -> QM31 {
    // The vendored `get_entries` over an emptied program section yields
    // exactly the non-program entries: their addresses derive from
    // `initial_ap` / `final_ap`, never from the program section.
    let PublicMemory { program: _, public_segments, output, safe_call_ids } = *public_data
        .public_memory;
    let empty_program: MemorySection = array![].span();
    let public_memory = PublicMemory {
        program: empty_program, public_segments, output, safe_call_ids,
    };
    let entries = public_memory
        .get_entries(
            initial_pc: (*public_data.initial_state.pc).into(),
            initial_ap: (*public_data.initial_state.ap).into(),
            final_ap: (*public_data.final_state.ap).into(),
        );
    let mut sum = sum_public_memory_entries(entries, elements);

    // Yield the initial state and use the final (mirrors
    // `PublicDataImpl::logup_sum`).
    let CasmState { pc, ap, fp } = *public_data.final_state;
    sum += elements.combine([OPCODES_RELATION_ID, pc, ap, fp].span()).inverse();
    let CasmState { pc, ap, fp } = *public_data.initial_state;
    sum -= elements.combine([OPCODES_RELATION_ID, pc, ap, fp].span()).inverse();

    for claimed_sum in interaction_claim.claimed_sums.span() {
        sum += *claimed_sum;
    }
    sum
}

/// The chunked pipeline end-to-end over an in-memory claim (test/reference
/// shape; production spreads the chunk calls over the claim-pipeline txs).
pub fn lookup_sum_chunked(
    public_data: @PublicData,
    elements: @CommonLookupElements,
    interaction_claim: @CairoInteractionClaim,
    chunk_entries: u32,
) -> QM31 {
    let program = *public_data.public_memory.program;
    let initial_pc: u32 = (*public_data.initial_state.pc).into();
    let n_entries = program.len();

    let mut accumulator: QM31 = Zero::zero();
    let mut offset = 0_u32;
    while offset != n_entries {
        let n = core::cmp::min(n_entries - offset, chunk_entries);
        let chunk = program.slice(offset, n);
        accumulator += lookup_sum_program_chunk(@chunk, initial_pc + offset, elements);
        offset += n;
    }
    accumulator + lookup_sum_rest(public_data, elements, interaction_claim)
}
