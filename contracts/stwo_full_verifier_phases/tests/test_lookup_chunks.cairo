//! Chunked `lookup_sum` equivalence over the REAL fixture claim, and the
//! program-prefix property of `verify_claim` (docs/lane2-design.md).

use core::num::traits::Zero;
use snforge_std::fs::{FileTrait, read_txt};
use stwo_cairo_air::claim::lookup_sum;
use stwo_cairo_air::claims::CairoClaim;
use stwo_cairo_air::{CairoProof, verify_claim};
use stwo_constraint_framework::LookupElementsImpl;
use stwo_full_verifier_phases::lookup_chunks::lookup_sum_chunked;
use stwo_full_verifier_phases::resumable_full::{FullCheckpoint, phase_a};
use stwo_full_verifier_phases::unpack_proof_v2;
use stwo_verifier_core::channel::poseidon252::new_channel;

const N_VALUES: u32 = 301_143;
/// Program entries per chunk transaction (matches the claim-mix pipeline's
/// chunk unit; the fixture's 2,597 entries → 5 chunks).
const CHUNK_ENTRIES: u32 = 540;
/// The fixture program's entry count (asserted, so the layout surgery in the
/// prefix test can't silently drift).
const N_PROGRAM_ENTRIES: u32 = 2_597;
/// Serde felts per program entry: (id, [8 u32 limbs]).
const FELTS_PER_ENTRY: u32 = 9;

#[test]
fn test_chunked_lookup_sum_matches_monolithic() {
    let file = FileTrait::new("tests/data/poseidon_chain_n100_full_proof_packed_v2.txt");
    let slots = read_txt(@file);
    let values = unpack_proof_v2(slots.span(), N_VALUES);

    // The lookup elements are drawn from the checkpointed pre-draw digest —
    // exactly what every chunk transaction does.
    let FullCheckpoint { digest_pre_draw, digest_post_prologue: _, proof_hash: _ } = phase_a(
        values.span(),
    );
    let mut draw_channel = new_channel(digest_pre_draw);
    let elements = LookupElementsImpl::draw(ref draw_channel);

    let mut span = values.span();
    let proof: CairoProof = Serde::deserialize(ref span).expect('proof deser');
    let CairoProof {
        claim, interaction_pow: _, interaction_claim, stark_proof: _, channel_salt: _,
    } = proof;

    let chunked = lookup_sum_chunked(
        @claim.public_data, @elements, @interaction_claim, CHUNK_ENTRIES,
    );
    let monolithic = lookup_sum(@claim, @elements, @interaction_claim);

    assert!(chunked == monolithic, "chunked lookup_sum must equal monolithic");
    assert!(chunked.is_zero(), "fixture logup sum must be zero");
}

#[test]
fn test_chunked_lookup_sum_detects_tampered_entry() {
    let file = FileTrait::new("tests/data/poseidon_chain_n100_full_proof_packed_v2.txt");
    let slots = read_txt(@file);
    let values = unpack_proof_v2(slots.span(), N_VALUES);

    let FullCheckpoint { digest_pre_draw, digest_post_prologue: _, proof_hash: _ } = phase_a(
        values.span(),
    );
    let mut draw_channel = new_channel(digest_pre_draw);
    let elements = LookupElementsImpl::draw(ref draw_channel);

    // Tamper one program-entry limb in the raw claim stream (the program
    // section starts at claim felt 1: [len, (id, 8 limbs)*]; felt 3 is the
    // second limb of entry 0's value) and re-deserialize.
    let mut tampered: Array<felt252> = array![];
    let mut index = 0_u32;
    for value in values.span() {
        if index == 3 {
            tampered.append(*value + 1);
        } else {
            tampered.append(*value);
        }
        index += 1;
    }
    let mut span = tampered.span();
    let proof: CairoProof = Serde::deserialize(ref span).expect('proof deser');
    let CairoProof {
        claim, interaction_pow: _, interaction_claim, stark_proof: _, channel_salt: _,
    } = proof;

    let chunked = lookup_sum_chunked(
        @claim.public_data, @elements, @interaction_claim, CHUNK_ENTRIES,
    );
    assert!(!chunked.is_zero(), "tampered entry must break the logup sum");
}

/// `verify_claim` reads only the first 6 program entries (plus small-claim
/// data), so the begin transaction can run the vendored function verbatim
/// over the small claim + first program chunk. Proven at the minimum prefix:
/// a claim whose program span holds just 6 entries passes.
#[test]
fn test_verify_claim_passes_on_program_prefix() {
    let file = FileTrait::new("tests/data/poseidon_chain_n100_full_proof_packed_v2.txt");
    let slots = read_txt(@file);
    let values = unpack_proof_v2(slots.span(), N_VALUES);

    // Measure the claim's felt extent.
    let mut span = values.span();
    let _full_claim: CairoClaim = Serde::deserialize(ref span).expect('claim deser');
    let claim_len = values.len() - span.len();

    // The claim stream starts with the program section: [len, entries…].
    let claim_felts = values.span().slice(0, claim_len);
    let program_len: u32 = (*claim_felts[0]).try_into().unwrap();
    assert!(program_len == N_PROGRAM_ENTRIES);

    // Doctored stream: program length 6, first 6 entries, then everything
    // after the program section unchanged.
    let prefix_entries = 6_u32;
    let mut doctored: Array<felt252> = array![prefix_entries.into()];
    doctored.append_span(claim_felts.slice(1, prefix_entries * FELTS_PER_ENTRY));
    let rest_offset = 1 + program_len * FELTS_PER_ENTRY;
    doctored.append_span(claim_felts.slice(rest_offset, claim_len - rest_offset));

    let mut doctored_span = doctored.span();
    let prefix_claim: CairoClaim = Serde::deserialize(ref doctored_span)
        .expect('prefix claim deser');
    assert!(doctored_span.is_empty(), "prefix stream fully consumed");
    assert!(prefix_claim.public_data.public_memory.program.len() == prefix_entries);

    // Must pass: verify_claim touches program[0..6] only.
    verify_claim(@prefix_claim);
}
