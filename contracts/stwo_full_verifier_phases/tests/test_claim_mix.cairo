//! Chunked claim-mix equivalence over the REAL fixture claim: the pipeline
//! (begin → N program-entry chunks with checkpoint serde round-trips →
//! finalize) must land on exactly the digest the monolithic
//! `claim.mix_into` produces.

use core::array::SpanTrait;
use core::cmp::min;
use snforge_std::fs::{FileTrait, read_txt};
use stwo_cairo_air::claims::{CairoClaimFlattenTrait, CairoClaimImpl};
use stwo_cairo_air::{CairoProof, PublicDataImpl};
use stwo_full_verifier_phases::claim_mix::{
    claim_mix_absorb_program_entries, claim_mix_begin, claim_mix_finalize,
};
use stwo_full_verifier_phases::unpack_proof_v2;
use stwo_verifier_core::channel::poseidon252::new_channel;

const N_SLOTS: u32 = 55_540;
const N_VALUES: u32 = 301_143;

/// Program entries fed per pipeline transaction (the real machine sizes
/// chunks by the ~4.9k-felt calldata budget: an entry is 9 serde felts, so
/// ~540 entries/tx; 401 also exercises unaligned pending buffers).
const CHUNK_ENTRIES: u32 = 401;

#[test]
fn test_chunked_claim_mix_matches_monolithic() {
    let file = FileTrait::new("tests/data/poseidon_chain_n100_full_proof_packed_v2.txt");
    let slots = read_txt(@file);
    let values = unpack_proof_v2(slots.span(), N_VALUES);
    let mut span = values.span();
    let proof: CairoProof = Serde::deserialize(ref span).expect('proof deser');
    let claim = proof.claim;

    let digest0 = 'claim-mix-test-digest';

    // Monolithic reference.
    let mut channel = new_channel(digest0);
    claim.mix_into(ref channel);
    let expected = channel.digest;

    // Chunked pipeline over the same claim.
    let flat = claim.flatten_claim();
    let (public_claim, _output_claim, _program_claim) = flat.public_data.pack_into_u32s();
    let program = flat.public_data.public_memory.program;
    let n_program = SpanTrait::len(program);
    let prefix = public_claim.slice(0, SpanTrait::len(public_claim) - n_program);

    let mut channel = new_channel(digest0);
    let mut state = claim_mix_begin(
        ref channel,
        flat.component_enable_bits,
        flat.component_log_sizes,
        prefix,
        flat.public_data.public_memory.output,
        n_program,
    );

    let mut remaining = program;
    while SpanTrait::len(remaining) != 0 {
        let left = SpanTrait::len(remaining);
        let n = min(left, CHUNK_ENTRIES);
        claim_mix_absorb_program_entries(ref state, remaining.slice(0, n));
        remaining = remaining.slice(n, left - n);

        // Simulate the transaction boundary: checkpoint serde round-trip.
        let mut serialized = array![];
        Serde::serialize(@state, ref serialized);
        let mut cp_span = serialized.span();
        state = Serde::deserialize(ref cp_span).expect('state deser');
    }

    assert!(claim_mix_finalize(state) == expected);
}
