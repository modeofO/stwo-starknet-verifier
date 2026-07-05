//! Cross-validation of the bridge's `emit-calldata` output (the router's
//! per-transaction transport) against the streams the Cairo side builds
//! from the committed proof fixture: unpacking each emitted file must
//! reproduce byte-for-byte the section that `build_streams`-style carving
//! (and the witness-group fixtures) produce in-circuit. Fixture files:
//! tests/data/calldata/, regenerated with
//! `privacy_prove_cairo_bridge emit-calldata <extended_proof> <dir>`.

use core::array::SpanTrait;
use core::cmp::min;
use snforge_std::fs::{FileTrait, read_txt};
use stwo_cairo_air::claim::CairoInteractionClaim;
use stwo_cairo_air::claims::CairoClaim;
use stwo_full_verifier_phases::machine::HEAD_PROGRAM_ENTRIES;
use stwo_full_verifier_phases::unpack_proof_v2;
use crate::fri_v3_util::build_fri_transport;
use stwo_verifier_core::fields::m31::M31;
use stwo_verifier_core::fields::qm31::{QM31, QM31Serde};
use stwo_verifier_core::fri::FriProof;
use stwo_verifier_core::pcs::PcsConfig;
use stwo_verifier_core::vcs::MerkleHasher;
use stwo_verifier_core::vcs::verifier::MerkleDecommitment;
use stwo_verifier_core::Hash;
use stwo_verifier_utils::MemorySection;

const N_VALUES: u32 = 301_143;
const CHUNK_ENTRIES: u32 = 540;
const FELTS_PER_ENTRY: u32 = 9;
// Unpacked section lengths (tests/data/calldata/manifest.json).
const HEAD_N: u32 = 446;
const SAMPLED_N: u32 = 18_261;
// FRI transport v3: the FriHead commitment slice + 3 layer chunks.
const FRI_HEAD_N: u32 = 27;
const FRI_LAYERS_N: [u32; 3] = [4_337, 5_269, 803];
const CHUNK_N: [u32; 5] = [4_861, 4_861, 4_861, 4_861, 3_934];
const ROWS_N: [u32; 5] = [55_877, 55_877, 55_877, 55_877, 20_957];
const WITNESSES_N: [u32; 5] = [969, 969, 1_017, 1_053, 383];

#[derive(Drop)]
struct Streams {
    head: Array<felt252>,
    program: MemorySection,
    sampled: Span<felt252>,
    fri: Span<felt252>,
}

/// Same carving as test_machine's build_streams.
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
    let _nonce: u64 = Serde::deserialize(ref span).expect('nonce');
    let nonce_end = total - SpanTrait::len(span);
    let _fri: FriProof = Serde::deserialize(ref span).expect('fri');
    let fri_end = total - SpanTrait::len(span);
    let _salt: u32 = Serde::deserialize(ref span).expect('salt');
    assert!(SpanTrait::is_empty(span));

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
        fri: values.slice(nonce_end, fri_end - nonce_end),
    }
}

fn read_calldata(name: ByteArray, n_values: u32) -> Array<felt252> {
    let file = FileTrait::new(format!("tests/data/calldata/{}", name));
    let packed = read_txt(@file);
    unpack_proof_v2(packed.span(), n_values)
}

fn assert_section_eq(actual: Span<felt252>, expected: Span<felt252>, name: ByteArray) {
    assert!(SpanTrait::len(actual) == SpanTrait::len(expected), "{} length", name);
    let mut index = 0_u32;
    for value in expected {
        assert!(*actual[index] == *value, "{} felt {}", name, index);
        index += 1;
    }
}

#[test]
fn test_emitted_calldata_matches_streams() {
    let file = FileTrait::new("tests/data/poseidon_chain_n100_full_proof_packed_v2.txt");
    let slots = read_txt(@file);
    let values = unpack_proof_v2(slots.span(), N_VALUES);
    let streams = build_streams(values.span());

    assert_section_eq(read_calldata("head.txt", HEAD_N).span(), streams.head.span(), "head");
    assert_section_eq(
        read_calldata("sampled.txt", SAMPLED_N).span(), streams.sampled, "sampled",
    );
    // FRI transport v3: the emitted head + layer chunks must equal the
    // in-Cairo slicing of the carved fri section (fri_v3_util's greedy
    // cut under the same 4,300-packed-slot budget).
    let fri_transport = build_fri_transport(streams.fri);
    assert_section_eq(
        read_calldata("fri_head.txt", FRI_HEAD_N).span(),
        fri_transport.head_felts.span(),
        "fri head",
    );
    assert!(fri_transport.layer_chunks.len() == 3, "fri layer chunk count");
    let mut layer_chunk = 0_u32;
    for chunk in fri_transport.layer_chunks.span() {
        assert_section_eq(
            read_calldata(
                format!("fri_layers_0{}.txt", layer_chunk),
                *FRI_LAYERS_N.span()[layer_chunk],
            )
                .span(),
            chunk.span(),
            format!("fri layers {}", layer_chunk),
        );
        layer_chunk += 1;
    }

    // Program-entry chunks: each file is the serde of the exact
    // MemorySection slice the claim/lookup phases consume.
    let program = streams.program;
    let n_entries = program.len();
    let mut chunk = 0_u32;
    let mut offset = 0_u32;
    while offset != n_entries {
        let n = min(n_entries - offset, CHUNK_ENTRIES);
        let mut expected: Array<felt252> = array![];
        Serde::serialize(@program.slice(offset, n), ref expected);
        assert_section_eq(
            read_calldata(format!("chunk_0{}.txt", chunk), *CHUNK_N.span()[chunk]).span(),
            expected.span(),
            format!("chunk {}", chunk),
        );
        offset += n;
        chunk += 1;
    }
    assert!(chunk == 5);

    // Query groups: rows and witnesses must equal the witness-group
    // fixtures (the streams test_machine drives the machine with).
    let mut group = 0_u32;
    while group != 5 {
        let file = FileTrait::new(format!("tests/data/witness_group_{}.txt", group));
        let mut span = read_txt(@file).span();
        let _start: u32 = Serde::deserialize(ref span).expect('start');
        let _n: u32 = Serde::deserialize(ref span).expect('n');
        let witnesses: Array<Span<felt252>> = Serde::deserialize(ref span).expect('witnesses');
        let rows: Array<Span<M31>> = Serde::deserialize(ref span).expect('rows');

        let mut expected_rows: Array<felt252> = array![];
        Serde::serialize(@rows, ref expected_rows);
        assert_section_eq(
            read_calldata(format!("group_0{}_rows.txt", group), *ROWS_N.span()[group]).span(),
            expected_rows.span(),
            format!("group {} rows", group),
        );

        let mut expected_witnesses: Array<felt252> = array![];
        Serde::serialize(@witnesses, ref expected_witnesses);
        assert_section_eq(
            read_calldata(format!("group_0{}_witnesses.txt", group), *WITNESSES_N.span()[group])
                .span(),
            expected_witnesses.span(),
            format!("group {} witnesses", group),
        );
        group += 1;
    }
}
