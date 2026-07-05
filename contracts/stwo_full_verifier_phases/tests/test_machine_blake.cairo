//! qm31-pivot machine equivalence: the full N-phase sequence over the REAL
//! blake2s-channel fixture proof (qm31_opcode build) — begin → claim chunks
//! → claim finalize → lookup chunks → lookup finalize → OODS+mix → FRI
//! commit → fused Merkle/fri_answers group txs → FRI decommit + fact — with
//! a checkpoint serde round-trip between every pair of transactions — must
//! produce exactly the monolithic verifier's output, hitting the same
//! channel digests at the phase seams. Mirrors test_machine.cairo; the
//! channel digests crossing checkpoints are 8-u32 blake hashes here.

use core::array::SpanTrait;
use core::cmp::min;
use snforge_std::fs::{FileTrait, read_txt};
use stwo_cairo_air::claim::CairoInteractionClaim;
use stwo_cairo_air::claims::CairoClaim;
use stwo_full_verifier_phases::machine::{
    HEAD_PROGRAM_ENTRIES, machine_begin, machine_claim_chunk, machine_claim_finalize,
    machine_fri_commit, machine_finalize, machine_fri_layers, machine_fri_layers_begin,
    machine_group, machine_lookup_chunk, machine_lookup_finalize, machine_oods_mix,
};
use crate::fri_v3_util::build_fri_transport;
use stwo_full_verifier_phases::resumable_full::{
    FullCheckpoint, phase_a, verify_full_monolithic,
};
use stwo_full_verifier_phases::unpack_proof_v2;
use stwo_verifier_core::fields::m31::M31;
use stwo_verifier_core::fields::qm31::{QM31, QM31Serde};
use stwo_verifier_core::fri::FriProof;
use stwo_verifier_core::pcs::PcsConfig;
use stwo_verifier_core::vcs::MerkleHasher;
use stwo_verifier_core::vcs::verifier::MerkleDecommitment;
use stwo_verifier_core::Hash;
use stwo_verifier_utils::MemorySection;

/// The blake fixture proof (prover_params_blake.json: plain blake2s channel,
/// canonical preprocessed trace, same PCS shape as the poseidon fixture).
const N_VALUES: u32 = 381_079;
/// Program entries per claim/lookup chunk transaction.
const CHUNK_ENTRIES: u32 = 540;
/// Fused Merkle+fri_answers group files (bridge split-witness --blake,
/// group size 8 — the production shape: with the sampled section staged,
/// an 8-query group's rows + witnesses fit the ~4,996-felt calldata cap;
/// 16-query rows alone are ~8.1k slots).
const N_GROUPS: u32 = 9;
/// Serde felts per program entry.
const FELTS_PER_ENTRY: u32 = 9;

/// The per-transaction calldata sections carved out of the fixture stream.
#[derive(Drop)]
struct Streams {
    head: Array<felt252>,
    program: MemorySection,
    sampled: Span<felt252>,
    fri: Span<felt252>,
}

/// Splits the proof stream into the machine's transport sections and builds
/// the head — identical carving to test_machine.cairo (the stream layout is
/// channel-generic; blake hashes are 8 serde felts each).
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
    head.append(*values[queried_end]); // queries PoW nonce (one felt)
    head.append(*values[total - 1]); // channel salt (one felt)

    Streams {
        head,
        program: claim.public_data.public_memory.program,
        sampled: values.slice(commitments_end, sampled_end - commitments_end),
        fri: values.slice(nonce_end, fri_end - nonce_end),
    }
}

/// Simulates the transaction boundary: the checkpoint must survive serde.
fn roundtrip<T, +Serde<T>, +Drop<T>>(state: T) -> T {
    let mut felts = array![];
    Serde::serialize(@state, ref felts);
    let mut span = felts.span();
    Serde::deserialize(ref span).expect('checkpoint roundtrip')
}

/// Loads one bridge witness-group fixture (split-witness --blake layout:
/// witnesses are Span<Hash>, 8 felts per blake hash).
fn read_group(group: u32) -> (Array<Span<Hash>>, Array<Span<M31>>) {
    let file = FileTrait::new(format!("tests/data/blake/witness_group_{}.txt", group));
    let mut span = read_txt(@file).span();
    let _start: u32 = Serde::deserialize(ref span).expect('start');
    let _n: u32 = Serde::deserialize(ref span).expect('n');
    let witnesses: Array<Span<Hash>> = Serde::deserialize(ref span).expect('witnesses');
    let rows: Array<Span<M31>> = Serde::deserialize(ref span).expect('rows');
    assert!(SpanTrait::is_empty(span));
    (witnesses, rows)
}

#[test]
fn test_machine_blake_full_sequence_matches_monolithic() {
    let file = FileTrait::new("tests/data/poseidon_chain_n100_blake_proof_packed_v2.txt");
    let slots = read_txt(@file);
    let values = unpack_proof_v2(slots.span(), N_VALUES);

    let expected = verify_full_monolithic(values.span());
    let FullCheckpoint { digest_pre_draw, digest_post_prologue, proof_hash: _ } = phase_a(
        values.span(),
    );

    let streams = build_streams(values.span());
    let program = streams.program;
    let n_entries = program.len();

    // Tx 1: begin.
    let mut claim_state = roundtrip(machine_begin(streams.head.span(), n_entries));

    // Tx 2..k: claim chunks.
    let mut offset = 0_u32;
    while offset != n_entries {
        let n = min(n_entries - offset, CHUNK_ENTRIES);
        claim_state = roundtrip(machine_claim_chunk(claim_state, program.slice(offset, n)));
        offset += n;
    }

    // Tx k+1: claim finalize + trace commit + interaction PoW.
    let lookup_state = roundtrip(machine_claim_finalize(claim_state, streams.head.span()));
    // Seam check: the machine lands on the skeleton's checkpoint digest.
    assert!(lookup_state.digest_pre_draw == digest_pre_draw, "pre-draw seam");

    // Tx k+2..m: lookup chunks (same boundaries as the claim chunks).
    let mut lookup_state = lookup_state;
    let mut offset = 0_u32;
    while offset != n_entries {
        let n = min(n_entries - offset, CHUNK_ENTRIES);
        lookup_state = roundtrip(machine_lookup_chunk(lookup_state, program.slice(offset, n)));
        offset += n;
    }

    // Tx m+1: lookup finalize + interaction claim mix/commit.
    let oods_state = roundtrip(machine_lookup_finalize(lookup_state, streams.head.span()));
    assert!(oods_state.digest_post_prologue == digest_post_prologue, "post-prologue seam");

    // Tx m+2: composition commit + OODS check + sampled mix.
    let fri_state = roundtrip(machine_oods_mix(oods_state, streams.head.span(), streams.sampled));

    // Tx m+3: FRI commitment + queries PoW + query sampling — transport
    // v3: only the FriHead commitment slice is consumed.
    let fri_transport = build_fri_transport(streams.fri);
    let fri_head = fri_transport.head_felts.span();
    let mut group_state = roundtrip(
        machine_fri_commit(fri_state, streams.head.span(), fri_head),
    );
    assert!(SpanTrait::len(group_state.query_positions) == 70);

    // Tx m+4..p: fused Merkle + fri_answers group transactions.
    let mut group = 0_u32;
    while group != N_GROUPS {
        let (witnesses, rows) = read_group(group);
        group_state =
            roundtrip(
                machine_group(
                    group_state, streams.head.span(), streams.sampled, rows, witnesses,
                ),
            );
        group += 1;
    }

    // Tx p+1..q: FRI decommit layer chunks (self-authenticating layer
    // proofs as calldata; the folded (queries, evals) ride the checkpoint).
    let mut chunks = fri_transport.layer_chunks.span();
    let first_chunk = chunks.pop_front().unwrap();
    let mut layers_state = roundtrip(
        machine_fri_layers_begin(
            group_state, streams.head.span(), fri_head, first_chunk.span(),
        ),
    );
    for chunk in chunks {
        layers_state =
            roundtrip(
                machine_fri_layers(layers_state, streams.head.span(), fri_head, chunk.span()),
            );
    }

    // Tx q+1: last-layer check, query-equality belt + fact material.
    let output = machine_finalize(layers_state, streams.head.span(), fri_head);
    assert!(output == expected, "machine output must equal monolithic");
}

#[test]
#[should_panic(expected: 'head binding')]
fn test_machine_blake_rejects_tampered_head() {
    let file = FileTrait::new("tests/data/poseidon_chain_n100_blake_proof_packed_v2.txt");
    let slots = read_txt(@file);
    let values = unpack_proof_v2(slots.span(), N_VALUES);
    let streams = build_streams(values.span());
    let program = streams.program;

    let claim_state = machine_begin(streams.head.span(), program.len());
    let claim_state = machine_claim_chunk(claim_state, program);

    let mut tampered: Array<felt252> = array![];
    let mut index = 0_u32;
    for value in streams.head.span() {
        tampered.append(if index == 5 {
            *value + 1
        } else {
            *value
        });
        index += 1;
    }
    let _ = machine_claim_finalize(claim_state, tampered.span());
}
