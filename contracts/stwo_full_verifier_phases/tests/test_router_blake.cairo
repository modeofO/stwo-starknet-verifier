//! qm31-pivot router drive: the REAL blake2s-channel fixture proof driven
//! end-to-end through the deployed router — the production transaction
//! shape of the sovereign lane (FRI transport v3): 2 sampled staging txs +
//! begin + 5 claim chunks + claim finalize + 5 lookup chunks + lookup
//! finalize + oods begin + 15 merged OODS group classes + oods finalize +
//! fri commit (FriHead calldata) + 9 fused 8-query group txs + N fri
//! layer-chunk txs + finalize. The fri section is NEVER stored: its bulk
//! is self-authenticating against the layer commitments and arrives
//! layer-batched as calldata; the OODS txs supply the sampled section as
//! calldata too (staged reads cost ~122k gas/slot, devnet-measured) while
//! the fused group txs read the staged copy (their rows leave no room).
//! Every tx's calldata is COUNTED and asserted under the ~4,996-felt
//! usable cap and every staging tx under the block state-diff budget
//! (4,000 felts at TWO felts per storage write, devnet-measured) — this
//! test is the measured "everything fits" claim for the pivot, executed.
//!
//! The fact must land in the shared registry with program/output hashes
//! equal to the vendored `encode_and_hash_memory_section` of the claim's
//! sections — the same fact definition as the poseidon build.

use core::array::SpanTrait;
use core::cmp::min;
use core::poseidon::poseidon_hash_span;
use snforge_std::fs::{FileTrait, read_txt};
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare, test_address};
use starknet::ClassHash;
use stwo_cairo_air::claim::CairoInteractionClaim;
use stwo_cairo_air::claims::CairoClaim;
use stwo_full_verifier_phases::fact_registry::{
    IStwoSharedFactRegistryDispatcher, IStwoSharedFactRegistryDispatcherTrait,
};
use stwo_full_verifier_phases::machine::HEAD_PROGRAM_ENTRIES;
use stwo_full_verifier_phases::pack::pack_v2;
use stwo_full_verifier_phases::router::{
    IStwoVerifierRouterDispatcher, IStwoVerifierRouterDispatcherTrait, SECTION_SAMPLED, TAG_DONE,
};
use crate::fri_v3_util::build_fri_transport;
use stwo_full_verifier_phases::unpack_proof_v2;
use stwo_verifier_core::fields::m31::M31;
use stwo_verifier_core::fields::qm31::{QM31, QM31Serde};
use stwo_verifier_core::fri::FriProof;
use stwo_verifier_core::pcs::PcsConfig;
use stwo_verifier_core::vcs::MerkleHasher;
use stwo_verifier_core::vcs::verifier::MerkleDecommitment;
use stwo_verifier_core::Hash;
use stwo_verifier_utils::poseidon252::encode_and_hash_memory_section;
use stwo_verifier_utils::{MemorySection, construct_f252};

const N_VALUES: u32 = 381_079;
const CHUNK_ENTRIES: u32 = 540;
/// Fused group transactions: 70 queries at 8 per group (production size —
/// see the staged-section-store arithmetic in docs/lane2-design.md).
const N_GROUPS: u32 = 9;
const FELTS_PER_ENTRY: u32 = 9;
const PROOF_ID: felt252 = 'poseidon_chain_n100_blake';
/// Usable felts per invoke transaction (5,000 minus the account-call
/// envelope; docs/lane2-design.md).
const CALLDATA_CAP: u32 = 4_996;
/// Staged slots per staging tx: the bouncer's 4,000-felt state-diff
/// budget counts key + value = 2 felts PER WRITE (devnet-measured), so
/// ~1,950 writes is the real bound; 1,900 is the production chunk.
const STAGE_CHUNK: u32 = 1_900;

#[derive(Drop)]
struct Streams {
    head: Array<felt252>,
    program: MemorySection,
    output: MemorySection,
    sampled: Span<felt252>,
    fri: Span<felt252>,
}

/// Same carving as test_machine_blake's build_streams (+ the output
/// section for the expected fact hashes).
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
        output: claim.public_data.public_memory.output,
        sampled: values.slice(commitments_end, sampled_end - commitments_end),
        fri: values.slice(nonce_end, fri_end - nonce_end),
    }
}

/// Loads one bridge witness-group fixture (split-witness --blake, size 8).
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

fn class_hash(name: ByteArray) -> ClassHash {
    *declare(name).unwrap().contract_class().class_hash
}

/// Deploys the shared fact registry owned by the test contract.
fn deploy_registry() -> IStwoSharedFactRegistryDispatcher {
    let registry = declare("StwoSharedFactRegistry").unwrap().contract_class();
    let mut calldata = array![];
    Serde::serialize(@test_address(), ref calldata);
    let (address, _) = registry.deploy(@calldata).unwrap();
    IStwoSharedFactRegistryDispatcher { contract_address: address }
}

/// Declares the 21 machine classes (blake build: G07 is the 8-family
/// per-component builtins class) and deploys the router as a registry
/// route. Identical class list to the poseidon build — one source.
fn deploy_router() -> (IStwoVerifierRouterDispatcher, IStwoSharedFactRegistryDispatcher) {
    let registry = deploy_registry();
    let group_names: Array<ByteArray> = array![
        "StwoOodsG00", "StwoOodsG01", "StwoOodsG02", "StwoOodsG03", "StwoOodsG04",
        "StwoOodsG05", "StwoOodsG06", "StwoOodsG07", "StwoOodsG08", "StwoOodsG09",
        "StwoOodsG10", "StwoOodsG11", "StwoOodsG12", "StwoOodsG13", "StwoOodsG14",
    ];
    let mut oods_groups: Array<ClassHash> = array![];
    for name in group_names {
        oods_groups.append(class_hash(name));
    }

    let mut calldata = array![];
    Serde::serialize(@class_hash("StwoMachineClaim"), ref calldata);
    Serde::serialize(@class_hash("StwoMachineLookup"), ref calldata);
    Serde::serialize(@class_hash("StwoOodsBegin"), ref calldata);
    Serde::serialize(@oods_groups.span(), ref calldata);
    Serde::serialize(@class_hash("StwoOodsFinalize"), ref calldata);
    Serde::serialize(@class_hash("StwoMachineGroup"), ref calldata);
    Serde::serialize(@class_hash("StwoMachineFri"), ref calldata);
    Serde::serialize(@registry.contract_address, ref calldata);
    let router = declare("StwoVerifierRouter").unwrap().contract_class();
    let (address, _) = router.deploy(@calldata).unwrap();
    let router = IStwoVerifierRouterDispatcher { contract_address: address };
    registry.add_route(router.contract_address);
    (router, registry)
}

fn packed(values: Span<felt252>) -> (Span<felt252>, u32) {
    (pack_v2(values).span(), SpanTrait::len(values))
}

fn packed_serde<T, +Serde<T>, +Drop<T>>(value: @T) -> (Span<felt252>, u32) {
    let mut felts = array![];
    Serde::serialize(value, ref felts);
    packed(felts.span())
}

fn load_streams() -> Streams {
    let file = FileTrait::new("tests/data/poseidon_chain_n100_blake_proof_packed_v2.txt");
    let slots = read_txt(@file);
    let values = unpack_proof_v2(slots.span(), N_VALUES);
    build_streams(values.span())
}

/// The calldata cost of one entrypoint invocation: scalar args count 1
/// felt each; each span arg costs len + 1 (its length prefix).
fn tx_calldata(scalars: u32, spans: Span<Span<felt252>>) -> u32 {
    let mut total = scalars;
    for s in spans {
        total += SpanTrait::len(*s) + 1;
    }
    total
}

/// Asserts one transaction under the usable calldata cap.
fn assert_fits(label: ByteArray, felts: u32) {
    assert!(felts <= CALLDATA_CAP, "{} calldata {} over cap", label, felts);
}

/// Stages a packed section in state-diff-capped chunks; every staging tx
/// is also checked against the calldata cap. Returns the tx count.
fn stage_section(
    router: IStwoVerifierRouterDispatcher, section: felt252, packed: Span<felt252>,
) -> u32 {
    let total = SpanTrait::len(packed);
    let mut offset = 0_u32;
    let mut txs = 0_u32;
    while offset != total {
        let n = min(total - offset, STAGE_CHUNK);
        let chunk = packed.slice(offset, n);
        // proof_id + section + offset + the slot span.
        assert_fits("stage", tx_calldata(3, [chunk].span()));
        router.stage(PROOF_ID, section, offset, chunk);
        offset += n;
        txs += 1;
    }
    txs
}

#[test]
fn test_router_blake_full_drive_registers_fact() {
    let streams = load_streams();
    let (router, registry) = deploy_router();
    let (head_p, head_n) = packed(streams.head.span());
    let (sampled_p, sampled_n) = packed(streams.sampled);
    let fri_transport = build_fri_transport(streams.fri);
    let (fri_head_p, fri_head_n) = packed(fri_transport.head_felts.span());
    let program = streams.program;
    let n_entries = program.len();
    let mut txs = 0_u32;

    // Write-once staging (v3: sampled only, for the fused group txs).
    txs += stage_section(router, SECTION_SAMPLED, sampled_p);
    assert!(txs == 2, "staging txs");
    let sampled_slots = SpanTrait::len(sampled_p);

    assert_fits("begin", tx_calldata(3, [head_p].span()));
    let mut state = router.begin(PROOF_ID, head_p, head_n, n_entries);
    txs += 1;

    let mut offset = 0_u32;
    while offset != n_entries {
        let n = min(n_entries - offset, CHUNK_ENTRIES);
        let (entries_p, entries_n) = packed_serde(@program.slice(offset, n));
        assert_fits("claim_chunk", tx_calldata(3, [state.span(), entries_p].span()));
        state = router.claim_chunk(PROOF_ID, state.span(), entries_p, entries_n);
        txs += 1;
        offset += n;
    }
    assert_fits("claim_finalize", tx_calldata(3, [state.span(), head_p].span()));
    state = router.claim_finalize(PROOF_ID, state.span(), head_p, head_n);
    txs += 1;

    let mut offset = 0_u32;
    while offset != n_entries {
        let n = min(n_entries - offset, CHUNK_ENTRIES);
        let (entries_p, entries_n) = packed_serde(@program.slice(offset, n));
        assert_fits("lookup_chunk", tx_calldata(3, [state.span(), entries_p].span()));
        state = router.lookup_chunk(PROOF_ID, state.span(), entries_p, entries_n);
        txs += 1;
        offset += n;
    }
    assert_fits("lookup_finalize", tx_calldata(3, [state.span(), head_p].span()));
    state = router.lookup_finalize(PROOF_ID, state.span(), head_p, head_n);
    txs += 1;

    // OODS transactions carry the sampled section as CALLDATA (v3).
    assert_fits("oods_begin", tx_calldata(3, [state.span(), head_p, sampled_p].span()));
    state = router
        .oods_begin(PROOF_ID, state.span(), head_p, head_n, sampled_p, sampled_n);
    txs += 1;
    let mut group_index = 0_u32;
    while group_index != 15 {
        assert_fits("oods_group", tx_calldata(4, [state.span(), head_p, sampled_p].span()));
        state = router
            .oods_group(
                PROOF_ID, group_index, state.span(), head_p, head_n, sampled_p, sampled_n,
            );
        txs += 1;
        group_index += 1;
    }
    assert_fits("oods_finalize", tx_calldata(3, [state.span(), head_p, sampled_p].span()));
    state = router
        .oods_finalize(PROOF_ID, state.span(), head_p, head_n, sampled_p, sampled_n);
    txs += 1;

    assert_fits("fri_commit", tx_calldata(3, [state.span(), head_p, fri_head_p].span()));
    state = router.fri_commit(PROOF_ID, state.span(), head_p, head_n, fri_head_p, fri_head_n);
    txs += 1;

    let mut group = 0_u32;
    let mut worst_group_tx = 0_u32;
    while group != N_GROUPS {
        let (witnesses, rows) = read_group(group);
        let (rows_p, rows_n) = packed_serde(@rows);
        let (wit_p, wit_n) = packed_serde(@witnesses);
        let felts = tx_calldata(7, [state.span(), head_p, rows_p, wit_p].span());
        assert_fits("group", felts);
        worst_group_tx = core::cmp::max(worst_group_tx, felts);
        state = router
            .group(
                PROOF_ID, state.span(), head_p, head_n, sampled_slots, sampled_n, rows_p,
                rows_n, wit_p, wit_n,
            );
        txs += 1;
        group += 1;
    }
    // FRI decommit layer chunks: self-authenticating layer proofs as
    // calldata, folded (queries, evals) riding the checkpoint.
    let n_layer_chunks = fri_transport.layer_chunks.len();
    let mut worst_layer_tx = 0_u32;
    for chunk in fri_transport.layer_chunks.span() {
        let (chunk_p, chunk_n) = packed(chunk.span());
        let felts = tx_calldata(4, [state.span(), head_p, fri_head_p, chunk_p].span());
        assert_fits("fri_layers", felts);
        worst_layer_tx = core::cmp::max(worst_layer_tx, felts);
        state = router
            .fri_layers(
                PROOF_ID, state.span(), head_p, head_n, fri_head_p, fri_head_n, chunk_p,
                chunk_n,
            );
        txs += 1;
    }
    println!(
        "blake router drive: sampled {} slots, fri head {} slots, {} layer chunks (worst {} felts), worst group tx {} felts",
        sampled_slots, SpanTrait::len(fri_head_p), n_layer_chunks, worst_layer_tx,
        worst_group_tx,
    );

    assert_fits("finalize", tx_calldata(3, [state.span(), head_p, fri_head_p].span()));
    let (program_hash, output_hash) = router
        .finalize(PROOF_ID, state.span(), head_p, head_n, fri_head_p, fri_head_n);
    txs += 1;
    assert!(txs == 43 + n_layer_chunks, "total transactions");

    // Same fact definition as the poseidon build: the vendored poseidon
    // section hashes (contract-side binding, not stwo transcript state).
    assert!(
        program_hash == construct_f252(encode_and_hash_memory_section(streams.program)),
        "program hash",
    );
    assert!(
        output_hash == construct_f252(encode_and_hash_memory_section(streams.output)),
        "output hash",
    );
    let fact = poseidon_hash_span([program_hash, output_hash].span());
    assert!(registry.is_valid(fact), "fact registered");
    let (tag, _) = router.checkpoint(test_address(), PROOF_ID);
    assert!(tag == TAG_DONE, "checkpoint done");
}
