//! End-to-end router drive over the REAL fixture proof (FRI transport
//! v3): 2 sampled staging txs → begin → 5 claim chunks → claim finalize →
//! 5 lookup chunks → lookup finalize → oods begin → 15 merged OODS group
//! classes → oods finalize → fri commit (FriHead calldata) → 5 fused
//! group txs → N fri layer-chunk txs → finalize. Only the sampled section
//! is staged (for the fused group txs); the OODS txs carry it as
//! calldata, and the fri section's bulk arrives layer-batched as
//! calldata, self-authenticating against the layer commitments; every
//! state echoed against the hash-stored checkpoint — must register into
//! the shared fact registry the fact whose program/output hashes equal
//! the vendored `encode_and_hash_memory_section` of the claim's program
//! and output sections. Plus the router-layer rejections: proof-id reuse,
//! wrong-tag state, tampered state bytes, non-route fact registration.

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
    IStwoSharedFactRegistrySafeDispatcher, IStwoSharedFactRegistrySafeDispatcherTrait,
};
use stwo_full_verifier_phases::machine::HEAD_PROGRAM_ENTRIES;
use stwo_full_verifier_phases::pack::pack_v2;
use stwo_full_verifier_phases::router::{
    IStwoVerifierRouterDispatcher, IStwoVerifierRouterDispatcherTrait,
    IStwoVerifierRouterSafeDispatcher, IStwoVerifierRouterSafeDispatcherTrait, SECTION_SAMPLED,
    TAG_DONE,
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

const N_VALUES: u32 = 301_143;
const CHUNK_ENTRIES: u32 = 540;
const N_GROUPS: u32 = 5;
const FELTS_PER_ENTRY: u32 = 9;
const PROOF_ID: felt252 = 'poseidon_chain_n100';
/// Staged slots per staging transaction: the bouncer's 4,000-felt
/// state-diff budget counts key + value = 2 felts PER WRITE
/// (devnet-measured), so ~1,950 writes is the real bound; 1,900 is the
/// production chunk (trivially within the ~4,996-felt calldata cap).
const STAGE_CHUNK: u32 = 1_900;

#[derive(Drop)]
struct Streams {
    head: Array<felt252>,
    program: MemorySection,
    output: MemorySection,
    sampled: Span<felt252>,
    fri: Span<felt252>,
}

/// Same carving as test_machine's build_streams (+ the output section for
/// the expected fact hashes).
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

fn read_group(group: u32) -> (Array<Span<felt252>>, Array<Span<M31>>) {
    let file = FileTrait::new(format!("tests/data/witness_group_{}.txt", group));
    let mut span = read_txt(@file).span();
    let _start: u32 = Serde::deserialize(ref span).expect('start');
    let _n: u32 = Serde::deserialize(ref span).expect('n');
    let witnesses: Array<Span<felt252>> = Serde::deserialize(ref span).expect('witnesses');
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

/// Declares the 21 machine classes and deploys the router over them,
/// registered as a route of a fresh shared fact registry.
fn deploy_router() -> (IStwoVerifierRouterDispatcher, IStwoSharedFactRegistryDispatcher) {
    let registry = deploy_registry();
    // The 15 merged OODS group classes, in family order (lib.cairo map).
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

/// Stages a packed section in state-diff-capped chunks; returns the
/// number of staging transactions.
fn stage_section(
    router: IStwoVerifierRouterDispatcher, section: felt252, packed: Span<felt252>,
) -> u32 {
    let total = SpanTrait::len(packed);
    let mut offset = 0_u32;
    let mut txs = 0_u32;
    while offset != total {
        let n = min(total - offset, STAGE_CHUNK);
        router.stage(PROOF_ID, section, offset, packed.slice(offset, n));
        offset += n;
        txs += 1;
    }
    txs
}

/// Packs a section for transport; returns (packed, n_values).
fn packed(values: Span<felt252>) -> (Span<felt252>, u32) {
    (pack_v2(values).span(), SpanTrait::len(values))
}

/// Serde felts of a value, packed.
fn packed_serde<T, +Serde<T>, +Drop<T>>(value: @T) -> (Span<felt252>, u32) {
    let mut felts = array![];
    Serde::serialize(value, ref felts);
    packed(felts.span())
}

fn load_streams() -> Streams {
    let file = FileTrait::new("tests/data/poseidon_chain_n100_full_proof_packed_v2.txt");
    let slots = read_txt(@file);
    let values = unpack_proof_v2(slots.span(), N_VALUES);
    build_streams(values.span())
}

#[test]
fn test_router_full_drive_registers_fact() {
    let streams = load_streams();
    let (router, registry) = deploy_router();
    let (head_p, head_n) = packed(streams.head.span());
    let (sampled_p, sampled_n) = packed(streams.sampled);
    let fri_transport = build_fri_transport(streams.fri);
    let (fri_head_p, fri_head_n) = packed(fri_transport.head_felts.span());
    let program = streams.program;
    let n_entries = program.len();

    // Write-once staging (v3: sampled only — 2,609 slots, 2 txs — for the
    // fused group txs; the fri section is never stored).
    let sampled_txs = stage_section(router, SECTION_SAMPLED, sampled_p);
    assert!(sampled_txs == 2, "sampled staging txs");
    let sampled_slots = SpanTrait::len(sampled_p);

    let mut state = router.begin(PROOF_ID, head_p, head_n, n_entries);

    let mut offset = 0_u32;
    while offset != n_entries {
        let n = min(n_entries - offset, CHUNK_ENTRIES);
        let (entries_p, entries_n) = packed_serde(@program.slice(offset, n));
        state = router.claim_chunk(PROOF_ID, state.span(), entries_p, entries_n);
        offset += n;
    }
    state = router.claim_finalize(PROOF_ID, state.span(), head_p, head_n);

    let mut offset = 0_u32;
    while offset != n_entries {
        let n = min(n_entries - offset, CHUNK_ENTRIES);
        let (entries_p, entries_n) = packed_serde(@program.slice(offset, n));
        state = router.lookup_chunk(PROOF_ID, state.span(), entries_p, entries_n);
        offset += n;
    }
    state = router.lookup_finalize(PROOF_ID, state.span(), head_p, head_n);

    state = router
        .oods_begin(PROOF_ID, state.span(), head_p, head_n, sampled_p, sampled_n);
    let mut group_index = 0_u32;
    while group_index != 15 {
        state = router
            .oods_group(
                PROOF_ID, group_index, state.span(), head_p, head_n, sampled_p, sampled_n,
            );
        group_index += 1;
    }
    state = router
        .oods_finalize(PROOF_ID, state.span(), head_p, head_n, sampled_p, sampled_n);

    state = router.fri_commit(PROOF_ID, state.span(), head_p, head_n, fri_head_p, fri_head_n);

    let mut group = 0_u32;
    while group != N_GROUPS {
        let (witnesses, rows) = read_group(group);
        let (rows_p, rows_n) = packed_serde(@rows);
        let (wit_p, wit_n) = packed_serde(@witnesses);
        state = router
            .group(
                PROOF_ID, state.span(), head_p, head_n, sampled_slots, sampled_n, rows_p,
                rows_n, wit_p, wit_n,
            );
        group += 1;
    }

    for chunk in fri_transport.layer_chunks.span() {
        let (chunk_p, chunk_n) = packed(chunk.span());
        state = router
            .fri_layers(
                PROOF_ID, state.span(), head_p, head_n, fri_head_p, fri_head_n, chunk_p,
                chunk_n,
            );
    }

    let (program_hash, output_hash) = router
        .finalize(PROOF_ID, state.span(), head_p, head_n, fri_head_p, fri_head_n);

    // The fact hashes must equal the vendored section hashes (the same
    // values the monolithic verifier outputs — proven in test_machine).
    assert!(
        program_hash == construct_f252(encode_and_hash_memory_section(streams.program)),
        "program hash",
    );
    assert!(
        output_hash == construct_f252(encode_and_hash_memory_section(streams.output)),
        "output hash",
    );
    // The fact lands in the SHARED registry, written via the governed
    // route (the router), not in router-local storage.
    let fact = poseidon_hash_span([program_hash, output_hash].span());
    assert!(registry.is_valid(fact), "fact registered");
    let (tag, _) = router.checkpoint(test_address(), PROOF_ID);
    assert!(tag == TAG_DONE, "checkpoint done");
}

/// Router-layer rejections, all against one deployment via the safe
/// dispatcher: proof-id reuse, a state fed to the wrong phase kind, a
/// tampered state echo, and a non-route caller writing to the registry.
#[test]
#[feature("safe_dispatcher")]
fn test_router_rejects_bad_steps() {
    let streams = load_streams();
    let (router, registry) = deploy_router();
    let safe = IStwoVerifierRouterSafeDispatcher {
        contract_address: router.contract_address,
    };
    let (head_p, head_n) = packed(streams.head.span());
    let program = streams.program;
    let n_entries = program.len();

    let state = router.begin(PROOF_ID, head_p, head_n, n_entries);

    // Reusing a started proof_id must be rejected.
    match safe.begin(PROOF_ID, head_p, head_n, n_entries) {
        Result::Ok(_) => panic!("begin reuse must fail"),
        Result::Err(panic_data) => assert!(
            *panic_data[0] == 'router: proof id in use', "reuse panic",
        ),
    }

    // A claim-tagged state fed to a lookup-phase entrypoint must be
    // rejected by the tag check.
    let (entries_p, entries_n) = packed_serde(@program.slice(0, CHUNK_ENTRIES));
    match safe.lookup_chunk(PROOF_ID, state.span(), entries_p, entries_n) {
        Result::Ok(_) => panic!("wrong tag must fail"),
        Result::Err(panic_data) => assert!(*panic_data[0] == 'router: tag', "tag panic"),
    }

    // A tampered state echo must be rejected by the hash check.
    let mut tampered: Array<felt252> = array![];
    let mut index = 0_u32;
    for value in state.span() {
        tampered.append(if index == 0 {
            *value + 1
        } else {
            *value
        });
        index += 1;
    }
    match safe.claim_chunk(PROOF_ID, tampered.span(), entries_p, entries_n) {
        Result::Ok(_) => panic!("tampered state must fail"),
        Result::Err(panic_data) => assert!(*panic_data[0] == 'router: state', "state panic"),
    }

    // The test contract is not a route: registering directly must fail.
    let safe_registry = IStwoSharedFactRegistrySafeDispatcher {
        contract_address: registry.contract_address,
    };
    match safe_registry.register_fact('forged') {
        Result::Ok(_) => panic!("non-route register must fail"),
        Result::Err(panic_data) => assert!(
            *panic_data[0] == 'registry: not a route', "route panic",
        ),
    }

    // The honest step still works after the rejected attempts.
    let _ = router.claim_chunk(PROOF_ID, state.span(), entries_p, entries_n);
}
