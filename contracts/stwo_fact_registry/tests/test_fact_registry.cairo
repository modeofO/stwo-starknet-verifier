//! End-to-end FactRegistry test over a REAL proof: the multiverifier circuit
//! proof of `poseidon_chain(100)` executed under the privacy simple
//! bootloader (see docs/spike3-results.md; fixture regenerable with
//! scripts/prove-and-verify.sh + scripts/pack_proof.py).

use snforge_std::fs::{FileTrait, read_txt};
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use stwo_fact_registry::{IStwoFactRegistryDispatcher, IStwoFactRegistryDispatcherTrait};

/// Calldata limit per transaction on Starknet is 5,000 felts; leave headroom
/// for the selector and other tx overhead.
const CHUNK_SIZE: u32 = 4_000;
const N_SLOTS: u32 = 5_147;
const N_VALUES: u32 = 36_022;

fn deploy_registry() -> IStwoFactRegistryDispatcher {
    let contract = declare("StwoFactRegistry").unwrap().contract_class();
    let (address, _) = contract.deploy(@array![]).unwrap();
    IStwoFactRegistryDispatcher { contract_address: address }
}

fn load_packed_proof() -> Array<felt252> {
    let file = FileTrait::new("tests/data/poseidon_chain_n100_proof_packed.txt");
    read_txt(@file)
}

fn stage(
    registry: IStwoFactRegistryDispatcher, proof_id: felt252, slots: Span<felt252>,
) {
    let n: u32 = slots.len();
    let mut offset: u32 = 0;
    while offset != n {
        let take = core::cmp::min(CHUNK_SIZE, n - offset);
        registry.stage_proof(proof_id, offset, slots.slice(offset, take));
        offset += take;
    }
}

#[test]
fn test_stage_verify_register_real_proof() {
    let registry = deploy_registry();
    let packed = load_packed_proof();
    assert!(packed.len() == N_SLOTS, "fixture length changed");

    // Two staging transactions' worth of calldata...
    let proof_id = 'poseidon_chain_n100';
    stage(registry, proof_id, packed.span());

    // ...then verify and register in a single call.
    let fact = registry.verify_and_register(proof_id, N_SLOTS, N_VALUES);

    assert!(registry.is_valid(fact), "fact must be registered");
    assert!(!registry.is_valid(fact + 1), "unrelated fact must not be valid");
}

#[test]
#[should_panic]
fn test_corrupted_proof_rejected() {
    let registry = deploy_registry();
    let packed = load_packed_proof();

    // Flip a bit somewhere inside the FRI commitment data.
    let mut corrupted = array![];
    let mut i: u32 = 0;
    for slot in packed.span() {
        corrupted.append(if i == 3_000 {
            *slot + 1
        } else {
            *slot
        });
        i += 1;
    }

    let proof_id = 'corrupted';
    stage(registry, proof_id, corrupted.span());
    registry.verify_and_register(proof_id, N_SLOTS, N_VALUES);
}

/// Staging cost in isolation — subtract from the full test to get the
/// verify_and_register transaction's cost.
#[test]
fn test_staging_only() {
    let registry = deploy_registry();
    let packed = load_packed_proof();
    stage(registry, 'staging_only', packed.span());
}

/// Cost decomposition: unpacking alone (no contract, no storage).
#[test]
fn test_cost_unpack_only() {
    let packed = load_packed_proof();
    let values = stwo_fact_registry::unpack_proof(packed.span(), N_VALUES);
    assert!(values.len() == N_VALUES, "bad unpack length");
}

/// Cost decomposition: unpack + deserialize + bare verification
/// (no contract, no storage syscalls).
#[test]
fn test_cost_bare_verification() {
    let packed = load_packed_proof();
    let values = stwo_fact_registry::unpack_proof(packed.span(), N_VALUES);
    let mut span = values.span();
    let proof: stwo_circuit_air::CircuitProof = Serde::deserialize(ref span).unwrap();
    let output = stwo_circuit_air::get_verification_output(@proof);
    stwo_circuit_air::verify_circuit(proof);
    let fact = stwo_fact_registry::fact_from_output(@output);
    assert!(fact != 0, "fact");
}

/// The two-transaction flow: head of the packed proof via calldata,
/// 152-slot tail staged.
#[test]
fn test_verify_from_calldata_real_proof() {
    let registry = deploy_registry();
    let packed = load_packed_proof();
    let head_len: u32 = 4_995;
    let span = packed.span();
    let (head, tail) = (span.slice(0, head_len), span.slice(head_len, N_SLOTS - head_len));

    let proof_id = 'pcn100_calldata';
    registry.stage_proof(proof_id, 0, tail);
    let fact = registry
        .verify_and_register_from_calldata(proof_id, head, N_SLOTS - head_len, N_VALUES);
    assert!(registry.is_valid(fact), "fact must be registered");
}
