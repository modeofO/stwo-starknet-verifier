//! End-to-end FactRegistry tests over a REAL proof: the multiverifier
//! circuit proof of `poseidon_chain(100)` executed under the privacy simple
//! bootloader (see docs/spike3-results.md; fixture regenerable with
//! scripts/prove-and-verify.sh + scripts/pack_proof.py).

use snforge_std::fs::{FileTrait, read_txt};
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use stwo_fact_registry::{IStwoFactRegistryDispatcher, IStwoFactRegistryDispatcherTrait};
use stwo_verifier_phases::unpack_proof;

/// Calldata limit per transaction on Starknet is 5,000 felts (including the
/// account's __execute__ envelope of ~4 felts and the function's own
/// non-span arguments), so the head carries 4,991 slots.
const HEAD_LEN: u32 = 4_991;
const N_SLOTS: u32 = 5_147;
const N_VALUES: u32 = 36_022;

fn deploy_registry() -> IStwoFactRegistryDispatcher {
    let phase1 = declare("StwoPhase1").unwrap().contract_class();
    let phase2 = declare("StwoPhase2").unwrap().contract_class();
    let registry = declare("StwoFactRegistry").unwrap().contract_class();
    let mut calldata = array![];
    Serde::serialize(phase1.class_hash, ref calldata);
    Serde::serialize(phase2.class_hash, ref calldata);
    let (address, _) = registry.deploy(@calldata).unwrap();
    IStwoFactRegistryDispatcher { contract_address: address }
}

fn load_packed_proof() -> Array<felt252> {
    let file = FileTrait::new("tests/data/poseidon_chain_n100_proof_packed.txt");
    read_txt(@file)
}

/// Mirror of scripts/pack_proof.py — packs a felt value stream for staging.
fn pack_values(values: Span<felt252>) -> Array<felt252> {
    let mut limbs: Array<u64> = array![];
    for v in values {
        let as_u64: u64 = (*v).try_into().expect('value exceeds u64');
        if as_u64 < 0xFFFFFFFF {
            limbs.append(as_u64);
        } else {
            limbs.append(0xFFFFFFFF);
            limbs.append(as_u64 % 0x100000000);
            limbs.append(as_u64 / 0x100000000);
        }
    }
    let mut slots = array![];
    let limbs = limbs.span();
    let mut i = 0;
    while i < limbs.len() {
        let mut slot: felt252 = 0;
        let mut mult: felt252 = 1;
        let mut j = 0;
        while j != 7 && i < limbs.len() {
            slot += (*limbs[i]).into() * mult;
            mult *= 0x100000000;
            i += 1;
            j += 1;
        }
        slots.append(slot);
    }
    slots
}

/// Runs the full 3-tx flow (stage tail, phase1, phase2) for `proof_id` over
/// `packed`, returning the fact.
fn run_two_phase(
    registry: IStwoFactRegistryDispatcher, proof_id: felt252, packed: Span<felt252>,
) -> felt252 {
    let (head, tail) = (packed.slice(0, HEAD_LEN), packed.slice(HEAD_LEN, N_SLOTS - HEAD_LEN));
    registry.stage_proof(proof_id, 0, tail);
    let fri_offset = registry.verify_phase1(proof_id, head, N_SLOTS - HEAD_LEN, N_VALUES);

    let values = unpack_proof(packed, N_VALUES);
    let n_fri_values = N_VALUES - fri_offset - 1;
    let fri_values = values.span().slice(fri_offset, n_fri_values);
    let fri_slots = pack_values(fri_values);
    registry.verify_phase2(proof_id, fri_slots.span(), n_fri_values)
}

#[test]
fn test_two_phase_verification_real_proof() {
    let registry = deploy_registry();
    let packed = load_packed_proof();
    assert!(packed.len() == N_SLOTS, "fixture length changed");

    let fact = run_two_phase(registry, 'pcn100', packed.span());
    assert!(registry.is_valid(fact), "fact must be registered");
    assert!(!registry.is_valid(fact + 1), "unrelated fact must not be valid");
}

/// A corrupted proof head must be rejected in phase 1.
#[test]
#[should_panic]
fn test_corrupted_head_rejected() {
    let registry = deploy_registry();
    let packed = load_packed_proof();
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
    run_two_phase(registry, 'corrupted_head', corrupted.span());
}

/// A tampered FriProof must be rejected in phase 2 (query binding).
#[test]
#[should_panic]
fn test_two_phase_tampered_fri_rejected() {
    let registry = deploy_registry();
    let packed = load_packed_proof();
    let span = packed.span();
    let (head, tail) = (span.slice(0, HEAD_LEN), span.slice(HEAD_LEN, N_SLOTS - HEAD_LEN));

    let proof_id = 'tampered_fri';
    registry.stage_proof(proof_id, 0, tail);
    let fri_offset = registry.verify_phase1(proof_id, head, N_SLOTS - HEAD_LEN, N_VALUES);

    let values = unpack_proof(span, N_VALUES);
    let n_fri_values = N_VALUES - fri_offset - 1;
    let fri_values = values.span().slice(fri_offset, n_fri_values);
    let mut tampered = array![];
    let mut i = 0;
    for v in fri_values {
        tampered.append(if i == 100 {
            *v + 1
        } else {
            *v
        });
        i += 1;
    }
    let fri_slots = pack_values(tampered.span());
    registry.verify_phase2(proof_id, fri_slots.span(), n_fri_values);
}

/// Phase 2 without a phase-1 checkpoint must be rejected.
#[test]
#[should_panic(expected: 'no phase1 checkpoint')]
fn test_phase2_without_phase1_rejected() {
    let registry = deploy_registry();
    registry.verify_phase2('nonexistent', array![1, 2, 3].span(), 3);
}

/// Cost probe: bare phase 1 (no contract, no storage).
#[test]
fn test_cost_phase1_bare() {
    let packed = load_packed_proof();
    let values = unpack_proof(packed.span(), N_VALUES);
    let cp = stwo_verifier_phases::resumable::phase1(values.span());
    assert!(cp.fri_value_offset == 23_130, "unexpected fri offset");
}

/// Cost probe: bare phase 2 (no contract, no storage).
#[test]
fn test_cost_phase2_bare() {
    let packed = load_packed_proof();
    let values = unpack_proof(packed.span(), N_VALUES);
    let cp = stwo_verifier_phases::resumable::phase1(values.span());
    let n_fri_values = N_VALUES - cp.fri_value_offset - 1;
    let fri_values = values.span().slice(cp.fri_value_offset, n_fri_values);
    let _output = stwo_verifier_phases::resumable::phase2(fri_values, cp);
}
