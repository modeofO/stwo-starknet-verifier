//! MessageStore v3 tests: tree/registration behavior ported from
//! messagezk v2's suite, the lane-1 send path against the mock registry,
//! and the fact-chain seal — `compute_fact` over the milestone-1 gate
//! run's REAL tuple must reproduce the fact the circuit verifier's
//! printed output-hash words imply (docs/superpowers/specs/
//! 2026-07-05-zkmsg-milestone1-addendum.md).

use core::poseidon::poseidon_hash_span;
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_caller_address,
    stop_cheat_caller_address,
};
use starknet::ContractAddress;
use messagezk_store::merkle::verify_proof;
use messagezk_store::mock_registry::{
    IMockFactRegistryDispatcher, IMockFactRegistryDispatcherTrait,
};
use messagezk_store::store::{IMessageStoreV3Dispatcher, IMessageStoreV3DispatcherTrait};
use stwo_fact_binding::compute_fact;

/// Milestone-1 pinned constants (the REAL circuit's route).
const PROGRAM_HASH: felt252 = 0x250cb04a129e5259221ad4635950ac983bccf1de574893a2fae75c3c64385c;
const INNER_ROOT: [u32; 8] = [
    2674953418, 3988685724, 1385424428, 1661362028, 3534442848, 356489633, 2101289576,
    2757001180,
];
/// Milestone-1 gate-run public tuple.
const M1_COMMITMENT: felt252 = 0x24768d5e47fb400baf0a349b5b6b8213ab2bc6d21e142ba9245f4c6a5ac9f9d;
const M1_EPH_PUB: felt252 = 0x1efc3d7c9649900fcbd03f578a8248d095bc4b6a13b3c25f9886ef971ff96fa;
const M1_ROOT: felt252 = 0x225510ca702ebc9c1dad406f8cd08923fd3f8aea5a0ed58eb753265421522cd;

fn alice() -> ContractAddress {
    0xa11ce.try_into().unwrap()
}

fn bob() -> ContractAddress {
    0xb0b.try_into().unwrap()
}

fn deploy() -> (IMessageStoreV3Dispatcher, IMockFactRegistryDispatcher) {
    let mock = declare("MockFactRegistry").unwrap().contract_class();
    let (mock_addr, _) = mock.deploy(@array![]).unwrap();

    let store = declare("MessageStoreV3").unwrap().contract_class();
    let mut calldata = array![];
    Serde::serialize(@mock_addr, ref calldata);
    Serde::serialize(@PROGRAM_HASH, ref calldata);
    Serde::serialize(@INNER_ROOT, ref calldata);
    let (store_addr, _) = store.deploy(@calldata).unwrap();

    (
        IMessageStoreV3Dispatcher { contract_address: store_addr },
        IMockFactRegistryDispatcher { contract_address: mock_addr },
    )
}

fn register(store: IMessageStoreV3Dispatcher, who: ContractAddress, handle: felt252, key: felt252) {
    start_cheat_caller_address(store.contract_address, who);
    store.register(handle, key);
    stop_cheat_caller_address(store.contract_address);
}

/// The fact for a public tuple, exactly as the store must assemble it.
fn fact_for(commitment: felt252, eph: felt252, root: felt252) -> felt252 {
    compute_fact(PROGRAM_HASH, array![commitment, eph, root].span(), INNER_ROOT)
}

// --- the fact-chain seal -------------------------------------------------

/// The milestone-1 circuit run printed the verifier's output-hash words;
/// the registry's fact is poseidon over them. compute_fact from the raw
/// application tuple must land on the same felt — this pins program_hash,
/// inner_root, the output ORDER, and the whole blake2s chain at once.
#[test]
fn test_fact_chain_matches_milestone1_artifacts() {
    let words: [u32; 8] = [
        3110578688, 528312754, 1818420841, 1584490969, 406408838, 3678385441, 1556530268,
        4142792485,
    ];
    let [w0, w1, w2, w3, w4, w5, w6, w7] = words;
    let expected = poseidon_hash_span(
        array![
            w0.into(), w1.into(), w2.into(), w3.into(), w4.into(), w5.into(), w6.into(),
            w7.into(),
        ]
            .span(),
    );
    assert!(
        fact_for(M1_COMMITMENT, M1_EPH_PUB, M1_ROOT) == expected,
        "fact chain diverges from the real artifacts",
    );
}

// --- registration + tree -------------------------------------------------

#[test]
fn test_register_updates_root_and_path_verifies() {
    let (store, _) = deploy();
    let root0 = store.get_merkle_root();
    register(store, alice(), 'alice', 42);

    let root1 = store.get_merkle_root();
    assert!(root1 != root0, "root must change");

    let (owner, key, index) = store.get_user('alice');
    assert!(owner == alice() && key == 42 && index == 0, "get_user");

    let path = store.get_merkle_path(index);
    assert!(verify_proof(root1, 42, index, path.span()), "path must verify");
}

#[test]
fn test_two_users_paths_verify_and_old_root_known() {
    let (store, _) = deploy();
    register(store, alice(), 'alice', 42);
    let root_after_alice = store.get_merkle_root();
    register(store, bob(), 'bob', 99);
    let root_after_bob = store.get_merkle_root();

    assert!(root_after_bob != root_after_alice, "roots differ");
    assert!(store.is_known_root(root_after_alice), "ring keeps old root");
    assert!(store.is_known_root(root_after_bob), "current root known");
    assert!(!store.is_known_root(0xdead), "foreign root unknown");

    let path_a = store.get_merkle_path(0);
    let path_b = store.get_merkle_path(1);
    assert!(verify_proof(root_after_bob, 42, 0, path_a.span()), "alice path");
    assert!(verify_proof(root_after_bob, 99, 1, path_b.span()), "bob path");
}

#[test]
#[should_panic(expected: 'handle taken')]
fn test_duplicate_handle_rejected() {
    let (store, _) = deploy();
    register(store, alice(), 'alice', 42);
    register(store, bob(), 'alice', 99);
}

#[test]
#[should_panic(expected: 'already registered')]
fn test_double_registration_rejected() {
    let (store, _) = deploy();
    register(store, alice(), 'alice', 42);
    register(store, alice(), 'alice2', 43);
}

#[test]
#[should_panic(expected: 'not registered')]
fn test_leaf_index_unregistered_panics() {
    let (store, _) = deploy();
    store.get_leaf_index(bob());
}

// --- the send path --------------------------------------------------------

#[test]
fn test_send_with_registered_fact_emits_and_counts() {
    let (store, mock) = deploy();
    register(store, alice(), 'alice', 42);
    let root = store.get_merkle_root();

    mock.set_valid(fact_for(0x111, 0x222, root));
    store.send_message(0x111, 0x222, root, "ciphertext-bytes");
    assert!(store.n_messages() == 1, "nonce bumped");
}

#[test]
#[should_panic(expected: 'no proof for this send')]
fn test_send_without_fact_rejected() {
    let (store, _) = deploy();
    register(store, alice(), 'alice', 42);
    let root = store.get_merkle_root();
    store.send_message(0x111, 0x222, root, "junk");
}

#[test]
#[should_panic(expected: 'no proof for this send')]
fn test_fact_binds_the_whole_tuple() {
    let (store, mock) = deploy();
    register(store, alice(), 'alice', 42);
    let root = store.get_merkle_root();
    // Fact registered for a DIFFERENT ephemeral pubkey — same commitment
    // and root must not pass.
    mock.set_valid(fact_for(0x111, 0x333, root));
    store.send_message(0x111, 0x222, root, "junk");
}

#[test]
#[should_panic(expected: 'unknown merkle root')]
fn test_send_with_foreign_root_rejected() {
    let (store, mock) = deploy();
    register(store, alice(), 'alice', 42);
    mock.set_valid(fact_for(0x111, 0x222, 0xdead));
    store.send_message(0x111, 0x222, 0xdead, "junk");
}

#[test]
#[should_panic(expected: 'commitment consumed')]
fn test_commitment_replay_rejected() {
    let (store, mock) = deploy();
    register(store, alice(), 'alice', 42);
    let root = store.get_merkle_root();
    mock.set_valid(fact_for(0x111, 0x222, root));
    store.send_message(0x111, 0x222, root, "first");
    // A third party replaying the world-readable tuple with junk content.
    start_cheat_caller_address(store.contract_address, bob());
    store.send_message(0x111, 0x222, root, "replayed junk");
}

#[test]
fn test_verification_route_pinned() {
    let (store, mock) = deploy();
    let (registry, program_hash, inner_root) = store.verification_route();
    assert!(registry == mock.contract_address, "registry pinned");
    assert!(program_hash == PROGRAM_HASH, "program hash pinned");
    let expected: [u32; 8] = INNER_ROOT;
    let mut i = 0;
    for w in expected.span() {
        assert!(*inner_root[i] == *w, "inner root word");
        i += 1;
    }
}
