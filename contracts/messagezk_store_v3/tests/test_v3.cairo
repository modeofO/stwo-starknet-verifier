//! MessageStoreV3 + ZkmsgSendProverV3.
//!
//! The prover runs here as an ordinary contract call (in production it only
//! ever runs inside the virtual OS) so its L2->L1 message can be checked
//! against zkmsg-core's v3 vector. The store's proof check is driven with
//! `cheat_proof_facts`, building facts exactly as the virtual OS lays them out.

use snforge_std::{
    CheatSpan, ContractClassTrait, DeclareResultTrait, EventSpyTrait, MessageToL1SpyTrait,
    cheat_caller_address, cheat_proof_facts, declare, spy_events, spy_messages_to_l1,
};
use starknet::ContractAddress;
use messagezk_store_v3::prover::{
    IZkmsgSendProverV3Dispatcher, IZkmsgSendProverV3DispatcherTrait, LEAF_V3, MEMBER_V3, leaf_v3,
    member_commit, send_payload,
};
use messagezk_store_v3::store::{
    IMessageStoreV3Dispatcher, IMessageStoreV3DispatcherTrait, PROOF_VERSION_V1,
    VIRTUAL_OS_OUTPUT_VERSION, VIRTUAL_SNOS, content_hash, kem_digest, message_hash,
};
use crate::vector::{
    ALICE_KEM_DIGEST, ALICE_LEAF, ALICE_MEMBER_SECRET, ALICE_M_COMMIT, ALICE_SCAN_PUB,
    BOB_KEM_DIGEST, BOB_LEAF, BOB_MEMBER_SECRET, BOB_M_COMMIT, BOB_SCAN_PUB, COMMITMENT,
    CONTENT_HASH, EPHEMERAL_PUBKEY, LEAF_DOMAIN, MEMBER_DOMAIN, ROOT, alice_kem_pubkey, alice_path,
    bob_kem_pubkey, content,
};

const PROVER: felt252 = 0x9407e2;
const ALICE: felt252 = 0xa11ce;
const BOB: felt252 = 0xb0b;

fn addr(value: felt252) -> ContractAddress {
    value.try_into().unwrap()
}

fn deploy_prover() -> IZkmsgSendProverV3Dispatcher {
    let class = declare("ZkmsgSendProverV3").unwrap().contract_class();
    let (address, _) = class.deploy(@array![]).unwrap();
    IZkmsgSendProverV3Dispatcher { contract_address: address }
}

fn deploy_empty_store(prover: ContractAddress) -> IMessageStoreV3Dispatcher {
    let class = declare("MessageStoreV3").unwrap().contract_class();
    let (address, _) = class.deploy(@array![prover.into()]).unwrap();
    IMessageStoreV3Dispatcher { contract_address: address }
}

fn register_as(
    store: IMessageStoreV3Dispatcher,
    caller: felt252,
    handle: felt252,
    scan_pubkey: felt252,
    kem_pubkey: ByteArray,
    m_commit: felt252,
) {
    cheat_caller_address(store.contract_address, addr(caller), CheatSpan::TargetCalls(1));
    store.register(handle, scan_pubkey, kem_pubkey, m_commit);
}

/// A store pinned to `prover` with alice (leaf 0) and bob (leaf 1), so its
/// root is the vector's root.
fn deploy_store(prover: ContractAddress) -> IMessageStoreV3Dispatcher {
    let store = deploy_empty_store(prover);
    register_as(store, ALICE, 'alice', ALICE_SCAN_PUB, alice_kem_pubkey(), ALICE_M_COMMIT);
    register_as(store, BOB, 'bob', BOB_SCAN_PUB, bob_kem_pubkey(), BOB_M_COMMIT);
    store
}

/// Proof facts as the virtual OS lays them out, carrying one message hash.
fn facts_with(message: felt252) -> Array<felt252> {
    array![
        PROOF_VERSION_V1, VIRTUAL_SNOS, 0x53f6c9, VIRTUAL_OS_OUTPUT_VERSION, 15850106, 0xb10c,
        0xc0f, 1, message,
    ]
}

/// The facts a genuine proof of the vector's send to `store` would carry.
fn genuine_facts(
    prover: ContractAddress, store: ContractAddress, content: @ByteArray,
) -> Array<felt252> {
    let payload = send_payload(
        store.into(), COMMITMENT, EPHEMERAL_PUBKEY, ROOT, content_hash(content),
    );
    facts_with(message_hash(prover.into(), 0, payload.span()))
}

fn send(store: IMessageStoreV3Dispatcher, facts: Array<felt252>, content: ByteArray) {
    cheat_proof_facts(store.contract_address, facts.span(), CheatSpan::TargetCalls(1));
    store.send_message(COMMITMENT, EPHEMERAL_PUBKEY, ROOT, content);
}

fn bytes(n: u32) -> ByteArray {
    let mut b: ByteArray = Default::default();
    for _ in 0..n {
        b.append_byte(0x5a);
    }
    b
}

// --- vectors -----------------------------------------------------------------

#[test]
fn leaf_vector() {
    assert_eq!(MEMBER_V3, MEMBER_DOMAIN);
    assert_eq!(LEAF_V3, LEAF_DOMAIN);
    assert_eq!(kem_digest(@alice_kem_pubkey()), ALICE_KEM_DIGEST);
    assert_eq!(kem_digest(@bob_kem_pubkey()), BOB_KEM_DIGEST);
    assert_eq!(member_commit(ALICE_MEMBER_SECRET), ALICE_M_COMMIT);
    assert_eq!(member_commit(BOB_MEMBER_SECRET), BOB_M_COMMIT);
    assert_eq!(leaf_v3(ALICE_SCAN_PUB, ALICE_KEM_DIGEST, ALICE_M_COMMIT), ALICE_LEAF);
    assert_eq!(leaf_v3(BOB_SCAN_PUB, BOB_KEM_DIGEST, BOB_M_COMMIT), BOB_LEAF);
}

#[test]
fn content_hash_vector() {
    assert_eq!(content_hash(@content()), CONTENT_HASH);
}

// --- registration --------------------------------------------------------------

#[test]
fn registration_reproduces_the_client_tree() {
    let store = deploy_store(addr(PROVER));
    assert_eq!(store.get_merkle_root(), ROOT);
    let (owner, scan_pubkey, digest, m_commit, leaf_index) = store.get_user('alice');
    assert(owner == addr(ALICE), 'wrong owner');
    assert_eq!(scan_pubkey, ALICE_SCAN_PUB);
    assert_eq!(digest, ALICE_KEM_DIGEST);
    assert_eq!(m_commit, ALICE_M_COMMIT);
    assert_eq!(leaf_index, 0);
    let (_, _, bob_digest, bob_commit, bob_index) = store.get_user('bob');
    assert_eq!(bob_digest, BOB_KEM_DIGEST);
    assert_eq!(bob_commit, BOB_M_COMMIT);
    assert_eq!(bob_index, 1);
    assert_eq!(store.get_m_commit(addr(BOB)), BOB_M_COMMIT);
    assert_eq!(store.get_kem_digest(addr(BOB)), BOB_KEM_DIGEST);
    assert_eq!(store.get_merkle_path(0), alice_path());
}

/// Event layout the clients parse: keys [selector, owner]; data
/// [handle, scan_pubkey, leaf_index, m_commit, kem_pubkey ByteArray...].
#[test]
fn register_event_shape() {
    let store = deploy_empty_store(addr(PROVER));
    let mut spy = spy_events();
    register_as(store, ALICE, 'alice', ALICE_SCAN_PUB, alice_kem_pubkey(), ALICE_M_COMMIT);
    let events = spy.get_events().events;
    assert_eq!(events.len(), 1);
    let (from, event) = events.at(0);
    assert(*from == store.contract_address, 'wrong emitter');
    assert_eq!(event.keys.len(), 2);
    assert_eq!(*event.keys.at(0), selector!("UserRegistered"));
    assert_eq!(*event.keys.at(1), ALICE);

    let mut expected: Array<felt252> = array!['alice', ALICE_SCAN_PUB, 0, ALICE_M_COMMIT];
    alice_kem_pubkey().serialize(ref expected);
    assert(event.data == @expected, 'wrong event data');
    // 38 full words + pending word + pending len + word count.
    assert_eq!(event.data.len(), 4 + 41);
}

#[test]
#[should_panic(expected: ('kem pubkey must be 1184 bytes',))]
fn register_rejects_a_short_kem_pubkey() {
    let store = deploy_empty_store(addr(PROVER));
    register_as(store, ALICE, 'alice', ALICE_SCAN_PUB, bytes(1183), ALICE_M_COMMIT);
}

#[test]
#[should_panic(expected: ('kem pubkey must be 1184 bytes',))]
fn register_rejects_a_long_kem_pubkey() {
    let store = deploy_empty_store(addr(PROVER));
    register_as(store, ALICE, 'alice', ALICE_SCAN_PUB, bytes(1185), ALICE_M_COMMIT);
}

#[test]
#[should_panic(expected: ('handle taken',))]
fn register_rejects_a_taken_handle() {
    let store = deploy_store(addr(PROVER));
    register_as(store, 0xc4201, 'alice', BOB_SCAN_PUB, bob_kem_pubkey(), BOB_M_COMMIT);
}

#[test]
#[should_panic(expected: ('already registered',))]
fn register_rejects_a_second_registration() {
    let store = deploy_store(addr(PROVER));
    register_as(store, ALICE, 'alice2', ALICE_SCAN_PUB, alice_kem_pubkey(), ALICE_M_COMMIT);
}

// --- prover ------------------------------------------------------------------

#[test]
fn prover_emits_the_payload() {
    let prover = deploy_prover();
    let store: felt252 = 0x5702e;
    let mut spy = spy_messages_to_l1();
    prover
        .prove_send(
            store, CONTENT_HASH, COMMITMENT, EPHEMERAL_PUBKEY, ROOT, ALICE_SCAN_PUB,
            ALICE_KEM_DIGEST, ALICE_MEMBER_SECRET, 0, alice_path().span(),
        );
    let messages = spy.get_messages().messages;
    assert_eq!(messages.len(), 1);
    let (from, message) = messages.at(0);
    assert(*from == prover.contract_address, 'wrong sender');
    let to: felt252 = (*message.to_address).into();
    assert_eq!(to, 0);
    assert(
        message.payload == @send_payload(store, COMMITMENT, EPHEMERAL_PUBKEY, ROOT, CONTENT_HASH),
        'wrong payload',
    );
}

/// The public scan key and KEM digest are not enough: without m there is no
/// membership. This is the v3 point — v2 failed here only on the scan key.
#[test]
#[should_panic(expected: ('sender not a member',))]
fn prover_rejects_a_wrong_member_secret() {
    let prover = deploy_prover();
    prover
        .prove_send(
            0x5702e, CONTENT_HASH, COMMITMENT, EPHEMERAL_PUBKEY, ROOT, ALICE_SCAN_PUB,
            ALICE_KEM_DIGEST, ALICE_MEMBER_SECRET + 1, 0, alice_path().span(),
        );
}

/// Another member's secret does not open this member's leaf.
#[test]
#[should_panic(expected: ('sender not a member',))]
fn prover_rejects_another_members_secret() {
    let prover = deploy_prover();
    prover
        .prove_send(
            0x5702e, CONTENT_HASH, COMMITMENT, EPHEMERAL_PUBKEY, ROOT, ALICE_SCAN_PUB,
            ALICE_KEM_DIGEST, BOB_MEMBER_SECRET, 0, alice_path().span(),
        );
}

#[test]
#[should_panic(expected: ('sender not a member',))]
fn prover_rejects_a_wrong_scan_pubkey() {
    let prover = deploy_prover();
    prover
        .prove_send(
            0x5702e, CONTENT_HASH, COMMITMENT, EPHEMERAL_PUBKEY, ROOT, BOB_SCAN_PUB,
            ALICE_KEM_DIGEST, ALICE_MEMBER_SECRET, 0, alice_path().span(),
        );
}

#[test]
#[should_panic(expected: ('sender not a member',))]
fn prover_rejects_a_wrong_kem_digest() {
    let prover = deploy_prover();
    prover
        .prove_send(
            0x5702e, CONTENT_HASH, COMMITMENT, EPHEMERAL_PUBKEY, ROOT, ALICE_SCAN_PUB,
            BOB_KEM_DIGEST, ALICE_MEMBER_SECRET, 0, alice_path().span(),
        );
}

#[test]
#[should_panic(expected: ('zero m_commit',))]
fn register_rejects_a_zero_m_commit() {
    let store = deploy_empty_store(addr(PROVER));
    register_as(store, ALICE, 'alice', ALICE_SCAN_PUB, alice_kem_pubkey(), 0);
}

// --- send --------------------------------------------------------------------

#[test]
fn proven_send_publishes_once() {
    let prover = addr(PROVER);
    let store = deploy_store(prover);
    send(store, genuine_facts(prover, store.contract_address, @content()), content());
    assert_eq!(store.n_messages(), 1);
}

#[test]
#[should_panic(expected: ('commitment consumed',))]
fn replay_is_rejected() {
    let prover = addr(PROVER);
    let store = deploy_store(prover);
    send(store, genuine_facts(prover, store.contract_address, @content()), content());
    send(store, genuine_facts(prover, store.contract_address, @content()), content());
}

#[test]
#[should_panic(expected: ('expected one proven message',))]
fn unproven_send_is_rejected() {
    let store = deploy_store(addr(PROVER));
    store.send_message(COMMITMENT, EPHEMERAL_PUBKEY, ROOT, content());
}

#[test]
#[should_panic(expected: ('no proof for this send',))]
fn proof_for_other_content_is_rejected() {
    let prover = addr(PROVER);
    let store = deploy_store(prover);
    let mut other = content();
    other.append_byte(0);
    send(store, genuine_facts(prover, store.contract_address, @content()), other);
}

#[test]
#[should_panic(expected: ('no proof for this send',))]
fn proof_from_another_prover_is_rejected() {
    let store = deploy_store(addr(PROVER));
    send(store, genuine_facts(addr(0xbad), store.contract_address, @content()), content());
}

#[test]
#[should_panic(expected: ('no proof for this send',))]
fn proof_for_another_store_is_rejected() {
    let prover = addr(PROVER);
    let store = deploy_store(prover);
    send(store, genuine_facts(prover, addr(0x07e12), @content()), content());
}

#[test]
#[should_panic(expected: ('content too short',))]
fn short_content_is_rejected() {
    let prover = addr(PROVER);
    let store = deploy_store(prover);
    let short = bytes(1088 + 12 + 15);
    send(store, genuine_facts(prover, store.contract_address, @short), short);
}

#[test]
#[should_panic(expected: ('unknown merkle root',))]
fn unknown_root_is_rejected() {
    let prover = addr(PROVER);
    let store = deploy_store(prover);
    cheat_proof_facts(
        store.contract_address,
        genuine_facts(prover, store.contract_address, @content()).span(),
        CheatSpan::TargetCalls(1),
    );
    store.send_message(COMMITMENT, EPHEMERAL_PUBKEY, ROOT + 1, content());
}

#[test]
#[should_panic(expected: ('not a virtual OS proof',))]
fn foreign_proof_variant_is_rejected() {
    let prover = addr(PROVER);
    let store = deploy_store(prover);
    let mut facts = genuine_facts(prover, store.contract_address, @content());
    let mut forged = array![*facts.at(0), 'OTHER'];
    for i in 2..facts.len() {
        forged.append(*facts.at(i));
    }
    send(store, forged, content());
}

/// The root after alice and bob stays sendable through 63 more
/// registrations (64-root history) and goes stale at the 64th.
#[test]
fn root_history_window() {
    let prover = addr(PROVER);
    let store = deploy_store(prover);
    let mut i: felt252 = 0;
    while i != 63 {
        register_as(store, 0x1000 + i, 0x2000 + i, BOB_SCAN_PUB, bob_kem_pubkey(), BOB_M_COMMIT);
        i += 1;
    }
    assert(store.is_known_root(ROOT), 'root dropped early');
    register_as(store, 0x1000 + 63, 0x2000 + 63, BOB_SCAN_PUB, bob_kem_pubkey(), BOB_M_COMMIT);
    assert(!store.is_known_root(ROOT), 'root kept too long');
}
