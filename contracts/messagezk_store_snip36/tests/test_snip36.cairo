//! MessageStoreSnip36 + ZkmsgSendProver.
//!
//! The prover runs here as an ordinary contract call (in production it only
//! ever runs inside the virtual OS) so its L2->L1 message can be checked
//! against zkmsg-core's vector. The store's proof check is driven with
//! `cheat_proof_facts`, building facts exactly as the virtual OS lays them out.

use core::ec::{EcPointTrait, EcStateTrait, stark_curve};
use snforge_std::{
    CheatSpan, ContractClassTrait, DeclareResultTrait, MessageToL1SpyTrait, cheat_caller_address,
    cheat_proof_facts, declare, spy_messages_to_l1,
};
use starknet::ContractAddress;
use messagezk_store_snip36::prover::{
    IZkmsgSendProverDispatcher, IZkmsgSendProverDispatcherTrait, send_payload,
};
use messagezk_store_snip36::store::{
    IMessageStoreSnip36Dispatcher, IMessageStoreSnip36DispatcherTrait, PROOF_VERSION_V1,
    VIRTUAL_OS_OUTPUT_VERSION, VIRTUAL_SNOS, content_hash, message_hash,
};
use crate::vector::{
    COMMITMENT, EPHEMERAL_PRIV, EPHEMERAL_PUBKEY, PHONE_CONTENT_HASH, PHONE_MESSAGE_HASH,
    PHONE_PROVER, PHONE_STORE, RECIPIENT_LEAF_INDEX, RECIPIENT_SCAN_PUB, ROOT, SENDER_LEAF_INDEX,
    SENDER_SCAN_PRIV, recipient_path, sender_path,
};

/// x(SENDER_SCAN_PRIV · G), the sender's leaf.
fn sender_scan_pub() -> felt252 {
    let gen = EcPointTrait::new_nz(stark_curve::GEN_X, stark_curve::GEN_Y).unwrap();
    let mut state = EcStateTrait::init();
    state.add_mul(SENDER_SCAN_PRIV, gen);
    let (x, _) = state.finalize_nz().unwrap().coordinates();
    x
}

fn addr(value: felt252) -> ContractAddress {
    value.try_into().unwrap()
}

fn deploy_prover() -> IZkmsgSendProverDispatcher {
    let class = declare("ZkmsgSendProver").unwrap().contract_class();
    let (address, _) = class.deploy(@array![]).unwrap();
    IZkmsgSendProverDispatcher { contract_address: address }
}

/// A store pinned to `prover`, with the vector's two members registered in
/// leaf order so its root is the vector's root.
fn deploy_store(prover: ContractAddress) -> IMessageStoreSnip36Dispatcher {
    let class = declare("MessageStoreSnip36").unwrap().contract_class();
    let (address, _) = class.deploy(@array![prover.into()]).unwrap();
    let store = IMessageStoreSnip36Dispatcher { contract_address: address };
    cheat_caller_address(address, addr(0xa11ce), CheatSpan::TargetCalls(1));
    store.register('sender', sender_scan_pub());
    cheat_caller_address(address, addr(0xb0b), CheatSpan::TargetCalls(1));
    store.register('recipient', RECIPIENT_SCAN_PUB);
    store
}

/// Proof facts as the virtual OS lays them out, carrying one message hash.
fn facts_with(message: felt252) -> Array<felt252> {
    array![
        PROOF_VERSION_V1, VIRTUAL_SNOS, 0x53f6c9, VIRTUAL_OS_OUTPUT_VERSION, 15850106, 0xb10c,
        0xc0f, 1, message,
    ]
}

fn content() -> ByteArray {
    "sealed envelope bytes"
}

/// The facts a genuine proof of this vector's send to `store` would carry.
fn genuine_facts(prover: ContractAddress, store: ContractAddress, content: @ByteArray) -> Array<felt252> {
    let payload = send_payload(
        store.into(), COMMITMENT, EPHEMERAL_PUBKEY, ROOT, content_hash(content),
    );
    facts_with(message_hash(prover.into(), 0, payload.span()))
}

fn send(store: IMessageStoreSnip36Dispatcher, facts: Array<felt252>, content: ByteArray) {
    cheat_proof_facts(store.contract_address, facts.span(), CheatSpan::TargetCalls(1));
    store.send_message(COMMITMENT, EPHEMERAL_PUBKEY, ROOT, content);
}

#[test]
fn message_hash_matches_the_phone_proof() {
    let payload = send_payload(PHONE_STORE, COMMITMENT, EPHEMERAL_PUBKEY, ROOT, PHONE_CONTENT_HASH);
    assert_eq!(message_hash(PHONE_PROVER, 0, payload.span()), PHONE_MESSAGE_HASH);
}

#[test]
fn prover_emits_the_vector_tuple() {
    let prover = deploy_prover();
    let mut spy = spy_messages_to_l1();
    prover
        .prove_send(
            PHONE_STORE, PHONE_CONTENT_HASH, ROOT, SENDER_SCAN_PRIV, RECIPIENT_SCAN_PUB,
            EPHEMERAL_PRIV, SENDER_LEAF_INDEX, RECIPIENT_LEAF_INDEX, sender_path().span(),
            recipient_path().span(),
        );
    let messages = spy.get_messages().messages;
    assert_eq!(messages.len(), 1);
    let (from, message) = messages.at(0);
    assert(*from == prover.contract_address, 'wrong sender');
    let to: felt252 = (*message.to_address).into();
    assert_eq!(to, 0);
    assert(
        message.payload == @send_payload(
            PHONE_STORE, COMMITMENT, EPHEMERAL_PUBKEY, ROOT, PHONE_CONTENT_HASH,
        ),
        'wrong payload',
    );
}

#[test]
#[should_panic(expected: ('sender not a member',))]
fn prover_rejects_a_non_member_sender() {
    let prover = deploy_prover();
    prover
        .prove_send(
            PHONE_STORE, PHONE_CONTENT_HASH, ROOT, SENDER_SCAN_PRIV + 1, RECIPIENT_SCAN_PUB,
            EPHEMERAL_PRIV, SENDER_LEAF_INDEX, RECIPIENT_LEAF_INDEX, sender_path().span(),
            recipient_path().span(),
        );
}

#[test]
fn registration_reproduces_the_client_tree() {
    let store = deploy_store(addr(0x9407e2));
    assert_eq!(store.get_merkle_root(), ROOT);
}

#[test]
fn proven_send_publishes_once() {
    let prover = addr(0x9407e2);
    let store = deploy_store(prover);
    send(store, genuine_facts(prover, store.contract_address, @content()), content());
    assert_eq!(store.n_messages(), 1);
}

#[test]
#[should_panic(expected: ('commitment consumed',))]
fn replay_is_rejected() {
    let prover = addr(0x9407e2);
    let store = deploy_store(prover);
    send(store, genuine_facts(prover, store.contract_address, @content()), content());
    send(store, genuine_facts(prover, store.contract_address, @content()), content());
}

#[test]
#[should_panic(expected: ('expected one proven message',))]
fn unproven_send_is_rejected() {
    let store = deploy_store(addr(0x9407e2));
    store.send_message(COMMITMENT, EPHEMERAL_PUBKEY, ROOT, content());
}

#[test]
#[should_panic(expected: ('no proof for this send',))]
fn proof_for_other_content_is_rejected() {
    let prover = addr(0x9407e2);
    let store = deploy_store(prover);
    send(store, genuine_facts(prover, store.contract_address, @content()), "swapped ciphertext");
}

#[test]
#[should_panic(expected: ('no proof for this send',))]
fn proof_from_another_prover_is_rejected() {
    let store = deploy_store(addr(0x9407e2));
    send(store, genuine_facts(addr(0xbad), store.contract_address, @content()), content());
}

#[test]
#[should_panic(expected: ('no proof for this send',))]
fn proof_for_another_store_is_rejected() {
    let prover = addr(0x9407e2);
    let store = deploy_store(prover);
    send(store, genuine_facts(prover, addr(0x07e12), @content()), content());
}

#[test]
#[should_panic(expected: ('unknown merkle root',))]
fn unknown_root_is_rejected() {
    let prover = addr(0x9407e2);
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
    let prover = addr(0x9407e2);
    let store = deploy_store(prover);
    let mut facts = genuine_facts(prover, store.contract_address, @content());
    let mut forged = array![*facts.at(0), 'OTHER'];
    for i in 2..facts.len() {
        forged.append(*facts.at(i));
    }
    send(store, forged, content());
}

/// Pinned so the phone's Swift `Snip36.contentHash` can be checked against
/// the contract's own serialization (a 31-byte word, a pending word, length).
#[test]
fn content_hash_vector() {
    let content: ByteArray = "zkmsg: a ciphertext longer than one felt word";
    assert_eq!(content_hash(@content), 0x4ec73c48431f40fa835370b13e57e100fa367be4150d655c88438a91c6bc954);
}
