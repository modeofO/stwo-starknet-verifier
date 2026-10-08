//! ZkmsgSendProverV4 as an ordinary call (in production it runs only inside
//! the virtual OS): membership as v3, plus the quota-bounded nullifier.

use snforge_std::{MessageToL1SpyTrait, spy_messages_to_l1};
use zkmsg_pool_v4::merkle::{TREE_DEPTH, hash_pair, zero_hash};
use zkmsg_pool_v4::pool::content_hash;
use zkmsg_pool_v4::prover::{
    IZkmsgSendProverV4DispatcherTrait, LEAF_V3, MEMBER_V3, NULLIFIER_V4, TICKET_NULL_V4, TICKET_V4,
    leaf_v3, member_commit, nullifier_v4, send_payload_v4, ticket_leaf, ticket_nullifier,
};
use crate::common::{EPOCH, QUOTA, content, deploy_prover};
use crate::vector::{
    ALICE_KEM_DIGEST, ALICE_LEAF, ALICE_MEMBER_SECRET, ALICE_M_COMMIT, ALICE_SCAN_PUB,
    BOB_MEMBER_SECRET, COMMITMENT, EPHEMERAL_PUBKEY, LEAF_DOMAIN, MEMBER_DOMAIN, ROOT, alice_path,
};

const STORE: felt252 = 0x5702e;
const TICKET: felt252 = 0x7111c37;

/// A ticket tree holding one leaf (index 0): its root and the path.
fn one_ticket_tree(secret: felt252) -> (felt252, Array<felt252>) {
    let mut path = array![];
    let mut node = ticket_leaf(secret);
    for level in 0..TREE_DEPTH {
        let sibling = zero_hash(level);
        path.append(sibling);
        node = hash_pair(node, sibling);
    }
    (node, path)
}

#[test]
fn ticket_preimages() {
    assert_eq!(TICKET_V4, 'zkmsg-ticket-v4');
    assert_eq!(TICKET_NULL_V4, 'zkmsg-ticket-null-v4');
    assert_eq!(
        ticket_leaf(TICKET), core::poseidon::poseidon_hash_span(array![TICKET_V4, TICKET].span()),
    );
    assert_eq!(
        ticket_nullifier(STORE, TICKET),
        core::poseidon::poseidon_hash_span(array![TICKET_NULL_V4, STORE, TICKET].span()),
    );
    // The spend tag is not the leaf: spending names no leaf.
    assert_ne!(ticket_nullifier(STORE, TICKET), ticket_leaf(TICKET));
}

#[test]
fn v3_leaf_is_unchanged() {
    assert_eq!(MEMBER_V3, MEMBER_DOMAIN);
    assert_eq!(LEAF_V3, LEAF_DOMAIN);
    assert_eq!(member_commit(ALICE_MEMBER_SECRET), ALICE_M_COMMIT);
    assert_eq!(leaf_v3(ALICE_SCAN_PUB, ALICE_KEM_DIGEST, ALICE_M_COMMIT), ALICE_LEAF);
}

#[test]
fn nullifier_preimage() {
    assert_eq!(NULLIFIER_V4, 'zkmsg-nullifier-v4');
    assert_eq!(
        nullifier_v4(STORE, ALICE_MEMBER_SECRET, EPOCH, 1),
        core::poseidon::poseidon_hash_span(
            array![NULLIFIER_V4, STORE, ALICE_MEMBER_SECRET, EPOCH.into(), 1].span(),
        ),
    );
}

/// Same (member, store, epoch, slot) -> same nullifier: that determinism IS
/// the rate limit. Any one component changed -> a different nullifier.
#[test]
fn nullifier_separates_slots_epochs_stores_and_members() {
    let n = nullifier_v4(STORE, ALICE_MEMBER_SECRET, EPOCH, 0);
    assert_eq!(n, nullifier_v4(STORE, ALICE_MEMBER_SECRET, EPOCH, 0));
    assert_ne!(n, nullifier_v4(STORE, ALICE_MEMBER_SECRET, EPOCH, 1));
    assert_ne!(n, nullifier_v4(STORE, ALICE_MEMBER_SECRET, EPOCH + 1, 0));
    assert_ne!(n, nullifier_v4(STORE + 1, ALICE_MEMBER_SECRET, EPOCH, 0));
    assert_ne!(n, nullifier_v4(STORE, BOB_MEMBER_SECRET, EPOCH, 0));
}

fn prove_alice_with(member_secret: felt252, slot: u32, quota: u32, ticket_secret: felt252) {
    let (ticket_root, ticket_path) = one_ticket_tree(TICKET);
    deploy_prover()
        .prove_send(
            STORE,
            content_hash(@content()),
            COMMITMENT,
            EPHEMERAL_PUBKEY,
            ROOT,
            EPOCH,
            quota,
            ticket_root,
            ALICE_SCAN_PUB,
            ALICE_KEM_DIGEST,
            member_secret,
            slot,
            0,
            alice_path().span(),
            ticket_secret,
            0,
            ticket_path.span(),
        );
}

fn prove_alice(member_secret: felt252, slot: u32, quota: u32) {
    prove_alice_with(member_secret, slot, quota, TICKET);
}

#[test]
#[should_panic(expected: ('no such ticket',))]
fn prover_rejects_a_wrong_ticket_secret() {
    prove_alice_with(ALICE_MEMBER_SECRET, 0, QUOTA, TICKET + 1);
}

#[test]
fn prover_emits_the_v4_payload() {
    let prover = deploy_prover();
    let (ticket_root, ticket_path) = one_ticket_tree(TICKET);
    let mut spy = spy_messages_to_l1();
    prover
        .prove_send(
            STORE,
            content_hash(@content()),
            COMMITMENT,
            EPHEMERAL_PUBKEY,
            ROOT,
            EPOCH,
            QUOTA,
            ticket_root,
            ALICE_SCAN_PUB,
            ALICE_KEM_DIGEST,
            ALICE_MEMBER_SECRET,
            2,
            0,
            alice_path().span(),
            TICKET,
            0,
            ticket_path.span(),
        );
    let messages = spy.get_messages().messages;
    assert_eq!(messages.len(), 1);
    let (from, message) = messages.at(0);
    assert(*from == prover.contract_address, 'wrong sender');
    let to: felt252 = (*message.to_address).into();
    assert_eq!(to, 0);
    let expected = send_payload_v4(
        STORE,
        COMMITMENT,
        EPHEMERAL_PUBKEY,
        ROOT,
        content_hash(@content()),
        nullifier_v4(STORE, ALICE_MEMBER_SECRET, EPOCH, 2),
        EPOCH,
        QUOTA,
        ticket_root,
        ticket_nullifier(STORE, TICKET),
    );
    assert(message.payload == @expected, 'wrong payload');
    // Nothing in the payload is the member's leaf, index, keys or secret,
    // nor the ticket's secret or leaf.
    for item in message.payload.span() {
        assert(*item != TICKET && *item != ticket_leaf(TICKET), 'leaks the ticket');
        assert(*item != ALICE_MEMBER_SECRET && *item != ALICE_M_COMMIT, 'leaks m');
        assert(*item != ALICE_SCAN_PUB && *item != ALICE_LEAF, 'leaks identity');
    }
}

#[test]
#[should_panic(expected: ('slot over quota',))]
fn prover_rejects_a_slot_at_the_quota() {
    prove_alice(ALICE_MEMBER_SECRET, QUOTA, QUOTA);
}

#[test]
fn prover_accepts_the_last_slot() {
    prove_alice(ALICE_MEMBER_SECRET, QUOTA - 1, QUOTA);
}

#[test]
#[should_panic(expected: ('sender not a member',))]
fn prover_rejects_a_wrong_member_secret() {
    prove_alice(ALICE_MEMBER_SECRET + 1, 0, QUOTA);
}

#[test]
#[should_panic(expected: ('sender not a member',))]
fn prover_rejects_another_members_secret() {
    prove_alice(BOB_MEMBER_SECRET, 0, QUOTA);
}
