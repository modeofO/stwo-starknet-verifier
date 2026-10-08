//! ZkmsgSendProverV4 as an ordinary call (in production it runs only inside
//! the virtual OS): membership as v3, plus the quota-bounded nullifier.

use snforge_std::{MessageToL1SpyTrait, spy_messages_to_l1};
use zkmsg_pool_v4::pool::content_hash;
use zkmsg_pool_v4::prover::{
    IZkmsgSendProverV4DispatcherTrait, LEAF_V3, MEMBER_V3, NULLIFIER_V4, leaf_v3, member_commit,
    nullifier_v4, send_payload_v4,
};
use crate::common::{EPOCH, QUOTA, deploy_prover};
use crate::vector::{
    ALICE_KEM_DIGEST, ALICE_LEAF, ALICE_MEMBER_SECRET, ALICE_M_COMMIT, ALICE_SCAN_PUB,
    BOB_MEMBER_SECRET, COMMITMENT, EPHEMERAL_PUBKEY, LEAF_DOMAIN, MEMBER_DOMAIN, ROOT, alice_path,
    content,
};

const STORE: felt252 = 0x5702e;

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

fn prove_alice(member_secret: felt252, slot: u32, quota: u32) {
    deploy_prover()
        .prove_send(
            STORE,
            content_hash(@content()),
            COMMITMENT,
            EPHEMERAL_PUBKEY,
            ROOT,
            EPOCH,
            quota,
            ALICE_SCAN_PUB,
            ALICE_KEM_DIGEST,
            member_secret,
            slot,
            0,
            alice_path().span(),
        );
}

#[test]
fn prover_emits_the_v4_payload() {
    let prover = deploy_prover();
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
            ALICE_SCAN_PUB,
            ALICE_KEM_DIGEST,
            ALICE_MEMBER_SECRET,
            2,
            0,
            alice_path().span(),
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
    );
    assert(message.payload == @expected, 'wrong payload');
    // Nothing in the payload is the member's leaf, index, keys or secret.
    for item in message.payload.span() {
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
