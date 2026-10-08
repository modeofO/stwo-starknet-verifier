//! ZkmsgPoolV4 as an account: `__validate__` admits exactly the sends whose
//! `__execute__` will succeed, and refuses everything else (where the
//! sequencer charges nothing).
//!
//! The proofs are stood in for by running the real prover as a call and
//! putting its exact message hash into `cheat_proof_facts`. What snforge
//! does NOT model: validate-mode syscall restrictions (call_contract to
//! others, block-number rounding — the pool rounds explicitly), the
//! gateway's proof verification, fees actually charged, nonces.

use snforge_std::{
    EventSpyTrait, spy_events, start_cheat_block_number_global, start_cheat_signature_global,
    start_cheat_tip_global, stop_cheat_proof_facts_global,
};
use starknet::VALIDATED;
use starknet::account::Call;
use zkmsg_pool_v4::pool::{
    IPoolAccountDispatcher, IPoolAccountDispatcherTrait, IZkmsgPoolV4Dispatcher,
    IZkmsgPoolV4DispatcherTrait, content_hash,
};
use zkmsg_pool_v4::prover::IZkmsgSendProverV4Dispatcher;
use crate::common::{
    ALICE, BASE_BLOCK, C1, C2, C3, C4, EPOCH, EPOCH_BLOCKS, NOW, QUOTA, Send, addr, alice_send,
    as_protocol, bytes, deploy_pool_with, deploy_prover, facts, prove, register_as, send_calls,
    tx_env,
};
use crate::vector::{
    ALICE_KEM_DIGEST, ALICE_M_COMMIT, ALICE_SCAN_PUB, EPHEMERAL_PUBKEY, ROOT, alice_kem_pubkey,
    content,
};

#[derive(Drop, Copy)]
struct Fixture {
    prover: IZkmsgSendProverV4Dispatcher,
    pool: IZkmsgPoolV4Dispatcher,
    account: IPoolAccountDispatcher,
}

fn setup() -> Fixture {
    let prover = deploy_prover();
    let (pool, account) = deploy_pool_with(prover.contract_address, QUOTA);
    Fixture { prover, pool, account }
}

/// Proves `send`, sets up its publish transaction at base block `base`, and
/// returns (calls, nullifier).
fn prepare_at(f: Fixture, send: @Send, base: u64) -> (Array<Call>, felt252) {
    let (nullifier, message) = prove(f.prover, f.pool.contract_address, send);
    tx_env(facts(base, message).span());
    (send_calls(f.pool.contract_address, send, nullifier), nullifier)
}

fn prepare(f: Fixture, send: @Send) -> (Array<Call>, felt252) {
    prepare_at(f, send, BASE_BLOCK)
}

fn validate(f: Fixture, calls: Array<Call>) -> felt252 {
    as_protocol(f.account.contract_address);
    f.account.__validate__(calls)
}

fn execute(f: Fixture, calls: Array<Call>) {
    as_protocol(f.account.contract_address);
    f.account.__execute__(calls);
}

/// The full publish: validate then execute, as the sequencer runs them.
fn publish(f: Fixture, send: @Send) -> felt252 {
    let (calls, nullifier) = prepare(f, send);
    assert_eq!(validate(f, calls.clone()), VALIDATED);
    execute(f, calls);
    nullifier
}

// --- the happy path ----------------------------------------------------------

#[test]
fn validate_then_execute_publishes() {
    let f = setup();
    let send = alice_send(C1, 0);
    let (calls, nullifier) = prepare(f, @send);
    assert!(!f.pool.is_nullifier_spent(nullifier));
    assert_eq!(validate(f, calls.clone()), VALIDATED);
    // Validate writes nothing.
    assert!(!f.pool.is_nullifier_spent(nullifier));
    assert_eq!(f.pool.n_messages(), 0);

    let mut spy = spy_events();
    execute(f, calls);
    assert_eq!(f.pool.n_messages(), 1);
    assert!(f.pool.is_nullifier_spent(nullifier));
    assert!(f.pool.is_commitment_consumed(C1));
    let events = spy.get_events().events;
    assert_eq!(events.len(), 1);
    let (from, event) = events.at(0);
    assert(*from == f.pool.contract_address, 'wrong emitter');
    assert_eq!(*event.keys.at(0), selector!("MessageSent"));
    assert_eq!(*event.keys.at(1), C1);
}

/// The client can pre-flight with the public view, same rules.
#[test]
fn check_send_matches_validate() {
    let f = setup();
    let send = alice_send(C1, 0);
    let (_, nullifier) = prepare(f, @send);
    f.pool.check_send(C1, EPHEMERAL_PUBKEY, ROOT, nullifier, content_hash(@content()));
}

// --- quota: k-per-epoch via the nullifier ------------------------------------

#[test]
fn quota_slots_each_publish_once() {
    let f = setup();
    publish(f, @alice_send(C1, 0));
    publish(f, @alice_send(C2, 1));
    publish(f, @alice_send(C3, 2));
    assert_eq!(f.pool.n_messages(), 3);
}

/// Re-using a slot in the same epoch (new commitment, same nullifier) is
/// refused in VALIDATE: rejected, not charged.
#[test]
#[should_panic(expected: ('nullifier spent',))]
fn a_reused_slot_is_rejected_in_validate() {
    let f = setup();
    publish(f, @alice_send(C1, 0));
    let (calls, _) = prepare(f, @alice_send(C2, 0));
    validate(f, calls);
}

/// The fourth send of an epoch has no slot: the prover itself refuses
/// (slot 3 with quota 3), so no proof exists to publish.
#[test]
#[should_panic(expected: ('slot over quota',))]
fn a_fourth_send_cannot_be_proven() {
    let f = setup();
    publish(f, @alice_send(C1, 0));
    publish(f, @alice_send(C2, 1));
    publish(f, @alice_send(C3, 2));
    publish(f, @alice_send(C4, 3));
}

/// Claiming a larger quota than the store's: the proof exists (the prover
/// takes quota as public input) but its message hash cannot match.
#[test]
#[should_panic(expected: ('no proof for this send',))]
fn a_proof_with_an_inflated_quota_is_rejected() {
    let f = setup();
    let mut send = alice_send(C4, 7);
    send.quota = 100;
    let (calls, _) = prepare(f, @send);
    validate(f, calls);
}

/// A new epoch gives fresh slots.
#[test]
fn the_next_epoch_refills_the_quota() {
    let f = setup();
    publish(f, @alice_send(C1, 0));
    let mut next = alice_send(C2, 0);
    next.epoch = EPOCH + 1;
    let base = (EPOCH + 1) * EPOCH_BLOCKS + 5;
    let (calls, _) = prepare_at(f, @next, base);
    start_cheat_block_number_global(base + 20);
    assert_eq!(validate(f, calls.clone()), VALIDATED);
    execute(f, calls);
    assert_eq!(f.pool.n_messages(), 2);
}

/// The epoch is the store's, derived from the facts' base block: a proof
/// that claims another epoch for its base block does not match.
#[test]
#[should_panic(expected: ('no proof for this send',))]
fn a_proof_claiming_another_epoch_is_rejected() {
    let f = setup();
    let mut send = alice_send(C1, 0);
    send.epoch = EPOCH - 1;
    let (calls, _) = prepare(f, @send);
    validate(f, calls);
}

/// An ancient base block (no max age at the protocol level) would mint a
/// fresh quota per past epoch; the store refuses anything older than
/// max_epoch_lag.
#[test]
#[should_panic(expected: ('stale epoch',))]
fn an_old_base_block_is_rejected() {
    let f = setup();
    let mut send = alice_send(C1, 0);
    send.epoch = EPOCH - 2;
    let (calls, _) = prepare_at(f, @send, (EPOCH - 2) * EPOCH_BLOCKS + 5);
    validate(f, calls);
}

#[test]
fn one_epoch_behind_is_still_accepted() {
    let f = setup();
    let mut send = alice_send(C1, 0);
    send.epoch = EPOCH - 1;
    let (calls, _) = prepare_at(f, @send, (EPOCH - 1) * EPOCH_BLOCKS + 999);
    assert_eq!(validate(f, calls), VALIDATED);
}

// --- validate refuses everything execute would revert on ---------------------

#[test]
#[should_panic(expected: ('commitment consumed',))]
fn a_replayed_commitment_is_rejected_in_validate() {
    let f = setup();
    publish(f, @alice_send(C1, 0));
    // Same commitment, new slot: a fresh nullifier but a consumed commitment.
    let (calls, _) = prepare(f, @alice_send(C1, 1));
    validate(f, calls);
}

#[test]
#[should_panic(expected: ('unknown merkle root',))]
fn an_unknown_root_is_rejected_in_validate() {
    let f = setup();
    let (_, nullifier) = prepare(f, @alice_send(C1, 0));
    let mut calldata: Array<felt252> = array![];
    (C1, EPHEMERAL_PUBKEY, ROOT + 1, nullifier, content()).serialize(ref calldata);
    let calls = array![
        Call {
            to: f.pool.contract_address,
            selector: selector!("send_message"),
            calldata: calldata.span(),
        },
    ];
    validate(f, calls);
}

#[test]
#[should_panic(expected: ('expected one proven message',))]
fn a_transaction_without_facts_is_rejected() {
    let f = setup();
    let (calls, _) = prepare(f, @alice_send(C1, 0));
    stop_cheat_proof_facts_global();
    validate(f, calls);
}

/// Swapping the content keeps everything else but breaks the binding.
#[test]
#[should_panic(expected: ('no proof for this send',))]
fn other_content_is_rejected_in_validate() {
    let f = setup();
    let send = alice_send(C1, 0);
    let (_, nullifier) = prepare(f, @send);
    let mut other = send.clone();
    other.content.append_byte(0);
    validate(f, send_calls(f.pool.contract_address, @other, nullifier));
}

/// A different nullifier than the proof's (e.g. a fresh random one to dodge
/// the quota) breaks the binding.
#[test]
#[should_panic(expected: ('no proof for this send',))]
fn a_forged_nullifier_is_rejected() {
    let f = setup();
    let send = alice_send(C1, 0);
    let (_, nullifier) = prepare(f, @send);
    validate(f, send_calls(f.pool.contract_address, @send, nullifier + 1));
}

#[test]
#[should_panic(expected: ('content too long',))]
fn content_past_the_event_limit_is_rejected_in_validate() {
    let f = setup();
    let mut send = alice_send(C1, 0);
    send.content = bytes(8193);
    let (calls, _) = prepare(f, @send);
    validate(f, calls);
}

#[test]
#[should_panic(expected: ('content too short',))]
fn short_content_is_rejected_in_validate() {
    let f = setup();
    let mut send = alice_send(C1, 0);
    send.content = bytes(1088 + 12 + 15);
    let (calls, _) = prepare(f, @send);
    validate(f, calls);
}

// --- validate refuses calls the pool would pay for -----------------------------

#[test]
#[should_panic(expected: ('pool takes exactly one call',))]
fn two_calls_are_rejected() {
    let f = setup();
    let (calls, _) = prepare(f, @alice_send(C1, 0));
    let mut two = calls.clone();
    two.append(*calls.at(0));
    validate(f, two);
}

#[test]
#[should_panic(expected: ('pool takes exactly one call',))]
fn no_calls_are_rejected() {
    let f = setup();
    prepare(f, @alice_send(C1, 0));
    validate(f, array![]);
}

/// e.g. an STRK transfer out of the pool.
#[test]
#[should_panic(expected: ('pool only calls itself',))]
fn a_call_to_another_contract_is_rejected() {
    let f = setup();
    prepare(f, @alice_send(C1, 0));
    validate(
        f,
        array![
            Call {
                to: addr(0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d),
                selector: selector!("transfer"),
                calldata: array![0xbad, 1000, 0].span(),
            },
        ],
    );
}

#[test]
#[should_panic(expected: ('pool only sends messages',))]
fn another_selector_is_rejected() {
    let f = setup();
    let (calls, _) = prepare(f, @alice_send(C1, 0));
    validate(
        f,
        array![
            Call {
                to: f.pool.contract_address,
                selector: selector!("register"),
                calldata: *calls.at(0).calldata,
            },
        ],
    );
}

/// Padding calldata is archival data the pool would pay for.
#[test]
#[should_panic(expected: ('trailing calldata',))]
fn trailing_calldata_is_rejected() {
    let f = setup();
    let (calls, _) = prepare(f, @alice_send(C1, 0));
    let mut padded: Array<felt252> = array![];
    for x in *calls.at(0).calldata {
        padded.append(*x);
    }
    padded.append(0);
    validate(
        f,
        array![
            Call {
                to: f.pool.contract_address,
                selector: selector!("send_message"),
                calldata: padded.span(),
            },
        ],
    );
}

#[test]
#[should_panic(expected: ('bad send calldata',))]
fn truncated_calldata_is_rejected() {
    let f = setup();
    prepare(f, @alice_send(C1, 0));
    validate(
        f,
        array![
            Call {
                to: f.pool.contract_address,
                selector: selector!("send_message"),
                calldata: array![C1, EPHEMERAL_PUBKEY].span(),
            },
        ],
    );
}

// --- fee policy, through the account ---------------------------------------------

#[test]
#[should_panic(expected: ('tip over policy',))]
fn a_griefing_tip_is_rejected_in_validate() {
    let f = setup();
    let (calls, _) = prepare(f, @alice_send(C1, 0));
    start_cheat_tip_global(1_000_000_000_000);
    validate(f, calls);
}

#[test]
#[should_panic(expected: ('pool takes no signature',))]
fn signature_padding_is_rejected_in_validate() {
    let f = setup();
    let (calls, _) = prepare(f, @alice_send(C1, 0));
    start_cheat_signature_global(array![1, 2, 3].span());
    validate(f, calls);
}

// --- who may call the entry points ------------------------------------------------

#[test]
#[should_panic(expected: ('protocol only',))]
fn validate_is_protocol_only() {
    let f = setup();
    let (calls, _) = prepare(f, @alice_send(C1, 0));
    f.account.__validate__(calls);
}

/// Another contract cannot drive the pool's `__execute__` (it would skip
/// validate's fee policy).
#[test]
#[should_panic(expected: ('protocol only',))]
fn execute_is_protocol_only() {
    let f = setup();
    let (calls, _) = prepare(f, @alice_send(C1, 0));
    f.account.__execute__(calls);
}

#[test]
#[should_panic]
fn the_pool_does_not_declare() {
    let f = setup();
    as_protocol(f.account.contract_address);
    f.account.__validate_declare__(0x123);
}

#[test]
#[should_panic(expected: ('pool cannot register',))]
fn the_pool_cannot_register() {
    let f = setup();
    register_as(
        f.pool,
        f.pool.contract_address.into(),
        'pool',
        ALICE_SCAN_PUB,
        alice_kem_pubkey(),
        ALICE_M_COMMIT,
    );
}

/// A member may still publish from their own account (and be named, and
/// pay) — same rules, same nullifier.
#[test]
fn a_member_can_publish_directly() {
    let f = setup();
    let send = alice_send(C1, 0);
    let (_, nullifier) = prepare(f, @send);
    snforge_std::cheat_caller_address(
        f.pool.contract_address, addr(ALICE), snforge_std::CheatSpan::TargetCalls(1),
    );
    f.pool.send_message(C1, EPHEMERAL_PUBKEY, ROOT, nullifier, content());
    assert!(f.pool.is_nullifier_spent(nullifier));
    let _ = ALICE_KEM_DIGEST;
    let _ = NOW;
}
