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
    CheatSpan, ContractClassTrait, DeclareResultTrait, EventSpyTrait, cheat_caller_address, declare,
    spy_events, start_cheat_block_number_global, start_cheat_resource_bounds_global,
    start_cheat_signature_global, start_cheat_tip_global, stop_cheat_proof_facts_global,
};
use starknet::account::Call;
use starknet::{ResourcesBounds, VALIDATED};
use zkmsg_pool_v4::mock_strk::{IMockStrkDispatcher, IMockStrkDispatcherTrait};
use zkmsg_pool_v4::policy::{FeePolicy, L2_GAS};
use zkmsg_pool_v4::pool::{
    IPoolAccountDispatcher, IPoolAccountDispatcherTrait, IZkmsgPoolV4Dispatcher,
    IZkmsgPoolV4DispatcherTrait, content_hash,
};
use zkmsg_pool_v4::prover::{IZkmsgSendProverV4Dispatcher, ticket_leaf};
use crate::common::{
    ALICE, BASE_BLOCK, BUYER, C1, C2, C3, C4, EPOCH, EPOCH_BLOCKS, MIN_L2_GAS, N_TICKETS, Proven,
    QUOTA, Send, TICKET_PRICE, addr, alice_send, as_protocol, buy, bytes, content, deploy_pool_with,
    deploy_prover, deploy_strk, facts, pool_args, prove, register_as, send_calls, ticket_secret,
    tx_env,
};
use crate::vector::{ALICE_M_COMMIT, ALICE_SCAN_PUB, EPHEMERAL_PUBKEY, ROOT, alice_kem_pubkey};

#[derive(Drop, Copy)]
struct Fixture {
    prover: IZkmsgSendProverV4Dispatcher,
    pool: IZkmsgPoolV4Dispatcher,
    account: IPoolAccountDispatcher,
    strk: IMockStrkDispatcher,
}

fn setup() -> Fixture {
    let prover = deploy_prover();
    let (pool, account, strk) = deploy_pool_with(prover.contract_address, QUOTA);
    Fixture { prover, pool, account, strk }
}

/// Proves `send`, sets up its publish transaction at base block `base`, and
/// returns (calls, what the proof binds).
fn prepare_at(f: Fixture, send: @Send, base: u64) -> (Array<Call>, Proven) {
    let p = prove(f.prover, f.pool, send);
    tx_env(facts(base, p.message).span());
    (send_calls(f.pool.contract_address, send, p), p)
}

fn prepare(f: Fixture, send: @Send) -> (Array<Call>, Proven) {
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
fn publish(f: Fixture, send: @Send) -> Proven {
    let (calls, p) = prepare(f, send);
    assert_eq!(validate(f, calls.clone()), VALIDATED);
    execute(f, calls);
    p
}

// --- the happy path ----------------------------------------------------------

#[test]
fn validate_then_execute_publishes() {
    let f = setup();
    let send = alice_send(C1, 0);
    let (calls, p) = prepare(f, @send);
    let nullifier = p.nullifier;
    assert!(!f.pool.is_nullifier_spent(nullifier));
    assert!(!f.pool.is_ticket_spent(p.ticket_nullifier));
    assert_eq!(validate(f, calls.clone()), VALIDATED);
    // Validate burns the ticket and nothing else.
    assert!(f.pool.is_ticket_spent(p.ticket_nullifier));
    assert!(!f.pool.is_nullifier_spent(nullifier));
    assert_eq!(f.pool.n_messages(), 0);

    let mut spy = spy_events();
    execute(f, calls);
    assert_eq!(f.pool.n_messages(), 1);
    assert!(f.pool.is_nullifier_spent(nullifier));
    assert!(f.pool.is_envelope_consumed(C1, content_hash(@content())));
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
    let (_, p) = prepare(f, @send);
    f
        .pool
        .check_send(
            C1,
            EPHEMERAL_PUBKEY,
            ROOT,
            p.nullifier,
            p.ticket_root,
            p.ticket_nullifier,
            content_hash(@content()),
        );
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
    let mut again = alice_send(C2, 0);
    again.ticket = 5; // a fresh ticket: only the quota slot is re-used
    let (calls, _) = prepare(f, @again);
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
    next.ticket = 1;
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
#[should_panic(expected: ('envelope consumed',))]
fn a_replayed_envelope_is_rejected_in_validate() {
    let f = setup();
    publish(f, @alice_send(C1, 0));
    // Same commitment and content, new slot and ticket: a consumed envelope.
    let (calls, _) = prepare(f, @alice_send(C1, 1));
    validate(f, calls);
}

/// F9: a member who front-runs a pending send with its commitment over
/// other content no longer blocks it. Both land; only the real one opens
/// for the recipient.
#[test]
fn a_front_run_commitment_does_not_block_the_real_send() {
    let f = setup();
    let mut forged = alice_send(C1, 0);
    forged.content = bytes(1372);
    publish(f, @forged);
    publish(f, @alice_send(C1, 1));
    assert_eq!(f.pool.n_messages(), 2);
    assert!(f.pool.is_envelope_consumed(C1, content_hash(@content())));
    assert!(f.pool.is_envelope_consumed(C1, content_hash(@bytes(1372))));
}

#[test]
#[should_panic(expected: ('unknown merkle root',))]
fn an_unknown_root_is_rejected_in_validate() {
    let f = setup();
    let (_, p) = prepare(f, @alice_send(C1, 0));
    let mut calldata: Array<felt252> = array![];
    (C1, EPHEMERAL_PUBKEY, ROOT + 1, p.nullifier, p.ticket_root, p.ticket_nullifier, content())
        .serialize(ref calldata);
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
    let (_, p) = prepare(f, @send);
    let mut other = send.clone();
    other.content = bytes(1372); // same padded size, other bytes
    validate(f, send_calls(f.pool.contract_address, @other, p));
}

/// A different nullifier than the proof's (e.g. a fresh random one to dodge
/// the quota) breaks the binding.
#[test]
#[should_panic(expected: ('no proof for this send',))]
fn a_forged_nullifier_is_rejected() {
    let f = setup();
    let send = alice_send(C1, 0);
    let (_, mut p) = prepare(f, @send);
    p.nullifier += 1;
    validate(f, send_calls(f.pool.contract_address, @send, p));
}

/// Every padded size publishes; the largest still fits the event cap.
#[test]
fn each_padded_size_publishes() {
    let f = setup();
    let mut slot = 0;
    for len in array![1372_u32, 2140, 5212] {
        let mut send = alice_send(C1 + slot.into(), slot);
        send.content = bytes(len);
        publish(f, @send);
        slot += 1;
    }
    assert_eq!(f.pool.n_messages(), 3);
}

fn validate_len(len: u32) {
    let f = setup();
    let mut send = alice_send(C1, 0);
    send.content = bytes(len);
    let (calls, _) = prepare(f, @send);
    validate(f, calls);
}

#[test]
#[should_panic(expected: ('content not a padded size',))]
fn one_byte_under_a_bucket_is_rejected_in_validate() {
    validate_len(1371);
}

#[test]
#[should_panic(expected: ('content not a padded size',))]
fn one_byte_over_a_bucket_is_rejected_in_validate() {
    validate_len(2141);
}

#[test]
#[should_panic(expected: ('content not a padded size',))]
fn the_old_unpadded_size_is_rejected_in_validate() {
    validate_len(1136);
}

#[test]
#[should_panic(expected: ('content not a padded size',))]
fn past_the_top_bucket_is_rejected_in_validate() {
    validate_len(5213);
}

/// execute applies the same rule (a direct send_message from the pool).
#[test]
#[should_panic(expected: ('content not a padded size',))]
fn send_message_rejects_other_sizes_too() {
    let f = setup();
    let send = alice_send(C1, 0);
    let (_, p) = prepare(f, @send);
    cheat_caller_address(
        f.pool.contract_address, f.pool.contract_address, CheatSpan::TargetCalls(1),
    );
    f
        .pool
        .send_message(
            C1, EPHEMERAL_PUBKEY, ROOT, p.nullifier, p.ticket_root, p.ticket_nullifier, bytes(2000),
        );
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
/// validate's fee policy and the ticket burn).
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

/// `send_message` is reachable only through the pool's own `__execute__`:
/// a member calling it from their own account would skip the ticket.
#[test]
#[should_panic(expected: ('send through the pool',))]
fn send_message_is_pool_only() {
    let f = setup();
    let send = alice_send(C1, 0);
    let (_, p) = prepare(f, @send);
    cheat_caller_address(f.pool.contract_address, addr(ALICE), CheatSpan::TargetCalls(1));
    f
        .pool
        .send_message(
            C1, EPHEMERAL_PUBKEY, ROOT, p.nullifier, p.ticket_root, p.ticket_nullifier, content(),
        );
}

// --- tickets: users fund the pool, one burnt per send ------------------------------

#[test]
fn buying_tickets_pays_the_pool() {
    let f = setup();
    let price: u256 = TICKET_PRICE.into();
    assert_eq!(f.pool.n_tickets(), N_TICKETS);
    assert_eq!(f.strk.balance_of(f.pool.contract_address), price * N_TICKETS.into());
    assert_eq!(f.strk.balance_of(addr(BUYER)), 0);
    assert!(f.pool.is_known_ticket_root(f.pool.get_ticket_root()));
    let mut spy = spy_events();
    buy(f.pool, f.strk, N_TICKETS, 2);
    // One TicketBought per leaf: [selector], data [leaf, index].
    let events = spy.get_events().events;
    let (_, last) = events.at(events.len() - 1);
    assert_eq!(*last.keys.at(0), selector!("TicketBought"));
    assert(
        last.data == @array![ticket_leaf(ticket_secret(N_TICKETS + 1)), (N_TICKETS + 1).into()],
        'ticket event',
    );
}

#[test]
#[should_panic(expected: ('insufficient allowance',))]
fn tickets_must_be_paid_for() {
    let f = setup();
    cheat_caller_address(f.pool.contract_address, addr(BUYER), CheatSpan::TargetCalls(1));
    f.pool.buy_tickets(array![ticket_leaf(0x5ee)]);
}

#[test]
#[should_panic(expected: ('pool cannot buy',))]
fn the_pool_cannot_buy_tickets_with_its_own_funds() {
    let f = setup();
    cheat_caller_address(
        f.pool.contract_address, f.pool.contract_address, CheatSpan::TargetCalls(1),
    );
    f.pool.buy_tickets(array![ticket_leaf(0x5ee)]);
}

/// A ticket pays once. Here: a new quota slot and commitment, same ticket.
#[test]
#[should_panic(expected: ('ticket spent',))]
fn a_spent_ticket_is_rejected_in_validate() {
    let f = setup();
    publish(f, @alice_send(C1, 0));
    let mut again = alice_send(C2, 1);
    again.ticket = 0;
    let (calls, _) = prepare(f, @again);
    validate(f, calls);
}

/// The burn happens in validate: a second validate of the very same
/// transaction (e.g. the same tx later in the block) is rejected.
#[test]
#[should_panic(expected: ('ticket spent',))]
fn validate_burns_the_ticket() {
    let f = setup();
    let (calls, _) = prepare(f, @alice_send(C1, 0));
    validate(f, calls.clone());
    validate(f, calls);
}

/// Execute without this transaction's validate having burnt the ticket.
#[test]
#[should_panic(expected: ('ticket not burnt',))]
fn execute_requires_the_burn() {
    let f = setup();
    let (calls, _) = prepare(f, @alice_send(C1, 0));
    execute(f, calls);
}

/// A secret that was never bought has no leaf: no proof can be made.
#[test]
#[should_panic(expected: ('no such ticket',))]
fn an_unbought_ticket_cannot_be_proven() {
    let f = setup();
    let mut send = alice_send(C1, 0);
    send.ticket = N_TICKETS; // index past the bought leaves
    prepare(f, @send);
}

#[test]
#[should_panic(expected: ('unknown ticket root',))]
fn an_unknown_ticket_root_is_rejected() {
    let f = setup();
    let send = alice_send(C1, 0);
    let (_, mut p) = prepare(f, @send);
    p.ticket_root += 1;
    validate(f, send_calls(f.pool.contract_address, @send, p));
}

/// Purchases after the proof was made move the ticket root; every root the
/// append-only ticket tree ever had stays acceptable.
#[test]
fn a_proof_survives_later_purchases() {
    let f = setup();
    let (calls, p) = prepare(f, @alice_send(C1, 0));
    buy(f.pool, f.strk, N_TICKETS, 32);
    assert(f.pool.get_ticket_root() != p.ticket_root, 'root did not move');
    assert_eq!(validate(f, calls.clone()), VALIDATED);
    execute(f, calls);
    assert_eq!(f.pool.n_messages(), 1);
}

/// The worst-case fee may not exceed the ticket: 100M L2 gas at 35e9
/// = 3.5 STRK > 3 STRK.
#[test]
#[should_panic(expected: ('fee over policy',))]
fn a_fee_bound_over_the_ticket_is_rejected() {
    let f = setup();
    let (calls, _) = prepare(f, @alice_send(C1, 0));
    start_cheat_resource_bounds_global(
        array![
            ResourcesBounds {
                resource: L2_GAS, max_amount: MIN_L2_GAS, max_price_per_unit: 35_000_000_000,
            },
        ]
            .span(),
    );
    validate(f, calls);
}

#[test]
#[should_panic]
fn the_policy_may_not_exceed_the_ticket_price() {
    let strk = deploy_strk();
    let class = declare("ZkmsgPoolV4").unwrap().contract_class();
    let mut args: Array<felt252> = array![
        0x9407e2, strk.contract_address.into(), TICKET_PRICE.into(), EPOCH_BLOCKS.into(), 1,
        QUOTA.into(),
    ];
    FeePolicy { max_fee: TICKET_PRICE + 1, max_tip: 0, min_l2_gas: MIN_L2_GAS }.serialize(ref args);
    class.deploy(@args).unwrap();
}

#[test]
fn pool_args_are_well_formed() {
    let strk = deploy_strk();
    let class = declare("ZkmsgPoolV4").unwrap().contract_class();
    class.deploy(@pool_args(addr(0x9407e2), strk.contract_address, QUOTA)).unwrap();
}

