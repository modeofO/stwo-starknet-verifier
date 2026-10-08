//! Shared fixtures: a pool with alice (leaf 0) and bob (leaf 1) registered,
//! the real v4 prover run as an ordinary call to obtain the exact message
//! hash a virtual-OS proof would carry, and a transaction environment that
//! satisfies the pool's fee policy.

use snforge_std::{
    CheatSpan, ContractClassTrait, DeclareResultTrait, MessageToL1SpyTrait, cheat_caller_address,
    declare, spy_messages_to_l1, start_cheat_block_number_global, start_cheat_proof_facts_global,
    start_cheat_resource_bounds_global, start_cheat_signature_global, start_cheat_tip_global,
    start_cheat_transaction_version_global,
};
use starknet::account::Call;
use starknet::{ContractAddress, ResourcesBounds};
use zkmsg_pool_v4::facts::{PROOF_VERSION_V1, VIRTUAL_OS_OUTPUT_VERSION, VIRTUAL_SNOS, message_hash};
use zkmsg_pool_v4::mock_strk::{IMockStrkDispatcher, IMockStrkDispatcherTrait};
use zkmsg_pool_v4::policy::{FeePolicy, L1_DATA_GAS, L1_GAS, L2_GAS};
use zkmsg_pool_v4::pool::{
    IPoolAccountDispatcher, IZkmsgPoolV4Dispatcher, IZkmsgPoolV4DispatcherTrait, content_hash,
};
use zkmsg_pool_v4::prover::{
    IZkmsgSendProverV4Dispatcher, IZkmsgSendProverV4DispatcherTrait, ticket_leaf,
};
use crate::vector::{
    ALICE_KEM_DIGEST, ALICE_MEMBER_SECRET, ALICE_M_COMMIT, ALICE_SCAN_PUB, BOB_M_COMMIT,
    BOB_SCAN_PUB, COMMITMENT, EPHEMERAL_PUBKEY, ROOT, alice_kem_pubkey, alice_path, bob_kem_pubkey,
    content,
};

pub const ALICE: felt252 = 0xa11ce;
pub const BOB: felt252 = 0xb0b;

pub const EPOCH_BLOCKS: u64 = 1000;
pub const MAX_EPOCH_LAG: u64 = 1;
pub const QUOTA: u32 = 3;

/// A Sepolia-like base block and a head 20 blocks later (the gateway needs
/// the base to trail by >= 10).
pub const BASE_BLOCK: u64 = 15850106;
pub const NOW: u64 = BASE_BLOCK + 20;
pub const EPOCH: u64 = BASE_BLOCK / EPOCH_BLOCKS;

/// 1 STRK = 10^18 fri. A ticket covers one send's WORST case: 3 STRK =
/// 100M L2 gas (MIN_L2_GAS) at 30e9 fri, i.e. 1.5x the ~2.0e10 fri/gas
/// Sepolia charged for v3 sends (78.0M L2 gas, 1.565 STRK;
/// docs/zkmsg-deployment.md). Actual cost ~1.55 STRK; the rest stays.
pub const TICKET_PRICE: u128 = 3_000_000_000_000_000_000;
pub const MAX_FEE: u128 = TICKET_PRICE;
/// Who buys the fixture's tickets (an account unrelated to the members).
pub const BUYER: felt252 = 0xb0e5;
pub const N_TICKETS: u32 = 8;
/// Ticket i's secret; tickets are bought in order, so its leaf index is i.
pub fn ticket_secret(i: u32) -> felt252 {
    0x7111c3700000 + i.into()
}
pub const MAX_TIP: u128 = 1_000_000_000;
pub const MIN_L2_GAS: u64 = 100_000_000;

pub fn addr(value: felt252) -> ContractAddress {
    value.try_into().unwrap()
}

pub fn policy() -> FeePolicy {
    FeePolicy { max_fee: MAX_FEE, max_tip: MAX_TIP, min_l2_gas: MIN_L2_GAS }
}

/// Bounds a client would set: 150M L2 gas at 10 gwei-fri (1.5 STRK ceiling
/// incl. small L1 parts), within the 3 STRK ticket.
pub fn good_bounds() -> Array<ResourcesBounds> {
    array![
        ResourcesBounds { resource: L1_GAS, max_amount: 0, max_price_per_unit: 0 },
        ResourcesBounds {
            resource: L2_GAS, max_amount: 150_000_000, max_price_per_unit: 10_000_000_000,
        },
        ResourcesBounds { resource: L1_DATA_GAS, max_amount: 2000, max_price_per_unit: 100_000 },
    ]
}

pub fn deploy_prover() -> IZkmsgSendProverV4Dispatcher {
    let class = declare("ZkmsgSendProverV4").unwrap().contract_class();
    let (address, _) = class.deploy(@array![]).unwrap();
    IZkmsgSendProverV4Dispatcher { contract_address: address }
}

pub fn deploy_strk() -> IMockStrkDispatcher {
    let class = declare("MockStrk").unwrap().contract_class();
    let (address, _) = class.deploy(@array![]).unwrap();
    IMockStrkDispatcher { contract_address: address }
}

pub fn pool_args(prover: ContractAddress, strk: ContractAddress, quota: u32) -> Array<felt252> {
    let mut args: Array<felt252> = array![
        prover.into(), strk.into(), TICKET_PRICE.into(), EPOCH_BLOCKS.into(), MAX_EPOCH_LAG.into(),
        quota.into(),
    ];
    policy().serialize(ref args);
    args
}

/// BUYER funds itself, approves the pool and buys `n` tickets.
pub fn buy(pool: IZkmsgPoolV4Dispatcher, strk: IMockStrkDispatcher, first: u32, n: u32) {
    let price: u256 = TICKET_PRICE.into();
    strk.mint(addr(BUYER), price * n.into());
    cheat_caller_address(strk.contract_address, addr(BUYER), CheatSpan::TargetCalls(1));
    strk.approve(pool.contract_address, price * n.into());
    let mut leaves = array![];
    for i in first..first + n {
        leaves.append(ticket_leaf(ticket_secret(i)));
    }
    cheat_caller_address(pool.contract_address, addr(BUYER), CheatSpan::TargetCalls(1));
    pool.buy_tickets(leaves);
}

/// A pool with alice and bob registered and N_TICKETS tickets bought.
pub fn deploy_pool_with(
    prover: ContractAddress, quota: u32,
) -> (IZkmsgPoolV4Dispatcher, IPoolAccountDispatcher, IMockStrkDispatcher) {
    let strk = deploy_strk();
    let class = declare("ZkmsgPoolV4").unwrap().contract_class();
    let args = pool_args(prover, strk.contract_address, quota);
    let (address, _) = class.deploy(@args).unwrap();
    let pool = IZkmsgPoolV4Dispatcher { contract_address: address };
    register_as(pool, ALICE, 'alice', ALICE_SCAN_PUB, alice_kem_pubkey(), ALICE_M_COMMIT);
    register_as(pool, BOB, 'bob', BOB_SCAN_PUB, bob_kem_pubkey(), BOB_M_COMMIT);
    assert_eq!(pool.get_merkle_root(), ROOT);
    buy(pool, strk, 0, N_TICKETS);
    (pool, IPoolAccountDispatcher { contract_address: address }, strk)
}

pub fn register_as(
    pool: IZkmsgPoolV4Dispatcher,
    caller: felt252,
    handle: felt252,
    scan_pubkey: felt252,
    kem_pubkey: ByteArray,
    m_commit: felt252,
) {
    cheat_caller_address(pool.contract_address, addr(caller), CheatSpan::TargetCalls(1));
    pool.register(handle, scan_pubkey, kem_pubkey, m_commit);
}

/// A send's public tuple plus what alice's proof of it would claim.
#[derive(Drop, Clone)]
pub struct Send {
    pub commitment: felt252,
    pub content: ByteArray,
    pub epoch: u64,
    pub quota: u32,
    pub slot: u32,
    /// Which fixture ticket pays (its secret and leaf index).
    pub ticket: u32,
}

/// Alice's send with quota slot `slot`, paid with ticket number `slot`.
pub fn alice_send(commitment: felt252, slot: u32) -> Send {
    Send { commitment, content: content(), epoch: EPOCH, quota: QUOTA, slot, ticket: slot }
}

/// The public values a proof binds besides the send itself.
#[derive(Drop, Copy)]
pub struct Proven {
    pub nullifier: felt252,
    pub ticket_root: felt252,
    pub ticket_nullifier: felt252,
    pub message: felt252,
}

/// Runs the real prover for alice against the pool's current ticket root
/// and returns what the virtual OS would record. Nullifiers are read back
/// from the emitted payload, i.e. exactly what the prover computed.
pub fn prove(
    prover: IZkmsgSendProverV4Dispatcher, pool: IZkmsgPoolV4Dispatcher, send: @Send,
) -> Proven {
    let ticket_root = pool.get_ticket_root();
    let ticket_path = pool.get_ticket_path(*send.ticket);
    let mut spy = spy_messages_to_l1();
    prover
        .prove_send(
            pool.contract_address.into(),
            content_hash(send.content),
            *send.commitment,
            EPHEMERAL_PUBKEY,
            ROOT,
            *send.epoch,
            *send.quota,
            ticket_root,
            ALICE_SCAN_PUB,
            ALICE_KEM_DIGEST,
            ALICE_MEMBER_SECRET,
            *send.slot,
            0,
            alice_path().span(),
            ticket_secret(*send.ticket),
            *send.ticket,
            ticket_path.span(),
        );
    let messages = spy.get_messages().messages;
    assert_eq!(messages.len(), 1);
    let (from, message) = messages.at(0);
    let to: felt252 = (*message.to_address).into();
    Proven {
        nullifier: *message.payload.at(5),
        ticket_root: *message.payload.at(8),
        ticket_nullifier: *message.payload.at(9),
        message: message_hash((*from).into(), to, message.payload.span()),
    }
}

pub fn facts(base_block: u64, message: felt252) -> Array<felt252> {
    array![
        PROOF_VERSION_V1, VIRTUAL_SNOS, 0x53f6c9, VIRTUAL_OS_OUTPUT_VERSION, base_block.into(),
        0xb10c, 0xc0f, 1, message,
    ]
}

/// The calls a client puts in the pool's publish transaction.
pub fn send_calls(pool: ContractAddress, send: @Send, p: Proven) -> Array<Call> {
    let mut calldata: Array<felt252> = array![];
    (
        *send.commitment,
        EPHEMERAL_PUBKEY,
        ROOT,
        p.nullifier,
        p.ticket_root,
        p.ticket_nullifier,
        send.content.clone(),
    )
        .serialize(ref calldata);
    array![Call { to: pool, selector: selector!("send_message"), calldata: calldata.span() }]
}

/// The publish transaction's environment: a v3 tx within policy, at NOW,
/// carrying `facts`.
pub fn tx_env(facts: Span<felt252>) {
    start_cheat_block_number_global(NOW);
    start_cheat_transaction_version_global(3);
    start_cheat_resource_bounds_global(good_bounds().span());
    start_cheat_tip_global(0);
    start_cheat_signature_global(array![].span());
    start_cheat_proof_facts_global(facts);
}

/// The protocol calls account entry points with caller 0.
pub fn as_protocol(account: ContractAddress) {
    cheat_caller_address(account, addr(0), CheatSpan::TargetCalls(1));
}

pub fn bytes(n: u32) -> ByteArray {
    let mut b: ByteArray = Default::default();
    for _ in 0..n {
        b.append_byte(0x5a);
    }
    b
}

pub const C1: felt252 = COMMITMENT;
pub const C2: felt252 = COMMITMENT + 1;
pub const C3: felt252 = COMMITMENT + 2;
pub const C4: felt252 = COMMITMENT + 3;
