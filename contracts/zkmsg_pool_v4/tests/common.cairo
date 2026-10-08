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
use zkmsg_pool_v4::policy::{FeePolicy, L1_DATA_GAS, L1_GAS, L2_GAS};
use zkmsg_pool_v4::pool::{
    IPoolAccountDispatcher, IZkmsgPoolV4Dispatcher, IZkmsgPoolV4DispatcherTrait, content_hash,
};
use zkmsg_pool_v4::prover::{IZkmsgSendProverV4Dispatcher, IZkmsgSendProverV4DispatcherTrait};
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

/// 1 STRK = 10^18 fri.
pub const MAX_FEE: u128 = 5_000_000_000_000_000_000;
pub const MAX_TIP: u128 = 1_000_000_000;
pub const MIN_L2_GAS: u64 = 100_000_000;

pub fn addr(value: felt252) -> ContractAddress {
    value.try_into().unwrap()
}

pub fn policy() -> FeePolicy {
    FeePolicy { max_fee: MAX_FEE, max_tip: MAX_TIP, min_l2_gas: MIN_L2_GAS }
}

/// Bounds a client would set: 150M L2 gas at 20 gwei-fri (3 STRK ceiling
/// incl. small L1 parts), within MAX_FEE.
pub fn good_bounds() -> Array<ResourcesBounds> {
    array![
        ResourcesBounds { resource: L1_GAS, max_amount: 0, max_price_per_unit: 0 },
        ResourcesBounds {
            resource: L2_GAS, max_amount: 150_000_000, max_price_per_unit: 20_000_000_000,
        },
        ResourcesBounds { resource: L1_DATA_GAS, max_amount: 2000, max_price_per_unit: 100_000 },
    ]
}

pub fn deploy_prover() -> IZkmsgSendProverV4Dispatcher {
    let class = declare("ZkmsgSendProverV4").unwrap().contract_class();
    let (address, _) = class.deploy(@array![]).unwrap();
    IZkmsgSendProverV4Dispatcher { contract_address: address }
}

pub fn deploy_pool_with(
    prover: ContractAddress, quota: u32,
) -> (IZkmsgPoolV4Dispatcher, IPoolAccountDispatcher) {
    let class = declare("ZkmsgPoolV4").unwrap().contract_class();
    let mut args: Array<felt252> = array![
        prover.into(), EPOCH_BLOCKS.into(), MAX_EPOCH_LAG.into(), quota.into(),
    ];
    policy().serialize(ref args);
    let (address, _) = class.deploy(@args).unwrap();
    let pool = IZkmsgPoolV4Dispatcher { contract_address: address };
    register_as(pool, ALICE, 'alice', ALICE_SCAN_PUB, alice_kem_pubkey(), ALICE_M_COMMIT);
    register_as(pool, BOB, 'bob', BOB_SCAN_PUB, bob_kem_pubkey(), BOB_M_COMMIT);
    assert_eq!(pool.get_merkle_root(), ROOT);
    (pool, IPoolAccountDispatcher { contract_address: address })
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
}

pub fn alice_send(commitment: felt252, slot: u32) -> Send {
    Send { commitment, content: content(), epoch: EPOCH, quota: QUOTA, slot }
}

/// Runs the real prover for alice and returns (nullifier, message hash) as
/// the virtual OS would record them. The nullifier is read back from the
/// emitted payload, i.e. exactly what the prover computed.
pub fn prove(
    prover: IZkmsgSendProverV4Dispatcher, pool: ContractAddress, send: @Send,
) -> (felt252, felt252) {
    let mut spy = spy_messages_to_l1();
    prover
        .prove_send(
            pool.into(),
            content_hash(send.content),
            *send.commitment,
            EPHEMERAL_PUBKEY,
            ROOT,
            *send.epoch,
            *send.quota,
            ALICE_SCAN_PUB,
            ALICE_KEM_DIGEST,
            ALICE_MEMBER_SECRET,
            *send.slot,
            0,
            alice_path().span(),
        );
    let messages = spy.get_messages().messages;
    assert_eq!(messages.len(), 1);
    let (from, message) = messages.at(0);
    let to: felt252 = (*message.to_address).into();
    let nullifier = *message.payload.at(5);
    (nullifier, message_hash((*from).into(), to, message.payload.span()))
}

pub fn facts(base_block: u64, message: felt252) -> Array<felt252> {
    array![
        PROOF_VERSION_V1, VIRTUAL_SNOS, 0x53f6c9, VIRTUAL_OS_OUTPUT_VERSION, base_block.into(),
        0xb10c, 0xc0f, 1, message,
    ]
}

/// The calls a client puts in the pool's publish transaction.
pub fn send_calls(pool: ContractAddress, send: @Send, nullifier: felt252) -> Array<Call> {
    let mut calldata: Array<felt252> = array![];
    (*send.commitment, EPHEMERAL_PUBKEY, ROOT, nullifier, send.content.clone())
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
