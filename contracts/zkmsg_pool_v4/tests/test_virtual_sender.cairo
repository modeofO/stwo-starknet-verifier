//! ZkmsgVirtualSenderV4: the shared sender of every virtual prove_send.

use snforge_std::{
    CheatSpan, ContractClassTrait, DeclareResultTrait, MessageToL1SpyTrait, cheat_caller_address,
    declare, spy_messages_to_l1, start_cheat_resource_bounds_global, start_cheat_tip_global,
};
use starknet::account::{AccountContractDispatcher, AccountContractDispatcherTrait, Call};
use starknet::{ContractAddress, ResourcesBounds, VALIDATED};
use zkmsg_pool_v4::policy::{L1_DATA_GAS, L1_GAS, L2_GAS};
use zkmsg_pool_v4::pool::content_hash;
use crate::common::{EPOCH, QUOTA, addr, deploy_prover, good_bounds};
use crate::vector::{
    ALICE_KEM_DIGEST, ALICE_MEMBER_SECRET, ALICE_SCAN_PUB, COMMITMENT, EPHEMERAL_PUBKEY, ROOT,
    alice_path, content,
};

fn deploy_sender() -> AccountContractDispatcher {
    let class = declare("ZkmsgVirtualSenderV4").unwrap().contract_class();
    let (address, _) = class.deploy(@array![]).unwrap();
    AccountContractDispatcher { contract_address: address }
}

/// The bounds the virtual prover requires: zero prices, nonzero L2 amount.
fn zero_fee_bounds() -> Array<ResourcesBounds> {
    array![
        ResourcesBounds { resource: L1_GAS, max_amount: 0, max_price_per_unit: 0 },
        ResourcesBounds { resource: L2_GAS, max_amount: 1_000_000_000, max_price_per_unit: 0 },
        ResourcesBounds { resource: L1_DATA_GAS, max_amount: 0, max_price_per_unit: 0 },
    ]
}

fn protocol(account: ContractAddress) {
    cheat_caller_address(account, addr(0), CheatSpan::TargetCalls(1));
}

fn prove_send_call(prover: ContractAddress) -> Call {
    let mut calldata: Array<felt252> = array![];
    (
        0x5702e,
        content_hash(@content()),
        COMMITMENT,
        EPHEMERAL_PUBKEY,
        ROOT,
        EPOCH,
        QUOTA,
        ALICE_SCAN_PUB,
        ALICE_KEM_DIGEST,
        ALICE_MEMBER_SECRET,
        0_u32,
        0_u32,
    )
        .serialize(ref calldata);
    alice_path().span().serialize(ref calldata);
    Call { to: prover, selector: selector!("prove_send"), calldata: calldata.span() }
}

#[test]
fn accepts_any_signature_at_zero_fee() {
    let sender = deploy_sender();
    start_cheat_resource_bounds_global(zero_fee_bounds().span());
    start_cheat_tip_global(0);
    protocol(sender.contract_address);
    assert_eq!(sender.__validate__(array![]), VALIDATED);
}

/// Nonzero prices: what any real-chain transaction must carry. Refused, so
/// the account can never move its nonce on the real chain.
#[test]
#[should_panic(expected: ('virtual only: fee',))]
fn refuses_a_real_fee() {
    let sender = deploy_sender();
    start_cheat_resource_bounds_global(good_bounds().span());
    start_cheat_tip_global(0);
    protocol(sender.contract_address);
    sender.__validate__(array![]);
}

#[test]
#[should_panic(expected: ('virtual only: tip',))]
fn refuses_a_tip() {
    let sender = deploy_sender();
    start_cheat_resource_bounds_global(zero_fee_bounds().span());
    start_cheat_tip_global(1);
    protocol(sender.contract_address);
    sender.__validate__(array![]);
}

/// The proven message's from_address is the PROVER, not this account: the
/// sender is invisible in the message hash.
#[test]
fn forwards_prove_send_and_the_message_names_the_prover() {
    let sender = deploy_sender();
    let prover = deploy_prover();
    let mut spy = spy_messages_to_l1();
    protocol(sender.contract_address);
    sender.__execute__(array![prove_send_call(prover.contract_address)]);
    let messages = spy.get_messages().messages;
    assert_eq!(messages.len(), 1);
    let (from, _) = messages.at(0);
    assert(*from == prover.contract_address, 'from is not the prover');
    assert(*from != sender.contract_address, 'from is the sender');
}

#[test]
#[should_panic(expected: ('protocol only',))]
fn execute_is_protocol_only() {
    let sender = deploy_sender();
    let prover = deploy_prover();
    sender.__execute__(array![prove_send_call(prover.contract_address)]);
}
