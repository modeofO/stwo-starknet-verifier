//! The pool's fee policy: pure checks on the outer transaction's fee fields.
//!
//! The pool has no signature, so ANYONE can choose the fee fields of a
//! transaction the pool pays for. The sequencer charges up to
//! sum(max_amount * max_price_per_unit) + tip * l2_gas.max_amount, and on an
//! `__execute__` revert it charges what was used. `__validate__` therefore
//! caps the worst case and demands enough L2 gas that execute cannot run
//! out (an out-of-gas revert would still be paid).

use starknet::ResourcesBounds as ResourceBounds;

pub const L1_GAS: felt252 = 'L1_GAS';
pub const L2_GAS: felt252 = 'L2_GAS';
pub const L1_DATA_GAS: felt252 = 'L1_DATA';

/// Transaction version 3, and its fee-estimation (query) form 2^128 + 3,
/// which never reaches a block.
pub const TX_V3: felt252 = 3;
pub const TX_V3_QUERY: felt252 = 0x100000000000000000000000000000003;

#[derive(Drop, Copy, Serde, starknet::Store, PartialEq, Debug)]
pub struct FeePolicy {
    /// Ceiling, in fri, on what one send can cost the pool.
    pub max_fee: u128,
    pub max_tip: u128,
    /// Floor on l2_gas.max_amount: proof (75M fixed) + validate + execute +
    /// calldata/event archival for the longest allowed content, with margin.
    pub min_l2_gas: u64,
}

/// The worst-case fee the bounds allow, in fri. u256 so no product
/// overflows silently.
pub fn max_possible_fee(resource_bounds: Span<ResourceBounds>, tip: u128) -> u256 {
    let mut total: u256 = 0;
    for bound in resource_bounds {
        let amount: u256 = (*bound.max_amount).into();
        let mut price: u256 = (*bound.max_price_per_unit).into();
        if *bound.resource == L2_GAS {
            price += tip.into();
        }
        total += amount * price;
    }
    total
}

pub fn l2_gas_bound(resource_bounds: Span<ResourceBounds>) -> u64 {
    let mut amount: u64 = 0;
    for bound in resource_bounds {
        if *bound.resource == L2_GAS {
            amount = *bound.max_amount;
        }
    }
    amount
}

/// Panics with the reason a transaction's fee fields break the policy.
pub fn check_fee_fields(
    version: felt252,
    resource_bounds: Span<ResourceBounds>,
    tip: u128,
    signature_len: u32,
    paymaster_data_len: u32,
    account_deployment_data_len: u32,
    nonce_da_mode: u32,
    fee_da_mode: u32,
    policy: FeePolicy,
) {
    assert(version == TX_V3 || version == TX_V3_QUERY, 'pool takes v3 only');
    // Signature felts are archival data the pool would pay for; the pool
    // authorizes by proof, so there is nothing to sign.
    assert(signature_len == 0, 'pool takes no signature');
    assert(paymaster_data_len == 0, 'no paymaster data');
    assert(account_deployment_data_len == 0, 'no deployment data');
    assert(nonce_da_mode == 0 && fee_da_mode == 0, 'L1 DA modes only');
    assert(tip <= policy.max_tip, 'tip over policy');
    assert(l2_gas_bound(resource_bounds) >= policy.min_l2_gas, 'l2 gas bound too low');
    assert(max_possible_fee(resource_bounds, tip) <= policy.max_fee.into(), 'fee over policy');
}
