//! policy.cairo: the fee fields a signature-less pool must refuse.

use starknet::ResourcesBounds;
use zkmsg_pool_v4::policy::{
    L1_GAS, L2_GAS, TX_V3, TX_V3_QUERY, check_fee_fields, l2_gas_bound, max_possible_fee,
};
use crate::common::{MAX_FEE, MAX_TIP, MIN_L2_GAS, good_bounds, policy};

fn check(version: felt252, bounds: Array<ResourcesBounds>, tip: u128) {
    check_fee_fields(version, bounds.span(), tip, 0, 0, 0, 0, 0, policy());
}

fn l2(amount: u64, price: u128) -> Array<ResourcesBounds> {
    array![
        ResourcesBounds { resource: L1_GAS, max_amount: 0, max_price_per_unit: 0 },
        ResourcesBounds { resource: L2_GAS, max_amount: amount, max_price_per_unit: price },
    ]
}

#[test]
fn good_bounds_pass() {
    check(TX_V3, good_bounds(), 0);
    check(TX_V3_QUERY, good_bounds(), MAX_TIP);
}

#[test]
fn worst_case_fee_counts_the_tip_on_l2_gas() {
    // 150M * 20e9 + 2000 * 1e5 = 3e18 + 2e8; tip 7 adds 150M * 7.
    let bounds = good_bounds();
    assert_eq!(max_possible_fee(bounds.span(), 0), 3_000_000_000_200_000_000);
    assert_eq!(max_possible_fee(bounds.span(), 7), 3_000_000_001_250_000_000);
    assert_eq!(l2_gas_bound(bounds.span()), 150_000_000);
}

#[test]
#[should_panic(expected: ('fee over policy',))]
fn rejects_a_price_spike() {
    // Same gas, a price that would let one send cost 15 STRK.
    check(TX_V3, l2(150_000_000, 100_000_000_000), 0);
}

#[test]
#[should_panic(expected: ('fee over policy',))]
fn rejects_a_huge_amount_at_a_fair_price() {
    check(TX_V3, l2(1_000_000_000, 20_000_000_000), 0);
}

#[test]
fn accepts_the_exact_ceiling() {
    // 250M * 20e9 = 5e18 = MAX_FEE.
    check(TX_V3, l2(250_000_000, 20_000_000_000), 0);
    assert_eq!(MAX_FEE, 5_000_000_000_000_000_000);
}

/// An L2 bound too small for the send would run execute out of gas: a
/// revert the pool pays for. Refused in validate instead.
#[test]
#[should_panic(expected: ('l2 gas bound too low',))]
fn rejects_an_l2_bound_that_would_starve_execute() {
    check(TX_V3, l2(MIN_L2_GAS - 1, 1), 0);
}

#[test]
#[should_panic(expected: ('l2 gas bound too low',))]
fn rejects_missing_l2_bounds() {
    check(TX_V3, array![], 0);
}

#[test]
#[should_panic(expected: ('tip over policy',))]
fn rejects_a_big_tip() {
    check(TX_V3, good_bounds(), MAX_TIP + 1);
}

#[test]
#[should_panic(expected: ('pool takes v3 only',))]
fn rejects_old_versions() {
    check(1, good_bounds(), 0);
}

#[test]
#[should_panic(expected: ('pool takes no signature',))]
fn rejects_signature_padding() {
    check_fee_fields(TX_V3, good_bounds().span(), 0, 4000, 0, 0, 0, 0, policy());
}

#[test]
#[should_panic(expected: ('no paymaster data',))]
fn rejects_paymaster_data() {
    check_fee_fields(TX_V3, good_bounds().span(), 0, 0, 1, 0, 0, 0, policy());
}

#[test]
#[should_panic(expected: ('no deployment data',))]
fn rejects_deployment_data() {
    check_fee_fields(TX_V3, good_bounds().span(), 0, 0, 0, 1, 0, 0, policy());
}

#[test]
#[should_panic(expected: ('L1 DA modes only',))]
fn rejects_l2_da_mode() {
    check_fee_fields(TX_V3, good_bounds().span(), 0, 0, 0, 0, 1, 0, policy());
}
