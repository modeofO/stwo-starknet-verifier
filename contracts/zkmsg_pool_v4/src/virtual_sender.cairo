//! The shared, well-known sender of every member's VIRTUAL `prove_send`
//! transaction, so a member's own account never enters a proof request.
//!
//! The virtual OS runs one invoke v3 from a deployed Cairo 1 account whose
//! nonce equals its nonce at the base block, and really runs its
//! `__validate__` (apollo_starknet_os_program .../execution_constraints__
//! virtual.cairo, execute_transaction_utils.cairo:73-75,
//! transaction_impls.cairo:325-330). Nothing about the sender reaches the
//! proof's public output: the message hash commits to `from_address` = the
//! prover contract, not the account (virtual_os_output.cairo:16-24,
//! execute_syscalls__virtual.cairo:303).
//!
//! So this account:
//!
//!   * accepts any signature (there is nothing to authorize: the statement
//!     is the prover's, and its `from_address` is what the store pins);
//!   * accepts ONLY zero-fee transactions. The virtual prover requires zero
//!     prices and tip (starknet_transaction_prover virtual_snos_prover.rs
//!     validate_zero_fee_fields), while the real gateway rejects zero
//!     resource bounds. So it can never transact on the real chain, its
//!     nonce stays 0 forever, and every member proves with the same
//!     (sender, nonce) — the request names no one;
//!   * forwards its calls (call_contract is legal in execute mode).
//!
//! Deployed once, by anyone; its address is a constant of the client.

#[starknet::contract(account)]
pub mod ZkmsgVirtualSenderV4 {
    use core::num::traits::Zero;
    use starknet::account::Call;
    use starknet::syscalls::{call_contract_syscall, get_execution_info_v3_syscall};
    use starknet::{SyscallResultTrait, VALIDATED, get_caller_address};

    #[storage]
    struct Storage {}

    /// Panics unless every price and the tip are zero.
    pub fn assert_zero_fee() {
        let tx = get_execution_info_v3_syscall().unwrap_syscall().tx_info;
        assert(tx.tip == 0, 'virtual only: tip');
        for bound in tx.resource_bounds {
            assert(*bound.max_price_per_unit == 0, 'virtual only: fee');
        }
    }

    #[external(v0)]
    fn __validate__(self: @ContractState, calls: Array<Call>) -> felt252 {
        assert(get_caller_address().is_zero(), 'protocol only');
        assert_zero_fee();
        VALIDATED
    }

    #[external(v0)]
    fn __execute__(ref self: ContractState, calls: Array<Call>) -> Array<Span<felt252>> {
        assert(get_caller_address().is_zero(), 'protocol only');
        let mut results: Array<Span<felt252>> = array![];
        for call in calls.span() {
            results
                .append(
                    call_contract_syscall(*call.to, *call.selector, *call.calldata)
                        .unwrap_syscall(),
                );
        }
        results
    }

    #[external(v0)]
    fn __validate_declare__(self: @ContractState, class_hash: felt252) -> felt252 {
        core::panic_with_felt252('virtual sender: no declare')
    }
}
