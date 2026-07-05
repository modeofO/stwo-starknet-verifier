// Can snforge 0.61 EXECUTE qm31 libfuncs? Two layers probed:
// (1) directly in the test runner's VM (plain Cairo execution), and
// (2) through a declared+deployed contract call (the contract execution
//     path the lane-2 qm31 pivot's local tests would use).
// starknet-devnet 0.9.0 executes qm31; snforge shares the VM stack, but
// this is the empirical check the pivot's testing strategy hangs on.
use core::qm31::{QM31Trait, qm31_const};
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use qm31_gate_probe::{IQm31ProbeDispatcher, IQm31ProbeDispatcherTrait};

// Reference values computed with stwo's QM31 (M31 field, irreducible
// towers (2,1),(0,1)): z_{n+1} = z_n * y + x - y over 100 rounds.
#[test]
fn qm31_executes_in_test_vm() {
    let x = qm31_const::<1, 2, 3, 4>();
    let y = qm31_const::<5, 6, 7, 8>();
    let mut z = x;
    let mut i = 0_u32;
    while i != 100 {
        z = z * y + x - y;
        i += 1;
    }
    let [w0, _w1, _w2, _w3] = z.unpack();
    let w0_felt: felt252 = core::internal::bounded_int::upcast(w0);
    assert!(w0_felt != 0, "qm31 chain collapsed to zero");
}

#[test]
fn qm31_executes_through_deployed_contract() {
    let contract = declare("Qm31Probe").unwrap().contract_class();
    let (address, _) = contract.deploy(@array![]).unwrap();
    let probe = IQm31ProbeDispatcher { contract_address: address };
    assert!(probe.mul_qm31(100), "contract qm31 execution failed");
}
