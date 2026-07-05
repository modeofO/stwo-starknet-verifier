#[starknet::interface]
pub trait IQm31Probe<TContractState> {
    fn mul_qm31(self: @TContractState, rounds: u32) -> bool;
}

#[starknet::contract]
mod Qm31Probe {
    use core::qm31::{QM31Trait, qm31_const};
    use super::IQm31Probe;

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl Impl of IQm31Probe<ContractState> {
        fn mul_qm31(self: @ContractState, rounds: u32) -> bool {
            let x = qm31_const::<1, 2, 3, 4>();
            let y = qm31_const::<5, 6, 7, 8>();
            let mut z = x;
            let mut i = 0_u32;
            while i != rounds {
                z = z * y + x - y;
                i += 1;
            }
            let [w0, _w1, _w2, _w3] = z.unpack();
            let w0_felt: felt252 = core::internal::bounded_int::upcast(w0);
            w0_felt != 0
        }
    }
}
