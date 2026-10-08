//! TEST FIXTURE ONLY (never deployed): a minimal ERC20 with an open `mint`,
//! standing in for STRK in snforge tests of `buy_tickets`.

#[starknet::interface]
pub trait IMockStrk<T> {
    fn mint(ref self: T, to: starknet::ContractAddress, amount: u256);
    fn approve(ref self: T, spender: starknet::ContractAddress, amount: u256) -> bool;
    fn transfer_from(
        ref self: T,
        sender: starknet::ContractAddress,
        recipient: starknet::ContractAddress,
        amount: u256,
    ) -> bool;
    fn balance_of(self: @T, account: starknet::ContractAddress) -> u256;
}

#[starknet::contract]
pub mod MockStrk {
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};
    use starknet::{ContractAddress, get_caller_address};

    #[storage]
    struct Storage {
        balances: Map<ContractAddress, u256>,
        allowances: Map<(ContractAddress, ContractAddress), u256>,
    }

    #[abi(embed_v0)]
    impl MockStrkImpl of super::IMockStrk<ContractState> {
        fn mint(ref self: ContractState, to: ContractAddress, amount: u256) {
            self.balances.write(to, self.balances.read(to) + amount);
        }

        fn approve(ref self: ContractState, spender: ContractAddress, amount: u256) -> bool {
            self.allowances.write((get_caller_address(), spender), amount);
            true
        }

        fn transfer_from(
            ref self: ContractState,
            sender: ContractAddress,
            recipient: ContractAddress,
            amount: u256,
        ) -> bool {
            let spender = get_caller_address();
            let allowance = self.allowances.read((sender, spender));
            assert(allowance >= amount, 'insufficient allowance');
            let balance = self.balances.read(sender);
            assert(balance >= amount, 'insufficient balance');
            self.allowances.write((sender, spender), allowance - amount);
            self.balances.write(sender, balance - amount);
            self.balances.write(recipient, self.balances.read(recipient) + amount);
            true
        }

        fn balance_of(self: @ContractState, account: ContractAddress) -> u256 {
            self.balances.read(account)
        }
    }
}
