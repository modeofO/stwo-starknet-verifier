//! TEST DOUBLE — a fact registry whose facts are set directly, so the
//! store's send path can be exercised without running a real lane-1
//! verification. NEVER deploy this to a public network; the production
//! constructor argument is the live `StwoFactRegistry`.

#[starknet::interface]
pub trait IMockFactRegistry<TContractState> {
    fn set_valid(ref self: TContractState, fact: felt252);
    fn is_valid(self: @TContractState, fact: felt252) -> bool;
}

#[starknet::contract]
pub mod MockFactRegistry {
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};

    #[storage]
    struct Storage {
        facts: Map<felt252, bool>,
    }

    #[abi(embed_v0)]
    impl MockImpl of super::IMockFactRegistry<ContractState> {
        fn set_valid(ref self: ContractState, fact: felt252) {
            self.facts.write(fact, true);
        }

        fn is_valid(self: @ContractState, fact: felt252) -> bool {
            self.facts.read(fact)
        }
    }
}
