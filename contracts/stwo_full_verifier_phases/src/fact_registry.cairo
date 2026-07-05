//! The shared fact registry — the convergence point of the two-lane
//! architecture (docs/architecture.md): verifier ROUTES write facts,
//! consumers read them via `is_valid(fact)` and never talk to a verifier
//! directly.
//!
//! The route set is governed: the owner adds routes (the lane-2
//! `StwoVerifierRouter`, eventually a lane-1 registry adapter) and then
//! freezes the list — after `freeze_routes` the set is immutable forever.
//! A swappable verifier is a rug vector, so consumers should check
//! `routes_frozen()` before trusting a deployment.
//!
//! Fact definitions are per-route (a fact is just a felt): the lane-2
//! router registers `poseidon(program_hash, output_hash)` where both
//! hashes are the vendored `encode_and_hash_memory_section` of the claim's
//! program/output sections — identical across the poseidon and blake
//! builds, so the pivot does not change any consumer.

use starknet::ContractAddress;

#[starknet::interface]
pub trait IStwoSharedFactRegistry<TContractState> {
    /// Registers a fact. Callable only by a registered route.
    fn register_fact(ref self: TContractState, fact: felt252);
    /// True iff `fact` was registered by a route.
    fn is_valid(self: @TContractState, fact: felt252) -> bool;
    /// Adds a verifier route. Owner-only; rejected once frozen.
    fn add_route(ref self: TContractState, route: ContractAddress);
    /// Freezes the route set forever. Owner-only.
    fn freeze_routes(ref self: TContractState);
    fn is_route(self: @TContractState, route: ContractAddress) -> bool;
    fn routes_frozen(self: @TContractState) -> bool;
    fn owner(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod StwoSharedFactRegistry {
    use starknet::storage::{
        Map, StoragePathEntry, StoragePointerReadAccess, StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_caller_address};
    use super::IStwoSharedFactRegistry;

    #[storage]
    struct Storage {
        owner: ContractAddress,
        frozen: bool,
        routes: Map<ContractAddress, bool>,
        facts: Map<felt252, bool>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        FactRegistered: FactRegistered,
        RouteAdded: RouteAdded,
        RoutesFrozen: RoutesFrozen,
    }

    #[derive(Drop, starknet::Event)]
    struct FactRegistered {
        #[key]
        fact: felt252,
        route: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct RouteAdded {
        route: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct RoutesFrozen {}

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        self.owner.write(owner);
    }

    #[abi(embed_v0)]
    impl Impl of IStwoSharedFactRegistry<ContractState> {
        fn register_fact(ref self: ContractState, fact: felt252) {
            let route = get_caller_address();
            assert(self.routes.entry(route).read(), 'registry: not a route');
            self.facts.entry(fact).write(true);
            self.emit(FactRegistered { fact, route });
        }

        fn is_valid(self: @ContractState, fact: felt252) -> bool {
            self.facts.entry(fact).read()
        }

        fn add_route(ref self: ContractState, route: ContractAddress) {
            assert(get_caller_address() == self.owner.read(), 'registry: not owner');
            assert(!self.frozen.read(), 'registry: routes frozen');
            self.routes.entry(route).write(true);
            self.emit(RouteAdded { route });
        }

        fn freeze_routes(ref self: ContractState) {
            assert(get_caller_address() == self.owner.read(), 'registry: not owner');
            self.frozen.write(true);
            self.emit(RoutesFrozen {});
        }

        fn is_route(self: @ContractState, route: ContractAddress) -> bool {
            self.routes.entry(route).read()
        }

        fn routes_frozen(self: @ContractState) -> bool {
            self.frozen.read()
        }

        fn owner(self: @ContractState) -> ContractAddress {
            self.owner.read()
        }
    }
}
