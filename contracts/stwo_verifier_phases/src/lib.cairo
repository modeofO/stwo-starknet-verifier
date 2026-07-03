//! Library classes for the two-phase Stwo circuit verification.
//!
//! The full verifier does not fit a single deployable class (its CASM
//! bytecode exceeds Starknet's 81,920-felt cap once both phases plus the
//! registry live together), so each phase is its own class. The
//! `StwoFactRegistry` contract invokes them via `library_call` — the phase
//! code executes in the registry's context but is stateless (pure compute
//! over calldata), so the classes carry no storage.
//!
//! See `resumable` for the verification logic and its soundness notes.

pub mod resumable;

#[starknet::interface]
pub trait IStwoPhase1<TContractState> {
    /// Runs verification phase 1 over the full packed proof. Returns the
    /// Serde-serialized `resumable::Checkpoint` (opaque to the caller).
    fn run_phase1(
        self: @TContractState, packed: Span<felt252>, n_values: u32,
    ) -> Array<felt252>;
}

#[starknet::interface]
pub trait IStwoPhase2<TContractState> {
    /// Runs verification phase 2: FRI decommitment of the packed
    /// `fri_proof` section against a phase-1 checkpoint. Returns the 8
    /// output-hash words on success; panics otherwise.
    fn run_phase2(
        self: @TContractState,
        fri_slots: Span<felt252>,
        n_fri_values: u32,
        checkpoint: Span<felt252>,
    ) -> [u32; 8];
}

/// The escape marker of the packed-proof encoding (see `unpack_proof`).
const ESCAPE: u32 = 0xFFFFFFFF;

/// Decodes the packed limb stream back into the proof's felt252 stream:
/// 7 little-endian u32 limbs per felt252 slot; a limb of `0xFFFFFFFF`
/// escapes a (low, high) u64 pair.
pub fn unpack_proof(packed: Span<felt252>, n_values: u32) -> Array<felt252> {
    let nz32: NonZero<u128> = 0x100000000_u128.try_into().unwrap();
    let mut limbs: Array<u32> = array![];
    for slot in packed {
        let v: u256 = (*slot).into();
        let (q, l0) = DivRem::div_rem(v.low, nz32);
        let (q, l1) = DivRem::div_rem(q, nz32);
        let (l3, l2) = DivRem::div_rem(q, nz32);
        let (q, l4) = DivRem::div_rem(v.high, nz32);
        let (l6, l5) = DivRem::div_rem(q, nz32);
        limbs.append(l0.try_into().unwrap());
        limbs.append(l1.try_into().unwrap());
        limbs.append(l2.try_into().unwrap());
        limbs.append(l3.try_into().unwrap());
        limbs.append(l4.try_into().unwrap());
        limbs.append(l5.try_into().unwrap());
        limbs.append(l6.try_into().unwrap());
    }

    let limbs = limbs.span();
    let mut values: Array<felt252> = array![];
    let mut i: usize = 0;
    while values.len() != n_values {
        let limb = *limbs[i];
        if limb == ESCAPE {
            let lo: felt252 = (*limbs[i + 1]).into();
            let hi: felt252 = (*limbs[i + 2]).into();
            values.append(lo + hi * 0x100000000);
            i += 3;
        } else {
            values.append(limb.into());
            i += 1;
        }
    }
    values
}

#[starknet::contract]
mod StwoPhase1 {
    use super::{IStwoPhase1, resumable, unpack_proof};

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl StwoPhase1Impl of IStwoPhase1<ContractState> {
        fn run_phase1(
            self: @ContractState, packed: Span<felt252>, n_values: u32,
        ) -> Array<felt252> {
            let values = unpack_proof(packed, n_values);
            let checkpoint = resumable::phase1(values.span());
            let mut serialized = array![];
            Serde::serialize(@checkpoint, ref serialized);
            serialized
        }
    }
}

#[starknet::contract]
mod StwoPhase2 {
    use super::{IStwoPhase2, resumable, unpack_proof};

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl StwoPhase2Impl of IStwoPhase2<ContractState> {
        fn run_phase2(
            self: @ContractState,
            fri_slots: Span<felt252>,
            n_fri_values: u32,
            checkpoint: Span<felt252>,
        ) -> [u32; 8] {
            let mut cp_span = checkpoint;
            let checkpoint: resumable::Checkpoint = Serde::deserialize(ref cp_span)
                .expect('checkpoint deser');
            let fri_values = unpack_proof(fri_slots, n_fri_values);
            resumable::phase2(fri_values.span(), checkpoint)
        }
    }
}
