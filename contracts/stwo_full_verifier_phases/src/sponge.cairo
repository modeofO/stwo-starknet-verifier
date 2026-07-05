//! A resumable `poseidon_hash_span`: the same sponge, but the state can pause
//! between absorption chunks and cross a phase boundary as a 4-felt
//! checkpoint.
//!
//! Why this is THE chunking primitive for lane 2: every big Fiat-Shamir
//! absorb in the poseidon verifier reduces to `poseidon_hash_span` over a
//! derived felt stream —
//! - `Poseidon252Channel::mix_felts` hashes `[digest, packed QM31 pairs…]`,
//! - `hash_u32s_with_state` hashes `[state, 7-word big-endian chunks…]`
//!   (this underlies `mix_memory_section` and `hash_small_vals`, i.e. the
//!   6.45M-step claim mix),
//! so splitting any of them across transactions = absorbing their stream in
//! chunks with this sponge and finalizing in the last chunk's transaction.
//! Chunk boundaries must fall on the derived stream's felt boundaries (QM31
//! pairs for `mix_felts`, 7-u32 groups for u32 streams).
//!
//! The state mirrors the corelib Poseidon `HashState` semantics exactly
//! (rate-2 sponge, `+1` padding on finalize); the equivalence with
//! `poseidon_hash_span` is asserted in tests for empty/even/odd streams.

use core::poseidon::hades_permutation;

/// Pausable sponge state. Serializes to 4 felts for a phase checkpoint.
#[derive(Drop, Serde, Copy, PartialEq, Debug)]
pub struct SpongeState {
    pub s0: felt252,
    pub s1: felt252,
    pub s2: felt252,
    /// True when one value of the current rate-2 block has been absorbed.
    pub odd: bool,
}

/// A fresh sponge (equivalent to starting `poseidon_hash_span`).
pub fn sponge_start() -> SpongeState {
    SpongeState { s0: 0, s1: 0, s2: 0, odd: false }
}

/// Absorbs a chunk of the stream. May be called any number of times, on any
/// chunking of the stream, including across transaction boundaries.
pub fn sponge_absorb(ref state: SpongeState, mut values: Span<felt252>) {
    let SpongeState { mut s0, mut s1, mut s2, mut odd } = state;
    for value in values {
        if odd {
            let (r0, r1, r2) = hades_permutation(s0, s1 + *value, s2);
            s0 = r0;
            s1 = r1;
            s2 = r2;
            odd = false;
        } else {
            s0 = s0 + *value;
            odd = true;
        }
    }
    state = SpongeState { s0, s1, s2, odd };
}

/// Applies the `+1` padding and returns the digest. Equal to
/// `poseidon_hash_span(stream)` for the concatenation of all absorbed chunks.
pub fn sponge_finalize(state: SpongeState) -> felt252 {
    let SpongeState { s0, s1, s2, odd } = state;
    let (r0, _, _) = if odd {
        hades_permutation(s0, s1 + 1, s2)
    } else {
        hades_permutation(s0 + 1, s1, s2)
    };
    r0
}

// The reference channel these tests compare against is the poseidon one;
// the sponge itself (fact hashing, binding digests) is build-independent.
#[cfg(test)]
#[cfg(feature: "poseidon252_verifier")]
mod tests {
    use core::poseidon::poseidon_hash_span;
    use stwo_verifier_core::channel::poseidon252::new_channel;
    use stwo_verifier_core::channel::ChannelTrait;
    use stwo_verifier_core::fields::m31::M31Trait;
    use stwo_verifier_core::fields::qm31::{QM31, QM31Trait};
    use stwo_verifier_core::utils::pack_qm31;
    use stwo_verifier_utils::hash_u32s_with_state;
    use super::{sponge_absorb, sponge_finalize, sponge_start};

    fn stream(n: usize) -> Array<felt252> {
        let mut values = array![];
        let mut i = 0;
        while i != n {
            values.append(('seed' + i.into()) * 0x10000000000000001);
            i += 1;
        }
        values
    }

    /// The sponge equals `poseidon_hash_span` for empty, odd and even
    /// lengths, absorbed in one chunk.
    #[test]
    fn test_matches_poseidon_hash_span() {
        for n in array![0_usize, 1, 2, 3, 8, 101].span() {
            let values = stream(*n);
            let mut state = sponge_start();
            sponge_absorb(ref state, values.span());
            assert!(sponge_finalize(state) == poseidon_hash_span(values.span()));
        }
    }

    /// Chunked absorption — including a serde round-trip of the state
    /// between chunks, as it would cross a transaction boundary — equals the
    /// monolithic hash.
    #[test]
    fn test_chunked_absorption_with_checkpoint_roundtrip() {
        let values = stream(1_001);
        let expected = poseidon_hash_span(values.span());

        let mut state = sponge_start();
        let mut remaining = values.span();
        loop {
            // Absorb in uneven chunks to exercise both parities.
            let chunk_len = core::cmp::min(remaining.len(), 137);
            if chunk_len == 0 {
                break;
            }
            let chunk = remaining.slice(0, chunk_len);
            remaining = remaining.slice(chunk_len, remaining.len() - chunk_len);
            sponge_absorb(ref state, chunk);

            // Simulate the phase boundary: serialize + deserialize the state.
            let mut serialized = array![];
            Serde::serialize(@state, ref serialized);
            let mut span = serialized.span();
            state = Serde::deserialize(ref span).unwrap();
        }
        assert!(sponge_finalize(state) == expected);
    }

    /// Chunked reproduction of `Poseidon252Channel::mix_felts`: the channel's
    /// stream is `[digest, pack_qm31(pack_qm31(1, x), y) per pair, and
    /// pack_qm31(1, tail)]`; absorbing it in chunks yields the same digest
    /// the monolithic mix produces. Chunk boundaries = QM31 pair boundaries.
    #[test]
    fn test_chunked_mix_felts() {
        // 11 QM31s: exercises the odd-tail branch too.
        let mut felts: Array<QM31> = array![];
        let mut i = 0_u32;
        while i != 11 {
            felts
                .append(
                    QM31Trait::from_fixed_array(
                        [
                            M31Trait::reduce_u32(7 * i + 1), M31Trait::reduce_u32(11 * i + 2),
                            M31Trait::reduce_u32(13 * i + 3), M31Trait::reduce_u32(17 * i + 5),
                        ],
                    ),
                );
            i += 1;
        }
        let initial_digest = 'lane2-digest';

        // Monolithic reference.
        let mut channel = new_channel(initial_digest);
        channel.mix_felts(felts.span());
        let expected = channel.digest;

        // Chunked: derive the packed stream, absorb in two chunks.
        let mut packed = array![];
        let mut span = felts.span();
        while let Some(pair) = span.multi_pop_front::<2>() {
            let [x, y] = (*pair).unbox();
            packed.append(pack_qm31(pack_qm31(1, x), y));
        }
        if let Some(x) = span.pop_front() {
            packed.append(pack_qm31(1, *x));
        }

        let mut state = sponge_start();
        sponge_absorb(ref state, array![initial_digest].span());
        let packed = packed.span();
        sponge_absorb(ref state, packed.slice(0, 3));
        sponge_absorb(ref state, packed.slice(3, packed.len() - 3));
        assert!(sponge_finalize(state) == expected);
    }

    /// Chunked reproduction of `hash_u32s_with_state` (the primitive under
    /// the claim mix): its stream is `[state, 7-word BE chunks…]`.
    #[test]
    fn test_chunked_hash_u32s_with_state() {
        // 98 words = 14 exact 7-word groups (no length-padding tail).
        let mut words: Array<u32> = array![];
        let mut i = 0_u32;
        while i != 98 {
            words.append(0x01000193 * (i + 1));
            i += 1;
        }
        let initial_state = 'u32-state';
        let expected = hash_u32s_with_state(initial_state, words.span());

        // Derive the felt stream: construct_f252_be per 7-word group.
        let mut derived: Array<felt252> = array![initial_state];
        let mut span = words.span();
        while let Some(chunk) = span.multi_pop_front::<7>() {
            let [w0, w1, w2, w3, w4, w5, w6] = (*chunk).unbox();
            let mut f: felt252 = w0.into();
            f = f * 0x100000000 + w1.into();
            f = f * 0x100000000 + w2.into();
            f = f * 0x100000000 + w3.into();
            f = f * 0x100000000 + w4.into();
            f = f * 0x100000000 + w5.into();
            f = f * 0x100000000 + w6.into();
            derived.append(f);
        }

        let derived = derived.span();
        let mut state = sponge_start();
        sponge_absorb(ref state, derived.slice(0, 5));
        sponge_absorb(ref state, derived.slice(5, derived.len() - 5));
        assert!(sponge_finalize(state) == expected);
    }
}
