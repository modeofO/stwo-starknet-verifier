//! Consumer-side fact binding for `StwoFactRegistry` facts (lane 1, the
//! recursion route).
//!
//! A registered fact is `poseidon(output_hash words)` where `output_hash` is
//! the on-chain circuit verifier's `blake2s(multiverifier_root ‖ output
//! values)`. Those output values are the head of a blake2s chain that binds,
//! through the multiverifier and cairo-verifier circuits, down to the
//! *application* program hash and outputs (via the privacy bootloader's
//! output preimage). This library recomputes the whole chain from
//! application-level data, so a consumer contract can do:
//!
//! ```text
//! let fact = compute_fact(MY_PROGRAM_HASH, claimed_outputs, MY_INNER_ROOT);
//! assert!(registry.is_valid(fact), "no proof for these outputs");
//! ```
//!
//! `MY_INNER_ROOT` is the preprocessed root of the cairo-verifier circuit
//! configured for the app's proof shape (component set); it is deterministic
//! and printed by the wrap stage (`privacy_prove_cairo_bridge wrap`). It must
//! be whitelisted per application — it is what binds "a proof of *the
//! bootloader running my program*" (see docs/proof-only-wrapping.md).
//!
//! Chain layout (all hashes blake2s-256 over little-endian u32 word streams,
//! mirroring stwo-circuits at the pinned rev — see docs/how-it-works.md):
//!
//! 1. `V = blake2s_felt252(preimage)` where
//!    `preimage = [n_tasks=1, output_len=outputs.len()+2, program_hash, outputs…]`
//!    (the privacy simple bootloader's output section; felt encoding: 2 words
//!    if < 2^63 else 8 big-endian words with an MSB marker).
//! 2. `inner = blake2s(V as 28 nine-bit little-endian limbs, one u32 word each)`
//!    — the cairo-verifier circuit's reserved output values.
//! 3. `mv = blake2s([inner_root(8 full words) ‖ inner as (lo16,hi16,0,0)×8] × 2)`
//!    — the multiverifier hashes its two (identical, single-payload) inputs.
//! 4. `output_hash = blake2s(multiverifier_root ‖ mv as (lo16,hi16,0,0)×8)`
//!    — computed on-chain by the circuit verifier (`get_verification_output`).
//! 5. `fact = poseidon(output_hash words)` — `fact_from_words` in the registry.

use stwo_verifier_utils::blake2s::{encode_felt_in_limbs_to_array, hash_u32s};
use stwo_verifier_utils::{construct_f252, deconstruct_f252};

/// Preprocessed root of the multiverifier circuit pinned by the deployed
/// phase classes (`stwo_circuit_air::privacy_consts::preprocessed_root`).
pub const MULTIVERIFIER_ROOT: [u32; 8] = [
    4268871180, 1648605015, 1518856044, 936813334, 8391980, 3571729286, 3315525509, 1034558230,
];

/// Recomputes the registry fact for an application program hash and its
/// public outputs, under the given inner cairo-verifier circuit root and the
/// pinned [`MULTIVERIFIER_ROOT`].
pub fn compute_fact(
    program_hash: felt252, outputs: Span<felt252>, inner_root: [u32; 8],
) -> felt252 {
    compute_fact_with_roots(program_hash, outputs, inner_root, MULTIVERIFIER_ROOT)
}

/// [`compute_fact`] with an explicit multiverifier root (for future class
/// upgrades under the registry's governed route list).
pub fn compute_fact_with_roots(
    program_hash: felt252, outputs: Span<felt252>, inner_root: [u32; 8], mv_root: [u32; 8],
) -> felt252 {
    // 1. The bootloader output preimage and its felt252 blake hash V.
    let mut preimage = array![1, (outputs.len() + 2).into(), program_hash];
    preimage.append_span(outputs);
    let v = blake2s_felt252(preimage.span());

    // 2. The inner circuit's output digest: blake2s over V's 28 nine-bit limbs.
    let inner = hash_u32s(split_9bit_limbs(deconstruct_f252(v)).span());

    // 3. The multiverifier digest over its two (identical) inputs.
    let mut mv_input = array![];
    let mut i = 0;
    while i != 2 {
        mv_input.append_span(inner_root.span());
        append_words_as_16bit_quads(inner, ref mv_input);
        i += 1;
    }
    let mv = hash_u32s(mv_input.span());

    // 4. The on-chain verification output hash.
    let mut oh_input = array![];
    oh_input.append_span(mv_root.span());
    append_words_as_16bit_quads(mv, ref oh_input);
    let [w0, w1, w2, w3, w4, w5, w6, w7] = hash_u32s(oh_input.span()).unbox();

    // 5. The fact (mirrors `stwo_fact_registry::fact_from_words`).
    core::poseidon::poseidon_hash_span(
        array![
            w0.into(), w1.into(), w2.into(), w3.into(), w4.into(), w5.into(), w6.into(),
            w7.into(),
        ]
            .span(),
    )
}

/// Blake2s-256 of felt252 values under the Cairo felt-encoding (2 u32 words
/// for values < 2^63, else 8 big-endian words with an MSB marker), packed
/// back into a felt252 from the 8 little-endian digest words. Matches
/// `starknet_types_core::hash::Blake2Felt252::encode_felt252_data_and_calc_blake_hash`.
pub fn blake2s_felt252(values: Span<felt252>) -> felt252 {
    let mut encoded = array![];
    for value in values {
        encode_felt_in_limbs_to_array(deconstruct_f252(*value).unbox(), ref encoded);
    }
    construct_f252(hash_u32s(encoded.span()))
}

/// Splits a felt252 (as 8 little-endian u32 words) into 28 nine-bit
/// little-endian limbs, each returned as one u32. Mirrors the memory-value
/// limb encoding (`split_f252` in the vendored verifier / `Felt252::get_limbs`
/// prover-side).
fn split_9bit_limbs(words: Box<[u32; 8]>) -> Array<u32> {
    let words = words.unbox();
    let mut res = array![];
    let mut word_iter = words.span().into_iter();
    let mut word: u32 = *word_iter.next().unwrap();
    let mut n_bits_in_word: u32 = 32;
    let shift: NonZero<u32> = 0x200;
    for _ in 0_u32..28 {
        if n_bits_in_word > 9 {
            let (high, low) = DivRem::div_rem(word, shift);
            res.append(low);
            word = high;
            n_bits_in_word -= 9;
            continue;
        }

        let mut segment = word;
        word = *word_iter.next().unwrap_or(@0);
        if n_bits_in_word < 9 {
            // Take the missing (9 - n_bits_in_word) low bits from the next word.
            let missing = 9 - n_bits_in_word;
            let mask: u32 = pow2(missing) - 1;
            segment = segment + (word & mask) * pow2(n_bits_in_word);
            word = word / pow2(missing);
        }
        res.append(segment);
        n_bits_in_word += 32 - 9;
    }
    res
}

/// Appends each 32-bit digest word as the four u32 words
/// `(low_u16, high_u16, 0, 0)` — the QM31 word encoding used by the
/// stwo-circuits blake gadget when digests re-enter a hash preimage.
fn append_words_as_16bit_quads(words: Box<[u32; 8]>, ref out: Array<u32>) {
    let shift: NonZero<u32> = 0x10000;
    for word in words.unbox().span() {
        let (high, low) = DivRem::div_rem(*word, shift);
        out.append(low);
        out.append(high);
        out.append(0);
        out.append(0);
    }
}

fn pow2(n: u32) -> u32 {
    let mut res = 1_u32;
    for _ in 0..n {
        res *= 2;
    }
    res
}

#[cfg(test)]
mod tests {
    use super::{blake2s_felt252, compute_fact};

    /// The registered Sepolia fact for `poseidon_chain(100)` (see
    /// docs/lane1-results.md): registry 0x0194f440…c6aa, first on-chain
    /// verified Stwo fact.
    const LIVE_FACT: felt252 = 0x640299e88691d8a8eaf2c71bcde2c72334ad177e64c4485be069c5f6dcd615c;
    const PROGRAM_HASH: felt252 = 0x30443b3c06493c96351267eb1284996c2f91ac8b5165ee72ec0a597074721f3;
    const CHAIN_RESULT: felt252 = 0x10bd76b6949e70c61bbf65ce6a2ab151abe94ed26577475d58e23a09c50b721;

    /// Inner cairo-verifier circuit root for the poseidon_chain fixture's
    /// component set (printed by `privacy_prove_cairo_bridge wrap`).
    const INNER_ROOT_POSEIDON_CHAIN: [u32; 8] = [
        2674953418, 3988685724, 1385424428, 1661362028, 3534442848, 356489633, 2101289576,
        2757001180,
    ];

    /// Cross-check of the felt252 blake encoding against
    /// `starknet-types-core`'s `test_hash_array_one_two` vector.
    #[test]
    fn test_blake2s_felt252_reference_vector() {
        let h = blake2s_felt252(array![1, 2].span());
        assert!(h == 0x5534c03a14b214436366f30e9c77b6e56c8835de7dc5aee36957d4384cce66d);
    }

    /// End-to-end: recompute the live Sepolia fact from application data.
    #[test]
    fn test_reproduces_live_fact() {
        let fact = compute_fact(
            PROGRAM_HASH, array![CHAIN_RESULT].span(), INNER_ROOT_POSEIDON_CHAIN,
        );
        assert!(fact == LIVE_FACT);
    }
}
