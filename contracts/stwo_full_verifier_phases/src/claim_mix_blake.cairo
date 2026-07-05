//! Chunked claim mixing, blake2s (qm31-pivot) build — the counterpart of
//! `claim_mix.cairo` for the vendored verifier's default channel. Same
//! transcript, same API, different hash plumbing:
//!
//! 1. four small `mix_felts` — cheap, done in `claim_mix_begin`;
//! 2. `mix_felts(pack_into_qm31s(public_claim))` — ONE blake2s hash over
//!    `digest ‖ 4 words per QM31` (the program ids are the stream's tail,
//!    arriving chunk-by-chunk) — runs as a pausable compression
//!    ([`ChunkedU32Mix`] over [`BlakeAbsorber`]);
//! 3. `mix_commitment(hash_small_vals(output values))` — small, precomputed
//!    in `begin`, applied in `finalize`;
//! 4. `mix_commitment(hash_small_vals(program value limbs))` — the blake
//!    `hash_small_vals` is `hash_u32s` (a plain blake2s over the 28-limb
//!    splits, ~72k words for our fixture): a second pausable compression
//!    ([`ChunkedSmallVals`]).
//!
//! The pausable state is tiny and serde-able: 8 state words + byte count +
//! ≤16 pending words per absorber. Chunk boundaries are program-entry
//! boundaries, exactly as in the poseidon build; `pending` buffers partial
//! blocks between chunks. Equivalence with the monolithic `claim.mix_into`
//! is asserted over the real blake fixture claim in
//! `tests/test_machine_blake.cairo`.

use core::blake::{blake2s_compress, blake2s_finalize};
use core::box::BoxImpl;
use stwo_cairo_air::utils::split;
use stwo_verifier_core::channel::{Channel, ChannelTrait};
use stwo_verifier_core::utils::pack_into_qm31s;
use stwo_verifier_core::vcs::blake2s_hasher::{Blake2sHash, hash_small_vals};
use stwo_verifier_core::Hash;
use stwo_verifier_utils::{BLAKE2S_256_INITIAL_STATE, MemorySection};

/// u32 words per QM31 in the `mix_felts ∘ pack_into_qm31s` stream.
const WORDS_PER_QM31: usize = 4;
/// Words per blake2s message block.
const WORDS_PER_BLOCK: usize = 16;
/// Memory values are split into 28 nine-bit limbs (same in both builds).
const MEMORY_VALUES_LIMBS: usize = 28;

/// A pausable cumulative blake2s: compression state over completed 16-word
/// blocks + total real byte count + the words of the block in flight.
/// Compression is lazy (a full pending block is compressed only when more
/// words arrive), so `finalize` sees the true last block — exactly the
/// vendored `mix_felts` / `hash_u32s` block structure.
///
/// `state` reuses [`Blake2sHash`] purely for its 8-u32 Box + Serde; it holds
/// a compression state here, not a hash.
#[derive(Drop, Serde)]
pub struct BlakeAbsorber {
    pub state: Blake2sHash,
    pub byte_count: u32,
    pub pending: Array<u32>,
}

fn absorber_start() -> BlakeAbsorber {
    BlakeAbsorber {
        state: Blake2sHash { hash: BoxImpl::new(BLAKE2S_256_INITIAL_STATE) },
        byte_count: 0,
        pending: array![],
    }
}

fn absorber_absorb(ref self: BlakeAbsorber, mut words: Span<u32>) {
    let BlakeAbsorber { state, mut byte_count, pending } = self;
    let mut state = state.hash;
    let mut pending = pending;
    for word in words {
        if pending.len() == WORDS_PER_BLOCK {
            let msg: Box<[u32; 16]> = *pending.span().try_into().unwrap();
            state = blake2s_compress(state, byte_count, msg);
            pending = array![];
        }
        pending.append(*word);
        byte_count += 4;
    }
    self = BlakeAbsorber { state: Blake2sHash { hash: state }, byte_count, pending };
}

fn absorber_finalize(self: BlakeAbsorber) -> Blake2sHash {
    let BlakeAbsorber { state, byte_count, mut pending } = self;
    for _ in pending.len()..WORDS_PER_BLOCK {
        pending.append(0);
    }
    let msg: Box<[u32; 16]> = *pending.span().try_into().unwrap();
    Blake2sHash { hash: blake2s_finalize(state.hash, byte_count, msg) }
}

/// A pausable `channel.mix_felts(pack_into_qm31s(u32 stream))`: blake2s over
/// `digest words ‖ stream words`, where `pack_into_qm31s` zero-pads the
/// stream's tail to a whole QM31 (4 words, bytes COUNTED) and `mix_felts`
/// zero-pads the last block to 16 words (bytes not counted). `pending_vals`
/// buffers a partial 4-word group between chunks.
#[derive(Drop, Serde)]
pub struct ChunkedU32Mix {
    pub absorber: BlakeAbsorber,
    pub pending_vals: Array<u32>,
}

/// Starts the mix on a channel whose digest is `digest` (the stream's first
/// 8 words, exactly as `Blake2sChannel::mix_felts` does).
pub fn u32_mix_start(digest: Hash) -> ChunkedU32Mix {
    let mut absorber = absorber_start();
    let [d0, d1, d2, d3, d4, d5, d6, d7] = digest.hash.unbox();
    absorber_absorb(ref absorber, array![d0, d1, d2, d3, d4, d5, d6, d7].span());
    ChunkedU32Mix { absorber, pending_vals: array![] }
}

/// Absorbs a chunk of the u32 stream (any chunking).
pub fn u32_mix_absorb(ref self: ChunkedU32Mix, mut values: Span<u32>) {
    let ChunkedU32Mix { mut absorber, pending_vals } = self;
    let mut buffer = pending_vals;
    let mut whole: Array<u32> = array![];
    loop {
        while buffer.len() != WORDS_PER_QM31 && !values.is_empty() {
            buffer.append(*values.pop_front().unwrap());
        }
        if buffer.len() != WORDS_PER_QM31 {
            break;
        }
        whole.append_span(buffer.span());
        buffer = array![];
    }
    absorber_absorb(ref absorber, whole.span());
    self = ChunkedU32Mix { absorber, pending_vals: buffer };
}

/// Finishes the mix and returns the channel's next digest.
pub fn u32_mix_finalize(self: ChunkedU32Mix) -> Hash {
    let ChunkedU32Mix { mut absorber, pending_vals } = self;
    if !pending_vals.is_empty() {
        // pack_into_qm31s's zero-padded tail QM31: the pad words are real
        // stream bytes.
        let mut tail = pending_vals;
        for _ in tail.len()..WORDS_PER_QM31 {
            tail.append(0);
        }
        absorber_absorb(ref absorber, tail.span());
    }
    absorber_finalize(absorber)
}

/// A pausable blake `hash_small_vals` = `hash_u32s(values)`: a plain
/// cumulative blake2s over the word stream (no digest prefix).
#[derive(Drop, Serde)]
pub struct ChunkedSmallVals {
    pub absorber: BlakeAbsorber,
}

pub fn small_vals_start() -> ChunkedSmallVals {
    ChunkedSmallVals { absorber: absorber_start() }
}

pub fn small_vals_absorb(ref self: ChunkedSmallVals, values: Span<u32>) {
    let ChunkedSmallVals { mut absorber } = self;
    absorber_absorb(ref absorber, values);
    self = ChunkedSmallVals { absorber };
}

pub fn small_vals_finalize(self: ChunkedSmallVals) -> Blake2sHash {
    absorber_finalize(self.absorber)
}

/// The claim-mix pipeline state crossing transaction boundaries.
#[derive(Drop, Serde)]
pub struct ClaimMixState {
    /// The in-flight `mix_felts(public_claim)` (transcript step 2).
    pub public_mix: ChunkedU32Mix,
    /// The in-flight program-values hash (transcript step 4).
    pub program_vals: ChunkedSmallVals,
    /// `hash_small_vals(output values)`, precomputed (transcript step 3).
    pub output_hash: Hash,
}

/// First pipeline transaction — same contract as the poseidon build's
/// `claim_mix_begin` (see claim_mix.cairo).
pub fn claim_mix_begin(
    ref channel: Channel,
    enable_bits: Span<bool>,
    component_log_sizes: Span<u32>,
    public_claim_prefix: Span<u32>,
    output_section: MemorySection,
    program_len: u32,
) -> ClaimMixState {
    // Transcript step 1 (mirrors FlatClaim::mix_into's small mixes).
    channel.mix_felts(pack_into_qm31s(array![enable_bits.len()].span()));
    channel.mix_felts(pack_into_qm31s(enable_bits_to_u32s(enable_bits)));
    channel.mix_felts(pack_into_qm31s(component_log_sizes));
    channel.mix_felts(pack_into_qm31s(array![program_len].span()));

    // Transcript step 3's value (position applied in finalize).
    let output_hash = hash_small_vals(array![], section_value_limbs(output_section).span());

    // Open step 2's chunked mix on the current digest and feed the prefix.
    let mut public_mix = u32_mix_start(channel.digest);
    u32_mix_absorb(ref public_mix, public_claim_prefix);

    ClaimMixState { public_mix, program_vals: small_vals_start(), output_hash }
}

/// Middle pipeline transactions: absorb a chunk of program entries — ids
/// into the public-claim mix, 28-limb value splits into the program hash.
pub fn claim_mix_absorb_program_entries(ref self: ClaimMixState, entries: MemorySection) {
    let ClaimMixState { mut public_mix, mut program_vals, output_hash } = self;
    let mut ids: Array<u32> = array![];
    for entry in entries {
        let (id, _value) = entry;
        ids.append(*id);
    }
    u32_mix_absorb(ref public_mix, ids.span());
    small_vals_absorb(ref program_vals, section_value_limbs(entries).span());
    self = ClaimMixState { public_mix, program_vals, output_hash };
}

/// Last pipeline transaction: closes both absorbers and applies transcript
/// steps 2–4 to the channel. The returned channel digest equals the
/// monolithic `claim.mix_into`'s.
pub fn claim_mix_finalize(self: ClaimMixState) -> Hash {
    let ClaimMixState { public_mix, program_vals, output_hash } = self;
    let mut channel = crate::channel_compat::new_channel(u32_mix_finalize(public_mix));
    channel.mix_commitment(output_hash);
    channel.mix_commitment(small_vals_finalize(program_vals));
    channel.digest
}

/// Flattens a memory section's values into their 28-nine-bit-limb splits
/// (mirrors `PublicData::pack_into_u32s`'s value handling — identical in
/// both builds).
fn section_value_limbs(section: MemorySection) -> Array<u32> {
    let mut limbs: Array<u32> = array![];
    for entry in section {
        let (_id, value) = *entry;
        let split_limbs: [u32; MEMORY_VALUES_LIMBS] = split(value);
        limbs.append_span(split_limbs.span());
    }
    limbs
}

/// Mirrors the private `enable_bits_to_u32s` in the vendored claim module.
fn enable_bits_to_u32s(enable_bits: Span<bool>) -> Span<u32> {
    let mut res = array![];
    for bit in enable_bits {
        res.append(if *bit {
            1_u32
        } else {
            0_u32
        });
    }
    res.span()
}
