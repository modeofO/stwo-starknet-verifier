//! Chunked claim mixing — monster 1 of the lane-2 sub-phasing
//! (docs/lane2-design.md). Reproduces `CairoClaim::mix_into`'s channel
//! digest while receiving the program section *in chunks across
//! transactions*, so no single transaction needs the whole claim in
//! calldata or pays the whole 6.45M-step mix.
//!
//! What `claim.mix_into` actually does (vendored `FlatClaim::mix_into` +
//! `PublicData::mix_into`, poseidon build), in transcript order:
//!
//! 1. four small `mix_felts` (enable-bit count, enable bits, component log
//!    sizes, program length) — cheap, done in `claim_mix_begin`;
//! 2. `mix_felts(pack_into_qm31s(public_claim))` where `public_claim` =
//!    `[states, segment ranges, safe-call ids, output ids, program ids…]` —
//!    the program ids arrive chunk-by-chunk, so this mix runs as a chunked
//!    sponge ([`ChunkedU32Mix`]);
//! 3. `mix_commitment(hash_small_vals(output values))` — small, computed in
//!    `begin` and applied in `finalize` (its value doesn't depend on the
//!    channel, only its mixing position does);
//! 4. `mix_commitment(hash_small_vals(program value limbs))` — THE monster
//!    (72k+ limbs for our fixture): runs as a chunked sponge
//!    ([`ChunkedSmallVals`]) fed by the same program-entry chunks.
//!
//! Chunk boundaries are program-entry boundaries; the two sponge states plus
//! the pending buffers serialize into the phase checkpoint (a few dozen
//! felts). Equivalence with the monolithic `claim.mix_into` is asserted over
//! the real fixture claim in `tests/test_claim_mix.cairo`.

use stwo_cairo_air::utils::split;
use stwo_verifier_core::channel::{Channel, ChannelTrait};
use stwo_verifier_core::fields::m31::M31_SHIFT;
use stwo_verifier_core::fields::qm31::QM31;
use stwo_verifier_core::utils::{pack_into_qm31s, pack_qm31};
use stwo_verifier_core::vcs::poseidon_hasher::hash_small_vals;
use stwo_verifier_utils::{MemorySection, add_length_padding};
use crate::sponge::{SpongeState, sponge_absorb, sponge_finalize, sponge_start};

/// Number of u32 values per derived felt in the `mix_felts ∘ pack_into_qm31s`
/// stream: 4 u32 per QM31, 2 QM31 per packed felt.
const U32S_PER_MIX_FELT: usize = 8;
/// Number of values per packed word in the `hash_small_vals` stream.
const VALS_PER_WORD: usize = 8;
/// Memory values are split into 28 nine-bit limbs.
const MEMORY_VALUES_LIMBS: usize = 28;

/// A pausable `channel.mix_felts(pack_into_qm31s(u32 stream))`: the channel's
/// own mix is a `poseidon_hash_span` over `[digest, packed pairs…]`, absorbed
/// here through the resumable sponge. `pending` buffers a partial 8-u32
/// group between chunks.
#[derive(Drop, Serde)]
pub struct ChunkedU32Mix {
    pub sponge: SpongeState,
    pub pending: Array<u32>,
}

/// Starts the mix on a channel whose digest is `digest` (the stream's first
/// absorbed element, exactly as `Poseidon252Channel::mix_felts` does).
pub fn u32_mix_start(digest: felt252) -> ChunkedU32Mix {
    let mut sponge = sponge_start();
    sponge_absorb(ref sponge, array![digest].span());
    ChunkedU32Mix { sponge, pending: array![] }
}

/// Absorbs a chunk of the u32 stream (any chunking).
pub fn u32_mix_absorb(ref self: ChunkedU32Mix, mut values: Span<u32>) {
    let ChunkedU32Mix { mut sponge, pending } = self;
    let mut buffer = pending;
    let mut derived: Array<felt252> = array![];
    loop {
        while buffer.len() != U32S_PER_MIX_FELT && !values.is_empty() {
            buffer.append(*values.pop_front().unwrap());
        }
        if buffer.len() != U32S_PER_MIX_FELT {
            break;
        }
        derived.append(pack_full_mix_felt(buffer.span()));
        buffer = array![];
    }
    sponge_absorb(ref sponge, derived.span());
    self = ChunkedU32Mix { sponge, pending: buffer };
}

/// Finishes the mix and returns the channel's next digest.
pub fn u32_mix_finalize(self: ChunkedU32Mix) -> felt252 {
    let ChunkedU32Mix { mut sponge, pending } = self;
    if !pending.is_empty() {
        // Mirror `pack_into_qm31s`'s zero-padded tail + `mix_felts`'s
        // odd-QM31 handling: < 8 leftover u32s form 1 or 2 QM31s.
        let qm31s = pack_into_qm31s(pending.span());
        let mut qm31s = qm31s;
        let tail = if let Some(pair) = qm31s.multi_pop_front::<2>() {
            let [x, y] = (*pair).unbox();
            pack_qm31(pack_qm31(1, x), y)
        } else {
            let x = *qm31s.pop_front().unwrap();
            pack_qm31(1, x)
        };
        sponge_absorb(ref sponge, array![tail].span());
    }
    sponge_finalize(sponge)
}

/// Packs a full 8-u32 group into one `mix_felts` stream felt.
fn pack_full_mix_felt(group: Span<u32>) -> felt252 {
    let mut qm31s = pack_into_qm31s(group);
    let pair = qm31s.multi_pop_front::<2>().unwrap();
    let [x, y]: [QM31; 2] = (*pair).unbox();
    pack_qm31(pack_qm31(1, x), y)
}

/// A pausable `hash_small_vals(initial, values)`: `poseidon_hash_span` over
/// `[initial…, 8-value words…, length-padded tail]`.
#[derive(Drop, Serde)]
pub struct ChunkedSmallVals {
    pub sponge: SpongeState,
    pub pending: Array<u32>,
}

pub fn small_vals_start(initial: Span<felt252>) -> ChunkedSmallVals {
    let mut sponge = sponge_start();
    sponge_absorb(ref sponge, initial);
    ChunkedSmallVals { sponge, pending: array![] }
}

pub fn small_vals_absorb(ref self: ChunkedSmallVals, mut values: Span<u32>) {
    let ChunkedSmallVals { mut sponge, pending } = self;
    let mut buffer = pending;
    let mut derived: Array<felt252> = array![];
    loop {
        while buffer.len() != VALS_PER_WORD && !values.is_empty() {
            buffer.append(*values.pop_front().unwrap());
        }
        if buffer.len() != VALS_PER_WORD {
            break;
        }
        let mut word: felt252 = 0;
        for v in buffer.span() {
            word = word * M31_SHIFT + (*v).into();
        }
        derived.append(word);
        buffer = array![];
    }
    sponge_absorb(ref sponge, derived.span());
    self = ChunkedSmallVals { sponge, pending: buffer };
}

pub fn small_vals_finalize(self: ChunkedSmallVals) -> felt252 {
    let ChunkedSmallVals { mut sponge, pending } = self;
    if !pending.is_empty() {
        let remainder_length = pending.len();
        let mut word: felt252 = 0;
        for v in pending.span() {
            word = word * M31_SHIFT + (*v).into();
        }
        sponge_absorb(ref sponge, array![add_length_padding(word, remainder_length)].span());
    }
    sponge_finalize(sponge)
}

/// The claim-mix pipeline state crossing transaction boundaries.
#[derive(Drop, Serde)]
pub struct ClaimMixState {
    /// The in-flight `mix_felts(public_claim)` (transcript step 2).
    pub public_mix: ChunkedU32Mix,
    /// The in-flight program-values hash (transcript step 4).
    pub program_vals: ChunkedSmallVals,
    /// `hash_small_vals(output values)`, precomputed (transcript step 3).
    pub output_hash: felt252,
}

/// First pipeline transaction: applies the four small flat-claim mixes to
/// the channel, precomputes the output hash, and opens the two chunked
/// absorbers. `public_claim_prefix` is everything of `public_claim` before
/// the program ids: `[states, segment ranges, safe-call ids, output ids]`.
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

    ClaimMixState {
        public_mix, program_vals: small_vals_start(array![].span()), output_hash,
    }
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
pub fn claim_mix_finalize(self: ClaimMixState) -> felt252 {
    let ClaimMixState { public_mix, program_vals, output_hash } = self;
    let mut channel = stwo_verifier_core::channel::poseidon252::new_channel(
        u32_mix_finalize(public_mix),
    );
    channel.mix_commitment(output_hash);
    channel.mix_commitment(small_vals_finalize(program_vals));
    channel.digest
}

/// Flattens a memory section's values into their 28-nine-bit-limb splits
/// (mirrors `PublicData::pack_into_u32s`'s value handling).
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
