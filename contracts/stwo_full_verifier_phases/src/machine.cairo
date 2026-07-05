//! The production-shaped N-phase verification machine (machine plan v2,
//! docs/lane2-design.md): one pure function per transaction type, explicit
//! serde-able checkpoint state between them, per-section binding digests
//! replacing the skeleton's whole-stream `proof_hash`. The full sequence over
//! the real fixture proof is proven equivalent to the monolithic verifier in
//! `tests/test_machine.cairo`.
//!
//! ## Transaction sequence (fixture: 2,597 program entries, 70 queries)
//!
//! 1. `machine_begin(head)` — claim checks + transcript start.
//! 2. × N_chunks `machine_claim_chunk(entries)` — the claim-mix pipeline.
//! 3. `machine_claim_finalize(head)` — close the mix, trace commit,
//!    interaction PoW.
//! 4. × N `machine_lookup_chunk(entries)` — program entries re-supplied
//!    (rolling-digest-bound), logup accumulator.
//! 5. `machine_lookup_finalize(head)` — non-program logup terms, zero
//!    check, interaction claim mix + commit.
//! 6. `machine_oods_mix(head, sampled)` — composition commit, OODS draw +
//!    check, `mix_sampled_values`; saves the sampled-section digest.
//! 7. `machine_fri_commit(head, fri)` — FRI commitment walk, queries PoW,
//!    query sampling.
//! 8. × N_groups `machine_group(head, sampled, rows, witnesses)` — fused
//!    Merkle verification + `fri_answers` per query group (bridge
//!    `split-witness` artifacts).
//! 9. `machine_finalize(head, fri)` — FRI decommit (folding walk) + fact
//!    material.
//!
//! ## Binding rules (design doc "three classes of proof data")
//!
//! - **head** (small claim + pow + interaction claim + config + commitments
//!   + queries-PoW nonce + salt; the claim's program section truncated to
//!   its first 6 entries — all `verify_claim` reads): hashed once in
//!   `machine_begin` (`d_head`), every later transaction re-supplies it and
//!   checks the digest. Its bytes are also transcript-bound (every field is
//!   mixed into the channel), so a consistent-but-wrong head fails the
//!   final PoW/FRI checks exactly as in the monolithic verifier.
//! - **program entries**: absorbed into the claim-mix (transcript-bound);
//!   additionally folded into a rolling chunk digest so the lookup phase can
//!   re-supply the same bytes at the same chunk boundaries.
//! - **sampled values**: used by the OODS check, then mixed
//!   (transcript-bound); digest `d_sampled` saved for the group
//!   transactions' re-supply.
//! - **queried rows + witnesses**: self-authenticating (Merkle-verified on
//!   arrival against roots already bound upstream).
//! - **fri section**: consumed by `machine_fri_commit`, which saves its
//!   digest `d_fri` in the checkpoint; the finalize transaction's re-supply
//!   (in production: the router's write-once staged copy) must hash to
//!   `d_fri`. Belt and braces: finalize also re-runs the FRI commitment
//!   transcript from the checkpointed digest and requires the re-derived
//!   query positions to equal the checkpointed ones (the lane-1 query
//!   equality — it needs the `FriVerifier` anyway for the decommit).
//! - **checkpoint values** (digests, ood point, positions, accumulators,
//!   fact hash): written by the machine itself, trusted like lane 1's
//!   checkpoint (write-once per phase in the contract wrapper).
//!
//! The channel-state discipline is unchanged from `resumable_full.cairo`:
//! checkpoints only at `n_draws == 0` sites (immediately after a `mix_*`);
//! draws between mixes never affect the digest, so re-draw forks
//! (lookup elements, composition/fri coefficients) are deterministic.

use core::array::SpanTrait;
use core::box::BoxImpl;
use core::cmp::min;
use core::num::traits::Zero;
use core::poseidon::poseidon_hash_span;
use stwo_cairo_air::cairo_air::CairoAirNewImpl;
use stwo_cairo_air::claim::CairoInteractionClaim;
use stwo_cairo_air::claim::CairoInteractionClaimImpl;
use stwo_cairo_air::claims::{CairoClaim, CairoClaimFlattenTrait, CairoClaimImpl};
use stwo_cairo_air::preprocessed_columns::preprocessed_root;
use stwo_cairo_air::{INTERACTION_POW_BITS, PublicDataImpl, SECURITY_BITS, verify_claim};
use stwo_constraint_framework::LookupElementsImpl;
use stwo_verifier_core::channel::{Channel, ChannelTrait};
use stwo_verifier_core::circle::{ChannelGetRandomCirclePointImpl, CirclePoint};
use stwo_verifier_core::fields::Invertible;
use stwo_verifier_core::fields::m31::M31Trait;
use stwo_verifier_core::fields::qm31::{QM31, QM31Serde, QM31Trait};
use stwo_verifier_core::fri::{FriProof, FriVerifierTrait};
use stwo_verifier_core::pcs::quotients::fri_answers;
use stwo_verifier_core::pcs::verifier::{
    CommitmentSchemeVerifier, CommitmentSchemeVerifierImpl, QueriedValues,
    get_trace_lde_log_size, mix_sampled_values, prepare_preprocessed_query_positions,
};
use stwo_verifier_core::pcs::{PcsConfig, PcsConfigTrait};
use stwo_verifier_core::poly::circle::{CanonicCosetImpl, CanonicCosetTrait};
use stwo_verifier_core::vcs::MerkleHasher;
use stwo_verifier_core::vcs::verifier::{MerkleDecommitment, MerkleVerifierTrait};
use stwo_verifier_core::verifier::{Air, VerificationError, try_extract_composition_eval};
use stwo_verifier_core::Hash;
use stwo_verifier_utils::{MemorySection, construct_f252};
use stwo_verifier_utils::poseidon252::encode_and_hash_memory_section;
#[cfg(feature: "poseidon252_verifier")]
use crate::claim_mix::{
    ClaimMixState, claim_mix_absorb_program_entries, claim_mix_begin, claim_mix_finalize,
};
#[cfg(not(feature: "poseidon252_verifier"))]
use crate::claim_mix_blake::{
    ClaimMixState, claim_mix_absorb_program_entries, claim_mix_begin, claim_mix_finalize,
};
use crate::channel_compat::new_channel;
use crate::lookup_chunks::{lookup_sum_program_chunk, lookup_sum_rest};
use crate::resumable_full::{FullVerificationOutput, rebuild_tree};
use crate::sponge::{SpongeState, sponge_absorb, sponge_finalize, sponge_start};

/// Index of the preprocessed trace tree.
const PREPROCESSED_TRACE_IDX: usize = 0;
/// COMPOSITION_SPLIT_FACTOR (2) * QM31_EXTENSION_DEGREE (4).
const N_COMPOSITION_COLUMNS: usize = 8;
/// The head's claim carries exactly the program prefix `verify_claim` reads.
pub const HEAD_PROGRAM_ENTRIES: u32 = 6;

// ---------------------------------------------------------------------------
// Head stream

/// The head sections, deserialized. Stream layout (proof order, minus the
/// three big sections, program truncated to [`HEAD_PROGRAM_ENTRIES`]):
/// `[claim(prefix), interaction_pow, interaction_claim, pcs_config,
///   commitments, pow_nonce, channel_salt]`.
#[derive(Drop)]
pub struct Head {
    pub claim: CairoClaim,
    pub interaction_pow: u64,
    pub interaction_claim: CairoInteractionClaim,
    pub pcs_config: PcsConfig,
    pub commitments: Span<Hash>,
    pub pow_nonce: u64,
    pub channel_salt: u32,
}

pub fn parse_head(mut head: Span<felt252>) -> Head {
    let claim: CairoClaim = Serde::deserialize(ref head).expect('head claim');
    let interaction_pow: u64 = Serde::deserialize(ref head).expect('head pow');
    let interaction_claim: CairoInteractionClaim = Serde::deserialize(ref head)
        .expect('head icl');
    let pcs_config: PcsConfig = Serde::deserialize(ref head).expect('head config');
    let commitments: Span<Hash> = Serde::deserialize(ref head).expect('head commitments');
    let pow_nonce: u64 = Serde::deserialize(ref head).expect('head nonce');
    let channel_salt: u32 = Serde::deserialize(ref head).expect('head salt');
    assert(SpanTrait::is_empty(head), 'head trailing data');
    assert!(
        claim.public_data.public_memory.program.len() == HEAD_PROGRAM_ENTRIES,
        "head program prefix length",
    );
    Head {
        claim, interaction_pow, interaction_claim, pcs_config, commitments, pow_nonce,
        channel_salt,
    }
}

/// `assert(poseidon(head) == d_head)` — every post-begin transaction's first
/// step for its re-supplied head bytes.
pub fn check_head(head: Span<felt252>, d_head: felt252) -> Head {
    assert(poseidon_hash_span(head) == d_head, 'head binding');
    parse_head(head)
}

// ---------------------------------------------------------------------------
// Section helpers

/// Canonical felt encoding of a chunk of program entries (per-entry serde,
/// no outer length): the rolling-digest preimage.
fn entries_felts(entries: MemorySection) -> Array<felt252> {
    let mut felts: Array<felt252> = array![];
    for entry in entries {
        Serde::serialize(entry, ref felts);
    }
    felts
}

/// Rolling chunk digest: `H([roll, H(chunk felts)])`.
fn roll_chunk(roll: felt252, entries: MemorySection) -> felt252 {
    let chunk_hash = poseidon_hash_span(entries_felts(entries).span());
    poseidon_hash_span(array![roll, chunk_hash].span())
}

/// Absorbs a chunk's fact-hash contribution: one `construct_f252(value)`
/// felt per entry (the resumable form of the vendored
/// `hash_memory_section`, whose digest is the fact's `program_hash`).
fn absorb_fact_entries(ref sponge: SpongeState, entries: MemorySection) {
    let mut felts: Array<felt252> = array![];
    for entry in entries {
        let (_id, value) = *entry;
        felts.append(construct_f252(BoxTrait::new(value)));
    }
    sponge_absorb(ref sponge, felts.span());
}

/// Rebuilds all four Merkle-tree verifiers from head data (no channel
/// mixing — the roots were mixed during phases 1–6 and are digest-bound).
pub fn rebuild_all_trees(head: @Head) -> CommitmentSchemeVerifier {
    let log_blowup_factor = *head.pcs_config.fri_config.log_blowup_factor;
    let commitments: @Box<[Hash; 4]> = (*head.commitments).try_into().unwrap();
    let [
        preprocessed_commitment, trace_commitment, interaction_trace_commitment,
        composition_commitment,
    ] =
        commitments
        .unbox();
    let log_sizes: @Box<[Span<u32>; 3]> = head.claim.log_sizes().span().try_into().unwrap();
    let [preprocessed_log_sizes, trace_log_sizes, interaction_trace_log_sizes] = log_sizes.unbox();
    let mut trees = array![
        rebuild_tree(preprocessed_commitment, preprocessed_log_sizes, log_blowup_factor),
        rebuild_tree(trace_commitment, trace_log_sizes, log_blowup_factor),
        rebuild_tree(
            interaction_trace_commitment, interaction_trace_log_sizes, log_blowup_factor,
        ),
    ];
    let log_trace_degree_bound = get_trace_lde_log_size(@trees) - log_blowup_factor;
    trees
        .append(
            rebuild_tree(
                composition_commitment,
                [log_trace_degree_bound; N_COMPOSITION_COLUMNS].span(),
                log_blowup_factor,
            ),
        );
    CommitmentSchemeVerifier { trees }
}

/// The trace tree's height IS the trace LDE log size (blowup + max trace
/// column degree bound). Reading it directly works for the 4-tree scheme,
/// where the vendored `get_trace_lde_log_size` (fixed 3-tree unbox) doesn't.
pub fn log_trace_degree_bound_of(scheme: @CommitmentSchemeVerifier, log_blowup_factor: u32) -> u32 {
    *scheme.trees.at(1).tree_height - log_blowup_factor
}

// ---------------------------------------------------------------------------
// Checkpoint states

/// After `machine_begin` / between claim chunks.
#[derive(Drop, Serde)]
pub struct ClaimPhaseState {
    pub d_head: felt252,
    pub program_len: u32,
    pub entries_fed: u32,
    pub chunks_digest: felt252,
    pub claim_mix: ClaimMixState,
    pub fact_sponge: SpongeState,
}

/// After `machine_claim_finalize` / between lookup chunks.
#[derive(Drop, Serde)]
pub struct LookupPhaseState {
    pub d_head: felt252,
    pub program_len: u32,
    pub initial_pc: u32,
    pub chunks_digest: felt252,
    pub roll_check: felt252,
    pub entries_summed: u32,
    pub accumulator: QM31,
    pub digest_pre_draw: Hash,
    pub program_fact_hash: felt252,
}

/// After `machine_lookup_finalize`.
#[derive(Drop, Serde)]
pub struct OodsPhaseState {
    pub d_head: felt252,
    pub digest_pre_draw: Hash,
    pub digest_post_prologue: Hash,
    pub program_fact_hash: felt252,
}

/// After `machine_oods_mix`.
#[derive(Drop, Serde)]
pub struct FriCommitPhaseState {
    pub d_head: felt252,
    pub digest_pre_draw: Hash,
    pub digest_pre_fri: Hash,
    pub d_sampled: felt252,
    pub ood_x: QM31,
    pub ood_y: QM31,
    pub program_fact_hash: felt252,
}

/// After `machine_fri_commit` / between group transactions.
#[derive(Drop, Serde)]
pub struct GroupPhaseState {
    pub d_head: felt252,
    pub digest_pre_fri: Hash,
    pub d_sampled: felt252,
    pub d_fri: felt252,
    pub ood_x: QM31,
    pub ood_y: QM31,
    pub query_positions: Span<u32>,
    pub queries_done: u32,
    /// Accumulated fri answers as M31 components (4 per QM31), packed 7
    /// components per felt — the state is echoed as calldata every group
    /// transaction, and unpacked M31s would out-grow the calldata budget
    /// (measured: 4 unpacked components/answer pushed the worst 8-query
    /// group tx to 5,007 felts, 11 over the ~4,996 cap).
    pub answers_flat: Array<felt252>,
    /// Number of M31 components inside [`Self::answers_flat`] (the packed
    /// tail is zero-padded, so the count cannot be derived from length).
    pub answers_n: u32,
    pub program_fact_hash: felt252,
}

/// Packs M31 components 7 per felt, little-endian 32-bit limbs (the
/// transport packer's layout, minus escapes — M31s never need them).
fn pack_answers(mut components: Span<felt252>) -> Array<felt252> {
    let mut packed: Array<felt252> = array![];
    while !components.is_empty() {
        let mut slot: felt252 = 0;
        let mut shift: felt252 = 1;
        let mut k = 0_u32;
        while k != 7 {
            match components.pop_front() {
                Some(c) => slot += *c * shift,
                None => {},
            }
            shift *= 0x100000000;
            k += 1;
        }
        packed.append(slot);
    }
    packed
}

fn unpack_answers(packed: Span<felt252>, n: u32) -> Array<felt252> {
    let nz32: NonZero<u128> = 0x100000000_u128.try_into().unwrap();
    let mut components: Array<felt252> = array![];
    for slot in packed {
        let v: u256 = (*slot).into();
        let (q, l0) = DivRem::div_rem(v.low, nz32);
        let (q, l1) = DivRem::div_rem(q, nz32);
        let (l3, l2) = DivRem::div_rem(q, nz32);
        let (q, l4) = DivRem::div_rem(v.high, nz32);
        let (l6, l5) = DivRem::div_rem(q, nz32);
        for l in [l0, l1, l2, l3, l4, l5, l6].span() {
            if components.len() != n {
                components.append((*l).into());
            }
        }
    }
    components
}

fn unflatten_answers(mut flat: Span<felt252>) -> Array<QM31> {
    let mut answers: Array<QM31> = array![];
    while let Some(part) = flat.multi_pop_front::<4>() {
        let [a, b, c, d] = (*part).unbox();
        answers
            .append(
                QM31Trait::from_fixed_array(
                    [
                        M31Trait::reduce_u32(a.try_into().unwrap()),
                        M31Trait::reduce_u32(b.try_into().unwrap()),
                        M31Trait::reduce_u32(c.try_into().unwrap()),
                        M31Trait::reduce_u32(d.try_into().unwrap()),
                    ],
                ),
            );
    }
    answers
}

// ---------------------------------------------------------------------------
// Tx 1: begin

pub fn machine_begin(head: Span<felt252>, program_len: u32) -> ClaimPhaseState {
    let d_head = poseidon_hash_span(head);
    let h = parse_head(head);

    assert!(h.pcs_config.lifting_log_size.is_none());
    assert!(
        h.pcs_config.security_bits() >= SECURITY_BITS,
        "{}",
        VerificationError::SecurityBitsTooLow,
    );
    // All of verify_claim's reads live in the head (program prefix + small
    // claim) — the vendored function runs verbatim.
    verify_claim(@h.claim);

    // Transcript start (mirrors verify_cairo's prologue).
    let mut channel: Channel = Default::default();
    let channel_salt_as_felt: QM31 = M31Trait::reduce_u32(h.channel_salt).into();
    channel.mix_felts([channel_salt_as_felt].span());
    h.pcs_config.mix_into(ref channel);

    let log_blowup_factor = h.pcs_config.fri_config.log_blowup_factor;
    let commitments: @Box<[Hash; 4]> = h.commitments.try_into().unwrap();
    let [preprocessed_commitment, _trace, _interaction, _composition] = commitments.unbox();
    assert!(preprocessed_commitment == preprocessed_root(log_blowup_factor));
    let log_sizes: @Box<[Span<u32>; 3]> = h.claim.log_sizes().span().try_into().unwrap();
    let [preprocessed_log_sizes, _trace_log_sizes, _interaction_log_sizes] = log_sizes.unbox();
    let mut commitment_scheme = CommitmentSchemeVerifierImpl::new();
    commitment_scheme
        .commit(preprocessed_commitment, preprocessed_log_sizes, ref channel, log_blowup_factor);

    // Open the claim-mix pipeline. The head's program prefix serves only
    // verify_claim; ALL program entries arrive via machine_claim_chunk, so
    // the prefix's ids are excluded from the u32 stream here.
    let flat = h.claim.flatten_claim();
    let (public_claim, _output_claim, _program_claim) = flat.public_data.pack_into_u32s();
    let prefix = public_claim.slice(0, SpanTrait::len(public_claim) - HEAD_PROGRAM_ENTRIES);
    let claim_mix = claim_mix_begin(
        ref channel,
        flat.component_enable_bits,
        flat.component_log_sizes,
        prefix,
        flat.public_data.public_memory.output,
        program_len,
    );

    ClaimPhaseState {
        d_head,
        program_len,
        entries_fed: 0,
        chunks_digest: 0,
        claim_mix,
        fact_sponge: sponge_start(),
    }
}

// ---------------------------------------------------------------------------
// Tx 2..k: claim chunks

pub fn machine_claim_chunk(state: ClaimPhaseState, entries: MemorySection) -> ClaimPhaseState {
    let ClaimPhaseState {
        d_head, program_len, entries_fed, chunks_digest, mut claim_mix, mut fact_sponge,
    } = state;
    let n = entries.len();
    assert!(entries_fed + n <= program_len, "too many program entries");

    claim_mix_absorb_program_entries(ref claim_mix, entries);
    absorb_fact_entries(ref fact_sponge, entries);

    ClaimPhaseState {
        d_head,
        program_len,
        entries_fed: entries_fed + n,
        chunks_digest: roll_chunk(chunks_digest, entries),
        claim_mix,
        fact_sponge,
    }
}

// ---------------------------------------------------------------------------
// Tx k+1: claim finalize + trace commit + interaction PoW

pub fn machine_claim_finalize(state: ClaimPhaseState, head: Span<felt252>) -> LookupPhaseState {
    let ClaimPhaseState {
        d_head, program_len, entries_fed, chunks_digest, claim_mix, fact_sponge,
    } = state;
    assert!(entries_fed == program_len, "program entries incomplete");
    let h = check_head(head, d_head);

    let program_fact_hash = sponge_finalize(fact_sponge);

    let mut channel = new_channel(claim_mix_finalize(claim_mix));
    let log_blowup_factor = h.pcs_config.fri_config.log_blowup_factor;
    let commitments: @Box<[Hash; 4]> = h.commitments.try_into().unwrap();
    let [_pp, trace_commitment, _interaction, _composition] = commitments.unbox();
    let log_sizes: @Box<[Span<u32>; 3]> = h.claim.log_sizes().span().try_into().unwrap();
    let [_pp_log_sizes, trace_log_sizes, _interaction_log_sizes] = log_sizes.unbox();
    // Mixing-only commit: the tree state is rebuilt from head data wherever
    // a later phase needs it.
    let mut commitment_scheme = CommitmentSchemeVerifierImpl::new();
    commitment_scheme.commit(trace_commitment, trace_log_sizes, ref channel, log_blowup_factor);

    assert!(
        channel.verify_pow_nonce(INTERACTION_POW_BITS, h.interaction_pow),
        "{}",
        VerificationError::InteractionProofOfWork,
    );
    channel.mix_u64(h.interaction_pow);

    let initial_pc: u32 = h.claim.public_data.initial_state.pc.into();
    LookupPhaseState {
        d_head,
        program_len,
        initial_pc,
        chunks_digest,
        roll_check: 0,
        entries_summed: 0,
        accumulator: Zero::zero(),
        digest_pre_draw: channel.digest,
        program_fact_hash,
    }
}

// ---------------------------------------------------------------------------
// Tx k+2..m: lookup chunks (program entries re-supplied, roll-bound)

pub fn machine_lookup_chunk(state: LookupPhaseState, entries: MemorySection) -> LookupPhaseState {
    let LookupPhaseState {
        d_head, program_len, initial_pc, chunks_digest, roll_check, entries_summed,
        accumulator, digest_pre_draw, program_fact_hash,
    } = state;
    let n = entries.len();
    assert!(entries_summed + n <= program_len, "too many lookup entries");

    // Deterministic per-tx redraw of the lookup elements.
    let mut draw_channel = new_channel(digest_pre_draw);
    let elements = LookupElementsImpl::draw(ref draw_channel);

    let chunk_sum = lookup_sum_program_chunk(@entries, initial_pc + entries_summed, @elements);

    LookupPhaseState {
        d_head,
        program_len,
        initial_pc,
        chunks_digest,
        roll_check: roll_chunk(roll_check, entries),
        entries_summed: entries_summed + n,
        accumulator: accumulator + chunk_sum,
        digest_pre_draw,
        program_fact_hash,
    }
}

// ---------------------------------------------------------------------------
// Tx m+1: lookup finalize + interaction claim mix/commit

pub fn machine_lookup_finalize(state: LookupPhaseState, head: Span<felt252>) -> OodsPhaseState {
    let LookupPhaseState {
        d_head, program_len, initial_pc: _, chunks_digest, roll_check, entries_summed,
        accumulator, digest_pre_draw, program_fact_hash,
    } = state;
    assert!(entries_summed == program_len, "lookup entries incomplete");
    // The lookup phase saw exactly the bytes the claim mix absorbed, at the
    // same chunk boundaries.
    assert(roll_check == chunks_digest, 'lookup chunk binding');
    let h = check_head(head, d_head);

    let mut channel = new_channel(digest_pre_draw);
    let elements = LookupElementsImpl::draw(ref channel);
    let total = accumulator
        + lookup_sum_rest(@h.claim.public_data, @elements, @h.interaction_claim);
    assert!(total.is_zero(), "{}", VerificationError::InvalidLogupSum);

    h.interaction_claim.mix_into(ref channel);
    let log_blowup_factor = h.pcs_config.fri_config.log_blowup_factor;
    let commitments: @Box<[Hash; 4]> = h.commitments.try_into().unwrap();
    let [_pp, _trace, interaction_trace_commitment, _composition] = commitments.unbox();
    let log_sizes: @Box<[Span<u32>; 3]> = h.claim.log_sizes().span().try_into().unwrap();
    let [_pp_log_sizes, _trace_log_sizes, interaction_trace_log_sizes] = log_sizes.unbox();
    let mut commitment_scheme = CommitmentSchemeVerifierImpl::new();
    commitment_scheme
        .commit(
            interaction_trace_commitment,
            interaction_trace_log_sizes,
            ref channel,
            log_blowup_factor,
        );

    OodsPhaseState {
        d_head, digest_pre_draw, digest_post_prologue: channel.digest, program_fact_hash,
    }
}

// ---------------------------------------------------------------------------
// Tx m+2: composition commit + OODS check + sampled-values mix

pub fn machine_oods_mix(
    state: OodsPhaseState, head: Span<felt252>, sampled_felts: Span<felt252>,
) -> FriCommitPhaseState {
    let OodsPhaseState { d_head, digest_pre_draw, digest_post_prologue, program_fact_hash } =
        state;
    let h = check_head(head, d_head);

    let mut sampled_span = sampled_felts;
    let sampled_values: Span<Span<Span<QM31>>> = Serde::deserialize(ref sampled_span)
        .expect('sampled deser');
    assert(SpanTrait::is_empty(sampled_span), 'sampled trailing data');

    let mut draw_channel = new_channel(digest_pre_draw);
    let elements = LookupElementsImpl::draw(ref draw_channel);

    let log_blowup_factor = h.pcs_config.fri_config.log_blowup_factor;
    let commitment_scheme = rebuild_all_trees(@h);
    let log_trace_degree_bound = log_trace_degree_bound_of(@commitment_scheme, log_blowup_factor);

    let mut channel = new_channel(digest_post_prologue);
    let composition_random_coeff = channel.draw_secure_felt();
    // Mixing effect of the composition commit (tree already rebuilt above).
    let commitments: @Box<[Hash; 4]> = h.commitments.try_into().unwrap();
    let [_pp, _trace, _interaction, composition_commitment] = commitments.unbox();
    channel.mix_commitment(composition_commitment);

    let ood_point = channel.get_random_point();

    let composition_oods_eval = try_extract_composition_eval(
        sampled_values, ood_point, log_trace_degree_bound,
    )
        .unwrap_or_else(
            || panic!("{}", VerificationError::InvalidStructure('Invalid sampled_values')),
        );
    let cairo_air = CairoAirNewImpl::new(@h.claim, @elements, @h.interaction_claim);
    let numerator = cairo_air
        .eval_composition_polynomial_at_point(
            ood_point, sampled_values, composition_random_coeff,
        );
    let max_trace_domain = CanonicCosetImpl::new(log_trace_degree_bound);
    let denominator_inv = max_trace_domain.eval_vanishing(ood_point).inverse();
    assert!(
        composition_oods_eval == numerator * denominator_inv,
        "{}",
        VerificationError::OodsNotMatching,
    );

    mix_sampled_values(sampled_values, ref channel);

    FriCommitPhaseState {
        d_head,
        digest_pre_draw,
        digest_pre_fri: channel.digest,
        d_sampled: poseidon_hash_span(sampled_felts),
        ood_x: ood_point.x,
        ood_y: ood_point.y,
        program_fact_hash,
    }
}

// ---------------------------------------------------------------------------
// Tx m+3: FRI commitment phase + queries PoW + query sampling

pub fn machine_fri_commit(
    state: FriCommitPhaseState, head: Span<felt252>, fri_felts: Span<felt252>,
) -> GroupPhaseState {
    let FriCommitPhaseState {
        d_head, digest_pre_draw: _, digest_pre_fri, d_sampled, ood_x, ood_y, program_fact_hash,
    } = state;
    let h = check_head(head, d_head);

    let mut fri_span = fri_felts;
    let fri_proof: FriProof = Serde::deserialize(ref fri_span).expect('fri deser');
    assert(SpanTrait::is_empty(fri_span), 'fri trailing data');

    let log_blowup_factor = h.pcs_config.fri_config.log_blowup_factor;
    let commitment_scheme = rebuild_all_trees(@h);
    let log_trace_degree_bound = log_trace_degree_bound_of(@commitment_scheme, log_blowup_factor);

    let mut channel = new_channel(digest_pre_fri);
    let _random_coeff = channel.draw_secure_felt();
    let mut fri_verifier = FriVerifierTrait::commit(
        ref channel, h.pcs_config.fri_config, fri_proof, log_trace_degree_bound,
    );
    assert!(
        channel.verify_pow_nonce(h.pcs_config.pow_bits, h.pow_nonce),
        "{}",
        VerificationError::QueriesProofOfWork,
    );
    channel.mix_u64(h.pow_nonce);
    let queries = fri_verifier.sample_query_positions(ref channel);

    GroupPhaseState {
        d_head,
        digest_pre_fri,
        d_sampled,
        d_fri: poseidon_hash_span(fri_felts),
        ood_x,
        ood_y,
        query_positions: queries.positions,
        queries_done: 0,
        answers_flat: array![],
        answers_n: 0,
        program_fact_hash,
    }
}

// ---------------------------------------------------------------------------
// Tx m+4..p: fused Merkle + fri_answers query-group transactions

pub fn machine_group(
    state: GroupPhaseState,
    head: Span<felt252>,
    sampled_felts: Span<felt252>,
    rows: QueriedValues,
    witnesses: Array<Span<Hash>>,
) -> GroupPhaseState {
    let GroupPhaseState {
        d_head, digest_pre_fri, d_sampled, d_fri, ood_x, ood_y, query_positions, queries_done,
        answers_flat, answers_n, program_fact_hash,
    } = state;
    let h = check_head(head, d_head);
    assert(poseidon_hash_span(sampled_felts) == d_sampled, 'sampled binding');
    let mut sampled_span = sampled_felts;
    let sampled_values: Span<Span<Span<QM31>>> = Serde::deserialize(ref sampled_span)
        .expect('sampled deser');

    let log_blowup_factor = h.pcs_config.fri_config.log_blowup_factor;
    let mut commitment_scheme = rebuild_all_trees(@h);
    let log_trace_degree_bound = log_trace_degree_bound_of(@commitment_scheme, log_blowup_factor);
    let lifting_log_size = log_trace_degree_bound + log_blowup_factor;

    // The group's query range: rows and witnesses cover
    // [queries_done, queries_done + n) in sampled order.
    let n_group = SpanTrait::len(*rows[0]) / (*commitment_scheme.trees[0].column_log_deg_bounds)
        .len();
    let n = min(n_group, SpanTrait::len(query_positions) - queries_done);
    let group_positions = query_positions.slice(queries_done, n);

    // Merkle-verify the group's rows against all four roots
    // (self-authenticating transport).
    let mut tree_index = 0;
    for tree in commitment_scheme.trees.span() {
        let positions = if tree_index == PREPROCESSED_TRACE_IDX {
            prepare_preprocessed_query_positions(
                group_positions, lifting_log_size, *tree.tree_height,
            )
        } else {
            group_positions
        };
        assert!(
            SpanTrait::len(*rows[tree_index]) == n * (*tree.column_log_deg_bounds).len(),
            "group row length",
        );
        tree
            .verify(
                positions,
                *rows[tree_index],
                MerkleDecommitment::<MerkleHasher> { hash_witness: *witnesses[tree_index] },
            );
        tree_index += 1;
    }

    // fri_answers over the group (stateless constants recompute; the
    // one-time constants store is a contract-level optimization).
    let mut random_channel = new_channel(digest_pre_fri);
    let random_coeff = random_channel.draw_secure_felt();
    let answers = fri_answers(
        commitment_scheme.column_indices_per_tree_by_degree_bound(),
        log_blowup_factor,
        CirclePoint { x: ood_x, y: ood_y },
        sampled_values,
        random_coeff,
        group_positions,
        rows,
        log_trace_degree_bound,
    );
    let mut components = unpack_answers(answers_flat.span(), answers_n);
    for answer in answers {
        let [a, b, c, d] = (*answer).to_fixed_array();
        components.append(a.into());
        components.append(b.into());
        components.append(c.into());
        components.append(d.into());
    }
    let answers_n = components.len();

    GroupPhaseState {
        d_head,
        digest_pre_fri,
        d_sampled,
        d_fri,
        ood_x,
        ood_y,
        query_positions,
        queries_done: queries_done + n,
        answers_flat: pack_answers(components.span()),
        answers_n,
        program_fact_hash,
    }
}

// ---------------------------------------------------------------------------
// Tx p+1: FRI decommit (folding walk) + fact material

pub fn machine_finalize(
    state: GroupPhaseState, head: Span<felt252>, fri_felts: Span<felt252>,
) -> FullVerificationOutput {
    let GroupPhaseState {
        d_head, digest_pre_fri, d_sampled: _, d_fri, ood_x: _, ood_y: _, query_positions,
        queries_done, answers_flat, answers_n, program_fact_hash,
    } = state;
    assert!(queries_done == SpanTrait::len(query_positions), "query groups incomplete");
    let h = check_head(head, d_head);
    // The re-supplied fri section must be the bytes fri_commit consumed.
    assert(poseidon_hash_span(fri_felts) == d_fri, 'fri binding');

    let mut fri_span = fri_felts;
    let fri_proof: FriProof = Serde::deserialize(ref fri_span).expect('fri deser');
    assert(SpanTrait::is_empty(fri_span), 'fri trailing data');

    let log_blowup_factor = h.pcs_config.fri_config.log_blowup_factor;
    let commitment_scheme = rebuild_all_trees(@h);
    let log_trace_degree_bound = log_trace_degree_bound_of(@commitment_scheme, log_blowup_factor);

    // Re-run the FRI commitment transcript from the checkpointed digest;
    // the re-derived query positions must equal the checkpointed ones
    // (lane-1 query-equality binding for the re-supplied fri section).
    let mut channel = new_channel(digest_pre_fri);
    let _random_coeff = channel.draw_secure_felt();
    let mut fri_verifier = FriVerifierTrait::commit(
        ref channel, h.pcs_config.fri_config, fri_proof, log_trace_degree_bound,
    );
    assert!(
        channel.verify_pow_nonce(h.pcs_config.pow_bits, h.pow_nonce),
        "{}",
        VerificationError::QueriesProofOfWork,
    );
    channel.mix_u64(h.pow_nonce);
    let queries = fri_verifier.sample_query_positions(ref channel);
    assert(queries.positions == query_positions, 'query binding');

    fri_verifier
        .decommit(
            queries,
            unflatten_answers(unpack_answers(answers_flat.span(), answers_n).span()).span(),
        );

    let output_hash = construct_f252(
        encode_and_hash_memory_section(h.claim.public_data.public_memory.output),
    );
    FullVerificationOutput { program_hash: program_fact_hash, output_hash }
}
