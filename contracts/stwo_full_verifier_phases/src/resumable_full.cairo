//! Two-phase (resumable) verification of the FULL Cairo verifier — the lane-2
//! skeleton. Mirrors `stwo_cairo_air::verify_cairo`,
//! `stwo_verifier_core::verifier::verify` and `…::pcs::verifier::verify_values`
//! at the vendored commit 92bfd1d3, split at the lookup-elements seam; review
//! any vendor change against this file.
//!
//! This 2-phase split is the *pattern validation*, not the deployable shape:
//! each half is still far above the 1.21e9 per-invoke cap (the production
//! machine is ~15 phases — docs/lane2-design.md). What this module proves,
//! against the real fixture proof in snforge:
//!
//! - the Poseidon channel state crosses a phase boundary as a single felt
//!   (digest at an `n_draws == 0` site) and restores byte-identically;
//! - drawn values (the lookup elements) need not be checkpointed: a later
//!   phase re-draws them from the checkpointed pre-draw digest;
//! - re-supplied proof data is bound across phases by digest comparison
//!   (`proof_hash` here binds the whole stream; the production machine binds
//!   per-section).
//!
//! Soundness invariants (same as lane 1's `resumable.cairo`):
//! - The concatenated transcript across phases is byte-identical to the
//!   monolithic verifier's: phase B resumes from the digest saved immediately
//!   after phase A's last `mix_*` (`n_draws == 0` there), and its first
//!   channel operation is exactly the monolithic verifier's next operation.
//! - Phase B only accepts the same proof bytes phase A processed
//!   (`poseidon(values)` equality), so phase A's claim checks, interaction
//!   PoW and logup-sum check cover phase B's inputs.

use core::box::BoxImpl;
use core::num::traits::Zero;
use core::poseidon::poseidon_hash_span;
use stwo_cairo_air::claim::{CairoInteractionClaimImpl, lookup_sum};
use stwo_cairo_air::claims::CairoClaimImpl;
use stwo_cairo_air::cairo_air::CairoAirNewImpl;
use stwo_cairo_air::preprocessed_columns::preprocessed_root;
use stwo_cairo_air::{CairoProof, INTERACTION_POW_BITS, SECURITY_BITS, verify_claim};
use stwo_constraint_framework::LookupElementsImpl;
use stwo_verifier_core::channel::{Channel, ChannelTrait};
use crate::channel_compat::new_channel;
use stwo_verifier_core::circle::ChannelGetRandomCirclePointImpl;
use stwo_verifier_core::fields::Invertible;
use stwo_verifier_core::fields::m31::M31Trait;
use stwo_verifier_core::fields::qm31::QM31;
use stwo_verifier_core::fri::FriVerifierTrait;
use stwo_verifier_core::pcs::quotients::fri_answers;
use stwo_verifier_core::pcs::verifier::{
    CommitmentSchemeProof, CommitmentSchemeVerifier, CommitmentSchemeVerifierImpl,
    get_trace_lde_log_size, mix_sampled_values, prepare_preprocessed_query_positions,
};
use stwo_verifier_core::pcs::PcsConfigTrait;
use stwo_verifier_core::poly::circle::{CanonicCosetImpl, CanonicCosetTrait};
use stwo_verifier_core::utils::ArrayImpl;
use stwo_verifier_core::vcs::MerkleHasher;
use stwo_verifier_core::vcs::verifier::{MerkleVerifier, MerkleVerifierTrait};
use stwo_verifier_core::verifier::{
    Air, StarkProof, VerificationError, try_extract_composition_eval,
};
use stwo_verifier_core::Hash;
use stwo_verifier_utils::construct_f252;
use stwo_verifier_utils::poseidon252::encode_and_hash_memory_section;
use stwo_verifier_utils::zip_eq::zip_eq;

/// Index of the preprocessed trace tree (mirrors verifier_core's constant).
const PREPROCESSED_TRACE_IDX: usize = 0;
/// COMPOSITION_SPLIT_FACTOR (2) * QM31_EXTENSION_DEGREE (4), private consts upstream.
const N_COMPOSITION_COLUMNS: usize = 8;

/// State carried from phase A to phase B.
#[derive(Drop, Serde)]
pub struct FullCheckpoint {
    /// Channel digest immediately after `mix_u64(interaction_pow)` — the
    /// site the lookup elements are drawn from (`n_draws == 0`).
    pub digest_pre_draw: Hash,
    /// Channel digest immediately after the interaction-trace commit
    /// (`n_draws == 0`) — where the monolithic verifier enters `verify()`.
    pub digest_post_prologue: Hash,
    /// `poseidon(proof felt stream)` — binds phase B's re-supplied bytes to
    /// the ones phase A checked.
    pub proof_hash: felt252,
}

/// The verification result material for fact registration.
#[derive(Drop, Serde, PartialEq, Debug)]
pub struct FullVerificationOutput {
    pub program_hash: felt252,
    pub output_hash: felt252,
}

/// Phase A: claim checks + the Fiat-Shamir prologue (config/salt/claim
/// mixing, preprocessed + trace + interaction commits, interaction PoW,
/// logup-sum check). Everything before the monolithic `verify()` call.
pub fn phase_a(values: Span<felt252>) -> FullCheckpoint {
    let proof_hash = poseidon_hash_span(values);

    let mut span = values;
    let proof: CairoProof = Serde::deserialize(ref span).expect('proof deser');
    assert(span.is_empty(), 'trailing proof data');
    let CairoProof { claim, interaction_pow, interaction_claim, stark_proof, channel_salt } = proof;

    let pcs_config = stark_proof.commitment_scheme_proof.config;
    assert!(pcs_config.lifting_log_size.is_none());

    verify_claim(@claim);

    let mut channel: Channel = Default::default();
    let channel_salt_as_felt: QM31 = M31Trait::reduce_u32(channel_salt).into();
    channel.mix_felts([channel_salt_as_felt].span());

    pcs_config.mix_into(ref channel);
    let mut commitment_scheme = CommitmentSchemeVerifierImpl::new();

    let commitments: @Box<[Hash; 4]> = stark_proof
        .commitment_scheme_proof
        .commitments
        .try_into()
        .unwrap();
    let [
        preprocessed_commitment, trace_commitment, interaction_trace_commitment, _composition,
    ] =
        commitments
        .unbox();

    let log_sizes: @Box<[Span<u32>; 3]> = claim.log_sizes().span().try_into().unwrap();
    let [preprocessed_log_sizes, trace_log_sizes, interaction_trace_log_sizes] = log_sizes.unbox();

    let log_blowup_factor = pcs_config.fri_config.log_blowup_factor;
    let expected_preprocessed_root = preprocessed_root(log_blowup_factor);
    assert!(preprocessed_commitment == expected_preprocessed_root);
    commitment_scheme
        .commit(preprocessed_commitment, preprocessed_log_sizes, ref channel, log_blowup_factor);
    claim.mix_into(ref channel);

    commitment_scheme.commit(trace_commitment, trace_log_sizes, ref channel, log_blowup_factor);
    assert!(
        channel.verify_pow_nonce(INTERACTION_POW_BITS, interaction_pow),
        "{}",
        VerificationError::InteractionProofOfWork,
    );
    channel.mix_u64(interaction_pow);

    // ---- Checkpoint site 1: the lookup elements are drawn from here.
    let digest_pre_draw = channel.digest;

    let common_lookup_elements = LookupElementsImpl::draw(ref channel);
    assert!(
        lookup_sum(@claim, @common_lookup_elements, @interaction_claim).is_zero(),
        "{}",
        VerificationError::InvalidLogupSum,
    );

    interaction_claim.mix_into(ref channel);
    commitment_scheme
        .commit(
            interaction_trace_commitment,
            interaction_trace_log_sizes,
            ref channel,
            log_blowup_factor,
        );

    // ---- Checkpoint site 2: the monolithic verifier enters `verify()` here.
    let digest_post_prologue = channel.digest;

    FullCheckpoint { digest_pre_draw, digest_post_prologue, proof_hash }
}

/// Phase B: restores the transcript, re-draws the lookup elements, and runs
/// the monolithic `verify()` + `verify_values()` (composition/OODS check,
/// FRI commitment, Merkle decommitments, FRI answers and folding walk).
/// Returns the fact material on success.
pub fn phase_b(values: Span<felt252>, checkpoint: FullCheckpoint) -> FullVerificationOutput {
    let FullCheckpoint { digest_pre_draw, digest_post_prologue, proof_hash } = checkpoint;

    // Bind phase B's bytes to the ones phase A verified the claim over.
    assert(poseidon_hash_span(values) == proof_hash, 'proof binding');

    let mut span = values;
    let proof: CairoProof = Serde::deserialize(ref span).expect('proof deser');
    assert(span.is_empty(), 'trailing proof data');
    let CairoProof {
        claim, interaction_pow: _, interaction_claim, stark_proof, channel_salt: _,
    } = proof;

    // Fact material (mirrors `get_verification_output`, poseidon_outputs_packing).
    let program_hash = construct_f252(
        encode_and_hash_memory_section(claim.public_data.public_memory.program),
    );
    let output_hash = construct_f252(
        encode_and_hash_memory_section(claim.public_data.public_memory.output),
    );

    let StarkProof { commitment_scheme_proof } = stark_proof;
    let pcs_config = commitment_scheme_proof.config;
    let log_blowup_factor = pcs_config.fri_config.log_blowup_factor;

    // Rebuild the commitment-scheme trees phase A committed (without
    // re-mixing: their roots are already part of the checkpointed
    // transcript, and the roots/log-sizes come from the bound proof bytes).
    let commitments: @Box<[Hash; 4]> = commitment_scheme_proof.commitments.try_into().unwrap();
    let [
        preprocessed_commitment, trace_commitment, interaction_trace_commitment,
        composition_commitment,
    ] =
        commitments
        .unbox();
    let log_sizes: @Box<[Span<u32>; 3]> = claim.log_sizes().span().try_into().unwrap();
    let [preprocessed_log_sizes, trace_log_sizes, interaction_trace_log_sizes] = log_sizes.unbox();
    let mut commitment_scheme = CommitmentSchemeVerifier {
        trees: array![
            rebuild_tree(preprocessed_commitment, preprocessed_log_sizes, log_blowup_factor),
            rebuild_tree(trace_commitment, trace_log_sizes, log_blowup_factor),
            rebuild_tree(
                interaction_trace_commitment, interaction_trace_log_sizes, log_blowup_factor,
            ),
        ],
    };

    // Re-draw the lookup elements from checkpoint site 1 (deterministic).
    let mut draw_channel = new_channel(digest_pre_draw);
    let common_lookup_elements = LookupElementsImpl::draw(ref draw_channel);

    // Resume the main transcript at checkpoint site 2.
    let mut channel = new_channel(digest_post_prologue);

    let trace_lde_log_size = get_trace_lde_log_size(@commitment_scheme.trees);
    let log_trace_degree_bound = trace_lde_log_size - log_blowup_factor;
    let cairo_air = CairoAirNewImpl::new(@claim, @common_lookup_elements, @interaction_claim);

    // ---- verify() body (vendor verifier_core/src/verifier.cairo:53).
    assert!(
        commitment_scheme_proof.config.security_bits() >= SECURITY_BITS,
        "{}",
        VerificationError::SecurityBitsTooLow,
    );

    let composition_random_coeff = channel.draw_secure_felt();

    commitment_scheme
        .commit(
            composition_commitment,
            [log_trace_degree_bound; N_COMPOSITION_COLUMNS].span(),
            ref channel,
            log_blowup_factor,
        );

    let ood_point = channel.get_random_point();

    let sampled_oods_values = commitment_scheme_proof.sampled_values;

    let composition_oods_eval = try_extract_composition_eval(
        sampled_oods_values, ood_point, log_trace_degree_bound,
    )
        .unwrap_or_else(
            || panic!("{}", VerificationError::InvalidStructure('Invalid sampled_values')),
        );

    let numerator = cairo_air
        .eval_composition_polynomial_at_point(
            ood_point, sampled_oods_values, composition_random_coeff,
        );
    let max_trace_domain = CanonicCosetImpl::new(log_trace_degree_bound);
    let denominator_inv = max_trace_domain.eval_vanishing(ood_point).inverse();
    assert!(
        composition_oods_eval == numerator * denominator_inv,
        "{}",
        VerificationError::OodsNotMatching,
    );

    // ---- verify_values() body (vendor verifier_core/src/pcs/verifier.cairo:127).
    let CommitmentSchemeProof {
        config,
        commitments: _,
        sampled_values,
        decommitments,
        queried_values: queried_values_per_tree,
        proof_of_work_nonce,
        fri_proof,
    } = commitment_scheme_proof;

    mix_sampled_values(sampled_values, ref channel);

    let random_coeff = channel.draw_secure_felt();
    let fri_config = config.fri_config;

    let mut fri_verifier = FriVerifierTrait::commit(
        ref channel, fri_config, fri_proof, log_trace_degree_bound,
    );

    assert!(
        channel.verify_pow_nonce(config.pow_bits, proof_of_work_nonce),
        "{}",
        VerificationError::QueriesProofOfWork,
    );
    channel.mix_u64(proof_of_work_nonce);

    let queries = fri_verifier.sample_query_positions(ref channel);
    let query_positions = queries.positions;
    let lifting_log_size = log_trace_degree_bound + fri_config.log_blowup_factor;

    let mut tree_index = 0;
    for (tree, (queried_values, decommitment)) in zip_eq(
        commitment_scheme.trees.span(), zip_eq(queried_values_per_tree.span(), decommitments),
    ) {
        let query_positions = if tree_index == PREPROCESSED_TRACE_IDX {
            let pp_max_log_size = *tree.tree_height;
            prepare_preprocessed_query_positions(
                query_positions, lifting_log_size, pp_max_log_size,
            )
        } else {
            query_positions
        };
        tree.verify(query_positions, *queried_values, decommitment);
        tree_index += 1;
    }

    let fri_answers = fri_answers(
        commitment_scheme.column_indices_per_tree_by_degree_bound(),
        fri_config.log_blowup_factor,
        ood_point,
        sampled_values,
        random_coeff,
        query_positions,
        queried_values_per_tree,
        log_trace_degree_bound,
    );

    fri_verifier.decommit(queries, fri_answers);

    FullVerificationOutput { program_hash, output_hash }
}

/// Reconstructs one committed Merkle tree's verifier-side state, mirroring
/// `CommitmentSchemeVerifierTrait::commit` minus the channel mixing (the
/// mixing already happened in phase A and is bound by the checkpoint digest).
pub fn rebuild_tree(
    root: Hash, degree_bound_by_column: Span<u32>, log_blowup_factor: u32,
) -> MerkleVerifier<MerkleHasher> {
    let mut max_log_degree_bound = 0_u32;
    for bound in degree_bound_by_column {
        if *bound > max_log_degree_bound {
            max_log_degree_bound = *bound;
        }
    }
    MerkleVerifier {
        root,
        tree_height: log_blowup_factor + max_log_degree_bound,
        column_log_deg_bounds: degree_bound_by_column,
    }
}

/// The monolithic reference: exactly what the vendored executable's `main`
/// does. Used by tests to assert the two-phase split is equivalent.
pub fn verify_full_monolithic(values: Span<felt252>) -> FullVerificationOutput {
    let mut span = values;
    let proof: CairoProof = Serde::deserialize(ref span).expect('proof deser');
    assert(span.is_empty(), 'trailing proof data');
    let program_hash = construct_f252(
        encode_and_hash_memory_section(proof.claim.public_data.public_memory.program),
    );
    let output_hash = construct_f252(
        encode_and_hash_memory_section(proof.claim.public_data.public_memory.output),
    );
    stwo_cairo_air::verify_cairo(proof);
    FullVerificationOutput { program_hash, output_hash }
}
