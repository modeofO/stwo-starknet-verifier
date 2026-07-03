//! Lane-2 phase-cost probe: `verify_cairo` truncated at candidate resumable-phase
//! boundaries, so each boundary's cumulative step cost can be measured with
//! `scarb execute --print-resource-usage`. Subtracting successive stages gives the
//! per-phase cost table that drives the lane-2 split design (docs/lane2-design.md).
//!
//! Mirrors, verbatim where possible:
//! - `stwo_cairo_air::verify_cairo`                (vendor cairo_air/src/lib.cairo)
//! - `stwo_verifier_core::verifier::verify`        (vendor verifier_core/src/verifier.cairo)
//! - `...::pcs::verifier::verify_values`           (vendor verifier_core/src/pcs/verifier.cairo)
//! at the vendored commit 92bfd1d3. Review any vendor change against this file.
//!
//! Stages (cumulative):
//!   0 = argument deserialization only
//!   1 = + verify_claim
//!   2 = + Fiat-Shamir prologue: salt/config/claim mixing, preprocessed+trace+
//!         interaction commits, interaction PoW, logup-sum check
//!   3 = + composition commit, OODS draw, composition-poly eval at OODS, OODS check
//!   4 = + mix_sampled_values, FRI commitment phase, queries PoW, query sampling
//!   5 = + Merkle decommitments for all 4 trees
//!   6 = + fri_answers (quotient accumulation at query positions)
//!   7 = + FRI decommit/folding walk (== complete verify_cairo)

use core::box::BoxImpl;
use core::num::traits::Zero;
use stwo_cairo_air::claim::{CairoInteractionClaimImpl, lookup_sum};
use stwo_cairo_air::claims::CairoClaimImpl;
use stwo_cairo_air::cairo_air::CairoAirNewImpl;
use stwo_cairo_air::preprocessed_columns::preprocessed_root;
use stwo_cairo_air::{
    CairoProof, INTERACTION_POW_BITS, SECURITY_BITS, verify_claim,
};
use stwo_constraint_framework::LookupElementsImpl;
use stwo_verifier_core::channel::{Channel, ChannelTrait};
use stwo_verifier_core::circle::ChannelGetRandomCirclePointImpl;
use stwo_verifier_core::fields::Invertible;
use stwo_verifier_core::fields::m31::M31Trait;
use stwo_verifier_core::fields::qm31::QM31;
use stwo_verifier_core::fri::FriVerifierTrait;
use stwo_verifier_core::pcs::quotients::fri_answers;
use stwo_verifier_core::pcs::verifier::{
    CommitmentSchemeProof, CommitmentSchemeVerifierImpl, get_trace_lde_log_size,
    mix_sampled_values, prepare_preprocessed_query_positions,
};
use stwo_verifier_core::pcs::PcsConfigTrait;
use stwo_verifier_core::poly::circle::{CanonicCosetImpl, CanonicCosetTrait};
use stwo_verifier_core::utils::ArrayImpl;
use stwo_verifier_core::vcs::verifier::MerkleVerifierTrait;
use stwo_verifier_core::verifier::{
    Air, StarkProof, VerificationError, try_extract_composition_eval,
};
use stwo_verifier_core::Hash;
use stwo_verifier_utils::zip_eq::zip_eq;

/// Index of the preprocessed trace tree (mirrors verifier_core's constant).
const PREPROCESSED_TRACE_IDX: usize = 0;
/// COMPOSITION_SPLIT_FACTOR (2) * QM31_EXTENSION_DEGREE (4), private consts upstream.
const N_COMPOSITION_COLUMNS: usize = 8;

#[executable]
fn main(stage: u32, proof: CairoProof) {
    if stage == 0 {
        return;
    }

    // ---- verify_cairo prologue (vendor cairo_air/src/lib.cairo:178).
    let CairoProof { claim, interaction_pow, interaction_claim, stark_proof, channel_salt } = proof;

    let pcs_config = stark_proof.commitment_scheme_proof.config;
    assert!(pcs_config.lifting_log_size.is_none());

    verify_claim(@claim);
    if stage == 1 {
        return;
    }

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
        preprocessed_commitment,
        trace_commitment,
        interaction_trace_commitment,
        composition_commitment,
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
    // Sub-stage 21: prologue up to and including claim mixing + trace commit + PoW.
    if stage == 21 {
        return;
    }

    let common_lookup_elements = LookupElementsImpl::draw(ref channel);
    assert!(
        lookup_sum(@claim, @common_lookup_elements, @interaction_claim).is_zero(),
        "{}",
        VerificationError::InvalidLogupSum,
    );
    // Sub-stage 22: + the logup/lookup sum over all claims and public memory.
    if stage == 22 {
        return;
    }

    interaction_claim.mix_into(ref channel);
    commitment_scheme
        .commit(
            interaction_trace_commitment,
            interaction_trace_log_sizes,
            ref channel,
            log_blowup_factor,
        );

    let trace_lde_log_size = get_trace_lde_log_size(@commitment_scheme.trees);
    let log_trace_degree_bound = trace_lde_log_size - pcs_config.fri_config.log_blowup_factor;
    let cairo_air = CairoAirNewImpl::new(@claim, @common_lookup_elements, @interaction_claim);
    if stage == 2 {
        return;
    }

    // ---- verify() body (vendor verifier_core/src/verifier.cairo:53).
    let StarkProof { commitment_scheme_proof } = stark_proof;

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
            commitment_scheme_proof.config.fri_config.log_blowup_factor,
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
    if stage == 3 {
        return;
    }

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
    if stage == 4 {
        return;
    }

    // ---- Merkle decommitments for the 4 trees.
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
    if stage == 5 {
        return;
    }

    // ---- FRI answers (quotient accumulation at the query positions).
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
    if stage == 6 {
        return;
    }

    // ---- FRI decommit (folding walk down to the last layer).
    fri_verifier.decommit(queries, fri_answers);
}
