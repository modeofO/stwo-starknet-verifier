//! Cost probe for the sampled-values/constants dilemma (docs/lane2-design.md,
//! machine plan v2): each fri_answers chunk transaction needs the quotient
//! constants, which derive from ALL sampled values. The candidate designs are
//! (a) a one-time constants store + per-chunk reads, (b) column-range-sliced
//! derivation, (c) recompute-per-chunk from re-supplied (digest-bound)
//! sampled values. This file isolates the recompute cost empirically:
//!
//! - `probe_a_replay_only`: the shared transcript replay (baseline).
//! - `probe_b_constants_only`: replay + the fri_answers *prelude* over the
//!   full sampled values with ZERO queries — exactly the per-chunk constants
//!   derivation a recompute design pays.
//! - `probe_c_one_query` / `probe_d_chunk16`: prelude + 1 / 16 queries, to
//!   separate the per-query cost from the prelude.
//!
//! Compare the reported l2_gas across the four tests (they share the same
//! replay); the deltas are the isolated costs.

use core::array::SpanTrait;
use core::box::BoxImpl;
use snforge_std::fs::{FileTrait, read_txt};
use stwo_cairo_air::claims::CairoClaimImpl;
use stwo_cairo_air::CairoProof;
use stwo_full_verifier_phases::fri_chunks::{queried_values_strides, slice_queried_values};
use stwo_full_verifier_phases::resumable_full::{FullCheckpoint, phase_a, rebuild_tree};
use stwo_full_verifier_phases::unpack_proof_v2;
use stwo_verifier_core::channel::poseidon252::new_channel;
use stwo_verifier_core::channel::ChannelTrait;
use stwo_verifier_core::circle::ChannelGetRandomCirclePointImpl;
use stwo_verifier_core::fields::qm31::QM31;
use stwo_verifier_core::fri::FriVerifierTrait;
use stwo_verifier_core::pcs::quotients::fri_answers;
use stwo_verifier_core::pcs::verifier::{
    CommitmentSchemeProof, CommitmentSchemeVerifier, CommitmentSchemeVerifierImpl,
    get_trace_lde_log_size, mix_sampled_values,
};
use stwo_verifier_core::verifier::StarkProof;
use stwo_verifier_core::Hash;

const N_VALUES: u32 = 301_143;

/// Runs the shared replay and, when `n_queries > 0` or `prelude_only` is
/// true, calls the vendored `fri_answers` over the query range
/// `[0, n_queries)` with correspondingly sliced queried values.
fn probe(run_fri_answers: bool, n_queries: u32) -> u32 {
    let file = FileTrait::new("tests/data/poseidon_chain_n100_full_proof_packed_v2.txt");
    let slots = read_txt(@file);
    let values = unpack_proof_v2(slots.span(), N_VALUES);

    let FullCheckpoint { digest_pre_draw: _, digest_post_prologue, proof_hash: _ } = phase_a(
        values.span(),
    );

    let mut span = values.span();
    let proof: CairoProof = Serde::deserialize(ref span).expect('proof deser');
    let CairoProof {
        claim, interaction_pow: _, interaction_claim: _, stark_proof, channel_salt: _,
    } = proof;

    let StarkProof { commitment_scheme_proof } = stark_proof;
    let pcs_config = commitment_scheme_proof.config;
    let log_blowup_factor = pcs_config.fri_config.log_blowup_factor;

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

    let mut channel = new_channel(digest_post_prologue);
    let trace_lde_log_size = get_trace_lde_log_size(@commitment_scheme.trees);
    let log_trace_degree_bound = trace_lde_log_size - log_blowup_factor;

    let _composition_random_coeff = channel.draw_secure_felt();
    commitment_scheme
        .commit(
            composition_commitment,
            [log_trace_degree_bound; 8].span(),
            ref channel,
            log_blowup_factor,
        );
    let ood_point = channel.get_random_point();

    let CommitmentSchemeProof {
        config,
        commitments: _,
        sampled_values,
        decommitments: _,
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
    assert!(channel.verify_pow_nonce(config.pow_bits, proof_of_work_nonce));
    channel.mix_u64(proof_of_work_nonce);
    let queries = fri_verifier.sample_query_positions(ref channel);
    let query_positions = queries.positions;

    if !run_fri_answers {
        return SpanTrait::len(query_positions);
    }

    let strides = queried_values_strides(@commitment_scheme.trees);
    let answers: Span<QM31> = fri_answers(
        commitment_scheme.column_indices_per_tree_by_degree_bound(),
        fri_config.log_blowup_factor,
        ood_point,
        sampled_values,
        random_coeff,
        query_positions.slice(0, n_queries),
        slice_queried_values(@queried_values_per_tree, strides.span(), 0, n_queries),
        log_trace_degree_bound,
    );
    assert!(SpanTrait::len(answers) == n_queries);
    SpanTrait::len(query_positions)
}

#[test]
fn probe_a_replay_only() {
    assert!(probe(false, 0) == 70);
}

#[test]
fn probe_b_constants_only() {
    // Zero queries: fri_answers runs exactly the prelude a recompute-per-
    // chunk transaction pays (build_samples_with_randomness + per-degree-
    // bound sample batches + QuotientConstantsImpl::gen).
    assert!(probe(true, 0) == 70);
}

#[test]
fn probe_c_one_query() {
    assert!(probe(true, 1) == 70);
}

#[test]
fn probe_d_chunk16() {
    assert!(probe(true, 16) == 70);
}
