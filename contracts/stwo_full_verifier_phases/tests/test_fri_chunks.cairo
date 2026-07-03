//! Chunked `fri_answers` equivalence over the REAL fixture proof: computing
//! the answers in query-range chunks (each over its own queried-values
//! slices, as a per-transaction calldata section) must equal the single-shot
//! vendored `fri_answers`.

use core::array::SpanTrait;
use core::box::BoxImpl;
use core::cmp::min;
use snforge_std::fs::{FileTrait, read_txt};
use stwo_cairo_air::claims::CairoClaimImpl;
use stwo_cairo_air::CairoProof;
use stwo_constraint_framework::LookupElementsImpl;
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

const N_SLOTS: u32 = 55_540;
const N_VALUES: u32 = 301_143;
/// Queries per chunk transaction (70 queries at this config → 5 chunks).
const CHUNK_QUERIES: u32 = 16;

#[test]
fn test_chunked_fri_answers_matches_monolithic() {
    let file = FileTrait::new("tests/data/poseidon_chain_n100_full_proof_packed_v2.txt");
    let slots = read_txt(@file);
    let values = unpack_proof_v2(slots.span(), N_VALUES);

    // Phase A gives the transcript checkpoint the FRI phase resumes from.
    let FullCheckpoint { digest_pre_draw, digest_post_prologue, proof_hash: _ } = phase_a(
        values.span(),
    );

    // ---- Replicate phase B's prefix up to the fri_answers inputs
    // (the composition eval is channel-free and irrelevant here).
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

    // Lookup elements are not needed for fri_answers, but the draw is
    // replayed to mirror the production flow's determinism check.
    let mut draw_channel = new_channel(digest_pre_draw);
    let _common_lookup_elements = LookupElementsImpl::draw(ref draw_channel);

    let mut channel = new_channel(digest_post_prologue);
    let trace_lde_log_size = get_trace_lde_log_size(@commitment_scheme.trees);
    let log_trace_degree_bound = trace_lde_log_size - log_blowup_factor;

    let composition_random_coeff = channel.draw_secure_felt();
    let _ = composition_random_coeff;
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

    // ---- Chunked: query ranges over sliced queried values.
    let strides = queried_values_strides(@commitment_scheme.trees);
    let n_queries = SpanTrait::len(query_positions);
    let mut chunked: Array<QM31> = array![];
    let mut start = 0;
    while start != n_queries {
        let n = min(n_queries - start, CHUNK_QUERIES);
        let chunk_answers = fri_answers(
            commitment_scheme.column_indices_per_tree_by_degree_bound(),
            fri_config.log_blowup_factor,
            ood_point,
            sampled_values,
            random_coeff,
            query_positions.slice(start, n),
            slice_queried_values(@queried_values_per_tree, strides.span(), start, n),
            log_trace_degree_bound,
        );
        chunked.append_span(chunk_answers);
        start += n;
    }

    // ---- Monolithic reference.
    let expected = fri_answers(
        commitment_scheme.column_indices_per_tree_by_degree_bound(),
        fri_config.log_blowup_factor,
        ood_point,
        sampled_values,
        random_coeff,
        query_positions,
        queried_values_per_tree,
        log_trace_degree_bound,
    );

    assert!(SpanTrait::len(expected) == chunked.len());
    let mut i = 0;
    for answer in chunked.span() {
        assert!(*answer == *expected[i]);
        i += 1;
    }
}
