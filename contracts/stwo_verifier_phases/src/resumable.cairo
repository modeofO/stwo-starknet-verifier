//! Two-phase (resumable) Stwo circuit verification.
//!
//! `verify_circuit` costs ~1.4e9 L2 gas under production constants — above
//! Starknet's 1.21e9 per-invoke cap — so verification is split at the FRI
//! boundary into two transactions:
//!
//! - **Phase 1** (`phase1`): the full prologue of `verify_circuit` (claim
//!   checks, Fiat-Shamir mixing, commitment absorption, interaction PoW,
//!   logup sum), the OODS composition check, tree Merkle decommitments, and
//!   the FRI first-layer answers. Produces a small [`Checkpoint`].
//! - **Phase 2** (`phase2`): restores the Fiat-Shamir channel from the
//!   checkpoint, re-runs the FRI commitment phase over a caller-supplied
//!   `FriProof`, re-derives the query positions and asserts they equal the
//!   checkpointed ones (this binds the `FriProof` bytes: any change to the
//!   FRI proof changes the channel, hence the queries), then verifies the
//!   FRI decommitment against the checkpointed first-layer evaluations.
//!
//! Soundness notes:
//! - The Fiat-Shamir transcript is byte-identical to the monolithic
//!   `verify_circuit`: the checkpoint stores the channel digest at a point
//!   where `n_draws == 0` (immediately after `mix_sampled_values`), so
//!   `new_channel(digest)` restores the exact state.
//! - Phase 2 accepting *any* FriProof that passes is exactly as sound as
//!   standard FRI: the FRI proof is prover-chosen witness data, and the
//!   query-position equality check enforces the same Fiat-Shamir binding
//!   the monolithic verifier gets from processing both halves in one pass.
//! - The registered fact is computed in phase 1 (it depends only on the
//!   claim) but only becomes valid if phase 2's decommitment passes.
//!
//! This module mirrors the vendored `stwo_circuit_air::verify_circuit` and
//! `stwo_verifier_core::{verifier::verify, pcs::verifier::verify_values}`
//! at stwo-cairo commit 92bfd1d3; review any upstream change against it.

use stwo_circuit_air::claims::{
    CircuitClaim, CircuitInteractionClaim, derive_component_log_sizes, column_log_sizes_per_tree,
    lookup_sum,
};
use stwo_circuit_air::circuit_air::CircuitAirNewImpl;
use stwo_circuit_air::privacy_consts::{
    LIFTING_LOG_SIZE, N_OUTPUTS, PREPROCESSED_COLUMN_LOG_SIZES, circuit_pcs_config,
    preprocessed_root,
};
use stwo_circuit_air::{INTERACTION_POW_BITS, SECURITY_BITS, verify_claim};
use core::box::BoxImpl;
use core::num::traits::Zero;
use stwo_circuit_air::claims::{CircuitClaimTrait, CircuitInteractionClaimTrait};
use stwo_constraint_framework::LookupElementsImpl;
use stwo_verifier_core::channel::blake2s::new_channel;
use stwo_verifier_core::channel::{Channel, ChannelTrait};
use stwo_verifier_core::circle::ChannelGetRandomCirclePointImpl;
use stwo_verifier_core::fields::Invertible;
use stwo_verifier_core::fields::m31::M31Trait;
use stwo_verifier_core::fields::m31::M31;
use stwo_verifier_core::fields::qm31::{QM31, QM31Serde, QM31Trait};
use stwo_verifier_core::fri::{FriProof, FriVerifierTrait};
use stwo_verifier_core::pcs::quotients::fri_answers;
use stwo_verifier_core::pcs::verifier::{
    CommitmentSchemeVerifierImpl, mix_sampled_values, prepare_preprocessed_query_positions,
};
use stwo_verifier_core::pcs::{PcsConfig, PcsConfigTrait};
use stwo_verifier_core::poly::circle::{CanonicCosetImpl, CanonicCosetTrait};
use stwo_verifier_core::utils::ArrayImpl;
use stwo_verifier_core::vcs::blake2s_hasher::{Blake2sHash, Blake2sMerkleHasher};
use stwo_verifier_core::vcs::verifier::{MerkleDecommitment, MerkleVerifierTrait};
use stwo_verifier_core::verifier::{Air, try_extract_composition_eval};
use stwo_verifier_core::Hash;

/// Index of the preprocessed trace tree (mirrors verifier_core's constant).
const PREPROCESSED_TRACE_IDX: usize = 0;

/// State carried from phase 1 to phase 2. Serde-serialized into storage.
#[derive(Drop, Serde)]
pub struct Checkpoint {
    /// Fiat-Shamir channel digest immediately after `mix_sampled_values`
    /// (`n_draws == 0` at that point).
    pub channel_digest: [u32; 8],
    /// The queries proof-of-work nonce from the proof.
    pub proof_of_work_nonce: u64,
    /// FRI query positions derived in phase 1; phase 2 must re-derive the
    /// same ones from its FriProof.
    pub query_positions: Array<u32>,
    /// FRI first-layer evaluations at the query positions.
    pub first_layer_evals: Array<QM31>,
    /// The fact to register if phase 2 succeeds.
    pub fact_output_hash: [u32; 8],
    /// Value offset of the `fri_proof` field within the proof felt stream
    /// (informational, for clients extracting the FRI section).
    pub fri_value_offset: u32,
}

/// Phase 1 over the full proof felt stream (post-unpack).
pub fn phase1(values: Span<felt252>) -> Checkpoint {
    let total = values.len();
    let mut span = values;

    // ---- Manual field-by-field deserialization of CircuitProof, tracking
    // the offset of `fri_proof` so clients can extract the FRI section.
    let claim: CircuitClaim = Serde::deserialize(ref span).expect('claim deser');
    let interaction_pow: u64 = Serde::deserialize(ref span).expect('pow deser');
    let interaction_claim: CircuitInteractionClaim = Serde::deserialize(ref span)
        .expect('icl deser');
    // stark_proof.commitment_scheme_proof fields:
    let pcs_config: PcsConfig = Serde::deserialize(ref span).expect('config deser');
    let commitments: Span<Hash> = Serde::deserialize(ref span).expect('roots deser');
    let sampled_values: Span<Span<Span<QM31>>> = Serde::deserialize(ref span)
        .expect('sampled deser');
    let decommitments: Array<MerkleDecommitment<Blake2sMerkleHasher>> =
        Serde::deserialize(ref span)
        .expect('decommit deser');
    let queried_values: Array<Span<M31>> = Serde::deserialize(ref span).expect('queried deser');
    let proof_of_work_nonce: u64 = Serde::deserialize(ref span).expect('nonce deser');
    let fri_value_offset: u32 = total - span.len();
    let fri_proof: FriProof = Serde::deserialize(ref span).expect('fri deser');
    let channel_salt: u32 = Serde::deserialize(ref span).expect('salt deser');
    assert(span.is_empty(), 'trailing proof data');

    // ---- verify_circuit prologue (mirrors vendored code).
    let preprocessed_column_log_sizes = PREPROCESSED_COLUMN_LOG_SIZES;
    assert!(claim.public_data.output_values.len() == N_OUTPUTS);
    assert!(pcs_config == circuit_pcs_config(), "unexpected proof pcs config");
    let lifting_log_size = LIFTING_LOG_SIZE;

    let component_log_sizes = derive_component_log_sizes(preprocessed_column_log_sizes.span());
    verify_claim(component_log_sizes);

    let mut channel: Channel = Default::default();
    let channel_salt_as_felt: QM31 = M31Trait::reduce_u32(channel_salt).into();
    channel.mix_felts([channel_salt_as_felt].span());

    pcs_config.mix_into(ref channel);
    let mut commitment_scheme = CommitmentSchemeVerifierImpl::new();

    let commitments_box: @Box<[Hash; 4]> = commitments.try_into().unwrap();
    let [
        preprocessed_commitment, trace_commitment, interaction_trace_commitment,
        composition_commitment,
    ] =
        commitments_box
        .unbox();

    let log_sizes = column_log_sizes_per_tree(component_log_sizes);
    let log_sizes_box: @Box<[Span<u32>; 3]> = log_sizes.span().try_into().unwrap();
    let [_, trace_log_sizes, interaction_trace_log_sizes] = log_sizes_box.unbox();

    let log_blowup_factor = pcs_config.fri_config.log_blowup_factor;

    assert!(preprocessed_commitment == preprocessed_root());
    commitment_scheme
        .commit(
            preprocessed_commitment,
            preprocessed_column_log_sizes.span(),
            ref channel,
            log_blowup_factor,
        );

    claim.mix_into(ref channel);
    commitment_scheme.commit(trace_commitment, trace_log_sizes, ref channel, log_blowup_factor);

    assert!(
        channel.verify_pow_nonce(INTERACTION_POW_BITS, interaction_pow),
        "interaction proof of work",
    );
    channel.mix_u64(interaction_pow);

    let common_lookup_elements = LookupElementsImpl::draw(ref channel);
    assert!(
        lookup_sum(@claim, @common_lookup_elements, @interaction_claim).is_zero(),
        "invalid logup sum",
    );

    interaction_claim.mix_into(ref channel);
    commitment_scheme
        .commit(
            interaction_trace_commitment,
            interaction_trace_log_sizes,
            ref channel,
            log_blowup_factor,
        );

    let trace_log_degree_bound = lifting_log_size - log_blowup_factor;
    let circuit_air = CircuitAirNewImpl::new(
        component_log_sizes, @common_lookup_elements, @interaction_claim,
    );

    // ---- verifier_core::verify (first half, mirrors vendored code).
    assert!(pcs_config.security_bits() >= SECURITY_BITS, "security bits too low");

    let composition_random_coeff = channel.draw_secure_felt();

    // COMPOSITION_SPLIT_FACTOR (2) * QM31_EXTENSION_DEGREE (4) = 8 columns.
    commitment_scheme
        .commit(
            composition_commitment,
            [trace_log_degree_bound; 8].span(),
            ref channel,
            log_blowup_factor,
        );

    let ood_point = channel.get_random_point();

    let composition_oods_eval = try_extract_composition_eval(
        sampled_values, ood_point, trace_log_degree_bound,
    )
        .expect('invalid sampled_values');

    let numerator = circuit_air
        .eval_composition_polynomial_at_point(
            ood_point, sampled_values, composition_random_coeff,
        );
    let max_trace_domain = CanonicCosetImpl::new(trace_log_degree_bound);
    let denominator_inv = max_trace_domain.eval_vanishing(ood_point).inverse();
    assert!(composition_oods_eval == numerator * denominator_inv, "oods mismatch");

    // ---- verify_values (first half, mirrors vendored code).
    mix_sampled_values(sampled_values, ref channel);

    // Checkpoint state: n_draws == 0 here (mix_sampled_values ends in a mix).
    let channel_digest = channel.digest.hash.unbox();

    let random_coeff = channel.draw_secure_felt();
    let fri_config = pcs_config.fri_config;

    let mut fri_verifier = FriVerifierTrait::commit(
        ref channel, fri_config, fri_proof, trace_log_degree_bound,
    );

    assert!(
        channel.verify_pow_nonce(pcs_config.pow_bits, proof_of_work_nonce),
        "queries proof of work",
    );
    channel.mix_u64(proof_of_work_nonce);

    let queries = fri_verifier.sample_query_positions(ref channel);
    let query_positions = queries.positions;
    let lifting = trace_log_degree_bound + fri_config.log_blowup_factor;

    // Merkle decommitments for the 4 trees.
    let mut tree_index = 0;
    let mut decommitments = decommitments;
    let trees = commitment_scheme.trees.span();
    let mut queried_values_iter = queried_values.span();
    for decommitment in decommitments {
        let tree = trees[tree_index];
        let tree_queried_values = *queried_values_iter.pop_front().unwrap();
        let positions = if tree_index == PREPROCESSED_TRACE_IDX {
            let pp_max_log_size = *tree.tree_height;
            prepare_preprocessed_query_positions(query_positions, lifting, pp_max_log_size)
        } else {
            query_positions
        };
        tree.verify(positions, tree_queried_values, decommitment);
        tree_index += 1;
    }

    // FRI first-layer answers.
    let first_layer_evals = fri_answers(
        commitment_scheme.column_indices_per_tree_by_degree_bound(),
        fri_config.log_blowup_factor,
        ood_point,
        sampled_values,
        random_coeff,
        query_positions,
        queried_values,
        trace_log_degree_bound,
    );

    // Fact material: blake2s(preprocessed_root ‖ output_values), as in
    // stwo_circuit_air::get_verification_output.
    let fact_output_hash = compute_output_hash(@claim);

    let mut positions_arr = array![];
    for p in query_positions {
        positions_arr.append(*p);
    }
    let mut evals_arr = array![];
    for e in first_layer_evals {
        evals_arr.append(*e);
    }

    Checkpoint {
        channel_digest,
        proof_of_work_nonce,
        query_positions: positions_arr,
        first_layer_evals: evals_arr,
        fact_output_hash,
        fri_value_offset,
    }
}

/// Phase 2: FRI commitment replay + decommitment against the checkpoint.
/// Returns the fact's output-hash words on success (panics otherwise).
pub fn phase2(fri_proof_values: Span<felt252>, checkpoint: Checkpoint) -> [u32; 8] {
    let Checkpoint {
        channel_digest,
        proof_of_work_nonce,
        query_positions,
        first_layer_evals,
        fact_output_hash,
        fri_value_offset: _,
    } = checkpoint;

    let mut span = fri_proof_values;
    let fri_proof: FriProof = Serde::deserialize(ref span).expect('fri deser');
    assert(span.is_empty(), 'trailing fri data');

    let pcs_config = circuit_pcs_config();
    let trace_log_degree_bound = LIFTING_LOG_SIZE - pcs_config.fri_config.log_blowup_factor;

    // Restore the Fiat-Shamir channel (n_draws == 0 at the checkpoint).
    let mut channel = new_channel(Blake2sHash { hash: BoxImpl::new(channel_digest) });

    // Replay the exact draw sequence of the monolithic verifier.
    let _random_coeff = channel.draw_secure_felt();

    let mut fri_verifier = FriVerifierTrait::commit(
        ref channel, pcs_config.fri_config, fri_proof, trace_log_degree_bound,
    );

    assert!(
        channel.verify_pow_nonce(pcs_config.pow_bits, proof_of_work_nonce),
        "queries proof of work",
    );
    channel.mix_u64(proof_of_work_nonce);

    let queries = fri_verifier.sample_query_positions(ref channel);

    // Bind the caller-supplied FriProof to phase 1's transcript: identical
    // query positions ⟺ identical FRI commitment-phase channel evolution.
    let mut expected = query_positions.span();
    assert!(queries.positions.len() == expected.len(), "query count mismatch");
    for p in queries.positions {
        assert!(*p == *expected.pop_front().unwrap(), "query position mismatch");
    }

    fri_verifier.decommit(queries, first_layer_evals.span());

    fact_output_hash
}

/// blake2s(preprocessed_root ‖ output_values) — mirrors the vendored
/// `stwo_circuit_air::get_verification_output` (blake2s configuration).
fn compute_output_hash(claim: @CircuitClaim) -> [u32; 8] {
    let [r0, r1, r2, r3, r4, r5, r6, r7] = preprocessed_root().hash.unbox();
    let mut words = array![r0, r1, r2, r3, r4, r5, r6, r7];
    for value in claim.public_data.output_values.span() {
        let [c0, c1, c2, c3] = (*value).to_fixed_array();
        words.append(c0.into());
        words.append(c1.into());
        words.append(c2.into());
        words.append(c3.into());
    }
    stwo_verifier_utils::blake2s::hash_u32s(words.span()).unbox()
}
