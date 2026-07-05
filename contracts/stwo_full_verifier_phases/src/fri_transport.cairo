//! FRI transport v3 — calldata-sliced FRI phases (docs/lane2-design.md,
//! "Devnet drive: the gas oracle falsifies the staged-fri design").
//!
//! The devnet oracle measured staged-section READS at ~122k gas per slot
//! all-in, so any transaction loading the whole 8k-slot fri section from
//! storage exceeds the ~1e9 per-invoke execute budget. The fix follows the
//! design doc's own fusion principle: the bulk of the fri section (the
//! per-layer queried evals + Merkle witnesses) is SELF-AUTHENTICATING
//! against the layer commitments, so it arrives as calldata in the
//! transaction that consumes it and is never stored. Only the tiny
//! transcript-relevant slice rides across transactions:
//!
//! - [`FriHead`] — first/inner layer commitments + the last-layer poly:
//!   everything `FriVerifierImpl::commit` mixes into the channel. A few
//!   hundred felts; supplied as calldata to `machine_fri_commit`, every
//!   `machine_fri_layers*` chunk and `machine_finalize`, bound across them
//!   by `d_fri = poseidon(fri_head felts)` plus the lane-1 query-equality
//!   re-derivation in finalize (Fiat-Shamir itself authenticates the
//!   commitments: they are mixed before the queries are drawn, exactly as
//!   in the monolithic verifier).
//! - The layer proofs ([`FriLayerProof`]: fri_witness + decommitment +
//!   commitment) arrive layer-batched as calldata in the `fri_layers`
//!   chunk transactions; `FriProof` serializes PER LAYER, so the client
//!   slices the existing serialization at layer boundaries.
//!
//! [`fri_head_walk`] mirrors the vendored `FriVerifierImpl::commit`
//! transcript walk (mixes, alpha draws, fold-step chain asserts) without
//! the layer proofs; [`verify_first_layer`] / [`verify_inner_layer`] fork
//! the vendored `FriFirstLayerVerifier::verify` + fold and
//! `FriInnerLayerVerifier::verify_and_fold` (those types are file-private
//! upstream), taking the walk's derived parameters plus one calldata
//! layer proof. The loop-carried `(layer_queries, layer_query_evals)`
//! pair rides the machine checkpoint between chunk transactions.
//!
//! Fork provenance: `compute_decommitment_positions_and_rebuild_evals`,
//! `SparseEvaluation` (+ `fold_line`/`fold_circle`) and
//! `build_merkle_verification_inputs` are copied verbatim from the pinned
//! vendored `verifier_core/src/fri.cairo` (they are private there);
//! `fold_coset`, `fri_fold`, `Queries`, `MerkleVerifier` and the domain
//! types are imported. Equivalence with the vendored
//! `FriVerifier::commit + decommit` over the real proof is asserted in
//! the machine tests of both builds.

use core::array::{SpanIter, SpanTrait};
use core::dict::{Felt252Dict, SquashedFelt252DictTrait};
use core::iter::{IntoIterator, Iterator};
use stwo_verifier_utils::zip_eq::zip_eq;
use stwo_verifier_core::Hash;
use stwo_verifier_core::channel::{Channel, ChannelTrait};
use stwo_verifier_core::circle::{CirclePointM31Impl, CosetImpl};
use stwo_verifier_core::fields::Invertible;
use stwo_verifier_core::fields::qm31::{QM31, QM31Serde, QM31Trait, QM31_EXTENSION_DEGREE};
use stwo_verifier_core::fri::{
    FriConfig, FriLayerProof, FriVerificationError, LOG_PACKED_LEAF_SIZE, fold_coset,
};
use stwo_verifier_core::poly::circle::{
    CanonicCosetImpl, CanonicCosetTrait, CircleDomain, CircleDomainImpl,
};
use stwo_verifier_core::poly::line::{LineDomain, LineDomainImpl, LineDomainTrait, LinePoly};
use stwo_verifier_core::poly::utils::fri_fold;
use stwo_verifier_core::utils::{ArrayImpl, OptionImpl, SpanExTrait, bit_reverse_index, pow2};
use stwo_verifier_core::vcs::MerkleHasher;
use stwo_verifier_core::vcs::verifier::{MerkleVerifier, MerkleVerifierTrait};

/// Copy of the vendored `queries::Queries` — that module is private in
/// verifier_core, and the machine needs to construct query sets from
/// checkpointed positions. Semantics identical (positions ascending).
#[derive(Drop, Copy, Debug, PartialEq)]
pub struct Queries {
    pub positions: Span<usize>,
    pub log_domain_size: u32,
}

#[generate_trait]
pub impl QueriesImpl of QueriesImplTrait {
    /// Copy of the vendored `QueriesImpl::generate`.
    fn generate(ref channel: Channel, log_domain_size: u32, n_queries: usize) -> Queries {
        let mut positions_dict: Felt252Dict<felt252> = Default::default();
        let mut n_dict_entries = 0;
        let domain_size: NonZero<u32> = pow2(log_domain_size).try_into().unwrap();
        while n_dict_entries != n_queries {
            let mut random_words = channel.draw_u32s();
            for word in random_words {
                let (_, position) = DivRem::div_rem(*word, domain_size);
                positions_dict.insert(position.into(), 0);
                n_dict_entries += 1;
                if n_dict_entries == n_queries {
                    break;
                }
            }
        }

        // A squashed dict's entries are sorted by key in ascending order.
        let dict_entries = positions_dict.squash().into_entries();
        let mut sorted_positions: Array<u32> = array![];

        for (position, _, _) in dict_entries {
            sorted_positions.append(position.try_into().unwrap());
        }

        Queries { positions: sorted_positions.span(), log_domain_size }
    }

    fn fold(self: Queries, n_folds: u32) -> Queries {
        Queries {
            positions: get_folded_query_positions(self.positions, n_folds),
            log_domain_size: self.log_domain_size - n_folds,
        }
    }
}

/// Copy of the vendored `queries::get_folded_query_positions`.
pub fn get_folded_query_positions(
    mut query_positions: Span<usize>, n_folds: u32,
) -> Span<usize> {
    let folding_factor = pow2(n_folds);
    let mut prev_folded_position = *query_positions.pop_front().unwrap() / folding_factor;
    let mut folded_positions = array![prev_folded_position];

    for position in query_positions {
        let folded_position = *position / folding_factor;

        if folded_position != prev_folded_position {
            folded_positions.append(folded_position);
            prev_folded_position = folded_position;
        }
    }

    folded_positions.span()
}

/// The transcript-relevant slice of a [`FriProof`]: exactly what
/// `FriVerifierImpl::commit` mixes into the channel, in mix order.
#[derive(Drop, Serde)]
pub struct FriHead {
    pub first_commitment: Hash,
    pub inner_commitments: Span<Hash>,
    pub last_layer_poly: LinePoly,
}

/// Per-inner-layer parameters derived by [`fri_head_walk`] — the fields of
/// the vendored (private) `FriInnerLayerVerifier` minus the proof.
#[derive(Drop)]
pub struct FriLayerParams {
    pub log_degree_bound: u32,
    pub domain: LineDomain,
    pub folding_alpha: QM31,
    pub fold_step: u32,
}

/// Everything the walk derives from a [`FriHead`].
#[derive(Drop)]
pub struct FriHeadWalk {
    /// First-layer commitment domain (queries are sampled over its size).
    pub commitment_domain: CircleDomain,
    pub first_folding_alpha: QM31,
    /// The circle-to-line fold step (== config.fold_step).
    pub fold_step: u32,
    pub first_log_bound: u32,
    pub layers: Array<FriLayerParams>,
    pub last_layer_coeffs: Span<QM31>,
}

/// Mirrors the vendored `FriVerifierImpl::commit` channel transcript and
/// structural asserts over the commitments-only [`FriHead`].
pub fn fri_head_walk(
    ref channel: Channel, config: FriConfig, head: @FriHead, log_bound: u32,
) -> FriHeadWalk {
    channel.mix_commitment(*head.first_commitment);

    let commitment_domain_log_size = log_bound + config.log_blowup_factor;
    let commitment_domain = CanonicCosetImpl::new(commitment_domain_log_size).circle_domain();
    let first_folding_alpha = channel.draw_secure_felt();

    let mut layers = array![];
    let mut layer_log_bound = log_bound - config.fold_step;
    let mut layer_domain = LineDomainImpl::new_unchecked(
        CosetImpl::half_odds(layer_log_bound + config.log_blowup_factor),
    );

    let inner_commitments = *head.inner_commitments;
    let n_inner_layers = SpanTrait::len(inner_commitments);
    let mut layer_index = 0;
    for commitment in inner_commitments {
        channel.mix_commitment(*commitment);

        let fold_step = if layer_index == n_inner_layers - 1 {
            let remaining = layer_log_bound - config.log_last_layer_degree_bound;
            assert!(
                1 <= remaining && remaining <= config.fold_step,
                "{}",
                FriVerificationError::InvalidNumFriLayers,
            );
            remaining
        } else {
            config.fold_step
        };

        layers
            .append(
                FriLayerParams {
                    log_degree_bound: layer_log_bound,
                    domain: layer_domain,
                    folding_alpha: channel.draw_secure_felt(),
                    fold_step,
                },
            );

        layer_log_bound -= fold_step;
        layer_domain = layer_domain.repeated_double(fold_step);
        layer_index += 1;
    }
    assert!(
        layer_log_bound == config.log_last_layer_degree_bound,
        "{}",
        FriVerificationError::InvalidNumFriLayers,
    );
    assert!(
        *head.last_layer_poly.log_size == config.log_last_layer_degree_bound,
        "{}",
        FriVerificationError::LastLayerDegreeInvalid,
    );
    channel.mix_felts(head.last_layer_poly.coeffs.span());

    FriHeadWalk {
        commitment_domain,
        first_folding_alpha,
        fold_step: config.fold_step,
        first_log_bound: log_bound,
        layers,
        last_layer_coeffs: head.last_layer_poly.coeffs.span(),
    }
}

/// Fork of the vendored `FriFirstLayerVerifier::verify` + the circle fold
/// + query fold that `decommit_first_layer`/`decommit_inner_layers` chain
/// through: Merkle-verifies the first layer's proof against its committed
/// root and folds the query evals to the first inner layer.
pub fn verify_first_layer(
    walk: @FriHeadWalk, proof: @FriLayerProof, queries: Queries, query_evals: Span<QM31>,
) -> (Queries, Array<QM31>) {
    let log_size = walk.commitment_domain.log_size();
    assert!(queries.log_domain_size == log_size);

    let mut fri_witness = (*proof.fri_witness).into_iter();
    let mut decommitted_values = array![];

    let (column_decommitment_positions, sparse_evaluation) =
        compute_decommitment_positions_and_rebuild_evals(
        queries, query_evals, ref fri_witness, *walk.fold_step,
    );

    for subset_eval in sparse_evaluation.subset_evals.span() {
        for eval in subset_eval.span() {
            let [v0, v1, v2, v3] = (*eval).to_fixed_array();
            decommitted_values.append(v0);
            decommitted_values.append(v1);
            decommitted_values.append(v2);
            decommitted_values.append(v3);
        };
    }

    assert!(
        fri_witness.next().is_none(), "{}", FriVerificationError::FirstLayerEvaluationsInvalid,
    );

    let leaf_log_size: u32 = if log_size >= LOG_PACKED_LEAF_SIZE && *walk.fold_step > 1 {
        LOG_PACKED_LEAF_SIZE
    } else {
        0
    };
    let merkle_positions = build_merkle_verification_inputs(
        column_decommitment_positions, leaf_log_size,
    );
    let n_columns = QM31_EXTENSION_DEGREE * pow2(leaf_log_size);
    let degree_bound_by_column = ArrayImpl::new_repeated(n: n_columns, v: *walk.first_log_bound);
    let merkle_verifier = MerkleVerifier {
        root: *proof.commitment,
        tree_height: log_size - leaf_log_size,
        column_log_deg_bounds: degree_bound_by_column.span(),
    };
    merkle_verifier
        .verify(merkle_positions, decommitted_values.span(), (*proof.decommitment).clone());

    let folded_evals = sparse_evaluation
        .fold_circle(*walk.first_folding_alpha, *walk.commitment_domain, *walk.fold_step);
    let folded_queries = queries.fold(*walk.fold_step);
    (folded_queries, folded_evals)
}

/// Fork of the vendored `FriInnerLayerVerifier::verify_and_fold`.
pub fn verify_inner_layer(
    params: @FriLayerParams, proof: @FriLayerProof, queries: Queries, evals_at_queries: Span<QM31>,
) -> (Queries, Array<QM31>) {
    assert!(queries.log_domain_size == params.domain.log_size());

    let mut fri_witness = (*proof.fri_witness).into_iter();

    let (decommitment_positions, sparse_evaluation) =
        compute_decommitment_positions_and_rebuild_evals(
        queries, evals_at_queries, ref fri_witness, *params.fold_step,
    );

    assert!(
        fri_witness.next().is_none(), "{}", FriVerificationError::InnerLayerEvaluationsInvalid,
    );

    let mut decommitted_values = array![];
    for subset_eval in sparse_evaluation.subset_evals.span() {
        for eval in subset_eval.span() {
            let [v0, v1, v2, v3] = (*eval).to_fixed_array();
            decommitted_values.append(v0);
            decommitted_values.append(v1);
            decommitted_values.append(v2);
            decommitted_values.append(v3);
        };
    }

    let column_log_size = params.domain.log_size();
    let leaf_log_size: u32 = if column_log_size >= LOG_PACKED_LEAF_SIZE
        && *params.fold_step > 1 {
        LOG_PACKED_LEAF_SIZE
    } else {
        0
    };
    let merkle_positions = build_merkle_verification_inputs(
        decommitment_positions, leaf_log_size,
    );
    let n_columns = QM31_EXTENSION_DEGREE * pow2(leaf_log_size);
    let degree_bound_by_column = ArrayImpl::new_repeated(
        n: n_columns, v: *params.log_degree_bound,
    );
    let merkle_verifier = MerkleVerifier {
        root: *proof.commitment,
        tree_height: column_log_size - leaf_log_size,
        column_log_deg_bounds: degree_bound_by_column.span(),
    };
    merkle_verifier
        .verify(merkle_positions, decommitted_values.span(), (*proof.decommitment).clone());

    let folded_queries = queries.fold(*params.fold_step);
    let folded_evals = sparse_evaluation
        .fold_line(*params.folding_alpha, *params.domain, *params.fold_step);

    (folded_queries, folded_evals)
}

// ---------------------------------------------------------------------------
// Verbatim copies of the vendored fri.cairo privates (pinned upstream).

fn compute_decommitment_positions_and_rebuild_evals(
    mut queries: Queries,
    mut query_evals: Span<QM31>,
    ref witness_evals_iter: SpanIter<QM31>,
    fold_step: u32,
) -> (Span<usize>, SparseEvaluation) {
    let fold_factor = pow2(fold_step);

    let mut decommitment_positions = array![];
    let mut subset_evals = array![];
    let mut subset_domain_start_indices = array![];

    let mut query_positions = queries.positions;
    let mut folded_query_positions = queries.fold(fold_step).positions;

    for folded_query_position in folded_query_positions {
        let subset_start = *folded_query_position * fold_factor;
        let subset_end = subset_start + fold_factor;
        let mut subset_decommitment_positions = (subset_start..subset_end).into_iter();
        let mut subset_eval = array![];

        for decommitment_position in subset_decommitment_positions {
            decommitment_positions.append(decommitment_position);

            subset_eval
                .append(
                    *match query_positions.next_if_eq(@decommitment_position) {
                        Some(_) => query_evals.pop_front().unwrap(),
                        None => witness_evals_iter.next().unwrap(),
                    },
                );
        }

        subset_evals.append(subset_eval);

        subset_domain_start_indices
            .append(bit_reverse_index(subset_start, queries.log_domain_size));
    }

    assert!(query_positions.is_empty());
    assert!(query_evals.is_empty());

    let sparse_evaluation = SparseEvaluationImpl::new(
        subset_evals, subset_domain_start_indices.span(),
    );

    (decommitment_positions.span(), sparse_evaluation)
}

#[derive(Drop)]
struct SparseEvaluation {
    subset_evals: Array<Array<QM31>>,
    subset_domain_initial_indexes: Span<usize>,
}

#[generate_trait]
impl SparseEvaluationImpl of SparseEvaluationTrait {
    fn new(
        subset_evals: Array<Array<QM31>>, subset_domain_initial_indexes: Span<usize>,
    ) -> SparseEvaluation {
        assert!(subset_evals.len() == subset_domain_initial_indexes.len());
        SparseEvaluation { subset_evals, subset_domain_initial_indexes }
    }

    fn fold_line(
        self: @SparseEvaluation, fold_alpha: QM31, source_domain: LineDomain, fold_step: u32,
    ) -> Array<QM31> {
        let mut folded_eval = array![];

        for (subset_eval, subset_domain_initial_index) in zip_eq(
            self.subset_evals.span(), *self.subset_domain_initial_indexes,
        ) {
            let fold_domain_initial = source_domain.coset.index_at(*subset_domain_initial_index);
            let fold_domain = LineDomainImpl::new_unchecked(
                CosetImpl::new(fold_domain_initial, fold_step),
            );
            let mut x_coords = array![];
            let mut j = 0;
            while j < fold_domain.size() {
                let x_coord = fold_domain.at(bit_reverse_index(j, fold_step));
                x_coords.append(x_coord);
                j += 2;
            }

            folded_eval.append(fold_coset(subset_eval.span(), x_coords.span(), fold_alpha));
        }

        folded_eval
    }

    fn fold_circle(
        self: @SparseEvaluation, fold_alpha: QM31, source_domain: CircleDomain, fold_step: u32,
    ) -> Array<QM31> {
        let mut folded_eval = array![];

        if fold_step == 1 {
            for (subset_eval, subset_domain_initial_index) in zip_eq(
                self.subset_evals.span(), *self.subset_domain_initial_indexes,
            ) {
                let boxed_pair: Box<[QM31; 2]> = *subset_eval.span().try_into().unwrap();
                let [v0, v1] = boxed_pair.unbox();
                let circle_point = source_domain.at(*subset_domain_initial_index);
                folded_eval.append(fri_fold(v0, v1, circle_point.y.inverse(), fold_alpha));
            }
            return folded_eval;
        }

        for (subset_eval, subset_domain_initial_index) in zip_eq(
            self.subset_evals.span(), *self.subset_domain_initial_indexes,
        ) {
            let fold_domain_initial = source_domain.index_at(*subset_domain_initial_index);
            let circle_fold_domain = CircleDomainImpl::new(
                CosetImpl::new(fold_domain_initial, fold_step - 1),
            );

            let mut subset_eval = subset_eval.span();
            let mut x_coords = array![];
            let mut line_eval_domain = array![];
            let mut j = 0;
            while let Some(evals) = subset_eval.multi_pop_front::<4>() {
                let [v0, v1, v2, v3] = evals.unbox();
                let circle_pt_0 = circle_fold_domain.at(bit_reverse_index(j, fold_step));
                let circle_pt_1 = circle_fold_domain.at(bit_reverse_index(j + 2, fold_step));
                line_eval_domain.append(fri_fold(v0, v1, circle_pt_0.y.inverse(), fold_alpha));
                line_eval_domain.append(fri_fold(v2, v3, circle_pt_1.y.inverse(), fold_alpha));
                x_coords.append(circle_pt_0.x);
                j += 4;
            }
            let alpha_sq = fold_alpha * fold_alpha;
            folded_eval.append(fold_coset(line_eval_domain.span(), x_coords.span(), alpha_sq));
        }

        folded_eval
    }
}

fn build_merkle_verification_inputs(
    decommitment_positions: Span<u32>, leaf_log_size: u32,
) -> Span<u32> {
    if leaf_log_size == 0 {
        return decommitment_positions;
    }
    let leaf_size = pow2(leaf_log_size);
    let mut merkle_positions = array![];
    let mut prev: Option<u32> = Option::None;
    for pos in decommitment_positions {
        let merkle_pos = *pos / leaf_size;
        if prev != Option::Some(merkle_pos) {
            merkle_positions.append(merkle_pos);
            prev = Option::Some(merkle_pos);
        }
    }
    merkle_positions.span()
}
