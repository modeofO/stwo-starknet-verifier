//! Chunked `fri_answers` — monster 2 of the lane-2 sub-phasing
//! (docs/lane2-design.md).
//!
//! The 12.75M-step `fri_answers` block needs NO algebraic state across
//! chunks: each query's answer is independent (`answers[q] = Σ_groups
//! accumulate_row_quotients(...)`), and the queried values are consumed in
//! query-major order with a fixed per-query stride per tree (one M31 per
//! committed column). So a transaction can compute any contiguous query
//! range by calling the *vendored* `fri_answers` verbatim over:
//!
//! - the range's slice of `query_positions`, and
//! - each tree's queried-values slice `[start·stride_i, end·stride_i)`,
//!   where `stride_i` = tree i's column count.
//!
//! Cross-chunk checkpoint state is just the answers accumulated so far
//! (70 QM31 total at our config) — plus, in the production machine, the
//! per-tree queried-values digests the Merkle phases established (a chunk's
//! slice re-binds by digest, since the same bytes were already
//! Merkle-verified). The per-group quotient constants are recomputed per
//! transaction; that is the price of statelessness and is small
//! (∝ columns, ≈ one extra query's worth of work per chunk).
//!
//! Equivalence with single-shot `fri_answers` over the real fixture proof is
//! asserted in `tests/test_fri_chunks.cairo`.

use stwo_verifier_core::fields::m31::M31;
use stwo_verifier_core::pcs::verifier::QueriedValues;
use stwo_verifier_core::vcs::MerkleHasher;
use stwo_verifier_core::vcs::verifier::MerkleVerifier;
use stwo_verifier_core::TreeArray;

/// Per-query stride of each tree's queried-values array: one value per
/// committed column.
pub fn queried_values_strides(trees: @TreeArray<MerkleVerifier<MerkleHasher>>) -> Array<usize> {
    let mut strides = array![];
    for tree in trees.span() {
        strides.append((*tree.column_log_deg_bounds).len());
    }
    strides
}

/// Slices each tree's queried values to the rows of queries
/// `[start, start + n_queries)`. In the production machine the transaction
/// receives exactly this slice as calldata; here it also serves the
/// equivalence test.
pub fn slice_queried_values(
    queried_values_per_tree: @QueriedValues, strides: Span<usize>, start: usize, n_queries: usize,
) -> QueriedValues {
    let mut sliced: Array<Span<M31>> = array![];
    let mut tree_index = 0;
    for queried_values in queried_values_per_tree.span() {
        let stride = *strides[tree_index];
        sliced.append((*queried_values).slice(start * stride, n_queries * stride));
        tree_index += 1;
    }
    sliced
}
