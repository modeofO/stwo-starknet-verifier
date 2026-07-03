//! Per-query-group Merkle decommitment witnesses — the bridge's
//! `split-witness` output — verified over the REAL fixture proof: for every
//! query group, the vendored `MerkleVerifier::verify` must accept the group's
//! row slices with the group's synthesized hash witness, against the same
//! tree roots the monolithic verifier uses. All groups × 4 trees.
//!
//! This is the missing half of the fused (tree × query-group) transactions in
//! machine plan v2 (docs/lane2-design.md): `fri_chunks` proved the
//! queried-value rows slice cleanly per query range; here the *decommitments*
//! do too, because the bridge synthesizes a fresh sibling set per group from
//! `ExtendedStarkProof.aux` (the union witness in the proof cannot be sliced).
//!
//! Fixture files `tests/data/witness_group_{g}.txt` are emitted by:
//!   privacy_prove_cairo_bridge split-witness <extended_proof.json> <dir> 16

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
use stwo_verifier_core::fields::m31::{M31, M31Trait};
use stwo_verifier_core::fri::FriVerifierTrait;
use stwo_verifier_core::pcs::verifier::{
    CommitmentSchemeProof, CommitmentSchemeVerifier, CommitmentSchemeVerifierImpl,
    get_trace_lde_log_size, mix_sampled_values, prepare_preprocessed_query_positions,
    QueriedValues,
};
use stwo_verifier_core::vcs::MerkleHasher;
use stwo_verifier_core::vcs::verifier::{MerkleDecommitment, MerkleVerifier, MerkleVerifierTrait};
use stwo_verifier_core::verifier::StarkProof;
use stwo_verifier_core::Hash;

const N_VALUES: u32 = 301_143;
/// Emitted by split-witness at group size 16 over the fixture's 70 queries.
const N_GROUPS: u32 = 5;

/// Everything a fused Merkle-group transaction needs from the transcript
/// replay: the 4 committed trees, the channel-drawn query positions, the
/// proof's queried values and the lifting size for the preprocessed remap.
#[derive(Drop)]
struct Setup {
    trees: Array<MerkleVerifier<MerkleHasher>>,
    query_positions: Span<u32>,
    queried_values: QueriedValues,
    lifting_log_size: u32,
}

/// Replays the transcript over the fixture proof up to query sampling
/// (same prefix as tests/test_fri_chunks.cairo).
fn setup() -> Setup {
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
    let _ood_point = channel.get_random_point();

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
    let _random_coeff = channel.draw_secure_felt();
    let fri_config = config.fri_config;
    let mut fri_verifier = FriVerifierTrait::commit(
        ref channel, fri_config, fri_proof, log_trace_degree_bound,
    );
    assert!(channel.verify_pow_nonce(config.pow_bits, proof_of_work_nonce));
    channel.mix_u64(proof_of_work_nonce);
    let queries = fri_verifier.sample_query_positions(ref channel);

    let CommitmentSchemeVerifier { trees } = commitment_scheme;
    Setup {
        trees,
        query_positions: queries.positions,
        queried_values: queried_values_per_tree,
        lifting_log_size: log_trace_degree_bound + fri_config.log_blowup_factor,
    }
}

/// Reads one witness-group fixture file:
/// (start, n_queries, per-tree hash witnesses, per-tree row slices).
fn read_group(group: u32) -> (u32, u32, Array<Span<felt252>>, Array<Span<M31>>) {
    let file = FileTrait::new(format!("tests/data/witness_group_{}.txt", group));
    let mut span = read_txt(@file).span();
    let start: u32 = Serde::deserialize(ref span).expect('start');
    let n_queries: u32 = Serde::deserialize(ref span).expect('n_queries');
    let witnesses: Array<Span<felt252>> = Serde::deserialize(ref span).expect('witnesses');
    let rows: Array<Span<M31>> = Serde::deserialize(ref span).expect('rows');
    assert!(SpanTrait::is_empty(span), "trailing group data");
    assert!(witnesses.len() == 4);
    assert!(rows.len() == 4);
    (start, n_queries, witnesses, rows)
}

/// Verifies one group's rows + synthesized witness against tree `tree_index`.
fn verify_group_tree(
    setup: @Setup,
    tree_index: u32,
    start: u32,
    n_queries: u32,
    row: Span<M31>,
    hash_witness: Span<felt252>,
) {
    let group_positions = (*setup.query_positions).slice(start, n_queries);
    let tree = setup.trees.span()[tree_index];
    let positions = if tree_index == 0 {
        prepare_preprocessed_query_positions(
            group_positions, *setup.lifting_log_size, *tree.tree_height,
        )
    } else {
        group_positions
    };
    tree.verify(positions, row, MerkleDecommitment::<MerkleHasher> { hash_witness });
}

#[test]
fn test_group_witnesses_verify_all_trees() {
    let setup = setup();
    let strides = queried_values_strides(@setup.trees);
    let n_queries = SpanTrait::len(setup.query_positions);

    let mut covered = 0_u32;
    let mut group = 0_u32;
    while group != N_GROUPS {
        let (start, n, witnesses, rows) = read_group(group);
        assert!(start == covered, "groups must tile the query range");

        // The bridge's row slices must equal the on-chain slice of the
        // proof's queried_values — same bytes a fused (tree × group)
        // transaction transports and Merkle-verifies.
        let sliced = slice_queried_values(@setup.queried_values, strides.span(), start, n);
        let mut tree_index = 0_u32;
        while tree_index != 4 {
            assert!(*rows[tree_index] == *sliced[tree_index], "row slice mismatch");
            verify_group_tree(@setup, tree_index, start, n, *rows[tree_index], *witnesses[tree_index]);
            tree_index += 1;
        }

        covered += n;
        group += 1;
    }
    assert!(covered == n_queries, "groups must cover all queries");
}

#[test]
#[should_panic(expected: "Merkle Verification Error: Root Mismatch")]
fn test_group_witness_tamper_rejected() {
    let setup = setup();
    let (start, n, witnesses, rows) = read_group(0);

    // Flip one felt of the trace tree's witness (length unchanged).
    let original = *witnesses[1];
    let mut tampered: Array<felt252> = array![*original[0] + 1];
    let mut i = 1;
    while i != SpanTrait::len(original) {
        tampered.append(*original[i]);
        i += 1;
    }

    verify_group_tree(@setup, 1, start, n, *rows[1], tampered.span());
}

#[test]
#[should_panic(expected: "Merkle Verification Error: Root Mismatch")]
fn test_group_row_tamper_rejected() {
    let setup = setup();
    let (start, n, witnesses, rows) = read_group(0);

    // Flip one queried value of the trace tree's rows (length unchanged;
    // +1 in the field always changes the value).
    let original = *rows[1];
    let flipped: M31 = *original[0] + M31Trait::reduce_u32(1);
    let mut tampered: Array<M31> = array![flipped];
    let mut i = 1;
    while i != SpanTrait::len(original) {
        tampered.append(*original[i]);
        i += 1;
    }

    verify_group_tree(@setup, 1, start, n, tampered.span(), *witnesses[1]);
}
