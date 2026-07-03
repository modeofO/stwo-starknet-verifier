//! Bridge from an application Cairo program to the felt252 proof stream consumed by
//! the on-chain Stwo circuit verifier (stwo-cairo `stwo_circuit_verifier`,
//! `main(proof: CircuitProof) -> VerificationOutput`).
//!
//! Subcommands (the proof-only boundary is the point — see docs/architecture.md):
//!
//!   prove <task> <cairo_proof_out.json> <preimage_out.json> [program_args.json]
//!       CLIENT SIDE. Runs the task under the privacy simple bootloader and
//!       Stwo-proves the run (Blake2sM31 channel, privacy params, extended proof
//!       with aux data). Emits a serde-JSON `CairoProof<Blake2sMerkleHasher>` and
//!       the bootloader output preimage (both public; the witness never leaves).
//!
//!   wrap <cairo_proof.json> <preimage.json> <proof_out.json>
//!       WRAPPER SIDE. Takes ONLY the proof + output preimage — no program, no
//!       witness. Verifies the Cairo proof inside the cairo-verifier circuit
//!       (privacy config: the bootloader program embedded in the circuit),
//!       circuit-proves it, wraps in the multiverifier, serializes for the
//!       on-chain verifier.
//!
//!   wrap-app <cairo_proof.json> <proof_out.json>
//!       WRAPPER SIDE, experimental (spike: proof-only wrapping of direct app
//!       proofs). Embeds the proven program itself in the cairo-verifier circuit
//!       config — program, outputs and component set are taken from the proof's
//!       public data; the pinned preprocessed root and privacy PCS config are
//!       enforced. Requires the proof to have the full 11-segment public layout
//!       (bootloader-shaped); raw standalone-executable proofs do not (see
//!       docs/proof-only-wrapping.md).
//!
//!   prove-poseidon <task> <proof_out.json> <params.json> [program_args.json] [--extended <extended_out.json>]
//!       LANE 2. Runs the task under the privacy bootloader, then proves with
//!       the given prover-params JSON (e.g. fixtures/prover_params_poseidon.json:
//!       poseidon252 channel) and serializes cairo-serde felts for the FULL
//!       vendored Cairo verifier (`stwo_cairo_verifier`, poseidon build).
//!       With --extended, also dumps the full `CairoProof` (including
//!       `ExtendedStarkProof.aux`: per-layer Merkle node values + FRI aux) as
//!       serde JSON — the input to `split-witness`.
//!
//!   split-witness <extended_proof.json> <out_dir> [group_size]
//!       LANE 2 witness splitter. Synthesizes per-query-group Merkle
//!       decommitments from `ExtendedStarkProof.aux` (no re-proving: the
//!       aux's `all_node_values` holds every sibling hash a subset walk can
//!       need) and emits, per group, a snforge-readable felt file with the
//!       4 per-tree hash witnesses + the group's queried-value row slices
//!       (query-major, columns sorted by log size — the Cairo verifier's
//!       layout). Self-check: the witness synthesized for the FULL query set
//!       must equal the proof's own `hash_witness` per tree, byte for byte.
//!
//!   full <task> <proof_out.json> [preimage_out.json] [program_args.json]
//!       Legacy one-shot: prove + wrap in memory. Also the default when the
//!       first argument is not a subcommand (backwards compatible).
//!
//! Chain mirrors stwo-circuits' `circuit_multiverifier::verify_test`
//! `test_serialize_multiverifier_proof_for_cairo1_verifier`.

use std::path::PathBuf;

use cairo_vm::vm::runners::cairo_pie::CairoPie;
use circuit_cairo_serialize::proof::prepare_circuit_proof_for_cairo_verifier;
use cairo_air::flat_claims::FlatClaim;
use cairo_air::utils::{serialize_proof_to_file, sort_and_transpose_queried_values, ProofFormat};
use cairo_air::verifier::INTERACTION_POW_BITS as CAIRO_INTERACTION_POW_BITS;
use cairo_air::CairoProof;
use circuit_cairo_verifier::all_components::all_components as all_cairo_components;
use indexmap::IndexMap;
use privacy_circuit_verify::consts::CAIRO_PCS_CONFIG;
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTraceVariant;
use stwo_cairo_common::prover_types::felt::split_f252;
use circuit_cairo_verifier::privacy::get_pcs_config;
use circuit_cairo_verifier::statement::MEMORY_VALUES_LIMBS;
use circuit_cairo_verifier::verify::{
    build_cairo_verifier_circuit, build_fixed_cairo_circuit, get_preprocessed_root,
    prepare_cairo_proof_for_circuit_verifier, CairoVerifierConfig,
};
use privacy_circuit_verify::{compute_privacy_bootloader_output, get_cairo_verifier_config};
use circuit_common::finalize::{pad_to_targets, ComponentSizes};
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_multiverifier::verify::{build_multiverifier_circuit, MultiverifierInput, SharedConfig};
use circuit_prover::prover::{
    prepare_circuit_proof_for_circuit_verifier, prove_circuit_assignment,
    prove_circuit_assignment_with_channel,
};
use circuit_verifier::statement::{
    all_circuit_components, circuit_component_log_sizes, INTERACTION_POW_BITS,
};
use circuits::blake::HashValue;
use circuits::ivalue::NoValue;
use circuits_stark_verifier::order_hash_map::OrderedHashMap;
use circuits_stark_verifier::proof::ProofConfig;
use cairo_program_runner_lib::tasks::create_cairo1_program_task;
use cairo_program_runner_lib::Task;
use privacy_prove::consts::CAIRO_PROVER_PARAMS;
use privacy_prove::run_privacy_bootloader_task;
use starknet_ff::FieldElement as FieldElement252;
use starknet_types_core::felt::Felt;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use stwo::core::pcs::utils::prepare_preprocessed_query_positions;
use stwo::core::vcs_lifted::blake2_merkle::{
    Blake2sM31MerkleChannel, Blake2sMerkleChannel, Blake2sMerkleHasher,
};
use stwo::core::vcs_lifted::poseidon252_merkle::{
    Poseidon252MerkleChannel, Poseidon252MerkleHasher,
};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::mempool::BaseColumnPool;
use stwo_cairo_prover::prover::{prove_cairo, ChannelHash, ProverParameters};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;

type Error = Box<dyn std::error::Error>;

// Constants mirroring `circuit_multiverifier::verify_test` at this rev; the multiverifier
// preprocessed root they produce is what the on-chain Cairo verifier pins.
const PRIVACY_CAIRO_VERIFIER_TRACE_LOG_SIZE: u32 = 21;
const LOG_BLOWUP_FACTOR: u32 = 3;
const PCS_CONFIG: stwo::core::pcs::PcsConfig =
    get_pcs_config(PRIVACY_CAIRO_VERIFIER_TRACE_LOG_SIZE, LOG_BLOWUP_FACTOR);
const TARGET_PADDING_SIZES: ComponentSizes = ComponentSizes {
    eq: 1 << 17,
    qm31_ops: 1 << 21,
    m31_to_u32: 1 << 18,
    triple_xor: 1 << 17,
    blake_g_gate: 1 << 20,
};
const CIRCUIT_N_PREPROCESSED_COLUMNS: usize = 45;

fn multiverifier_preprocessed_column_log_sizes() -> OrderedHashMap<PreProcessedColumnId, u32> {
    [
        ("bitwise_xor_4_0", 8u32),
        ("bitwise_xor_4_1", 8),
        ("bitwise_xor_4_2", 8),
        ("bitwise_xor_7_0", 14),
        ("bitwise_xor_7_1", 14),
        ("bitwise_xor_7_2", 14),
        ("seq_16", 16),
        ("bitwise_xor_8_0", 16),
        ("bitwise_xor_8_1", 16),
        ("bitwise_xor_8_2", 16),
        ("eq_in0_address", 17),
        ("eq_in1_address", 17),
        ("triple_xor_input_addr_0", 17),
        ("triple_xor_input_addr_1", 17),
        ("triple_xor_input_addr_2", 17),
        ("triple_xor_output_addr", 17),
        ("triple_xor_multiplicity", 17),
        ("m31_to_u32_input_addr", 18),
        ("m31_to_u32_output_addr", 18),
        ("m31_to_u32_multiplicity", 18),
        ("bitwise_xor_9_0", 18),
        ("bitwise_xor_9_1", 18),
        ("bitwise_xor_9_2", 18),
        ("blake_g_gate_input_addr_a", 20),
        ("blake_g_gate_input_addr_b", 20),
        ("blake_g_gate_input_addr_c", 20),
        ("blake_g_gate_input_addr_d", 20),
        ("blake_g_gate_input_addr_f0", 20),
        ("blake_g_gate_input_addr_f1", 20),
        ("blake_g_gate_output_addr_a", 20),
        ("blake_g_gate_output_addr_b", 20),
        ("blake_g_gate_output_addr_c", 20),
        ("blake_g_gate_output_addr_d", 20),
        ("blake_g_gate_multiplicity", 20),
        ("bitwise_xor_10_0", 20),
        ("bitwise_xor_10_1", 20),
        ("bitwise_xor_10_2", 20),
        ("qm31_ops_add_flag", 21),
        ("qm31_ops_sub_flag", 21),
        ("qm31_ops_mul_flag", 21),
        ("qm31_ops_pointwise_mul_flag", 21),
        ("qm31_ops_in0_address", 21),
        ("qm31_ops_in1_address", 21),
        ("qm31_ops_out_address", 21),
        ("qm31_ops_mults", 21),
    ]
    .into_iter()
    .map(|(id, log_size)| (PreProcessedColumnId { id: id.to_string() }, log_size))
    .collect()
}

/// Runs the task under the privacy bootloader (stage 1 shared by all prove modes).
fn bootloader_stage(
    task_path: &PathBuf,
    program_args_file: Option<PathBuf>,
) -> Result<(stwo_cairo_adapter::ProverInput, Vec<Felt>), Error> {
    eprintln!("[prove 1/2] running privacy bootloader over {}", task_path.display());
    let task = if task_path.extension().is_some_and(|e| e == "json") {
        create_cairo1_program_task(task_path, None, program_args_file)
            .map_err(|e| format!("create_cairo1_program_task: {e:?}"))?
    } else {
        Task::Pie(CairoPie::read_zip_file(task_path)?)
    };
    Ok(run_privacy_bootloader_task(task)?)
}

/// Stages 1–2: bootloader run + Stwo proof of it (the client side of the boundary).
fn prove_stage(
    task_path: &PathBuf,
    program_args_file: Option<PathBuf>,
) -> Result<(CairoProof<Blake2sMerkleHasher>, Vec<Felt>), Error> {
    let (prover_input, output_preimage) = bootloader_stage(task_path, program_args_file)?;

    eprintln!("[prove 2/2] stwo-proving the bootloader run");
    let cairo_proof = prove_cairo::<Blake2sM31MerkleChannel>(prover_input, CAIRO_PROVER_PARAMS)?;
    Ok((cairo_proof, output_preimage))
}

/// Checks the invariants the wrapper relies on at the proof-only boundary.
fn check_proof_shape(cairo_proof: &CairoProof<Blake2sMerkleHasher>) -> Result<(), Error> {
    let pcs = &cairo_proof.extended_stark_proof.proof.config;
    if *pcs != CAIRO_PCS_CONFIG {
        return Err(format!(
            "proof PCS config {pcs:?} does not match the privacy config {CAIRO_PCS_CONFIG:?} \
             (the client must prove with the privacy prover parameters)"
        )
        .into());
    }
    if cairo_proof.preprocessed_trace_variant != PreProcessedTraceVariant::CanonicalSmall {
        return Err(format!(
            "proof preprocessed trace variant {:?} != CanonicalSmall",
            cairo_proof.preprocessed_trace_variant
        )
        .into());
    }
    Ok(())
}

/// Stages 3–5 over an already-built cairo-verifier circuit config: circuit-prove the
/// cairo verification, wrap in the multiverifier, serialize for the on-chain verifier.
fn wrap_stage(
    cairo_proof: &CairoProof<Blake2sMerkleHasher>,
    cairo_verifier_config: &CairoVerifierConfig,
    outputs: Vec<[M31; MEMORY_VALUES_LIMBS]>,
    out_path: &PathBuf,
) -> Result<(), Error> {
    let FlatClaim { component_enable_bits, .. } = cairo_proof.claim.flatten_claim();

    eprintln!("[wrap 1/3] circuit-proving the cairo verification");
    let (prepared_proof, serialized_aux_data) =
        prepare_cairo_proof_for_circuit_verifier(cairo_proof, &component_enable_bits);
    let mut context = build_fixed_cairo_circuit(
        cairo_verifier_config,
        prepared_proof,
        serialized_aux_data,
        outputs,
    );
    if !context.is_circuit_valid() {
        return Err("cairo-verifier circuit is not valid over this proof".into());
    }
    pad_to_targets(&mut context, TARGET_PADDING_SIZES);
    let mut novalue_context = build_cairo_verifier_circuit(cairo_verifier_config);
    pad_to_targets(&mut novalue_context, TARGET_PADDING_SIZES);
    let preprocessed = PreprocessedCircuit::preprocess_circuit(&mut novalue_context);
    let pool = BaseColumnPool::<SimdBackend>::new();
    let circuit_proof =
        prove_circuit_assignment(context.values(), &preprocessed, &pool, PCS_CONFIG)?;

    let inner_preprocessed_root: HashValue<QM31> =
        circuit_proof.stark_proof.proof.commitments.0[0].into();
    eprintln!(
        "[wrap 1/3] inner circuit root (consumers whitelist this): {:?}",
        inner_preprocessed_root.0.each_ref().map(|w| *w.get())
    );
    let (inner_proof, inner_public_data) =
        prepare_circuit_proof_for_circuit_verifier(circuit_proof);
    let output_values: [QM31; circuit_common::N_RESERVED] = inner_public_data
        .output_values
        .clone()
        .try_into()
        .map_err(|_| "unexpected number of inner output values")?;

    eprintln!("[wrap 2/3] circuit-proving the multiverifier");
    let shared_config = SharedConfig {
        pcs_config: PCS_CONFIG,
        proof_config: ProofConfig::new(
            &all_circuit_components::<QM31>(),
            CIRCUIT_N_PREPROCESSED_COLUMNS,
            &PCS_CONFIG,
            INTERACTION_POW_BITS,
        ),
        preprocessed_column_log_sizes: multiverifier_preprocessed_column_log_sizes(),
    };
    let make_input = || MultiverifierInput {
        proof: inner_proof.clone(),
        preprocessed_root: inner_preprocessed_root.clone(),
        output_values,
    };
    let mut multiverifier_context =
        build_multiverifier_circuit::<QM31>(make_input(), make_input(), &shared_config);
    pad_to_targets(&mut multiverifier_context, TARGET_PADDING_SIZES);
    multiverifier_context.validate_circuit();
    let preprocessed_multiverifier =
        PreprocessedCircuit::preprocess_circuit(&mut multiverifier_context);
    let pool = BaseColumnPool::<SimdBackend>::new();
    let multi_circuit_proof = prove_circuit_assignment_with_channel::<Blake2sMerkleChannel>(
        multiverifier_context.values(),
        &preprocessed_multiverifier,
        &pool,
        PCS_CONFIG,
    )?;

    eprintln!("[wrap 3/3] serializing for the Cairo1 verifier");
    let component_log_sizes = circuit_component_log_sizes(
        &all_circuit_components::<NoValue>(),
        &preprocessed_multiverifier.preprocessed_trace.log_sizes(),
    );
    let felts = prepare_circuit_proof_for_cairo_verifier(multi_circuit_proof, &component_log_sizes);
    let hex: Vec<String> = felts.iter().map(|f| format!("0x{f:x}")).collect();
    std::fs::write(out_path, serde_json::to_string(&hex)?)?;
    eprintln!("wrote {} felts to {}", hex.len(), out_path.display());
    Ok(())
}

/// The privacy (bootloader-embedded) cairo-verifier circuit config, adjusted to this
/// proof's component set. The canonical privacy config fixes the component set of the
/// privacy transaction; arbitrary payloads enable a different set (e.g. no pedersen).
/// The resulting circuit root differs per component set, but it enters the multiverifier
/// as a free input that the final statement binds.
fn bootloader_config_for_proof(
    cairo_proof: &CairoProof<Blake2sMerkleHasher>,
) -> Result<CairoVerifierConfig, Error> {
    let mut config = get_cairo_verifier_config()?;
    let FlatClaim { component_enable_bits, .. } = cairo_proof.claim.flatten_claim();
    let enabled: IndexMap<_, _> = all_cairo_components::<NoValue>()
        .into_iter()
        .zip(component_enable_bits.iter())
        .filter_map(|((name, component), &bit)| bit.then_some((name, component)))
        .collect();
    config.enabled_bits = component_enable_bits;
    config.proof_config = ProofConfig::new(
        &enabled,
        PreProcessedTraceVariant::CanonicalSmall.n_columns(),
        &CAIRO_PCS_CONFIG,
        CAIRO_INTERACTION_POW_BITS,
    );
    Ok(config)
}

/// Design-B config: the *proven application program itself* is embedded in the circuit
/// (instead of the privacy bootloader). Program, outputs and component set come from the
/// proof's public data; the preprocessed root and PCS config are pinned, NOT taken from
/// the proof. The circuit root then binds the app program + component set + topology —
/// consumers whitelist the expected root per application.
fn app_config_for_proof(
    cairo_proof: &CairoProof<Blake2sMerkleHasher>,
) -> Result<(CairoVerifierConfig, Vec<[M31; MEMORY_VALUES_LIMBS]>), Error> {
    let FlatClaim { component_enable_bits, public_data, .. } = cairo_proof.claim.flatten_claim();

    let n_present_segments = public_data.public_memory.public_segments.present_segments().len();
    eprintln!(
        "[wrap-app] proof shape: {} public segments, {} program cells, {} outputs",
        n_present_segments,
        public_data.public_memory.program.len(),
        public_data.public_memory.output.len(),
    );

    let program: Vec<[M31; MEMORY_VALUES_LIMBS]> = public_data
        .public_memory
        .program
        .iter()
        .map(|(_id, value)| split_f252(*value))
        .collect();
    let outputs: Vec<[M31; MEMORY_VALUES_LIMBS]> = public_data
        .public_memory
        .output
        .iter()
        .map(|(_id, value)| split_f252(*value))
        .collect();

    let enabled: IndexMap<_, _> = all_cairo_components::<NoValue>()
        .into_iter()
        .zip(component_enable_bits.iter())
        .filter_map(|((name, component), &bit)| bit.then_some((name, component)))
        .collect();
    let proof_config = ProofConfig::new(
        &enabled,
        PreProcessedTraceVariant::CanonicalSmall.n_columns(),
        &CAIRO_PCS_CONFIG,
        CAIRO_INTERACTION_POW_BITS,
    );
    let lifting_log_size = proof_config.fri.log_evaluation_domain_size() as u32;

    let config = CairoVerifierConfig {
        proof_config,
        enabled_bits: component_enable_bits,
        program: program.into(),
        n_outputs: outputs.len(),
        preprocessed_root: get_preprocessed_root(lifting_log_size),
        preprocessed_trace_variant: PreProcessedTraceVariant::CanonicalSmall,
    };
    Ok((config, outputs))
}

fn read_cairo_proof(path: &PathBuf) -> Result<CairoProof<Blake2sMerkleHasher>, Error> {
    eprintln!("reading Cairo proof from {}", path.display());
    let bytes = std::fs::read(path)?;
    let proof: CairoProof<Blake2sMerkleHasher> = serde_json::from_slice(&bytes)?;
    check_proof_shape(&proof)?;
    Ok(proof)
}

fn read_preimage(path: &PathBuf) -> Result<Vec<Felt>, Error> {
    let hex: Vec<String> = serde_json::from_slice(&std::fs::read(path)?)?;
    hex.iter().map(|s| Ok(Felt::from_hex(s)?)).collect()
}

fn write_preimage(path: &PathBuf, preimage: &[Felt]) -> Result<(), Error> {
    let pre: Vec<String> = preimage.iter().map(|f| format!("0x{f:x}")).collect();
    std::fs::write(path, serde_json::to_string(&pre)?)?;
    eprintln!("wrote {} output preimage felts to {}", pre.len(), path.display());
    Ok(())
}

/// Cross-checks that the claimed output preimage hashes to the proof's actual output
/// value, so a wrapper operator gets a clear error instead of a deep circuit failure.
fn bootloader_outputs_checked(
    cairo_proof: &CairoProof<Blake2sMerkleHasher>,
    output_preimage: &[Felt],
) -> Result<Vec<[M31; MEMORY_VALUES_LIMBS]>, Error> {
    let computed = compute_privacy_bootloader_output(output_preimage);
    let FlatClaim { public_data, .. } = cairo_proof.claim.flatten_claim();
    let from_proof: Vec<[M31; MEMORY_VALUES_LIMBS]> = public_data
        .public_memory
        .output
        .iter()
        .map(|(_id, value)| split_f252(*value))
        .collect();
    if from_proof != vec![computed] {
        return Err("output preimage does not hash to the proof's output value".into());
    }
    Ok(vec![computed])
}

// ---------------------------------------------------------------------------
// Lane-2 witness splitter (docs/lane2-design.md, machine plan v2).
//
// The proof's serialized decommitment is deduplicated across the union of all
// query paths; a query *subset* needs a different (larger) sibling set, so the
// on-chain side cannot slice the union witness. But
// `MerkleDecommitmentLiftedAux.all_node_values` records, per layer, the hashes
// of BOTH children of every internal node visited by the union walk — and a
// subset's paths are a subset of the union's paths, so every sibling a subset
// walk needs is in that map. Synthesis is therefore a replay of the verifier's
// bottom-up walk over the subset positions, pulling lone-node siblings from
// the aux instead of the witness stream. The emitted order (per layer,
// ascending position, leaves → root) is exactly the order both the Rust
// prover emits and the vendored Cairo `MerkleVerifier::verify` consumes.

type PoseidonCairoProof = CairoProof<Poseidon252MerkleHasher>;

/// Replays the Merkle walk for `positions` (must be sorted + deduplicated),
/// collecting the sibling hashes a verifier of exactly this subset consumes.
fn synthesize_witness(
    positions: &[usize],
    aux: &stwo::core::vcs_lifted::verifier::MerkleDecommitmentLiftedAux<Poseidon252MerkleHasher>,
) -> Result<Vec<FieldElement252>, Error> {
    let all_node_values = &aux.all_node_values;
    let mut witness = Vec::new();
    let mut layer_positions: Vec<usize> = positions.to_vec();
    for (layer_idx, layer) in all_node_values.iter().enumerate() {
        let mut parents = Vec::with_capacity(layer_positions.len());
        let mut i = 0;
        while i < layer_positions.len() {
            let pos = layer_positions[i];
            if i + 1 < layer_positions.len() && layer_positions[i + 1] == (pos ^ 1) {
                // Both children present: no witness needed.
                i += 2;
            } else {
                let sibling = pos ^ 1;
                let hash = layer.get(&sibling).ok_or_else(|| {
                    format!("aux is missing sibling {sibling} at layer {layer_idx}")
                })?;
                witness.push(*hash);
                i += 1;
            }
            parents.push(pos >> 1);
        }
        layer_positions = parents;
    }
    if layer_positions.len() != 1 {
        return Err(format!("walk did not converge to the root: {layer_positions:?}").into());
    }
    Ok(witness)
}

fn sorted_dedup(mut v: Vec<usize>) -> Vec<usize> {
    v.sort_unstable();
    v.dedup();
    v
}

/// Per-tree query positions: the preprocessed tree (index 0) queries a
/// possibly different domain size; the mapping mirrors the prover/verifier.
fn tree_query_positions(
    tree_index: usize,
    group_positions: &[usize],
    lifting_log_size: u32,
    pp_max_log_size: u32,
) -> Vec<usize> {
    if tree_index == 0 {
        // The mapping is not monotonic; the walk needs sorted+deduped input
        // (both the Rust prover and the Cairo verifier sort internally).
        sorted_dedup(prepare_preprocessed_query_positions(
            group_positions,
            lifting_log_size,
            pp_max_log_size,
        ))
    } else {
        group_positions.to_vec()
    }
}

fn split_witness(
    extended_proof_path: &PathBuf,
    out_dir: &PathBuf,
    group_size: usize,
) -> Result<(), Error> {
    eprintln!("reading extended proof from {}", extended_proof_path.display());
    let bytes = std::fs::read(extended_proof_path)?;
    let proof: PoseidonCairoProof = serde_json::from_slice(&bytes)?;

    let scheme_proof = &proof.extended_stark_proof.proof.0;
    let aux = &proof.extended_stark_proof.aux;
    let n_trees = scheme_proof.decommitments.len();
    if n_trees != 4 || aux.trace_decommitment.len() != 4 {
        return Err(format!("expected 4 trees, got {n_trees}").into());
    }

    // Global sorted+deduped query positions (the order queried-value rows and
    // the Cairo verifier's `queries.positions` follow).
    let positions = sorted_dedup(aux.unsorted_query_locations.clone());
    let n_queries = positions.len();

    // Tree heights from the aux itself (all_node_values has one map per layer).
    let heights: Vec<u32> = aux
        .trace_decommitment
        .iter()
        .map(|t| t.all_node_values.len() as u32)
        .collect();
    let lifting_log_size = heights[1];
    if heights[2] != lifting_log_size || heights[3] != lifting_log_size {
        return Err(format!("non-preprocessed tree heights differ: {heights:?}").into());
    }
    let pp_max_log_size = heights[0];
    eprintln!(
        "{} unique query positions; tree heights {:?} (lifting {}, preprocessed {})",
        n_queries, heights, lifting_log_size, pp_max_log_size
    );

    // Self-check: the witness synthesized for the FULL query set must equal
    // the proof's own hash witness, per tree — same walk, same aux, so any
    // divergence means the layout assumptions are wrong.
    for tree_index in 0..n_trees {
        let tree_positions =
            tree_query_positions(tree_index, &positions, lifting_log_size, pp_max_log_size);
        let synthesized = synthesize_witness(
            &tree_positions,
            &aux.trace_decommitment[tree_index],
        )?;
        let expected = &scheme_proof.decommitments[tree_index].hash_witness;
        if &synthesized != expected {
            return Err(format!(
                "full-set witness mismatch on tree {tree_index}: synthesized {} felts, proof has {}",
                synthesized.len(),
                expected.len()
            )
            .into());
        }
    }
    eprintln!("full-set self-check passed: synthesized witnesses == proof witnesses (4 trees)");

    // Queried values in the Cairo verifier's layout: per tree, query-major
    // rows with columns sorted by log size (same felts the packed fixture
    // carries in its queried_values section).
    let trace_and_interaction_trace_log_sizes = proof.claim.log_sizes();
    let sorted_queried_values = sort_and_transpose_queried_values(
        &scheme_proof.queried_values,
        trace_and_interaction_trace_log_sizes
            .iter()
            .map(|c| c.as_slice())
            .collect(),
    );
    let strides: Vec<usize> = scheme_proof
        .queried_values
        .iter()
        .map(|tree_cols| tree_cols.len())
        .collect();
    eprintln!("per-query row strides (columns per tree): {strides:?}");

    std::fs::create_dir_all(out_dir)?;
    let n_groups = n_queries.div_ceil(group_size);
    for group in 0..n_groups {
        let start = group * group_size;
        let end = usize::min(start + group_size, n_queries);
        let group_positions = &positions[start..end];

        // Serde stream the snforge test deserializes:
        //   start, n_queries, Array<Span<felt252>> (witnesses), Array<Span<M31>> (rows)
        let mut felts: Vec<String> = Vec::new();
        felts.push(format!("0x{:x}", start));
        felts.push(format!("0x{:x}", end - start));

        felts.push(format!("0x{:x}", n_trees));
        let mut witness_sizes = Vec::new();
        for tree_index in 0..n_trees {
            let tree_positions = tree_query_positions(
                tree_index,
                group_positions,
                lifting_log_size,
                pp_max_log_size,
            );
            let witness = synthesize_witness(
                &tree_positions,
                &aux.trace_decommitment[tree_index],
            )?;
            witness_sizes.push(witness.len());
            felts.push(format!("0x{:x}", witness.len()));
            for hash in &witness {
                felts.push(format!("0x{hash:x}"));
            }
        }

        felts.push(format!("0x{:x}", n_trees));
        let mut row_sizes = Vec::new();
        for (tree_index, stride) in strides.iter().enumerate() {
            let rows = &sorted_queried_values[tree_index][start * stride..end * stride];
            row_sizes.push(rows.len());
            felts.push(format!("0x{:x}", rows.len()));
            for value in rows {
                felts.push(format!("0x{:x}", value.0));
            }
        }

        let path = out_dir.join(format!("witness_group_{group}.txt"));
        std::fs::write(&path, felts.join("\n") + "\n")?;
        eprintln!(
            "group {group}: queries [{start}..{end}), witness felts {witness_sizes:?}, row felts {row_sizes:?}, total {} felts -> {}",
            felts.len(),
            path.display()
        );
    }
    eprintln!("wrote {n_groups} groups (group size {group_size}) to {}", out_dir.display());
    Ok(())
}

fn main() -> Result<(), Error> {
    tracing_subscriber::fmt().init();
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage:\n  \
        privacy_prove_cairo_bridge prove <task.pie.zip|task.executable.json> <cairo_proof_out.json> <preimage_out.json> [program_args.json]\n  \
        privacy_prove_cairo_bridge wrap <cairo_proof.json> <preimage.json> <proof_out.json>\n  \
        privacy_prove_cairo_bridge wrap-app <cairo_proof.json> <proof_out.json>\n  \
        privacy_prove_cairo_bridge prove-poseidon <task> <proof_out.json> <params.json> [program_args.json] [--extended <extended_out.json>]\n  \
        privacy_prove_cairo_bridge split-witness <extended_proof.json> <out_dir> [group_size]\n  \
        privacy_prove_cairo_bridge [full] <task.pie.zip|task.executable.json> <proof_out.json> [preimage_out.json] [program_args.json]";

    match argv.first().map(String::as_str) {
        Some("prove") => {
            let [task, proof_out, preimage_out] = ["task", "proof_out", "preimage_out"]
                .iter()
                .enumerate()
                .map(|(i, name)| {
                    argv.get(i + 1).map(PathBuf::from).ok_or(format!("missing <{name}>\n{usage}"))
                })
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .unwrap();
            let args_file = argv.get(4).map(PathBuf::from);
            let (cairo_proof, output_preimage) = prove_stage(&task, args_file)?;
            let json = serde_json::to_vec(&cairo_proof)?;
            std::fs::write(&proof_out, &json)?;
            eprintln!(
                "wrote Cairo proof ({:.1} MB) to {}",
                json.len() as f64 / 1e6,
                proof_out.display()
            );
            write_preimage(&preimage_out, &output_preimage)?;
        }
        Some("wrap") => {
            let proof_in = argv.get(1).map(PathBuf::from).ok_or(usage)?;
            let preimage_in = argv.get(2).map(PathBuf::from).ok_or(usage)?;
            let out = argv.get(3).map(PathBuf::from).ok_or(usage)?;
            let cairo_proof = read_cairo_proof(&proof_in)?;
            let output_preimage = read_preimage(&preimage_in)?;
            let outputs = bootloader_outputs_checked(&cairo_proof, &output_preimage)?;
            let config = bootloader_config_for_proof(&cairo_proof)?;
            wrap_stage(&cairo_proof, &config, outputs, &out)?;
        }
        Some("prove-poseidon") => {
            // Split off the optional `--extended <path>` flag before
            // positional parsing.
            let mut positional: Vec<String> = Vec::new();
            let mut extended_out: Option<PathBuf> = None;
            let mut iter = argv.iter().skip(1);
            while let Some(arg) = iter.next() {
                if arg == "--extended" {
                    extended_out =
                        Some(PathBuf::from(iter.next().ok_or("--extended needs a path")?));
                } else {
                    positional.push(arg.clone());
                }
            }
            let task = positional.first().map(PathBuf::from).ok_or(usage)?;
            let proof_out = positional.get(1).map(PathBuf::from).ok_or(usage)?;
            let params = positional.get(2).map(PathBuf::from).ok_or(usage)?;
            let args_file = positional.get(3).map(PathBuf::from);

            let proof_params: ProverParameters =
                serde_json::from_str(&std::fs::read_to_string(&params)?)?;
            let ChannelHash::Poseidon252 = proof_params.channel_hash else {
                return Err("prove-poseidon expects poseidon252 channel params".into());
            };
            let (prover_input, output_preimage) = bootloader_stage(&task, args_file)?;
            eprintln!(
                "[prove 2/2] stwo-proving with params {} (cairo-serde output)",
                params.display()
            );
            let cairo_proof =
                prove_cairo::<Poseidon252MerkleChannel>(prover_input, proof_params)?;
            serialize_proof_to_file(&cairo_proof, &proof_out, ProofFormat::CairoSerde)?;
            eprintln!("wrote cairo-serde proof to {}", proof_out.display());
            if let Some(extended_path) = extended_out {
                let json = serde_json::to_vec(&cairo_proof)?;
                std::fs::write(&extended_path, &json)?;
                eprintln!(
                    "wrote extended proof with aux ({:.1} MB) to {}",
                    json.len() as f64 / 1e6,
                    extended_path.display()
                );
            }
            eprintln!(
                "output preimage: {:?}",
                output_preimage.iter().map(|f| format!("0x{f:x}")).collect::<Vec<_>>()
            );
        }
        Some("split-witness") => {
            let extended_in = argv.get(1).map(PathBuf::from).ok_or(usage)?;
            let out_dir = argv.get(2).map(PathBuf::from).ok_or(usage)?;
            let group_size: usize =
                argv.get(3).map(|s| s.parse()).transpose()?.unwrap_or(16);
            split_witness(&extended_in, &out_dir, group_size)?;
        }
        Some("wrap-app") => {
            let proof_in = argv.get(1).map(PathBuf::from).ok_or(usage)?;
            let out = argv.get(2).map(PathBuf::from).ok_or(usage)?;
            let cairo_proof = read_cairo_proof(&proof_in)?;
            let (config, outputs) = app_config_for_proof(&cairo_proof)?;
            wrap_stage(&cairo_proof, &config, outputs, &out)?;
        }
        Some(first) => {
            // `full`, or legacy positional form (first arg is the task path).
            let offset = if first == "full" { 1 } else { 0 };
            let task = argv.get(offset).map(PathBuf::from).ok_or(usage)?;
            let out = argv.get(offset + 1).map(PathBuf::from).ok_or(usage)?;
            let preimage_out = argv.get(offset + 2).map(PathBuf::from);
            let args_file = argv.get(offset + 3).map(PathBuf::from);
            let (cairo_proof, output_preimage) = prove_stage(&task, args_file)?;
            check_proof_shape(&cairo_proof)?;
            let outputs = bootloader_outputs_checked(&cairo_proof, &output_preimage)?;
            let config = bootloader_config_for_proof(&cairo_proof)?;
            wrap_stage(&cairo_proof, &config, outputs, &out)?;
            if let Some(p) = preimage_out {
                write_preimage(&p, &output_preimage)?;
            }
        }
        None => return Err(usage.into()),
    }
    Ok(())
}
