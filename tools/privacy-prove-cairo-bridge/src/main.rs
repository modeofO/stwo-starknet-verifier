//! End-to-end bridge from an application Cairo PIE to the felt252 proof stream
//! consumed by the on-chain Stwo circuit verifier
//! (stwo-cairo `stwo_circuit_verifier`, `main(proof: CircuitProof) -> VerificationOutput`).
//!
//! Chain (mirrors stwo-circuits' `circuit_multiverifier::verify_test`
//! `test_serialize_multiverifier_proof_for_cairo1_verifier`, but over a caller-supplied PIE):
//!   1. Run the PIE under the privacy simple bootloader; adapt to ProverInput.
//!   2. Stwo-prove the bootloader run (Blake2sM31 channel, privacy params).
//!   3. Verify that Cairo proof inside the cairo-verifier circuit (privacy config,
//!      padded to the multiverifier's target sizes); circuit-prove the assignment.
//!   4. Build the multiverifier circuit over two copies of that circuit proof;
//!      circuit-prove it with the lossless Blake2s channel.
//!   5. Serialize with `prepare_circuit_proof_for_cairo_verifier` to a JSON hex felt array
//!      (the `scarb execute --arguments-file` format).
//!
//! Usage: privacy_prove_cairo_bridge <cairo_pie.zip> <proof_out.json> [preimage_out.json]

use std::path::PathBuf;

use cairo_vm::vm::runners::cairo_pie::CairoPie;
use circuit_cairo_serialize::proof::prepare_circuit_proof_for_cairo_verifier;
use cairo_air::flat_claims::FlatClaim;
use cairo_air::verifier::INTERACTION_POW_BITS as CAIRO_INTERACTION_POW_BITS;
use circuit_cairo_verifier::all_components::all_components as all_cairo_components;
use indexmap::IndexMap;
use privacy_circuit_verify::consts::CAIRO_PCS_CONFIG;
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTraceVariant;
use circuit_cairo_verifier::privacy::get_pcs_config;
use circuit_cairo_verifier::verify::{
    build_cairo_verifier_circuit, build_fixed_cairo_circuit,
    prepare_cairo_proof_for_circuit_verifier,
};
use privacy_circuit_verify::{compute_privacy_bootloader_output, get_cairo_verifier_config};
use circuit_common::finalize::{ComponentSizes, pad_to_targets};
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_multiverifier::verify::{MultiverifierInput, SharedConfig, build_multiverifier_circuit};
use circuit_prover::prover::{
    prepare_circuit_proof_for_circuit_verifier, prove_circuit_assignment,
    prove_circuit_assignment_with_channel,
};
use circuit_verifier::statement::{
    INTERACTION_POW_BITS, all_circuit_components, circuit_component_log_sizes,
};
use circuits::blake::HashValue;
use circuits::ivalue::NoValue;
use circuits_stark_verifier::order_hash_map::OrderedHashMap;
use circuits_stark_verifier::proof::ProofConfig;
use cairo_program_runner_lib::tasks::create_cairo1_program_task;
use cairo_program_runner_lib::Task;
use privacy_prove::consts::CAIRO_PROVER_PARAMS;
use privacy_prove::run_privacy_bootloader_task;
use stwo::core::fields::qm31::QM31;
use stwo::core::pcs::PcsConfig;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sMerkleChannel};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::mempool::BaseColumnPool;
use stwo_cairo_prover::prover::prove_cairo;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;

// Constants mirroring `circuit_multiverifier::verify_test` at this rev; the multiverifier
// preprocessed root they produce is what the on-chain Cairo verifier pins.
const PRIVACY_CAIRO_VERIFIER_TRACE_LOG_SIZE: u32 = 21;
const LOG_BLOWUP_FACTOR: u32 = 3;
const PCS_CONFIG: PcsConfig =
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().init();
    let mut args = std::env::args().skip(1);
    let usage = "usage: privacy_prove_cairo_bridge <task.pie.zip|task.executable.json> <proof_out.json> [preimage_out.json] [program_args_file.json]";
    let task_path = PathBuf::from(args.next().expect(usage));
    let out_path = PathBuf::from(args.next().expect(usage));
    let preimage_out = args.next().map(PathBuf::from);
    let program_args_file = args.next().map(PathBuf::from);

    // 1. Bootloader run. Cairo 1 executables (scarb `.executable.json`) run as
    // Cairo1Program tasks; `.zip` inputs are treated as Cairo PIEs.
    eprintln!("[1/5] running privacy bootloader over {}", task_path.display());
    let task = if task_path.extension().is_some_and(|e| e == "json") {
        create_cairo1_program_task(&task_path, None, program_args_file)
            .map_err(|e| format!("create_cairo1_program_task: {e:?}"))?
    } else {
        Task::Pie(CairoPie::read_zip_file(&task_path)?)
    };
    let (prover_input, output_preimage) = run_privacy_bootloader_task(task)?;

    // 2. Cairo proof of the bootloader run.
    eprintln!("[2/5] stwo-proving the bootloader run");
    let cairo_proof = prove_cairo::<Blake2sM31MerkleChannel>(prover_input, CAIRO_PROVER_PARAMS)?;

    // 3. Cairo-verifier circuit proof (production fixed-circuit path: the circuit
    // config embeds the bootloader program actually proven above).
    eprintln!("[3/5] circuit-proving the cairo verification");
    let mut cairo_verifier_config = get_cairo_verifier_config()?;
    let FlatClaim { component_enable_bits, .. } = cairo_proof.claim.flatten_claim();
    // The canonical privacy config fixes the component set of the privacy transaction;
    // arbitrary payloads enable a different set (e.g. no pedersen). Rebuild the circuit
    // config for THIS proof's component set. The resulting circuit root differs per
    // component set, but it enters the multiverifier as a free input.
    let enabled: IndexMap<_, _> = all_cairo_components::<NoValue>()
        .into_iter()
        .zip(component_enable_bits.iter())
        .filter_map(|((name, component), &bit)| bit.then_some((name, component)))
        .collect();
    cairo_verifier_config.enabled_bits = component_enable_bits.clone();
    cairo_verifier_config.proof_config = ProofConfig::new(
        &enabled,
        PreProcessedTraceVariant::CanonicalSmall.n_columns(),
        &CAIRO_PCS_CONFIG,
        CAIRO_INTERACTION_POW_BITS,
    );
    let (prepared_proof, serialized_aux_data) =
        prepare_cairo_proof_for_circuit_verifier(&cairo_proof, &component_enable_bits);
    let bootloader_outputs = compute_privacy_bootloader_output(&output_preimage);
    let mut context = build_fixed_cairo_circuit(
        &cairo_verifier_config,
        prepared_proof,
        serialized_aux_data,
        vec![bootloader_outputs],
    );
    if !context.is_circuit_valid() {
        return Err("cairo-verifier circuit is not valid over this proof".into());
    }
    pad_to_targets(&mut context, TARGET_PADDING_SIZES);
    let mut novalue_context = build_cairo_verifier_circuit(&cairo_verifier_config);
    pad_to_targets(&mut novalue_context, TARGET_PADDING_SIZES);
    let preprocessed = PreprocessedCircuit::preprocess_circuit(&mut novalue_context);
    let pool = BaseColumnPool::<SimdBackend>::new();
    let circuit_proof =
        prove_circuit_assignment(context.values(), &preprocessed, &pool, PCS_CONFIG)?;

    let inner_preprocessed_root: HashValue<QM31> =
        circuit_proof.stark_proof.proof.commitments.0[0].into();
    let (inner_proof, inner_public_data) =
        prepare_circuit_proof_for_circuit_verifier(circuit_proof);
    let output_values: [QM31; circuit_common::N_RESERVED] = inner_public_data
        .output_values
        .clone()
        .try_into()
        .map_err(|_| "unexpected number of inner output values")?;

    // 4. Multiverifier proof over two copies of the inner proof.
    eprintln!("[4/5] circuit-proving the multiverifier");
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
    let multi_circuit_proof = prove_circuit_assignment_with_channel::<Blake2sMerkleChannel>(
        multiverifier_context.values(),
        &preprocessed_multiverifier,
        &pool,
        PCS_CONFIG,
    )?;

    // 5. Serialize for the on-chain Cairo verifier.
    eprintln!("[5/5] serializing for the Cairo1 verifier");
    let component_log_sizes = circuit_component_log_sizes(
        &all_circuit_components::<NoValue>(),
        &preprocessed_multiverifier.preprocessed_trace.log_sizes(),
    );
    let felts = prepare_circuit_proof_for_cairo_verifier(multi_circuit_proof, &component_log_sizes);
    let hex: Vec<String> = felts.iter().map(|f| format!("0x{f:x}")).collect();
    std::fs::write(&out_path, serde_json::to_string(&hex)?)?;
    eprintln!("wrote {} felts to {}", hex.len(), out_path.display());

    if let Some(p) = preimage_out {
        let pre: Vec<String> = output_preimage.iter().map(|f| format!("0x{f:x}")).collect();
        std::fs::write(&p, serde_json::to_string(&pre)?)?;
        eprintln!("wrote {} output preimage felts to {}", pre.len(), p.display());
    }
    Ok(())
}
