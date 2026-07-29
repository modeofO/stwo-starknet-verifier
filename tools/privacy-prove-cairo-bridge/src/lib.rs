//! Shared prove/wrap core of the privacy bridge, plus a C FFI surface so the
//! same soundness-critical pipeline (pinned PCS configs, padding targets,
//! output binding) links into an iOS app unchanged. The CLI in main.rs is a
//! thin wrapper over this crate; lane-2 transport tooling stays in the CLI.

pub mod spill_alloc;

/// Route large allocations to unlinked file-backed mappings so the prover's
/// LDE/witness buffers stay out of the Darwin phys_footprint ledger (the
/// budget iOS enforces). See spill_alloc.rs.
#[global_allocator]
static GLOBAL: spill_alloc::SpillAlloc = spill_alloc::SpillAlloc;

use std::path::PathBuf;


use cairo_vm::vm::runners::cairo_pie::CairoPie;
use circuit_cairo_serialize::proof::prepare_circuit_proof_for_cairo_verifier;
use cairo_air::flat_claims::FlatClaim;
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
use circuits_stark_verifier::proof::ProofConfig;
use cairo_program_runner_lib::tasks::create_cairo1_program_task;
use cairo_program_runner_lib::Task;
use privacy_prove::consts::CAIRO_PROVER_PARAMS;
use privacy_prove::run_privacy_bootloader_task;
use starknet_types_core::felt::Felt;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use stwo::core::vcs_lifted::blake2_merkle::{
    Blake2sM31MerkleChannel, Blake2sMerkleChannel, Blake2sMerkleHasher,
};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::mempool::BaseColumnPool;
use stwo_cairo_prover::prover::prove_cairo;

pub type Error = Box<dyn std::error::Error>;

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

/// Runs the task under the privacy bootloader (stage 1 shared by all prove modes).
pub fn bootloader_stage(
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
pub fn prove_stage(
    task_path: &PathBuf,
    program_args_file: Option<PathBuf>,
) -> Result<(CairoProof<Blake2sMerkleHasher>, Vec<Felt>), Error> {
    let (prover_input, output_preimage) = bootloader_stage(task_path, program_args_file)?;

    eprintln!("[prove 2/2] stwo-proving the bootloader run");
    let cairo_proof = prove_cairo::<Blake2sM31MerkleChannel>(prover_input, CAIRO_PROVER_PARAMS)?;
    Ok((cairo_proof, output_preimage))
}

/// Checks the invariants the wrapper relies on at the proof-only boundary.
pub fn check_proof_shape(cairo_proof: &CairoProof<Blake2sMerkleHasher>) -> Result<(), Error> {
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
pub fn wrap_stage(
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
    let c = context.circuit();
    eprintln!(
        "[wrap 1/3] circuit rows: eq={} qm31_ops={} m31_to_u32={} triple_xor={} blake_g_gate={}",
        c.eq.len(),
        c.add.len()
            + c.sub.len()
            + c.mul.len()
            + c.pointwise_mul.len()
            + c.permutation.iter().map(|p| p.inputs.len() + p.outputs.len()).sum::<usize>(),
        c.m31_to_u32.len(),
        c.triple_xor.len(),
        c.blake_g_gate.len(),
    );
    pad_to_targets(&mut context, TARGET_PADDING_SIZES);
    let mut novalue_context = build_cairo_verifier_circuit(cairo_verifier_config);
    pad_to_targets(&mut novalue_context, TARGET_PADDING_SIZES);
    let preprocessed = PreprocessedCircuit::preprocess_circuit(&mut novalue_context);
    let pool = BaseColumnPool::<SimdBackend>::new();
    let circuit_proof =
        prove_circuit_assignment(context.values(), &preprocessed, &pool, PCS_CONFIG)?;
    let inner_pp_log_sizes = preprocessed.preprocessed_trace.log_sizes();
    drop(context);
    drop(novalue_context);
    drop(preprocessed);
    drop(pool);

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
        preprocessed_column_log_sizes: inner_pp_log_sizes,
    };
    let input1 = MultiverifierInput {
        proof: inner_proof.clone(),
        preprocessed_root: inner_preprocessed_root.clone(),
        output_values,
    };
    let input0 = MultiverifierInput {
        proof: inner_proof,
        preprocessed_root: inner_preprocessed_root.clone(),
        output_values,
    };
    let mut multiverifier_context =
        build_multiverifier_circuit::<QM31>(input0, input1, &shared_config);
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
    // The FRI section's start offset in the felt stream. Phase 2 needs it, and
    // the on-chain phase 1 returns it — but only through a transaction trace,
    // and integration's trace endpoint is deprecated. It is derivable here
    // instead: `fri_proof` is the last field of the serialized stark proof and
    // is followed by exactly one felt (`channel_salt`), so the section starts
    // `len - fri_len - 1` felts in. Emitting it at wrap time removes the trace
    // dependency on every network.
    let fri_len = {
        use stwo_cairo_serialize::CairoSerialize;
        let mut buf = Vec::new();
        CairoSerialize::serialize(&multi_circuit_proof.stark_proof.proof.0.fri_proof, &mut buf);
        buf.len()
    };
    let component_log_sizes = circuit_component_log_sizes(
        &all_circuit_components::<NoValue>(),
        &preprocessed_multiverifier.preprocessed_trace.log_sizes(),
    );
    let felts = prepare_circuit_proof_for_cairo_verifier(multi_circuit_proof, &component_log_sizes);
    let hex: Vec<String> = felts.iter().map(|f| format!("0x{f:x}")).collect();
    std::fs::write(out_path, serde_json::to_string(&hex)?)?;
    let fri_offset = hex
        .len()
        .checked_sub(fri_len + 1)
        .ok_or("fri section longer than the proof stream")?;
    std::fs::write(
        out_path.with_extension("meta.json"),
        serde_json::to_string(&serde_json::json!({
            "n_values": hex.len(),
            "fri_offset": fri_offset,
        }))?,
    )?;
    eprintln!("wrote {} felts to {} (fri_offset {fri_offset})", hex.len(), out_path.display());
    Ok(())
}

/// The privacy (bootloader-embedded) cairo-verifier circuit config, adjusted to this
/// proof's component set. The canonical privacy config fixes the component set of the
/// privacy transaction; arbitrary payloads enable a different set (e.g. no pedersen).
/// The resulting circuit root differs per component set, but it enters the multiverifier
/// as a free input that the final statement binds.
pub fn bootloader_config_for_proof(
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
pub fn app_config_for_proof(
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

pub fn read_cairo_proof(path: &PathBuf) -> Result<CairoProof<Blake2sMerkleHasher>, Error> {
    eprintln!("reading Cairo proof from {}", path.display());
    let bytes = std::fs::read(path)?;
    let proof: CairoProof<Blake2sMerkleHasher> = serde_json::from_slice(&bytes)?;
    check_proof_shape(&proof)?;
    Ok(proof)
}

pub fn read_preimage(path: &PathBuf) -> Result<Vec<Felt>, Error> {
    let hex: Vec<String> = serde_json::from_slice(&std::fs::read(path)?)?;
    hex.iter().map(|s| Ok(Felt::from_hex(s)?)).collect()
}

pub fn write_preimage(path: &PathBuf, preimage: &[Felt]) -> Result<(), Error> {
    let pre: Vec<String> = preimage.iter().map(|f| format!("0x{f:x}")).collect();
    std::fs::write(path, serde_json::to_string(&pre)?)?;
    eprintln!("wrote {} output preimage felts to {}", pre.len(), path.display());
    Ok(())
}

/// Cross-checks that the claimed output preimage hashes to the proof's actual output
/// value, so a wrapper operator gets a clear error instead of a deep circuit failure.
pub fn bootloader_outputs_checked(
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
// C FFI (iOS bench / app integration). Panics must not cross the FFI
// boundary, so both entry points run under catch_unwind and report failure
// through the return code: 0 = ok, 1 = pipeline error, 2 = panic, 3 = bad
// arguments. Errors are printed to stderr (visible in the app console).

use std::ffi::CStr;
use std::os::raw::c_char;

fn cstr_path(p: *const c_char) -> Option<PathBuf> {
    if p.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(p) }.to_str().ok()?;
    Some(PathBuf::from(s))
}

fn report(result: std::thread::Result<Result<(), Error>>) -> i32 {
    match result {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => {
            eprintln!("[zkmsg-bridge] error: {e}");
            1
        }
        Err(_) => {
            eprintln!("[zkmsg-bridge] panicked");
            2
        }
    }
}

/// Runs the client prove leg: bootloader + Stwo proof of `task`, writing the
/// serde-JSON CairoProof and the output preimage.
#[unsafe(no_mangle)]
pub extern "C" fn zkmsg_prove(
    task: *const c_char,
    args: *const c_char,
    proof_out: *const c_char,
    preimage_out: *const c_char,
) -> i32 {
    let (Some(task), Some(proof_out), Some(preimage_out)) =
        (cstr_path(task), cstr_path(proof_out), cstr_path(preimage_out))
    else {
        return 3;
    };
    let args = cstr_path(args);
    report(std::panic::catch_unwind(move || -> Result<(), Error> {
        let (cairo_proof, output_preimage) = prove_stage(&task, args)?;
        std::fs::write(&proof_out, serde_json::to_vec(&cairo_proof)?)?;
        write_preimage(&preimage_out, &output_preimage)?;
        Ok(())
    }))
}

/// Runs the wrapper leg over public inputs: cairo-verifier circuit +
/// multiverifier, writing the felt252 stream for the on-chain verifier.
#[unsafe(no_mangle)]
pub extern "C" fn zkmsg_wrap(
    proof_in: *const c_char,
    preimage_in: *const c_char,
    out: *const c_char,
) -> i32 {
    let (Some(proof_in), Some(preimage_in), Some(out)) =
        (cstr_path(proof_in), cstr_path(preimage_in), cstr_path(out))
    else {
        return 3;
    };
    report(std::panic::catch_unwind(move || -> Result<(), Error> {
        let cairo_proof = read_cairo_proof(&proof_in)?;
        let output_preimage = read_preimage(&preimage_in)?;
        let outputs = bootloader_outputs_checked(&cairo_proof, &output_preimage)?;
        let config = bootloader_config_for_proof(&cairo_proof)?;
        wrap_stage(&cairo_proof, &config, outputs, &out)
    }))
}
