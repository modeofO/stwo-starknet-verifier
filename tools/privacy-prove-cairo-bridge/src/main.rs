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
//!   prove-blake <task> <proof_out.json> <params.json> [program_args.json] [--extended <extended_out.json>]
//!       LANE 2, qm31 pivot. Same flow as prove-poseidon but with the PLAIN
//!       blake2s channel (`Blake2sMerkleChannel`): the vendored verifier's
//!       default build keeps raw blake2s digests (only DRAWS reduce mod M31,
//!       identically in both Rust variants), so `Blake2sM31MerkleChannel` —
//!       whose per-hash M31 output reduction exists for the recursion
//!       circuits — does NOT match it (measured: interaction PoW fails).
//!       Params: fixtures/prover_params_blake.json — identical PCS shape to
//!       the poseidon params (70 queries, blowup 1, fold_step 1) so all
//!       lane-2 section-map assumptions carry over, but preprocessed_trace
//!       MUST be "canonical" (the default build pins the WITH-pedersen
//!       root). Emits cairo-serde felts for the qm31-opcode verifier build;
//!       --extended dumps the aux for split-witness / emit-calldata.
//!
//!   split-witness <extended_proof.json> <out_dir> [group_size]
//!       (group_size defaults to 7 in both subcommands — the production
//!       fused-group size under the staged-section store; the committed
//!       poseidon 16/5 fixtures pass 16 explicitly.)
//!       LANE 2 witness splitter. Synthesizes per-query-group Merkle
//!       decommitments from `ExtendedStarkProof.aux` (no re-proving: the
//!       aux's `all_node_values` holds every sibling hash a subset walk can
//!       need) and emits, per group, a snforge-readable felt file with the
//!       4 per-tree hash witnesses + the group's queried-value row slices
//!       (query-major, columns sorted by log size — the Cairo verifier's
//!       layout). Self-check: the witness synthesized for the FULL query set
//!       must equal the proof's own `hash_witness` per tree, byte for byte.
//!
//!   emit-calldata <extended_proof.json> <out_dir> [chunk_entries] [group_size]
//!       LANE 2 per-transaction calldata emitter for the StwoVerifierRouter
//!       (contracts/stwo_full_verifier_phases/src/router.cairo). Emits, all
//!       packed v2 (one felt per line, hex):
//!         head.txt            — head surgery: the claim with its program
//!                               truncated to the 6-entry prefix verify_claim
//!                               reads, + interaction pow + interaction claim
//!                               + pcs config + commitments + queries-PoW
//!                               nonce + channel salt;
//!         chunk_NN.txt        — program-entry chunks (serde MemorySection
//!                               slices; the claim AND lookup phases replay
//!                               the same files at the same boundaries);
//!         sampled.txt         — the sampled-values section;
//!         fri_head.txt        — the FriHead commitment slice (transport
//!                               v3: first/inner commitments + last-layer
//!                               poly — all fri_commit/fri_layers/finalize
//!                               consume as calldata);
//!         fri_layers_NN.txt   — greedy layer-batched Array<FriLayerProof>
//!                               chunks (chunk 0 led by the first-layer
//!                               proof), each ≤ 4,300 packed slots;
//!         group_NN_rows.txt / group_NN_witnesses.txt
//!                             — per query group: queried-value row slices
//!                               (Array<Span<M31>> serde) and synthesized
//!                               per-tree Merkle witnesses
//!                               (Array<Span<felt252>> serde);
//!         manifest.json       — file list in call order with the unpacked
//!                               n_values every router argument needs.
//!       Self-checks: the per-section serializations must concatenate to
//!       exactly the proof's full cairo-serde stream, the chunk entry felts
//!       must reproduce the claim's program section, and the synthesized
//!       full-set witnesses must equal the proof's own (as in
//!       split-witness).
//!
//!   full <task> <proof_out.json> [preimage_out.json] [program_args.json]
//!       Legacy one-shot: prove + wrap in memory. Also the default when the
//!       first argument is not a subcommand (backwards compatible).
//!
//! Chain mirrors stwo-circuits' `circuit_multiverifier::verify_test`
//! `test_serialize_multiverifier_proof_for_cairo1_verifier`.

use std::path::PathBuf;


use cairo_air::utils::{serialize_proof_to_file, sort_and_transpose_queried_values, ProofFormat};
use cairo_air::CairoProof;
use starknet_ff::FieldElement as FieldElement252;
use stwo::core::pcs::utils::prepare_preprocessed_query_positions;
use stwo::core::vcs_lifted::blake2_merkle::{
    Blake2sMerkleChannel, Blake2sMerkleHasher,
};
use stwo::core::vcs_lifted::poseidon252_merkle::{
    Poseidon252MerkleChannel, Poseidon252MerkleHasher,
};
use stwo_cairo_prover::prover::{prove_cairo, ChannelHash, ProverParameters};

use privacy_prove_cairo_bridge::{
    app_config_for_proof, bootloader_config_for_proof, bootloader_outputs_checked,
    bootloader_stage, check_proof_shape, prove_stage, read_cairo_proof, read_preimage,
    wrap_stage, write_preimage, Error,
};

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
type BlakeCairoProof = CairoProof<Blake2sMerkleHasher>;

/// Emission of a Merkle-witness hash into the snforge felt stream, matching
/// the vendored Cairo `Serde<Hash>`: one felt for a poseidon hash, 8 LE u32
/// words for a blake2s hash.
trait WitnessHashFelts {
    fn to_hex_felts(&self) -> Vec<String>;
}

impl WitnessHashFelts for FieldElement252 {
    fn to_hex_felts(&self) -> Vec<String> {
        vec![format!("0x{self:x}")]
    }
}

impl WitnessHashFelts for stwo::core::vcs::blake2_hash::Blake2sHash {
    fn to_hex_felts(&self) -> Vec<String> {
        self.0
            .chunks_exact(4)
            .map(|c| format!("0x{:x}", u32::from_le_bytes(c.try_into().unwrap())))
            .collect()
    }
}

/// Replays the Merkle walk for `positions` (must be sorted + deduplicated),
/// collecting the sibling hashes a verifier of exactly this subset consumes.
fn synthesize_witness<H: stwo::core::vcs_lifted::MerkleHasherLifted>(
    positions: &[usize],
    aux: &stwo::core::vcs_lifted::verifier::MerkleDecommitmentLiftedAux<H>,
) -> Result<Vec<H::Hash>, Error> {
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
    blake: bool,
) -> Result<(), Error> {
    eprintln!("reading extended proof from {}", extended_proof_path.display());
    let bytes = std::fs::read(extended_proof_path)?;
    if blake {
        let proof: BlakeCairoProof = serde_json::from_slice(&bytes)?;
        split_witness_impl(&proof, out_dir, group_size)
    } else {
        let proof: PoseidonCairoProof = serde_json::from_slice(&bytes)?;
        split_witness_impl(&proof, out_dir, group_size)
    }
}

fn split_witness_impl<H: stwo::core::vcs_lifted::MerkleHasherLifted>(
    proof: &CairoProof<H>,
    out_dir: &PathBuf,
    group_size: usize,
) -> Result<(), Error>
where
    H::Hash: WitnessHashFelts,
{
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
                felts.extend(hash.to_hex_felts());
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

// ---------------------------------------------------------------------------
// Lane-2 per-transaction calldata emitter (router transport).

/// The head's claim carries exactly the program prefix `verify_claim` reads
/// (mirror of `machine.cairo::HEAD_PROGRAM_ENTRIES`).
const HEAD_PROGRAM_ENTRIES: usize = 6;

const U32_MAX_LIMB: u64 = 0xFFFF_FFFF;
const FELT_ESCAPE_LIMB: u64 = 0xFFFF_FFFE;

/// Packing v2 — mirror of `scripts/pack_proof.py --v2` and the contract's
/// `unpack_proof_v2`: 7 LE u32 limbs per felt252 slot; `0xFFFFFFFF` escapes
/// a (lo, hi) u64 pair (any value in [0xFFFFFFFE, 2^64)); `0xFFFFFFFE`
/// escapes a full felt252 as 8 LE u32 limbs.
fn pack_v2(values: &[FieldElement252]) -> Vec<FieldElement252> {
    let mut limbs: Vec<u64> = Vec::new();
    for value in values {
        let bytes = value.to_bytes_be(); // 32 bytes, big-endian
        let mut words = [0u64; 4]; // LE u64 words
        for (i, chunk) in bytes.rchunks(8).enumerate() {
            let mut w = [0u8; 8];
            w[8 - chunk.len()..].copy_from_slice(chunk);
            words[i] = u64::from_be_bytes(w);
        }
        if words[1] == 0 && words[2] == 0 && words[3] == 0 {
            let v = words[0];
            if v < FELT_ESCAPE_LIMB {
                limbs.push(v);
            } else {
                limbs.push(U32_MAX_LIMB);
                limbs.push(v & U32_MAX_LIMB);
                limbs.push(v >> 32);
            }
        } else {
            limbs.push(FELT_ESCAPE_LIMB);
            for k in 0..8 {
                limbs.push((words[k / 2] >> (32 * (k % 2))) & U32_MAX_LIMB);
            }
        }
    }
    limbs
        .chunks(7)
        .map(|chunk| {
            let mut slot = FieldElement252::ZERO;
            let mut shift = FieldElement252::ONE;
            let two_pow_32 = FieldElement252::from(1u64 << 32);
            for limb in chunk {
                slot += FieldElement252::from(*limb) * shift;
                shift *= two_pow_32;
            }
            slot
        })
        .collect()
}

fn write_packed(
    out_dir: &PathBuf,
    name: &str,
    values: &[FieldElement252],
) -> Result<serde_json::Value, Error> {
    let packed = pack_v2(values);
    let lines: Vec<String> = packed.iter().map(|f| format!("0x{f:x}")).collect();
    std::fs::write(out_dir.join(name), lines.join("\n") + "\n")?;
    Ok(serde_json::json!({
        "file": name,
        "n_values": values.len(),
        "packed_slots": packed.len(),
    }))
}

fn emit_calldata(
    extended_proof_path: &PathBuf,
    out_dir: &PathBuf,
    chunk_entries: usize,
    group_size: usize,
    blake: bool,
) -> Result<(), Error> {
    eprintln!("reading extended proof from {}", extended_proof_path.display());
    let bytes = std::fs::read(extended_proof_path)?;
    if blake {
        let proof: BlakeCairoProof = serde_json::from_slice(&bytes)?;
        emit_calldata_impl(&proof, out_dir, chunk_entries, group_size)
    } else {
        let proof: PoseidonCairoProof = serde_json::from_slice(&bytes)?;
        emit_calldata_impl(&proof, out_dir, chunk_entries, group_size)
    }
}

fn emit_calldata_impl<H: stwo::core::vcs_lifted::MerkleHasherLifted>(
    proof: &CairoProof<H>,
    out_dir: &PathBuf,
    chunk_entries: usize,
    group_size: usize,
) -> Result<(), Error>
where
    H::Hash: stwo_cairo_serialize::CairoSerialize,
{
    use stwo_cairo_serialize::CairoSerialize;

    let scheme_proof = &proof.extended_stark_proof.proof.0;
    let aux = &proof.extended_stark_proof.aux;

    // The reference: the full cairo-serde stream (what pack_proof.py packs
    // into the committed fixture).
    let mut full: Vec<FieldElement252> = Vec::new();
    CairoSerialize::serialize(proof, &mut full);
    eprintln!("full cairo-serde stream: {} felts", full.len());

    // --- per-section streams (must concatenate to `full`) ----------------
    let ser = |f: &dyn Fn(&mut Vec<FieldElement252>)| {
        let mut out = Vec::new();
        f(&mut out);
        out
    };
    let claim_felts = ser(&|out| CairoSerialize::serialize(&proof.claim, out));
    let mid_felts = ser(&|out| {
        CairoSerialize::serialize(&proof.interaction_pow, out);
        CairoSerialize::serialize(&proof.interaction_claim.flatten_interaction_claim(), out);
        CairoSerialize::serialize(&scheme_proof.config, out);
        CairoSerialize::serialize(&*scheme_proof.commitments, out);
    });
    let sampled_felts = ser(&|out| CairoSerialize::serialize(&*scheme_proof.sampled_values, out));
    let decommitments_felts =
        ser(&|out| CairoSerialize::serialize(&*scheme_proof.decommitments, out));
    let trace_and_interaction_trace_log_sizes = proof.claim.log_sizes();
    let sorted_queried_values = sort_and_transpose_queried_values(
        &scheme_proof.queried_values,
        trace_and_interaction_trace_log_sizes.iter().map(|c| c.as_slice()).collect(),
    );
    let queried_felts = ser(&|out| CairoSerialize::serialize(&*sorted_queried_values, out));
    let nonce_felts = ser(&|out| CairoSerialize::serialize(&scheme_proof.proof_of_work, out));
    let fri_felts = ser(&|out| CairoSerialize::serialize(&scheme_proof.fri_proof, out));
    let salt_felts = ser(&|out| CairoSerialize::serialize(&proof.channel_salt, out));

    let concatenated: Vec<FieldElement252> = [
        claim_felts.as_slice(),
        mid_felts.as_slice(),
        sampled_felts.as_slice(),
        decommitments_felts.as_slice(),
        queried_felts.as_slice(),
        nonce_felts.as_slice(),
        fri_felts.as_slice(),
        salt_felts.as_slice(),
    ]
    .concat();
    if concatenated != full {
        return Err("per-section streams do not concatenate to the full proof stream".into());
    }
    eprintln!("section self-check passed: per-section streams == full stream");

    // --- head surgery -----------------------------------------------------
    let mut head_claim = proof.claim.clone();
    head_claim.public_data.public_memory.program.truncate(HEAD_PROGRAM_ENTRIES);
    let mut head: Vec<FieldElement252> = Vec::new();
    CairoSerialize::serialize(&head_claim, &mut head);
    head.extend_from_slice(&mid_felts);
    head.extend_from_slice(&nonce_felts);
    head.extend_from_slice(&salt_felts);

    // --- program-entry chunks ---------------------------------------------
    let program = &proof.claim.public_data.public_memory.program;
    let program_len = program.len();
    // Chunk self-check: the chunk entry felts (minus the per-chunk length
    // prefixes) must reproduce the claim's program section.
    let program_felts = ser(&|out| CairoSerialize::serialize(program.as_slice(), out));
    let mut replayed: Vec<FieldElement252> = vec![program_felts[0]];
    let mut chunk_streams: Vec<Vec<FieldElement252>> = Vec::new();
    let mut offset = 0usize;
    while offset != program_len {
        let n = usize::min(chunk_entries, program_len - offset);
        let chunk = ser(&|out| CairoSerialize::serialize(&program[offset..offset + n], out));
        replayed.extend_from_slice(&chunk[1..]); // drop the chunk length prefix
        chunk_streams.push(chunk);
        offset += n;
    }
    if replayed != program_felts {
        return Err("chunk streams do not reproduce the program section".into());
    }

    // --- query groups (rows + synthesized witnesses, router serde) ---------
    let positions = sorted_dedup(aux.unsorted_query_locations.clone());
    let n_queries = positions.len();
    let heights: Vec<u32> =
        aux.trace_decommitment.iter().map(|t| t.all_node_values.len() as u32).collect();
    let lifting_log_size = heights[1];
    let pp_max_log_size = heights[0];
    let n_trees = scheme_proof.decommitments.len();
    for tree_index in 0..n_trees {
        let tree_positions =
            tree_query_positions(tree_index, &positions, lifting_log_size, pp_max_log_size);
        let synthesized =
            synthesize_witness(&tree_positions, &aux.trace_decommitment[tree_index])?;
        if &synthesized != &scheme_proof.decommitments[tree_index].hash_witness {
            return Err(format!("full-set witness mismatch on tree {tree_index}").into());
        }
    }
    let strides: Vec<usize> =
        scheme_proof.queried_values.iter().map(|tree_cols| tree_cols.len()).collect();

    std::fs::create_dir_all(out_dir)?;
    let mut manifest = serde_json::Map::new();
    manifest.insert("program_len".into(), program_len.into());
    manifest.insert("chunk_entries".into(), chunk_entries.into());
    manifest.insert("group_size".into(), group_size.into());
    manifest.insert("head".into(), write_packed(out_dir, "head.txt", &head)?);
    manifest.insert("sampled".into(), write_packed(out_dir, "sampled.txt", &sampled_felts)?);

    // --- FRI transport v3: FriHead commitment slice + layer chunks --------
    // (docs/lane2-design.md, "Devnet drive: the gas oracle falsifies the
    // staged-fri design"). The fri section is never stored on-chain: the
    // head (first/inner commitments + last-layer poly, the transcript-
    // relevant slice) goes to fri_commit / every fri_layers chunk /
    // finalize as calldata, and the layer proofs go layer-batched as
    // calldata chunks (serialized Array<FriLayerProof>, chunk 0 led by the
    // first-layer proof), greedily cut under the packed-slot budget.
    const MAX_LAYER_CHUNK_SLOTS: usize = 4_300;
    let fri = &scheme_proof.fri_proof;
    let fri_head = ser(&|out| {
        CairoSerialize::serialize(&fri.first_layer.commitment, out);
        let inner_commitments: Vec<_> =
            fri.inner_layers.iter().map(|layer| layer.commitment.clone()).collect();
        CairoSerialize::serialize(&*inner_commitments, out);
        CairoSerialize::serialize(&fri.last_layer_poly, out);
    });
    // Self-check: the per-piece serializations must reassemble the fri
    // section exactly (FriProof serde = first_layer + inner_layers array +
    // last_layer_poly).
    let reassembled = ser(&|out| {
        CairoSerialize::serialize(&fri.first_layer, out);
        CairoSerialize::serialize(&*fri.inner_layers, out);
        CairoSerialize::serialize(&fri.last_layer_poly, out);
    });
    if reassembled != fri_felts {
        return Err("fri layer slices do not reassemble the fri section".into());
    }
    manifest.insert("fri_head".into(), write_packed(out_dir, "fri_head.txt", &fri_head)?);

    let all_layers: Vec<_> = std::iter::once(fri.first_layer.clone())
        .chain(fri.inner_layers.iter().cloned())
        .collect();
    let mut layer_chunks: Vec<Vec<FieldElement252>> = Vec::new();
    let mut current: Vec<_> = vec![all_layers[0].clone()];
    for layer in &all_layers[1..] {
        let mut candidate = current.clone();
        candidate.push(layer.clone());
        let felts = ser(&|out| CairoSerialize::serialize(&*candidate, out));
        if pack_v2(&felts).len() <= MAX_LAYER_CHUNK_SLOTS {
            current = candidate;
        } else {
            layer_chunks.push(ser(&|out| CairoSerialize::serialize(&*current, out)));
            current = vec![layer.clone()];
        }
    }
    layer_chunks.push(ser(&|out| CairoSerialize::serialize(&*current, out)));
    let mut fri_layers = Vec::new();
    for (index, chunk) in layer_chunks.iter().enumerate() {
        fri_layers.push(write_packed(out_dir, &format!("fri_layers_{index:02}.txt"), chunk)?);
    }
    manifest.insert("fri_layers".into(), fri_layers.into());

    let mut chunks = Vec::new();
    for (index, chunk) in chunk_streams.iter().enumerate() {
        chunks.push(write_packed(out_dir, &format!("chunk_{index:02}.txt"), chunk)?);
    }
    manifest.insert("chunks".into(), chunks.into());

    let n_groups = n_queries.div_ceil(group_size);
    let mut groups = Vec::new();
    for group in 0..n_groups {
        let start = group * group_size;
        let end = usize::min(start + group_size, n_queries);
        let group_positions = &positions[start..end];

        // rows: Array<Span<M31>> serde — n_trees, then per tree len + values.
        let mut rows: Vec<FieldElement252> = vec![n_trees.into()];
        for (tree_index, stride) in strides.iter().enumerate() {
            let tree_rows = &sorted_queried_values[tree_index][start * stride..end * stride];
            rows.push(tree_rows.len().into());
            rows.extend(tree_rows.iter().map(|m| FieldElement252::from(m.0)));
        }
        // witnesses: Array<Span<felt252>> serde.
        let mut witnesses: Vec<FieldElement252> = vec![n_trees.into()];
        for tree_index in 0..n_trees {
            let tree_positions = tree_query_positions(
                tree_index,
                group_positions,
                lifting_log_size,
                pp_max_log_size,
            );
            let witness =
                synthesize_witness(&tree_positions, &aux.trace_decommitment[tree_index])?;
            witnesses.push(witness.len().into());
            // Per-hash CairoSerialize: one felt per poseidon hash, 8 LE u32
            // words per blake hash — the vendored `Serde<Hash>` layout.
            for hash in &witness {
                CairoSerialize::serialize(hash, &mut witnesses);
            }
        }
        groups.push(serde_json::json!({
            "rows": write_packed(out_dir, &format!("group_{group:02}_rows.txt"), &rows)?,
            "witnesses": write_packed(
                out_dir,
                &format!("group_{group:02}_witnesses.txt"),
                &witnesses,
            )?,
        }));
    }
    manifest.insert("groups".into(), groups.into());

    let manifest_path = out_dir.join("manifest.json");
    std::fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)?;
    eprintln!(
        "emitted head + {} chunks + sampled + fri head + {} fri layer chunks + {} groups to {} (manifest: {})",
        chunk_streams.len(),
        layer_chunks.len(),
        n_groups,
        out_dir.display(),
        manifest_path.display()
    );
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
        privacy_prove_cairo_bridge prove-blake <task> <proof_out.json> <params.json> [program_args.json] [--extended <extended_out.json>]\n  \
        privacy_prove_cairo_bridge split-witness <extended_proof.json> <out_dir> [group_size]\n  \
        privacy_prove_cairo_bridge emit-calldata <extended_proof.json> <out_dir> [chunk_entries] [group_size]\n  \
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
        Some("prove-blake") => {
            // Identical flow to prove-poseidon, plain blake2s channel (the
            // vendored verifier's default build; see the doc comment above —
            // Blake2sM31 does NOT match it).
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
            let ChannelHash::Blake2s = proof_params.channel_hash else {
                return Err("prove-blake expects blake2s channel params".into());
            };
            let (prover_input, output_preimage) = bootloader_stage(&task, args_file)?;
            eprintln!(
                "[prove 2/2] stwo-proving with params {} (cairo-serde output)",
                params.display()
            );
            let started = std::time::Instant::now();
            let cairo_proof =
                prove_cairo::<Blake2sMerkleChannel>(prover_input, proof_params)?;
            eprintln!("proved in {:.1} s", started.elapsed().as_secs_f64());
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
            // Optional `--blake` flag: the extended proof is a blake2s-channel
            // (qm31-pivot) proof; witnesses emit as 8 LE u32 words per hash.
            let mut positional: Vec<String> = Vec::new();
            let mut blake = false;
            for arg in argv.iter().skip(1) {
                if arg == "--blake" {
                    blake = true;
                } else {
                    positional.push(arg.clone());
                }
            }
            let extended_in = positional.first().map(PathBuf::from).ok_or(usage)?;
            let out_dir = positional.get(1).map(PathBuf::from).ok_or(usage)?;
            let group_size: usize =
                positional.get(2).map(|s| s.parse()).transpose()?.unwrap_or(7);
            split_witness(&extended_in, &out_dir, group_size, blake)?;
        }
        Some("emit-calldata") => {
            // Optional `--blake` flag, as in split-witness.
            let mut positional: Vec<String> = Vec::new();
            let mut blake = false;
            for arg in argv.iter().skip(1) {
                if arg == "--blake" {
                    blake = true;
                } else {
                    positional.push(arg.clone());
                }
            }
            let extended_in = positional.first().map(PathBuf::from).ok_or(usage)?;
            let out_dir = positional.get(1).map(PathBuf::from).ok_or(usage)?;
            let chunk_entries: usize =
                positional.get(2).map(|s| s.parse()).transpose()?.unwrap_or(540);
            let group_size: usize =
                positional.get(3).map(|s| s.parse()).transpose()?.unwrap_or(7);
            emit_calldata(&extended_in, &out_dir, chunk_entries, group_size, blake)?;
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
