//! Test-module gating by build: the poseidon (default) suite runs against
//! the poseidon fixture proof; the qm31/blake pivot suite runs with
//!   snforge test --no-default-features --features qm31_opcode,blake_outputs_packing
//! against the blake fixture proof (docs/lane2-design.md, "The qm31 pivot,
//! measured end-to-end").

#[cfg(feature: "poseidon252_verifier")]
mod test_claim_mix;
#[cfg(feature: "poseidon252_verifier")]
mod test_constants_probe;
#[cfg(feature: "poseidon252_verifier")]
mod test_emitter_calldata;
#[cfg(feature: "poseidon252_verifier")]
mod test_fri_chunks;
#[cfg(feature: "poseidon252_verifier")]
mod test_lookup_chunks;
#[cfg(feature: "poseidon252_verifier")]
mod test_machine;
#[cfg(feature: "poseidon252_verifier")]
mod test_oods_chunks;
#[cfg(feature: "poseidon252_verifier")]
mod test_resumable_full;
#[cfg(feature: "poseidon252_verifier")]
mod test_router;
#[cfg(feature: "poseidon252_verifier")]
mod test_sections;
#[cfg(feature: "poseidon252_verifier")]
mod test_witness_groups;

#[cfg(not(feature: "poseidon252_verifier"))]
mod test_machine_blake;
#[cfg(not(feature: "poseidon252_verifier"))]
mod test_oods_chunks_blake;
