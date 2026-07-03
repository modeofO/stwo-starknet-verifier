//! Section-size probe: field-by-field deserialization of the fixture proof
//! stream, printing each section's felt extent. These numbers drive the
//! phase machine's calldata plan (docs/lane2-design.md). Run with
//! `snforge test sections -- --nocapture` equivalent (snforge always shows
//! println output for passing tests when run with `-v`— it also shows on
//! failure; we just always print).

use snforge_std::fs::{FileTrait, read_txt};
use stwo_cairo_air::claim::CairoInteractionClaim;
use stwo_cairo_air::claims::CairoClaim;
use stwo_full_verifier_phases::unpack_proof_v2;
use stwo_verifier_core::fields::m31::M31;
use stwo_verifier_core::fields::qm31::{QM31, QM31Serde};
use stwo_verifier_core::fri::FriProof;
use stwo_verifier_core::pcs::PcsConfig;
use stwo_verifier_core::vcs::MerkleHasher;
use stwo_verifier_core::vcs::verifier::MerkleDecommitment;
use stwo_verifier_core::Hash;

const N_SLOTS: u32 = 55_540;
const N_VALUES: u32 = 301_143;

#[test]
fn test_print_section_sizes() {
    let file = FileTrait::new("tests/data/poseidon_chain_n100_full_proof_packed_v2.txt");
    let slots = read_txt(@file);
    let values = unpack_proof_v2(slots.span(), N_VALUES);
    let total = values.len();
    let mut span = values.span();
    let mut last = 0_u32;

    let _claim: CairoClaim = Serde::deserialize(ref span).expect('claim');
    let off = total - span.len();
    println!("claim: {} felts [0..{}]", off - last, off);
    last = off;

    let _pow: u64 = Serde::deserialize(ref span).expect('pow');
    let off = total - span.len();
    println!("interaction_pow: {} felts", off - last);
    last = off;

    let _icl: CairoInteractionClaim = Serde::deserialize(ref span).expect('icl');
    let off = total - span.len();
    println!("interaction_claim: {} felts", off - last);
    last = off;

    let _config: PcsConfig = Serde::deserialize(ref span).expect('config');
    let off = total - span.len();
    println!("pcs_config: {} felts", off - last);
    last = off;

    let _commitments: Span<Hash> = Serde::deserialize(ref span).expect('commitments');
    let off = total - span.len();
    println!("commitments: {} felts", off - last);
    last = off;

    let _sampled: Span<Span<Span<QM31>>> = Serde::deserialize(ref span).expect('sampled');
    let off = total - span.len();
    println!("sampled_values: {} felts [{}..{}]", off - last, last, off);
    last = off;

    let _decommitments: Array<MerkleDecommitment<MerkleHasher>> = Serde::deserialize(ref span)
        .expect('decommitments');
    let off = total - span.len();
    println!("decommitments: {} felts [{}..{}]", off - last, last, off);
    last = off;

    let _queried: Array<Span<M31>> = Serde::deserialize(ref span).expect('queried');
    let off = total - span.len();
    println!("queried_values: {} felts [{}..{}]", off - last, last, off);
    last = off;

    let _nonce: u64 = Serde::deserialize(ref span).expect('nonce');
    let off = total - span.len();
    println!("pow_nonce: {} felts", off - last);
    last = off;

    let _fri: FriProof = Serde::deserialize(ref span).expect('fri');
    let off = total - span.len();
    println!("fri_proof: {} felts [{}..{}]", off - last, last, off);
    last = off;

    let _salt: u32 = Serde::deserialize(ref span).expect('salt');
    let off = total - span.len();
    println!("salt: {} felts; total {}", off - last, off);
    assert!(span.is_empty());

    // Layout assertions for the fixture (drives the phase machine's
    // calldata plan — see the section map in docs/lane2-design.md).
    // queried_values is 81% of the proof; the claim is 99% program entries.
    assert!(total == 301_143);
    assert!(off == 301_143);
}
