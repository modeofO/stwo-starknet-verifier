//! Lane-2 skeleton tests over the REAL poseidon-config proof: the full Cairo
//! verifier's proof of `poseidon_chain(100)` under the privacy bootloader
//! (fixture regenerable with `privacy_prove_cairo_bridge prove-poseidon` +
//! `scripts/pack_proof.py --v2`; see docs/lane2-design.md).

use snforge_std::fs::{FileTrait, read_txt};
use stwo_full_verifier_phases::resumable_full::{
    FullCheckpoint, phase_a, phase_b, verify_full_monolithic,
};
use stwo_full_verifier_phases::unpack_proof_v2;

const N_SLOTS: u32 = 55_540;
const N_VALUES: u32 = 301_143;

fn load_proof() -> Array<felt252> {
    let file = FileTrait::new("tests/data/poseidon_chain_n100_full_proof_packed_v2.txt");
    let slots = read_txt(@file);
    assert!(slots.len() == N_SLOTS.into(), "fixture slot count");
    unpack_proof_v2(slots.span(), N_VALUES)
}

/// The full two-phase flow over the real proof, checked for equivalence
/// against the monolithic verifier (the vendored executable's `main`).
#[test]
fn test_two_phase_matches_monolithic() {
    let values = load_proof();

    let checkpoint = phase_a(values.span());
    let two_phase = phase_b(values.span(), checkpoint);

    let monolithic = verify_full_monolithic(values.span());
    assert!(two_phase == monolithic);
}

/// Phase B must reject bytes that differ from what phase A checked.
#[test]
#[should_panic(expected: 'proof binding')]
fn test_phase_b_rejects_tampered_proof() {
    let values = load_proof();
    let checkpoint = phase_a(values.span());

    // Flip one value in the FRI region (near the end of the stream).
    let target = values.len() - 1_000;
    let mut tampered = array![];
    let mut i = 0;
    for v in values.span() {
        tampered.append(if i == target {
            *v + 1
        } else {
            *v
        });
        i += 1;
    }
    phase_b(tampered.span(), checkpoint);
}

/// A checkpoint with a perturbed transcript digest must not verify: the
/// composition coefficient and everything after it derive from that digest.
#[test]
#[should_panic]
fn test_phase_b_rejects_wrong_checkpoint_digest() {
    let values = load_proof();
    let FullCheckpoint { digest_pre_draw, digest_post_prologue, proof_hash } = phase_a(
        values.span(),
    );
    let forged = FullCheckpoint {
        digest_pre_draw, digest_post_prologue: digest_post_prologue + 1, proof_hash,
    };
    phase_b(values.span(), forged);
}
