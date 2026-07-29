//! Parity tests for the pure send builder.
//!
//! `send::build_send` is the half of a send that must agree with the circuit
//! byte-for-byte: a wrong witness is only discovered after proving and paying
//! for it. These pin it two ways — a deterministic synthetic case that runs in
//! CI, and (locally, opt-in) a replay of a send that actually landed on
//! Sepolia.
//!
//! Note on secrets: the witness carries the sender's `scan_priv` at index 1,
//! so a recorded real witness can never be committed. The replay test reads
//! the operator's own profile and skips when it is absent.

use starknet_types_core::felt::Felt;
use zkmsg_core::crypto::ec_mul_gen_x;
use zkmsg_core::send::{build_send, SendInputs};
use zkmsg_core::tree::MerkleTree;

/// Two members, fixed keys, fixed ephemeral key — so the witness and the whole
/// public tuple are reproducible. Guards the field order the circuit expects.
#[test]
fn synthetic_send_is_deterministic_and_well_formed() {
    let sender_priv = Felt::from(5u32);
    let recipient_priv = Felt::from(7u32);
    let recipient_pub = ec_mul_gen_x(&recipient_priv);

    let mut tree = MerkleTree::new();
    tree.insert(ec_mul_gen_x(&sender_priv));
    tree.insert(recipient_pub);
    let (sender_path, recipient_path) = (tree.path(0), tree.path(1));

    let inputs = |text| SendInputs {
        merkle_root: tree.root(),
        sender_scan_priv: sender_priv,
        recipient_scan_pub: recipient_pub,
        sender_leaf_index: 0,
        recipient_leaf_index: 1,
        sender_path: &sender_path,
        recipient_path: &recipient_path,
        text,
        ephemeral_priv: Some(Felt::from(6u32)),
    };

    let a = build_send(&inputs("hello")).expect("build");
    let b = build_send(&inputs("hello")).expect("rebuild");

    // The witness and public tuple are a pure function of the inputs...
    assert_eq!(a.args, b.args, "witness is not deterministic");
    assert_eq!(a.commitment, b.commitment);
    assert_eq!(a.ephemeral_pubkey, b.ephemeral_pubkey);
    assert_eq!(a.proof_id, b.proof_id);
    // ...but the envelope is not: AES-GCM draws a fresh nonce per call.
    assert_ne!(a.ciphertext, b.ciphertext, "envelope must not repeat a nonce");

    assert_eq!(a.args.len(), 46, "circuit takes exactly 46 felts");
    assert_eq!(a.args[0], a.merkle_root, "args[0] must be the root");
    assert_eq!(a.args[4], "0x0", "args[4] is the sender leaf index");
    assert_eq!(a.args[5], "0x1", "args[5] is the recipient leaf index");
    assert!(a.id.len() == 10 && a.commitment.contains(&a.id), "id is the commitment prefix");
}

/// A stale root (or a wrong path) must fail here — locally, in milliseconds —
/// rather than minutes later inside the bootloader, after the caller has begun
/// paying for a proof that cannot verify.
#[test]
fn membership_that_does_not_fold_is_rejected_before_proving() {
    let sender_priv = Felt::from(5u32);
    let recipient_pub = ec_mul_gen_x(&Felt::from(7u32));
    let mut tree = MerkleTree::new();
    tree.insert(ec_mul_gen_x(&sender_priv));
    tree.insert(recipient_pub);
    let (sender_path, recipient_path) = (tree.path(0), tree.path(1));

    let err = build_send(&SendInputs {
        merkle_root: Felt::from(0xdeadu32), // not this tree's root
        sender_scan_priv: sender_priv,
        recipient_scan_pub: recipient_pub,
        sender_leaf_index: 0,
        recipient_leaf_index: 1,
        sender_path: &sender_path,
        recipient_path: &recipient_path,
        text: "hi",
        ephemeral_priv: Some(Felt::from(6u32)),
    })
    .expect_err("a bad root must not build");
    assert!(
        err.to_string().contains("membership"),
        "expected a membership failure, got: {err}"
    );
}

/// Replays a send that landed on Sepolia: rebuilds its witness from its own
/// recorded inputs and requires an exact match, including the public tuple the
/// on-chain fact was registered against.
///
/// Opt-in and local-only — the recorded witness contains a real `scan_priv`,
/// so it lives in the operator's profile, never in the repo:
///     cargo test -p zkmsg-core --test send_parity -- --ignored
#[test]
#[ignore = "reads the local ~/.zkmsg profile"]
fn replays_a_landed_send_exactly() {
    let path = dirs_home()
        .join(".zkmsg/.zkmsg-boat/sends/12cd279d7e.json");
    let Ok(raw) = std::fs::read_to_string(&path) else {
        eprintln!("skipping: {} not present", path.display());
        return;
    };
    let state: serde_json::Value = serde_json::from_str(&raw).expect("send state json");
    let recorded: Vec<String> = serde_json::from_value(state["args_hex"].clone()).expect("args");
    assert_eq!(recorded.len(), 46);

    let felt = |s: &String| Felt::from_hex(s).expect("felt");
    let sender_path: Vec<Felt> = recorded[6..26].iter().map(felt).collect();
    let recipient_path: Vec<Felt> = recorded[26..46].iter().map(felt).collect();
    let leaf = |s: &String| u32::from_str_radix(s.trim_start_matches("0x"), 16).expect("leaf");

    let rebuilt = build_send(&SendInputs {
        merkle_root: felt(&recorded[0]),
        sender_scan_priv: felt(&recorded[1]),
        recipient_scan_pub: felt(&recorded[2]),
        sender_leaf_index: leaf(&recorded[4]),
        recipient_leaf_index: leaf(&recorded[5]),
        sender_path: &sender_path,
        recipient_path: &recipient_path,
        text: "irrelevant — only the envelope depends on it",
        ephemeral_priv: Some(felt(&recorded[3])),
    })
    .expect("rebuild the landed send");

    assert_eq!(rebuilt.args, recorded, "witness diverged from the landed send");
    // These three are the public tuple the store checked against the proof.
    assert_eq!(rebuilt.commitment, state["expected_commitment"].as_str().unwrap());
    assert_eq!(rebuilt.ephemeral_pubkey, state["expected_ephemeral_pubkey"].as_str().unwrap());
    assert_eq!(rebuilt.merkle_root, state["expected_merkle_root"].as_str().unwrap());
    assert_eq!(rebuilt.proof_id, state["proof_id"].as_str().unwrap());
    assert_eq!(rebuilt.id, state["id"].as_str().unwrap());
}

fn dirs_home() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var("HOME").expect("HOME"))
}
