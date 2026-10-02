//! Host check: `verify_cli <prefix>` verifies `<prefix>.proof` (base64, as `prove_cli` writes it)
//! against `<prefix>.proof_facts` with the sequencer's own verifier.

use starknet_api::transaction::fields::{Proof, ProofFacts};

fn main() {
    let prefix = std::env::args().nth(1).expect("usage: verify_cli <prefix>");
    let proof: Proof = serde_json::from_value(serde_json::Value::String(
        std::fs::read_to_string(format!("{prefix}.proof")).unwrap().trim().to_string(),
    ))
    .unwrap();
    let facts: ProofFacts =
        serde_json::from_str(&std::fs::read_to_string(format!("{prefix}.proof_facts")).unwrap())
            .unwrap();
    match starknet_proof_verifier::verify_proof(facts, proof) {
        Ok(()) => println!("VERIFY OK"),
        Err(e) => {
            println!("VERIFY FAIL: {e}");
            std::process::exit(1)
        }
    }
}
