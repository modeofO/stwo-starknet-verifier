//! Read-only probe of the v4 virtual route on Sepolia: proves one
//! `prove_send` with the real `snip36-prove`, run from the SHARED virtual
//! sender against made-up member and ticket trees, and checks the facts
//! attest the expected v4 message hash. Sends nothing, spends nothing.
//!
//!     cargo run --release -p zkmsg-core --example v4_prove_probe [store]
//!
//! The prover contract never reads the store, so any `store` felt works;
//! the deployed pool's address makes the probe's facts publishable in
//! principle (they would still fail its root checks).

use std::path::PathBuf;
use std::time::Instant;

use serde_json::json;
use starknet_types_core::felt::Felt;
use zkmsg_core::chain::{Chain, felt_hex};
use zkmsg_core::config::{SEPOLIA_PROVER_RPC, SEPOLIA_V4_SEND_PROVER, SEPOLIA_V4_VIRTUAL_SENDER};
use zkmsg_core::crypto::{ec_mul_gen_x, leaf_v3, member_commit, nullifier_v4, ticket_leaf, ticket_nullifier};
use zkmsg_core::invoke_v3::Call;
use zkmsg_core::tree::MerkleTree;
use zkmsg_core::virtual_send::{PublicV4, WitnessV4, check_facts, prove_send_calldata_v4, run_prover, virtual_invoke};

fn main() -> anyhow::Result<()> {
    let store = Felt::from_hex(&std::env::args().nth(1).unwrap_or_else(|| "0x5704e".into()))?;
    let prover = Felt::from_hex(SEPOLIA_V4_SEND_PROVER)?;
    let vsender = Felt::from_hex(SEPOLIA_V4_VIRTUAL_SENDER)?;
    let chain = Chain::new(SEPOLIA_PROVER_RPC, "unused");
    let block = chain.rpc("starknet_blockNumber", json!([]))?.as_u64().unwrap();
    let nonce = Felt::from_hex(chain.rpc("starknet_getNonce", json!([{"block_number": block}, felt_hex(&vsender)]))?.as_str().unwrap())?;

    let (scan_pub, digest, m) = (ec_mul_gen_x(&Felt::from(5u64)), Felt::from(0xd16e57u64), Felt::from(7u64));
    let mut members = MerkleTree::new();
    members.insert(Felt::from(0xaaau64));
    let leaf_index = members.insert(leaf_v3(&scan_pub, &digest, &member_commit(&m)));
    let t = Felt::from(9u64);
    let mut tickets = MerkleTree::new();
    let ticket_index = tickets.insert(ticket_leaf(&t));

    let epoch = block / 5_000;
    let public = PublicV4 {
        store,
        commitment: Felt::from(0xc0u64),
        ephemeral: Felt::from(0xe0u64),
        root: members.root(),
        content_hash: Felt::from(0xc4u64),
        nullifier: nullifier_v4(&store, &m, epoch, 1),
        epoch,
        quota: 10,
        ticket_root: tickets.root(),
        ticket_nullifier: ticket_nullifier(&store, &t),
    };
    let (path, ticket_path) = (members.path(leaf_index), tickets.path(ticket_index));
    let calldata = prove_send_calldata_v4(
        &public,
        &WitnessV4 {
            scan_pub,
            kem_digest: digest,
            member_secret: m,
            slot: 1,
            leaf_index,
            path: &path,
            ticket_secret: t,
            ticket_index,
            ticket_path: &ticket_path,
        },
    )?;
    let tx = virtual_invoke(vsender, &[Call::new(prover, "prove_send", calldata)], nonce);

    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize()?;
    let bin = std::env::var("ZKMSG_PROVER_BIN").map(PathBuf::from).unwrap_or_else(|_| {
        // The worktree has no `.prover/`; the main checkout's build is the one to use.
        let local = repo.join(".prover/sequencer/target/release/snip36-prove");
        if local.exists() { local } else { PathBuf::from("/Users/modeofo/Apps/stwo-starknet-verifier/.prover/sequencer/target/release/snip36-prove") }
    });
    let work = std::env::temp_dir().join(format!("zkmsg-v4-probe-{}", std::process::id()));
    std::fs::create_dir_all(&work)?;
    println!("block {block}, virtual sender nonce {}, prover {}", felt_hex(&nonce), bin.display());
    let started = Instant::now();
    let proof = run_prover(&bin, &work.join("spill"), &work.join("out.json"), SEPOLIA_PROVER_RPC, "SN_SEPOLIA", block, tx)?;
    let facts: Vec<Felt> = proof.proof_facts.iter().map(|f| Felt::from_hex(f).unwrap()).collect();
    check_facts(&facts, public.message_hash(prover), block)?;
    println!(
        "proved in {:.1} s: {} b64 proof bytes; facts attest the v4 message hash {}",
        started.elapsed().as_secs_f64(),
        proof.proof.len(),
        felt_hex(&public.message_hash(prover))
    );
    let _ = std::fs::remove_dir_all(&work);
    Ok(())
}
