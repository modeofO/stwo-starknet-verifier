//! The pure half of preparing a send: witness, envelope and public tuple.
//!
//! Split out of `app::prepare_send` so the part that must agree with the
//! circuit contains no I/O. `prepare_send` fetches the membership data from a
//! chain and calls this; a phone fetches the same data from a locally rebuilt
//! tree (`zkmsg-gateway`) and calls this. Both must produce identical bytes,
//! because a witness that disagrees with the circuit fails *after* the caller
//! has paid to prove it.
//!
//! Nothing here touches the network, the filesystem, or a subprocess — it is
//! deterministic given its inputs plus the ephemeral key.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;

use crate::args::{args_to_json, build_circuit_args, CircuitInputs};
use crate::app::short_string_felt;
use crate::chain::felt_hex;
use crate::crypto::{ecdh_shared_x, encrypt, poseidon2, scan_keygen};

/// Everything the pure builder needs. Membership data (`merkle_root`, both
/// leaf indices and paths) comes from wherever the caller can get it: a view
/// call, or a locally replayed event log.
pub struct SendInputs<'a> {
    pub merkle_root: Felt,
    pub sender_scan_priv: Felt,
    pub recipient_scan_pub: Felt,
    pub sender_leaf_index: u32,
    pub recipient_leaf_index: u32,
    pub sender_path: &'a [Felt],
    pub recipient_path: &'a [Felt],
    pub text: &'a str,
    /// Normally `None` — a fresh ephemeral key is minted per send and dropped
    /// immediately. Tests pin it to reproduce a known send byte-for-byte.
    pub ephemeral_priv: Option<Felt>,
}

/// The product of a send preparation: the circuit witness, the encrypted
/// body, and the public tuple the store will check against the proof.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SendMaterial {
    /// Short id derived from the commitment — the send's directory name.
    pub id: String,
    /// The 46-felt witness, hex, in the order the circuit consumes it.
    pub args: Vec<String>,
    /// AES-256-GCM envelope: nonce ‖ ciphertext ‖ tag, hex.
    pub ciphertext: String,
    pub commitment: String,
    pub ephemeral_pubkey: String,
    pub merkle_root: String,
    /// Storage key for staging the proof, `poseidon2(commitment, "zkmsg")`.
    pub proof_id: String,
}

/// Builds the witness and envelope. Membership is verified locally first:
/// `build_circuit_args` folds both paths to the root, so a stale root or a
/// wrong path fails here rather than minutes later inside the bootloader.
pub fn build_send(inputs: &SendInputs<'_>) -> Result<SendMaterial> {
    let ephemeral_priv = match inputs.ephemeral_priv {
        Some(k) => k,
        None => scan_keygen().0,
    };

    let (circuit_args, tuple) = build_circuit_args(&CircuitInputs {
        merkle_root: inputs.merkle_root,
        sender_scan_priv: inputs.sender_scan_priv,
        recipient_scan_pub: inputs.recipient_scan_pub,
        ephemeral_priv,
        sender_leaf_index: inputs.sender_leaf_index,
        recipient_leaf_index: inputs.recipient_leaf_index,
        sender_path: inputs.sender_path,
        recipient_path: inputs.recipient_path,
    })?;

    let shared = ecdh_shared_x(&ephemeral_priv, &inputs.recipient_scan_pub)?;
    let ciphertext = encrypt(&shared, inputs.text.as_bytes());

    let id = format!("{:.10}", felt_hex(&tuple.commitment).trim_start_matches("0x"));
    let proof_id = poseidon2(&tuple.commitment, &short_string_felt("zkmsg")?);
    let args: Vec<String> =
        serde_json::from_str(&args_to_json(&circuit_args)).expect("args_to_json round trip");

    Ok(SendMaterial {
        id,
        args,
        ciphertext: hex::encode(&ciphertext),
        commitment: felt_hex(&tuple.commitment),
        ephemeral_pubkey: felt_hex(&tuple.ephemeral_pubkey),
        merkle_root: felt_hex(&tuple.merkle_root),
        proof_id: felt_hex(&proof_id),
    })
}
