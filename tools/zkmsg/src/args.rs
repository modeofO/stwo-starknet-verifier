//! Circuit args builder — the 46-felt argument vector for
//! fixtures/messagezk_scan, in `main`'s exact declaration order:
//! `[merkle_root, sender_scan_priv, recipient_scan_pub, ephemeral_priv,
//! sender_leaf_index, recipient_leaf_index, s0..s19, r0..r19]`,
//! serialized as the hex-string JSON array the bridge's `prove` consumes
//! (same format as fixtures/poseidon_chain_args_100.json). Also computes
//! the tuple the proof MUST output — the pipeline aborts before spending
//! a single wei if the preimage disagrees.

use anyhow::{Result, ensure};
use starknet_types_core::felt::Felt;

use crate::crypto::{commitment, ec_mul_gen_x, ecdh_shared_x};
use crate::tree::{TREE_DEPTH, fold_path};

/// The public tuple the circuit returns (and the fact binds), in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicTuple {
    pub commitment: Felt,
    pub ephemeral_pubkey: Felt,
    pub merkle_root: Felt,
}

pub struct CircuitInputs<'a> {
    pub merkle_root: Felt,
    pub sender_scan_priv: Felt,
    pub recipient_scan_pub: Felt,
    pub ephemeral_priv: Felt,
    pub sender_leaf_index: u32,
    pub recipient_leaf_index: u32,
    pub sender_path: &'a [Felt],
    pub recipient_path: &'a [Felt],
}

/// Builds the args vector + the expected public tuple, verifying both
/// memberships locally first (a bad path would otherwise burn ~40s of
/// proving before failing inside the bootloader).
pub fn build_circuit_args(inputs: &CircuitInputs<'_>) -> Result<(Vec<Felt>, PublicTuple)> {
    ensure!(inputs.sender_path.len() == TREE_DEPTH as usize, "sender path length");
    ensure!(inputs.recipient_path.len() == TREE_DEPTH as usize, "recipient path length");

    let sender_pub = ec_mul_gen_x(&inputs.sender_scan_priv);
    ensure!(
        fold_path(&sender_pub, inputs.sender_leaf_index, inputs.sender_path)
            == inputs.merkle_root,
        "sender membership does not fold to the root",
    );
    ensure!(
        fold_path(&inputs.recipient_scan_pub, inputs.recipient_leaf_index, inputs.recipient_path)
            == inputs.merkle_root,
        "recipient membership does not fold to the root",
    );

    let shared = ecdh_shared_x(&inputs.ephemeral_priv, &inputs.recipient_scan_pub)?;
    let expected = PublicTuple {
        commitment: commitment(&shared),
        ephemeral_pubkey: ec_mul_gen_x(&inputs.ephemeral_priv),
        merkle_root: inputs.merkle_root,
    };

    let mut args = Vec::with_capacity(46);
    args.push(inputs.merkle_root);
    args.push(inputs.sender_scan_priv);
    args.push(inputs.recipient_scan_pub);
    args.push(inputs.ephemeral_priv);
    args.push(Felt::from(inputs.sender_leaf_index));
    args.push(Felt::from(inputs.recipient_leaf_index));
    args.extend_from_slice(inputs.sender_path);
    args.extend_from_slice(inputs.recipient_path);
    debug_assert_eq!(args.len(), 46);

    Ok((args, expected))
}

/// The bridge's arguments-file format: a JSON array of hex felts.
pub fn args_to_json(args: &[Felt]) -> String {
    let hex: Vec<String> = args.iter().map(|f| format!("{f:#x}")).collect();
    serde_json::to_string(&hex).expect("string vec serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::MerkleTree;

    /// Rebuild the milestone-1 gate args exactly (scan privs 5/7, eph 6)
    /// and check the expected tuple against the addendum's recorded
    /// values — the same numbers the REAL proof's preimage carried.
    #[test]
    fn milestone1_args_and_tuple() {
        let sender_priv = Felt::from(5u32);
        let recipient_priv = Felt::from(7u32);
        let recipient_pub = ec_mul_gen_x(&recipient_priv);

        let mut tree = MerkleTree::new();
        tree.insert(ec_mul_gen_x(&sender_priv));
        tree.insert(recipient_pub);

        let (sender_path, recipient_path) = (tree.path(0), tree.path(1));
        let (args, tuple) = build_circuit_args(&CircuitInputs {
            merkle_root: tree.root(),
            sender_scan_priv: sender_priv,
            recipient_scan_pub: recipient_pub,
            ephemeral_priv: Felt::from(6u32),
            sender_leaf_index: 0,
            recipient_leaf_index: 1,
            sender_path: &sender_path,
            recipient_path: &recipient_path,
        })
        .unwrap();

        assert_eq!(args.len(), 46);
        let hx = |s: &str| Felt::from_hex(s).unwrap();
        assert_eq!(
            tuple.commitment,
            hx("0x24768d5e47fb400baf0a349b5b6b8213ab2bc6d21e142ba9245f4c6a5ac9f9d"),
        );
        assert_eq!(
            tuple.ephemeral_pubkey,
            hx("0x1efc3d7c9649900fcbd03f578a8248d095bc4b6a13b3c25f9886ef971ff96fa"),
        );
        assert_eq!(
            tuple.merkle_root,
            hx("0x225510ca702ebc9c1dad406f8cd08923fd3f8aea5a0ed58eb753265421522cd"),
        );

        let json = args_to_json(&args);
        let parsed: Vec<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 46);
        assert!(parsed[0].starts_with("0x"));
    }

    #[test]
    fn bad_path_rejected_before_proving() {
        let sender_priv = Felt::from(5u32);
        let recipient_pub = ec_mul_gen_x(&Felt::from(7u32));
        let mut tree = MerkleTree::new();
        tree.insert(ec_mul_gen_x(&sender_priv));
        tree.insert(recipient_pub);

        let mut bad_path = tree.path(0);
        bad_path[3] += Felt::ONE;
        let err = build_circuit_args(&CircuitInputs {
            merkle_root: tree.root(),
            sender_scan_priv: sender_priv,
            recipient_scan_pub: recipient_pub,
            ephemeral_priv: Felt::from(6u32),
            sender_leaf_index: 0,
            recipient_leaf_index: 1,
            sender_path: &bad_path,
            recipient_path: &tree.path(1),
        })
        .unwrap_err();
        assert!(err.to_string().contains("sender membership"));
    }
}
