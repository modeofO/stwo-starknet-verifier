//! v2 test driver for a Mac-side SNIP-36 send (no desktop client yet).
//!
//!     v2_cli keygen                                   -> {"kem_seed_hex"}
//!     v2_cli register <keys.json>                     -> register calldata
//!     v2_cli send <keys.json> <send.json>             -> prove + publish calldata
//!     v2_cli open <keys.json> <event.json>            -> plaintext or "not ours"
//!     v2_cli digest <ek_hex_file>                     -> kem_digest of an ek
//!
//! keys.json: {"scan_priv", "kem_seed_hex", "handle"}.
//! send.json: {"store", "prover", "merkle_root", "leaf_index", "path": [20],
//!             "recipient_scan_pub", "recipient_ek_hex", "text"}.
//! event.json: {"commitment", "ephemeral_pub", "content_hex"}.
//! Felts are 0x-hex strings throughout.

use serde_json::{Value, json};
use starknet_types_core::felt::Felt;
use zkmsg_core::chain::{felt_hex, snkeccak};
use zkmsg_core::crypto::{
    KEM_SEED_LEN, bytearray_felts, ec_mul_gen_x, kem_digest, kem_keygen_from_seed, kem_seed_gen,
    leaf_v2, receive_v2, send_v2,
};
use zkmsg_core::tree::fold_path;

fn read(path: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn felt(v: &Value) -> Felt {
    Felt::from_hex(v.as_str().unwrap()).unwrap()
}

fn seed(keys: &Value) -> [u8; KEM_SEED_LEN] {
    hex::decode(keys["kem_seed_hex"].as_str().unwrap()).unwrap().try_into().unwrap()
}

fn hexes(felts: &[Felt]) -> Vec<String> {
    felts.iter().map(felt_hex).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out = match args[1].as_str() {
        "keygen" => json!({ "kem_seed_hex": hex::encode(kem_seed_gen()) }),
        "register" => {
            let keys = read(&args[2]);
            let scan_pub = ec_mul_gen_x(&felt(&keys["scan_priv"]));
            let (_, ek) = kem_keygen_from_seed(&seed(&keys));
            let handle = Felt::from_bytes_be_slice(keys["handle"].as_str().unwrap().as_bytes());
            let mut calldata = vec![handle, scan_pub];
            calldata.extend(bytearray_felts(&ek));
            let digest = kem_digest(&ek);
            json!({
                "scan_pub": felt_hex(&scan_pub),
                "ek_hex": hex::encode(&ek),
                "kem_digest": felt_hex(&digest),
                "leaf": felt_hex(&leaf_v2(&scan_pub, &digest)),
                "calldata": hexes(&calldata),
            })
        }
        "send" => {
            let keys = read(&args[2]);
            let req = read(&args[3]);
            let scan_priv = felt(&keys["scan_priv"]);
            let (_, ek) = kem_keygen_from_seed(&seed(&keys));
            let digest = kem_digest(&ek);
            let leaf = leaf_v2(&ec_mul_gen_x(&scan_priv), &digest);
            let root = felt(&req["merkle_root"]);
            let index = req["leaf_index"].as_u64().unwrap() as u32;
            let path: Vec<Felt> = req["path"].as_array().unwrap().iter().map(felt).collect();
            assert_eq!(fold_path(&leaf, index, &path), root, "sender path does not fold to the root");

            let recipient_ek = hex::decode(req["recipient_ek_hex"].as_str().unwrap()).unwrap();
            let sealed = send_v2(
                &felt(&req["recipient_scan_pub"]),
                &recipient_ek,
                req["text"].as_str().unwrap().as_bytes(),
            )
            .unwrap();

            let store = felt(&req["store"]);
            let mut prove_args = vec![
                store,
                sealed.content_hash,
                sealed.commitment,
                sealed.ephemeral_pub,
                root,
                scan_priv,
                digest,
                Felt::from(index),
                Felt::from(path.len() as u64),
            ];
            prove_args.extend(path);
            // Account __execute__ calldata: one call.
            let mut execute = vec![
                Felt::ONE,
                felt(&req["prover"]),
                snkeccak("prove_send"),
                Felt::from(prove_args.len() as u64),
            ];
            execute.extend(prove_args);

            let mut publish = vec![sealed.commitment, sealed.ephemeral_pub, root];
            publish.extend(bytearray_felts(&sealed.content));
            let mut publish_execute =
                vec![Felt::ONE, store, snkeccak("send_message"), Felt::from(publish.len() as u64)];
            publish_execute.extend(publish);

            json!({
                "commitment": felt_hex(&sealed.commitment),
                "ephemeral_pub": felt_hex(&sealed.ephemeral_pub),
                "content_hex": hex::encode(&sealed.content),
                "content_hash": felt_hex(&sealed.content_hash),
                "prove_execute_calldata": hexes(&execute),
                "publish_execute_calldata": hexes(&publish_execute),
            })
        }
        "open" => {
            let keys = read(&args[2]);
            let ev = read(&args[3]);
            let (dk, _) = kem_keygen_from_seed(&seed(&keys));
            let content = hex::decode(ev["content_hex"].as_str().unwrap()).unwrap();
            match receive_v2(
                &felt(&keys["scan_priv"]),
                &dk,
                &felt(&ev["commitment"]),
                &felt(&ev["ephemeral_pub"]),
                &content,
            ) {
                None => json!({ "ours": false }),
                Some(Ok(text)) => json!({ "ours": true, "text": String::from_utf8_lossy(&text) }),
                Some(Err(e)) => json!({ "ours": true, "error": e.to_string() }),
            }
        }
        "digest" => {
            let ek = hex::decode(std::fs::read_to_string(&args[2]).unwrap().trim()).unwrap();
            json!({ "len": ek.len(), "kem_digest": felt_hex(&kem_digest(&ek)) })
        }
        other => panic!("unknown command {other}"),
    };
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
