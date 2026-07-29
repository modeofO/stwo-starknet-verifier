//! Tests the C ABI as a caller sees it: JSON in, JSON out, no panics
//! escaping, and results identical to the native path.

use std::ffi::{CStr, CString};

use serde_json::{json, Value};

/// Calls an entry point the way Swift does and frees the result.
fn call(f: unsafe extern "C" fn(*const i8) -> *mut i8, request: &Value) -> Value {
    let c_req = CString::new(request.to_string()).expect("no interior nul");
    let raw = unsafe { f(c_req.as_ptr()) };
    assert!(!raw.is_null(), "entry point returned null");
    let text = unsafe { CStr::from_ptr(raw) }.to_str().expect("utf-8").to_owned();
    unsafe { zkmsg_ffi::zkmsg_string_free(raw) };
    serde_json::from_str(&text).expect("response is json")
}

fn ok(v: &Value) -> &Value {
    v.get("ok").unwrap_or_else(|| panic!("expected ok, got {v}"))
}

/// The same two-member fixture the core parity test uses, driven through JSON.
fn fixture() -> Value {
    use starknet_types_core::felt::Felt;
    use zkmsg_core::crypto::ec_mul_gen_x;
    use zkmsg_core::tree::MerkleTree;

    let sender_priv = Felt::from(5u32);
    let recipient_pub = ec_mul_gen_x(&Felt::from(7u32));
    let mut tree = MerkleTree::new();
    tree.insert(ec_mul_gen_x(&sender_priv));
    tree.insert(recipient_pub);
    let hexes = |v: Vec<Felt>| v.iter().map(|f| format!("{f:#x}")).collect::<Vec<_>>();

    json!({
        "merkle_root": format!("{:#x}", tree.root()),
        "sender_scan_priv": format!("{sender_priv:#x}"),
        "recipient_scan_pub": format!("{recipient_pub:#x}"),
        "sender_leaf_index": 0,
        "recipient_leaf_index": 1,
        "sender_path": hexes(tree.path(0)),
        "recipient_path": hexes(tree.path(1)),
        "text": "hello from the abi",
        "ephemeral_priv": "0x6",
    })
}

#[test]
fn prepare_send_returns_the_witness_and_envelope() {
    let response = call(zkmsg_ffi::zkmsg_prepare_send, &fixture());
    let material = ok(&response);

    let args = material["args"].as_array().expect("args array");
    assert_eq!(args.len(), 46, "circuit takes exactly 46 felts");
    assert_eq!(args[0], material["merkle_root"], "args[0] is the root");
    assert!(material["commitment"].as_str().unwrap().starts_with("0x"));
    assert!(!material["ciphertext"].as_str().unwrap().is_empty());
    assert!(material["proof_id"].as_str().unwrap().starts_with("0x"));
}

#[test]
fn abi_result_matches_the_native_builder() {
    use starknet_types_core::felt::Felt;
    use zkmsg_core::crypto::ec_mul_gen_x;
    use zkmsg_core::send::{build_send, SendInputs};
    use zkmsg_core::tree::MerkleTree;

    let sender_priv = Felt::from(5u32);
    let recipient_pub = ec_mul_gen_x(&Felt::from(7u32));
    let mut tree = MerkleTree::new();
    tree.insert(ec_mul_gen_x(&sender_priv));
    tree.insert(recipient_pub);
    let (sp, rp) = (tree.path(0), tree.path(1));

    let native = build_send(&SendInputs {
        merkle_root: tree.root(),
        sender_scan_priv: sender_priv,
        recipient_scan_pub: recipient_pub,
        sender_leaf_index: 0,
        recipient_leaf_index: 1,
        sender_path: &sp,
        recipient_path: &rp,
        text: "hello from the abi",
        ephemeral_priv: Some(Felt::from(6u32)),
    })
    .expect("native build");

    let via_abi = call(zkmsg_ffi::zkmsg_prepare_send, &fixture());
    let material = ok(&via_abi);

    // Everything except the envelope is a pure function of the inputs, so the
    // ABI must not perturb any of it.
    assert_eq!(material["args"], json!(native.args));
    assert_eq!(material["commitment"], json!(native.commitment));
    assert_eq!(material["ephemeral_pubkey"], json!(native.ephemeral_pubkey));
    assert_eq!(material["merkle_root"], json!(native.merkle_root));
    assert_eq!(material["proof_id"], json!(native.proof_id));
    assert_eq!(material["id"], json!(native.id));
}

/// Bad input must come back as an error string, never a crash or a null.
#[test]
fn malformed_requests_are_reported_not_fatal() {
    let bad_felt = {
        let mut f = fixture();
        f["merkle_root"] = json!("not-a-felt");
        f
    };
    assert!(call(zkmsg_ffi::zkmsg_prepare_send, &bad_felt).get("error").is_some());

    // A root that no path folds to: the local membership check must reject it
    // rather than let the caller pay to prove an unverifiable statement.
    let stale_root = {
        let mut f = fixture();
        f["merkle_root"] = json!("0xdead");
        f
    };
    let response = call(zkmsg_ffi::zkmsg_prepare_send, &stale_root);
    let err = response["error"].as_str().expect("error string");
    assert!(err.contains("membership"), "expected a membership failure, got: {err}");

    // Wrong shape entirely.
    assert!(call(zkmsg_ffi::zkmsg_prepare_send, &json!({"nope": 1})).get("error").is_some());

    // Null request.
    let raw = unsafe { zkmsg_ffi::zkmsg_prepare_send(std::ptr::null()) };
    assert!(!raw.is_null(), "null input must still return a response");
    let text = unsafe { CStr::from_ptr(raw) }.to_str().unwrap().to_owned();
    unsafe { zkmsg_ffi::zkmsg_string_free(raw) };
    assert!(text.contains("null request"));
}

#[test]
fn pack_proof_matches_the_contract_transport() {
    // 7 u32 limbs per slot: 14 small values must pack into exactly 2 slots.
    let values: Vec<String> = (1..=14u32).map(|v| format!("{v:#x}")).collect();
    let response = call(zkmsg_ffi::zkmsg_pack_proof, &json!({ "values": values }));
    let packed = ok(&response);
    assert_eq!(packed["n_values"], 14);
    assert_eq!(packed["slots"].as_array().unwrap().len(), 2, "7 limbs per felt252 slot");

    // And it agrees with the native packer the desktop pipeline uses.
    use starknet_types_core::felt::Felt;
    let native = zkmsg_core::pack::pack_v1(
        &(1..=14u32).map(Felt::from).collect::<Vec<_>>(),
    )
    .expect("native pack");
    let expected: Vec<String> = native.iter().map(|f| format!("{f:#x}")).collect();
    assert_eq!(packed["slots"], json!(expected));
}
