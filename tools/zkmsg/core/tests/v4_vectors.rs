//! zkmsg v4 golden vectors: every encoding a port (zkmsg-ios) must
//! reproduce for a pool send, pinned three ways.
//!
//!   * `testdata/v4_vectors.json` is what this file builds; the test fails if
//!     the code and the committed file disagree. Regenerate with
//!         ZKMSG_WRITE_VECTORS=1 cargo test -p zkmsg-core --test v4_vectors
//!   * The Cairo side asserts the same values against the contracts'
//!     own functions (contracts/zkmsg_pool_v4/tests/test_vectors_v4.cairo).
//!   * A real Sepolia pool publish (`testdata/v4_pool_publish_tx.json`, the
//!     feeder's copy of carol→mode #0): its hash, sender, empty signature and
//!     facts are reproduced from its public calldata.

use std::path::PathBuf;

use serde_json::{Value, json};
use starknet_crypto::poseidon_hash_many;
use starknet_types_core::felt::Felt;
use zkmsg_core::chain::{bytearray_decode, felt_hex};
use zkmsg_core::config::{SEPOLIA_POOL_V4, SEPOLIA_V4_SEND_PROVER, SEPOLIA_V4_VIRTUAL_SENDER};
use zkmsg_core::crypto::{
    Sealing, assemble_v2, ec_mul_gen_x, encap_deterministic, envelope_key, kem_keygen_from_seed,
    leaf_v3, member_commit, nullifier_v4, nullifier_v4_domain, pad_v4, receive_v4,
    seal_v2_with_nonce, ticket_leaf, ticket_null_v4_domain, ticket_nullifier, ticket_v4_domain,
    unpad_v4,
};
use zkmsg_core::txpolicy::{self, TIP, TxKind};
use zkmsg_core::invoke_v3::{Bounds, Call, InvokeV3, ResourceBounds, execute_calldata, short_string};
use zkmsg_core::tree::MerkleTree;
use zkmsg_core::virtual_send::{
    PoolFeePolicy, PublicV4, WitnessV4, check_facts, content_hash, prove_send_calldata_v4,
    send_message_calldata_v4, virtual_invoke,
};

fn f(hex: &str) -> Felt {
    Felt::from_hex(hex).unwrap()
}

fn hexes(v: &[Felt]) -> Vec<String> {
    v.iter().map(felt_hex).collect()
}

/// The Cairo fixtures' ticket secrets (contracts/zkmsg_pool_v4/tests/common.cairo).
fn fixture_ticket_secret(i: u64) -> Felt {
    Felt::from(0x7111c3700000u64 + i)
}

/// The Cairo fixtures' pool fixture store address stands in for "some store".
const STORE: &str = "0x50f98ee98a0c1a583529c115f394ad79d18686ff66dc1ee25ba0f7bc53669b9";
const MEMBER_SECRET: &str = "0x4d3b2a1f00112233445566778899aabbccddeeff00112233445566778899aab";

fn build() -> Value {
    let store = f(STORE);
    let m = f(MEMBER_SECRET);
    let prover = f(SEPOLIA_V4_SEND_PROVER);

    let nullifiers: Vec<Value> = [(3251u64, 0u32), (3251, 9), (3252, 0)]
        .iter()
        .map(|&(epoch, slot)| {
            json!({"epoch": epoch, "slot": slot, "nullifier": felt_hex(&nullifier_v4(&store, &m, epoch, slot))})
        })
        .collect();

    let secrets: Vec<Felt> = (0..8).map(fixture_ticket_secret).collect();
    let leaves: Vec<Felt> = secrets.iter().map(ticket_leaf).collect();
    let mut tree = MerkleTree::new();
    for l in &leaves {
        tree.insert(*l);
    }
    let tickets: Vec<Value> = secrets
        .iter()
        .zip(&leaves)
        .map(|(t, l)| json!({"secret": felt_hex(t), "leaf": felt_hex(l), "nullifier": felt_hex(&ticket_nullifier(&store, t))}))
        .collect();

    // One member tree (the sender at leaf 1) and the full public tuple.
    let scan_pub = f("0x3948102149cf2d831e1a91e9014fd63216b6b83cdbbbba17fe82ccddf2df054");
    let digest = f("0x3d9aebb2f9823b47e55d0a962f225afa89da234c4ec60e3e8a366f079775f2e");
    let mut members = MerkleTree::new();
    members.insert(f("0xaaa"));
    let leaf_index = members.insert(leaf_v3(&scan_pub, &digest, &member_commit(&m)));
    let content: Vec<u8> = (0..1136u32).map(|i| (i * 7 % 251) as u8).collect();
    let (epoch, slot) = (3251u64, 2u32);
    let public = PublicV4 {
        store,
        commitment: f("0x8bd512dc0383b1b8"),
        ephemeral: f("0xe0e0"),
        root: members.root(),
        content_hash: content_hash(&content),
        nullifier: nullifier_v4(&store, &m, epoch, slot),
        epoch,
        quota: 10,
        ticket_root: tree.root(),
        ticket_nullifier: ticket_nullifier(&store, &secrets[1]),
    };
    let (path, ticket_path) = (members.path(leaf_index), tree.path(1));
    let prove_calldata = prove_send_calldata_v4(
        &public,
        &WitnessV4 {
            scan_pub,
            kem_digest: digest,
            member_secret: m,
            slot,
            leaf_index,
            path: &path,
            ticket_secret: secrets[1],
            ticket_index: 1,
            ticket_path: &ticket_path,
        },
    )
    .unwrap();
    let send_calldata = send_message_calldata_v4(&public, &content).unwrap();
    let send_call = Call::new(store, "send_message", send_calldata.clone());
    let facts = [
        short_string("PROOF1"),
        short_string("VIRTUAL_SNOS"),
        f("0x53f6c9fcfd31d27279ff7d7e422b44623550a732b59fe193354a7316a96daa1"),
        short_string("VIRTUAL_SNOS0"),
        Felt::from(16_257_164u64),
        f("0xb10c"),
        f("0x57ed4d5e20d617d8cc087a5882eae4f71d005172326be6439b2e1fd8b4dc57"),
        Felt::ONE,
        public.message_hash(prover),
    ];
    let prices = (52_616_363_968_810u128, 18_090_898_182u128, 52_616u128);
    let bounds = PoolFeePolicy { max_fee: 3_000_000_000_000_000_000, max_tip: 1_000_000_000, min_l2_gas: 100_000_000 }
        .bounds(prices)
        .unwrap();
    let publish_calldata = execute_calldata(std::slice::from_ref(&send_call));
    let publish_hash = InvokeV3 {
        sender: store,
        calldata: &publish_calldata,
        chain_id: short_string("SN_SEPOLIA"),
        nonce: Felt::from(7u64),
        tip: TIP,
        bounds,
        proof_facts: &facts,
    }
    .hash();
    let vsender = f(SEPOLIA_V4_VIRTUAL_SENDER);

    // v4 sealing: fixed randomness, one case per padding boundary.
    let recipient_priv = Felt::from(31337u64);
    let recipient_pub = ec_mul_gen_x(&recipient_priv);
    let (dk, ek) = kem_keygen_from_seed(&[7u8; 64]);
    let sealing: Vec<Value> = [0usize, 1, 254, 255, 1022, 1023, 4094]
        .iter()
        .map(|&n| {
            let plaintext: Vec<u8> = (0..n).map(|i| b'a' + (i % 26) as u8).collect();
            let padded = pad_v4(&plaintext).unwrap();
            let encap = encap_deterministic(Sealing::V4, &Felt::from(271828u64), &recipient_pub, &ek, &[0x42u8; 32]).unwrap();
            let blob = seal_v2_with_nonce(&encap.keys, &encap.ephemeral_pub, &[9u8; 12], &padded);
            let sealed = assemble_v2(&encap, &blob);
            let opened = receive_v4(&recipient_priv, &dk, &sealed.commitment, &sealed.ephemeral_pub, &sealed.content);
            assert_eq!(opened.unwrap().unwrap(), plaintext);
            json!({
                "plaintext_len": n,
                "padded_len": padded.len(),
                "padded_hex": hex::encode(&padded),
                "content_len": sealed.content.len(),
                "content_hex": hex::encode(&sealed.content),
                "commitment": felt_hex(&sealed.commitment),
                "ephemeral_pub": felt_hex(&sealed.ephemeral_pub),
                "content_hash": felt_hex(&sealed.content_hash),
            })
        })
        .collect();
    // Padded plaintexts a receiver must refuse.
    let mut nonzero_tail = pad_v4(b"hello").unwrap();
    nonzero_tail[100] = 1;
    let mut long_len = pad_v4(b"hello").unwrap();
    long_len[..2].copy_from_slice(&255u16.to_be_bytes());
    let bad_padding: Vec<Value> = [("nonzero tail", nonzero_tail), ("length over bucket - 2", long_len), ("not a bucket size", vec![0u8; 300])]
        .into_iter()
        .map(|(why, padded)| {
            assert!(unpad_v4(&padded).is_err(), "{why}");
            json!({"why": why, "padded_hex": hex::encode(&padded)})
        })
        .collect();

    let policy_bounds: Value = [TxKind::Publish, TxKind::Register, TxKind::BuyTickets]
        .iter()
        .map(|k| (k.name().to_string(), txpolicy::bounds(*k, prices).rpc_json()))
        .collect::<serde_json::Map<_, _>>()
        .into();
    let schedule: Vec<Value> = [16_257_200u64, 16_257_194, 16_257_193]
        .iter()
        .map(|&head| json!({"head": head, "base": txpolicy::base_block(head)}))
        .collect();

    json!({
        "generator": "zkmsg-core tests/v4_vectors.rs (ZKMSG_WRITE_VECTORS=1 cargo test -p zkmsg-core --test v4_vectors)",
        "domains": {
            "NULLIFIER_V4": felt_hex(&nullifier_v4_domain()),
            "TICKET_V4": felt_hex(&ticket_v4_domain()),
            "TICKET_NULL_V4": felt_hex(&ticket_null_v4_domain()),
        },
        "store": STORE,
        "member_secret": MEMBER_SECRET,
        "nullifier_v4": nullifiers,
        "tickets": tickets,
        "ticket_tree": {"n": 8, "root": felt_hex(&tree.root()), "path_of_1": hexes(&tree.path(1))},
        "envelope_key": {
            "commitment": felt_hex(&public.commitment),
            "content_hash": felt_hex(&public.content_hash),
            "key": felt_hex(&envelope_key(&public.commitment, &public.content_hash)),
        },
        "send": {
            "content_hex": hex::encode(&content),
            "content_hash": felt_hex(&public.content_hash),
            "scan_pub": felt_hex(&scan_pub),
            "kem_digest": felt_hex(&digest),
            "member_tree": {"leaves": [felt_hex(&f("0xaaa")), felt_hex(&leaf_v3(&scan_pub, &digest, &member_commit(&m)))], "root": felt_hex(&members.root())},
            "epoch": epoch,
            "quota": 10,
            "slot": slot,
            "ticket_index": 1,
            "payload": hexes(&public.payload()),
            "prover": SEPOLIA_V4_SEND_PROVER,
            "message_hash": felt_hex(&public.message_hash(prover)),
            "prove_send_calldata": hexes(&prove_calldata),
            "virtual_invoke": virtual_invoke(vsender, &[Call::new(prover, "prove_send", prove_calldata.clone())], Felt::ZERO),
            "send_message_calldata": hexes(&send_calldata),
        },
        "sealing_v4": {
            "hkdf": {"salt": "zkmsg-v4", "info_aead": "zkmsg-v4 aead", "info_tag": "zkmsg-v4 tag"},
            "pad_buckets": zkmsg_core::crypto::PAD_BUCKETS,
            "content_lens": zkmsg_core::crypto::content_lens_v4(),
            "max_plaintext": zkmsg_core::crypto::MAX_PLAINTEXT_V4,
            "recipient_scan_priv": felt_hex(&recipient_priv),
            "recipient_kem_seed_byte": 7,
            "ephemeral_priv": felt_hex(&Felt::from(271828u64)),
            "kem_m_byte": 0x42,
            "aead_nonce_byte": 9,
            "plaintext": "bytes b'a' + (i % 26)",
            "cases": sealing,
            "bad_padding": bad_padding,
            "receiver_rule": "a MessageSent whose tag matches but which does not open or unpad is dropped silently (front-run copies, F9)",
        },
        "policy": {
            "tip": TIP,
            "price_rule": "ceil(price * 3 / 2), rounded UP to 2 significant figures",
            "publish_cap_rule": "if the L2 bound exceeds (max_fee - l1_data_amount*l1_data_bound)/l2_amount - tip, use that, rounded DOWN to 2 s.f.; refuse if below ceil(1.1 * l2 price)",
            "l1_data_gas": txpolicy::L1_DATA_GAS,
            "l2_gas": {"publish": TxKind::Publish.l2_gas(), "register": TxKind::Register.l2_gas(), "buy_tickets": TxKind::BuyTickets.l2_gas()},
            "max_tickets_per_purchase": txpolicy::MAX_TICKETS_PER_PURCHASE,
            "da_modes": "L1",
            "paymaster_data": [],
            "account_deployment_data": [],
            "member_signature": "[r, s]",
            "sample_prices": {"l1_gas": prices.0.to_string(), "l2_gas": prices.1.to_string(), "l1_data_gas": prices.2.to_string()},
            "bounds": policy_bounds,
        },
        "schedule": {
            "base_round": txpolicy::BASE_ROUND,
            "base_min_age": txpolicy::BASE_MIN_AGE,
            "publish_delay": txpolicy::PUBLISH_DELAY,
            "publish_jitter": txpolicy::PUBLISH_JITTER,
            "rule": "base = floor((head - 10) / 32) * 32; publish once head >= base + 90 + j, j uniform in 0..=20",
            "examples": schedule,
        },
        "publish": {
            "sender": felt_hex(&store),
            "nonce": "0x7",
            "prices": {"l1_gas": "52616363968810", "l2_gas": "18090898182", "l1_data_gas": "52616"},
            "bounds": bounds.rpc_json(),
            "calldata": hexes(&publish_calldata),
            "proof_facts": hexes(&facts),
            "signature": [],
            "tip": TIP,
            "transaction_hash": felt_hex(&publish_hash),
        },
    })
}

fn testdata(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join(name)
}

#[test]
fn v4_vectors_match_testdata() {
    let built = build();
    let path = testdata("v4_vectors.json");
    if std::env::var("ZKMSG_WRITE_VECTORS").is_ok() {
        std::fs::write(&path, serde_json::to_string_pretty(&built).unwrap() + "\n").unwrap();
    }
    let committed: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(built, committed, "v4 encodings drifted from {}", path.display());
}

/// The values contracts/zkmsg_pool_v4/tests/test_vectors_v4.cairo asserts
/// against the contracts' own functions (snforge, 5 tests) — kept here as
/// literals so a drift on either side fails a test.
#[test]
fn v4_vectors_agree_with_cairo() {
    let v = build();
    assert_eq!(v["domains"]["NULLIFIER_V4"], felt_hex(&Felt::from_bytes_be_slice(b"zkmsg-nullifier-v4")));
    assert_eq!(v["nullifier_v4"][0]["nullifier"], CAIRO_NULLIFIER_3251_0);
    assert_eq!(v["tickets"][1]["leaf"], CAIRO_TICKET1_LEAF);
    assert_eq!(v["tickets"][1]["nullifier"], CAIRO_TICKET1_NULLIFIER);
    assert_eq!(v["ticket_tree"]["root"], CAIRO_TICKET_ROOT_8);
    assert_eq!(v["envelope_key"]["key"], CAIRO_ENVELOPE_KEY);
    assert_eq!(v["send"]["message_hash"], CAIRO_MESSAGE_HASH);
}

const CAIRO_NULLIFIER_3251_0: &str = "0x76326b96000472e47c449966dbadc5eae260e9f1c177f1ffd49fbee2493496a";
const CAIRO_TICKET1_LEAF: &str = "0x6893299d164e622ebf235843d161bc42370da5d44a55f4d8d722dac56f36def";
const CAIRO_TICKET1_NULLIFIER: &str = "0xd0aa28a392959e32bbc4cae5d753c3a96dcbd5051743b2ec42843f4131e403";
const CAIRO_TICKET_ROOT_8: &str = "0x642fdbf0f58b3405e7ee922139b205c611a8d8512cea14290298e85e840ec4b";
const CAIRO_ENVELOPE_KEY: &str = "0xdb5df8796eb0f72f8fe37edcb415ac738ca66c55607d6811e1d1d7d4d9b9a";
const CAIRO_MESSAGE_HASH: &str = "0x2c545f9f495912fe51e1e76c5d0e4d23a1ff02aee9a6250b36acdd3fc431e34";

/// A real pool publish on Sepolia: unsigned, sent by the pool, and its
/// facts attest the v4 message hash rebuilt from its own calldata, with the
/// epoch the pool derives from the facts' base block.
#[test]
fn live_pool_publish_reproduces() {
    let tx: Value = serde_json::from_str(&std::fs::read_to_string(testdata("v4_pool_publish_tx.json")).unwrap()).unwrap();
    let felts = |k: &str| -> Vec<Felt> { tx[k].as_array().unwrap().iter().map(|x| f(x.as_str().unwrap())).collect() };
    let (calldata, facts) = (felts("calldata"), felts("proof_facts"));
    let pool = f(SEPOLIA_POOL_V4);
    assert_eq!(f(tx["sender_address"].as_str().unwrap()), pool, "the pool publishes");
    assert_eq!(tx["signature"], json!([]), "and signs nothing");

    // [1, pool, selector, len, commitment, E, root, nullifier, ticket_root, ticket_nullifier, ByteArray…]
    assert_eq!((calldata[0], calldata[1]), (Felt::ONE, pool));
    let args = &calldata[4..];
    let (content, used) = bytearray_decode(&args[6..]).unwrap();
    assert_eq!(6 + used, args.len());
    let base = zkmsg_core::chain::felt_to_u64(&facts[4]).unwrap();
    let public = PublicV4 {
        store: pool,
        commitment: args[0],
        ephemeral: args[1],
        root: args[2],
        content_hash: content_hash(&content),
        nullifier: args[3],
        epoch: base / 5_000,
        quota: 10,
        ticket_root: args[4],
        ticket_nullifier: args[5],
    };
    assert_eq!(send_message_calldata_v4(&public, &content).unwrap(), args);
    check_facts(&facts, public.message_hash(f(SEPOLIA_V4_SEND_PROVER)), base).unwrap();

    let rb = &tx["resource_bounds"];
    let bound = |k: &str| ResourceBounds {
        max_amount: u64::from_str_radix(rb[k]["max_amount"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap(),
        max_price_per_unit: u128::from_str_radix(rb[k]["max_price_per_unit"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap(),
    };
    let bounds = Bounds { l1_gas: bound("L1_GAS"), l2_gas: bound("L2_GAS"), l1_data_gas: bound("L1_DATA_GAS") };
    let hash = InvokeV3 {
        sender: pool,
        calldata: &calldata,
        chain_id: short_string("SN_SEPOLIA"),
        nonce: f(tx["nonce"].as_str().unwrap()),
        tip: 0,
        bounds,
        proof_facts: &facts,
    }
    .hash();
    assert_eq!(hash, f(tx["transaction_hash"].as_str().unwrap()));
    // The poseidon form of the facts' message hash, spelled out.
    let mut pre = vec![f(SEPOLIA_V4_SEND_PROVER), Felt::ZERO, Felt::from(10u64)];
    pre.extend_from_slice(&public.payload());
    assert_eq!(poseidon_hash_many(&pre), facts[8]);
}
