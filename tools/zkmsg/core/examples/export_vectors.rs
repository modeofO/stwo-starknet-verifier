//! Export golden test vectors for cross-language ports (zkmsg-ios).
//!
//! Emits JSON to stdout covering every primitive a port must reproduce
//! byte-exactly: Poseidon hashes, Stark-curve ec_mul/ECDH, the v2 hybrid KEM
//! key schedule and content format, ByteArray/Span calldata encoding, and
//! selector hashing.
//!
//!     cargo run -p zkmsg-core --example export_vectors > vectors.json
//!
//! Every input is fixed, so a rerun reproduces the output byte for byte.

use serde_json::json;
use starknet_types_core::felt::Felt;
use zkmsg_core::chain::{bytearray_calldata, bytearray_decode, felt_hex, snkeccak, span_calldata};
use zkmsg_core::crypto::{
    KEM_SEED_LEN, assemble_v2, bytearray_felts, content_hash, decap_tag_v2,
    ec_mul_gen_x, ecdh_shared_x, encap_v2_deterministic, hash_pair, kem_digest,
    kem_keygen_from_seed, leaf_v2, leaf_v2_domain, open_v2, poseidon2, receive_v2,
    seal_v2_with_nonce,
};
use zkmsg_core::tree::MerkleTree;

fn hexvec(v: &[String]) -> Vec<String> {
    v.to_vec()
}

fn main() {
    let f = |d: &str| Felt::from_dec_str(d).unwrap();

    // --- ECDH chain: same values as crypto.rs golden tests -----------------
    let pub5 = ec_mul_gen_x(&f("5"));
    let pub7 = ec_mul_gen_x(&f("7"));
    let shared_6_7 = ecdh_shared_x(&f("6"), &pub7).unwrap();

    // Commutativity pair (inbox trial-decrypt property).
    let scan_pub = ec_mul_gen_x(&f("31337"));
    let eph_pub = ec_mul_gen_x(&f("271828"));
    let shared_a = ecdh_shared_x(&f("271828"), &scan_pub).unwrap();
    let shared_b = ecdh_shared_x(&f("31337"), &eph_pub).unwrap();
    assert_eq!(shared_a, shared_b);

    // --- ByteArray encodings -------------------------------------------------
    let ba = |s: &str| {
        let felts = bytearray_calldata(s.as_bytes());
        let parsed: Vec<Felt> = felts.iter().map(|h| Felt::from_hex(h).unwrap()).collect();
        let (bytes, consumed) = bytearray_decode(&parsed).unwrap();
        assert_eq!(bytes, s.as_bytes());
        assert_eq!(consumed, parsed.len());
        json!({ "text": s, "felts": hexvec(&felts) })
    };

    // --- chain-layer primitives: pedersen, RFC6979 ECDSA, contract address --
    let point_hex = |pt: &starknet_types_core::curve::AffinePoint| {
        json!({ "x": felt_hex(&pt.x()), "y": felt_hex(&pt.y()) })
    };
    use starknet_curve::curve_params;

    let wide_a = Felt::from_hex(
        "0x2c7e60e4e3f4d2a3b8f7d5c1a0918273645faceb0123456789abcdef0123456",
    )
    .unwrap();
    let wide_b = Felt::from_hex(
        "0x53df1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e",
    )
    .unwrap();

    let sign_case = |priv_hex: &str, msg_hex: &str, seed: Option<Felt>| {
        let private = Felt::from_hex(priv_hex).unwrap();
        let msg = Felt::from_hex(msg_hex).unwrap();
        let k = starknet_crypto::rfc6979_generate_k(&msg, &private, seed.as_ref());
        let sig = starknet_crypto::sign(&private, &msg, &k).unwrap();
        json!({
            "private": priv_hex,
            "message": msg_hex,
            "seed": seed.map(|s| felt_hex(&s)),
            "k": felt_hex(&k),
            "r": felt_hex(&sig.r),
            "s": felt_hex(&sig.s),
            "v": felt_hex(&sig.v),
            "public": felt_hex(&starknet_crypto::get_public_key(&private)),
        })
    };

    // OZ account class hash live on Sepolia (docs/zkmsg-deployment.md route).
    let oz_class = "0x061dac032f228abef9c6626f995015233097ae253a7f72d68552db02f2971b8f";
    let addr_case = |salt: &str, class: &str, calldata: &[&str], deployer: &str| {
        let cd: Vec<Felt> = calldata.iter().map(|h| Felt::from_hex(h).unwrap()).collect();
        let addr = starknet_core::utils::get_contract_address(
            Felt::from_hex(salt).unwrap(),
            Felt::from_hex(class).unwrap(),
            &cd,
            Felt::from_hex(deployer).unwrap(),
        );
        json!({
            "salt": salt,
            "class_hash": class,
            "constructor_calldata": calldata,
            "deployer": deployer,
            "address": felt_hex(&addr),
        })
    };

    let pedersen_wide = {
        let h = starknet_crypto::pedersen_hash(&wide_a, &wide_b);
        json!({ "a": felt_hex(&wide_a), "b": felt_hex(&wide_b), "hash": felt_hex(&h) })
    };

    let perm_out = {
        let mut state = [Felt::ONE, Felt::TWO, Felt::THREE];
        starknet_crypto::poseidon_permute_comp(&mut state);
        state.iter().map(felt_hex).collect::<Vec<_>>()
    };

    let v2 = v2_vectors();

    let out = json!({
        "generator": "zkmsg-core export_vectors (tools/zkmsg/core/examples/export_vectors.rs)",
        "poseidon": {
            "hash_pair_1_2": felt_hex(&hash_pair(&Felt::ONE, &Felt::TWO)),
            "poseidon2_3_4": felt_hex(&poseidon2(&Felt::THREE, &f("4"))),
            "poseidon2_0_0": felt_hex(&poseidon2(&Felt::ZERO, &Felt::ZERO)),
            "many_1": felt_hex(&starknet_crypto::poseidon_hash_many(&[Felt::ONE])),
            "many_3": felt_hex(&starknet_crypto::poseidon_hash_many(&[
                Felt::ONE,
                Felt::TWO,
                Felt::THREE,
            ])),
            "many_4": felt_hex(&starknet_crypto::poseidon_hash_many(&[
                Felt::ONE,
                Felt::TWO,
                Felt::THREE,
                f("4"),
            ])),
            "single_9": felt_hex(&starknet_crypto::poseidon_hash_single(f("9"))),
        },
        "poseidon_permutation": {
            "input": ["0x1", "0x2", "0x3"],
            "output": perm_out,
        },
        "curve_constants": {
            "generator": point_hex(&curve_params::GENERATOR),
            "shift_point": point_hex(&curve_params::SHIFT_POINT),
            "pedersen_p0": point_hex(&curve_params::PEDERSEN_P0),
            "pedersen_p1": point_hex(&curve_params::PEDERSEN_P1),
            "pedersen_p2": point_hex(&curve_params::PEDERSEN_P2),
            "pedersen_p3": point_hex(&curve_params::PEDERSEN_P3),
        },
        "pedersen": {
            "hash_1_2": felt_hex(&starknet_crypto::pedersen_hash(&Felt::ONE, &Felt::TWO)),
            "hash_0_0": felt_hex(&starknet_crypto::pedersen_hash(&Felt::ZERO, &Felt::ZERO)),
            "hash_wide": pedersen_wide,
            "on_elements_empty": felt_hex(&starknet_core::crypto::compute_hash_on_elements(&[])),
            "on_elements_1_2_3": felt_hex(&starknet_core::crypto::compute_hash_on_elements(&[
                Felt::ONE,
                Felt::TWO,
                Felt::THREE,
            ])),
        },
        "ecdsa": [
            sign_case("0x1", "0x2", None),
            sign_case(
                "0x2e9c99d8382fa004dcbbee720aef8a97002de0e991f6a8344e6dc14a0f4d9c4",
                "0x6fea80189363a786037ed3e7ba546dad0ef7de49fccae0e31eb658b7dd4ea76",
                None,
            ),
            sign_case(
                "0x2e9c99d8382fa004dcbbee720aef8a97002de0e991f6a8344e6dc14a0f4d9c4",
                "0x6fea80189363a786037ed3e7ba546dad0ef7de49fccae0e31eb658b7dd4ea76",
                Some(Felt::ONE),
            ),
        ],
        "contract_address": [
            addr_case("0x1", oz_class, &["0x2"], "0x0"),
            addr_case(
                "0x65f2b360bb2c1e3d9e4d4a6b9a2e1c7f80d5c4b3a2918273645fdecb0a19283",
                oz_class,
                &["0x4a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f"],
                "0x0",
            ),
            addr_case("0x0", oz_class, &[], "0x0"),
        ],
        "ec_mul": {
            "x_of_5G": felt_hex(&pub5),
            "x_of_7G": felt_hex(&pub7),
            "x_of_31337G": felt_hex(&scan_pub),
            "x_of_271828G": felt_hex(&eph_pub),
        },
        "ecdh": {
            "priv": "0x6",
            "peer_pub_x": felt_hex(&pub7),
            "shared_x": felt_hex(&shared_6_7),
            "commute_shared_x": felt_hex(&shared_a),
        },
        "bytearray": [
            ba(""),
            ba("hi"),
            ba("exactly-thirty-one-bytes-long!!"),
            ba("a longer message that spills across multiple 31-byte words to exercise the pending-word tail path"),
        ],
        "span": {
            "items": ["0x1", "0x2", "0x3"],
            "felts": span_calldata(&[Felt::ONE, Felt::TWO, Felt::THREE]),
        },
        "selectors": {
            "transfer": felt_hex(&snkeccak("transfer")),
            "register": felt_hex(&snkeccak("register")),
            "is_valid": felt_hex(&snkeccak("is_valid")),
        },
        "v2": v2,
    });

    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

/// v2 hybrid (ML-KEM-768 + ECDH) vectors. Every input is fixed — seeds,
/// the ephemeral scalar, the ML-KEM encapsulation randomness `m` and the
/// AES-GCM nonce — so a rerun reproduces this section byte for byte.
fn v2_vectors() -> serde_json::Value {
    use ml_kem::Decapsulate;

    let seed = |b: u8| -> [u8; KEM_SEED_LEN] {
        let mut s = [0u8; KEM_SEED_LEN];
        for (i, v) in s.iter_mut().enumerate() {
            *v = b.wrapping_add(i as u8);
        }
        s
    };
    let identity = |scan_priv: &str, kem_seed: [u8; KEM_SEED_LEN]| {
        let scan_priv = Felt::from_hex(scan_priv).unwrap();
        let scan_pub = ec_mul_gen_x(&scan_priv);
        let (dk, ek) = kem_keygen_from_seed(&kem_seed);
        let digest = kem_digest(&ek);
        let leaf = leaf_v2(&scan_pub, &digest);
        (scan_priv, scan_pub, kem_seed, dk, ek, digest, leaf)
    };

    let alice = identity("0x7a69", seed(0x00)); // 31337
    let bob = identity("0x1e240", seed(0x80)); // 123456

    let id_json = |id: &(Felt, Felt, [u8; KEM_SEED_LEN], ml_kem::DecapsulationKey768, Vec<u8>, Felt, Felt)| {
        json!({
            "scan_priv": felt_hex(&id.0),
            "scan_pub": felt_hex(&id.1),
            "kem_seed_hex": hex::encode(id.2),
            "ek_hex": hex::encode(&id.4),
            "ek_bytearray_len": bytearray_felts(&id.4).len(),
            "kem_digest": felt_hex(&id.5),
            "leaf": felt_hex(&id.6),
        })
    };

    let mut tree = MerkleTree::new();
    tree.insert(alice.6);
    tree.insert(bob.6);

    // Send to alice.
    let eph_priv = Felt::from_hex("0x425e4").unwrap(); // 271844
    let m = [0x42u8; 32];
    let nonce = [0x11u8; 12];
    let plaintext = b"post-quantum hello from bob";
    let encap = encap_v2_deterministic(&eph_priv, &alice.1, &alice.4, &m).unwrap();
    let blob = seal_v2_with_nonce(&encap.keys, &encap.ephemeral_pub, &nonce, plaintext);
    let sealed = assemble_v2(&encap, &blob);
    assert_eq!(sealed.content_hash, content_hash(&sealed.content));

    // Recipient side reproduces everything.
    let keys = decap_tag_v2(&alice.0, &alice.3, &encap.ephemeral_pub, &encap.kem_ct).unwrap();
    assert_eq!(keys, encap.keys);
    assert_eq!(open_v2(&keys, &encap.ephemeral_pub, &blob).unwrap(), plaintext.to_vec());
    assert_eq!(
        receive_v2(&alice.0, &alice.3, &sealed.commitment, &sealed.ephemeral_pub, &sealed.content)
            .unwrap()
            .unwrap(),
        plaintext.to_vec(),
    );
    assert!(receive_v2(&bob.0, &bob.3, &sealed.commitment, &sealed.ephemeral_pub, &sealed.content).is_none());

    // Implicit rejection: a flipped ciphertext byte still decapsulates, to
    // a pseudorandom secret.
    let mut bad_ct = encap.kem_ct.clone();
    bad_ct[0] ^= 0x01;
    let bad_ct_arr: [u8; 1088] = bad_ct.as_slice().try_into().unwrap();
    let rejected: [u8; 32] = alice.3.decapsulate(&bad_ct_arr.into()).into();

    json!({
        "spec": "docs/superpowers/specs/2026-10-01-zkmsg-pq-hybrid-kem-design.md",
        "leaf_domain": felt_hex(&leaf_v2_domain()),
        "hkdf": {
            "salt_utf8": "zkmsg-v2",
            "info_aead_utf8": "zkmsg-v2 aead",
            "info_tag_utf8": "zkmsg-v2 tag",
            "ikm_layout": "ss_kem(32) | ss_ec(32 BE) | E(32 BE) | R(32 BE) | SHA3-256(kem_ct)(32)",
            "aad_layout": "tag(32 BE) | E(32 BE)",
        },
        "alice": id_json(&alice),
        "bob": id_json(&bob),
        "tree_alice_bob": {
            "root": felt_hex(&tree.root()),
            "alice_index": 0,
            "alice_path": tree.path(0).iter().map(felt_hex).collect::<Vec<_>>(),
            "bob_index": 1,
            "bob_path": tree.path(1).iter().map(felt_hex).collect::<Vec<_>>(),
        },
        "send_to_alice": {
            "ephemeral_priv": felt_hex(&eph_priv),
            "ephemeral_pub": felt_hex(&encap.ephemeral_pub),
            "kem_m_hex": hex::encode(m),
            "nonce_hex": hex::encode(nonce),
            "plaintext_utf8": String::from_utf8_lossy(plaintext),
            "ss_ec": felt_hex(&encap.ss_ec),
            "ss_kem_hex": hex::encode(encap.ss_kem),
            "kem_ct_hex": hex::encode(&encap.kem_ct),
            "prk_hex": hex::encode(encap.keys.prk),
            "k_hex": hex::encode(encap.keys.k),
            "tag": felt_hex(&encap.keys.tag),
            "commitment": felt_hex(&sealed.commitment),
            "blob_hex": hex::encode(&blob),
            "content_hex": hex::encode(&sealed.content),
            "content_hash": felt_hex(&sealed.content_hash),
        },
        "decaps_reject": {
            "kem_ct_hex": hex::encode(&bad_ct),
            "ss_kem_hex": hex::encode(rejected),
        },
    })
}
