//! Export golden test vectors for cross-language ports (zkmsg-ios).
//!
//! Emits JSON to stdout covering every primitive a port must reproduce
//! byte-exactly: Poseidon hashes, Stark-curve ec_mul/ECDH, the AEAD blob
//! format, ByteArray/Span calldata encoding, and selector hashing.
//!
//!     cargo run -p zkmsg-core --example export_vectors > vectors.json
//!
//! The AEAD `blob` uses a random nonce at generation time; the committed
//! fixture is deterministic because the output is committed, not the run.

use serde_json::json;
use starknet_types_core::felt::Felt;
use zkmsg_core::chain::{bytearray_calldata, bytearray_decode, felt_hex, snkeccak, span_calldata};
use zkmsg_core::crypto::{
    commitment, decrypt, ec_mul_gen_x, ecdh_shared_x, encrypt, hash_pair, poseidon2,
};

fn hexvec(v: &[String]) -> Vec<String> {
    v.to_vec()
}

fn main() {
    let f = |d: &str| Felt::from_dec_str(d).unwrap();

    // --- ECDH chain: same values as crypto.rs golden tests -----------------
    let pub5 = ec_mul_gen_x(&f("5"));
    let pub7 = ec_mul_gen_x(&f("7"));
    let shared_6_7 = ecdh_shared_x(&f("6"), &pub7).unwrap();
    let commit_6_7 = commitment(&shared_6_7);

    // Commutativity pair (inbox trial-decrypt property).
    let scan_pub = ec_mul_gen_x(&f("31337"));
    let eph_pub = ec_mul_gen_x(&f("271828"));
    let shared_a = ecdh_shared_x(&f("271828"), &scan_pub).unwrap();
    let shared_b = ecdh_shared_x(&f("31337"), &eph_pub).unwrap();
    assert_eq!(shared_a, shared_b);

    // --- AEAD: fixed shared secret, recorded blob ---------------------------
    let plaintext = b"the first natively-proven private message";
    let blob = encrypt(&shared_6_7, plaintext);
    assert_eq!(decrypt(&shared_6_7, &blob).unwrap(), plaintext.to_vec());

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
            "commitment": felt_hex(&commit_6_7),
            "commute_shared_x": felt_hex(&shared_a),
        },
        "aead": {
            "shared_x": felt_hex(&shared_6_7),
            "plaintext_utf8": String::from_utf8_lossy(plaintext),
            "blob_hex": hex::encode(&blob),
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
    });

    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
