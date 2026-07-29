//! Adversarial "limit tests" for the zkmsg authenticity model.
//!
//! These do not test that the happy path works (the unit tests and the
//! live Sepolia sends already prove that). They test that every attack we
//! could name FAILS — the properties the product's privacy claim rests on.
//!
//! Adversary model. On-chain, everything is public: every `MessageSent`
//! event exposes `(commitment, ephemeral_pubkey, ciphertext)`, every
//! `UserRegistered` event exposes `(handle, scan_pubkey, leaf_index)`, and
//! all Merkle roots are readable. The adversary Eve may be a registered
//! user with her own scan keypair. What she never has: any other user's
//! `scan_priv`, or any `ephemeral_priv` (minted fresh per send, dropped
//! immediately after — see app::prepare_send). Every test below hands Eve
//! the full public view and asserts she still cannot read, forge, link, or
//! crash.
//!
//! Claims proven here:
//!  1. Confidentiality      — only the recipient's scan_priv decrypts.
//!  2. Cross-key isolation  — no foreign key opens the envelope (the exact
//!                            "couldn't anyone use their own keys?" question).
//!  3. Trial-decrypt sound  — the inbox predicate matches iff addressed to us;
//!                            the sender's own inbox stays empty.
//!  4. Integrity            — any tamper (ciphertext, nonce, tag, length)
//!                            is rejected by the AEAD.
//!  5. Commitment binding   — a "for-Bob" envelope cannot be forged without
//!                            bob_scan_priv or the ephemeral secret.
//!  6. Membership           — you cannot send AS or TO a non-registered user
//!                            through the honest arg/circuit gate.
//!  7. Unlinkability        — fresh ephemerals make two sends to the same
//!                            recipient unlinkable and share no AEAD key.
//!  8. Malformed input      — an off-curve ephemeral in a crafted event is
//!                            skipped, never matched, never a panic.
//!
//! All offline, deterministic where the property is deterministic and
//! property-checked over random keys where the claim is "for ALL keys".
//! No network, no STRK. The one live check is `#[ignore]`d at the bottom.

use starknet_types_core::felt::Felt;
use zkmsg_core::crypto::{commitment, ecdh_shared_x, encrypt, decrypt, scan_keygen};

/// One honest send, reduced to what actually lands on-chain. Mirrors
/// app::prepare_send: fresh ephemeral, shared = ecdh(eph_priv, recipient_pub),
/// commitment = poseidon2(shared, 0), ciphertext = AEAD(shared, text).
struct Envelope {
    eph_pub: Felt,
    commitment: Felt,
    ciphertext: Vec<u8>,
}

fn seal(recipient_pub: &Felt, text: &[u8]) -> Envelope {
    let (eph_priv, eph_pub) = scan_keygen();
    let shared = ecdh_shared_x(&eph_priv, recipient_pub).expect("recipient pub is on-curve");
    Envelope {
        eph_pub,
        commitment: commitment(&shared),
        ciphertext: encrypt(&shared, text),
    }
}

/// The inbox's exact trial-decrypt predicate (inbox::scan): a scan key
/// "owns" an envelope iff its ECDH reproduces the published commitment.
/// Returns the recovered plaintext only on a genuine match.
fn trial_open(scan_priv: &Felt, env: &Envelope) -> Option<Vec<u8>> {
    let shared = ecdh_shared_x(scan_priv, &env.eph_pub).ok()?;
    if commitment(&shared) != env.commitment {
        return None; // not for us — same branch inbox.rs takes
    }
    decrypt(&shared, &env.ciphertext).ok()
}

// --- 1 + 2. Confidentiality and cross-key isolation ----------------------

#[test]
fn recipient_recovers_plaintext_but_eve_cannot() {
    let (bob_priv, bob_pub) = scan_keygen();
    let (eve_priv, _eve_pub) = scan_keygen();
    let msg = b"the witness never leaves your machine";

    let env = seal(&bob_pub, msg);

    // Bob (the intended recipient) opens it.
    assert_eq!(trial_open(&bob_priv, &env).as_deref(), Some(&msg[..]));
    // Eve, with her own valid key and the full public envelope, cannot.
    assert!(trial_open(&eve_priv, &env).is_none());
}

#[test]
fn no_foreign_key_ever_opens_the_envelope() {
    // The property behind recipient anonymity: for a message to Bob, run
    // the trial-decrypt with 256 independent foreign keys. Not one may
    // match the commitment (a false positive) or decrypt (a leak).
    let (_bob_priv, bob_pub) = scan_keygen();
    let env = seal(&bob_pub, b"addressed to exactly one person");

    for _ in 0..256 {
        let (eve_priv, _) = scan_keygen();
        assert!(
            trial_open(&eve_priv, &env).is_none(),
            "a foreign scan key opened an envelope it was not addressed to",
        );
    }
}

#[test]
fn eve_with_full_public_view_derives_a_different_secret() {
    // Eve sees eph_pub and bob_pub (both public). Combining two *public*
    // keys is not the shared secret: she has no private scalar that yields
    // shared = eph_priv * bob_priv * G. Concretely, her best move —
    // ecdh(eve_priv, eph_pub) — lands on a different point.
    let (bob_priv, bob_pub) = scan_keygen();
    let (eph_priv, eph_pub) = scan_keygen();
    let (eve_priv, _) = scan_keygen();

    let real_shared = ecdh_shared_x(&eph_priv, &bob_pub).unwrap();
    let bob_shared = ecdh_shared_x(&bob_priv, &eph_pub).unwrap();
    let eve_shared = ecdh_shared_x(&eve_priv, &eph_pub).unwrap();

    assert_eq!(real_shared, bob_shared, "DH must commute for the recipient");
    assert_ne!(eve_shared, real_shared, "a non-recipient must land elsewhere");
}

// --- 3. Trial-decrypt soundness ------------------------------------------

#[test]
fn sender_own_inbox_is_empty() {
    // Alice sends to Bob. Alice's own scan key must NOT match her own
    // outgoing message — ecdh(alice, eph) != ecdh(eph, bob) unless
    // alice == bob. This is why "your sent messages never show in your
    // inbox" holds.
    let (alice_priv, _alice_pub) = scan_keygen();
    let (_bob_priv, bob_pub) = scan_keygen();
    let env = seal(&bob_pub, b"hello bob");
    assert!(trial_open(&alice_priv, &env).is_none());
}

#[test]
fn message_to_self_is_the_only_self_match() {
    // A user messaging themselves is the sole case where the sender's key
    // opens the envelope — proving the predicate keys strictly on the
    // recipient pubkey, nothing else.
    let (me_priv, me_pub) = scan_keygen();
    let env = seal(&me_pub, b"note to self");
    assert_eq!(trial_open(&me_priv, &env).as_deref(), Some(&b"note to self"[..]));
}

// --- 4. Integrity: AEAD tamper detection ---------------------------------

#[test]
fn any_single_byte_tamper_is_rejected() {
    let (bob_priv, bob_pub) = scan_keygen();
    let env = seal(&bob_pub, b"integrity or nothing");
    let shared = ecdh_shared_x(&bob_priv, &env.eph_pub).unwrap();

    // Sanity: the pristine blob opens.
    assert!(decrypt(&shared, &env.ciphertext).is_ok());

    // Flip every byte in turn — nonce region, ciphertext body, GCM tag —
    // and require each corruption to fail closed.
    for i in 0..env.ciphertext.len() {
        let mut tampered = env.ciphertext.clone();
        tampered[i] ^= 0xFF;
        assert!(
            decrypt(&shared, &tampered).is_err(),
            "AEAD accepted a blob corrupted at byte {i}",
        );
    }
}

#[test]
fn truncation_and_extension_are_rejected() {
    let (bob_priv, bob_pub) = scan_keygen();
    let env = seal(&bob_pub, b"exact bytes only");
    let shared = ecdh_shared_x(&bob_priv, &env.eph_pub).unwrap();

    let mut short = env.ciphertext.clone();
    short.pop();
    assert!(decrypt(&shared, &short).is_err(), "truncated blob accepted");

    let mut long = env.ciphertext.clone();
    long.push(0);
    assert!(decrypt(&shared, &long).is_err(), "extended blob accepted");

    assert!(decrypt(&shared, &[]).is_err(), "empty blob accepted");
}

#[test]
fn ciphertext_cannot_be_moved_between_envelopes() {
    // Two independent sends to Bob. The AEAD key is derived from a
    // per-message shared secret, so pairing envelope A's ciphertext with
    // envelope B's key (or vice versa) must fail — no cut-and-paste.
    let (bob_priv, bob_pub) = scan_keygen();
    let a = seal(&bob_pub, b"message A");
    let b = seal(&bob_pub, b"message B");
    let shared_a = ecdh_shared_x(&bob_priv, &a.eph_pub).unwrap();
    let shared_b = ecdh_shared_x(&bob_priv, &b.eph_pub).unwrap();

    assert!(decrypt(&shared_a, &b.ciphertext).is_err());
    assert!(decrypt(&shared_b, &a.ciphertext).is_err());
}

// --- 5. Commitment binding / unforgeability ------------------------------

#[test]
fn a_random_commitment_never_opens_for_bob() {
    // An attacker who publishes a MessageSent with a made-up commitment
    // and a made-up ephemeral pubkey cannot make it appear addressed to
    // Bob: his trial-decrypt keys on poseidon2(ecdh(bob_priv, eph), 0),
    // which he cannot pre-image without bob_priv.
    let (bob_priv, _bob_pub) = scan_keygen();
    for seed in 1u64..=256 {
        let (_junk_priv, junk_eph) = scan_keygen();
        let forged = Envelope {
            eph_pub: junk_eph,
            commitment: Felt::from(seed) * Felt::from(0x9e37_79b9u64), // arbitrary
            ciphertext: vec![0u8; 40],
        };
        assert!(trial_open(&bob_priv, &forged).is_none());
    }
}

#[test]
fn forging_a_for_bob_commitment_requires_bobs_secret() {
    // The ONLY commitment Bob accepts for a given ephemeral pubkey is
    // poseidon2(ecdh(bob_priv, eph_pub), 0). Computing it requires
    // bob_priv; anyone holding it is Bob. We show the accepted value is
    // exactly that and nothing adjacent works.
    let (bob_priv, bob_pub) = scan_keygen();
    let (eph_priv, eph_pub) = scan_keygen();

    let shared = ecdh_shared_x(&eph_priv, &bob_pub).unwrap();
    let accepted = commitment(&shared);

    // The value Bob will match.
    let bob_side = commitment(&ecdh_shared_x(&bob_priv, &eph_pub).unwrap());
    assert_eq!(accepted, bob_side);

    // Off-by-one on the commitment breaks the match.
    let env = Envelope { eph_pub, commitment: accepted + Felt::ONE, ciphertext: vec![] };
    assert!(
        commitment(&ecdh_shared_x(&bob_priv, &env.eph_pub).unwrap()) != env.commitment,
    );
}

// --- 6. Membership: cannot send AS or TO a non-user ----------------------

mod membership {
    use starknet_types_core::felt::Felt;
    use zkmsg_core::args::{build_circuit_args, CircuitInputs};
    use zkmsg_core::crypto::ec_mul_gen_x;
    use zkmsg_core::tree::MerkleTree;

    /// A registered two-user tree (sender at 0, recipient at 1), the honest
    /// inputs that build_circuit_args accepts, and the pieces to perturb.
    struct Fixture {
        tree: MerkleTree,
        sender_priv: Felt,
        recipient_pub: Felt,
    }

    fn registered_pair() -> Fixture {
        let sender_priv = Felt::from(5u32);
        let recipient_pub = ec_mul_gen_x(&Felt::from(7u32));
        let mut tree = MerkleTree::new();
        tree.insert(ec_mul_gen_x(&sender_priv));
        tree.insert(recipient_pub);
        Fixture { tree, sender_priv, recipient_pub }
    }

    fn inputs<'a>(
        f: &Fixture,
        sender_priv: Felt,
        recipient_pub: Felt,
        sender_index: u32,
        recipient_index: u32,
        sender_path: &'a [Felt],
        recipient_path: &'a [Felt],
    ) -> CircuitInputs<'a> {
        CircuitInputs {
            merkle_root: f.tree.root(),
            sender_scan_priv: sender_priv,
            recipient_scan_pub: recipient_pub,
            ephemeral_priv: Felt::from(6u32),
            sender_leaf_index: sender_index,
            recipient_leaf_index: recipient_index,
            sender_path,
            recipient_path,
        }
    }

    #[test]
    fn honest_pair_is_accepted() {
        let f = registered_pair();
        let (sp, rp) = (f.tree.path(0), f.tree.path(1));
        assert!(
            build_circuit_args(&inputs(&f, f.sender_priv, f.recipient_pub, 0, 1, &sp, &rp))
                .is_ok(),
        );
    }

    #[test]
    fn unregistered_sender_rejected() {
        // A sender whose scan pubkey is not a leaf cannot fold to the root.
        let f = registered_pair();
        let (sp, rp) = (f.tree.path(0), f.tree.path(1));
        let outsider = Felt::from(9999u32); // never inserted
        let err = build_circuit_args(&inputs(&f, outsider, f.recipient_pub, 0, 1, &sp, &rp))
            .unwrap_err();
        assert!(err.to_string().contains("sender membership"), "{err}");
    }

    #[test]
    fn unregistered_recipient_rejected() {
        let f = registered_pair();
        let (sp, rp) = (f.tree.path(0), f.tree.path(1));
        let outsider_pub = ec_mul_gen_x(&Felt::from(9999u32));
        let err = build_circuit_args(&inputs(&f, f.sender_priv, outsider_pub, 0, 1, &sp, &rp))
            .unwrap_err();
        assert!(err.to_string().contains("recipient membership"), "{err}");
    }

    #[test]
    fn wrong_sender_leaf_index_rejected() {
        // Correct pubkey, correct path, but claim the wrong index — the
        // fold direction flips and misses the root.
        let f = registered_pair();
        let (sp, rp) = (f.tree.path(0), f.tree.path(1));
        let err = build_circuit_args(&inputs(&f, f.sender_priv, f.recipient_pub, 1, 1, &sp, &rp))
            .unwrap_err();
        assert!(err.to_string().contains("sender membership"), "{err}");
    }

    #[test]
    fn swapped_paths_rejected() {
        // Use the recipient's path to authenticate the sender.
        let f = registered_pair();
        let (sp, rp) = (f.tree.path(0), f.tree.path(1));
        let err = build_circuit_args(&inputs(&f, f.sender_priv, f.recipient_pub, 0, 1, &rp, &sp))
            .unwrap_err();
        assert!(err.to_string().contains("membership"), "{err}");
    }

    #[test]
    fn stale_or_forged_root_rejected() {
        // Advance the root past what the paths authenticate: the membership
        // that used to fold no longer does. (The store separately pins the
        // root to a 20-deep freshness window; here we prove the client gate.)
        let mut f = registered_pair();
        let (sp, rp) = (f.tree.path(0), f.tree.path(1));
        f.tree.insert(ec_mul_gen_x(&Felt::from(11u32))); // root moves
        let err = build_circuit_args(&inputs(&f, f.sender_priv, f.recipient_pub, 0, 1, &sp, &rp))
            .unwrap_err();
        assert!(err.to_string().contains("membership"), "{err}");
    }
}

// --- 7. Unlinkability via fresh ephemerals -------------------------------

#[test]
fn two_sends_to_the_same_recipient_are_unlinkable() {
    // Identical (recipient, text), two sends. Because the ephemeral is
    // fresh each time, an on-chain observer sees two unrelated
    // (eph_pub, commitment, ciphertext) triples — no field links them.
    let (bob_priv, bob_pub) = scan_keygen();
    let text = b"same words, twice";
    let a = seal(&bob_pub, text);
    let b = seal(&bob_pub, text);

    assert_ne!(a.eph_pub, b.eph_pub, "ephemeral pubkey must be fresh");
    assert_ne!(a.commitment, b.commitment, "commitment must not repeat");
    assert_ne!(a.ciphertext, b.ciphertext, "ciphertext must not repeat");

    // Yet Bob opens both to the same plaintext.
    assert_eq!(trial_open(&bob_priv, &a).as_deref(), Some(&text[..]));
    assert_eq!(trial_open(&bob_priv, &b).as_deref(), Some(&text[..]));
}

#[test]
fn identical_plaintext_encrypts_differently_each_time() {
    // Even under a FIXED shared secret, encrypt() randomizes the nonce, so
    // no two ciphertexts of the same plaintext collide (no AEAD nonce
    // reuse leak). Belt-and-suspenders on top of fresh-ephemeral.
    let (_p, pubk) = scan_keygen();
    let shared = ecdh_shared_x(&Felt::from(3u32), &pubk).unwrap();
    let c1 = encrypt(&shared, b"repeat");
    let c2 = encrypt(&shared, b"repeat");
    assert_ne!(c1, c2, "nonce reuse: identical ciphertext for identical input");
    assert_eq!(decrypt(&shared, &c1).unwrap(), decrypt(&shared, &c2).unwrap());
}

// --- 8. Malformed on-chain input -----------------------------------------

#[test]
fn off_curve_ephemeral_is_skipped_not_matched() {
    // A crafted MessageSent may carry an ephemeral_pubkey x that is not a
    // valid stark-curve x. The inbox lifts it via ecdh_shared_x, which
    // must Err (inbox then `continue`s) — never panic, never false-match.
    let (bob_priv, _bob_pub) = scan_keygen();

    // Find an off-curve x (roughly half of all felts are); bounded scan.
    let mut off_curve = None;
    for candidate in 2u64..4096 {
        let x = Felt::from(candidate);
        if ecdh_shared_x(&bob_priv, &x).is_err() {
            off_curve = Some(x);
            break;
        }
    }
    let x = off_curve.expect("an off-curve x must exist below 4096");

    let env = Envelope { eph_pub: x, commitment: Felt::ZERO, ciphertext: vec![0u8; 40] };
    assert!(trial_open(&bob_priv, &env).is_none());
}

#[test]
fn shared_secret_is_nondegenerate() {
    // The shared x must not collapse to a trivial value (0, or the
    // ephemeral pubkey itself) that would weaken the derived AEAD key.
    for _ in 0..64 {
        let (_p, pubk) = scan_keygen();
        let (eph, _) = scan_keygen();
        let shared = ecdh_shared_x(&eph, &pubk).unwrap();
        assert_ne!(shared, Felt::ZERO);
        assert_ne!(shared, pubk);
    }
}

// --- Live, read-only Sepolia invariant (opt-in) --------------------------
//
// `#[ignore]` by default: needs network. Run with:
//     cargo test -p zkmsg-core --test adversarial -- --ignored live_
//
// Proves the deployed store is what the client trusts: the verification
// route (registry, program_hash, inner_root) is pinned to the immutable
// config values, and the live registry still validates the first shipped
// fact. A route swap or unset verifier — the rug vector the store's own
// docs warn about — would fail this.

#[test]
#[ignore = "hits Sepolia; run with --ignored"]
fn live_store_route_is_pinned_and_registry_validates_shipped_fact() {
    use serde_json::json;
    use zkmsg_core::chain::{snkeccak, Chain};
    use zkmsg_core::config::{
        INNER_ROOT, PROGRAM_HASH, SEPOLIA_REGISTRY, SEPOLIA_RPC_DEFAULT, SEPOLIA_STORE_DEFAULT,
    };

    let chain = Chain::new(SEPOLIA_RPC_DEFAULT, "unused-for-read-only");

    let call = |contract: &str, func: &str, calldata: Vec<String>| -> Vec<Felt> {
        let selector = format!("{:#x}", snkeccak(func));
        let result = chain
            .rpc(
                "starknet_call",
                json!([
                    { "contract_address": contract, "entry_point_selector": selector,
                      "calldata": calldata },
                    "latest"
                ]),
            )
            .unwrap_or_else(|e| panic!("live call {func} failed: {e}"));
        result
            .as_array()
            .expect("starknet_call returns a felt array")
            .iter()
            .map(|v| Felt::from_hex(v.as_str().unwrap()).unwrap())
            .collect()
    };

    // verification_route() -> (registry, program_hash, [8 inner_root words]).
    let route = call(SEPOLIA_STORE_DEFAULT, "verification_route", vec![]);
    assert_eq!(route[0], Felt::from_hex(SEPOLIA_REGISTRY).unwrap(), "registry re-pointed");
    assert_eq!(route[1], Felt::from_hex(PROGRAM_HASH).unwrap(), "program hash changed");
    // route[2] is the span length (8); words follow.
    assert_eq!(route[2], Felt::from(8u32));
    for (i, word) in INNER_ROOT.iter().enumerate() {
        assert_eq!(route[3 + i], Felt::from(*word), "inner_root word {i} drifted");
    }

    // The first shipped fact must still validate on the live registry.
    const SHIPPED_FACT: &str =
        "0x2dc0a3703c2703c471591c64307ebb8a50f8c4eae35f0c916d6fca56014145f";
    let valid = call(SEPOLIA_REGISTRY, "is_valid", vec![SHIPPED_FACT.into()]);
    assert_eq!(valid, vec![Felt::ONE], "live registry no longer validates the shipped fact");
}
