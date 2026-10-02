//! Adversarial "limit tests" for the zkmsg v2 authenticity model.
//!
//! These do not test that the happy path works (the unit tests and the
//! live Sepolia sends already prove that). They test that every attack we
//! could name FAILS — the properties the product's privacy claim rests on.
//!
//! Adversary model. On-chain, everything is public: every `MessageSent`
//! event exposes `(commitment, ephemeral_pubkey, content = kem_ct ‖ blob)`,
//! every `UserRegistered` event exposes `(handle, scan_pubkey, leaf_index,
//! kem_pubkey)`, and all Merkle roots are readable. The adversary Eve may be
//! a registered user with her own keys. What she never has: any other user's
//! scan key or ML-KEM seed, or any send's ephemeral scalar or ML-KEM
//! randomness (fresh per send, dropped immediately after — see
//! crypto::encap_v2). Every test below hands Eve the full public view and
//! asserts she still cannot read, forge, link, or crash.
//!
//! Claims proven here (v2: hybrid ML-KEM-768 + ECDH):
//!  1. Confidentiality      — only the recipient's keys decrypt.
//!  2. Hybrid binding       — the scan key alone, or the KEM key alone, opens
//!                            nothing: the tag needs both shared secrets.
//!  3. Trial-decrypt sound  — the inbox predicate matches iff addressed to us;
//!                            the sender's own inbox stays empty.
//!  4. Integrity            — any tamper (kem_ct, nonce, body, tag, length) is
//!                            rejected or simply not ours.
//!  5. Tag unforgeability   — a made-up commitment never opens for Bob.
//!  6. Membership           — a leaf binds both the scan key and the KEM key;
//!                            a swapped KEM key does not fold to the root.
//!  7. Unlinkability        — fresh randomness makes two sends to the same
//!                            recipient unlinkable.
//!  8. Malformed input      — off-curve ephemerals and short content are
//!                            skipped, never matched, never a panic.
//!
//! All offline. No network, no STRK. The one live check is `#[ignore]`d at
//! the bottom.

use ml_kem::DecapsulationKey768;
use starknet_types_core::felt::Felt;
use zkmsg_core::crypto::{
    KEM_CT_LEN, MIN_CONTENT_V2_LEN, decap_tag_v2, ec_mul_gen_x, ecdh_shared_x, kem_keygen_from_seed,
    kem_seed_gen, receive_v2, scan_keygen, send_v2,
};

/// One user: scan key, ML-KEM key pair.
struct User {
    scan_priv: Felt,
    scan_pub: Felt,
    dk: DecapsulationKey768,
    ek: Vec<u8>,
}

fn user() -> User {
    let (scan_priv, scan_pub) = scan_keygen();
    let (dk, ek) = kem_keygen_from_seed(&kem_seed_gen());
    User { scan_priv, scan_pub, dk, ek }
}

/// One honest send, reduced to what lands on-chain.
struct Envelope {
    eph_pub: Felt,
    commitment: Felt,
    content: Vec<u8>,
}

fn seal(to: &User, text: &[u8]) -> Envelope {
    let s = send_v2(&to.scan_pub, &to.ek, text).expect("recipient keys are valid");
    Envelope { eph_pub: s.ephemeral_pub, commitment: s.commitment, content: s.content }
}

/// The inbox's exact predicate (inbox::scan): Some(plaintext) only on a
/// genuine, openable match.
fn trial_open(scan_priv: &Felt, dk: &DecapsulationKey768, env: &Envelope) -> Option<Vec<u8>> {
    receive_v2(scan_priv, dk, &env.commitment, &env.eph_pub, &env.content)?.ok()
}

fn open(u: &User, env: &Envelope) -> Option<Vec<u8>> {
    trial_open(&u.scan_priv, &u.dk, env)
}

// --- 1. Confidentiality ----------------------------------------------------

#[test]
fn recipient_recovers_plaintext_but_eve_cannot() {
    let (bob, eve) = (user(), user());
    let msg = b"the witness never leaves your machine";
    let env = seal(&bob, msg);
    assert_eq!(open(&bob, &env).as_deref(), Some(&msg[..]));
    assert!(open(&eve, &env).is_none());
}

#[test]
fn no_foreign_identity_ever_opens_the_envelope() {
    // The property behind recipient anonymity: 64 independent foreign
    // identities run the trial. Not one may match (a false positive) or
    // decrypt (a leak).
    let bob = user();
    let env = seal(&bob, b"addressed to exactly one person");
    for _ in 0..64 {
        assert!(open(&user(), &env).is_none(), "a foreign identity opened an envelope");
    }
}

// --- 2. Hybrid binding: both halves are required --------------------------------

#[test]
fn bobs_scan_key_with_another_kem_key_opens_nothing() {
    // A quantum adversary recovers bob's scan key from his public scan_pub.
    // Without his ML-KEM key the tag still does not match.
    let (bob, eve) = (user(), user());
    let env = seal(&bob, b"post-quantum");
    assert!(trial_open(&bob.scan_priv, &eve.dk, &env).is_none());
}

#[test]
fn bobs_kem_key_with_another_scan_key_opens_nothing() {
    // If ML-KEM were broken, security falls back to ECDH, never below it.
    let (bob, eve) = (user(), user());
    let env = seal(&bob, b"classical fallback");
    assert!(trial_open(&eve.scan_priv, &bob.dk, &env).is_none());
}

// --- 3. Trial-decrypt soundness ------------------------------------------------

#[test]
fn sender_own_inbox_is_empty() {
    let (alice, bob) = (user(), user());
    let env = seal(&bob, b"hello bob");
    assert!(open(&alice, &env).is_none());
}

#[test]
fn message_to_self_is_the_only_self_match() {
    let me = user();
    let env = seal(&me, b"note to self");
    assert_eq!(open(&me, &env).as_deref(), Some(&b"note to self"[..]));
}

// --- 4. Integrity -----------------------------------------------------------------

#[test]
fn any_single_byte_tamper_is_rejected() {
    // Flip every byte in turn. A kem_ct byte moves the tag (implicit
    // rejection), so the envelope is no longer ours; a blob byte keeps the
    // tag but fails the AEAD. Either way nothing opens.
    let bob = user();
    let env = seal(&bob, b"integrity or nothing");
    for i in 0..env.content.len() {
        let mut content = env.content.clone();
        content[i] ^= 0xFF;
        let tampered = Envelope { content, ..seal_copy(&env) };
        let result = receive_v2(&bob.scan_priv, &bob.dk, &tampered.commitment, &tampered.eph_pub, &tampered.content);
        if i < KEM_CT_LEN {
            assert!(result.is_none(), "a kem_ct tamper at byte {i} still matched");
        } else {
            assert!(matches!(result, Some(Err(_))), "a blob tamper at byte {i} opened");
        }
    }
}

fn seal_copy(env: &Envelope) -> Envelope {
    Envelope { eph_pub: env.eph_pub, commitment: env.commitment, content: env.content.clone() }
}

#[test]
fn truncation_and_extension_are_rejected() {
    let bob = user();
    let env = seal(&bob, b"exact bytes only");
    let mut short = seal_copy(&env);
    short.content.pop();
    assert!(open(&bob, &short).is_none(), "truncated content accepted");
    let mut long = seal_copy(&env);
    long.content.push(0);
    assert!(open(&bob, &long).is_none(), "extended content accepted");
    let empty = Envelope { content: vec![], ..seal_copy(&env) };
    assert!(open(&bob, &empty).is_none(), "empty content accepted");
}

#[test]
fn content_cannot_be_moved_between_envelopes() {
    // Two sends to Bob. Pairing A's content with B's (commitment, eph) must
    // fail: the tag binds kem_ct, E and R.
    let bob = user();
    let a = seal(&bob, b"message A");
    let b = seal(&bob, b"message B");
    let swapped = Envelope { content: b.content.clone(), ..seal_copy(&a) };
    assert!(open(&bob, &swapped).is_none());
    // Nor the ephemeral key: E is bound into the tag and the AAD.
    let swapped_eph = Envelope { eph_pub: b.eph_pub, ..seal_copy(&a) };
    assert!(open(&bob, &swapped_eph).is_none());
}

// --- 5. Tag unforgeability ---------------------------------------------------

#[test]
fn a_random_commitment_never_opens_for_bob() {
    let bob = user();
    let honest = seal(&bob, b"template");
    for seed in 1u64..=64 {
        let forged = Envelope {
            commitment: Felt::from(seed) * Felt::from(0x9e37_79b9u64),
            ..seal_copy(&honest)
        };
        assert!(open(&bob, &forged).is_none());
    }
}

#[test]
fn the_accepted_tag_is_exactly_the_hybrid_one() {
    let bob = user();
    let env = seal(&bob, b"exactly");
    let keys = decap_tag_v2(&bob.scan_priv, &bob.dk, &env.eph_pub, &env.content[..KEM_CT_LEN]).unwrap();
    assert_eq!(keys.tag, env.commitment);
    let off_by_one = Envelope { commitment: env.commitment + Felt::ONE, ..seal_copy(&env) };
    assert!(open(&bob, &off_by_one).is_none());
}

// --- 6. Membership: the leaf binds both keys -----------------------------------------

mod membership {
    use starknet_types_core::felt::Felt;
    use zkmsg_core::crypto::{ec_mul_gen_x, kem_digest, kem_keygen_from_seed, leaf_v2};
    use zkmsg_core::tree::{MerkleTree, fold_path};

    #[test]
    fn a_swapped_kem_key_is_not_a_member() {
        let scan_pub = ec_mul_gen_x(&Felt::from(5u32));
        let (_, ek) = kem_keygen_from_seed(&[1u8; 64]);
        let (_, other_ek) = kem_keygen_from_seed(&[2u8; 64]);
        let mut tree = MerkleTree::new();
        let index = tree.insert(leaf_v2(&scan_pub, &kem_digest(&ek)));
        tree.insert(leaf_v2(&ec_mul_gen_x(&Felt::from(7u32)), &kem_digest(&other_ek)));
        let path = tree.path(index);

        assert_eq!(fold_path(&leaf_v2(&scan_pub, &kem_digest(&ek)), index, &path), tree.root());
        assert_ne!(fold_path(&leaf_v2(&scan_pub, &kem_digest(&other_ek)), index, &path), tree.root());
        // A v1 leaf (the bare scan key) is not a v2 member either.
        assert_ne!(fold_path(&scan_pub, index, &path), tree.root());
    }
}

// --- 7. Unlinkability -------------------------------------------------------------

#[test]
fn two_sends_to_the_same_recipient_are_unlinkable() {
    let bob = user();
    let text = b"same words, twice";
    let (a, b) = (seal(&bob, text), seal(&bob, text));
    assert_ne!(a.eph_pub, b.eph_pub, "ephemeral pubkey must be fresh");
    assert_ne!(a.commitment, b.commitment, "commitment must not repeat");
    assert_ne!(a.content[..KEM_CT_LEN], b.content[..KEM_CT_LEN], "kem_ct must not repeat");
    assert_ne!(a.content, b.content, "content must not repeat");
    assert_eq!(open(&bob, &a).as_deref(), Some(&text[..]));
    assert_eq!(open(&bob, &b).as_deref(), Some(&text[..]));
}

// --- 8. Malformed on-chain input -----------------------------------------------------

#[test]
fn off_curve_ephemeral_is_skipped_not_matched() {
    let bob = user();
    let mut off_curve = None;
    for candidate in 2u64..4096 {
        let x = Felt::from(candidate);
        if ecdh_shared_x(&bob.scan_priv, &x).is_err() {
            off_curve = Some(x);
            break;
        }
    }
    let x = off_curve.expect("an off-curve x must exist below 4096");
    let env = Envelope { eph_pub: x, commitment: Felt::ZERO, content: vec![0u8; MIN_CONTENT_V2_LEN] };
    assert!(open(&bob, &env).is_none());
}

#[test]
fn shared_secret_is_nondegenerate() {
    for _ in 0..64 {
        let (_p, pubk) = scan_keygen();
        let (eph, _) = scan_keygen();
        let shared = ecdh_shared_x(&eph, &pubk).unwrap();
        assert_ne!(shared, Felt::ZERO);
        assert_ne!(shared, pubk);
        assert_ne!(shared, ec_mul_gen_x(&eph));
    }
}

// --- Live, read-only Sepolia invariant (opt-in) --------------------------
//
// `#[ignore]` by default: needs network. Run with:
//     cargo test -p zkmsg-core --test adversarial -- --ignored live_
//
// Proves the deployed v2 store is what the client trusts: it is pinned to the
// prover contract whose virtual execution the client proves. A store pinned
// elsewhere would accept proofs of some other statement.

#[test]
#[ignore = "hits Sepolia; run with --ignored"]
fn live_v2_store_is_pinned_to_our_prover() {
    use serde_json::json;
    use zkmsg_core::chain::{snkeccak, Chain};
    use zkmsg_core::config::{SEPOLIA_PROVER_RPC, SEPOLIA_STORE_V2, SEPOLIA_V2_SEND_PROVER};

    let chain = Chain::new(SEPOLIA_PROVER_RPC, "unused-for-read-only");
    let result = chain
        .rpc(
            "starknet_call",
            json!([
                { "contract_address": SEPOLIA_STORE_V2,
                  "entry_point_selector": format!("{:#x}", snkeccak("prover")),
                  "calldata": [] },
                "latest"
            ]),
        )
        .unwrap_or_else(|e| panic!("live call prover() failed: {e}"));
    let prover = Felt::from_hex(result[0].as_str().unwrap()).unwrap();
    assert_eq!(prover, Felt::from_hex(SEPOLIA_V2_SEND_PROVER).unwrap(), "store re-pinned");
}
