//! zkmsg crypto: Poseidon, Stark-curve ECDH, and the v2 hybrid ML-KEM-768 +
//! ECDH message key (below). The primitives are pinned by golden vectors
//! from fixtures/zkmsg_vectors (Cairo dump + starknet.js, cross-validated)
//! and by `examples/export_vectors`, which the iOS client pins to too:
//!
//! - `hash_pair`  = starknet_crypto::poseidon_hash_many(&[l, r])
//!   (Cairo: Poseidon builder over two children)
//! - `poseidon2`  = starknet_crypto::poseidon_hash(a, b)
//!   (Cairo: hades_permutation(a, b, 2).r0)
//! - `ec_mul_gen_x` / `ecdh_shared_x` = starknet-types-core curve ops; the
//!   shared x is y-parity-invariant, so lifting the peer's x with either
//!   root matches Cairo's `new_nz_from_x`.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Result, anyhow, bail};
use hkdf::Hkdf;
use ml_kem::{Decapsulate, DecapsulationKey768, EncapsulationKey768, KeyExport};
use rand::RngCore;
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use starknet_curve::curve_params::{EC_ORDER, GENERATOR};
use starknet_types_core::curve::AffinePoint;
use starknet_types_core::felt::Felt;

const NONCE_LEN: usize = 12;

pub fn hash_pair(l: &Felt, r: &Felt) -> Felt {
    starknet_crypto::poseidon_hash_many(&[*l, *r])
}

pub fn poseidon2(a: &Felt, b: &Felt) -> Felt {
    starknet_crypto::poseidon_hash(*a, *b)
}

/// x-coordinate of priv·G (the circuit's `ec_mul`).
pub fn ec_mul_gen_x(private: &Felt) -> Felt {
    (&GENERATOR * *private).x()
}

/// x-coordinate of priv·P where P is lifted from `peer_pub_x` (the
/// circuit's `ecdh`). Either lift of x gives the same shared x.
pub fn ecdh_shared_x(private: &Felt, peer_pub_x: &Felt) -> Result<Felt> {
    let peer = AffinePoint::new_from_x(peer_pub_x, true)
        .ok_or_else(|| anyhow!("peer pubkey x is not on the stark curve"))?;
    Ok((&peer * *private).x())
}

/// Fresh scalar in [1, EC_ORDER) from OS randomness, with its pubkey x.
pub fn scan_keygen() -> (Felt, Felt) {
    let mut bytes = [0u8; 32];
    loop {
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        // Reduce mod the curve order (bias ~2^-124, irrelevant here).
        let candidate = Felt::from_bytes_be(&bytes)
            .mod_floor(&EC_ORDER.try_into().expect("EC_ORDER is nonzero"));
        if candidate != Felt::ZERO {
            return (candidate, ec_mul_gen_x(&candidate));
        }
    }
}

// ---------------------------------------------------------------------------
// v2: hybrid ML-KEM-768 + Stark-curve ECDH
// (docs/superpowers/specs/2026-10-01-zkmsg-pq-hybrid-kem-design.md)
//
// Byte encodings, pinned by the v2 golden vectors:
//   * a felt is 32 bytes big endian (E, R, ss_ec, and the tag inside the AAD);
//   * ikm  = ss_kem(32) ‖ ss_ec(32) ‖ E(32) ‖ R(32) ‖ SHA3-256(kem_ct)(32);
//   * prk  = HKDF-Extract(salt "zkmsg-v2", ikm) with SHA-256;
//   * k    = HKDF-Expand(prk, "zkmsg-v2 aead", 32);
//   * tag  = HKDF-Expand(prk, "zkmsg-v2 tag", 31), read as a 31-byte BE felt;
//   * blob = nonce(12) ‖ AES-256-GCM(k, nonce, plaintext, aad = tag ‖ E) ‖ tag16;
//   * content = kem_ct(1088) ‖ blob.
// ---------------------------------------------------------------------------

/// ML-KEM-768 seed `d ‖ z` — the stored form of a KEM private key.
pub const KEM_SEED_LEN: usize = 64;
/// ML-KEM-768 encapsulation key (`ek`) length.
pub const KEM_EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length.
pub const KEM_CT_LEN: usize = 1088;
/// Shortest valid v2 content: kem_ct, a nonce, and an empty AES-GCM body.
pub const MIN_CONTENT_V2_LEN: usize = KEM_CT_LEN + NONCE_LEN + 16;

const HKDF_SALT_V2: &[u8] = b"zkmsg-v2";
const HKDF_INFO_AEAD_V2: &[u8] = b"zkmsg-v2 aead";
const HKDF_INFO_TAG_V2: &[u8] = b"zkmsg-v2 tag";

/// The leaf domain tag: Cairo short string 'zkmsg-leaf-v2'.
pub fn leaf_v2_domain() -> Felt {
    Felt::from_bytes_be_slice(b"zkmsg-leaf-v2")
}

/// Cairo `ByteArray` serialization as felts:
/// `[n_full_words, word_0.., pending_word, pending_len]`, 31-byte BE words.
pub fn bytearray_felts(bytes: &[u8]) -> Vec<Felt> {
    let full_words = bytes.len() / 31;
    let mut out = Vec::with_capacity(full_words + 3);
    out.push(Felt::from(full_words as u64));
    for chunk in bytes[..full_words * 31].chunks(31) {
        out.push(Felt::from_bytes_be_slice(chunk));
    }
    let pending = &bytes[full_words * 31..];
    out.push(Felt::from_bytes_be_slice(pending));
    out.push(Felt::from(pending.len() as u64));
    out
}

/// Poseidon over the ByteArray serialization — the store's `content_hash`.
pub fn bytearray_hash(bytes: &[u8]) -> Felt {
    starknet_crypto::poseidon_hash_many(&bytearray_felts(bytes))
}

/// `content_hash` of a v2 `content` (`kem_ct ‖ blob`).
pub fn content_hash(content: &[u8]) -> Felt {
    bytearray_hash(content)
}

/// `kem_digest` = poseidon over the ByteArray serialization of `ek`.
pub fn kem_digest(ek: &[u8]) -> Felt {
    bytearray_hash(ek)
}

/// leaf = poseidon_hash_many([LEAF_V2, R, kem_digest]).
pub fn leaf_v2(scan_pub: &Felt, kem_digest: &Felt) -> Felt {
    starknet_crypto::poseidon_hash_many(&[leaf_v2_domain(), *scan_pub, *kem_digest])
}

/// Fresh 64-byte ML-KEM seed from OS randomness.
pub fn kem_seed_gen() -> [u8; KEM_SEED_LEN] {
    let mut seed = [0u8; KEM_SEED_LEN];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed
}

/// Derives `(dk, ek)` from the 64-byte seed `d ‖ z` (FIPS 203
/// ML-KEM.KeyGen_internal). `ek` is the 1184-byte encoding.
pub fn kem_keygen_from_seed(seed: &[u8; KEM_SEED_LEN]) -> (DecapsulationKey768, Vec<u8>) {
    let dk = DecapsulationKey768::from_seed((*seed).into());
    let ek = dk.encapsulation_key().to_bytes().to_vec();
    (dk, ek)
}

/// The hybrid key schedule: everything both sides derive from the two
/// shared secrets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridKeys {
    pub prk: [u8; 32],
    /// AES-256-GCM key.
    pub k: [u8; 32],
    /// Detection tag, published as `commitment`.
    pub tag: Felt,
}

pub fn derive_v2(
    ss_kem: &[u8; 32],
    ss_ec: &Felt,
    ephemeral_pub: &Felt,
    recipient_scan_pub: &Felt,
    kem_ct: &[u8],
) -> HybridKeys {
    let mut ikm = Vec::with_capacity(160);
    ikm.extend_from_slice(ss_kem);
    ikm.extend_from_slice(&ss_ec.to_bytes_be());
    ikm.extend_from_slice(&ephemeral_pub.to_bytes_be());
    ikm.extend_from_slice(&recipient_scan_pub.to_bytes_be());
    ikm.extend_from_slice(&Sha3_256::digest(kem_ct));

    let (prk, hk) = Hkdf::<Sha256>::extract(Some(HKDF_SALT_V2), &ikm);
    let mut k = [0u8; 32];
    hk.expand(HKDF_INFO_AEAD_V2, &mut k).expect("32 bytes is a valid HKDF length");
    let mut tag = [0u8; 31];
    hk.expand(HKDF_INFO_TAG_V2, &mut tag).expect("31 bytes is a valid HKDF length");
    HybridKeys {
        prk: prk.into(),
        k,
        // 31 bytes BE: always below the field prime.
        tag: Felt::from_bytes_be_slice(&tag),
    }
}

/// Sender side of the hybrid exchange.
#[derive(Clone, Debug)]
pub struct EncapV2 {
    /// E = x(e·G), published as `ephemeral_pubkey`.
    pub ephemeral_pub: Felt,
    pub kem_ct: Vec<u8>,
    pub ss_kem: [u8; 32],
    pub ss_ec: Felt,
    pub keys: HybridKeys,
}

/// Encapsulates to a recipient with explicit randomness: the ephemeral
/// scalar `e` and the ML-KEM message `m` (FIPS 203 ML-KEM.Encaps_internal).
/// `m` must be 32 fresh uniform bytes per send; fixed values are for the
/// golden vectors only.
pub fn encap_v2_deterministic(
    ephemeral_priv: &Felt,
    recipient_scan_pub: &Felt,
    recipient_ek: &[u8],
    m: &[u8; 32],
) -> Result<EncapV2> {
    let ek_bytes: &[u8; KEM_EK_LEN] = recipient_ek
        .try_into()
        .map_err(|_| anyhow!("KEM public key must be {KEM_EK_LEN} bytes, got {}", recipient_ek.len()))?;
    let ek = EncapsulationKey768::new(&(*ek_bytes).into())
        .map_err(|_| anyhow!("KEM public key failed validation"))?;
    let (ct, ss) = ek.encapsulate_deterministic(&(*m).into());

    let ephemeral_pub = ec_mul_gen_x(ephemeral_priv);
    let ss_ec = ecdh_shared_x(ephemeral_priv, recipient_scan_pub)?;
    let ss_kem: [u8; 32] = ss.into();
    let kem_ct = ct.to_vec();
    let keys = derive_v2(&ss_kem, &ss_ec, &ephemeral_pub, recipient_scan_pub, &kem_ct);
    Ok(EncapV2 { ephemeral_pub, kem_ct, ss_kem, ss_ec, keys })
}

/// Encapsulates with fresh randomness. Returns the ephemeral scalar too:
/// the v2 prover does not need it, but callers may log or discard it.
pub fn encap_v2(recipient_scan_pub: &Felt, recipient_ek: &[u8]) -> Result<EncapV2> {
    let (ephemeral_priv, _) = scan_keygen();
    let mut m = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut m);
    encap_v2_deterministic(&ephemeral_priv, recipient_scan_pub, recipient_ek, &m)
}

/// Recipient side: recomputes the key schedule for one event. ML-KEM
/// decapsulation never fails on a well-sized ciphertext (implicit
/// rejection), so "not ours" shows up only as `keys.tag != commitment`.
pub fn decap_tag_v2(
    scan_priv: &Felt,
    dk: &DecapsulationKey768,
    ephemeral_pub: &Felt,
    kem_ct: &[u8],
) -> Result<HybridKeys> {
    let ct: &[u8; KEM_CT_LEN] = kem_ct
        .try_into()
        .map_err(|_| anyhow!("KEM ciphertext must be {KEM_CT_LEN} bytes, got {}", kem_ct.len()))?;
    let ss_kem: [u8; 32] = dk.decapsulate(&(*ct).into()).into();
    let ss_ec = ecdh_shared_x(scan_priv, ephemeral_pub)?;
    let own_scan_pub = ec_mul_gen_x(scan_priv);
    Ok(derive_v2(&ss_kem, &ss_ec, ephemeral_pub, &own_scan_pub, kem_ct))
}

fn aad_v2(tag: &Felt, ephemeral_pub: &Felt) -> [u8; 64] {
    let mut aad = [0u8; 64];
    aad[..32].copy_from_slice(&tag.to_bytes_be());
    aad[32..].copy_from_slice(&ephemeral_pub.to_bytes_be());
    aad
}

/// blob = nonce ‖ AES-256-GCM(k, nonce, plaintext, aad = tag ‖ E) ‖ tag16.
pub fn seal_v2_with_nonce(
    keys: &HybridKeys,
    ephemeral_pub: &Felt,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = Aes256Gcm::new((&keys.k).into());
    let aad = aad_v2(&keys.tag, ephemeral_pub);
    let ct = cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad: &aad })
        .expect("AES-GCM encryption is infallible for in-memory buffers");
    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&ct);
    blob
}

pub fn seal_v2(keys: &HybridKeys, ephemeral_pub: &Felt, plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    seal_v2_with_nonce(keys, ephemeral_pub, &nonce, plaintext)
}

pub fn open_v2(keys: &HybridKeys, ephemeral_pub: &Felt, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN + 16 {
        bail!("ciphertext blob too short ({} bytes)", blob.len());
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new((&keys.k).into());
    let aad = aad_v2(&keys.tag, ephemeral_pub);
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
        .map_err(|_| anyhow!("AEAD decryption failed (wrong key or tampered blob)"))
}

/// Splits v2 `content` into `(kem_ct, blob)`.
pub fn split_content_v2(content: &[u8]) -> Result<(&[u8], &[u8])> {
    if content.len() < MIN_CONTENT_V2_LEN {
        bail!("v2 content too short ({} bytes, need {MIN_CONTENT_V2_LEN})", content.len());
    }
    Ok(content.split_at(KEM_CT_LEN))
}

/// What a v2 send publishes (`content_hash` goes to the prover).
#[derive(Clone, Debug)]
pub struct SealedV2 {
    pub commitment: Felt,
    pub ephemeral_pub: Felt,
    pub content: Vec<u8>,
    pub content_hash: Felt,
}

/// Encapsulate, seal and assemble `content = kem_ct ‖ blob`.
pub fn send_v2(recipient_scan_pub: &Felt, recipient_ek: &[u8], plaintext: &[u8]) -> Result<SealedV2> {
    let encap = encap_v2(recipient_scan_pub, recipient_ek)?;
    let blob = seal_v2(&encap.keys, &encap.ephemeral_pub, plaintext);
    Ok(assemble_v2(&encap, &blob))
}

pub fn assemble_v2(encap: &EncapV2, blob: &[u8]) -> SealedV2 {
    let mut content = encap.kem_ct.clone();
    content.extend_from_slice(blob);
    SealedV2 {
        commitment: encap.keys.tag,
        ephemeral_pub: encap.ephemeral_pub,
        content_hash: content_hash(&content),
        content,
    }
}

/// Detect and decrypt one `MessageSent` event. `None`: not ours.
/// `Some(Err)`: the tag matched but the blob did not open.
pub fn receive_v2(
    scan_priv: &Felt,
    dk: &DecapsulationKey768,
    commitment: &Felt,
    ephemeral_pub: &Felt,
    content: &[u8],
) -> Option<Result<Vec<u8>>> {
    let (kem_ct, blob) = split_content_v2(content).ok()?;
    let keys = decap_tag_v2(scan_priv, dk, ephemeral_pub, kem_ct).ok()?;
    if keys.tag != *commitment {
        return None;
    }
    Some(open_v2(&keys, ephemeral_pub, blob))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn felt(dec: &str) -> Felt {
        Felt::from_dec_str(dec).unwrap()
    }

    // Golden vectors — fixtures/zkmsg_vectors/src/lib.cairo.
    #[test]
    fn golden_hash_pair() {
        assert_eq!(
            hash_pair(&Felt::ONE, &Felt::TWO),
            felt("1557996165160500454210437319447297236715335099509187222888255133199463084263"),
        );
    }

    #[test]
    fn golden_poseidon2() {
        assert_eq!(
            poseidon2(&Felt::THREE, &felt("4")),
            felt("2277075937292600178032240350608862537017378088372682623665183773811299784717"),
        );
        assert_eq!(
            poseidon2(&Felt::ZERO, &Felt::ZERO),
            felt("1165814756574493433332935684348403390128033890862827107228326727661107483845"),
        );
    }

    #[test]
    fn golden_ec_mul() {
        assert_eq!(
            ec_mul_gen_x(&felt("5")),
            felt("3406946075390113347849186141614382943859026331139362801098460541807050012492"),
        );
    }

    #[test]
    fn golden_ecdh() {
        let pub7 = ec_mul_gen_x(&felt("7"));
        let shared = ecdh_shared_x(&felt("6"), &pub7).unwrap();
        assert_eq!(
            shared,
            felt("116790107469130620194501433118398966236215846997329127478236149064647078075"),
        );
    }

    /// ECDH commutes: ecdh(eph, pub(scan)) == ecdh(scan, pub(eph)) — the
    /// property the recipient's inbox trial-decrypt relies on.
    #[test]
    fn ecdh_commutes() {
        let (scan_priv, scan_pub) = (felt("31337"), ec_mul_gen_x(&felt("31337")));
        let (eph_priv, eph_pub) = (felt("271828"), ec_mul_gen_x(&felt("271828")));
        let a = ecdh_shared_x(&eph_priv, &scan_pub).unwrap();
        let b = ecdh_shared_x(&scan_priv, &eph_pub).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn keygen_produces_valid_scalars() {
        let (private, public) = scan_keygen();
        assert_ne!(private, Felt::ZERO);
        assert_eq!(public, ec_mul_gen_x(&private));
        // The pubkey x must lift back onto the curve (inbox lift path).
        assert!(ecdh_shared_x(&Felt::TWO, &public).is_ok());
    }

    // --- v2 ----------------------------------------------------------------

    fn alice_v2() -> (Felt, Felt, DecapsulationKey768, Vec<u8>) {
        let scan_priv = felt("31337");
        let (dk, ek) = kem_keygen_from_seed(&[7u8; KEM_SEED_LEN]);
        (scan_priv, ec_mul_gen_x(&scan_priv), dk, ek)
    }

    #[test]
    fn v2_sizes_and_leaf_domain() {
        let (_, _, _, ek) = alice_v2();
        assert_eq!(ek.len(), KEM_EK_LEN);
        // 'zkmsg-leaf-v2' as a Cairo short string.
        assert_eq!(leaf_v2_domain(), Felt::from_hex("0x7a6b6d73672d6c6561662d7632").unwrap());
    }

    #[test]
    fn v2_bytearray_felts_match_calldata_encoding() {
        for len in [0usize, 1, 30, 31, 32, 62, 1184, 1088 + 28 + 5] {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let want: Vec<Felt> = crate::chain::bytearray_calldata(&bytes)
                .iter()
                .map(|h| Felt::from_hex(h).unwrap())
                .collect();
            assert_eq!(bytearray_felts(&bytes), want, "len {len}");
        }
    }

    #[test]
    fn v2_seed_keygen_is_deterministic() {
        let (_, ek1) = kem_keygen_from_seed(&[1u8; KEM_SEED_LEN]);
        let (_, ek2) = kem_keygen_from_seed(&[1u8; KEM_SEED_LEN]);
        let (_, ek3) = kem_keygen_from_seed(&[2u8; KEM_SEED_LEN]);
        assert_eq!(ek1, ek2);
        assert_ne!(ek1, ek3);
    }

    #[test]
    fn v2_round_trip() {
        let (scan_priv, scan_pub, dk, ek) = alice_v2();
        let sealed = send_v2(&scan_pub, &ek, b"post-quantum hello").unwrap();
        assert!(sealed.content.len() >= MIN_CONTENT_V2_LEN);
        assert_eq!(sealed.content_hash, content_hash(&sealed.content));
        let got = receive_v2(&scan_priv, &dk, &sealed.commitment, &sealed.ephemeral_pub, &sealed.content)
            .expect("tag must match")
            .unwrap();
        assert_eq!(got, b"post-quantum hello".to_vec());
    }

    #[test]
    fn v2_other_recipient_does_not_detect() {
        let (_, scan_pub, _, ek) = alice_v2();
        let sealed = send_v2(&scan_pub, &ek, b"for alice").unwrap();
        // Bob: different scan key and KEM key.
        let (bob_dk, _) = kem_keygen_from_seed(&[9u8; KEM_SEED_LEN]);
        assert!(receive_v2(&felt("271828"), &bob_dk, &sealed.commitment, &sealed.ephemeral_pub, &sealed.content).is_none());
        // Right scan key, wrong KEM key: still not detected (both halves bind the tag).
        assert!(receive_v2(&felt("31337"), &bob_dk, &sealed.commitment, &sealed.ephemeral_pub, &sealed.content).is_none());
        // Right KEM key, wrong scan key.
        let (alice_dk, _) = kem_keygen_from_seed(&[7u8; KEM_SEED_LEN]);
        assert!(receive_v2(&felt("271828"), &alice_dk, &sealed.commitment, &sealed.ephemeral_pub, &sealed.content).is_none());
    }

    #[test]
    fn v2_tamper_is_detected() {
        let (scan_priv, scan_pub, dk, ek) = alice_v2();
        let sealed = send_v2(&scan_pub, &ek, b"tamper me").unwrap();

        // Flipping a blob byte: tag still matches, AEAD rejects.
        let mut content = sealed.content.clone();
        let last = content.len() - 1;
        content[last] ^= 1;
        assert!(receive_v2(&scan_priv, &dk, &sealed.commitment, &sealed.ephemeral_pub, &content).unwrap().is_err());

        // Flipping a kem_ct byte: implicit rejection changes ss_kem, so the tag misses.
        let mut content = sealed.content.clone();
        content[0] ^= 1;
        assert!(receive_v2(&scan_priv, &dk, &sealed.commitment, &sealed.ephemeral_pub, &content).is_none());

        // Short content is never ours.
        assert!(receive_v2(&scan_priv, &dk, &sealed.commitment, &sealed.ephemeral_pub, &sealed.content[..MIN_CONTENT_V2_LEN - 1]).is_none());
    }

    #[test]
    fn v2_deterministic_encap_matches_decap() {
        let (scan_priv, scan_pub, dk, ek) = alice_v2();
        let encap = encap_v2_deterministic(&felt("271828"), &scan_pub, &ek, &[5u8; 32]).unwrap();
        assert_eq!(encap.kem_ct.len(), KEM_CT_LEN);
        let again = encap_v2_deterministic(&felt("271828"), &scan_pub, &ek, &[5u8; 32]).unwrap();
        assert_eq!(encap.kem_ct, again.kem_ct);
        let keys = decap_tag_v2(&scan_priv, &dk, &encap.ephemeral_pub, &encap.kem_ct).unwrap();
        assert_eq!(keys, encap.keys);
    }

    #[test]
    fn v2_rejects_bad_ek() {
        let (_, scan_pub, _, ek) = alice_v2();
        assert!(encap_v2(&scan_pub, &ek[..KEM_EK_LEN - 1]).is_err());
        // Coefficients >= q fail the FIPS 203 modulus check.
        let mut bad = ek.clone();
        bad[0] = 0xff;
        bad[1] = 0xff;
        assert!(encap_v2(&scan_pub, &bad).is_err());
    }
}
