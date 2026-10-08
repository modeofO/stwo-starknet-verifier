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
const HKDF_SALT_V4: &[u8] = b"zkmsg-v4";
const HKDF_INFO_AEAD_V4: &[u8] = b"zkmsg-v4 aead";
const HKDF_INFO_TAG_V4: &[u8] = b"zkmsg-v4 tag";

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

/// Which key schedule: v2's labels, or v4's (same construction, labels
/// "zkmsg-v4", so a v4 ciphertext never opens as a v2/v3 one or back).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sealing {
    V2,
    V4,
}

impl Sealing {
    fn labels(self) -> (&'static [u8], &'static [u8], &'static [u8]) {
        match self {
            Self::V2 => (HKDF_SALT_V2, HKDF_INFO_AEAD_V2, HKDF_INFO_TAG_V2),
            Self::V4 => (HKDF_SALT_V4, HKDF_INFO_AEAD_V4, HKDF_INFO_TAG_V4),
        }
    }
}

pub fn derive_v2(
    ss_kem: &[u8; 32],
    ss_ec: &Felt,
    ephemeral_pub: &Felt,
    recipient_scan_pub: &Felt,
    kem_ct: &[u8],
) -> HybridKeys {
    derive(Sealing::V2, ss_kem, ss_ec, ephemeral_pub, recipient_scan_pub, kem_ct)
}

pub fn derive(
    sealing: Sealing,
    ss_kem: &[u8; 32],
    ss_ec: &Felt,
    ephemeral_pub: &Felt,
    recipient_scan_pub: &Felt,
    kem_ct: &[u8],
) -> HybridKeys {
    let (salt, info_aead, info_tag) = sealing.labels();
    let mut ikm = Vec::with_capacity(160);
    ikm.extend_from_slice(ss_kem);
    ikm.extend_from_slice(&ss_ec.to_bytes_be());
    ikm.extend_from_slice(&ephemeral_pub.to_bytes_be());
    ikm.extend_from_slice(&recipient_scan_pub.to_bytes_be());
    ikm.extend_from_slice(&Sha3_256::digest(kem_ct));

    let (prk, hk) = Hkdf::<Sha256>::extract(Some(salt), &ikm);
    let mut k = [0u8; 32];
    hk.expand(info_aead, &mut k).expect("32 bytes is a valid HKDF length");
    let mut tag = [0u8; 31];
    hk.expand(info_tag, &mut tag).expect("31 bytes is a valid HKDF length");
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
    encap_deterministic(Sealing::V2, ephemeral_priv, recipient_scan_pub, recipient_ek, m)
}

pub fn encap_deterministic(
    sealing: Sealing,
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
    let keys = derive(sealing, &ss_kem, &ss_ec, &ephemeral_pub, recipient_scan_pub, &kem_ct);
    Ok(EncapV2 { ephemeral_pub, kem_ct, ss_kem, ss_ec, keys })
}

/// Encapsulates with fresh randomness (v2 labels).
pub fn encap_v2(recipient_scan_pub: &Felt, recipient_ek: &[u8]) -> Result<EncapV2> {
    encap(Sealing::V2, recipient_scan_pub, recipient_ek)
}

/// Encapsulates with fresh randomness under `sealing`'s labels.
pub fn encap(sealing: Sealing, recipient_scan_pub: &Felt, recipient_ek: &[u8]) -> Result<EncapV2> {
    let (ephemeral_priv, _) = scan_keygen();
    let mut m = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut m);
    encap_deterministic(sealing, &ephemeral_priv, recipient_scan_pub, recipient_ek, &m)
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
    decap_tag(Sealing::V2, scan_priv, dk, ephemeral_pub, kem_ct)
}

pub fn decap_tag(
    sealing: Sealing,
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
    Ok(derive(sealing, &ss_kem, &ss_ec, ephemeral_pub, &own_scan_pub, kem_ct))
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

// ---------------------------------------------------------------------------
// v4 sealing: v2's hybrid construction under "zkmsg-v4" labels, with the
// plaintext padded to a fixed bucket inside the AEAD so the on-chain length
// says only which bucket:
//
//   padded  = len(plaintext) as u16 BE ‖ plaintext ‖ zeros, |padded| ∈ PAD_BUCKETS
//   blob    = nonce(12) ‖ AES-256-GCM(k, nonce, padded, aad = tag ‖ E) ‖ tag16
//   content = kem_ct(1088) ‖ blob   → 1372, 2140 or 5212 bytes
//
// The smallest bucket that fits is used; a plaintext over 4094 bytes is
// refused. Opening requires the length to fit the bucket and every
// trailing byte to be zero.
// ---------------------------------------------------------------------------

/// The sizes `padded` may have.
pub const PAD_BUCKETS: [usize; 3] = [256, 1024, 4096];
/// The longest plaintext: the top bucket less the u16 length prefix.
pub const MAX_PLAINTEXT_V4: usize = 4096 - 2;
/// Content bytes beyond `padded`: kem_ct, nonce, GCM tag.
pub const CONTENT_OVERHEAD_V4: usize = KEM_CT_LEN + NONCE_LEN + 16;

/// The on-chain content lengths a v4 send may have.
pub fn content_lens_v4() -> [usize; 3] {
    PAD_BUCKETS.map(|b| b + CONTENT_OVERHEAD_V4)
}

pub fn pad_v4(plaintext: &[u8]) -> Result<Vec<u8>> {
    let bucket = PAD_BUCKETS
        .iter()
        .copied()
        .find(|b| plaintext.len() + 2 <= *b)
        .ok_or_else(|| anyhow!("message is {} bytes; at most {MAX_PLAINTEXT_V4} fit", plaintext.len()))?;
    let mut padded = Vec::with_capacity(bucket);
    padded.extend_from_slice(&(plaintext.len() as u16).to_be_bytes());
    padded.extend_from_slice(plaintext);
    padded.resize(bucket, 0);
    Ok(padded)
}

pub fn unpad_v4(padded: &[u8]) -> Result<Vec<u8>> {
    if !PAD_BUCKETS.contains(&padded.len()) {
        bail!("padded plaintext is {} bytes, not a bucket size", padded.len());
    }
    let len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    if len > padded.len() - 2 {
        bail!("padding length {len} overruns the {}-byte bucket", padded.len());
    }
    if padded[2 + len..].iter().any(|b| *b != 0) {
        bail!("padding is not all zero");
    }
    Ok(padded[2..2 + len].to_vec())
}

/// Encapsulate (v4 labels), pad, seal and assemble `content = kem_ct ‖ blob`.
pub fn send_v4(recipient_scan_pub: &Felt, recipient_ek: &[u8], plaintext: &[u8]) -> Result<SealedV2> {
    let padded = pad_v4(plaintext)?;
    let encap = encap(Sealing::V4, recipient_scan_pub, recipient_ek)?;
    let blob = seal_v2(&encap.keys, &encap.ephemeral_pub, &padded);
    Ok(assemble_v2(&encap, &blob))
}

/// Detect and decrypt one v4 `MessageSent` event. `None`: not ours.
/// `Some(Err)`: the tag matched but the blob did not open or unpad — which
/// is what a front-run copy of someone's commitment over other content
/// looks like; the inbox drops it.
pub fn receive_v4(
    scan_priv: &Felt,
    dk: &DecapsulationKey768,
    commitment: &Felt,
    ephemeral_pub: &Felt,
    content: &[u8],
) -> Option<Result<Vec<u8>>> {
    let (kem_ct, blob) = split_content_v2(content).ok()?;
    let keys = decap_tag(Sealing::V4, scan_priv, dk, ephemeral_pub, kem_ct).ok()?;
    if keys.tag != *commitment {
        return None;
    }
    Some(open_v2(&keys, ephemeral_pub, blob).and_then(|padded| unpad_v4(&padded)))
}

// ---------------------------------------------------------------------------
// v3: hash-based membership
// (docs/superpowers/specs/2026-10-01-zkmsg-v3-pq-membership-design.md)
//
//   m        : 32 bytes BE, top 5 bits clear (m < 2^251 < p), m != 0
//   m_commit = poseidon_hash_many([MEMBER_V3, m])
//   leaf     = poseidon_hash_many([LEAF_V3, R, kem_digest, m_commit])
// ---------------------------------------------------------------------------

pub const MEMBER_SECRET_LEN: usize = 32;

/// 'zkmsg-member-v3' as a Cairo short string.
pub fn member_v3_domain() -> Felt {
    Felt::from_bytes_be_slice(b"zkmsg-member-v3")
}

/// 'zkmsg-leaf-v3' as a Cairo short string.
pub fn leaf_v3_domain() -> Felt {
    Felt::from_bytes_be_slice(b"zkmsg-leaf-v3")
}

/// Fresh membership secret: 32 random bytes with the top 5 bits cleared,
/// so it is always below 2^251 (a felt, uniform, unreduced). Never zero.
pub fn member_secret_gen() -> [u8; MEMBER_SECRET_LEN] {
    loop {
        let mut m = [0u8; MEMBER_SECRET_LEN];
        rand::rngs::OsRng.fill_bytes(&mut m);
        m[0] &= 0x07;
        if m.iter().any(|b| *b != 0) {
            return m;
        }
    }
}

/// The stored 32-byte form → felt. Rejects values >= 2^251 and zero, which
/// a generated secret never is (a hand-edited or truncated file might be).
pub fn member_secret_felt(m: &[u8]) -> Result<Felt> {
    let m: &[u8; MEMBER_SECRET_LEN] = m
        .try_into()
        .map_err(|_| anyhow!("member secret must be {MEMBER_SECRET_LEN} bytes, got {}", m.len()))?;
    if m[0] & 0xf8 != 0 {
        bail!("member secret is not below 2^251");
    }
    if m.iter().all(|b| *b == 0) {
        bail!("member secret is zero");
    }
    Ok(Felt::from_bytes_be(m))
}

/// m_commit = poseidon_hash_many([MEMBER_V3, m]).
pub fn member_commit(m: &Felt) -> Felt {
    starknet_crypto::poseidon_hash_many(&[member_v3_domain(), *m])
}

/// leaf = poseidon_hash_many([LEAF_V3, R, kem_digest, m_commit]).
pub fn leaf_v3(scan_pub: &Felt, kem_digest: &Felt, m_commit: &Felt) -> Felt {
    starknet_crypto::poseidon_hash_many(&[leaf_v3_domain(), *scan_pub, *kem_digest, *m_commit])
}

// ---------------------------------------------------------------------------
// v4: the pool's rate-limit nullifier and single-send tickets
// (docs/superpowers/specs/2026-10-07-zkmsg-v4-pool-tickets-design.md;
// contracts/zkmsg_pool_v4/src/prover.cairo)
//
//   nullifier        = poseidon_hash_many([NULLIFIER_V4, store, m, epoch, slot])
//   ticket leaf      = poseidon_hash_many([TICKET_V4, t])
//   ticket nullifier = poseidon_hash_many([TICKET_NULL_V4, store, t])
//   envelope key     = poseidon_hash_many([commitment, content_hash])
//
// A ticket secret t has the member secret's form: 32 bytes BE, top 5 bits
// clear, nonzero.
// ---------------------------------------------------------------------------

/// 'zkmsg-nullifier-v4' as a Cairo short string.
pub fn nullifier_v4_domain() -> Felt {
    Felt::from_bytes_be_slice(b"zkmsg-nullifier-v4")
}

/// 'zkmsg-ticket-v4' as a Cairo short string.
pub fn ticket_v4_domain() -> Felt {
    Felt::from_bytes_be_slice(b"zkmsg-ticket-v4")
}

/// 'zkmsg-ticket-null-v4' as a Cairo short string.
pub fn ticket_null_v4_domain() -> Felt {
    Felt::from_bytes_be_slice(b"zkmsg-ticket-null-v4")
}

/// The member's quota nullifier for `slot` of `epoch` on `store`. `m` and
/// `slot` stay private, so it names neither the member nor the slot.
pub fn nullifier_v4(store: &Felt, m: &Felt, epoch: u64, slot: u32) -> Felt {
    starknet_crypto::poseidon_hash_many(&[
        nullifier_v4_domain(),
        *store,
        *m,
        Felt::from(epoch),
        Felt::from(slot),
    ])
}

/// Fresh ticket secret: the member secret's distribution (< 2^251, nonzero).
pub fn ticket_secret_gen() -> [u8; MEMBER_SECRET_LEN] {
    member_secret_gen()
}

/// What `buy_tickets` publishes for the ticket `t`.
pub fn ticket_leaf(t: &Felt) -> Felt {
    starknet_crypto::poseidon_hash_many(&[ticket_v4_domain(), *t])
}

/// What a send spending the ticket `t` on `store` reveals.
pub fn ticket_nullifier(store: &Felt, t: &Felt) -> Felt {
    starknet_crypto::poseidon_hash_many(&[ticket_null_v4_domain(), *store, *t])
}

/// The key the v4 store refuses to publish twice: commitment AND content.
pub fn envelope_key(commitment: &Felt, content_hash: &Felt) -> Felt {
    starknet_crypto::poseidon_hash_many(&[*commitment, *content_hash])
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

    // --- v3 ----------------------------------------------------------------

    #[test]
    fn v4_pad_round_trips_and_boundaries() {
        for (n, bucket) in [(0, 256), (1, 256), (254, 256), (255, 1024), (1022, 1024), (1023, 4096), (4094, 4096)] {
            let text = vec![0xa5u8; n];
            let padded = pad_v4(&text).unwrap();
            assert_eq!(padded.len(), bucket, "{n} bytes");
            assert_eq!(unpad_v4(&padded).unwrap(), text);
        }
        assert!(pad_v4(&[0u8; 4095]).unwrap_err().to_string().contains("4094"));
        assert_eq!(content_lens_v4(), [1372, 2140, 5212]);
    }

    #[test]
    fn v4_malformed_padding_is_refused() {
        let mut padded = pad_v4(b"hello").unwrap();
        padded[100] = 1;
        assert!(unpad_v4(&padded).is_err(), "nonzero trailing byte");
        let mut padded = pad_v4(b"hello").unwrap();
        padded[..2].copy_from_slice(&255u16.to_be_bytes());
        assert!(unpad_v4(&padded).is_err(), "length past bucket - 2");
        assert!(unpad_v4(&[0u8; 300]).is_err(), "not a bucket size");
        assert!(unpad_v4(&[0u8; 1]).is_err());
    }

    #[test]
    fn v4_round_trip_and_label_separation() {
        let (scan_priv, scan_pub, dk, ek) = alice_v2();
        let sealed = send_v4(&scan_pub, &ek, b"padded hello").unwrap();
        assert_eq!(sealed.content.len(), 1372);
        let opened = receive_v4(&scan_priv, &dk, &sealed.commitment, &sealed.ephemeral_pub, &sealed.content);
        assert_eq!(opened.unwrap().unwrap(), b"padded hello");
        // A v4 envelope is not a v2 one, and back.
        assert!(receive_v2(&scan_priv, &dk, &sealed.commitment, &sealed.ephemeral_pub, &sealed.content).is_none());
        let v2 = send_v2(&scan_pub, &ek, b"old").unwrap();
        assert!(receive_v4(&scan_priv, &dk, &v2.commitment, &v2.ephemeral_pub, &v2.content).is_none());
        // Same tag, other content (a front-run copy): matched, refuses to open.
        let mut forged = sealed.content.clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(receive_v4(&scan_priv, &dk, &sealed.commitment, &sealed.ephemeral_pub, &forged).unwrap().is_err());
    }

    #[test]
    fn v3_domains() {
        assert_eq!(member_v3_domain(), Felt::from_hex("0x7a6b6d73672d6d656d6265722d7633").unwrap());
        assert_eq!(leaf_v3_domain(), Felt::from_hex("0x7a6b6d73672d6c6561662d7633").unwrap());
    }

    #[test]
    fn v3_member_secret_is_a_251_bit_nonzero_felt() {
        for _ in 0..256 {
            let m = member_secret_gen();
            assert_eq!(m[0] & 0xf8, 0);
            let f = member_secret_felt(&m).unwrap();
            assert_eq!(f.to_bytes_be(), m, "stored form round-trips");
        }
        let mut high = [0u8; 32];
        high[0] = 0x08;
        assert!(member_secret_felt(&high).is_err(), ">= 2^251 rejected");
        assert!(member_secret_felt(&[0u8; 32]).is_err(), "zero rejected");
        assert!(member_secret_felt(&[1u8; 31]).is_err(), "short rejected");
        let mut max = [0xffu8; 32];
        max[0] = 0x07;
        assert!(member_secret_felt(&max).is_ok(), "2^251 - 1 accepted");
    }

    #[test]
    fn v3_leaf_binds_every_part() {
        let (r, d, m) = (felt("5"), felt("6"), felt("7"));
        let c = member_commit(&m);
        let leaf = leaf_v3(&r, &d, &c);
        assert_ne!(leaf, leaf_v3(&r, &d, &member_commit(&felt("8"))));
        assert_ne!(leaf, leaf_v3(&felt("9"), &d, &c));
        assert_ne!(leaf, leaf_v3(&r, &felt("9"), &c));
        assert_ne!(leaf, leaf_v2(&r, &d), "not a v2 leaf");
        assert_ne!(c, m);
    }
}
