//! Stark-curve ECDH + Poseidon + content AEAD — the Rust mirror of the
//! circuit's primitives (fixtures/messagezk_scan). Every mapping is pinned
//! by golden vectors from fixtures/zkmsg_vectors (Cairo dump + starknet.js,
//! cross-validated; the milestone-1 bootloader preimage seals the full
//! chain — see docs/superpowers/specs/2026-07-05-zkmsg-milestone1-addendum.md):
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
use rand::RngCore;
use sha2::Sha256;
use starknet_curve::curve_params::{EC_ORDER, GENERATOR};
use starknet_types_core::curve::AffinePoint;
use starknet_types_core::felt::Felt;

const HKDF_INFO: &[u8] = b"zkmsg-v1";
const NONCE_LEN: usize = 12;

pub fn hash_pair(l: &Felt, r: &Felt) -> Felt {
    starknet_crypto::poseidon_hash_many(&[*l, *r])
}

pub fn poseidon2(a: &Felt, b: &Felt) -> Felt {
    starknet_crypto::poseidon_hash(*a, *b)
}

/// commitment = poseidon2(shared_x, 0) — the circuit's step 6.
pub fn commitment(shared_x: &Felt) -> Felt {
    poseidon2(shared_x, &Felt::ZERO)
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

fn aead_key(shared_x: &Felt) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, &shared_x.to_bytes_be());
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key).expect("32 bytes is a valid HKDF length");
    key
}

/// blob = nonce(12) ‖ AES-256-GCM ciphertext+tag under HKDF(shared_x).
pub fn encrypt(shared_x: &Felt, plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new((&aead_key(shared_x)).into());
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload::from(plaintext))
        .expect("AES-GCM encryption is infallible for in-memory buffers");
    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&ct);
    blob
}

pub fn decrypt(shared_x: &Felt, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN + 16 {
        bail!("ciphertext blob too short ({} bytes)", blob.len());
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new((&aead_key(shared_x)).into());
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload::from(ct))
        .map_err(|_| anyhow!("AEAD decryption failed (wrong key or tampered blob)"))
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
    fn golden_ecdh_and_commitment() {
        let pub7 = ec_mul_gen_x(&felt("7"));
        let shared = ecdh_shared_x(&felt("6"), &pub7).unwrap();
        assert_eq!(
            shared,
            felt("116790107469130620194501433118398966236215846997329127478236149064647078075"),
        );
        assert_eq!(
            commitment(&shared),
            felt("1030795386918240909424940654827557726691387512779373992039088349375326101405"),
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
    fn aead_round_trip_and_tamper() {
        let shared =
            felt("116790107469130620194501433118398966236215846997329127478236149064647078075");
        let blob = encrypt(&shared, b"the first natively-proven private message");
        assert_eq!(
            decrypt(&shared, &blob).unwrap(),
            b"the first natively-proven private message".to_vec(),
        );

        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(decrypt(&shared, &tampered).is_err());

        let wrong_key = felt("12345");
        assert!(decrypt(&wrong_key, &blob).is_err());
    }

    #[test]
    fn keygen_produces_valid_scalars() {
        let (private, public) = scan_keygen();
        assert_ne!(private, Felt::ZERO);
        assert_eq!(public, ec_mul_gen_x(&private));
        // The pubkey x must lift back onto the curve (inbox lift path).
        assert!(ecdh_shared_x(&Felt::TWO, &public).is_ok());
    }
}
