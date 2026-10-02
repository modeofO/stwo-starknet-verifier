//! Inbox scan: pull `MessageSent` events from the store, trial-ECDH each
//! `(commitment, ephemeral_pubkey)` against the local scan key — a hit
//! (poseidon2(shared, 0) == commitment) means the message is ours — and
//! decrypt the content blob. Observers cannot run this test without the
//! scan private key; that asymmetry IS the recipient anonymity.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;

use crate::chain::{Chain, bytearray_decode, felt_to_u64, snkeccak};
use crate::config::{Keys, StoreKind, store_deploy_block, store_kind};
use crate::crypto::{commitment, decrypt, ecdh_shared_x, receive_v2};

#[derive(Debug, Serialize, Deserialize)]
pub struct ReceivedMessage {
    pub nonce: u64,
    pub commitment: String,
    pub text: String,
}

/// Scans `store` with whichever detection its version uses: v2 stores need
/// the ML-KEM key as well as the scan key.
pub fn scan_with_keys(chain: &Chain, store: &str, keys: &Keys) -> Result<Vec<ReceivedMessage>> {
    let scan_priv = keys.scan_priv_felt()?;
    if store_kind(store) == Some(StoreKind::V2) {
        let (dk, _) = keys.kem_keypair().context("a v2 inbox needs the profile's ML-KEM key")?;
        scan_v2(chain, store, &scan_priv, &dk)
    } else {
        scan(chain, store, &scan_priv)
    }
}

/// One `MessageSent` event, decoded: keys = [selector, commitment]; data =
/// [ephemeral_pubkey, nonce, ByteArray content…] — the same on every store.
struct Envelope {
    commitment_hex: String,
    commitment: Felt,
    ephemeral: Felt,
    nonce: u64,
    content: Vec<u8>,
}

fn envelopes(chain: &Chain, store: &str) -> Result<Vec<Envelope>> {
    let key0 = format!("{:#x}", snkeccak("MessageSent"));
    let mut out = vec![];
    for (keys, data) in chain.events(store, &key0, store_deploy_block(store))? {
        let (Some(commitment_hex), true) = (keys.get(1), data.len() >= 5) else { continue };
        let felts: Vec<Felt> = data[2..]
            .iter()
            .map(|s| Felt::from_hex(s).context("event content felt"))
            .collect::<Result<_>>()?;
        out.push(Envelope {
            commitment_hex: commitment_hex.clone(),
            commitment: Felt::from_hex(commitment_hex).context("event commitment")?,
            ephemeral: Felt::from_hex(&data[0]).context("event ephemeral pubkey")?,
            nonce: felt_to_u64(&Felt::from_hex(&data[1]).context("event nonce")?)?,
            content: bytearray_decode(&felts)?.0,
        });
    }
    Ok(out)
}

/// v2 detect-and-decrypt: the hybrid key schedule (ECDH + ML-KEM decaps)
/// gives a tag; only the recipient's tag equals the commitment.
pub fn scan_v2(
    chain: &Chain,
    store: &str,
    scan_priv: &Felt,
    dk: &ml_kem::DecapsulationKey768,
) -> Result<Vec<ReceivedMessage>> {
    let mut received = vec![];
    for env in envelopes(chain, store)? {
        let Some(opened) = receive_v2(scan_priv, dk, &env.commitment, &env.ephemeral, &env.content)
        else {
            continue; // not for us
        };
        let text = match opened {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(e) => format!("<matched but undecryptable: {e}>"),
        };
        received.push(ReceivedMessage { nonce: env.nonce, commitment: env.commitment_hex, text });
    }
    received.sort_by_key(|m| m.nonce);
    Ok(received)
}

/// Scans all MessageSent events (from the store's deploy block, see
/// `config::store_deploy_block`) and returns the ones addressed to
/// `scan_priv`, decrypted.
pub fn scan(chain: &Chain, store: &str, scan_priv: &Felt) -> Result<Vec<ReceivedMessage>> {
    let key0 = format!("{:#x}", snkeccak("MessageSent"));
    let events = chain.events(store, &key0, store_deploy_block(store))?;

    let mut received = vec![];
    for (keys, data) in events {
        // keys = [sn_keccak(MessageSent), commitment]; data =
        // [ephemeral_pubkey, nonce, ByteArray content...].
        let (Some(commitment_hex), true) = (keys.get(1), data.len() >= 5) else { continue };
        let event_commitment = Felt::from_hex(commitment_hex).context("event commitment")?;
        let eph_pub = Felt::from_hex(&data[0]).context("event ephemeral pubkey")?;

        // The trial: does OUR scan key open this envelope?
        let Ok(shared) = ecdh_shared_x(scan_priv, &eph_pub) else { continue };
        if commitment(&shared) != event_commitment {
            continue; // not for us
        }

        let nonce = felt_to_u64(&Felt::from_hex(&data[1]).context("event nonce")?)?;
        let content_felts: Vec<Felt> = data[2..]
            .iter()
            .map(|s| Felt::from_hex(s).context("event content felt"))
            .collect::<Result<_>>()?;
        let (blob, _) = bytearray_decode(&content_felts)?;
        let text = match decrypt(&shared, &blob) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(e) => format!("<matched but undecryptable: {e}>"),
        };
        received.push(ReceivedMessage {
            nonce,
            commitment: commitment_hex.clone(),
            text,
        });
    }
    received.sort_by_key(|m| m.nonce);
    Ok(received)
}
