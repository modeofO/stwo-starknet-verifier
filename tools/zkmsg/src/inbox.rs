//! Inbox scan: pull `MessageSent` events from the store, trial-ECDH each
//! `(commitment, ephemeral_pubkey)` against the local scan key — a hit
//! (poseidon2(shared, 0) == commitment) means the message is ours — and
//! decrypt the content blob. Observers cannot run this test without the
//! scan private key; that asymmetry IS the recipient anonymity.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;

use crate::chain::{Chain, bytearray_decode, felt_to_u64, snkeccak};
use crate::crypto::{commitment, decrypt, ecdh_shared_x};

#[derive(Debug, Serialize, Deserialize)]
pub struct ReceivedMessage {
    pub nonce: u64,
    pub commitment: String,
    pub text: String,
}

/// Scans all MessageSent events and returns the ones addressed to
/// `scan_priv`, decrypted.
pub fn scan(chain: &Chain, store: &str, scan_priv: &Felt) -> Result<Vec<ReceivedMessage>> {
    let key0 = format!("{:#x}", snkeccak("MessageSent"));
    let events = chain.events(store, &key0, 0)?;

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
