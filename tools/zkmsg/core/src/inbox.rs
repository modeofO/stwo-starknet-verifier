//! Inbox scan: pull `MessageSent` events from the store and, for each,
//! recompute the hybrid key schedule (ECDH with the scan key + ML-KEM
//! decapsulation of the `kem_ct` the content leads with). The resulting tag
//! equals the event's commitment only for the recipient; then the blob
//! opens. Observers cannot run this test without both private keys; that
//! asymmetry IS the recipient anonymity.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;

use crate::chain::{Chain, bytearray_decode, felt_to_u64, snkeccak};
use crate::config::{Keys, is_v2_store, store_deploy_block};
use crate::crypto::receive_v2;

#[derive(Debug, Serialize, Deserialize)]
pub struct ReceivedMessage {
    pub nonce: u64,
    pub commitment: String,
    pub text: String,
}

/// Scans the v2 store with the profile's scan key and ML-KEM key. Other
/// stores are no longer read (owner decision 2026-10-01).
pub fn scan_with_keys(chain: &Chain, store: &str, keys: &Keys) -> Result<Vec<ReceivedMessage>> {
    ensure!(is_v2_store(store), "{store} is not the v2 store — `zkmsg migrate-store` moves this profile");
    let (dk, _) = keys.kem_keypair().context("a v2 inbox needs the profile's ML-KEM key")?;
    scan_v2(chain, store, &keys.scan_priv_felt()?, &dk)
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
