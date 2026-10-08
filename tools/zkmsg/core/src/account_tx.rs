//! The member's own transactions (register, ticket purchases), signed
//! natively under the shared transaction policy (`txpolicy`) instead of
//! through `sncast`, whose 1.5×-everything estimates made desktop
//! transactions recognisable (red team 2026-10, F3/F4).
//!
//! The account key is read where `sncast account create` put it
//! ([`Signer::from_sncast_account`]); the transaction goes out through the
//! profile's JSON-RPC (`starknet_addInvokeTransaction`), and the node must
//! echo the hash signed here.

use std::time::Duration;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use starknet_types_core::felt::Felt;

use crate::chain::{Chain, felt_hex};
use crate::invoke_v3::{Bounds, Call, InvokeV3, Signer, execute_calldata};
use crate::txpolicy::{self, TIP, TxKind};

const RECEIPT_TIMEOUT: Duration = Duration::from_secs(600);

/// One signed INVOKE v3 in RPC shape, and its hash.
pub fn signed_invoke(
    signer: &Signer,
    calls: &[Call],
    nonce: Felt,
    bounds: Bounds,
    chain_id: Felt,
) -> Result<(Felt, Value)> {
    let calldata = execute_calldata(calls);
    let hash = InvokeV3 { sender: signer.address, calldata: &calldata, chain_id, nonce, tip: TIP, bounds, proof_facts: &[] }
        .hash();
    let [r, s] = signer.sign(&hash)?;
    let tx = json!({
        "type": "INVOKE",
        "version": "0x3",
        "sender_address": felt_hex(&signer.address),
        "calldata": calldata.iter().map(felt_hex).collect::<Vec<_>>(),
        "signature": [felt_hex(&r), felt_hex(&s)],
        "nonce": felt_hex(&nonce),
        "resource_bounds": bounds.rpc_json(),
        "tip": format!("{TIP:#x}"),
        "paymaster_data": [],
        "account_deployment_data": [],
        "nonce_data_availability_mode": "L1",
        "fee_data_availability_mode": "L1",
    });
    Ok((hash, tx))
}

/// Signs `calls` from `account` with `kind`'s bounds at the latest prices,
/// submits, and waits for a successful receipt. Returns the hash.
pub fn send(chain: &Chain, account: &str, calls: &[Call], kind: TxKind) -> Result<String> {
    let hex = submit(chain, account, calls, kind)?;
    chain.wait_receipt(&hex, RECEIPT_TIMEOUT)?;
    Ok(hex)
}

/// `send` without the receipt wait: the hash once the node took it.
pub fn submit(chain: &Chain, account: &str, calls: &[Call], kind: TxKind) -> Result<String> {
    let signer = Signer::from_sncast_account(account)?;
    let chain_id = Felt::from_hex(chain.rpc("starknet_chainId", json!([]))?.as_str().context("chain id")?)?;
    let nonce = chain.rpc("starknet_getNonce", json!(["latest", felt_hex(&signer.address)]))?;
    let nonce = Felt::from_hex(nonce.as_str().context("nonce")?)?;
    let bounds = txpolicy::bounds(kind, chain.gas_prices()?);
    let (hash, tx) = signed_invoke(&signer, calls, nonce, bounds, chain_id)?;
    let reply = chain
        .rpc("starknet_addInvokeTransaction", json!({"invoke_transaction": tx}))
        .with_context(|| format!("submitting {}", kind.name()))?;
    let echoed = reply["transaction_hash"].as_str().context("no transaction_hash in reply")?;
    ensure!(
        Felt::from_hex(echoed)? == hash,
        "the node hashed the {} as {echoed}, not {}",
        kind.name(),
        felt_hex(&hash)
    );
    Ok(felt_hex(&hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invoke_v3::short_string;

    /// The shape every member transaction shares: policy bounds, the
    /// shared tip, L1 DA, empty paymaster/deployment data, `[r, s]`.
    #[test]
    fn member_transactions_have_the_shared_shape() {
        let key = Felt::from_hex("0x1234567890abcdef").unwrap();
        let signer = Signer::new(Felt::from_hex("0x5617").unwrap(), key);
        let call = Call::new(Felt::from(9u64), "register", vec![Felt::ONE]);
        let prices = (52_616_363_968_810, 18_090_898_182, 52_616);
        let bounds = txpolicy::bounds(TxKind::Register, prices);
        let (hash, tx) = signed_invoke(&signer, &[call.clone()], Felt::TWO, bounds, short_string("SN_SEPOLIA")).unwrap();
        assert_eq!(tx["tip"], "0x5f5e100");
        assert_eq!(tx["resource_bounds"]["l2_gas"]["max_amount"], "0x1c9c380");
        assert_eq!(tx["resource_bounds"]["l2_gas"]["max_price_per_unit"], "0x684ee1800");
        assert_eq!(tx["paymaster_data"], json!([]));
        assert_eq!(tx["nonce_data_availability_mode"], "L1");
        let sig: Vec<Felt> = tx["signature"].as_array().unwrap().iter().map(|x| Felt::from_hex(x.as_str().unwrap()).unwrap()).collect();
        assert_eq!(sig.len(), 2);
        assert!(starknet_crypto::verify(&starknet_crypto::get_public_key(&key), &hash, &sig[0], &sig[1]).unwrap());
        let calldata = execute_calldata(&[call]);
        let want = InvokeV3 {
            sender: signer.address,
            calldata: &calldata,
            chain_id: short_string("SN_SEPOLIA"),
            nonce: Felt::TWO,
            tip: TIP,
            bounds,
            proof_facts: &[],
        }
        .hash();
        assert_eq!(hash, want);
    }
}
