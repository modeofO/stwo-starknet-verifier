//! INVOKE v3 hashing and signing, natively — the SNIP-36 publish leg can't go
//! through `sncast`, which has no way to attach `proof` / `proof_facts`.
//!
//! The hash is SNIP-8 v3 (three-resource fee bounds since Starknet 0.13.4),
//! with SNIP-36's one extension: a transaction that carries a proof signs its
//! facts too, as one more field, `poseidon(proof_facts)`, after the calldata
//! hash. Without facts the hash is the ordinary one, so the same function signs
//! both the virtual transaction (proven, never sent) and the real one.
//!
//! A port of zkmsg-ios `TransactionHashV3.invokeV3Hash` and
//! `StarknetAccount.executeCalldata`. Pinned by a real Sepolia SNIP-36 send
//! (`testdata/snip36_send_tx.json`, the sequencer's own hash) and, for the
//! fact-less case, by starknet-core.
//!
//! Signing key: the desktop keeps account keys where `sncast` put them, in
//! `~/.starknet_accounts/starknet_open_zeppelin_accounts.json`, and reads them
//! from there ([`Signer::from_sncast_account`]). Every desktop account was made
//! by `sncast account create` (setup wizard, burners), so that file is already
//! the single place a key lives; copying it into `keys.json` would make two.

use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use serde_json::Value;
use starknet_crypto::{get_public_key, poseidon_hash_many, rfc6979_generate_k, sign};
use starknet_types_core::felt::Felt;

use crate::chain::{felt_hex, snkeccak};

/// One resource's fee ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResourceBounds {
    pub max_amount: u64,
    pub max_price_per_unit: u128,
}

impl ResourceBounds {
    /// `(name << 192) | (max_amount << 128) | max_price_per_unit`, the felt the
    /// fee hash absorbs. `name` is the resource's short string (≤ 8 bytes).
    fn packed(&self, name: &str) -> Felt {
        let mut buf = [0u8; 32];
        let name = name.as_bytes();
        buf[8 - name.len()..8].copy_from_slice(name);
        buf[8..16].copy_from_slice(&self.max_amount.to_be_bytes());
        buf[16..32].copy_from_slice(&self.max_price_per_unit.to_be_bytes());
        Felt::from_bytes_be(&buf)
    }

    fn json(&self) -> Value {
        serde_json::json!({
            "max_amount": format!("{:#x}", self.max_amount),
            "max_price_per_unit": format!("{:#x}", self.max_price_per_unit),
        })
    }
}

/// The three resources priced separately since Starknet 0.13.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bounds {
    pub l1_gas: ResourceBounds,
    pub l2_gas: ResourceBounds,
    pub l1_data_gas: ResourceBounds,
}

impl Bounds {
    /// RPC spelling (`starknet_proveTransaction`, `starknet_addInvokeTransaction`).
    pub fn rpc_json(&self) -> Value {
        serde_json::json!({
            "l1_gas": self.l1_gas.json(),
            "l2_gas": self.l2_gas.json(),
            "l1_data_gas": self.l1_data_gas.json(),
        })
    }

    /// Gateway spelling (`add_transaction`).
    pub fn gateway_json(&self) -> Value {
        serde_json::json!({
            "L1_GAS": self.l1_gas.json(),
            "L2_GAS": self.l2_gas.json(),
            "L1_DATA_GAS": self.l1_data_gas.json(),
        })
    }
}

/// One call in an account's `__execute__` multicall.
#[derive(Debug, Clone)]
pub struct Call {
    pub to: Felt,
    pub selector: Felt,
    pub calldata: Vec<Felt>,
}

impl Call {
    pub fn new(to: Felt, entrypoint: &str, calldata: Vec<Felt>) -> Self {
        Self { to, selector: snkeccak(entrypoint), calldata }
    }
}

/// The Cairo 1 account `__execute__` calldata:
/// `[n_calls, (to, selector, len, calldata…)…]`.
pub fn execute_calldata(calls: &[Call]) -> Vec<Felt> {
    let mut out = vec![Felt::from(calls.len() as u64)];
    for call in calls {
        out.push(call.to);
        out.push(call.selector);
        out.push(Felt::from(call.calldata.len() as u64));
        out.extend_from_slice(&call.calldata);
    }
    out
}

/// What an INVOKE v3 commits to. Paymaster data and account deployment data
/// are always empty and both DA modes are L1: zkmsg never uses either.
#[derive(Debug, Clone)]
pub struct InvokeV3<'a> {
    pub sender: Felt,
    /// The account's `__execute__` calldata (see [`execute_calldata`]).
    pub calldata: &'a [Felt],
    pub chain_id: Felt,
    pub nonce: Felt,
    pub tip: u64,
    pub bounds: Bounds,
    /// SNIP-36 facts the transaction signs over; empty for an ordinary invoke.
    pub proof_facts: &'a [Felt],
}

impl InvokeV3<'_> {
    pub fn hash(&self) -> Felt {
        let fee_hash = poseidon_hash_many(&[
            Felt::from(self.tip),
            self.bounds.l1_gas.packed("L1_GAS"),
            self.bounds.l2_gas.packed("L2_GAS"),
            self.bounds.l1_data_gas.packed("L1_DATA"),
        ]);
        let mut fields = vec![
            short_string("invoke"),
            Felt::THREE,
            self.sender,
            fee_hash,
            poseidon_hash_many(&[]), // paymaster_data
            self.chain_id,
            self.nonce,
            Felt::ZERO, // (nonce DA << 32) | fee DA, both L1 = 0
            poseidon_hash_many(&[]), // account_deployment_data
            poseidon_hash_many(self.calldata),
        ];
        if !self.proof_facts.is_empty() {
            fields.push(poseidon_hash_many(self.proof_facts));
        }
        poseidon_hash_many(&fields)
    }
}

/// An account that signs transactions: its address and private key.
pub struct Signer {
    pub address: Felt,
    private_key: Felt,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer").field("address", &felt_hex(&self.address)).finish_non_exhaustive()
    }
}

impl Signer {
    pub fn new(address: Felt, private_key: Felt) -> Self {
        Self { address, private_key }
    }

    /// Loads `account` from sncast's accounts file (Sepolia section), and
    /// checks the key matches the public key recorded beside it.
    pub fn from_sncast_account(account: &str) -> Result<Self> {
        let path = sncast_accounts_path()?;
        let raw: Value = serde_json::from_str(
            &std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?,
        )?;
        let entry = &raw["alpha-sepolia"][account];
        let field = |name: &str| -> Result<Felt> {
            let hex = entry[name]
                .as_str()
                .with_context(|| format!("account '{account}' has no {name} in {}", path.display()))?;
            Felt::from_hex(hex).with_context(|| format!("account '{account}' {name}"))
        };
        let signer = Self::new(field("address")?, field("private_key")?);
        if let Ok(public_key) = field("public_key") {
            ensure!(
                get_public_key(&signer.private_key) == public_key,
                "account '{account}': private key does not match its recorded public key",
            );
        }
        Ok(signer)
    }

    /// ECDSA over `hash` with an RFC 6979 nonce: `[r, s]`.
    pub fn sign(&self, hash: &Felt) -> Result<[Felt; 2]> {
        let k = rfc6979_generate_k(hash, &self.private_key, None);
        let signature = sign(&self.private_key, hash, &k).context("ecdsa sign")?;
        Ok([signature.r, signature.s])
    }
}

fn sncast_accounts_path() -> Result<PathBuf> {
    Ok(PathBuf::from(std::env::var("HOME")?)
        .join(".starknet_accounts/starknet_open_zeppelin_accounts.json"))
}

/// Cairo short string: up to 31 ASCII bytes as a big-endian integer.
pub fn short_string(text: &str) -> Felt {
    assert!(text.len() <= 31 && text.is_ascii(), "not a short string: {text}");
    let mut buf = [0u8; 32];
    buf[32 - text.len()..].copy_from_slice(text.as_bytes());
    Felt::from_bytes_be(&buf)
}

/// Felt → its short string, for chain ids (`SN_SEPOLIA`).
pub fn short_string_text(felt: &Felt) -> Result<String> {
    let bytes = felt.to_bytes_be();
    let text: Vec<u8> = bytes.iter().copied().skip_while(|b| *b == 0).collect();
    ensure!(text.is_ascii(), "{} is not a short string", felt_hex(felt));
    Ok(String::from_utf8(text)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn felts(v: &Value) -> Vec<Felt> {
        v.as_array().unwrap().iter().map(|x| Felt::from_hex(x.as_str().unwrap()).unwrap()).collect()
    }

    fn bound(v: &Value) -> ResourceBounds {
        let hex = |k: &str| v[k].as_str().unwrap().trim_start_matches("0x").to_string();
        ResourceBounds {
            max_amount: u64::from_str_radix(&hex("max_amount"), 16).unwrap(),
            max_price_per_unit: u128::from_str_radix(&hex("max_price_per_unit"), 16).unwrap(),
        }
    }

    fn fixture() -> Value {
        serde_json::from_str(include_str!("../testdata/snip36_send_tx.json")).unwrap()
    }

    fn fixture_invoke(tx: &Value) -> (Vec<Felt>, Vec<Felt>, Bounds) {
        let rb = &tx["resource_bounds"];
        let bounds = Bounds {
            l1_gas: bound(&rb["L1_GAS"]),
            l2_gas: bound(&rb["L2_GAS"]),
            l1_data_gas: bound(&rb["L1_DATA_GAS"]),
        };
        (felts(&tx["calldata"]), felts(&tx["proof_facts"]), bounds)
    }

    /// The sequencer's hash of a real SNIP-36 send on Sepolia: facts appended.
    #[test]
    fn reproduces_live_snip36_hash() {
        let tx = fixture();
        let (calldata, facts, bounds) = fixture_invoke(&tx);
        let invoke = InvokeV3 {
            sender: Felt::from_hex(tx["sender_address"].as_str().unwrap()).unwrap(),
            calldata: &calldata,
            chain_id: short_string("SN_SEPOLIA"),
            nonce: Felt::from_hex(tx["nonce"].as_str().unwrap()).unwrap(),
            tip: 0,
            bounds,
            proof_facts: &facts,
        };
        let want = Felt::from_hex(tx["transaction_hash"].as_str().unwrap()).unwrap();
        assert_eq!(invoke.hash(), want);
        // Dropping the facts must change the hash: they are signed over.
        assert_ne!(InvokeV3 { proof_facts: &[], ..invoke }.hash(), want);
    }

    /// Without facts, the hash is the ordinary INVOKE v3 hash: a real Sepolia
    /// `register` (zkmsg-ios `Fixtures/sepolia_txs.json`, `invoke_register`).
    #[test]
    fn factless_hash_matches_live_register() {
        let tx: Value = serde_json::from_str(
            r#"{
                "calldata": ["0x1",
                    "0x2d66a02b2efdddb5282bf7d7931cbb7a724f191478843b1fccbf3b9729e91b7",
                    "0x1007bd789f73e08c2714644c55b11c7d202931d717def434e3c9caa12a9f583",
                    "0x2", "0x6275726e65722d376563303730",
                    "0x61c181c6a88e17d0514deda2166418afdf6afcd8c4d06cd186ded9c8b6d79e1"],
                "nonce": "0x1",
                "resource_bounds": {
                    "L1_DATA_GAS": {"max_amount": "0xd80", "max_price_per_unit": "0x1d8dd78ff2a"},
                    "L1_GAS": {"max_amount": "0x0", "max_price_per_unit": "0x130f6a8e80b59"},
                    "L2_GAS": {"max_amount": "0xbdcea0", "max_price_per_unit": "0xa076b0047"}
                },
                "sender_address": "0x733887f60196abc3c941f62709333f53b895f02dcedd65ffda725a55852600c",
                "transaction_hash": "0x174b41823d6749940d85bfbd81d284cbfff9d9c9bebdb8f5e3c7481d57be884",
                "proof_facts": []
            }"#,
        )
        .unwrap();
        let (calldata, facts, bounds) = fixture_invoke(&tx);
        let invoke = InvokeV3 {
            sender: Felt::from_hex(tx["sender_address"].as_str().unwrap()).unwrap(),
            calldata: &calldata,
            chain_id: short_string("SN_SEPOLIA"),
            nonce: Felt::from_hex(tx["nonce"].as_str().unwrap()).unwrap(),
            tip: 0,
            bounds,
            proof_facts: &facts,
        };
        assert_eq!(invoke.hash(), Felt::from_hex(tx["transaction_hash"].as_str().unwrap()).unwrap());
    }

    #[test]
    fn execute_calldata_matches_live_envelope() {
        // The fixture's calldata is one send_message call to the v1 store.
        let tx = fixture();
        let calldata = felts(&tx["calldata"]);
        let call = Call {
            to: calldata[1],
            selector: snkeccak("send_message"),
            calldata: calldata[4..].to_vec(),
        };
        assert_eq!(call.selector, calldata[2]);
        assert_eq!(execute_calldata(&[call]), calldata);
    }

    #[test]
    fn signature_verifies() {
        let key = Felt::from_hex("0x1234567890abcdef").unwrap();
        let signer = Signer::new(Felt::ONE, key);
        let hash = Felt::from_hex("0x5ee").unwrap();
        let [r, s] = signer.sign(&hash).unwrap();
        assert!(starknet_crypto::verify(&get_public_key(&key), &hash, &r, &s).unwrap());
        // RFC 6979: deterministic.
        assert_eq!(signer.sign(&hash).unwrap(), [r, s]);
    }

    #[test]
    fn chain_id_round_trip() {
        assert_eq!(short_string_text(&short_string("SN_SEPOLIA")).unwrap(), "SN_SEPOLIA");
    }
}
