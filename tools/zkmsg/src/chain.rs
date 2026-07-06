//! Starknet driver: `sncast --json` subprocesses for account
//! transactions (the path with the proven Sepolia runbook behavior) and
//! raw JSON-RPC (ureq) for receipts, traces, calls-by-result and events.
//!
//! An invoke's return value is not exposed over RPC, and a read-only
//! starknet_call cannot stand in when state is caller-keyed — so, as in
//! scripts/devnet_drive.py, retdata comes from starknet_traceTransaction
//! (the inner call's `result` in the account's execute_invocation).

use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use starknet_types_core::felt::Felt;

/// Explicit resource bounds — sncast's automatic estimation multiplies
/// by 1.5, which pushes the big lane-1 verify txs over the per-invoke
/// bound check (docs/lane1-results.md runbook).
#[derive(Debug, Clone, Default)]
pub struct GasBounds {
    pub l1_gas: Option<u64>,
    pub l1_gas_price: Option<u128>,
    pub l2_gas: Option<u64>,
    pub l2_gas_price: Option<u128>,
    pub l1_data_gas: Option<u64>,
    pub l1_data_gas_price: Option<u128>,
}

impl GasBounds {
    fn args(&self) -> Vec<String> {
        let mut out = vec![];
        let mut push = |flag: &str, v: Option<String>| {
            if let Some(v) = v {
                out.push(flag.to_string());
                out.push(v);
            }
        };
        push("--l1-gas", self.l1_gas.map(|v| v.to_string()));
        push("--l1-gas-price", self.l1_gas_price.map(|v| v.to_string()));
        push("--l2-gas", self.l2_gas.map(|v| v.to_string()));
        push("--l2-gas-price", self.l2_gas_price.map(|v| v.to_string()));
        push("--l1-data-gas", self.l1_data_gas.map(|v| v.to_string()));
        push("--l1-data-gas-price", self.l1_data_gas_price.map(|v| v.to_string()));
        out
    }
}

pub struct Chain {
    pub rpc_url: String,
    pub account: String,
}

impl Chain {
    pub fn new(rpc_url: &str, account: &str) -> Self {
        Self { rpc_url: rpc_url.into(), account: account.into() }
    }

    // --- sncast ------------------------------------------------------------

    fn sncast(&self, args: &[String]) -> Result<Value> {
        let mut cmd = Command::new("sncast");
        cmd.arg("--json").arg("--account").arg(&self.account);
        cmd.args(args);
        cmd.arg("--url").arg(&self.rpc_url);
        let out = cmd.output().context("running sncast")?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        if !out.status.success() {
            bail!(
                "sncast {} failed:\n{}\n{}",
                args.first().map(String::as_str).unwrap_or(""),
                stdout,
                String::from_utf8_lossy(&out.stderr),
            );
        }
        parse_sncast_json(&stdout)
    }

    pub fn invoke(
        &self,
        contract: &str,
        function: &str,
        calldata: &[String],
        bounds: &GasBounds,
    ) -> Result<String> {
        let mut args: Vec<String> = vec![
            "invoke".into(),
            "--contract-address".into(),
            contract.into(),
            "--function".into(),
            function.into(),
        ];
        if !calldata.is_empty() {
            args.push("--calldata".into());
            args.extend_from_slice(calldata);
        }
        args.extend(bounds.args());
        let v = self.sncast(&args)?;
        let tx = v["transaction_hash"]
            .as_str()
            .with_context(|| format!("no transaction_hash in sncast output: {v}"))?;
        Ok(tx.to_string())
    }

    pub fn call(&self, contract: &str, function: &str, calldata: &[String]) -> Result<Vec<String>> {
        let mut args: Vec<String> = vec![
            "call".into(),
            "--contract-address".into(),
            contract.into(),
            "--function".into(),
            function.into(),
        ];
        if !calldata.is_empty() {
            args.push("--calldata".into());
            args.extend_from_slice(calldata);
        }
        let v = self.sncast(&args)?;
        // sncast 0.61: `response` is a pretty-printed string; the felts
        // live in `response_raw`.
        let response = v["response_raw"]
            .as_array()
            .or_else(|| v["response"].as_array())
            .with_context(|| format!("no response felts in sncast call output: {v}"))?;
        Ok(response.iter().filter_map(|x| x.as_str().map(String::from)).collect())
    }

    // --- raw RPC -----------------------------------------------------------

    pub fn rpc(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let reply: Value = ureq::post(&self.rpc_url)
            .set("Content-Type", "application/json")
            .send_json(body)
            .with_context(|| format!("rpc {method}"))?
            .into_json()?;
        if let Some(err) = reply.get("error") {
            bail!("{method}: {err}");
        }
        Ok(reply["result"].clone())
    }

    /// Polls until SUCCEEDED; errors on REVERTED with the reason (fees are
    /// burned on revert — the caller's state file has already recorded the
    /// tx hash by then).
    pub fn wait_receipt(&self, tx_hash: &str, timeout: Duration) -> Result<Value> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.rpc("starknet_getTransactionReceipt", json!([tx_hash])) {
                Ok(receipt) => match receipt["execution_status"].as_str() {
                    Some("SUCCEEDED") => return Ok(receipt),
                    Some("REVERTED") => bail!(
                        "tx {tx_hash} REVERTED: {}",
                        receipt["revert_reason"].as_str().unwrap_or("?"),
                    ),
                    _ => {}
                },
                Err(_) => {} // not yet indexed
            }
            if Instant::now() > deadline {
                bail!("tx {tx_hash}: no receipt after {timeout:?}");
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    /// The entrypoint's retdata: the first inner call of the account's
    /// execute_invocation trace.
    pub fn trace_retdata(&self, tx_hash: &str) -> Result<Vec<String>> {
        let trace = self.rpc("starknet_traceTransaction", json!([tx_hash]))?;
        let result = &trace["execute_invocation"]["calls"][0]["result"];
        let arr = result
            .as_array()
            .with_context(|| format!("no inner-call result in trace of {tx_hash}"))?;
        Ok(arr.iter().filter_map(|x| x.as_str().map(String::from)).collect())
    }

    /// All events for `address` filtered by `key0`, walking continuation
    /// tokens. Returns (keys, data) pairs.
    pub fn events(
        &self,
        address: &str,
        key0: &str,
        from_block: u64,
    ) -> Result<Vec<(Vec<String>, Vec<String>)>> {
        let mut out = vec![];
        let mut token: Option<String> = None;
        loop {
            let mut filter = json!({
                "from_block": {"block_number": from_block},
                "to_block": "latest",
                "address": address,
                "keys": [[key0]],
                "chunk_size": 100,
            });
            if let Some(t) = &token {
                filter["continuation_token"] = json!(t);
            }
            let page = self.rpc("starknet_getEvents", json!([filter]))?;
            for ev in page["events"].as_array().unwrap_or(&vec![]) {
                let keys = str_vec(&ev["keys"]);
                let data = str_vec(&ev["data"]);
                out.push((keys, data));
            }
            match page["continuation_token"].as_str() {
                Some(t) => token = Some(t.to_string()),
                None => return Ok(out),
            }
        }
    }
}

fn str_vec(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

/// sncast --json emits one JSON object per line; the RESULT is the object
/// with type == "response" (a "links" notification can follow it).
pub fn parse_sncast_json(stdout: &str) -> Result<Value> {
    let objects: Vec<Value> = stdout
        .lines()
        .filter(|l| l.trim_start().starts_with('{'))
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    if let Some(err) = objects.iter().find(|v| v["type"] == "error") {
        bail!("sncast error: {}", err["error"]);
    }
    objects
        .iter()
        .find(|v| v["type"] == "response")
        .or_else(|| objects.last())
        .cloned()
        .context("no JSON object in sncast output")
}

/// sn_keccak of an ASCII name (event key / entrypoint selector): keccak256
/// masked to 250 bits.
pub fn snkeccak(name: &str) -> Felt {
    use sha3::{Digest, Keccak256};
    let hash = Keccak256::digest(name.as_bytes());
    let mut bytes: [u8; 32] = hash.into();
    bytes[0] &= 0x03; // mask to 250 bits
    Felt::from_bytes_be(&bytes)
}

// --- calldata serde helpers -------------------------------------------------

pub fn felt_hex(f: &Felt) -> String {
    format!("{f:#x}")
}

/// Span<felt252> serde: length prefix + elements.
pub fn span_calldata(items: &[Felt]) -> Vec<String> {
    let mut out = vec![format!("{:#x}", Felt::from(items.len() as u64))];
    out.extend(items.iter().map(felt_hex));
    out
}

/// ByteArray serde: [n_full_words, full 31-byte words…, pending_word,
/// pending_word_len].
pub fn bytearray_calldata(bytes: &[u8]) -> Vec<String> {
    let full_words = bytes.len() / 31;
    let mut out = vec![format!("{:#x}", full_words)];
    for chunk in bytes[..full_words * 31].chunks(31) {
        out.push(felt_hex(&felt_from_be_bytes(chunk)));
    }
    let pending = &bytes[full_words * 31..];
    out.push(felt_hex(&felt_from_be_bytes(pending)));
    out.push(format!("{:#x}", pending.len()));
    out
}

/// Decodes the ByteArray serde layout back to bytes (event data side).
pub fn bytearray_decode(data: &[Felt]) -> Result<(Vec<u8>, usize)> {
    let n_words = felt_to_u64(data.first().context("empty bytearray data")?)? as usize;
    if data.len() < n_words + 3 {
        bail!("bytearray data too short: {} felts for {} words", data.len(), n_words);
    }
    let mut bytes = vec![];
    for word in &data[1..1 + n_words] {
        bytes.extend_from_slice(&word.to_bytes_be()[1..]); // low 31 bytes
    }
    let pending_len = felt_to_u64(&data[1 + n_words + 1])?;
    let pending = data[1 + n_words].to_bytes_be();
    bytes.extend_from_slice(&pending[32 - pending_len as usize..]);
    // consumed felts: 1 + n_words + 2
    Ok((bytes, 1 + n_words + 2))
}

/// Small-felt to u64 (errors if it doesn't fit).
pub fn felt_to_u64(f: &Felt) -> Result<u64> {
    let bytes = f.to_bytes_be();
    if bytes[..24].iter().any(|b| *b != 0) {
        bail!("felt {f:#x} does not fit in u64");
    }
    Ok(u64::from_be_bytes(bytes[24..].try_into().unwrap()))
}

fn felt_from_be_bytes(bytes: &[u8]) -> Felt {
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(bytes);
    Felt::from_bytes_be(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_last_json_line() {
        let stdout = "some banner\n{\"phase\":\"estimating\"}\n{\"transaction_hash\":\"0xabc\"}\n";
        let v = parse_sncast_json(stdout).unwrap();
        assert_eq!(v["transaction_hash"].as_str(), Some("0xabc"));
    }

    #[test]
    fn snkeccak_known_selector() {
        // sn_keccak("transfer") — the canonical cross-implementation vector.
        assert_eq!(
            snkeccak("transfer"),
            Felt::from_hex("0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e")
                .unwrap(),
        );
    }

    #[test]
    fn bytearray_round_trip() {
        for msg in [
            b"hello".to_vec(),
            b"exactly-thirty-one-bytes-word!!".to_vec(), // 31 bytes
            vec![7u8; 100],
            vec![],
        ] {
            let calldata = bytearray_calldata(&msg);
            let felts: Vec<Felt> =
                calldata.iter().map(|s| Felt::from_hex(s).unwrap()).collect();
            let (decoded, consumed) = bytearray_decode(&felts).unwrap();
            assert_eq!(decoded, msg);
            assert_eq!(consumed, felts.len());
        }
    }

    #[test]
    fn bytearray_short_string_shape() {
        // "hello" -> [0, 0x68656c6c6f, 5]
        let calldata = bytearray_calldata(b"hello");
        assert_eq!(calldata, vec!["0x0", "0x68656c6c6f", "0x5"]);
    }

    #[test]
    fn span_prefixes_length() {
        let out = span_calldata(&[Felt::ONE, Felt::TWO]);
        assert_eq!(out, vec!["0x2", "0x1", "0x2"]);
    }
}
