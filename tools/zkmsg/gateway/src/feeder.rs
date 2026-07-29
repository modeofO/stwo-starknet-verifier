//! Feeder-gateway transport. Read-only: blocks and gas prices.
//!
//! Endpoint status on sepolia-integration, probed 2026-07-29:
//!   get_block      — SERVES full blocks incl. transaction_receipts + events
//!   call_contract  — DEPRECATED_ENDPOINT (since 0.12.3)
//!   get_nonce      — DEPRECATED_ENDPOINT (since 0.12.3)
//! Hence: everything is derived from blocks.

use std::sync::mpsc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};

use crate::Block;

/// Attempts per request before giving up (see the backoff note in `get_block_raw`).
const RETRIES: u32 = 6;

/// Exponential backoff with a 4 s ceiling: 250 ms, 500 ms, 1 s, 2 s, 4 s, 4 s.
fn backoff(attempt: u32) -> Duration {
    Duration::from_millis(250u64 << attempt.min(4))
}

pub const INTEGRATION_FEEDER: &str = "https://feeder.integration-sepolia.starknet.io/feeder_gateway";
pub const INTEGRATION_GATEWAY: &str = "https://integration-sepolia.starknet.io/gateway";

pub struct Feeder {
    pub base: String,
}

impl Feeder {
    pub fn new(base: &str) -> Self {
        Self { base: base.trim_end_matches('/').to_string() }
    }

    pub fn integration() -> Self {
        Self::new(INTEGRATION_FEEDER)
    }

    fn get_block_raw(&self, selector: &str) -> Result<String> {
        let url = format!("{}/get_block?{selector}", self.base);
        // Network I/O: retry transient transport failures and 429/5xx with
        // exponential backoff. The feeder rate-limits aggressively (measured:
        // 16 concurrent workers earn a 429 within ~2,000 blocks), and since a
        // full sync is thousands of requests, backing off correctly is the
        // difference between a slow sync and a failed one. Other 4xx are our
        // fault, not flakiness — surface them immediately.
        let mut last_err = None;
        for attempt in 0..RETRIES {
            match ureq::get(&url).timeout(Duration::from_secs(30)).call() {
                Ok(resp) => return resp.into_string().context("reading block body"),
                Err(ureq::Error::Status(code, _resp)) if code == 429 || code >= 500 => {
                    last_err = Some(anyhow!("feeder HTTP {code}"));
                    std::thread::sleep(backoff(attempt));
                }
                Err(ureq::Error::Status(code, resp)) => {
                    let body = resp.into_string().unwrap_or_default();
                    return Err(anyhow!("feeder HTTP {code}: {body}"));
                }
                Err(e) => {
                    last_err = Some(anyhow!("{e}"));
                    std::thread::sleep(backoff(attempt));
                }
            }
        }
        Err(anyhow!("feeder request failed after {RETRIES} attempts: {}", last_err.unwrap()))
    }

    pub fn block(&self, number: u64) -> Result<Block> {
        let body = self.get_block_raw(&format!("blockNumber={number}"))?;
        serde_json::from_str(&body).with_context(|| format!("parsing block {number}"))
    }

    pub fn latest(&self) -> Result<Block> {
        let body = self.get_block_raw("blockNumber=latest")?;
        serde_json::from_str(&body).context("parsing latest block")
    }

    /// Storage writes made by `contract` in `block`, from `get_state_update`.
    ///
    /// This is the one way to read contract state on a feeder-only network:
    /// the deprecated `call_contract` is gone, but state diffs are still
    /// published. Used here to check derived state against the chain's own
    /// storage; a client could in principle replay diffs to read any slot.
    pub fn storage_writes(&self, block: u64, contract: &str) -> Result<Vec<(String, String)>> {
        let url = format!("{}/get_state_update?blockNumber={block}", self.base);
        let body = ureq::get(&url)
            .timeout(Duration::from_secs(30))
            .call()
            .map_err(|e| anyhow!("state update: {e}"))?
            .into_string()?;
        let v: serde_json::Value = serde_json::from_str(&body).context("parsing state update")?;
        let want = crate::normalize_felt(contract);
        let diffs = v
            .get("state_diff")
            .and_then(|d| d.get("storage_diffs"))
            .and_then(|d| d.as_object())
            .ok_or_else(|| anyhow!("state update has no storage_diffs"))?;
        Ok(diffs
            .iter()
            .filter(|(addr, _)| crate::normalize_felt(addr) == want)
            .flat_map(|(_, entries)| entries.as_array().cloned().unwrap_or_default())
            .filter_map(|e| {
                Some((
                    e.get("key")?.as_str()?.to_string(),
                    e.get("value")?.as_str()?.to_string(),
                ))
            })
            .collect())
    }

    /// Fetches `[from, to)` with `parallelism` workers. Blocks are independent,
    /// so the only ordering requirement is that the caller absorbs them in
    /// sequence — hence results are collected and sorted before returning.
    pub fn blocks(&self, from: u64, to: u64, parallelism: usize) -> Result<Vec<Block>> {
        if from >= to {
            return Ok(vec![]);
        }
        let numbers: Vec<u64> = (from..to).collect();
        let chunk = numbers.len().div_ceil(parallelism.max(1));
        let (tx, rx) = mpsc::channel();

        std::thread::scope(|scope| {
            for shard in numbers.chunks(chunk) {
                let tx = tx.clone();
                let base = self.base.clone();
                scope.spawn(move || {
                    let feeder = Feeder::new(&base);
                    for &n in shard {
                        let _ = tx.send(feeder.block(n).map(|b| (n, b)));
                    }
                });
            }
            drop(tx);

            let mut out = Vec::with_capacity(numbers.len());
            for received in rx {
                out.push(received?);
            }
            out.sort_by_key(|(n, _)| *n);
            Ok(out.into_iter().map(|(_, b)| b).collect())
        })
    }
}
