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

/// Attempts per request for transport failures and 5xx before giving up (see
/// the backoff note in `get_block_raw`).
const TRANSPORT_RETRIES: u32 = 6;

/// Exponential backoff with a 4 s ceiling: 250 ms, 500 ms, 1 s, 2 s, 4 s, 4 s.
fn backoff(attempt: u32) -> Duration {
    Duration::from_millis(250u64 << attempt.min(4))
}

/// Cumulative wait allowed for HTTP 429 on one request. A 429 is not a
/// failure — the feeder is saying "later" — and its limit window is minutes
/// wide: the transport schedule's ~12 s of total patience abandons a sync
/// that fifteen more minutes of work depends on.
const RATE_LIMIT_BUDGET: Duration = Duration::from_secs(240);

/// 5 s, 10 s, 20 s, 40 s, then 60 s — used when the feeder sends no
/// Retry-After header.
fn rate_limit_backoff(strike: u32) -> Duration {
    Duration::from_secs((5u64 << strike.min(3)).min(60))
}

pub const INTEGRATION_FEEDER: &str = "https://feeder.integration-sepolia.starknet.io/feeder_gateway";
pub const INTEGRATION_GATEWAY: &str = "https://integration-sepolia.starknet.io/gateway";

/// Minimum spacing between requests on one connection — a client-side ceiling
/// of 10 req/s. Probed 2026-07-29: the limiter sustains ~12 req/s cold on one
/// kept-alive connection, tightens to ~5-8 req/s once tripped, and punishes
/// connection churn hardest (fresh-connection traffic drew 429s at ~3 req/s).
/// Staying just under the tightened rate means the penalty never engages.
const PACE: Duration = Duration::from_millis(100);

pub struct Feeder {
    pub base: String,
    /// One connection, kept alive. The feeder's limiter treats each new TLS
    /// connection as hostile long before the request rate matters, so a
    /// connection per request (ureq's free functions) is the one pattern that
    /// must never be used here.
    agent: ureq::Agent,
    last_request: std::sync::Mutex<std::time::Instant>,
}

impl Feeder {
    pub fn new(base: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            agent: ureq::AgentBuilder::new().timeout(Duration::from_secs(30)).build(),
            last_request: std::sync::Mutex::new(std::time::Instant::now() - PACE),
        }
    }

    /// Blocks until this connection is allowed its next request.
    fn pace(&self) {
        let mut last = self.last_request.lock().unwrap();
        let elapsed = last.elapsed();
        if elapsed < PACE {
            std::thread::sleep(PACE - elapsed);
        }
        *last = std::time::Instant::now();
    }

    pub fn integration() -> Self {
        Self::new(INTEGRATION_FEEDER)
    }

    fn get_block_raw(&self, selector: &str) -> Result<String> {
        let url = format!("{}/get_block?{selector}", self.base);
        // Network I/O, three failure classes with three answers. A 429 means
        // wait — honor Retry-After when sent, otherwise escalate to a minute,
        // bounded by cumulative RATE_LIMIT_BUDGET (measured: 16 concurrent
        // workers earn a 429 within ~2,000 blocks, and the limit window is
        // minutes wide). 5xx and transport failures get short exponential
        // retries. Other 4xx are our fault, not flakiness — surface them
        // immediately.
        let mut transport_attempts = 0;
        let mut strikes = 0;
        let mut rate_limited = Duration::ZERO;
        loop {
            self.pace();
            let err = match self.agent.get(&url).call() {
                Ok(resp) => return resp.into_string().context("reading block body"),
                Err(ureq::Error::Status(429, resp)) => {
                    let wait = resp
                        .header("retry-after")
                        .and_then(|s| s.parse::<u64>().ok())
                        .map(Duration::from_secs)
                        .unwrap_or_else(|| rate_limit_backoff(strikes));
                    strikes += 1;
                    if rate_limited + wait > RATE_LIMIT_BUDGET {
                        return Err(anyhow!(
                            "feeder still rate-limiting after {} s of waiting",
                            rate_limited.as_secs()
                        ));
                    }
                    rate_limited += wait;
                    std::thread::sleep(wait);
                    continue;
                }
                Err(ureq::Error::Status(code, resp)) if code < 500 => {
                    let body = resp.into_string().unwrap_or_default();
                    return Err(anyhow!("feeder HTTP {code}: {body}"));
                }
                Err(ureq::Error::Status(code, _resp)) => anyhow!("feeder HTTP {code}"),
                Err(e) => anyhow!("{e}"),
            };
            transport_attempts += 1;
            if transport_attempts >= TRANSPORT_RETRIES {
                return Err(anyhow!(
                    "feeder request failed after {TRANSPORT_RETRIES} attempts: {err}"
                ));
            }
            std::thread::sleep(backoff(transport_attempts - 1));
        }
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
        self.pace();
        let body = self
            .agent
            .get(&url)
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
    ///
    /// Each worker keeps its own connection, and the feeder's limiter counts
    /// connections, not just requests (measured: 3 connections at 15 req/s
    /// aggregate drew 82% rejections while 1 connection at 12 req/s drew
    /// none). One worker saturates the per-IP allowance; more of them only
    /// antagonize the limiter.
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
