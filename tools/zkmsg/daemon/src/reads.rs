//! The chain reads the daemon does OUTSIDE the pipeline: health's chain id
//! and balance, and resolve's handle lookup. They sit behind a trait so the
//! health/resolve handlers unit-test against a fixture — a live chain is not
//! needed to check the JSON shaping or the readiness gate.

use anyhow::Result;
use serde_json::json;
use zkmsg_core::app;
use zkmsg_core::chain::{felt_hex, Chain};
use zkmsg_core::config::Config;

/// The read-only chain surface the daemon touches per request. Kept small on
/// purpose: everything else the daemon does goes through the pipeline.
pub trait ChainReader: Send + Sync {
    /// `starknet_chainId`, e.g. `0x534e5f5345504f4c4941` (SN_SEPOLIA).
    fn chain_id(&self) -> Result<String>;
    /// The sender account's STRK balance, whole tokens (floor).
    fn balance_strk(&self) -> Result<u128>;
    /// A recipient handle's `(scan_pub_hex, leaf_index)`, or an error when it
    /// is not registered.
    fn resolve(&self, handle: &str) -> Result<(String, u32)>;
}

/// The production reader — one `Chain` per call (cheap: it just holds the
/// rpc url and account name). Config is cloned in so balance/store/account
/// stay consistent for the daemon's lifetime.
pub struct LiveReads {
    config: Config,
}

impl LiveReads {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    fn chain(&self) -> Chain {
        Chain::new(&self.config.rpc_url, &self.config.account)
    }
}

impl ChainReader for LiveReads {
    fn chain_id(&self) -> Result<String> {
        let v = self.chain().rpc("starknet_chainId", json!([]))?;
        Ok(v.as_str().unwrap_or_default().to_string())
    }

    fn balance_strk(&self) -> Result<u128> {
        app::account_balance_strk(&self.chain(), &self.config)
    }

    fn resolve(&self, handle: &str) -> Result<(String, u32)> {
        let (scan_pub, leaf) = app::resolve_recipient(&self.chain(), &self.config.store, handle)?;
        Ok((felt_hex(&scan_pub), leaf))
    }
}

#[cfg(test)]
pub mod testing {
    use super::*;
    use std::collections::HashMap;

    /// A scripted reader for handler tests. Any field left `None`/absent
    /// makes the corresponding call return an error, mirroring an RPC that
    /// is down or a handle that is not registered.
    #[derive(Default)]
    pub struct FakeReads {
        pub chain_id: Option<String>,
        pub balance_strk: Option<u128>,
        pub handles: HashMap<String, (String, u32)>,
    }

    impl ChainReader for FakeReads {
        fn chain_id(&self) -> Result<String> {
            self.chain_id.clone().ok_or_else(|| anyhow::anyhow!("chain id unavailable"))
        }
        fn balance_strk(&self) -> Result<u128> {
            self.balance_strk.ok_or_else(|| anyhow::anyhow!("balance unavailable"))
        }
        fn resolve(&self, handle: &str) -> Result<(String, u32)> {
            self.handles
                .get(handle)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("handle not registered"))
        }
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;

    /// A real Sepolia read (no prove). Gated behind ZKMSG_DAEMON_LIVE: when
    /// the var is unset the test body early-returns, so `cargo test` stays
    /// offline and never touches the chain. With the var set it reads the
    /// configured home's rpc and asserts a plausible chain id.
    #[test]
    fn chain_id_reads_sepolia_when_live() {
        if std::env::var("ZKMSG_DAEMON_LIVE").is_err() {
            eprintln!("skipping chain_id_reads_sepolia_when_live (set ZKMSG_DAEMON_LIVE to run)");
            return;
        }
        let home = zkmsg_core::config::Home::new(
            std::path::PathBuf::from(std::env::var("HOME").unwrap()).join(".zkmsg"),
        );
        let dir = zkmsg_core::profiles::resolve_cli_home(&home.dir).unwrap();
        let config = zkmsg_core::config::Home::new(dir).load_config().unwrap();
        let reads = LiveReads::new(config);
        let id = reads.chain_id().expect("chain id from live rpc");
        assert!(id.starts_with("0x"), "chain id looks like a felt: {id}");
    }
}
