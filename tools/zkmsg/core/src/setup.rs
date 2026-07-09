//! The identity-setup wizard as a checkpointed pipeline:
//!
//!   CreateAccount → Fund → Deploy → Init → Register
//!
//! Mirrors `pipeline.rs`: every step is persisted after it runs (to
//! `<profile_dir>/setup.json`), so a crash resumes at the first
//! incomplete step and never re-executes a done step. Fund moves the
//! user's real STRK, so it is gated (`fund_strk > 0`), guarded by a
//! balance pre-check (a landed-but-uncheckpointed transfer is not
//! re-sent), and — like the send pipeline's tx steps — emits
//! `TxSubmitted` between the invoke and the receipt wait.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::app::{self, RegisterOutcome};
use crate::chain::{self, Chain};
use crate::config::{Home, STRK_TOKEN};

const RECEIPT_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SetupStepKind {
    /// `sncast account create` — precomputes the OZ account address.
    CreateAccount,
    /// STRK transfer from `source_account` to the new address (real money).
    Fund,
    /// `sncast account deploy` — the DEPLOY_ACCOUNT tx.
    Deploy,
    /// scan keypair + `config.json` for the profile.
    Init,
    /// on-chain handle registration.
    Register,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupStep {
    pub kind: SetupStepKind,
    pub done: bool,
    pub tx_hash: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum FundMode {
    /// STRK transfer from `source_account` (the original wizard behavior).
    #[default]
    Transfer,
    /// Wait until the new address holds >= `fund_strk`; the app never
    /// transfers — the user deposits from outside their account graph.
    /// `source_account` is unused (and empty) in this mode.
    External,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupState {
    pub profile_name: String,
    pub handle: String,
    pub account_name: String,
    pub fund_strk: u64,
    pub source_account: String,
    #[serde(default)]
    pub fund_mode: FundMode,
    /// The new account's address, filled once CreateAccount runs.
    pub address: Option<String>,
    pub steps: Vec<SetupStep>,
}

impl SetupState {
    pub fn new_plan(
        profile_name: String,
        handle: String,
        account_name: String,
        fund_strk: u64,
        source_account: String,
    ) -> Self {
        let steps = [
            SetupStepKind::CreateAccount,
            SetupStepKind::Fund,
            SetupStepKind::Deploy,
            SetupStepKind::Init,
            SetupStepKind::Register,
        ]
        .into_iter()
        .map(|kind| SetupStep { kind, done: false, tx_hash: None, note: None })
        .collect();
        Self {
            profile_name,
            handle,
            account_name,
            fund_strk,
            source_account,
            fund_mode: FundMode::Transfer,
            address: None,
            steps,
        }
    }

    pub fn next_pending(&self) -> Option<usize> {
        self.steps.iter().position(|s| !s.done)
    }

    pub fn mark_done(&mut self, index: usize, tx_hash: Option<String>, note: Option<String>) {
        self.steps[index].done = true;
        self.steps[index].tx_hash = tx_hash;
        self.steps[index].note = note;
    }

    fn path(dir: &Path) -> PathBuf {
        dir.join("setup.json")
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        fs::create_dir_all(dir)?;
        fs::write(Self::path(dir), serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn load(dir: &Path) -> Result<Self> {
        let raw = fs::read_to_string(Self::path(dir))
            .with_context(|| format!("no setup state in {}", dir.display()))?;
        Ok(serde_json::from_str(&raw)?)
    }
}

#[derive(Debug, Clone)]
pub enum SetupEvent {
    StepStarted { index: usize, total: usize, kind: SetupStepKind },
    TxSubmitted { kind: SetupStepKind, tx_hash: String },
    StepCompleted { kind: SetupStepKind, tx_hash: Option<String>, note: Option<String> },
    /// External fund mode only: the runner parked because the new address
    /// does not yet hold the target. Emitted INSTEAD of executing Fund;
    /// the run returns Ok(()) with Fund still pending.
    AwaitingDeposit { address: String, target_strk: u64, balance_fri: u128 },
    Completed,
}

enum StepOutcome {
    Done(Option<String>, Option<String>),
    /// External Fund, deposit not yet arrived: stop the run, keep pending.
    Park,
}

pub struct SetupRunner<'a> {
    pub rpc_url: &'a str,
    pub profile_dir: &'a Path,
    pub repo_root: &'a Path,
}

impl SetupRunner<'_> {
    /// Runs every remaining step; emits progress events via `sink`.
    pub fn run(&self, state: &mut SetupState, sink: &mut dyn FnMut(SetupEvent)) -> Result<()> {
        while let Some(index) = state.next_pending() {
            let kind = state.steps[index].kind.clone();
            let total = state.steps.len();
            sink(SetupEvent::StepStarted { index, total, kind: kind.clone() });
            match self.execute(state, &kind, sink)? {
                StepOutcome::Done(tx, note) => {
                    state.mark_done(index, tx.clone(), note.clone());
                    state.save(self.profile_dir)?;
                    sink(SetupEvent::StepCompleted { kind, tx_hash: tx, note });
                }
                StepOutcome::Park => return Ok(()),
            }
        }
        sink(SetupEvent::Completed);
        Ok(())
    }

    fn execute(
        &self,
        state: &mut SetupState,
        kind: &SetupStepKind,
        sink: &mut dyn FnMut(SetupEvent),
    ) -> Result<StepOutcome> {
        match kind {
            SetupStepKind::CreateAccount => {
                let (tx, note) = self.step_create(state)?;
                Ok(StepOutcome::Done(tx, note))
            }
            SetupStepKind::Fund => self.step_fund(state, kind, sink),
            SetupStepKind::Deploy => {
                let (tx, note) = self.step_deploy(state, kind, sink)?;
                Ok(StepOutcome::Done(tx, note))
            }
            SetupStepKind::Init => {
                let (tx, note) = self.step_init(state)?;
                Ok(StepOutcome::Done(tx, note))
            }
            SetupStepKind::Register => {
                let (tx, note) = self.step_register(state)?;
                Ok(StepOutcome::Done(tx, note))
            }
        }
    }

    fn step_create(&self, state: &mut SetupState) -> Result<(Option<String>, Option<String>)> {
        let chain = Chain::new(self.rpc_url, &state.source_account);
        let (address, note) = match chain.account_create(&state.account_name) {
            Ok(addr) => (addr.clone(), addr),
            // A previous run may have created the account before dying; if
            // the OZ accounts file already has it, adopt that address.
            Err(e) => match chain::account_address(&state.account_name) {
                Ok(addr) => (addr, "account already existed".to_string()),
                Err(_) => return Err(e),
            },
        };
        state.address = Some(address);
        Ok((None, Some(note)))
    }

    fn step_fund(
        &self,
        state: &SetupState,
        kind: &SetupStepKind,
        sink: &mut dyn FnMut(SetupEvent),
    ) -> Result<StepOutcome> {
        ensure!(state.fund_strk > 0, "fund amount must be > 0 STRK");
        let address = state.address.clone().context("fund step before address is known")?;
        let chain = Chain::new(self.rpc_url, &state.source_account);

        if state.fund_mode == FundMode::External {
            // Never transfers. Covered -> done; not covered -> park. A
            // balance-read error also parks (retry via Refresh) rather
            // than failing the checklist red.
            let balance = read_balance_fri(&chain, &address).unwrap_or(0);
            if !fund_needed(balance, state.fund_strk) {
                return Ok(StepOutcome::Done(None, Some("funded externally".into())));
            }
            sink(SetupEvent::AwaitingDeposit {
                address,
                target_strk: state.fund_strk,
                balance_fri: balance,
            });
            return Ok(StepOutcome::Park);
        }

        // FundMode::Transfer — unchanged behavior (resume guard + transfer).
        // Resume guard: if the new account already holds enough STRK (a
        // prior run's transfer landed before we could checkpoint Fund),
        // don't re-send and double-fund. If the balance read itself errors
        // we fall through and transfer — availability over the rare-crash
        // guard, since a missing balance almost always means "not funded".
        if let Ok(balance_fri) = read_balance_fri(&chain, &address) {
            if !fund_needed(balance_fri, state.fund_strk) {
                return Ok(StepOutcome::Done(None, Some("already funded (balance covers)".into())));
            }
        }

        let tx = chain.invoke(
            STRK_TOKEN,
            "transfer",
            &[address, strk_to_fri_hex(state.fund_strk), "0x0".into()],
            &Default::default(),
        )?;
        sink(SetupEvent::TxSubmitted { kind: kind.clone(), tx_hash: tx.clone() });
        chain.wait_receipt(&tx, RECEIPT_TIMEOUT)?;
        Ok(StepOutcome::Done(Some(tx), Some(format!("funded {} STRK", state.fund_strk))))
    }

    fn step_deploy(
        &self,
        state: &SetupState,
        kind: &SetupStepKind,
        sink: &mut dyn FnMut(SetupEvent),
    ) -> Result<(Option<String>, Option<String>)> {
        let chain = Chain::new(self.rpc_url, &state.source_account);
        match chain.account_deploy(&state.account_name) {
            Ok(tx) => {
                sink(SetupEvent::TxSubmitted { kind: kind.clone(), tx_hash: tx.clone() });
                chain.wait_receipt(&tx, RECEIPT_TIMEOUT)?;
                Ok((Some(tx), None))
            }
            // A prior run's deploy may already have landed — sncast then
            // errors that the account is deployed; treat that as done.
            Err(e) if e.to_string().to_lowercase().contains("already deployed") => {
                Ok((None, Some("already deployed".into())))
            }
            Err(e) => Err(e),
        }
    }

    fn step_init(&self, state: &SetupState) -> Result<(Option<String>, Option<String>)> {
        let home = Home::new(self.profile_dir.to_path_buf());
        if home.keys_path().exists() {
            return Ok((None, Some("already initialized".into())));
        }
        app::init_identity(&home, &state.account_name, None, self.repo_root)?;
        Ok((None, None))
    }

    fn step_register(&self, state: &SetupState) -> Result<(Option<String>, Option<String>)> {
        let home = Home::new(self.profile_dir.to_path_buf());
        match app::register(&home, &state.handle)? {
            RegisterOutcome::Registered { tx_hash, leaf_index } => {
                Ok((Some(tx_hash), Some(format!("registered at leaf {leaf_index}"))))
            }
            RegisterOutcome::AlreadyRegistered { .. } => {
                Ok((None, Some("already registered".into())))
            }
        }
    }
}

/// Whole STRK to fri (wei-scale, 1e18) as a u256-low hex literal for
/// calldata.
pub fn strk_to_fri_hex(strk: u64) -> String {
    format!("{:#x}", strk as u128 * 1_000_000_000_000_000_000)
}

/// Whether the Fund step still needs to send a transfer: true iff the
/// account's current balance (in fri) does not already cover `fund_strk`.
/// A balance exactly at the target counts as covered (no transfer).
fn fund_needed(balance_fri: u128, fund_strk: u64) -> bool {
    balance_fri < fund_strk as u128 * 1_000_000_000_000_000_000
}

/// The account's STRK balance in fri (u256 low limb) — same read shape as
/// `app::account_balance_strk`, but undivided for the exact pre-check.
/// Also reused by the External-fund deposit poll and by Task 4's sweep.
pub fn read_balance_fri(chain: &Chain, address: &str) -> Result<u128> {
    let out = chain.call(STRK_TOKEN, "balance_of", &[address.to_string()])?;
    Ok(u128::from_str_radix(
        out.first().context("balance_of shape")?.trim_start_matches("0x"),
        16,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_orders_five_steps_and_roundtrips() {
        let dir = std::env::temp_dir().join(format!("zkmsg-setup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut s = SetupState::new_plan("carol".into(), "carol".into(),
            "zkmsg-carol".into(), 60, "funded-deployer".into());
        assert_eq!(s.steps.len(), 5);
        assert!(matches!(s.steps[0].kind, SetupStepKind::CreateAccount));
        assert!(matches!(s.steps[4].kind, SetupStepKind::Register));
        assert_eq!(s.next_pending(), Some(0));
        s.mark_done(0, None, Some("0xabc".into()));
        s.address = Some("0xabc".into());
        s.save(&dir).unwrap();
        let loaded = SetupState::load(&dir).unwrap();
        assert_eq!(loaded.next_pending(), Some(1));
        assert_eq!(loaded.address.as_deref(), Some("0xabc"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn strk_to_fri_is_wei_scale() {
        assert_eq!(strk_to_fri_hex(60), format!("{:#x}", 60u128 * 1_000_000_000_000_000_000));
        assert_eq!(strk_to_fri_hex(0), "0x0");
    }

    #[test]
    fn setup_state_serde_defaults_fund_mode_to_transfer() {
        // A carol-era setup.json: no fund_mode field. Must load as Transfer.
        let carol_era = r#"{
            "profile_name": "carol", "handle": "carol",
            "account_name": "zkmsg-carol", "fund_strk": 60,
            "source_account": "funded-deployer", "address": null,
            "steps": [
                {"kind": "CreateAccount", "done": false, "tx_hash": null, "note": null},
                {"kind": "Fund", "done": false, "tx_hash": null, "note": null},
                {"kind": "Deploy", "done": false, "tx_hash": null, "note": null},
                {"kind": "Init", "done": false, "tx_hash": null, "note": null},
                {"kind": "Register", "done": false, "tx_hash": null, "note": null}
            ]
        }"#;
        let s: SetupState = serde_json::from_str(carol_era).unwrap();
        assert_eq!(s.fund_mode, FundMode::Transfer);
        // And it round-trips with the field present.
        let json = serde_json::to_string(&s).unwrap();
        let s2: SetupState = serde_json::from_str(&json).unwrap();
        assert_eq!(s2.fund_mode, FundMode::Transfer);
    }

    #[test]
    fn new_plan_is_transfer_mode() {
        let s = SetupState::new_plan("x".into(), "x".into(), "zkmsg-x".into(), 60, "src".into());
        assert_eq!(s.fund_mode, FundMode::Transfer);
    }

    #[test]
    fn fund_needed_respects_balance_coverage() {
        let one = 1_000_000_000_000_000_000u128;
        // under target -> still needs funding
        assert!(fund_needed(59 * one, 60));
        assert!(fund_needed(0, 60));
        assert!(fund_needed(60 * one - 1, 60));
        // exact boundary -> covered, no transfer
        assert!(!fund_needed(60 * one, 60));
        // over target -> covered
        assert!(!fund_needed(61 * one, 60));
    }
}
