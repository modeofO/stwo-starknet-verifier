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
    #[serde(default)]
    pub burner: bool,
    #[serde(default)]
    pub reply_handle: Option<String>,
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
            burner: false,
            reply_handle: None,
            address: None,
            steps,
        }
    }

    /// A burner plan: external funding (the app never transfers), flagged
    /// so Init stamps the profile config. `source_account` is empty —
    /// External mode never signs with it (create/deploy are
    /// `--name`-addressed; Register pays from the new account itself).
    pub fn new_plan_external_burner(
        profile_name: String,
        handle: String,
        account_name: String,
        fund_strk: u64,
        reply_handle: Option<String>,
    ) -> Self {
        let mut s = Self::new_plan(profile_name, handle, account_name, fund_strk, String::new());
        s.fund_mode = FundMode::External;
        s.burner = true;
        s.reply_handle = reply_handle;
        s
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
        let note = if home.keys_path().exists() {
            Some("already initialized".into())
        } else {
            app::init_identity(&home, &state.account_name, None, self.repo_root)?;
            None
        };
        if state.burner {
            // Stamp burner metadata on the freshly written (or existing)
            // config — idempotent, local-only.
            let mut config = home.load_config()?;
            config.burner = true;
            config.reply_handle = state.reply_handle.clone();
            home.save_config(&config)?;
        }
        Ok((None, note))
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

/// Auto-identity for a burner: `burner-<6 lowercase hex>` from OS
/// randomness. Doubles as the registered handle (public on-chain
/// forever), so it must never derive from the user or the machine.
pub fn burner_name() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 3];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("burner-{}", hex::encode(bytes))
}

/// Static fallback when the live gas-price read fails.
pub const FALLBACK_FUNDING_STRK: u64 = 80;

/// Expected ACTUAL l2 gas spent before phase 2 submits: one stage tx
/// (~28M measured) + phase 1 (~865M measured, max 873.8M) + publish
/// (~3.3M), rounded up per leg.
const ACTUAL_L2_BEFORE_PHASE2: u128 = 935_000_000;
/// create + deploy + register fees, generously (measured 0.35 STRK total).
const FLAT_SETUP_FRI: u128 = 1_000_000_000_000_000_000;
const FRI_PER_STRK: u128 = 1_000_000_000_000_000_000;

/// Recommended funding for one send from a fresh account, in whole STRK,
/// from live (l1, l2, l1_data) gas prices in fri.
///
/// The binding constraint is sequential worst-case-bounds validation
/// (carol's 2026-07-08 stall): after phase 1's ACTUAL fee lands, the
/// account must still hold phase 2's BOUNDS PRODUCT (amounts x 1.5x
/// prices, mirroring `pipeline::bounds_for`). +10% margin, ceil.
pub fn recommended_funding_strk(prices: (u128, u128, u128)) -> u64 {
    let (l1_price, l2_price, l1_data_price) = prices;
    let actuals = ACTUAL_L2_BEFORE_PHASE2 * l2_price;
    let phase2_bound = 100 * (l1_price * 3 / 2)
        + crate::pipeline::L2_GAS_BOUND_PHASE2 as u128 * (l2_price * 3 / 2)
        + 32_768 * (l1_data_price * 3 / 2);
    let total_fri = actuals + phase2_bound + FLAT_SETUP_FRI;
    let with_margin = total_fri * 11 / 10;
    with_margin.div_ceil(FRI_PER_STRK) as u64
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
    fn recommended_funding_tracks_l2_price() {
        // Pure-l2 price points (l1/data zero to keep arithmetic exact).
        // 20 Gfri: actuals 935M*20e9 = 1.87e19 fri; phase2 bound 1e9*30e9 = 3.0e19;
        // + 1 STRK flat = 4.97e19; *1.1 = 5.467e19 -> ceil 55 STRK.
        assert_eq!(recommended_funding_strk((0, 20_000_000_000, 0)), 55);
        // carol's spike, 43.9 Gfri: 4.10465e19 + 6.585e19 + 0.1e19 = 10.78965e19;
        // *1.1 = 11.868615e19 -> ceil 119 STRK.
        assert_eq!(recommended_funding_strk((0, 43_900_000_000, 0)), 119);
        // Monotonic in l2 price.
        assert!(
            recommended_funding_strk((0, 50_000_000_000, 0))
                > recommended_funding_strk((0, 20_000_000_000, 0))
        );
        // Zero prices still demand the flat fee floor (deploy+register+margin).
        assert!(recommended_funding_strk((0, 0, 0)) >= 2);
    }

    #[test]
    fn burner_name_shape() {
        let a = burner_name();
        let b = burner_name();
        assert!(a.starts_with("burner-"));
        let hexpart = &a["burner-".len()..];
        assert_eq!(hexpart.len(), 6);
        assert!(hexpart.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_ne!(a, b); // 2^24 space — collision here means broken randomness
        // Registered-handle legal (short_string_felt: ASCII, <= 31 chars).
        assert!(a.is_ascii() && a.len() <= 31);
    }

    #[test]
    fn burner_plan_is_external_and_flagged() {
        let s = SetupState::new_plan_external_burner(
            "burner-ab12cd".into(), "burner-ab12cd".into(),
            "zkmsg-burner-ab12cd".into(), 80, Some("alice".into()),
        );
        assert_eq!(s.fund_mode, FundMode::External);
        assert!(s.burner);
        assert_eq!(s.reply_handle.as_deref(), Some("alice"));
        assert!(s.source_account.is_empty());
        assert_eq!(s.steps.len(), 5);
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
