# zkmsg Burner Accounts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Externally-funded throwaway sender profiles (burners) on top of the shipped identity wizard: auto-named, park-at-Fund until an external deposit lands, live-price funding targets, an encrypted from-line for replies, and a sweep+archive retirement path — plus the deferred profile-UX minors.

**Architecture:** `zkmsg_core::setup` gains a `FundMode` (Transfer/External) and parks the runner at an unfunded external Fund step; `core::config` gains serde-defaulted burner metadata; sweep lives in `core::app`, archive in `core::profiles`. The GUI extends the wizard (burner mode + waiting card), compose (from-line), inbox (sender chip), and adds a retire dialog. No protocol change; CLI flags and stdout untouched.

**Tech Stack:** Existing deps only (Rust, egui/eframe 0.29, `std::thread` + `mpsc`, sncast 0.61 subprocesses, ureq, rand, hex). No new crates.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-08-zkmsg-burners-design.md`.
- **CLI parity:** no CLI flag or output line changes. All new `config.json`/`setup.json` fields are `#[serde(default)]` so every existing file loads unchanged.
- **Threading rule is absolute:** never block the egui UI thread on RPC/subprocess — worker threads + `mpsc` + `ctx.request_repaint()`, no async runtime.
- **Keys are irreplaceable:** archive uses `fs::rename` only; never copy, delete, or overwrite `keys.json`. Collisions abort before any move (symlink-safe, like `execute_migration`).
- **The `work_in_flight()` lock lattice is symmetric and must stay so:** every paid entry point (send, wizard spend segment, register, sweep) blocks every other, both directions. A parked (awaiting-deposit) wizard holds NO lock.
- **Wizard completion is keyed on the `Completed` event (`flow.completed`), never on `Done(Ok)`** — a parked runner returns `Ok(())` with Fund still pending.
- Burner handles/names come from OS randomness, never derived from the user or machine.
- macOS/Apple Silicon native. Build/test from `tools/zkmsg/` (pure cargo; scarb irrelevant).
- Baseline suites that must stay green: zkmsg-core 39, zkmsg-gui 5, zkmsg CLI 1. Commit per task.
- Real STRK moves only in Task 9 (user-driven acceptance, explicit go-ahead required).

---

### Task 1: `core::setup` — `FundMode` + external-fund park (`AwaitingDeposit`)

**Files:**
- Modify: `tools/zkmsg/core/src/setup.rs`

**Interfaces:**
- Consumes: existing `read_balance_fri`, `fund_needed`, `SetupRunner`, `SetupState`.
- Produces:
  - `pub enum FundMode { Transfer, External }` (derive `Debug, Clone, PartialEq, Serialize, Deserialize, Default`; `#[default] Transfer`)
  - `SetupState` gains `#[serde(default)] pub fund_mode: FundMode` (`new_plan` keeps its signature; it produces `Transfer`)
  - `SetupEvent::AwaitingDeposit { address: String, target_strk: u64, balance_fri: u128 }`
  - `read_balance_fri` becomes `pub fn read_balance_fri(chain: &Chain, address: &str) -> Result<u128>` (Task 4's sweep reuses it)
  - Runner semantics: External Fund with insufficient balance emits `AwaitingDeposit` and returns `Ok(())` with Fund still pending (**park**); `Completed` is emitted only when every step is done.

- [ ] **Step 1: Write the failing tests** (append to `setup.rs` tests):

```rust
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
```

- [ ] **Step 2: Run tests, expect FAIL**

Run: `cd tools/zkmsg && cargo test -p zkmsg-core setup`
Expected: compile FAIL (`FundMode` undefined).

- [ ] **Step 3: Implement.**

Add above `SetupState`:

```rust
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
```

`SetupState` gains the field (place after `source_account`):

```rust
    #[serde(default)]
    pub fund_mode: FundMode,
```

and `new_plan` initializes `fund_mode: FundMode::Transfer`.

Add the event variant:

```rust
    /// External fund mode only: the runner parked because the new address
    /// does not yet hold the target. Emitted INSTEAD of executing Fund;
    /// the run returns Ok(()) with Fund still pending.
    AwaitingDeposit { address: String, target_strk: u64, balance_fri: u128 },
```

Parking: introduce a step-result enum so `run` can stop without marking done:

```rust
enum StepOutcome {
    Done(Option<String>, Option<String>),
    /// External Fund, deposit not yet arrived: stop the run, keep pending.
    Park,
}
```

`execute` returns `Result<StepOutcome>`; every existing arm wraps its
`(tx, note)` in `StepOutcome::Done`. `run` becomes:

```rust
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
```

`step_fund` branches on mode (the Transfer arm is today's body verbatim,
wrapped in `StepOutcome::Done`):

```rust
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
```

(The Transfer arm is today's `step_fund` body with the return values
wrapped in `StepOutcome::Done` — including the existing resume-guard
comment block, kept verbatim.)

Make `read_balance_fri` `pub` and update its doc comment to note the sweep
(Task 4) also uses it.

- [ ] **Step 4: Run tests, expect PASS**

Run: `cd tools/zkmsg && cargo test -p zkmsg-core && cargo test`
Expected: core 41 green (39 + 2), gui 5, cli 1 — the GUI compiles unchanged
(new event variant is additive; `setup_flow.rs` has a match on `SetupEvent`
— add a no-op `SetupEvent::AwaitingDeposit { .. } => {}` arm there in this
task to keep it compiling; Task 5 replaces it with the real handling).

- [ ] **Step 5: Commit**

```bash
cd /Users/modeofo/Apps/stwo-starknet-verifier
git add tools/zkmsg/core/src/setup.rs tools/zkmsg/gui/src/setup_flow.rs
git commit -m "zkmsg burners task 1: FundMode::External parks the setup runner at an unfunded Fund (AwaitingDeposit event, no lock, no error)"
```

### Task 2: live-price funding recommendation

**Files:**
- Modify: `tools/zkmsg/core/src/pipeline.rs` (promote gas numbers to pub consts)
- Modify: `tools/zkmsg/core/src/setup.rs` (the recommendation fn)

**Interfaces:**
- Consumes: `Chain::gas_prices()` (callers fetch prices; the fn itself is pure).
- Produces:
  - `pipeline.rs`: `pub const L2_GAS_BOUND_PHASE2: u64 = 1_000_000_000;` (extracted from `bounds_for`, which now uses it — single definition)
  - `setup.rs`: `pub fn recommended_funding_strk(prices: (u128, u128, u128)) -> u64` and `pub const FALLBACK_FUNDING_STRK: u64 = 80;`

- [ ] **Step 1: Write the failing tests** (append to `setup.rs` tests):

```rust
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
```

- [ ] **Step 2: Run, expect FAIL** (`cargo test -p zkmsg-core recommended`), then implement.

In `pipeline.rs`, extract the phase-2 bound (keep `bounds_for`'s other
numbers inline — only phase 2's is consumed elsewhere):

```rust
/// Phase-2 l2-gas bound (measured 815.7M + margin). Public because the
/// wizard's funding recommendation prices the same worst case.
pub const L2_GAS_BOUND_PHASE2: u64 = 1_000_000_000;
```

and use it in `bounds_for`'s `StepKind::Phase2` arm.

In `setup.rs`:

```rust
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
```

- [ ] **Step 3: Run tests, expect PASS**

Run: `cd tools/zkmsg && cargo test`
Expected: core 42 green (41 + 1 test fn), gui 5, cli 1.

- [ ] **Step 4: Commit**

```bash
git add tools/zkmsg/core
git commit -m "zkmsg burners task 2: recommended_funding_strk — live-price funding target (actual-phase1 + phase2 bounds product + margin), replacing the flat-60 era"
```

### Task 3: burner metadata + auto-naming + the burner plan constructor

**Files:**
- Modify: `tools/zkmsg/core/src/config.rs` (burner fields on `Config`)
- Modify: `tools/zkmsg/core/src/setup.rs` (`burner_name`, burner fields on `SetupState`, `new_plan_external_burner`, Init-step patch)

**Interfaces:**
- Consumes: `FundMode` (Task 1).
- Produces:
  - `Config` gains `#[serde(default)] pub burner: bool` and `#[serde(default)] pub reply_handle: Option<String>` (both local-only; the CLI never branches on them)
  - `setup::burner_name() -> String` — `burner-<6 lowercase hex>` from OS randomness
  - `SetupState` gains `#[serde(default)] pub burner: bool`, `#[serde(default)] pub reply_handle: Option<String>`
  - `SetupState::new_plan_external_burner(profile_name: String, handle: String, account_name: String, fund_strk: u64, reply_handle: Option<String>) -> Self` — `fund_mode: External`, `burner: true`, `source_account: String::new()` (unused in External mode: `account create`/`deploy` are `--name`-addressed, Register pays from the NEW account)
  - Init step: when `state.burner`, after `init_identity` (or its already-initialized branch) the profile's config is patched with `burner = true` + `reply_handle` (idempotent)

- [ ] **Step 1: Write the failing tests.**

In `config.rs` tests:

```rust
#[test]
fn config_serde_defaults_burner_fields() {
    // A pre-burner config.json (alice/bob/carol era): no burner fields.
    let old = r#"{
        "rpc_url": "https://x", "account": "funded-deployer",
        "registry": "0x1", "store": "0x2",
        "bridge_bin": "/b", "circuit_executable": "/c"
    }"#;
    let c: Config = serde_json::from_str(old).unwrap();
    assert!(!c.burner);
    assert!(c.reply_handle.is_none());
}
```

In `setup.rs` tests:

```rust
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
```

- [ ] **Step 2: Run, expect FAIL**, then implement.

`config.rs` — after `circuit_executable`:

```rust
    /// This profile is a throwaway sender created by the burner wizard.
    /// Local-only; nothing on-chain marks a burner.
    #[serde(default)]
    pub burner: bool,
    /// The creating profile's registered handle, for the compose
    /// from-line. Local-only.
    #[serde(default)]
    pub reply_handle: Option<String>,
```

`default_sepolia` initializes `burner: false, reply_handle: None`.

`setup.rs`:

```rust
/// Auto-identity for a burner: `burner-<6 lowercase hex>` from OS
/// randomness. Doubles as the registered handle (public on-chain
/// forever), so it must never derive from the user or the machine.
pub fn burner_name() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 3];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("burner-{}", hex::encode(bytes))
}
```

`SetupState` fields (after `fund_mode`):

```rust
    #[serde(default)]
    pub burner: bool,
    #[serde(default)]
    pub reply_handle: Option<String>,
```

(`new_plan` initializes both to `false`/`None`.) Constructor:

```rust
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
```

`step_init` patches the config in BOTH branches (fresh init and
already-initialized), idempotently:

```rust
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
```

(Keep the `Result<(Option<String>, Option<String>)>` return; the Task-1
`execute` wraps it in `StepOutcome::Done` — adjust the call site to match
whichever shape Task 1 landed.)

- [ ] **Step 3: Run tests, expect PASS**

Run: `cd tools/zkmsg && cargo test`
Expected: core 45 green, gui 5, cli 1.

- [ ] **Step 4: Commit**

```bash
git add tools/zkmsg/core
git commit -m "zkmsg burners task 3: burner metadata (config + setup state, serde-defaulted), OS-random burner names, external-burner plan constructor"
```

### Task 4: sweep (`core::app`) + archive (`core::profiles`)

**Files:**
- Modify: `tools/zkmsg/core/src/app.rs` (sweep)
- Modify: `tools/zkmsg/core/src/profiles.rs` (archive)

**Interfaces:**
- Consumes: `setup::read_balance_fri` (Task 1), `chain::account_address`, `STRK_TOKEN`.
- Produces:
  - `app.rs`: `pub const SWEEP_HEADROOM_FRI: u128 = 200_000_000_000_000_000;` (0.2 STRK retained for the transfer fee), `pub fn sweep_amount_fri(balance_fri: u128, headroom_fri: u128) -> Option<u128>`, `pub fn sweep_strk(config: &Config, to_address: &str) -> Result<(String, u128)>` (returns tx hash + swept fri; invoke + wait_receipt — worker-thread only)
  - `profiles.rs`: `pub const ARCHIVE_DIR: &str = "archive";`, `pub fn archive_profile(root: &Path, name: &str) -> Result<PathBuf>` (rename-only, symlink-safe collision refuse; returns the new path)

- [ ] **Step 1: Write the failing tests.**

`app.rs` tests:

```rust
#[test]
fn sweep_amount_leaves_headroom() {
    let one = 1_000_000_000_000_000_000u128;
    assert_eq!(sweep_amount_fri(10 * one, one / 5), Some(10 * one - one / 5));
    assert_eq!(sweep_amount_fri(one / 5, one / 5), None); // exactly headroom: nothing to sweep
    assert_eq!(sweep_amount_fri(0, one / 5), None);
}
```

`profiles.rs` tests (reuse the `tmp`/`mk_profile` helpers):

```rust
#[test]
fn archive_moves_profile_out_of_picker_keys_intact() {
    let root = tmp("archive");
    mk_profile(&root.join(".zkmsg-burner-aa11bb"), Some("burner-aa11bb"));
    assert_eq!(list_profiles(&root).unwrap().len(), 1);
    let to = archive_profile(&root, "burner-aa11bb").unwrap();
    // Gone from the picker, present (renamed, keys intact) under archive/.
    assert!(list_profiles(&root).unwrap().is_empty());
    assert_eq!(to, root.join("archive/.zkmsg-burner-aa11bb"));
    assert!(to.join("keys.json").exists());
    assert!(to.join("config.json").exists());
    // Archiving a missing profile errors.
    assert!(archive_profile(&root, "burner-aa11bb").is_err());
    // A collision in archive/ refuses and leaves the source untouched.
    mk_profile(&root.join(".zkmsg-burner-aa11bb"), Some("again"));
    assert!(archive_profile(&root, "burner-aa11bb").is_err());
    assert!(root.join(".zkmsg-burner-aa11bb/keys.json").exists());
    fs::remove_dir_all(&root).unwrap();
}
```

- [ ] **Step 2: Run, expect FAIL**, then implement.

`app.rs` (near `account_balance_strk`):

```rust
/// Fri retained on a swept account to cover the transfer's own fee
/// (measured transfers cost ~0.05 STRK; 0.2 is generous, and the dust
/// left behind is the price of never under-providing the fee).
pub const SWEEP_HEADROOM_FRI: u128 = 200_000_000_000_000_000;

/// How much a sweep can move: balance minus headroom, `None` when the
/// balance doesn't exceed the headroom (nothing worth sweeping).
pub fn sweep_amount_fri(balance_fri: u128, headroom_fri: u128) -> Option<u128> {
    (balance_fri > headroom_fri).then(|| balance_fri - headroom_fri)
}

/// Sweeps (balance - headroom) STRK from `config.account` (the burner)
/// to `to_address`, waiting for the receipt. Returns (tx_hash, swept
/// fri). Blocking (invoke + receipt wait) — worker threads only.
///
/// The caller's UI must have shown the linking warning: this transfer
/// is a public on-chain edge from the burner to the target.
pub fn sweep_strk(config: &Config, to_address: &str) -> Result<(String, u128)> {
    let chain = Chain::new(&config.rpc_url, &config.account);
    let own_address = account_address(&config.account)?;
    let balance = crate::setup::read_balance_fri(&chain, &own_address)?;
    let amount = sweep_amount_fri(balance, SWEEP_HEADROOM_FRI)
        .with_context(|| format!("balance {balance} fri does not exceed the fee headroom"))?;
    let tx = chain.invoke(
        STRK_TOKEN,
        "transfer",
        &[to_address.to_string(), format!("{amount:#x}"), "0x0".into()],
        &Default::default(),
    )?;
    chain.wait_receipt(&tx, std::time::Duration::from_secs(600))?;
    Ok((tx, amount))
}
```

`profiles.rs`:

```rust
/// Retired (archived) profiles live under `root/archive/` — invisible to
/// `list_profiles` (which only matches `.zkmsg-*` direct children) but
/// fully intact: moving the dir back restores the profile, keys and all.
pub const ARCHIVE_DIR: &str = "archive";

/// Archives `root/.zkmsg-<name>` to `root/archive/.zkmsg-<name>` by
/// rename only — never copy, never delete; keys are irreplaceable. A
/// collision (even a dangling symlink) refuses before any move.
pub fn archive_profile(root: &Path, name: &str) -> Result<PathBuf> {
    let from = root.join(format!("{PROFILE_PREFIX}{name}"));
    ensure!(from.is_dir(), "no profile dir at {}", from.display());
    let to = root.join(ARCHIVE_DIR).join(format!("{PROFILE_PREFIX}{name}"));
    ensure!(
        to.symlink_metadata().is_err(),
        "archive target {} already exists — refusing to overwrite",
        to.display()
    );
    fs::create_dir_all(root.join(ARCHIVE_DIR))?;
    fs::rename(&from, &to)
        .with_context(|| format!("archiving {} -> {}", from.display(), to.display()))?;
    Ok(to)
}
```

- [ ] **Step 3: Run tests, expect PASS**

Run: `cd tools/zkmsg && cargo test`
Expected: core 48 green, gui 5, cli 1.

- [ ] **Step 4: Commit**

```bash
git add tools/zkmsg/core
git commit -m "zkmsg burners task 4: sweep_strk (headroom-preserving burner drain) + archive_profile (rename-only retirement under root/archive)"
```

### Task 5: wizard burner mode — waiting card, live funding default, picker entries

**Files:**
- Modify: `tools/zkmsg/gui/src/setup_flow.rs` (AwaitingDeposit reducer state)
- Modify: `tools/zkmsg/gui/src/wizard_view.rs` (burner mode, waiting card, confirm bypass, live default)
- Modify: `tools/zkmsg/gui/src/worker.rs` (`spawn_recommend`)
- Modify: `tools/zkmsg/gui/src/app.rs` (picker "New burner…", awaiting-funding labels)

**Interfaces:**
- Consumes: `setup::{FundMode, burner_name, recommended_funding_strk, FALLBACK_FUNDING_STRK, SetupState::new_plan_external_burner}`, `SetupEvent::AwaitingDeposit`.
- Produces:
  - `setup_flow.rs`: `pub struct AwaitingView { pub address: String, pub target_strk: u64, pub balance_fri: u128 }`; `SetupFlow` gains `pub awaiting: Option<AwaitingView>` (set by `AwaitingDeposit`, cleared by any `StepStarted`)
  - `wizard_view.rs`: `WizardUi::new_burner(reply_handle: Option<String>) -> Self`; `WizardCtx` unchanged
  - `worker.rs`: `pub enum RecommendMsg { Recommended(u64) }`, `pub fn spawn_recommend(rpc_url: String, ctx: egui::Context) -> Receiver<RecommendMsg>`
  - `app.rs`: `PickerAction::NewBurner`; incomplete external-Fund entries label "(awaiting funding)"

- [ ] **Step 1: Failing reducer tests** (`setup_flow.rs`):

```rust
#[test]
fn awaiting_deposit_parks_fund_row() {
    let mut f = SetupFlow {
        steps: vec![
            SetupStepView { kind: K::CreateAccount, status: StepStatus::Done, tx_hash: None },
            SetupStepView { kind: K::Fund, status: StepStatus::Pending, tx_hash: None },
        ],
        error: None,
        completed: false,
        awaiting: None,
    };
    f.apply(E::StepStarted { index: 1, total: 2, kind: K::Fund });
    assert!(matches!(f.steps[1].status, StepStatus::Running));
    f.apply(E::AwaitingDeposit {
        address: "0xburner".into(), target_strk: 80, balance_fri: 5,
    });
    // Parked: Fund back to Pending (not Failed — nothing went wrong),
    // and the waiting info is exposed for the card.
    assert!(matches!(f.steps[1].status, StepStatus::Pending));
    let a = f.awaiting.as_ref().unwrap();
    assert_eq!((a.address.as_str(), a.target_strk, a.balance_fri), ("0xburner", 80, 5));
    // A re-run (Refresh) clears the card the moment any step starts.
    f.apply(E::StepStarted { index: 1, total: 2, kind: K::Fund });
    assert!(f.awaiting.is_none());
}
```

(Existing two reducer tests gain `awaiting: None` in their literals.)

- [ ] **Step 2: Run `cargo test -p zkmsg-gui setup_flow`, expect FAIL, implement.**

`SetupFlow` gains the field (`from_state` sets `awaiting: None`); `apply`:

```rust
            SetupEvent::StepStarted { kind, .. } => {
                self.awaiting = None;
                if let Some(step) = self.find_pending_mut(&kind) {
                    step.status = StepStatus::Running;
                }
            }
            ...
            SetupEvent::AwaitingDeposit { address, target_strk, balance_fri } => {
                // Park: the runner returned without executing Fund. Not a
                // failure — revert the row to Pending and expose the info.
                if let Some(step) = self.find_pending_mut(&SetupStepKind::Fund) {
                    step.status = StepStatus::Pending;
                }
                self.awaiting = Some(AwaitingView { address, target_strk, balance_fri });
            }
```

Run: `cargo test -p zkmsg-gui`, expect the new test PASS (gui 6).

- [ ] **Step 3: Worker + wizard changes** (no unit tests — UI wiring; build gate below).

`worker.rs`:

```rust
pub enum RecommendMsg {
    Recommended(u64),
}

/// One-shot: live gas prices -> recommended funding, static fallback on
/// any read failure. Read-only RPC.
pub fn spawn_recommend(rpc_url: String, ctx: egui::Context) -> Receiver<RecommendMsg> {
    let (tx, rx) = channel();
    thread::spawn(move || {
        let chain = Chain::new(&rpc_url, "");
        let strk = chain
            .gas_prices()
            .map(zkmsg_core::setup::recommended_funding_strk)
            .unwrap_or(zkmsg_core::setup::FALLBACK_FUNDING_STRK);
        let _ = tx.send(RecommendMsg::Recommended(strk));
        ctx.request_repaint();
    });
    rx
}
```

`wizard_view.rs` — new fields on `WizardUi`:

```rust
    /// Burner mode: auto-named, external funding, stamps burner metadata.
    burner: bool,
    /// The creating profile's handle, recorded for the compose from-line.
    reply_handle: Option<String>,
    /// External resume: loaded state's fund mode (a resumed Transfer
    /// wizard still re-arms the confirm; External never needs it once the
    /// dir exists — nothing transfers).
    fund_mode: zkmsg_core::setup::FundMode,
    fund_touched: bool,
    recommend_rx: Option<std::sync::mpsc::Receiver<worker::RecommendMsg>>,
    recommend_fetched: bool,
```

Constructors: `new_profile()` sets `burner: false, reply_handle: None,
fund_mode: FundMode::Transfer, fund_touched: false, recommend_rx: None,
recommend_fetched: false` and `fund_strk: String::new()` (the flat "60"
dies here — the live estimate fills it). New:

```rust
    /// A burner form: auto-generated identity, external funding. The name
    /// stays editable but arrives filled so the default path is zero
    /// typing.
    pub fn new_burner(reply_handle: Option<String>) -> Self {
        let name = zkmsg_core::setup::burner_name();
        let mut w = Self::new_profile();
        w.handle = name.clone();
        w.account_name = format!("zkmsg-{name}");
        w.name = name;
        w.handle_touched = true;
        w.account_touched = true;
        w.burner = true;
        w.reply_handle = reply_handle;
        w.fund_mode = zkmsg_core::setup::FundMode::External;
        w
    }
```

`resume(dir)` additionally sets `burner: state.burner`,
`reply_handle: state.reply_handle.clone()`, `fund_mode: state.fund_mode.clone()`,
`fund_touched: true`, `recommend_fetched: true` (no estimate needed), and
`confirm_open: fund_pending && state.fund_mode == FundMode::Transfer` —
an external resume never re-arms the confirm (nothing transfers).

`update()` — first lines gain the estimate fetch (both modes):

```rust
        if !self.recommend_fetched && self.flow.is_none() {
            self.recommend_fetched = true;
            self.recommend_rx =
                Some(worker::spawn_recommend(wctx.rpc_url.to_string(), wctx.egui_ctx.clone()));
        }
        if let Some(rx) = &self.recommend_rx {
            if let Ok(worker::RecommendMsg::Recommended(strk)) = rx.try_recv() {
                self.recommend_rx = None;
                if !self.fund_touched {
                    self.fund_strk = strk.to_string();
                }
            }
        }
```

`render_form`: the fund row marks touch (`if ui.text_edit_singleline(&mut
self.fund_strk).changed() { self.fund_touched = true; }`), label becomes
`"deposit target (STRK)"` in burner mode / `"fund (STRK)"` otherwise, with
a weak-text `"(live estimate)"`/`"fetching live estimate…"` note beside it
while empty. Burner form heading: `"Create a burner"` and the source line
replaced by `"externally funded — nothing is transferred from your
profiles"`. Window title: `"New burner"` when `self.burner` (keep
`"New profile"` otherwise).

`render_confirm` burner text (replaces the transfer sentence when
`self.burner`):

```text
Create account '<account>'? Funding is external: the app will show a
deposit address and wait until it holds <n> STRK — nothing is
transferred from your profiles. Deploy and registering '<handle>' are
then paid by the burner itself. Fees ≈ under 1 STRK of the deposit.
```

`spawn`: when no checkpoint exists, build the plan with
`SetupState::new_plan_external_burner(name, handle, account, fund,
self.reply_handle.clone())` if `self.burner`, else `new_plan(...,
wctx.source_account.to_string())` as today. `resume_source` pinning stays
as-is (`state.source_account` — empty for burners; the confirm never
renders for a parked external resume, see `request_resume`).

`request_resume`:

```rust
    fn request_resume(&mut self, wctx: &WizardCtx) {
        // External mode never transfers, so a parked/failed external run
        // resumes without the spend confirm; Transfer mode keeps the gate
        // until Fund is checkpointed done.
        if self.fund_done() || self.fund_mode == zkmsg_core::setup::FundMode::External {
            self.spawn(wctx);
        } else {
            self.confirm_open = true;
        }
    }
```

`render_checklist`: when parked (`!self.running()` and
`flow.awaiting.is_some()` and `!flow.completed`), render the waiting card
INSTEAD of the plain Resume row:

```rust
        if let Some(a) = &flow.awaiting {
            ui.separator();
            ui.label("waiting for an external deposit:");
            ui.horizontal(|ui| {
                ui.monospace(&a.address);
                if ui.button("copy").clicked() {
                    ui.ctx().copy_text(a.address.clone());
                }
            });
            let balance_strk = a.balance_fri / 1_000_000_000_000_000_000;
            ui.label(format!(
                "target {} STRK — current balance ~{balance_strk} STRK",
                a.target_strk
            ));
            ui.label("fund it from outside your own accounts to keep the burner unlinkable");
            ui.horizontal(|ui| {
                if !wctx.session_busy && ui.button("Refresh").clicked() {
                    self.request_resume(wctx);
                }
                if ui.button("Close").clicked() {
                    outcome = WizardOutcome::Cancelled;
                }
            });
            return outcome;
        }
```

(Place it after the step rows, before the existing `if self.running()`
early-return — parked implies not running, so order the checks: running →
"working…"; awaiting → card; else → existing Resume/Close row.)

- [ ] **Step 4: Picker.** `app.rs`:

Add `NewBurner` to `PickerAction`. In `profile_picker`, after the
"New profile…" entry:

```rust
                    let newb = ui.add_enabled(
                        source_available,
                        egui::SelectableLabel::new(false, "New burner…"),
                    );
                    if newb.clicked() {
                        action = PickerAction::NewBurner;
                    }
                    if !source_available {
                        newb.on_hover_text(
                            "open a configured profile first — its RPC endpoint drives the setup \
                             (no funds are drawn from it)",
                        );
                    }
```

Incomplete entries: label from the checkpoint —

```rust
                        if entry.setup_incomplete {
                            let label = match zkmsg_core::setup::SetupState::load(&entry.dir) {
                                Ok(s) if s.fund_mode == zkmsg_core::setup::FundMode::External
                                    && s.steps.iter().any(|st| {
                                        matches!(st.kind, zkmsg_core::setup::SetupStepKind::Fund)
                                            && !st.done
                                    }) =>
                                    format!("{} (awaiting funding)", entry.name),
                                _ => format!("{} (setup incomplete)", entry.name),
                            };
                            ...existing add_enabled(SelectableLabel::new(false, label))...
                        }
```

Dispatch:

```rust
            PickerAction::NewBurner => {
                self.picker_error = None;
                let reply = self
                    .session
                    .as_ref()
                    .and_then(|s| s.keys.as_ref())
                    .and_then(|k| k.handle.clone());
                self.wizard = Some(WizardUi::new_burner(reply));
            }
```

- [ ] **Step 5: Build 0 warnings + full suite.**

Run: `cd tools/zkmsg && cargo build -p zkmsg-gui 2>&1 | grep -c "^warning" ; cargo test`
Expected: `0`; core 48 / gui 6 / cli 1 green.

- [ ] **Step 6: Commit**

```bash
git add tools/zkmsg/gui
git commit -m "zkmsg burners task 5: burner wizard mode — auto-identity, external-deposit waiting card (parked, lock-free), live funding default in both modes, picker New burner / awaiting-funding entries"
```

### Task 6: from-line — compose checkbox + inbox sender chip

**Files:**
- Create: `tools/zkmsg/gui/src/fromline.rs`
- Modify: `tools/zkmsg/gui/src/main.rs` (`mod fromline;`)
- Modify: `tools/zkmsg/gui/src/session.rs` (checkbox state)
- Modify: `tools/zkmsg/gui/src/compose_view.rs` (checkbox + prepend)
- Modify: `tools/zkmsg/gui/src/inbox_view.rs` (chip render)

**Interfaces:**
- Consumes: `Config::{burner, reply_handle}` (Task 3).
- Produces (`fromline.rs`):
  - `pub fn apply_from_line(text: &str, reply_handle: &str) -> String`
  - `pub fn split_from_line(text: &str) -> Option<(&str, &str)>` — `(handle, body)` when the first line is a well-formed `from: <handle>` (ASCII, 1–31 chars, no whitespace — the registered-handle shape), else `None`

- [ ] **Step 1: Write the failing tests** (`fromline.rs`):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_prepends_one_line() {
        assert_eq!(apply_from_line("hi bob", "alice"), "from: alice\nhi bob");
    }

    #[test]
    fn split_parses_only_wellformed_first_lines() {
        assert_eq!(split_from_line("from: alice\nhi"), Some(("alice", "hi")));
        // Round-trips apply.
        assert_eq!(
            split_from_line(&apply_from_line("hi", "burner-peer")),
            Some(("burner-peer", "hi"))
        );
        // Not a from-line: plain text, mid-text markers, empty handle,
        // over-long handle, embedded whitespace, no body separator.
        assert_eq!(split_from_line("hello from: alice"), None);
        assert_eq!(split_from_line("from: \nhi"), None);
        assert_eq!(split_from_line(&format!("from: {}\nhi", "x".repeat(32))), None);
        assert_eq!(split_from_line("from: two words\nhi"), None);
        assert_eq!(split_from_line("from: alice"), None); // no newline -> no body
        assert_eq!(split_from_line(""), None);
    }
}
```

- [ ] **Step 2: Run `cargo test -p zkmsg-gui fromline`, expect FAIL, implement:**

```rust
//! The from-line convention: an OPTIONAL first plaintext line
//! `from: <handle>` a burner sender may include so the recipient can
//! reply to the real identity. Rides inside AES-GCM — only the
//! recipient ever sees it. A convention, not a protocol: any client may
//! ignore it (the CLI prints it as ordinary text).

/// Prepends the from-line. Caller gates on the compose checkbox.
pub fn apply_from_line(text: &str, reply_handle: &str) -> String {
    format!("from: {reply_handle}\n{text}")
}

/// Parses a leading `from: <handle>` line into `(handle, body)`.
/// Handle must look like a registered handle: ASCII, 1-31 chars, no
/// whitespace. Anything else is ordinary text.
pub fn split_from_line(text: &str) -> Option<(&str, &str)> {
    let rest = text.strip_prefix("from: ")?;
    let (handle, body) = rest.split_once('\n')?;
    let ok = !handle.is_empty()
        && handle.len() <= 31
        && handle.is_ascii()
        && !handle.contains(char::is_whitespace);
    ok.then_some((handle, body))
}
```

Run: `cargo test -p zkmsg-gui`, expect PASS (gui 8).

- [ ] **Step 3: Wire compose.** `session.rs`: add field
`pub(crate) compose_reveal_from: bool` (init `true` in `new`).
`compose_view.rs` `render_compose_form`, after the message editor:

```rust
        if let Some(reply) = self.config.as_ref().filter(|c| c.burner).and_then(|c| c.reply_handle.clone()) {
            ui.checkbox(
                &mut self.compose_reveal_from,
                format!("reveal my handle ('{reply}') to the recipient (encrypted from-line)"),
            );
        }
```

`start_prepare`: compute the outgoing text —

```rust
        let text = match self
            .config
            .as_ref()
            .filter(|c| c.burner && self.compose_reveal_from)
            .and_then(|c| c.reply_handle.as_deref())
        {
            Some(reply) => crate::fromline::apply_from_line(&self.compose_text, reply),
            None => self.compose_text.clone(),
        };
```

and pass `text` to `spawn_prepare` instead of `self.compose_text.clone()`.

- [ ] **Step 4: Wire inbox.** `inbox_view.rs` message loop:

```rust
            for m in &self.inbox {
                ui.label(m.nonce.to_string());
                ui.label(&m.commitment[..m.commitment.len().min(18)]);
                match crate::fromline::split_from_line(&m.text) {
                    Some((handle, body)) => {
                        ui.vertical(|ui| {
                            ui.colored_label(
                                egui::Color32::from_rgb(120, 160, 220),
                                format!("from: {handle}"),
                            );
                            ui.label(body);
                        });
                    }
                    None => {
                        ui.label(&m.text);
                    }
                }
                ui.end_row();
            }
```

(CLI inbox output is untouched — parity holds by not changing the CLI.)

- [ ] **Step 5: Build 0 warnings + full suite; commit.**

Run: `cd tools/zkmsg && cargo build -p zkmsg-gui 2>&1 | grep -c "^warning" ; cargo test`
Expected: `0`; core 48 / gui 8 / cli 1.

```bash
git add tools/zkmsg/gui
git commit -m "zkmsg burners task 6: encrypted from-line — burner compose checkbox (default on), inbox sender chip; plaintext convention, CLI untouched"
```

### Task 7: retire dialog — sweep + archive

**Files:**
- Create: `tools/zkmsg/gui/src/retire_view.rs`
- Modify: `tools/zkmsg/gui/src/main.rs` (`mod retire_view;`)
- Modify: `tools/zkmsg/gui/src/worker.rs` (balance + sweep workers)
- Modify: `tools/zkmsg/gui/src/session.rs` (post-send offer flag)
- Modify: `tools/zkmsg/gui/src/compose_view.rs` (offer button)
- Modify: `tools/zkmsg/gui/src/app.rs` (own the dialog; picker archive entry; lock fold-in)

**Interfaces:**
- Consumes: `app::{sweep_strk, sweep_amount_fri, SWEEP_HEADROOM_FRI}`, `profiles::archive_profile`, `setup::read_balance_fri`, `chain::account_address`.
- Produces:
  - `worker.rs`: `pub enum RetireWorkerMsg { Balance(Result<u128, String>), Swept(Result<(String, u128), String>) }`, `pub fn spawn_retire_balance(home_dir: PathBuf, ctx: egui::Context) -> Receiver<RetireWorkerMsg>`, `pub fn spawn_sweep(home_dir: PathBuf, to_address: String, ctx: egui::Context) -> Receiver<RetireWorkerMsg>`
  - `retire_view.rs`: `pub struct RetireUi` with `pub fn new(profile_name: String, profile_dir: PathBuf, targets: Vec<(String, String)>) -> Self` (targets = `(profile name, account address)`), `pub fn sweeping(&self) -> bool`, `pub fn update(&mut self, ctx: &egui::Context, root: &Path) -> RetireOutcome`; `pub enum RetireOutcome { None, Cancelled, Archived { name: String } }`
  - `session.rs`: `pub(crate) retire_offer: bool` (set by the post-send button, drained by the app)
  - `app.rs`: `retire: Option<RetireUi>` field; `PickerAction::Retire(String, PathBuf)`

- [ ] **Step 1: Failing gate test** (`retire_view.rs`):

```rust
#[cfg(test)]
mod tests {
    use super::can_act;

    #[test]
    fn retire_actions_blocked_while_any_work_runs() {
        assert!(can_act(false, false));
        assert!(!can_act(true, false));  // app-level paid work in flight
        assert!(!can_act(false, true));  // own sweep in flight
        assert!(!can_act(true, true));
    }
}
```

- [ ] **Step 2: Run `cargo test -p zkmsg-gui retire`, expect FAIL, implement.**

`worker.rs`:

```rust
pub enum RetireWorkerMsg {
    Balance(Result<u128, String>),
    Swept(Result<(String, u128), String>),
}

/// Read-only: the burner profile's own account balance in fri.
pub fn spawn_retire_balance(home_dir: PathBuf, ctx: egui::Context) -> Receiver<RetireWorkerMsg> {
    let (tx, rx) = channel();
    thread::spawn(move || {
        let result = (|| {
            let config = Home::new(home_dir).load_config().map_err(|e| format!("{e:#}"))?;
            let chain = Chain::new(&config.rpc_url, &config.account);
            let address =
                zkmsg_core::chain::account_address(&config.account).map_err(|e| format!("{e:#}"))?;
            zkmsg_core::setup::read_balance_fri(&chain, &address).map_err(|e| format!("{e:#}"))
        })();
        let _ = tx.send(RetireWorkerMsg::Balance(result));
        ctx.request_repaint();
    });
    rx
}

/// Paid: sweep (balance - headroom) to `to_address` and wait the receipt.
pub fn spawn_sweep(
    home_dir: PathBuf,
    to_address: String,
    ctx: egui::Context,
) -> Receiver<RetireWorkerMsg> {
    let (tx, rx) = channel();
    thread::spawn(move || {
        let result = (|| {
            let config = Home::new(home_dir).load_config().map_err(|e| format!("{e:#}"))?;
            app::sweep_strk(&config, &to_address).map_err(|e| format!("{e:#}"))
        })();
        let _ = tx.send(RetireWorkerMsg::Swept(result));
        ctx.request_repaint();
    });
    rx
}
```

`retire_view.rs` core shape:

```rust
//! The burner retirement dialog: optional sweep (with the linking
//! warning shown verbatim) then archive-by-rename. Owned by ZkmsgApp
//! (it outlives the session it may close); all chain work runs on
//! worker threads.

use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;

use eframe::egui;

use zkmsg_core::app::{SWEEP_HEADROOM_FRI, sweep_amount_fri};
use zkmsg_core::profiles::archive_profile;

use crate::worker::{self, RetireWorkerMsg};

pub enum RetireOutcome {
    None,
    Cancelled,
    /// Archived (post-sweep or archive-only) — the app drops the session
    /// if it was this profile and rescans.
    Archived { name: String },
}

/// Whether a retire action (sweep or archive) may fire: nothing else
/// paid in flight app-wide, and no own sweep already running.
pub(crate) fn can_act(app_work_in_flight: bool, sweeping: bool) -> bool {
    !app_work_in_flight && !sweeping
}

pub struct RetireUi {
    profile_name: String,
    profile_dir: PathBuf,
    /// (profile name, account address) sweep targets — every OTHER
    /// complete profile whose account resolves.
    targets: Vec<(String, String)>,
    target_idx: usize,
    balance_fri: Option<u128>,
    rx: Option<Receiver<RetireWorkerMsg>>,
    sweeping: bool,
    swept_tx: Option<String>,
    error: Option<String>,
    /// App-level work_in_flight snapshot, fed per-frame by the app.
    pub app_busy: bool,
}
```

`new` initializes (`target_idx: 0`, `balance_fri: None`, `rx: None`,
`sweeping: false`, `swept_tx: None`, `error: None`, `app_busy: false`).
`sweeping()` returns `self.sweeping`. `update(ctx, root)`:

1. If `balance_fri.is_none() && rx.is_none()` → `rx =
   Some(worker::spawn_retire_balance(self.profile_dir.clone(), ctx.clone()))`.
2. Poll `rx.try_recv()`: `Balance(Ok(b))` → `balance_fri = Some(b)`, drop rx;
   `Balance(Err(e))` → `error = Some(e)`, `balance_fri = Some(0)` (archive-only
   still possible), drop rx; `Swept(Ok((tx, _)))` → `sweeping = false`,
   `swept_tx = Some(tx)`, drop rx, then immediately archive (step 3 path);
   `Swept(Err(e))` → `sweeping = false`, `error = Some(e)`, drop rx (retry
   possible).
3. Archive helper (used by both the post-sweep path and Archive only):
   `match archive_profile(root, &self.profile_name) { Ok(_) => return
   RetireOutcome::Archived { name: self.profile_name.clone() }, Err(e) =>
   self.error = Some(format!("{e:#}")) }`.
4. Render an `egui::Window::new(format!("Retire burner '{}'",
   self.profile_name))` (collapsible false, resizable false, centered):
   - balance line: `match self.balance_fri { None => "reading balance…",
     Some(b) => match sweep_amount_fri(b, SWEEP_HEADROOM_FRI) { Some(a) =>
     format!("sweepable: ~{} STRK (0.2 kept for the fee)", a / 10u128.pow(18)),
     None => "balance too low to sweep — archive only".into() } }`
   - the warning, verbatim, in orange:
     `"the sweep transfer is a public on-chain edge linking this burner to the target"`
   - target combo over `self.targets` labels (disabled if empty, with
     "no other profiles to sweep to");
   - `error` in red if set; `swept_tx` as a Voyager link if set;
   - buttons (all inside `ui.add_enabled_ui(can_act(self.app_busy, self.sweeping), ..)`):
     **Sweep & archive** (enabled only when a target exists and
     `sweep_amount_fri` is `Some`) → `self.sweeping = true; self.rx =
     Some(worker::spawn_sweep(self.profile_dir.clone(),
     self.targets[self.target_idx].1.clone(), ctx.clone()))`;
     **Archive only** → the archive helper directly;
     **Cancel** → `RetireOutcome::Cancelled` (disabled while sweeping —
     a paid tx is in flight; closing the dialog won't stop it).
   - while `self.sweeping`: spinner + "sweeping…" and `ctx.request_repaint()`.

- [ ] **Step 3: App wiring.** `app.rs`:

- Field `retire: Option<RetireUi>` (init `None`).
- `work_in_flight()` gains `|| self.retire.as_ref().is_some_and(|r| r.sweeping())`.
- `PickerAction` gains `Retire(String, PathBuf)`. In the picker loop, for
  complete entries whose config is a burner, render the row as a
  horizontal: the existing selectable label plus a small `"retire…"`
  button:

```rust
                        let is_burner = Home::new(entry.dir.clone())
                            .load_config()
                            .map(|c| c.burner)
                            .unwrap_or(false);
                        ui.horizontal(|ui| {
                            let selected = entry.name == active_name;
                            if ui.selectable_label(selected, picker_label(entry)).clicked()
                                && !selected
                            {
                                action = PickerAction::Switch(entry.name.clone(), entry.dir.clone());
                            }
                            if is_burner && ui.small_button("retire…").clicked() {
                                action = PickerAction::Retire(entry.name.clone(), entry.dir.clone());
                            }
                        });
```

  where `picker_label(entry)` is the Task-8 name-with-handle helper (until
  Task 8 lands, `&entry.name` inline is fine — Task 8 replaces it).
- Target construction, shared by both open paths (a method on `ZkmsgApp`):

```rust
    /// Sweep targets for retiring `exclude`: every other complete profile
    /// whose config + account address resolve. The retiring burner's
    /// `reply_handle` profile (its creator) sorts first, so it is the
    /// default selection — spec: "default: the profile named by
    /// reply_handle, else first non-burner".
    fn retire_targets(&self, exclude: &str, exclude_dir: &Path) -> Vec<(String, String)> {
        let reply = Home::new(exclude_dir.to_path_buf())
            .load_config()
            .ok()
            .and_then(|c| c.reply_handle);
        let mut targets: Vec<(String, String)> = self
            .profiles
            .iter()
            .filter(|p| !p.setup_incomplete && p.name != exclude)
            .filter_map(|p| {
                let config = Home::new(p.dir.clone()).load_config().ok()?;
                let address = zkmsg_core::chain::account_address(&config.account).ok()?;
                Some((p.name.clone(), address))
            })
            .collect();
        // Creator first (matched by profile name OR cached handle), then
        // non-burners before burners, then name order (list is name-sorted
        // already, and the sort is stable).
        targets.sort_by_key(|(name, _)| {
            let is_reply = reply.as_deref() == Some(name.as_str())
                || self.profiles.iter().any(|p| {
                    p.name == *name && p.handle.as_deref() == reply.as_deref() && reply.is_some()
                });
            let is_burner = Home::new(
                self.profiles.iter().find(|p| p.name == *name).map(|p| p.dir.clone()).unwrap_or_default(),
            )
            .load_config()
            .map(|c| c.burner)
            .unwrap_or(false);
            (!is_reply, is_burner)
        });
        targets
    }
```

- Dispatch:

```rust
            PickerAction::Retire(name, dir) => {
                self.picker_error = None;
                let targets = self.retire_targets(&name, &dir);
                self.retire = Some(RetireUi::new(name, dir, targets));
            }
```

- Post-send offer: `session.rs` gains `pub(crate) retire_offer: bool`
  (init `false`); `compose_view.rs` `render_send_progress`, next to
  "Compose another":

```rust
        if is_done
            && self.config.as_ref().is_some_and(|c| c.burner)
            && ui.button("Sweep & archive this burner…").clicked()
        {
            self.retire_offer = true;
        }
```

  `app.rs` `update`, after the central panel (before the wizard drive):

```rust
        if self
            .session
            .as_ref()
            .is_some_and(|s| s.retire_offer)
        {
            if let Some(s) = &mut self.session {
                s.retire_offer = false;
            }
            if self.retire.is_none() && self.root.is_some() {
                let (name, dir) = {
                    let s = self.session.as_ref().unwrap();
                    (s.name.clone(), s.home_dir())
                };
                let targets = self.retire_targets(&name, &dir);
                self.retire = Some(RetireUi::new(name, dir, targets));
            }
        }
```

- Drive the dialog (end of `update`, after the wizard):

```rust
        if let Some(mut retire) = self.retire.take() {
            retire.app_busy = app_busy;
            let Some(root) = self.root.clone() else {
                // No root (bare-profile launch) — retirement needs the
                // archive dir under a root; drop the dialog.
                self.retire = None;
                return;
            };
            match retire.update(ctx, &root) {
                RetireOutcome::None => self.retire = Some(retire),
                RetireOutcome::Cancelled => {}
                RetireOutcome::Archived { name } => {
                    if self.session.as_ref().is_some_and(|s| s.name == name) {
                        // The archived profile was active: drop the session;
                        // the no-session picker panel renders (a dangling
                        // `current` already falls back to the picker on
                        // relaunch — same behavior, live).
                        self.session = None;
                    }
                    self.profiles =
                        self.root.as_deref().map(list_profiles).and_then(Result::ok).unwrap_or_default();
                }
            }
        }
```

  Note `app_busy` here must be the value snapshotted BEFORE the retire
  dialog's own sweeping is folded in — pass the session+wizard part only
  (`self.session...work_in_flight() || wizard running`), or the dialog
  deadlocks itself. Compute one `paid_elsewhere` bool before the take.

- [ ] **Step 4: Build 0 warnings + full suite; commit.**

Run: `cd tools/zkmsg && cargo build -p zkmsg-gui 2>&1 | grep -c "^warning" ; cargo test`
Expected: `0`; core 48 / gui 9 / cli 1.

```bash
git add tools/zkmsg/gui
git commit -m "zkmsg burners task 7: retire dialog — optional sweep (linking warning verbatim, locked into the paid-work lattice) then archive-by-rename; post-send offer + picker retire entry"
```

### Task 8: cleanup wave — the four deferred minors

**Files:**
- Modify: `tools/zkmsg/gui/src/app.rs`

**Interfaces:**
- Consumes: existing `ZkmsgApp` fields; `ProfileEntry.handle`.
- Produces: no new API — four behavior fixes.

- [ ] **Step 1: NotNow root restore.** `ZkmsgApp` gains a field
`classified_root: Option<PathBuf>` set in `new` inside the
`HomeKind::Root` arm (`classified_root = Some(r.clone())` alongside
`root = Some(r)`), `None` in the other arms. The `MigrateAction::NotNow`
arm becomes:

```rust
            MigrateAction::NotNow => {
                self.migration = None;
                // Restore what classification said, not blanket None: a
                // genuine Root that ALSO had a legacy sibling detected keeps
                // its picker; only a legacy-Profile launch (where migration
                // detection was the sole reason root was set) reverts to the
                // static label.
                self.root = self.classified_root.clone();
            }
```

- [ ] **Step 2: `--profile` surfaces instead of silently falling back.**
In `new`, the Root arm:

```rust
            HomeKind::Root { root: r, current } => {
                profiles = list_profiles(&r).unwrap_or_default();
                let (chosen, profile_error) = match &profile_override {
                    Some(n) => {
                        let dir = r.join(format!("{PROFILE_PREFIX}{n}"));
                        if dir.join("config.json").is_file() {
                            (Some(dir), None)
                        } else {
                            // Do NOT fall back to `current`: opening a
                            // different profile than the one asked for is
                            // worse than opening none.
                            (None, Some(format!("--profile {n}: no such profile under {}", r.display())))
                        }
                    }
                    None => (current, None),
                };
                root = Some(r);
                picker_error_init = profile_error;
                chosen.map(|dir| (dir_suffix_name(&dir), Home::new(dir)))
            }
```

with a `let mut picker_error_init = None;` before the match and
`picker_error: picker_error_init` in the struct literal. (No session opens;
the no-session panel shows the error + the profile buttons.)

- [ ] **Step 3: `picker_error` dismiss.** Both render sites (top-bar
`profile_picker` and the no-session central panel) become:

```rust
        let mut dismiss = false;
        if let Some(err) = &self.picker_error {
            ui.horizontal(|ui| {
                ui.colored_label(egui::Color32::RED, err.as_str());
                if ui.small_button("\u{2715}").clicked() {
                    dismiss = true;
                }
            });
        }
        if dismiss {
            self.picker_error = None;
        }
```

(In `profile_picker` this replaces the existing `colored_label` block; the
central-panel copy mirrors it.)

- [ ] **Step 4: handle display.** Add the helper and use it for complete
picker rows (the Task-7 row render already calls it):

```rust
/// Picker label: `name (handle)` when a registered handle differs from
/// the profile name — e.g. a renamed dir — else just the name.
fn picker_label(entry: &ProfileEntry) -> String {
    match &entry.handle {
        Some(h) if h != &entry.name => format!("{} ({h})", entry.name),
        _ => entry.name.clone(),
    }
}
```

Also use it in the no-session central panel's profile buttons.

- [ ] **Step 5: Build 0 warnings + full suite; commit.**

Run: `cd tools/zkmsg && cargo build -p zkmsg-gui 2>&1 | grep -c "^warning" ; cargo test`
Expected: `0`; core 48 / gui 9 / cli 1.

```bash
git add tools/zkmsg/gui
git commit -m "zkmsg burners task 8: cleanup wave — NotNow restores classified root, --profile error surfaces (no silent fallback), picker_error dismiss, handle shown in picker"
```

### Task 9: live acceptance + docs (user-driven)

- [ ] **Step 1: Free dry-run on a fixture root** (the Task-4/5 fixture
pattern from the profiles plan: `HOME=/tmp/zkmsg-burner-test`). New
burner… → auto name appears, deposit target arrives from live prices,
Confirm → checklist parks at Fund with the waiting card (address +
target + balance 0), Close → picker shows "(awaiting funding)", reopen →
card again. Verify NO dir exists before Confirm and no lock is held
while parked (picker + compose stay enabled).
- [ ] **Step 2: REAL burner end-to-end (user go-ahead required —
~recommended-amount STRK deposit, user keeps most of it).** Create a
burner on the real root; deposit the recommended amount to the shown
address (funding it from alice/bob draws the very link burners avoid —
acceptable for this rehearsal, owner's call); Refresh → deploy → init →
register run green. Switch to the burner, compose to alice with the
from-line checkbox on, send (~50 STRK of the deposit). Alice's inbox
shows the `from:` chip. Then the post-send "Sweep & archive" offer:
sweep to alice (warning shown), verify the burner leaves the picker,
`~/.zkmsg/archive/.zkmsg-burner-*/keys.json` intact, alice's balance up
by the swept amount.
- [ ] **Step 3: CLI parity spot-check.** `./target/release/zkmsg status`
(via `current`) and `--home` pointing at a burner dir — output format
unchanged; burner config fields invisible.
- [ ] **Step 4: Docs.** `tools/zkmsg/README.md`: burners paragraph in the
GUI section + rewrite the "What's public" bullet (burner fix shipped,
honest caveats from the spec's threat-model section verbatim: tiny
anonymity set, timing, reuse linkage, sweep edge).
`docs/zkmsg-deployment.md`: "Burners (2026-07-08)" note with the
acceptance burner's txs. Repo README zkmsg bullet: append burners.
Update `.superpowers/sdd/progress.md`.
- [ ] **Step 5: Commit + push**

```bash
git add -A
git commit -m "zkmsg burners task 9: SHIPPED — first externally-funded burner sent unlinkably and retired (sweep+archive); docs updated"
git push
```

## Self-Review Notes

- Spec coverage: burner wizard mode (T3 core + T5 GUI), external funding +
  park + no-lock wait (T1 + T5), completion-on-Completed constraint
  (global constraint + existing `flow.completed` keying verified), live
  funding recommendation both modes (T2 + T5), from-line + chip (T6),
  sweep + archive + warning + all-three-combos (T4 + T7), threat-model
  honesty (T9 docs), cleanup wave (T8), Merkle-growth section (assessed,
  no change — no task by design).
- Type consistency: `FundMode`/`AwaitingDeposit` defined T1, consumed
  T5; `new_plan_external_burner`/`burner_name` defined T3, consumed T5;
  `read_balance_fri` promoted T1, consumed T4/T7; `sweep_strk`/`archive_profile`
  defined T4, consumed T7; `picker_label` defined T8, referenced T7 (T7
  notes the inline fallback until T8 lands).
- Deliberate choices: `StepOutcome::Park` over an error type (parking is
  not a failure); per-popup-frame `setup.json`/`config.json` reads in the
  picker (cheap local fs, same class as the existing rescan); retire
  dialog owned by the app, not the session (it outlives the session it
  closes).
- Known environmental risk: none new — no new sncast subcommands, no new
  deps; the only new RPC is `gas_prices` (already used by the pipeline).
