# zkmsg GUI Profiles + Identity Wizard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Root-`.zkmsg` profile layout with an explicit one-time migration, in-app profile switching via session extraction, and a one-confirm New-profile wizard (sncast create → fund → deploy → init → register).

**Architecture:** A new pure `zkmsg_core::profiles` module owns layout discovery/resolution/migration; a new `zkmsg_core::setup` module owns the checkpointed wizard pipeline (mirroring `pipeline.rs`); the GUI extracts all per-identity state into a `ProfileSession` that is dropped and rebuilt on switch. The CLI gains only default-home resolution through the new layout — flags and stdout stay byte-identical.

**Tech Stack:** Existing deps only (Rust, egui/eframe 0.29, `std::thread` + `mpsc`, sncast 0.61 subprocesses, ureq). No new crates.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-08-zkmsg-gui-profiles-design.md`.
- **CLI parity:** no CLI flag or output line changes. New behavior only where none existed (a `--home` that is a root, which was previously an error case).
- **Threading rule is absolute:** never block the egui UI thread on RPC/subprocess — worker threads + `mpsc` + `ctx.request_repaint()`, no async runtime.
- **Keys are irreplaceable:** migration uses `fs::rename` only; never copy, delete, or overwrite `keys.json`. Any collision aborts before any move.
- **`work_in_flight()` guards every entry to paid work AND profile switching.**
- Layout (owner-specified): root `~/.zkmsg/` containing `current` (plain-text profile name) + `.zkmsg-<name>/` profile dirs.
- macOS/Apple Silicon native only. Build/test from `tools/zkmsg/` (pure cargo; scarb/snforge irrelevant).
- Baseline suites that must stay green: zkmsg-core 29, zkmsg-gui 2, zkmsg CLI 1. Commit per task.
- A wizard live-run moves real STRK (default 60, user keeps it) — only Task 8's acceptance does this, and only with the user's go-ahead.

---

### Task 1: `core::profiles` — discovery, classification, migration (pure, TDD)

**Files:**
- Create: `tools/zkmsg/core/src/profiles.rs`
- Modify: `tools/zkmsg/core/src/lib.rs` (add `pub mod profiles;`)

**Interfaces:**
- Consumes: `crate::config::Home` (only for reading `keys.json` handles via `Home::new(dir).load_keys()`).
- Produces (all `pub` in `zkmsg_core::profiles`):
  - `const PROFILE_PREFIX: &str = ".zkmsg-"`
  - `struct ProfileEntry { pub name: String, pub dir: PathBuf, pub handle: Option<String>, pub setup_incomplete: bool }`
  - `fn list_profiles(root: &Path) -> Result<Vec<ProfileEntry>>` (sorted by name)
  - `fn read_current(root: &Path) -> Option<String>` / `fn write_current(root: &Path, name: &str) -> Result<()>`
  - `enum HomeKind { Profile(PathBuf), Root { root: PathBuf, current: Option<PathBuf> }, Empty(PathBuf) }`
  - `fn classify_home(path: &Path) -> HomeKind`
  - `fn resolve_cli_home(path: &Path) -> Result<PathBuf>`
  - `struct LegacySource { pub dir: PathBuf, pub is_root: bool, pub suggested_name: String }`
  - `fn detect_legacy(root: &Path) -> Vec<LegacySource>`
  - `struct MigrationMove { pub from: PathBuf, pub to: PathBuf }`
  - `fn plan_migration(root: &Path, named: &[(LegacySource, String)]) -> Result<Vec<MigrationMove>>`
  - `fn execute_migration(moves: &[MigrationMove]) -> Result<()>`

- [ ] **Step 1: Write the failing tests** at the bottom of the new `profiles.rs`. Use a fresh temp dir per test (pattern from `config.rs::keys_refuse_overwrite`). Helper builds fixture trees:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("zkmsg-profiles-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }
    fn mk_profile(dir: &std::path::Path, handle: Option<&str>) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("config.json"), "{}").unwrap();
        if let Some(h) = handle {
            fs::write(
                dir.join("keys.json"),
                format!(r#"{{"scan_priv":"0x1","scan_pub":"0x2","handle":"{h}","leaf_index":0}}"#),
            ).unwrap();
        }
    }

    #[test]
    fn classify_all_three_kinds() {
        let root = tmp("classify");
        // Empty: nothing inside
        assert!(matches!(classify_home(&root), HomeKind::Empty(_)));
        // Root: has a profile child
        mk_profile(&root.join(".zkmsg-alice"), Some("alice"));
        write_current(&root, "alice").unwrap();
        match classify_home(&root) {
            HomeKind::Root { current: Some(p), .. } => assert!(p.ends_with(".zkmsg-alice")),
            other => panic!("expected Root with current, got {other:?}"),
        }
        // Profile: config.json directly inside
        let prof = tmp("classify-prof");
        mk_profile(&prof, None);
        assert!(matches!(classify_home(&prof), HomeKind::Profile(_)));
        fs::remove_dir_all(&root).unwrap();
        fs::remove_dir_all(&prof).unwrap();
    }

    #[test]
    fn list_profiles_reads_handles_and_sorts() {
        let root = tmp("list");
        mk_profile(&root.join(".zkmsg-bob"), Some("bob"));
        mk_profile(&root.join(".zkmsg-alice"), Some("alice"));
        fs::create_dir_all(root.join(".zkmsg-half")).unwrap(); // no config.json, no setup.json → ignored
        let got = list_profiles(&root).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!((got[0].name.as_str(), got[0].handle.as_deref()), ("alice", Some("alice")));
        assert_eq!(got[1].name.as_str(), "bob");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn list_profiles_surfaces_incomplete_setups() {
        let root = tmp("incomplete");
        let half = root.join(".zkmsg-carol");
        fs::create_dir_all(&half).unwrap();
        fs::write(half.join("setup.json"), "{}").unwrap(); // wizard checkpoint, no config yet
        let got = list_profiles(&root).unwrap();
        assert_eq!(got.len(), 1);
        assert!(got[0].setup_incomplete);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn detect_legacy_finds_root_and_siblings() {
        let parent = tmp("legacy");
        let root = parent.join(".zkmsg");
        mk_profile(&root, Some("alice"));                        // legacy: config.json at root
        mk_profile(&parent.join(".zkmsg-bob"), Some("bob"));     // legacy sibling
        let found = detect_legacy(&root);
        assert_eq!(found.len(), 2);
        let root_src = found.iter().find(|s| s.is_root).unwrap();
        assert_eq!(root_src.suggested_name, "alice");            // from keys.json handle
        let sib = found.iter().find(|s| !s.is_root).unwrap();
        assert_eq!(sib.suggested_name, "bob");
        fs::remove_dir_all(&parent).unwrap();
    }

    #[test]
    fn migration_plans_moves_and_refuses_collisions() {
        let parent = tmp("migrate");
        let root = parent.join(".zkmsg");
        mk_profile(&root, Some("alice"));
        fs::create_dir_all(root.join("sends")).unwrap();
        mk_profile(&parent.join(".zkmsg-bob"), Some("bob"));
        let sources = detect_legacy(&root);
        let named: Vec<_> =
            sources.into_iter().map(|s| { let n = s.suggested_name.clone(); (s, n) }).collect();

        // duplicate names refused
        let dup: Vec<_> = named.iter().map(|(s, _)| (s.clone(), "same".to_string())).collect();
        assert!(plan_migration(&root, &dup).is_err());

        let moves = plan_migration(&root, &named).unwrap();
        execute_migration(&moves).unwrap();
        // legacy root entries moved into the alice child; bob dir moved under root
        assert!(root.join(".zkmsg-alice/config.json").exists());
        assert!(root.join(".zkmsg-alice/keys.json").exists());
        assert!(root.join(".zkmsg-alice/sends").exists());
        assert!(root.join(".zkmsg-bob/config.json").exists());
        assert!(!root.join("config.json").exists());
        assert!(!parent.join(".zkmsg-bob").exists());
        // and the result classifies as a Root with 2 profiles
        assert_eq!(list_profiles(&root).unwrap().len(), 2);

        // re-running the plan against the migrated tree collides → error, nothing touched
        let again = detect_legacy(&root);
        assert!(again.is_empty());
        fs::remove_dir_all(&parent).unwrap();
    }

    #[test]
    fn resolve_cli_home_all_kinds() {
        let root = tmp("resolve");
        mk_profile(&root.join(".zkmsg-alice"), None);
        write_current(&root, "alice").unwrap();
        assert!(resolve_cli_home(&root).unwrap().ends_with(".zkmsg-alice"));
        let prof = root.join(".zkmsg-alice");
        assert_eq!(resolve_cli_home(&prof).unwrap(), prof);   // profile dirs pass through
        fs::write(root.join("current"), "ghost").unwrap();
        assert!(resolve_cli_home(&root).is_err());            // current names a missing profile
        fs::remove_dir_all(&root).unwrap();
    }
}
```

- [ ] **Step 2: Run tests, expect FAIL**

Run: `cd tools/zkmsg && cargo test -p zkmsg-core profiles`
Expected: compile FAIL (module functions undefined).

- [ ] **Step 3: Implement the module.** Semantics to honor exactly:

```rust
//! Root-`.zkmsg` profile layout (spec 2026-07-08): discovery,
//! home classification, `current` bookkeeping, and the one-time
//! legacy migration. Pure filesystem logic — no network, ever.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};

use crate::config::Home;

pub const PROFILE_PREFIX: &str = ".zkmsg-";

#[derive(Debug, Clone)]
pub struct ProfileEntry {
    pub name: String,
    pub dir: PathBuf,
    /// Registered handle cached in this profile's keys.json, if any.
    pub handle: Option<String>,
    /// setup.json present but config.json absent — a wizard run to resume.
    pub setup_incomplete: bool,
}

pub fn list_profiles(root: &Path) -> Result<Vec<ProfileEntry>> {
    let mut out = vec![];
    if !root.is_dir() {
        return Ok(out);
    }
    for entry in fs::read_dir(root)? {
        let dir = entry?.path();
        let Some(fname) = dir.file_name().and_then(|s| s.to_str()) else { continue };
        let Some(name) = fname.strip_prefix(PROFILE_PREFIX) else { continue };
        if !dir.is_dir() || name.is_empty() {
            continue;
        }
        let has_config = dir.join("config.json").is_file();
        let has_setup = dir.join("setup.json").is_file();
        if !has_config && !has_setup {
            continue;
        }
        let handle = Home::new(dir.clone()).load_keys().ok().and_then(|k| k.handle);
        out.push(ProfileEntry {
            name: name.to_string(),
            dir,
            handle,
            setup_incomplete: !has_config && has_setup,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

pub fn read_current(root: &Path) -> Option<String> {
    let s = fs::read_to_string(root.join("current")).ok()?;
    let s = s.trim().to_string();
    (!s.is_empty()).then_some(s)
}

pub fn write_current(root: &Path, name: &str) -> Result<()> {
    fs::create_dir_all(root)?;
    fs::write(root.join("current"), name).context("writing current")
}

#[derive(Debug)]
pub enum HomeKind {
    /// Has a config.json — a concrete home, usable directly.
    Profile(PathBuf),
    /// Contains profile children and/or a `current` file.
    Root { root: PathBuf, current: Option<PathBuf> },
    /// Neither — preserves today's "no config — run `zkmsg init`" path.
    Empty(PathBuf),
}

pub fn classify_home(path: &Path) -> HomeKind {
    if path.join("config.json").is_file() {
        return HomeKind::Profile(path.to_path_buf());
    }
    let profiles = list_profiles(path).unwrap_or_default();
    if !profiles.is_empty() || path.join("current").is_file() {
        let current = read_current(path)
            .map(|n| path.join(format!("{PROFILE_PREFIX}{n}")))
            .filter(|p| p.join("config.json").is_file());
        return HomeKind::Root { root: path.to_path_buf(), current };
    }
    HomeKind::Empty(path.to_path_buf())
}

/// CLI-facing resolution: a profile passes through; a root follows its
/// `current` file; an empty path passes through (so `init` still works).
pub fn resolve_cli_home(path: &Path) -> Result<PathBuf> {
    match classify_home(path) {
        HomeKind::Profile(p) | HomeKind::Empty(p) => Ok(p),
        HomeKind::Root { root, current: Some(p) } => {
            let _ = root;
            Ok(p)
        }
        HomeKind::Root { root, current: None } => bail!(
            "{} is a profile root with no valid current profile — pass --home {}/{PROFILE_PREFIX}<name> or pick one in the GUI",
            root.display(),
            root.display(),
        ),
    }
}
```

Migration half — `detect_legacy` looks at (a) `root/config.json` (an is_root source) and (b) `root.parent()` children named `.zkmsg-*` (excluding root itself) that contain a `config.json`. `suggested_name`: the home's `keys.json` handle if readable, else the dir suffix for siblings, else `""` for the root source. `plan_migration` validates names (non-empty, ASCII, no `/`, unique, and — for every source — target `root/.zkmsg-<name>` must NOT exist unless it is being created from the root source itself, which also must not exist yet) and returns the move list: for `is_root` sources, one `MigrationMove` per existing entry among `config.json`, `keys.json`, `sends`, `inbox.json`, `proofs` from `root/<entry>` to `root/.zkmsg-<name>/<entry>`; for siblings, a single dir move. `execute_migration` re-checks each `to` does not exist, `fs::create_dir_all` the parent, then `fs::rename` — never copy/delete.

- [ ] **Step 4: Run tests, expect PASS**

Run: `cd tools/zkmsg && cargo test -p zkmsg-core profiles`
Expected: 6 passed. Then `cargo test` — full suite still green (29+6 core, 2 gui, 1 cli).

- [ ] **Step 5: Commit**

```bash
cd /Users/modeofo/Apps/stwo-starknet-verifier
git add tools/zkmsg/core/src/profiles.rs tools/zkmsg/core/src/lib.rs
git commit -m "zkmsg profiles task 1: core::profiles — layout discovery/classification + migration planner (pure, 6 tests)"
```

### Task 2: CLI + GUI entry resolution through the new layout

**Files:**
- Modify: `tools/zkmsg/cli/src/main.rs` (where the `--home` PathBuf becomes a `Home` — single choke point)
- Modify: `tools/zkmsg/gui/src/main.rs`

**Interfaces:**
- Consumes: `zkmsg_core::profiles::resolve_cli_home(&Path) -> Result<PathBuf>`.
- Produces (GUI): `main.rs` passes `(launch_path: PathBuf, profile_override: Option<String>)` to `app::ZkmsgApp::new` — Task 3 changes that constructor; in THIS task keep `ZkmsgApp::new(Home)` and compute `Home::new(resolved)` in main, parsing but ignoring `--profile` is NOT acceptable — implement `--profile` resolution here: if given, resolved = `<launch_path>/.zkmsg-<name>`.

- [ ] **Step 1: CLI.** Find the single place `cli/src/main.rs` turns the `--home` arg (or default `~/.zkmsg`) into `Home::new(dir)`. Wrap the dir: `let dir = zkmsg_core::profiles::resolve_cli_home(&dir)?;`. No other CLI change.

- [ ] **Step 2: GUI main.** Add `--profile <name>` parsing alongside `--home` (same style as `parse_home_arg`). Resolution: with `--profile`, home = `launch_path.join(format!(".zkmsg-{name}"))`; else `resolve_cli_home(&launch_path).unwrap_or(launch_path)` — the `unwrap_or` keeps a root-with-no-current launching (Task 3 shows the picker there; until then the existing "no config" onboarding shows).

- [ ] **Step 3: Verify current behavior unchanged (pre-migration).**

Run: `cd tools/zkmsg && cargo test && cargo build --release && ./target/release/zkmsg status`
Expected: suite green; `status` output identical to before (the real `~/.zkmsg` still has a top-level config.json → classifies as Profile → passes through).

- [ ] **Step 4: Commit**

```bash
git add tools/zkmsg/cli/src/main.rs tools/zkmsg/gui/src/main.rs
git commit -m "zkmsg profiles task 2: CLI + GUI resolve --home through the profile layout (profile dirs pass through; roots follow current); GUI gains --profile"
```

### Task 3: GUI session extraction (`ProfileSession`)

**Files:**
- Create: `tools/zkmsg/gui/src/session.rs`
- Modify: `tools/zkmsg/gui/src/app.rs`, `tools/zkmsg/gui/src/compose_view.rs`, `tools/zkmsg/gui/src/inbox_view.rs`, `tools/zkmsg/gui/src/main.rs`

**Interfaces:**
- Consumes: everything `ZkmsgApp` holds today (`gui/src/app.rs:28-90`).
- Produces:
  - `session::ProfileSession` — ALL per-identity fields of today's `ZkmsgApp` (every field except `repo_root`) plus `pub name: String` and the `tab: Tab` (a fresh session starts at `Tab::Status`). Constructor: `ProfileSession::new(name: String, home: Home) -> Self` (exactly today's `ZkmsgApp::new` body for those fields).
  - `ProfileSession::work_in_flight(&self) -> bool` — today's `send_in_flight()` logic, renamed (Task 7 extends it).
  - `ZkmsgApp` becomes: `{ root: Option<PathBuf>, repo_root: PathBuf, profiles: Vec<ProfileEntry>, session: Option<ProfileSession>, picker_error: Option<String> }` with `ZkmsgApp::new(launch_path: PathBuf, profile_override: Option<String>) -> Self`.
  - `ZkmsgApp::open_session(&mut self, ctx: &egui::Context, name: String, home: Home)` — sets the session, and sets the window title: `ctx.send_viewport_cmd(egui::ViewportCommand::Title(format!("zkmsg — {name}")))`.

- [ ] **Step 1: Mechanical extraction.** Move the per-identity fields and every method that touches them (`status_tab`, onboarding panels, `compose_tab`/`render_send_progress`/`start_send`/`resume_send`, `inbox_tab`/`poll_inbox_worker`/`refresh_inbox`, banner logic, all `poll_*`) from `ZkmsgApp` to `ProfileSession` (the view modules' `impl ZkmsgApp` blocks become `impl ProfileSession`). `repo_root` is passed into the two call sites that need it as a `&Path` parameter. Session naming at construction: `ZkmsgApp::new` classifies the launch path — `HomeKind::Profile(p)` → session named by `keys.json` handle, else dir suffix after `.zkmsg-`, else the dir name, `root: None`; `HomeKind::Root` → `root: Some(path)`, load `list_profiles`, open the `current` (or `--profile`) session named by its dir suffix; `HomeKind::Empty(p)` → treat as Profile (existing init onboarding renders).

- [ ] **Step 2: Dispatch in `update()`.** Top bar: tabs (from the session) + a right-aligned label with the active profile name (the interactive picker is Task 5). Central: `match &mut self.session { Some(s) => s.render(ui, ctx, &self.repo_root), None => centered label "no profile selected" + a list of `self.profiles` names as buttons that call `open_session` }`.

- [ ] **Step 3: Build clean + suite green.**

Run: `cd tools/zkmsg && cargo build -p zkmsg-gui 2>&1 | grep -c warning && cargo test`
Expected: `0` warnings; all tests pass (the two `send_flow` tests are unaffected).

- [ ] **Step 4: Manual smoke.** `cargo run -p zkmsg-gui -- --home ~/.zkmsg` (still legacy → Profile kind): Status tab renders alice exactly as before; window title reads `zkmsg — alice`.

- [ ] **Step 5: Commit**

```bash
git add tools/zkmsg/gui
git commit -m "zkmsg profiles task 3: session extraction — all per-identity GUI state moves into ProfileSession (drop+rebuild = switch); window title names the active profile"
```

### Task 4: Migration screen

**Files:**
- Create: `tools/zkmsg/gui/src/migrate_view.rs`
- Modify: `tools/zkmsg/gui/src/app.rs` (launch check + dispatch), `tools/zkmsg/gui/src/main.rs` (pass a `is_default_home: bool`)

**Interfaces:**
- Consumes: `profiles::{detect_legacy, plan_migration, execute_migration, list_profiles, write_current, LegacySource}`.
- Produces: `migrate_view::MigrationUi { sources: Vec<(LegacySource, String)>, error: Option<String> }`; `ZkmsgApp` gains `migration: Option<MigrationUi>`.

- [ ] **Step 1: Launch detection.** Only when the launch path is the DEFAULT root (`~/.zkmsg`, i.e. no `--home` was passed): run `detect_legacy(&path)`; if non-empty, set `self.migration = Some(MigrationUi { sources: found.into_iter().map(|s| { let n = s.suggested_name.clone(); (s, n) }).collect(), error: None })` and do NOT open a session yet. An explicit `--home` never triggers migration (spec: explicit paths keep working unchanged).

- [ ] **Step 2: Render.** When `self.migration` is `Some`, the central panel shows ONLY the migration screen: heading "One-time migration to the profile layout", one row per source (`dir.display()` + `egui::TextEdit::singleline` bound to the editable name), the explanation line "Files are moved with atomic renames — nothing is copied, deleted, or overwritten.", `error` in red if set, and two buttons: **Migrate** → `plan_migration(root, &named)` then `execute_migration`; on success clear `migration`, `list_profiles`, `write_current(root, first_name)`, `open_session`; on `Err(e)` set `error = Some(format!("{e:#}"))` and change nothing. **Not now** → clear `migration` and fall through to the pre-migration behavior (the legacy root still classifies as Profile, so alice opens as before).

- [ ] **Step 3: Manual test against a FIXTURE, not the real homes.** Build a throwaway tree and point the app at it with `HOME` overridden so the default-home check fires:

```bash
mkdir -p /tmp/zkmsg-mig-test/.zkmsg /tmp/zkmsg-mig-test/.zkmsg-bob
cp ~/.zkmsg/config.json /tmp/zkmsg-mig-test/.zkmsg/
printf '{"scan_priv":"0x1","scan_pub":"0x2","handle":"alice","leaf_index":0}' > /tmp/zkmsg-mig-test/.zkmsg/keys.json
cp /tmp/zkmsg-mig-test/.zkmsg/{config,keys}.json /tmp/zkmsg-mig-test/.zkmsg-bob/ && sed -i '' 's/alice/bob/' /tmp/zkmsg-mig-test/.zkmsg-bob/keys.json
cd tools/zkmsg && HOME=/tmp/zkmsg-mig-test cargo run -p zkmsg-gui
```

Expected: migration screen lists both with names prefilled alice/bob; Migrate produces `/tmp/zkmsg-mig-test/.zkmsg/{current,.zkmsg-alice,.zkmsg-bob}` and opens alice. Delete the fixture afterwards. (Status will show RPC data since config points at the real network — reads only, free.)

- [ ] **Step 4: Commit**

```bash
git add tools/zkmsg/gui
git commit -m "zkmsg profiles task 4: one-time migration screen — editable names prefilled from keys.json handles, atomic renames, inline errors, Not-now escape"
```

### Task 5: Profile picker + switching

**Files:**
- Modify: `tools/zkmsg/gui/src/app.rs`, `tools/zkmsg/gui/src/session.rs`

**Interfaces:**
- Consumes: `profiles::{list_profiles, write_current}`, `ProfileSession::work_in_flight()`, `ZkmsgApp::open_session`.
- Produces: the top-bar picker; Task 7 adds its "New profile…" entry.

- [ ] **Step 1: Picker.** In the top bar (right-aligned, only when `self.root.is_some()`): an `egui::ComboBox` labeled with the active session name. Opening it re-runs `list_profiles` (cheap, local). Selecting a different complete profile: `write_current(root, &name)`, then `open_session(ctx, name, Home::new(entry.dir))` — the old session drops, which is the whole switch. When `session.work_in_flight()`, render the combo inside `ui.add_enabled_ui(false, …)` with a small "send in progress" label beside it.

- [ ] **Step 2: work_in_flight unit test** in `session.rs` (pure — construct a default-ish session struct in-test or factor the check into `fn work_in_flight_flags(preparing: bool, sending: bool) -> bool` and test that):

```rust
#[test]
fn work_in_flight_covers_prepare_and_send_windows() {
    assert!(!work_in_flight_flags(false, false));
    assert!(work_in_flight_flags(true, false));   // prepare window (the race the 07-07 review closed)
    assert!(work_in_flight_flags(false, true));
}
```

- [ ] **Step 3: Manual test on the Task 4 fixture.** Switch alice↔bob: window title flips, Status/Inbox/banner all show the selected identity's data, and `current` in the fixture root updates.

- [ ] **Step 4: Run suite + commit**

Run: `cd tools/zkmsg && cargo test`
Expected: green.

```bash
git add tools/zkmsg/gui
git commit -m "zkmsg profiles task 5: top-bar profile picker — rescan on open, switch = write current + rebuild session, disabled while work is in flight"
```

### Task 6: `core::setup` — the wizard pipeline (create → fund → deploy → init → register)

**Files:**
- Create: `tools/zkmsg/core/src/setup.rs`
- Modify: `tools/zkmsg/core/src/lib.rs` (add `pub mod setup;`)
- Modify: `tools/zkmsg/core/src/chain.rs` (account subcommands + promote `account_address`)
- Modify: `tools/zkmsg/core/src/config.rs` (make the STRK token address a shared const)
- Modify: `tools/zkmsg/core/src/app.rs` (use the shared const; delete its private copies)

**Interfaces:**
- Consumes: `Chain::{invoke, wait_receipt}`, `app::{init_identity, register, RegisterOutcome}`, `parse_sncast_json`.
- Produces:
  - `config.rs`: `pub const STRK_TOKEN: &str = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";` (move of the private `STRK` in `app.rs:17`; `app.rs` and the CLI keep compiling against the new path)
  - `chain.rs`: `pub fn account_create(&self, name: &str) -> Result<String>` (returns the precomputed address), `pub fn account_deploy(&self, name: &str) -> Result<String>` (returns tx hash), `pub fn account_address(account: &str) -> Result<String>` (moved from `app.rs:273`, now `pub`, `app.rs` re-uses it)
  - `setup.rs`:
    - `enum SetupStepKind { CreateAccount, Fund, Deploy, Init, Register }` (derive `Debug, Clone, PartialEq, Serialize, Deserialize`)
    - `struct SetupStep { pub kind: SetupStepKind, pub done: bool, pub tx_hash: Option<String>, pub note: Option<String> }`
    - `struct SetupState { pub profile_name: String, pub handle: String, pub account_name: String, pub fund_strk: u64, pub source_account: String, pub address: Option<String>, pub steps: Vec<SetupStep> }` with `new_plan(profile_name, handle, account_name, fund_strk, source_account) -> Self` (5 steps in the order above), `next_pending() -> Option<usize>`, `mark_done(index, tx, note)`, `save(dir: &Path)` / `load(dir: &Path)` (file `<dir>/setup.json`)
    - `enum SetupEvent { StepStarted { index: usize, total: usize, kind: SetupStepKind }, TxSubmitted { kind: SetupStepKind, tx_hash: String }, StepCompleted { kind: SetupStepKind, tx_hash: Option<String>, note: Option<String> }, Completed }` (derive `Debug, Clone`)
    - `struct SetupRunner<'a> { pub rpc_url: &'a str, pub profile_dir: &'a Path, pub repo_root: &'a Path }` with `run(&self, state: &mut SetupState, sink: &mut dyn FnMut(SetupEvent)) -> Result<()>`
    - `pub fn strk_to_fri_hex(strk: u64) -> String` (u256-low hex for calldata)

- [ ] **Step 1: Verify sncast 0.61 account-command flags before writing code.**

Run: `sncast account create --help | head -25 && sncast account deploy --help | head -20`
Expected: `create` takes `--name <NAME>` (+ `--type`, default oz) and the global `--url`; `deploy` takes `--name <NAME>` + `--url`. If flags differ, adapt the two chain.rs functions to the actual flags — the contract with callers is only the two signatures above.

- [ ] **Step 2: Failing tests** in `setup.rs`:

```rust
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
}
```

- [ ] **Step 3: Run, expect FAIL** (`cargo test -p zkmsg-core setup`), then implement. `chain.rs` account functions build their own `Command` (do NOT reuse the private `sncast()` helper — it injects `--account`, which these subcommands don't take):

```rust
/// `sncast account create` — generates a keypair straight into the OZ
/// accounts file (no manual key handling) and returns the precomputed
/// address. Deployment happens separately, after funding.
pub fn account_create(&self, name: &str) -> Result<String> {
    let v = Self::sncast_account(&["create", "--name", name], &self.rpc_url)?;
    Ok(v["address"].as_str().with_context(|| format!("no address in: {v}"))?.to_string())
}

/// `sncast account deploy` — the DEPLOY_ACCOUNT tx, fees paid by the
/// (pre-funded) new account itself.
pub fn account_deploy(&self, name: &str) -> Result<String> {
    let v = Self::sncast_account(&["deploy", "--name", name], &self.rpc_url)?;
    Ok(v["transaction_hash"].as_str().with_context(|| format!("no tx in: {v}"))?.to_string())
}

fn sncast_account(args: &[&str], url: &str) -> Result<Value> {
    let mut cmd = Command::new("sncast");
    cmd.arg("--json").arg("account").args(args).arg("--url").arg(url);
    let out = cmd.output().context("running sncast account")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        bail!("sncast account {} failed:\n{}\n{}", args.first().unwrap_or(&""), stdout,
            String::from_utf8_lossy(&out.stderr));
    }
    parse_sncast_json(&stdout)
}
```

`SetupRunner::run` mirrors `Pipeline::run` (`pipeline.rs`): loop `next_pending`, emit `StepStarted`, execute, `mark_done` + `save`, emit `StepCompleted`; finish with `Completed`. Step execution:

- **CreateAccount**: `Chain::new(rpc, source_account).account_create(&state.account_name)`. If it errors AND `chain::account_address(&state.account_name)` succeeds (a previous run created it), use that address with note `"account already existed"`. Store `state.address`, note = the address.
- **Fund**: `ensure!(state.fund_strk > 0)`; `invoke(STRK_TOKEN, "transfer", &[address, strk_to_fri_hex(state.fund_strk), "0x0".into()], &Default::default())` as `source_account`, then `wait_receipt(tx, 600s)`. Emit `TxSubmitted` between invoke and wait (exactly like the pipeline's tx steps).
- **Deploy**: `account_deploy(&state.account_name)` then `wait_receipt`. Idempotency: if deploy errors with an already-deployed message, mark done with note `"already deployed"`.
- **Init**: if `Home::new(profile_dir).keys_path().exists()` → note `"already initialized"`; else `app::init_identity(&Home::new(profile_dir.to_path_buf()), &state.account_name, None, self.repo_root)`.
- **Register**: `app::register(&Home::new(profile_dir.to_path_buf()), &state.handle)` — already idempotent; map `RegisterOutcome::Registered{tx_hash,..}` to the step's tx, `AlreadyRegistered` to note `"already registered"`.

- [ ] **Step 4: Run tests, expect PASS** — `cargo test -p zkmsg-core` (8 profiles/setup tests + the original 29), and `cargo test` for the workspace (app.rs/CLI still compile against `STRK_TOKEN` and the moved `account_address`).

- [ ] **Step 5: Commit**

```bash
git add tools/zkmsg/core
git commit -m "zkmsg profiles task 6: core::setup wizard pipeline (create/fund/deploy/init/register, checkpointed to setup.json) + sncast account create/deploy in chain.rs"
```

### Task 7: Wizard GUI (New profile… + confirm + live checklist + resume)

**Files:**
- Create: `tools/zkmsg/gui/src/wizard_view.rs`, `tools/zkmsg/gui/src/setup_flow.rs`
- Modify: `tools/zkmsg/gui/src/worker.rs`, `tools/zkmsg/gui/src/app.rs`, `tools/zkmsg/gui/src/session.rs` (extend `work_in_flight`)

**Interfaces:**
- Consumes: `setup::{SetupState, SetupEvent, SetupStepKind, SetupRunner}`, `profiles::{write_current, list_profiles, PROFILE_PREFIX}`, the picker from Task 5.
- Produces:
  - `setup_flow::SetupFlow { pub steps: Vec<SetupStepView>, pub error: Option<String>, pub completed: bool }` with `from_state(&SetupState)`, `apply(&mut self, SetupEvent)`, `fail(&mut self, String)` — the exact shape of `send_flow.rs` with `SetupStepKind` (copy the structure; do not try to genericize over both enums).
  - `worker::SetupWorkerMsg { Progress(SetupEvent), Done(Result<(), String>) }` and `worker::spawn_setup(rpc_url: String, profile_dir: PathBuf, repo_root: PathBuf, state: SetupState, ctx: egui::Context) -> Receiver<SetupWorkerMsg>` (same shape as `spawn_send`, `gui/src/worker.rs:20-40`).
  - `ZkmsgApp.wizard: Option<wizard_view::WizardUi>`; app-level `work_in_flight` = session's OR `wizard.as_ref().is_some_and(|w| w.running())` — this guard now also disables the picker AND the Compose send button while a wizard runs.

- [ ] **Step 1: Failing reducer tests** in `setup_flow.rs` (mirror `send_flow.rs`'s two tests with `SetupStepKind::{CreateAccount, Fund}`; assert `Completed` sets `completed` and marks all steps done). Run `cargo test -p zkmsg-gui setup_flow`, expect FAIL, implement, expect PASS (4 gui tests total).

- [ ] **Step 2: WizardUi.** Fields: `name: String, handle: String, account_name: String, fund_strk: String, confirm_open: bool, flow: Option<SetupFlow>, rx: Option<Receiver<SetupWorkerMsg>>, profile_dir: Option<PathBuf>, error: Option<String>`. Opened from the picker's `New profile…` entry (added in this task) with `handle`/`account_name` auto-derived while the user types the name (`handle = name`, `account_name = format!("zkmsg-{name}")`, both still editable). Validation before enabling Create: name ASCII/non-empty/no `/`, `root/.zkmsg-<name>` must not exist, `fund_strk` parses to u64.
- [ ] **Step 3: Confirm + spawn.** The Create button opens a modal (same pattern as the send confirm in `compose_view.rs`): "Create account `<account_name>`, fund it with **N STRK** from `<source>` (the active profile's account), deploy it, and register '`<handle>`'? The N STRK moves to the new account — it stays yours. Fees ≈ under 1 STRK." Confirm → create `root/.zkmsg-<name>/`, `SetupState::new_plan(...).save(&dir)`, `spawn_setup`, set `flow = Some(SetupFlow::from_state(...))`. Cancel → nothing. The running checklist renders like the send progress (spinner/✓/✗ + Voyager links for tx hashes); on `Done(Err)` → `flow.fail(e)` + a **Resume** button that reloads `SetupState::load(&dir)` and re-spawns (the runner skips done steps). On `Done(Ok)`/`Completed`: `write_current`, rescan profiles, `open_session` for the new profile, clear the wizard.
- [ ] **Step 4: Resume path from the picker.** `ProfileEntry::setup_incomplete` entries render in the picker as "`<name>` (setup incomplete)"; selecting one opens the wizard directly in resume mode (load `SetupState` from the dir, show the checklist with a Resume button — NOT the blank form, and NO new confirm needed only if the Fund step is already done; if Fund is still pending, resume re-opens the confirm dialog since money has not moved yet).
- [ ] **Step 5: Build 0 warnings + full suite.**

Run: `cd tools/zkmsg && cargo build -p zkmsg-gui 2>&1 | grep -c warning && cargo test`
Expected: `0`; core 37 / gui 4 / cli 1 green.

- [ ] **Step 6: Manual dry check (no spend).** On the migration fixture from Task 4: open New profile…, type a name, see derived fields, open the confirm dialog, **Cancel**. Verify no dir was created before Confirm.

- [ ] **Step 7: Commit**

```bash
git add tools/zkmsg/gui
git commit -m "zkmsg profiles task 7: New-profile wizard — confirm-gated create/fund/deploy/init/register checklist, resumable from the picker; work_in_flight covers wizard runs"
```

### Task 8: Live acceptance + docs

- [ ] **Step 1: Migrate the real homes (user-visible moment; free).** Launch `cargo run -p zkmsg-gui` (default home). The migration screen must list `~/.zkmsg` (alice) + `~/.zkmsg-bob` (bob). Migrate; verify `~/.zkmsg/{current,.zkmsg-alice,.zkmsg-bob}` and that keys/sends all moved (`ls ~/.zkmsg/.zkmsg-alice`). Then verify the CLI followed: `./target/release/zkmsg status` (resolves via `current` → alice, output format unchanged) and `./target/release/zkmsg --home ~/.zkmsg/.zkmsg-bob inbox` (4 messages).
- [ ] **Step 2: Switching acceptance (free).** Switch alice↔bob in the picker: title, status, inbox, resume banner all flip. Restart the app: it opens the `current` profile.
- [ ] **Step 3: Wizard acceptance (REAL STRK — get the user's explicit go-ahead first: ~60 STRK moved to the new account + <1 STRK fees).** New profile "carol" funded from alice with the default 60: watch create → fund → deploy → init → register run green; record the account address + fund/deploy/register tx hashes. Verify: picker now lists carol; `zkmsg status` for carol shows handle + leaf 2 + balance ≈59; alice's balance dropped by ~60 + fee. Optional (owner's call): a paid send carol→alice (~48 STRK) to prove a wizard-born identity sends.
- [ ] **Step 4: Docs.** `tools/zkmsg/README.md` GUI section: profiles paragraph (root layout, picker, migration, wizard incl. the "sncast keys never touched by hand" point). `docs/zkmsg-deployment.md`: a "Profiles + identity wizard (2026-07-08)" note recording carol's account + txs. Repo README zkmsg bullet: append "in-app profiles + one-click funded identities". Update `.superpowers/sdd/progress.md`.
- [ ] **Step 5: Commit + push**

```bash
git add -A
git commit -m "zkmsg profiles task 8: SHIPPED — real homes migrated, in-app switching live, first wizard-born identity (carol) created/funded/deployed/registered end-to-end; docs updated"
git push
```

## Self-Review Notes

- Spec coverage: layout+migration (T1 core, T4 UI, T8 real homes), discovery/picker/switching + title + block-while-working (T1/T5), session extraction (T3), wizard backend+UI+resume (T6/T7), CLI resolution with unchanged output (T2), threading/money rules (constraints + T5 work_in_flight test + T7 guard extension), testing strategy (temp-tree tests T1, reducer tests T7, free acceptance T8 steps 1-2, paid step 3 gated on user).
- Type consistency: `ProfileEntry`/`HomeKind`/`LegacySource`/`MigrationMove` defined T1, consumed T2/T4/T5/T7 with matching names; `SetupState`/`SetupEvent`/`SetupStepKind`/`SetupRunner` defined T6, consumed T7; `work_in_flight` introduced T3, tested T5, extended T7.
- Deliberate duplication: `SetupFlow` copies `SendFlow`'s shape rather than genericizing — two small concrete reducers beat one generic one nobody asked for (YAGNI).
- Known environmental risk: sncast 0.61 `account create/deploy` flag names are verified in T6 Step 1 before implementation; only the two chain.rs signatures are contracts.
