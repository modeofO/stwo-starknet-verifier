//! Deleting an identity (owner decisions, 2026-10-08):
//!
//!   * Unspent tickets can first move to another profile on this machine.
//!     A ticket is a bearer secret no chain record ties to an identity, so
//!     moving one is local and links nothing.
//!   * The account's balance is NOT swept: a transfer to another account is
//!     a public edge linking the two (red team 01 found exactly this with
//!     `burner-7ec070`). The plan shows the balance; deleting abandons it.
//!   * Nothing happens on chain: the registration and past messages stay,
//!     and messages sent to the deleted handle become unreadable to everyone.
//!   * Locally everything goes: the profile key is shredded first (every
//!     sealed file becomes unreadable at once, see `vault`), then the
//!     account's entry in sncast's accounts file, then the directory, then
//!     `current` if it named this profile.
//!
//! `wipe_profile` needs no network and asks nothing, so a panic wipe of
//! every profile can reuse it.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde_json::Value;
use starknet_types_core::felt::Felt;

use crate::config::{Home, same_address};
use crate::profiles::{ARCHIVE_DIR, PROFILE_PREFIX, list_profiles, read_current, write_current};
use crate::setup::SetupState;
use crate::state::{SendState, StepKind};
use crate::tickets::{TicketState, Wallet};

/// What deleting a profile will do, read from local files only.
#[derive(Debug, Clone)]
pub struct DeletePlan {
    pub name: String,
    pub dir: PathBuf,
    /// The profile sits under `archive/`.
    pub archived: bool,
    pub handle: Option<String>,
    pub burner: bool,
    /// The sncast account name, and its address if sncast's accounts file
    /// holds it (`None`: there is no key there to remove).
    pub account: Option<String>,
    pub account_address: Option<String>,
    /// Other profiles (live, archived or mid-setup) configured with the same
    /// sncast account: its key then stays, whatever the options say.
    pub account_shared_with: Vec<String>,
    pub store: Option<String>,
    /// Tickets that can move to another profile.
    pub movable_tickets: usize,
    /// Reserved by a send whose publish was submitted: it may already be
    /// spent, so it is not moved.
    pub tickets_in_flight: usize,
    /// Other profile dirs carrying the same vault id (a copied directory):
    /// the key is then NOT shredded, or they would all become unreadable.
    pub key_shared_with: Vec<String>,
    /// Profiles on the same store that can take the tickets.
    pub ticket_targets: Vec<String>,
    /// Sends with a step still to run (deleting abandons them).
    pub incomplete_sends: usize,
}

impl DeletePlan {
    /// What the user types to confirm: the handle, else the profile name.
    pub fn confirm_text(&self) -> &str {
        self.handle.as_deref().unwrap_or(&self.name)
    }

    /// Whether the account's key will be removed from sncast's file.
    pub fn removes_account_key(&self, opts: &WipeOptions) -> bool {
        opts.delete_account_key && self.account_address.is_some() && self.account_shared_with.is_empty()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WipeOptions {
    /// Remove the account's entry (private key included) from sncast's
    /// accounts file, unless another profile uses it.
    pub delete_account_key: bool,
}

impl Default for WipeOptions {
    fn default() -> Self {
        Self { delete_account_key: true }
    }
}

#[derive(Debug, Clone, Default)]
pub struct WipeReport {
    /// A profile key existed and was deleted from the Keychain.
    pub shredded: bool,
    pub account_key_removed: Option<String>,
    /// `current` was this profile: now this one (`None`: cleared).
    pub new_current: Option<Option<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TicketMove {
    pub moved: usize,
    /// Already in the target's wallet (a second move after a crash).
    pub already_there: usize,
    pub left_in_flight: usize,
}

/// The directory of profile `name`, live or under `archive/`. Which one is
/// always explicit: a name can exist in both places (archive `carol`, then
/// make a new `carol`), and guessing would delete the wrong one.
pub fn profile_dir(root: &Path, name: &str, archived: bool) -> Result<PathBuf> {
    ensure!(
        !name.is_empty() && !name.contains('/') && !name.contains('\\') && name != "." && name != "..",
        "bad profile name {name:?}"
    );
    let parent = if archived { root.join(ARCHIVE_DIR) } else { root.to_path_buf() };
    let dir = parent.join(format!("{PROFILE_PREFIX}{name}"));
    ensure!(dir.is_dir(), "no {}profile '{name}' under {}", if archived { "archived " } else { "" }, root.display());
    Ok(dir)
}

/// Every profile dir under `root`, live and archived (complete or not).
pub fn all_profile_dirs(root: &Path) -> Vec<PathBuf> {
    let mut out = vec![];
    for parent in [root.to_path_buf(), root.join(ARCHIVE_DIR)] {
        let Ok(rd) = fs::read_dir(&parent) else { continue };
        for entry in rd.flatten() {
            let dir = entry.path();
            let is_profile = dir
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.len() > PROFILE_PREFIX.len() && n.starts_with(PROFILE_PREFIX));
            if is_profile && dir.is_dir() {
                out.push(dir);
            }
        }
    }
    out.sort();
    out
}

fn dir_name(dir: &Path) -> String {
    let f = dir.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    f.strip_prefix(PROFILE_PREFIX).unwrap_or(f).to_string()
}

/// Other profile dirs (live or archived) whose vault.json names the same
/// key id as `dir`'s.
fn key_sharers(root: &Path, dir: &Path) -> Vec<PathBuf> {
    let id_of = |d: &Path| crate::vault::profile_key_id(&Home::new(d.to_path_buf())).ok().flatten();
    let Some(id) = id_of(dir) else { return vec![] };
    all_profile_dirs(root).into_iter().filter(|d| d != dir && id_of(d).as_deref() == Some(id.as_str())).collect()
}

/// The sncast account a profile uses: config.json's, else a mid-setup
/// profile's account from setup.json.
fn profile_account(dir: &Path) -> Option<String> {
    Home::new(dir.to_path_buf())
        .load_config()
        .ok()
        .map(|c| c.account)
        .or_else(|| SetupState::load(dir).ok().map(|s| s.account_name))
        .filter(|a| !a.is_empty())
}

/// Which tickets of `wallet` can move: (movable, in flight). A reserved
/// ticket whose send never got a publish submitted is movable (that send
/// is deleted with the profile and can never publish).
fn classify_tickets(home: &Home, wallet: &Wallet) -> (Vec<usize>, usize) {
    let mut movable = vec![];
    let mut in_flight = 0;
    for (i, t) in wallet.tickets.iter().enumerate() {
        match &t.state {
            TicketState::Unspent | TicketState::Pending => movable.push(i),
            TicketState::Reserved { send_id } => {
                let submitted = SendState::load(home, send_id).ok().is_some_and(|s| {
                    s.steps.iter().any(|st| st.kind == StepKind::Publish && st.tx_hash.is_some())
                });
                if submitted {
                    in_flight += 1;
                } else {
                    movable.push(i);
                }
            }
            TicketState::Spent { .. } => {}
        }
    }
    (movable, in_flight)
}

/// Reads everything `delete_profile` will act on. Local files only.
pub fn plan_delete(root: &Path, name: &str, archived: bool) -> Result<DeletePlan> {
    let dir = profile_dir(root, name, archived)?;
    let home = Home::new(dir.clone());
    let config = home.load_config().ok();
    // Keys may be unreadable (a half-deleted profile): the plan still works.
    let handle = home.load_keys().ok().and_then(|k| k.handle);
    let account = profile_account(&dir);
    let account_address = account.as_deref().and_then(|a| crate::chain::account_address(a).ok());
    let account_shared_with = match &account {
        Some(a) => all_profile_dirs(root)
            .into_iter()
            .filter(|d| d != &dir && profile_account(d).as_deref() == Some(a.as_str()))
            .map(|d| dir_name(&d))
            .collect(),
        None => vec![],
    };

    let store = config.as_ref().map(|c| c.store.clone());
    let (mut movable_tickets, mut tickets_in_flight, mut ticket_targets) = (0, 0, vec![]);
    if let Some(store) = &store {
        if let Ok(wallet) = Wallet::load(&home, store) {
            let (movable, in_flight) = classify_tickets(&home, &wallet);
            movable_tickets = movable.len();
            tickets_in_flight = in_flight;
        }
        ticket_targets = list_profiles(root)?
            .into_iter()
            .filter(|p| p.dir != dir && !p.setup_incomplete)
            .filter(|p| {
                Home::new(p.dir.clone()).load_config().is_ok_and(|c| same_address(&c.store, store))
            })
            .map(|p| p.name)
            .collect();
    }
    let incomplete_sends = crate::app::pending_sends(&home).map(|p| p.len()).unwrap_or(0);
    let key_shared_with = key_sharers(root, &dir).into_iter().map(|d| dir_name(&d)).collect();

    Ok(DeletePlan {
        name: name.to_string(),
        dir,
        archived,
        handle,
        burner: config.as_ref().is_some_and(|c| c.burner),
        account,
        account_address,
        account_shared_with,
        store,
        movable_tickets,
        tickets_in_flight,
        ticket_targets,
        incomplete_sends,
        key_shared_with,
    })
}

/// Moves `from`'s movable tickets into `to`'s wallet (same store), as
/// Unspent or Pending. The target is written first and the source is left
/// as it is: the source is about to be wiped, and a crash in between
/// leaves the tickets in both places rather than in neither.
pub fn move_tickets(from: &Home, to: &Home) -> Result<TicketMove> {
    let from_store = from.load_config()?.store;
    let to_store = to.load_config()?.store;
    ensure!(
        same_address(&from_store, &to_store),
        "{} uses store {from_store}, {} uses {to_store}: tickets only move within one pool",
        from.dir.display(),
        to.dir.display()
    );
    ensure!(from.dir != to.dir, "moving tickets to the same profile");
    let source = Wallet::load(from, &from_store)?;
    let (movable, left_in_flight) = classify_tickets(from, &source);
    let mut target = Wallet::load(to, &to_store)?;
    let mut report = TicketMove { left_in_flight, ..Default::default() };
    for i in movable {
        let mut t = source.tickets[i].clone();
        let secret = Felt::from_hex(&t.secret).context("ticket secret")?;
        if target.tickets.iter().any(|x| Felt::from_hex(&x.secret).ok() == Some(secret)) {
            report.already_there += 1;
            continue;
        }
        if matches!(t.state, TicketState::Reserved { .. }) {
            t.state = TicketState::Unspent;
        }
        target.tickets.push(t);
        report.moved += 1;
    }
    if report.moved > 0 {
        target.save(to)?;
    }
    Ok(report)
}

/// Deletes one profile's local everything, offline: shred the profile key,
/// drop the account key from sncast's file (if `opts` says so and no other
/// profile uses it), remove the directory, fix up `current`.
pub fn wipe_profile(root: &Path, dir: &Path, opts: WipeOptions) -> Result<WipeReport> {
    let home = Home::new(dir.to_path_buf());
    let mut report = WipeReport::default();
    // First, so that whatever fails after this, the secrets are already gone.
    // Not when a copy of this directory shares the key: that would destroy
    // the copy too.
    if key_sharers(root, dir).is_empty() {
        report.shredded = crate::vault::shred(&home)?;
    }

    if opts.delete_account_key {
        if let Some(account) = profile_account(dir) {
            let shared = all_profile_dirs(root)
                .into_iter()
                .any(|d| d != dir && profile_account(&d).as_deref() == Some(account.as_str()));
            if !shared && remove_sncast_account(&sncast_accounts_path()?, &account)? {
                report.account_key_removed = Some(account);
            }
        }
    }

    fs::remove_dir_all(dir).with_context(|| format!("removing {}", dir.display()))?;

    // `current` only ever names a live profile.
    let name = dir_name(dir);
    let live = dir.parent() == Some(root);
    if live && read_current(root).as_deref() == Some(name.as_str()) {
        let next = list_profiles(root)?.into_iter().find(|p| !p.setup_incomplete).map(|p| p.name);
        match &next {
            Some(n) => write_current(root, n)?,
            None => {
                let _ = fs::remove_file(root.join("current"));
            }
        }
        report.new_current = Some(next);
    }
    Ok(report)
}

/// The confirmed delete: `typed` must be the plan's confirm text exactly.
/// Tickets move first (if `move_tickets_to` names a target), then the wipe.
pub fn delete_profile(
    root: &Path,
    plan: &DeletePlan,
    typed: &str,
    move_tickets_to: Option<&str>,
    opts: WipeOptions,
) -> Result<(Option<TicketMove>, WipeReport)> {
    ensure!(
        typed == plan.confirm_text(),
        "confirmation does not match: type '{}' exactly",
        plan.confirm_text()
    );
    let moved = match move_tickets_to {
        // Nothing movable (or a wallet no longer readable after a partial
        // wipe): skip rather than fail the retry.
        Some(_) if plan.movable_tickets == 0 => None,
        Some(target) => {
            ensure!(
                plan.ticket_targets.iter().any(|t| t == target),
                "'{target}' cannot take this profile's tickets (not a complete profile on the same pool)"
            );
            let to = profile_dir(root, target, false)?;
            Some(move_tickets(&Home::new(plan.dir.clone()), &Home::new(to))?)
        }
        None => None,
    };
    Ok((moved, wipe_profile(root, &plan.dir, opts)?))
}

/// The account's remaining STRK balance, in fri: shown before a delete,
/// never moved. Network; best effort.
pub fn account_balance_fri(plan: &DeletePlan) -> Result<u128> {
    let address = plan.account_address.as_deref().context("the account's address is unknown")?;
    let rpc = Home::new(plan.dir.clone())
        .load_config()
        .map(|c| c.rpc_url)
        .ok()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| crate::config::SEPOLIA_RPC_DEFAULT.into());
    crate::setup::read_balance_fri(&crate::chain::Chain::new(&rpc, ""), address)
}

/// `12.3456 STRK` (truncated to 4 decimals).
pub fn strk_label(fri: u128) -> String {
    const ONE: u128 = 1_000_000_000_000_000_000;
    format!("{}.{:04} STRK", fri / ONE, (fri % ONE) / (ONE / 10_000))
}

#[derive(Debug, Clone, Default)]
pub struct PanicReport {
    pub profiles: usize,
    pub keys_shredded: usize,
    pub account_keys_removed: Vec<String>,
    /// What could not be done; everything else still was.
    pub errors: Vec<String>,
}

/// The panic wipe: every identity on this machine, at once, offline, with
/// no questions. Order is by what matters most if it is interrupted:
///
///   1. every profile key in the Keychain (all sealed files under any root
///      become unreadable at once) and the app lock;
///   2. each profile's account entry in sncast's accounts file;
///   3. what zkmsg owns under the root: every `.zkmsg-<name>` profile, the
///      archive, `current`, and a legacy flat profile's own files; then the
///      root itself if that left it empty. Nothing else under the root is
///      touched, whatever `--home` pointed at.
///
/// It keeps going past a failed step and reports what failed.
pub fn panic_wipe(root: &Path) -> Result<PanicReport> {
    let dirs = all_profile_dirs(root);
    let mut accounts: Vec<String> = dirs.iter().filter_map(|d| profile_account(d)).collect();
    accounts.sort();
    accounts.dedup();
    let mut report = PanicReport { profiles: dirs.len(), ..Default::default() };

    match crate::vault::shred_all() {
        Ok(n) => report.keys_shredded = n,
        Err(e) => report.errors.push(format!("profile keys: {e:#}")),
    }
    if let Err(e) = crate::applock::destroy() {
        report.errors.push(format!("app lock: {e:#}"));
    }
    match sncast_accounts_path() {
        Ok(path) => {
            for account in &accounts {
                match remove_sncast_account(&path, account) {
                    Ok(true) => report.account_keys_removed.push(account.clone()),
                    Ok(false) => {}
                    Err(e) => report.errors.push(format!("sncast account {account}: {e:#}")),
                }
            }
        }
        Err(e) => report.errors.push(format!("sncast accounts file: {e:#}")),
    }
    for path in owned_entries(root) {
        let removed = if path.is_dir() { fs::remove_dir_all(&path) } else { fs::remove_file(&path) };
        if let Err(e) = removed {
            report.errors.push(format!("removing {}: {e}", path.display()));
        }
    }
    // Only if empty: never a directory holding anything zkmsg did not make.
    let archive = root.join(ARCHIVE_DIR);
    if archive.is_dir() {
        let _ = fs::remove_file(archive.join(".DS_Store"));
        let _ = fs::remove_dir(&archive);
    }
    let _ = fs::remove_file(root.join(".DS_Store")).ok().filter(|_| is_empty_but_ds_store(root));
    let _ = fs::remove_dir(root);
    Ok(report)
}

fn is_empty_but_ds_store(dir: &Path) -> bool {
    fs::read_dir(dir).map(|rd| rd.flatten().all(|e| e.file_name() == ".DS_Store")).unwrap_or(false)
}

/// The files and dirs under `root` that zkmsg made: profile dirs (live and
/// archived), `current`, and a legacy flat profile's files at the root.
fn owned_entries(root: &Path) -> Vec<PathBuf> {
    let mut out = all_profile_dirs(root);
    if root.join("current").is_file() {
        out.push(root.join("current"));
    }
    if root.join("config.json").is_file() {
        const LEGACY: [&str; 13] = [
            "config.json", "keys.json", "sends", "inbox.json", "proofs", "vault.json", "tickets.json",
            "quota.json", "setup.json", "daemon-token", "sync-cache.json", "registrations.json", "inbox-cache.json",
        ];
        for name in LEGACY {
            let p = root.join(name);
            if p.symlink_metadata().is_ok() {
                out.push(p);
            }
        }
        if let Ok(rd) = fs::read_dir(root) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                if n.starts_with("tickets-") && n.ends_with(".json") {
                    out.push(e.path());
                }
            }
        }
    }
    out
}

/// What a PIN-checked panic wipe did.
#[derive(Debug, Clone)]
pub enum PanicAttempt {
    Wiped(PanicReport),
    /// Wrong PIN: counted like any unlock attempt; nothing wiped.
    Wrong { attempts_left: u32, wait_secs: u64 },
    /// Too soon after wrong PINs; nothing checked or counted.
    Wait { secs: u64 },
}

/// The panic wipe behind the app PIN (owner decision 2026-10-08: a wipe
/// needs the unlock PIN as a check). The PIN goes through the same attempt
/// counter as unlocking, so a wipe prompt is no free guessing oracle; the
/// 10th wrong PIN in a row wipes anyway. Before any PIN was ever set there
/// is nothing to check, and `pin` is ignored.
pub fn panic_wipe_with_pin(root: &Path, pin: &str) -> Result<PanicAttempt> {
    use crate::applock::{self, LockState, Unlock};
    if applock::state()? == LockState::NotSet {
        return Ok(PanicAttempt::Wiped(panic_wipe(root)?));
    }
    Ok(match applock::unlock(pin, root)? {
        Unlock::Unlocked => PanicAttempt::Wiped(panic_wipe(root)?),
        Unlock::Wiped { errors } => PanicAttempt::Wiped(PanicReport { errors, ..Default::default() }),
        Unlock::Wrong { attempts_left, wait_secs } => PanicAttempt::Wrong { attempts_left, wait_secs },
        Unlock::Wait { secs } => PanicAttempt::Wait { secs },
    })
}

pub fn sncast_accounts_path() -> Result<PathBuf> {
    // Tests must never rewrite the real accounts file.
    if cfg!(test) {
        return Ok(std::env::temp_dir().join("zkmsg-test-no-such-sncast-accounts.json"));
    }
    Ok(PathBuf::from(std::env::var("HOME")?)
        .join(".starknet_accounts/starknet_open_zeppelin_accounts.json"))
}

/// Removes `account` from the Sepolia section of sncast's accounts file
/// (the only network zkmsg uses: a same-named mainnet account is not
/// ours), rewriting it atomically with its permissions kept. Returns
/// whether it was there.
pub fn remove_sncast_account(path: &Path, account: &str) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let mut raw: Value = serde_json::from_str(&fs::read_to_string(path)?)
        .with_context(|| format!("reading {}", path.display()))?;
    let found = raw
        .get_mut("alpha-sepolia")
        .and_then(Value::as_object_mut)
        .is_some_and(|accounts| accounts.remove(account).is_some());
    if found {
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(path)?.permissions().mode() & 0o777
        };
        #[cfg(not(unix))]
        let mode = 0o600;
        crate::config::write_atomic(path, serde_json::to_string_pretty(&raw)?.as_bytes(), mode)?;
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Keys};

    const STORE: &str = crate::config::SEPOLIA_POOL_V4;

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zkmsg-wipe-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A complete profile with sealed keys, on `store`, using `account`.
    fn mk(root: &Path, name: &str, handle: Option<&str>, account: &str, store: &str) -> Home {
        let home = Home::new(root.join(format!("{PROFILE_PREFIX}{name}")));
        let config = Config {
            account: account.into(),
            store: store.into(),
            ..Config::default_sepolia(Path::new("/r"))
        };
        home.save_config(&config).unwrap();
        home.save_new_keys(&Keys {
            scan_priv: "0x5".into(),
            scan_pub: "0x6".into(),
            handle: handle.map(String::from),
            leaf_index: Some(0),
            kem_seed: None,
            member_secret: None,
        })
        .unwrap();
        home
    }

    fn wallet_with(home: &Home, states: &[TicketState]) -> Wallet {
        let mut w = Wallet { store: STORE.into(), tickets: vec![] };
        w.mint(states.len()).unwrap();
        for (t, s) in w.tickets.iter_mut().zip(states) {
            t.state = s.clone();
        }
        w.save(home).unwrap();
        w
    }

    fn reserved(id: &str) -> TicketState {
        TicketState::Reserved { send_id: id.into() }
    }

    /// A send state whose publish was (or was not) submitted.
    fn send(home: &Home, id: &str, submitted: bool) {
        let mut s = SendState::new_virtual_plan(
            id.into(),
            "bob".into(),
            "00".into(),
            ("0x1".into(), "0x2".into(), "0x3".into()),
            1,
        );
        s.mark_done(0, None, None);
        s.mark_done(1, None, None);
        if submitted {
            s.record_submission(2, "0xabc".into());
        }
        s.save(home).unwrap();
    }

    #[test]
    fn plan_reads_tickets_targets_and_shared_accounts() {
        let root = tmp("plan");
        let carol = mk(&root, "carol", Some("carol"), "acct-carol", STORE);
        mk(&root, "mode", Some("mode"), "deployer", STORE);
        mk(&root, "old", None, "deployer", "0x123"); // another store: no target
        send(&carol, "s-unsent", false);
        send(&carol, "s-sent", true);
        wallet_with(
            &carol,
            &[
                TicketState::Unspent,
                TicketState::Pending,
                reserved("s-unsent"),
                reserved("s-sent"),
                TicketState::Spent { tx: None },
            ],
        );
        let plan = plan_delete(&root, "carol", false).unwrap();
        assert_eq!(plan.handle.as_deref(), Some("carol"));
        assert_eq!(plan.confirm_text(), "carol");
        assert_eq!((plan.movable_tickets, plan.tickets_in_flight), (3, 1));
        assert_eq!(plan.ticket_targets, vec!["mode".to_string()]);
        assert!(plan.account_shared_with.is_empty());
        assert_eq!(plan.incomplete_sends, 2);

        let plan = plan_delete(&root, "mode", false).unwrap();
        assert_eq!(plan.account_shared_with, vec!["old".to_string()]);
        assert!(!plan.removes_account_key(&WipeOptions::default()));
        // No handle: the profile name confirms.
        assert_eq!(plan_delete(&root, "old", false).unwrap().confirm_text(), "old");
        assert!(plan_delete(&root, "ghost", false).is_err());
        assert!(plan_delete(&root, "../x", false).is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn tickets_move_once_and_only_within_a_pool() {
        let root = tmp("move");
        let carol = mk(&root, "carol", Some("carol"), "a1", STORE);
        let mode = mk(&root, "mode", Some("mode"), "a2", STORE);
        let other = mk(&root, "other", Some("other"), "a3", "0x123");
        send(&carol, "s-unsent", false);
        send(&carol, "s-sent", true);
        let src = wallet_with(
            &carol,
            &[
                TicketState::Unspent,
                TicketState::Pending,
                reserved("s-unsent"),
                reserved("s-sent"),
                TicketState::Spent { tx: None },
            ],
        );
        wallet_with(&mode, &[TicketState::Unspent]);

        assert!(move_tickets(&carol, &other).is_err(), "different store refused");
        let r = move_tickets(&carol, &mode).unwrap();
        assert_eq!(r, TicketMove { moved: 3, already_there: 0, left_in_flight: 1 });
        let got = Wallet::load(&mode, STORE).unwrap();
        assert_eq!(got.tickets.len(), 4);
        let c = got.counts();
        assert_eq!((c.unspent, c.pending, c.reserved), (3, 1, 0), "reserved moves as unspent");
        for i in [0, 1, 2] {
            assert!(got.tickets.iter().any(|t| t.secret == src.tickets[i].secret));
        }
        // Again (a crash between move and wipe): nothing duplicated.
        let r = move_tickets(&carol, &mode).unwrap();
        assert_eq!((r.moved, r.already_there), (0, 3));
        assert_eq!(Wallet::load(&mode, STORE).unwrap().tickets.len(), 4);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn wipe_shreds_removes_and_moves_current() {
        let root = tmp("wipe");
        let carol = mk(&root, "carol", Some("carol"), "a1", STORE);
        mk(&root, "mode", Some("mode"), "a2", STORE);
        wallet_with(&carol, &[TicketState::Unspent]);
        send(&carol, "s1", false);
        fs::create_dir_all(carol.sends_dir().join("s1")).unwrap();
        fs::write(carol.sends_dir().join("s1/proof.json"), "{}").unwrap();
        write_current(&root, "carol").unwrap();

        // A copy of the sealed keys taken before the wipe (what an SSD keeps).
        let leftover = fs::read(carol.keys_path()).unwrap();
        let opts = WipeOptions { delete_account_key: false };
        let r = wipe_profile(&root, &carol.dir, opts).unwrap();
        assert!(r.shredded);
        assert_eq!(r.new_current, Some(Some("mode".into())));
        assert!(!carol.dir.exists());
        assert_eq!(read_current(&root).as_deref(), Some("mode"));
        // The lingering bytes no longer open: write them back and try.
        fs::create_dir_all(&carol.dir).unwrap();
        fs::write(carol.keys_path(), &leftover).unwrap();
        assert!(carol.load_keys().is_err());
        fs::remove_dir_all(&carol.dir).unwrap();

        // The last profile: `current` goes away.
        let mode = Home::new(root.join(".zkmsg-mode"));
        let r = wipe_profile(&root, &mode.dir, opts).unwrap();
        assert_eq!(r.new_current, Some(None));
        assert!(!root.join("current").exists());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn delete_requires_the_exact_handle_and_moves_tickets_first() {
        let root = tmp("delete");
        let carol = mk(&root, "carol", Some("carol"), "a1", STORE);
        let mode = mk(&root, "mode", Some("mode"), "a2", STORE);
        wallet_with(&carol, &[TicketState::Unspent, TicketState::Unspent]);
        let plan = plan_delete(&root, "carol", false).unwrap();
        let opts = WipeOptions { delete_account_key: false };
        for wrong in ["Carol", "carol ", "", "mode"] {
            assert!(delete_profile(&root, &plan, wrong, None, opts).is_err());
        }
        assert!(carol.dir.exists(), "nothing touched on a mismatch");
        assert!(delete_profile(&root, &plan, "carol", Some("ghost"), opts).is_err());
        assert!(carol.dir.exists());

        let (moved, report) = delete_profile(&root, &plan, "carol", Some("mode"), opts).unwrap();
        assert_eq!(moved.unwrap().moved, 2);
        assert!(report.shredded && !carol.dir.exists());
        assert_eq!(Wallet::load(&mode, STORE).unwrap().counts().unspent, 2);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn archived_profiles_can_be_deleted() {
        let root = tmp("archived");
        mk(&root, "burner-aa11bb", Some("burner-aa11bb"), "zkmsg-burner-aa11bb", STORE);
        crate::profiles::archive_profile(&root, "burner-aa11bb").unwrap();
        assert!(plan_delete(&root, "burner-aa11bb", false).is_err(), "not live");
        let plan = plan_delete(&root, "burner-aa11bb", true).unwrap();
        assert!(plan.archived);
        let opts = WipeOptions { delete_account_key: false };
        delete_profile(&root, &plan, "burner-aa11bb", None, opts).unwrap();
        assert!(crate::profiles::list_archived(&root).unwrap().is_empty());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn same_name_live_and_archived_are_never_confused() {
        let root = tmp("collide");
        mk(&root, "carol", Some("carol"), "a1", STORE);
        crate::profiles::archive_profile(&root, "carol").unwrap();
        let live = mk(&root, "carol", Some("carol"), "a2", STORE);
        write_current(&root, "carol").unwrap();
        let opts = WipeOptions { delete_account_key: false };
        let plan = plan_delete(&root, "carol", true).unwrap();
        delete_profile(&root, &plan, "carol", None, opts).unwrap();
        assert!(live.load_keys().is_ok(), "the live carol is untouched");
        assert_eq!(read_current(&root).as_deref(), Some("carol"));
        assert!(crate::profiles::list_archived(&root).unwrap().is_empty());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_copied_profile_keeps_its_shared_key() {
        let root = tmp("copy");
        let carol = mk(&root, "carol", Some("carol"), "a1", STORE);
        let copy = Home::new(root.join(".zkmsg-carol-copy"));
        fs::create_dir_all(&copy.dir).unwrap();
        for f in ["config.json", "keys.json", "vault.json"] {
            fs::copy(carol.dir.join(f), copy.dir.join(f)).unwrap();
        }
        let plan = plan_delete(&root, "carol-copy", false).unwrap();
        assert_eq!(plan.key_shared_with, vec!["carol".to_string()]);
        let opts = WipeOptions { delete_account_key: false };
        let (_, r) = delete_profile(&root, &plan, "carol", None, opts).unwrap();
        assert!(!r.shredded && !copy.dir.exists());
        assert!(carol.load_keys().is_ok(), "the original still opens");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn panic_wipe_takes_everything_offline() {
        let root = tmp("panic");
        let carol = mk(&root, "carol", Some("carol"), "a1", STORE);
        mk(&root, "mode", Some("mode"), "a2", STORE);
        mk(&root, "burner-aa11bb", None, "a3", STORE);
        crate::profiles::archive_profile(&root, "burner-aa11bb").unwrap();
        wallet_with(&carol, &[TicketState::Unspent]);
        write_current(&root, "carol").unwrap();
        crate::applock::set_pin("123456", &root).unwrap();
        let leftover = fs::read(carol.keys_path()).unwrap();

        let r = panic_wipe(&root).unwrap();
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert_eq!((r.profiles, r.keys_shredded), (3, 3));
        assert!(!root.exists(), "nothing else was there: the root goes too");
        assert_eq!(crate::applock::state().unwrap(), crate::applock::LockState::NotSet);
        // Lingering sealed bytes no longer open.
        fs::create_dir_all(&carol.dir).unwrap();
        fs::write(carol.keys_path(), &leftover).unwrap();
        assert!(carol.load_keys().is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn panic_wipe_never_touches_what_zkmsg_did_not_make() {
        let root = tmp("panic-foreign");
        mk(&root, "carol", Some("carol"), "a1", STORE);
        fs::write(root.join("thesis.pdf"), "mine").unwrap();
        fs::create_dir_all(root.join("photos")).unwrap();
        fs::write(root.join("photos/a.jpg"), "x").unwrap();
        fs::create_dir_all(root.join("archive")).unwrap();
        fs::write(root.join("archive/notes.txt"), "keep").unwrap();
        let r = panic_wipe(&root).unwrap();
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert!(!root.join(".zkmsg-carol").exists());
        assert_eq!(fs::read_to_string(root.join("thesis.pdf")).unwrap(), "mine");
        assert!(root.join("photos/a.jpg").exists());
        assert!(root.join("archive/notes.txt").exists());

        // An empty `--home` (no zkmsg in it at all) is left exactly as it was.
        let empty = tmp("panic-empty");
        fs::write(empty.join("doc.txt"), "x").unwrap();
        panic_wipe(&empty).unwrap();
        assert!(empty.join("doc.txt").exists());

        // A legacy flat profile at the root: its own files only.
        let flat = tmp("panic-flat");
        fs::write(flat.join("config.json"), "{}").unwrap();
        fs::write(flat.join("keys.json"), "{}").unwrap();
        fs::write(flat.join("tickets-050f.json"), "{}").unwrap();
        fs::write(flat.join("other.txt"), "keep").unwrap();
        panic_wipe(&flat).unwrap();
        assert!(!flat.join("keys.json").exists() && !flat.join("tickets-050f.json").exists());
        assert!(flat.join("other.txt").exists());
        for d in [root, empty, flat] {
            fs::remove_dir_all(d).unwrap();
        }
    }

    #[test]
    fn the_panic_wipe_needs_the_pin() {
        let root = tmp("panic-pin");
        let carol = mk(&root, "carol", Some("carol"), "a1", STORE);
        crate::applock::set_pin("123456", &root).unwrap();
        crate::applock::lock();
        assert!(matches!(
            panic_wipe_with_pin(&root, "000000").unwrap(),
            PanicAttempt::Wrong { attempts_left: 9, .. }
        ));
        assert!(carol.dir.exists(), "a wrong PIN wipes nothing");
        assert!(matches!(panic_wipe_with_pin(&root, "123456").unwrap(), PanicAttempt::Wiped(r) if r.errors.is_empty()));
        assert!(!carol.dir.exists());
        // No PIN ever set: nothing to check.
        let fresh = tmp("panic-nopin");
        mk(&fresh, "x", None, "a9", STORE);
        assert!(matches!(panic_wipe_with_pin(&fresh, "").unwrap(), PanicAttempt::Wiped(_)));
        assert!(!fresh.join(".zkmsg-x").exists());
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&fresh);
    }

    #[test]
    fn strk_labels() {
        assert_eq!(strk_label(0), "0.0000 STRK");
        assert_eq!(strk_label(3_000_000_000_000_000_000), "3.0000 STRK");
        assert_eq!(strk_label(83_123_456_789_000_000_000), "83.1234 STRK");
    }

    #[test]
    fn sncast_entry_removed_with_others_and_mode_kept() {
        let dir = tmp("sncast");
        let path = dir.join("accounts.json");
        fs::write(
            &path,
            r#"{"alpha-sepolia":{"keep":{"address":"0x1","private_key":"0x2"},
                "zkmsg-burner-aa11bb":{"address":"0x3","private_key":"0x4"}},
                "alpha-mainnet":{"keep":{"address":"0x5"},
                "zkmsg-burner-aa11bb":{"address":"0x6"}}}"#,
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(remove_sncast_account(&path, "zkmsg-burner-aa11bb").unwrap());
        assert!(!remove_sncast_account(&path, "zkmsg-burner-aa11bb").unwrap());
        let v: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(v["alpha-sepolia"]["zkmsg-burner-aa11bb"].is_null());
        assert_eq!(v["alpha-sepolia"]["keep"]["private_key"], "0x2");
        assert_eq!(v["alpha-mainnet"]["keep"]["address"], "0x5");
        assert_eq!(v["alpha-mainnet"]["zkmsg-burner-aa11bb"]["address"], "0x6", "other networks untouched");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert!(!remove_sncast_account(&dir.join("missing.json"), "x").unwrap());
        fs::remove_dir_all(&dir).unwrap();
    }
}
