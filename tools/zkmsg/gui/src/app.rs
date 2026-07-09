//! The eframe app shell: a tab bar plus a right-aligned active-profile
//! control, delegating all per-identity rendering to the active
//! `ProfileSession`. On a profile-root launch the control is an interactive
//! picker that switches profiles; on a bare-profile launch (no root to scan)
//! it is a static name label. When no profile is open (a profile root with no
//! `current`) the central panel lists the discovered profiles as buttons.

use std::path::{Path, PathBuf};

use eframe::egui;

use zkmsg_core::config::Home;
use zkmsg_core::profiles::{
    HomeKind, LegacySource, PROFILE_PREFIX, ProfileEntry, classify_home, detect_legacy,
    execute_migration, list_profiles, plan_migration, write_current,
};

use crate::migrate_view::{self, MigrateAction, MigrationUi};
use crate::retire_view::{RetireOutcome, RetireUi};
use crate::session::{ProfileSession, Tab};
use crate::wizard_view::{WizardCtx, WizardOutcome, WizardUi};

/// What the profile picker requested this frame.
enum PickerAction {
    None,
    /// Switch the active session to an existing (complete) profile.
    Switch(String, PathBuf),
    /// Open the New-profile wizard on a blank form.
    New,
    /// Open the wizard in burner mode (auto-identity, external funding).
    NewBurner,
    /// Resume an incomplete profile's setup wizard (from its checkpoint dir;
    /// the name is read back from `setup.json`).
    Resume(PathBuf),
    /// Retire a burner profile (open the sweep + archive dialog).
    Retire(String, PathBuf),
}

pub struct ZkmsgApp {
    /// `Some` when the launch path was a profile root — the dir under which
    /// `.zkmsg-<name>` children (and `current`) live. `None` for a legacy
    /// single-profile home. Read by the interactive picker (Task 5) to
    /// scope profile creation/switching, and by the migration flow as the
    /// destination root (set to the launch path when migration is pending).
    root: Option<PathBuf>,
    repo_root: PathBuf,
    profiles: Vec<ProfileEntry>,
    session: Option<ProfileSession>,
    picker_error: Option<String>,

    /// The session to open on the first frame. `new` resolves it but has
    /// no `egui::Context` to set the window title, so opening is deferred
    /// to the first `update()` where `open_session` can title the window.
    initial: Option<(String, Home)>,

    /// `Some` when legacy homes were found at the default launch path: the
    /// migration screen renders instead of opening `initial`, until the user
    /// migrates or clicks "Not now". Only ever set for the default home.
    migration: Option<MigrationUi>,

    /// The New-profile wizard, when open. Floats over the active session
    /// (which supplies the funding source account); `running()` folds into
    /// the app-level in-flight guard.
    wizard: Option<WizardUi>,

    /// The burner-retirement dialog, when open. Owned here (not on the
    /// session) because a successful archive drops the very session it may
    /// have been opened from; its sweep folds into `work_in_flight`.
    retire: Option<RetireUi>,
}

impl ZkmsgApp {
    pub fn new(
        launch_path: PathBuf,
        profile_override: Option<String>,
        is_default_home: bool,
    ) -> Self {
        let mut root = None;
        let mut profiles = Vec::new();
        let initial = match classify_home(&launch_path) {
            // A concrete home (or an empty one, where the Init onboarding
            // renders): open it directly, named by its handle.
            HomeKind::Profile(p) | HomeKind::Empty(p) => {
                Some((profile_name(&p), Home::new(p)))
            }
            // A profile root: list the children and open `--profile` (if it
            // names a real one) else `current`, named by its dir suffix. If
            // neither resolves, stay unopened — the picker list renders.
            HomeKind::Root { root: r, current } => {
                profiles = list_profiles(&r).unwrap_or_default();
                let chosen = profile_override
                    .as_ref()
                    .map(|n| r.join(format!("{PROFILE_PREFIX}{n}")))
                    .filter(|p| p.join("config.json").is_file())
                    .or(current);
                root = Some(r);
                chosen.map(|dir| (dir_suffix_name(&dir), Home::new(dir)))
            }
        };

        // Migration is offered only for the default home (no `--home`): scan
        // for legacy layouts and, if any are found, remember the launch path
        // as the destination root so `Migrate` can plan/write against it.
        let migration = is_default_home
            .then(|| detect_legacy(&launch_path))
            .filter(|found| !found.is_empty())
            .map(|found| MigrationUi {
                sources: found
                    .into_iter()
                    .map(|s| {
                        let name = s.suggested_name.clone();
                        (s, name)
                    })
                    .collect(),
                error: None,
            });
        if migration.is_some() {
            root = Some(launch_path.clone());
        }

        Self {
            root,
            repo_root: repo_root(),
            profiles,
            session: None,
            picker_error: None,
            initial,
            migration,
            wizard: None,
            retire: None,
        }
    }

    /// App-level in-flight: a send being prepared/run in the active session,
    /// OR the setup wizard spending. Disables the profile picker and the
    /// Compose send button so no two paid flows overlap.
    fn work_in_flight(&self) -> bool {
        self.session.as_ref().is_some_and(|s| s.work_in_flight())
            || self.wizard.as_ref().is_some_and(|w| w.running())
            || self.retire.as_ref().is_some_and(|r| r.sweeping())
    }

    /// Opens `home` as the active session and retitles the window to name
    /// the profile. The single path through which a session becomes active
    /// (the deferred launch open included), so the title always tracks it.
    pub fn open_session(&mut self, ctx: &egui::Context, name: String, home: Home) {
        ctx.send_viewport_cmd(egui::ViewportCommand::Title(format!("zkmsg — {name}")));
        self.session = Some(ProfileSession::new(name, home));
    }

    /// Renders the top-bar profile switcher (only reached when `root` is
    /// `Some`). `active_name` labels the closed combo; `in_flight` disables
    /// the whole control while a send is running so a switch — which drops
    /// the session mid-pipeline — can't fire. Returns the `(name, dir)` of a
    /// newly selected complete profile, or `None` (including for a click on
    /// the current profile, which is a no-op). Rescans `list_profiles` each
    /// frame the popup is open so freshly created profiles appear without a
    /// relaunch; the scan is cheap local fs reads.
    fn profile_picker(
        &mut self,
        ui: &mut egui::Ui,
        active_name: &str,
        in_flight: bool,
        source_available: bool,
    ) -> PickerAction {
        let mut action = PickerAction::None;
        ui.add_enabled_ui(!in_flight, |ui| {
            egui::ComboBox::from_id_salt("profile_picker").selected_text(active_name).show_ui(
                ui,
                |ui| {
                    self.profiles =
                        self.root.as_deref().map(list_profiles).and_then(Result::ok).unwrap_or_default();
                    for entry in &self.profiles {
                        if entry.setup_incomplete {
                            // Selectable-to-resume: clicking reopens the
                            // wizard on this profile's checkpoint. Resuming
                            // still needs a funding source (the active
                            // profile's config) to continue, so gate it the
                            // same way as New.
                            // An external-funding run parked at its unfunded
                            // Fund step reads as "(awaiting funding)"; anything
                            // else is a plain "(setup incomplete)".
                            let label = match zkmsg_core::setup::SetupState::load(&entry.dir) {
                                Ok(s)
                                    if s.fund_mode == zkmsg_core::setup::FundMode::External
                                        && s.steps.iter().any(|st| {
                                            matches!(
                                                st.kind,
                                                zkmsg_core::setup::SetupStepKind::Fund
                                            ) && !st.done
                                        }) =>
                                {
                                    format!("{} (awaiting funding)", entry.name)
                                }
                                _ => format!("{} (setup incomplete)", entry.name),
                            };
                            let resume = ui.add_enabled(
                                source_available,
                                egui::SelectableLabel::new(false, label),
                            );
                            if resume.clicked() {
                                action = PickerAction::Resume(entry.dir.clone());
                            }
                            if !source_available {
                                resume.on_hover_text(
                                    "open a profile with a funded account first — it funds the resume",
                                );
                            }
                            continue;
                        }
                        // A burner entry gets a small "retire…" button beside
                        // its row; the config read is a cheap local fs read.
                        let is_burner = Home::new(entry.dir.clone())
                            .load_config()
                            .map(|c| c.burner)
                            .unwrap_or(false);
                        ui.horizontal(|ui| {
                            let selected = entry.name == active_name;
                            // Task 8 replaces `&entry.name` with a name+handle
                            // picker_label helper; inline until then.
                            if ui.selectable_label(selected, &entry.name).clicked() && !selected {
                                action = PickerAction::Switch(entry.name.clone(), entry.dir.clone());
                            }
                            if is_burner && ui.small_button("retire…").clicked() {
                                action = PickerAction::Retire(entry.name.clone(), entry.dir.clone());
                            }
                        });
                    }
                    ui.separator();
                    // New profile needs a funded source account (the active
                    // profile's) to pay the create/fund/deploy; disabled with
                    // a tooltip when the active session has no config.
                    let new = ui.add_enabled(
                        source_available,
                        egui::SelectableLabel::new(false, "New profile…"),
                    );
                    if new.clicked() {
                        action = PickerAction::New;
                    }
                    if !source_available {
                        new.on_hover_text(
                            "open a profile with a funded account first — it funds the new one",
                        );
                    }
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
                },
            );
        });
        if in_flight {
            ui.label("busy");
        }
        // A switch that failed to persist `current` leaves the old session
        // active, so surface its error next to the picker rather than in the
        // no-session central panel (which this frame won't render).
        if let Some(err) = &self.picker_error {
            ui.colored_label(egui::Color32::RED, err.as_str());
        }
        action
    }

    /// Applies a picker selection: persists `current` BEFORE rebuilding the
    /// session, so a crash mid-switch still points the next launch at the
    /// chosen profile. If `current` can't be written the switch is aborted
    /// (the old session stays active) and the error is surfaced — a silent
    /// switch whose choice didn't persist would confuse the next launch.
    fn switch_profile(&mut self, ctx: &egui::Context, name: String, dir: PathBuf) {
        let Some(root) = self.root.clone() else { return };
        if let Err(e) = write_current(&root, &name) {
            self.picker_error = Some(format!("failed to switch profile: {e:#}"));
            return;
        }
        self.picker_error = None;
        self.open_session(ctx, name, Home::new(dir));
    }

    /// Drives the New-profile wizard for one frame. Extracts the funding
    /// source (the active session's account + rpc) so the wizard can borrow
    /// them without a `self` borrow conflict, then acts on its outcome: on
    /// completion, persist `current`, rescan, and open the new profile.
    fn update_wizard(&mut self, ctx: &egui::Context) {
        let Some(root) = self.root.clone() else {
            self.wizard = None;
            return;
        };
        let Some((source_account, rpc_url)) = self
            .session
            .as_ref()
            .and_then(|s| s.config.as_ref())
            .map(|c| (c.account.clone(), c.rpc_url.clone()))
        else {
            // No funding source (session gone / unconfigured) — can't run a
            // setup; drop the wizard rather than spend from nothing.
            self.wizard = None;
            return;
        };
        let repo_root = self.repo_root.clone();
        // A send in flight on the funding account blocks the wizard's own
        // spend — the mirror of the `locked` flag that blocks the send button
        // while the wizard runs. Also fold in the status/register worker: a
        // register is another paid tx from the same account, so it must block
        // the setup spend too. This over-locks during a plain status refresh
        // (same `busy` flag) — the intended safe direction.
        let session_busy = self
            .session
            .as_ref()
            .is_some_and(|s| s.work_in_flight() || s.worker_busy());
        let Some(mut wizard) = self.wizard.take() else { return };
        let outcome = wizard.update(&WizardCtx {
            egui_ctx: ctx,
            root: &root,
            repo_root: &repo_root,
            rpc_url: &rpc_url,
            source_account: &source_account,
            session_busy,
        });
        match outcome {
            WizardOutcome::None => self.wizard = Some(wizard),
            WizardOutcome::Cancelled => {}
            WizardOutcome::Completed { name, dir } => {
                // Surface a failed `current` write the same way the switch path
                // does (picker_error), rather than swallowing it — the profile
                // is fully built, so still open it; only the next-launch default
                // is what didn't persist.
                if let Err(e) = write_current(&root, &name) {
                    self.picker_error = Some(format!("failed to set current profile: {e:#}"));
                }
                self.profiles = list_profiles(&root).unwrap_or_default();
                self.open_session(ctx, name, Home::new(dir));
            }
        }
    }

    /// Renders the migration screen and dispatches the clicked button.
    /// Called instead of the normal frame while `migration` is `Some`.
    fn update_migration(&mut self, ctx: &egui::Context) {
        let mut action = MigrateAction::None;
        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(state) = self.migration.as_mut() {
                action = migrate_view::render(ui, state);
            }
        });
        match action {
            MigrateAction::None => {}
            // Fall through to pre-migration behavior: `initial` opens the
            // legacy home directly on the next frame (it still classifies as
            // a Profile), exactly as if migration had never been detected.
            // Migration detection is the only thing that set `root` to the
            // launch path (a legacy default-home launch has `root = None`), so
            // clearing it restores the static top-bar label — no picker or
            // "New profile…" over an un-migrated root.
            MigrateAction::NotNow => {
                self.migration = None;
                self.root = None;
            }
            MigrateAction::Migrate => self.run_migration(ctx),
        }
    }

    /// Plans and executes the migration from the edited names. On success,
    /// opens the first profile; on error, records it inline and changes
    /// nothing (the executor's renames are per-move, so a mid-way failure
    /// leaves already-moved entries in place — the surfaced error names the
    /// failing move). Only the Task-1 planner/executor touch the filesystem.
    fn run_migration(&mut self, ctx: &egui::Context) {
        let Some(state) = self.migration.as_ref() else { return };
        let Some(root) = self.root.clone() else { return };
        let named: Vec<(LegacySource, String)> = state.sources.clone();
        let planned = plan_migration(&root, &named).and_then(|moves| execute_migration(&moves));
        match planned {
            Ok(()) => {
                self.migration = None;
                // The legacy root's config.json has moved into a child, so the
                // deferred `initial` open would now hit an empty dir — drop it
                // and open the freshly migrated profile instead.
                self.initial = None;
                self.profiles = list_profiles(&root).unwrap_or_default();
                if let Some((_, name)) = named.first() {
                    // Surface a failed `current` write the same way the switch
                    // and wizard-completion paths do — the profiles are fully
                    // migrated, so still open the first; only the next-launch
                    // default is what didn't persist.
                    if let Err(e) = write_current(&root, name) {
                        self.picker_error = Some(format!("failed to set current profile: {e:#}"));
                    }
                    let dir = root.join(format!("{PROFILE_PREFIX}{name}"));
                    self.open_session(ctx, name.clone(), Home::new(dir));
                }
            }
            Err(e) => {
                if let Some(state) = self.migration.as_mut() {
                    state.error = Some(format!("{e:#}"));
                }
            }
        }
    }

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
}

impl eframe::App for ZkmsgApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // A pending migration owns the whole frame: no session opens (not even
        // the deferred `initial`) until the user migrates or clicks "Not now".
        if self.migration.is_some() {
            self.update_migration(ctx);
            return;
        }

        if let Some((name, home)) = self.initial.take() {
            self.open_session(ctx, name, home);
        }

        if let Some(session) = &mut self.session {
            session.poll_all(ctx);
        }

        // The active profile's name + in-flight state, snapshotted so the top
        // bar can render the picker without holding a borrow of `self.session`
        // (the picker mutates `self.profiles` on rescan). A switch selected in
        // the picker is collected here and applied after the panel closes,
        // since `open_session` needs `&mut self`.
        // Snapshotted before the panel closure borrows `self.session`: the
        // app-level in-flight guard (session send OR wizard run) disables the
        // picker, and whether the active session has a config decides if
        // "New profile…" has a funding source.
        let app_busy = self.work_in_flight();
        let source_available = self.session.as_ref().is_some_and(|s| s.config.is_some());
        let active_name = self.session.as_ref().map(|s| s.name.clone());
        let mut picker_action = PickerAction::None;
        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if let Some(session) = &mut self.session {
                    ui.selectable_value(&mut session.tab, Tab::Status, "Status");
                    ui.selectable_value(&mut session.tab, Tab::Compose, "Compose");
                    ui.selectable_value(&mut session.tab, Tab::Inbox, "Inbox");
                }
                if let Some(active_name) = &active_name {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // A root launch scans children, so it gets the switcher;
                        // a bare-profile launch has no root to scan and keeps the
                        // static label.
                        if self.root.is_some() {
                            picker_action = self.profile_picker(
                                ui,
                                active_name,
                                app_busy,
                                source_available,
                            );
                        } else {
                            ui.label(active_name);
                        }
                    });
                }
            });
        });
        match picker_action {
            PickerAction::None => {}
            PickerAction::Switch(name, dir) => self.switch_profile(ctx, name, dir),
            PickerAction::New => {
                self.picker_error = None;
                self.wizard = Some(WizardUi::new_profile());
            }
            PickerAction::NewBurner => {
                self.picker_error = None;
                let reply = self
                    .session
                    .as_ref()
                    .and_then(|s| s.keys.as_ref())
                    .and_then(|k| k.handle.clone());
                self.wizard = Some(WizardUi::new_burner(reply));
            }
            PickerAction::Resume(dir) => match WizardUi::resume(dir) {
                Ok(w) => {
                    self.picker_error = None;
                    self.wizard = Some(w);
                }
                Err(e) => self.picker_error = Some(e),
            },
            PickerAction::Retire(name, dir) => {
                self.picker_error = None;
                let targets = self.retire_targets(&name, &dir);
                self.retire = Some(RetireUi::new(name, dir, targets));
            }
        }

        // The app-level spend lock: a wizard actively spending OR a retire
        // sweep waiting on its receipt. Suppresses the pending-send banner's
        // Resume and disables the Compose spend buttons (and Register), so no
        // paid pipeline races the wizard's funding transfer — or a sweep
        // draining the very burner account a new send would spend from
        // (reachable via the post-send offer: sweep starts → "Compose
        // another" → Send). Computed while `retire` is still in `self`; the
        // dialog's own buttons gate on the separate session+wizard-only
        // `paid_elsewhere`, so this cannot deadlock the dialog itself.
        let locked = self.wizard.as_ref().is_some_and(|w| w.running())
            || self.retire.as_ref().is_some_and(|r| r.sweeping());
        if let Some(session) = &mut self.session {
            session.pending_banner(ctx, locked);
        }

        // Which profile the picker (no-session branch) wants opened —
        // collected inside the closure and acted on after it, since
        // `open_session` needs `&mut self` while the closure borrows fields.
        let mut open_request = None;
        egui::CentralPanel::default().show(ctx, |ui| match &mut self.session {
            Some(session) => session.render(ui, ctx, &self.repo_root, locked),
            None => {
                ui.vertical_centered(|ui| {
                    ui.label("no profile selected");
                    if let Some(err) = &self.picker_error {
                        ui.colored_label(egui::Color32::RED, err.as_str());
                    }
                    for entry in &self.profiles {
                        if entry.setup_incomplete {
                            // An incomplete setup has no config.json — opening
                            // it as a plain session would be a side door around
                            // the wizard's resume (and its spend confirm). It
                            // also can't resume here: resuming needs a funded
                            // source profile, which the no-session state lacks.
                            // Show it disabled; the user opens a complete
                            // profile first, then resumes via the picker.
                            ui.add_enabled(
                                false,
                                egui::Button::new(format!(
                                    "{} (setup incomplete — use the profile menu)",
                                    entry.name
                                )),
                            );
                        } else if ui.button(&entry.name).clicked() {
                            open_request = Some((entry.name.clone(), Home::new(entry.dir.clone())));
                        }
                    }
                });
            }
        });
        if let Some((name, home)) = open_request {
            self.open_session(ctx, name, home);
        }

        // The post-send "Sweep & archive this burner…" button set an offer
        // flag on the session; drain it and open the retire dialog (once,
        // and only under a root — a bare-profile launch has no archive dir).
        if self.session.as_ref().is_some_and(|s| s.retire_offer) {
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

        // The wizard floats over whatever the session rendered; drive it after
        // the central panel so its window lands on top.
        if self.wizard.is_some() {
            self.update_wizard(ctx);
        }

        if let Some(session) = &self.session {
            session.tick_repaint(ctx);
        }

        // Drive the retire dialog last, over everything. `app_busy` here MUST
        // exclude the retire's own sweep — folding `work_in_flight()` in whole
        // (which now counts retire.sweeping()) would disable the dialog's own
        // buttons and never process the sweep's completion, deadlocking it.
        // Snapshot only the session+wizard paid work before the take.
        if let Some(mut retire) = self.retire.take() {
            let paid_elsewhere = self.session.as_ref().is_some_and(|s| s.work_in_flight())
                || self.wizard.as_ref().is_some_and(|w| w.running());
            retire.app_busy = paid_elsewhere;
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
    }
}

/// Display name for a concrete home: a registered handle if `keys.json`
/// carries one, else the `.zkmsg-<suffix>` name, else the dir name.
fn profile_name(dir: &std::path::Path) -> String {
    if let Some(handle) = Home::new(dir.to_path_buf()).load_keys().ok().and_then(|k| k.handle) {
        return handle;
    }
    dir_suffix_name(dir)
}

/// The `.zkmsg-<suffix>` name, falling back to the raw dir name when there
/// is no prefix (a legacy `~/.zkmsg`).
fn dir_suffix_name(dir: &std::path::Path) -> String {
    let fname = dir.file_name().and_then(|s| s.to_str()).unwrap_or("profile");
    fname.strip_prefix(PROFILE_PREFIX).unwrap_or(fname).to_string()
}

/// The repo this binary was built from — `init_identity`'s default
/// config needs it for the bridge/circuit artifact paths. Mirrors
/// cli/src/main.rs's `repo_root()`: `gui/` sits at the same
/// `tools/zkmsg/<crate>/` depth as `cli/`, so the same "../../.." climbs
/// to the repo root.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap_or_else(|_| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
    })
}
