//! The eframe app shell: a tab bar plus a right-aligned active-profile
//! control, delegating all per-identity rendering to the active
//! `ProfileSession`. On a profile-root launch the control is an interactive
//! picker that switches profiles; on a bare-profile launch (no root to scan)
//! it is a static name label. When no profile is open (a profile root with no
//! `current`) the central panel lists the discovered profiles as buttons.

use std::path::PathBuf;

use eframe::egui;

use zkmsg_core::config::Home;
use zkmsg_core::profiles::{
    HomeKind, LegacySource, PROFILE_PREFIX, ProfileEntry, classify_home, detect_legacy,
    execute_migration, list_profiles, plan_migration, write_current,
};

use crate::migrate_view::{self, MigrateAction, MigrationUi};
use crate::session::{ProfileSession, Tab};

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
        }
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
    ) -> Option<(String, PathBuf)> {
        let mut request = None;
        ui.add_enabled_ui(!in_flight, |ui| {
            egui::ComboBox::from_id_salt("profile_picker").selected_text(active_name).show_ui(
                ui,
                |ui| {
                    self.profiles =
                        self.root.as_deref().map(list_profiles).and_then(Result::ok).unwrap_or_default();
                    for entry in &self.profiles {
                        if entry.setup_incomplete {
                            // The setup wizard is Task 7; until then an
                            // unfinished profile can't be opened, so show it
                            // grayed and unselectable rather than hiding it.
                            ui.add_enabled(
                                false,
                                egui::SelectableLabel::new(
                                    false,
                                    format!("{} (setup incomplete)", entry.name),
                                ),
                            );
                            continue;
                        }
                        let selected = entry.name == active_name;
                        if ui.selectable_label(selected, &entry.name).clicked() && !selected {
                            request = Some((entry.name.clone(), entry.dir.clone()));
                        }
                    }
                },
            );
        });
        if in_flight {
            ui.label("send in progress");
        }
        // A switch that failed to persist `current` leaves the old session
        // active, so surface its error next to the picker rather than in the
        // no-session central panel (which this frame won't render).
        if let Some(err) = &self.picker_error {
            ui.colored_label(egui::Color32::RED, err.as_str());
        }
        request
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
            MigrateAction::NotNow => self.migration = None,
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
                    let _ = write_current(&root, name);
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
        let session_info = self.session.as_ref().map(|s| (s.name.clone(), s.work_in_flight()));
        let mut switch_request: Option<(String, PathBuf)> = None;
        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if let Some(session) = &mut self.session {
                    ui.selectable_value(&mut session.tab, Tab::Status, "Status");
                    ui.selectable_value(&mut session.tab, Tab::Compose, "Compose");
                    ui.selectable_value(&mut session.tab, Tab::Inbox, "Inbox");
                }
                if let Some((active_name, in_flight)) = &session_info {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // A root launch scans children, so it gets the switcher;
                        // a bare-profile launch has no root to scan and keeps the
                        // static label.
                        if self.root.is_some() {
                            switch_request = self.profile_picker(ui, active_name, *in_flight);
                        } else {
                            ui.label(active_name);
                        }
                    });
                }
            });
        });
        if let Some((name, dir)) = switch_request {
            self.switch_profile(ctx, name, dir);
        }

        if let Some(session) = &mut self.session {
            session.pending_banner(ctx);
        }

        // Which profile the picker (no-session branch) wants opened —
        // collected inside the closure and acted on after it, since
        // `open_session` needs `&mut self` while the closure borrows fields.
        let mut open_request = None;
        egui::CentralPanel::default().show(ctx, |ui| match &mut self.session {
            Some(session) => session.render(ui, ctx, &self.repo_root),
            None => {
                ui.vertical_centered(|ui| {
                    ui.label("no profile selected");
                    if let Some(err) = &self.picker_error {
                        ui.colored_label(egui::Color32::RED, err.as_str());
                    }
                    for entry in &self.profiles {
                        if ui.button(&entry.name).clicked() {
                            open_request = Some((entry.name.clone(), Home::new(entry.dir.clone())));
                        }
                    }
                });
            }
        });
        if let Some((name, home)) = open_request {
            self.open_session(ctx, name, home);
        }

        if let Some(session) = &self.session {
            session.tick_repaint(ctx);
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
