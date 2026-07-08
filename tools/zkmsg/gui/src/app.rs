//! The eframe app shell: a tab bar plus a right-aligned active-profile
//! label, delegating all per-identity rendering to the active
//! `ProfileSession`. When no profile is open (a profile root with no
//! `current`) the central panel lists the discovered profiles as buttons.
//! An interactive profile picker is Task 5; here the label is static.

use std::path::PathBuf;

use eframe::egui;

use zkmsg_core::config::Home;
use zkmsg_core::profiles::{HomeKind, PROFILE_PREFIX, ProfileEntry, classify_home, list_profiles};

use crate::session::{ProfileSession, Tab};

pub struct ZkmsgApp {
    /// `Some` when the launch path was a profile root — the dir under which
    /// `.zkmsg-<name>` children (and `current`) live. `None` for a legacy
    /// single-profile home. Read by the interactive picker (Task 5) to
    /// scope profile creation/switching; recorded here now so this shell
    /// already carries it.
    #[allow(dead_code)]
    root: Option<PathBuf>,
    repo_root: PathBuf,
    profiles: Vec<ProfileEntry>,
    session: Option<ProfileSession>,
    picker_error: Option<String>,

    /// The session to open on the first frame. `new` resolves it but has
    /// no `egui::Context` to set the window title, so opening is deferred
    /// to the first `update()` where `open_session` can title the window.
    initial: Option<(String, Home)>,
}

impl ZkmsgApp {
    pub fn new(launch_path: PathBuf, profile_override: Option<String>) -> Self {
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
        Self {
            root,
            repo_root: repo_root(),
            profiles,
            session: None,
            picker_error: None,
            initial,
        }
    }

    /// Opens `home` as the active session and retitles the window to name
    /// the profile. The single path through which a session becomes active
    /// (the deferred launch open included), so the title always tracks it.
    pub fn open_session(&mut self, ctx: &egui::Context, name: String, home: Home) {
        ctx.send_viewport_cmd(egui::ViewportCommand::Title(format!("zkmsg — {name}")));
        self.session = Some(ProfileSession::new(name, home));
    }
}

impl eframe::App for ZkmsgApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some((name, home)) = self.initial.take() {
            self.open_session(ctx, name, home);
        }

        if let Some(session) = &mut self.session {
            session.poll_all(ctx);
        }

        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if let Some(session) = &mut self.session {
                    ui.selectable_value(&mut session.tab, Tab::Status, "Status");
                    ui.selectable_value(&mut session.tab, Tab::Compose, "Compose");
                    ui.selectable_value(&mut session.tab, Tab::Inbox, "Inbox");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(&session.name);
                    });
                }
            });
        });

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
