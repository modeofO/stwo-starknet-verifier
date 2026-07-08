//! One profile's live GUI state. Everything that is per-identity —
//! config/keys/status, the inbox, the compose+send flow, and the resume
//! banner — lives here; `ZkmsgApp` (app.rs) owns only the shell (which
//! profile is active, the profile list, the repo root). Switching
//! profiles is drop-this + build-a-fresh-one, so no per-identity state
//! can leak across a switch.
//!
//! The Status tab's onboarding flow lives on this type too (no keys ->
//! Init, keys but no handle -> Register, else the live `StatusReport`);
//! the Compose and Inbox tab methods are `impl ProfileSession` blocks in
//! `compose_view.rs` / `inbox_view.rs`.

use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;

use eframe::egui;
use starknet_types_core::felt::Felt;

use zkmsg_core::app::{RegisterOutcome, StatusReport, pending_sends};
use zkmsg_core::chain::felt_hex;
use zkmsg_core::config::{Config, Home, Keys};
use zkmsg_core::inbox::ReceivedMessage;
use zkmsg_core::state::StepKind;

use crate::send_flow::SendFlow;
use crate::worker::{self, InboxWorkerMsg, PrepareWorkerMsg, ResolveWorkerMsg, StatusWorkerMsg, WorkerMsg};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tab {
    Status,
    Compose,
    Inbox,
}

pub struct ProfileSession {
    /// The active profile's display name — a registered handle, else the
    /// `.zkmsg-<suffix>` name, else the home dir name. Also drives the
    /// window title and the top-bar label.
    pub name: String,
    home: Home,
    pub(crate) config: Option<Config>,
    pub(crate) keys: Option<Keys>,
    pub(crate) tab: Tab,

    account_input: String,
    handle_input: String,

    pub(crate) status: Option<StatusReport>,
    init_pubkey: Option<String>,
    register_outcome: Option<RegisterOutcome>,
    /// Shared across tabs (status + inbox) — each poll routine clears it
    /// on success and sets it on failure, same as the Status tab always did.
    pub(crate) last_error: Option<String>,

    /// Guards the status panel's auto-fetch-on-first-render (below) so a
    /// persistent RPC failure doesn't re-spawn a fetch every frame; once
    /// set, only the Refresh button fires another one.
    fetched_once: bool,
    busy: bool,
    rx: Option<Receiver<StatusWorkerMsg>>,

    pub(crate) inbox: Vec<ReceivedMessage>,
    pub(crate) inbox_loading: bool,
    pub(crate) inbox_rx: Option<Receiver<InboxWorkerMsg>>,
    pub(crate) inbox_auto_refresh: bool,
    /// Set on every scan spawn (manual or auto); the auto-refresh check in
    /// `inbox_tab` reads it to decide if 30s have elapsed.
    pub(crate) last_refresh: Option<std::time::Instant>,

    pub(crate) compose_handle: String,
    pub(crate) compose_text: String,
    pub(crate) compose_resolving: bool,
    /// `None` before a resolve has run; `Some(Err)` renders "unknown
    /// handle" rather than silently leaving the field blank.
    pub(crate) compose_resolved: Option<Result<(Felt, u32), String>>,
    pub(crate) compose_resolve_rx: Option<Receiver<ResolveWorkerMsg>>,
    pub(crate) compose_show_confirm: bool,
    pub(crate) compose_preparing: bool,
    pub(crate) compose_prepare_rx: Option<Receiver<PrepareWorkerMsg>>,
    /// `Some` once `prepare_send` has returned a plan — presence of this
    /// (not `tab`) is what switches the Compose central area to the
    /// progress checklist.
    pub(crate) send_flow: Option<SendFlow>,
    pub(crate) send_rx: Option<Receiver<WorkerMsg>>,
    /// The in-flight (or last) send's id, for the Resume-on-Failed path.
    pub(crate) send_state_id: Option<String>,

    /// Incomplete sends under `home` (id + next-pending step kind),
    /// computed once on launch and refreshed after each send
    /// completes/fails — drives the resume banner. Never rescanned
    /// per-frame.
    pub(crate) pending: Vec<(String, StepKind)>,
}

impl ProfileSession {
    pub fn new(name: String, home: Home) -> Self {
        let config = home.load_config().ok();
        let keys = home.load_keys().ok();
        let pending = pending_sends(&home).unwrap_or_default();
        Self {
            name,
            home,
            config,
            keys,
            tab: Tab::Status,
            account_input: "funded-deployer".to_string(),
            handle_input: String::new(),
            status: None,
            init_pubkey: None,
            register_outcome: None,
            last_error: None,
            fetched_once: false,
            busy: false,
            rx: None,
            inbox: Vec::new(),
            inbox_loading: false,
            inbox_rx: None,
            inbox_auto_refresh: false,
            last_refresh: None,
            compose_handle: String::new(),
            compose_text: String::new(),
            compose_resolving: false,
            compose_resolved: None,
            compose_resolve_rx: None,
            compose_show_confirm: false,
            compose_preparing: false,
            compose_prepare_rx: None,
            send_flow: None,
            send_rx: None,
            send_state_id: None,
            pending,
        }
    }

    /// Drains every worker channel this session may have in flight. Called
    /// once per frame by `ZkmsgApp::update` before rendering.
    pub(crate) fn poll_all(&mut self, ctx: &egui::Context) {
        self.poll_worker();
        self.poll_inbox_worker();
        self.poll_compose_worker(ctx);
        self.poll_send_worker();
    }

    /// Renders the active tab's central content. `repo_root` is the shell's
    /// (see `init_panel` — `init_identity`'s default config needs it).
    pub(crate) fn render(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, repo_root: &Path) {
        match self.tab {
            Tab::Status => self.status_tab(ui, ctx, repo_root),
            Tab::Compose => self.compose_tab(ui, ctx),
            Tab::Inbox => self.inbox_tab(ui, ctx),
        }
    }

    /// Frame-end repaint policy: spin while any worker is in flight, else
    /// wake once a second while inbox auto-refresh is armed, else sleep.
    pub(crate) fn tick_repaint(&self, ctx: &egui::Context) {
        let compose_busy =
            self.compose_resolving || self.compose_preparing || self.send_rx.is_some();
        if self.busy || self.inbox_loading || compose_busy {
            // A scan/call is in flight — repaint every frame so the mpsc
            // channel gets drained promptly once it lands.
            ctx.request_repaint();
        } else if self.inbox_auto_refresh {
            // Idle but armed: wake up periodically to re-check the 30s
            // elapsed-since-last-refresh condition, without busy-spinning.
            ctx.request_repaint_after(std::time::Duration::from_secs(1));
        }
    }

    /// Re-scans `<home>/sends/*.json` for incomplete sends. Cheap local
    /// fs reads (same cost class as `reload_local_state`) — called once on
    /// launch and again after each send finishes, never per-frame.
    pub(crate) fn refresh_pending(&mut self) {
        self.pending = pending_sends(&self.home).unwrap_or_default();
    }

    /// Renders a row per incomplete send above the tab content, if any are
    /// pending. Resume routes through the Compose tab's resume path
    /// (switch to it, then `resume_send`); Dismiss only drops the entry
    /// from this in-memory list — the checkpoint file is left untouched.
    pub(crate) fn pending_banner(&mut self, ctx: &egui::Context) {
        // Never offer Resume while a send is being prepared or run — a
        // second paid pipeline started here would race the active one
        // (double-spend). The banner returns once that send completes.
        if self.work_in_flight() {
            return;
        }
        if self.pending.is_empty() {
            return;
        }
        let mut resume_id = None;
        let mut dismiss_id = None;
        egui::TopBottomPanel::top("pending_banner").show(ctx, |ui| {
            for (id, kind) in &self.pending {
                ui.horizontal(|ui| {
                    ui.label(format!("send {id} stopped at {kind:?}"));
                    if ui.button("Resume").clicked() {
                        resume_id = Some(id.clone());
                    }
                    if ui.button("Dismiss").clicked() {
                        dismiss_id = Some(id.clone());
                    }
                });
            }
        });
        if let Some(id) = resume_id {
            // Drop the banner row the instant Resume is clicked — before the
            // worker starts — so a second click can't re-enter resume_send
            // for the same id (which would spawn a second send and could
            // double-spend on-chain), and so the banner doesn't linger over
            // the Compose progress view for the send it just launched.
            self.pending.retain(|(pid, _)| pid != &id);
            self.tab = Tab::Compose;
            self.resume_send(&id, ctx);
        }
        if let Some(id) = dismiss_id {
            self.pending.retain(|(pid, _)| pid != &id);
        }
    }

    /// Re-reads `config.json`/`keys.json` after a background call wrote
    /// them (init, register). Cheap local fs reads — fine on the UI thread.
    fn reload_local_state(&mut self) {
        self.config = self.home.load_config().ok();
        self.keys = self.home.load_keys().ok();
    }

    /// `Home` has no `Clone`, so worker spawns take the directory and
    /// build a fresh `Home` on the worker thread (see worker.rs).
    pub(crate) fn home_dir(&self) -> PathBuf {
        self.home.dir.clone()
    }

    fn poll_worker(&mut self) {
        let Some(rx) = &self.rx else { return };
        let Ok(msg) = rx.try_recv() else { return };
        self.busy = false;
        self.rx = None;
        match msg {
            StatusWorkerMsg::Status(Ok(report)) => {
                self.status = Some(report);
                self.last_error = None;
            }
            StatusWorkerMsg::Status(Err(e)) => self.last_error = Some(e),
            StatusWorkerMsg::Init(Ok(pubkey)) => {
                self.init_pubkey = Some(felt_hex(&pubkey));
                self.reload_local_state();
                self.last_error = None;
            }
            StatusWorkerMsg::Init(Err(e)) => self.last_error = Some(e),
            StatusWorkerMsg::Register(Ok(outcome)) => {
                self.register_outcome = Some(outcome);
                self.reload_local_state();
                self.last_error = None;
            }
            StatusWorkerMsg::Register(Err(e)) => self.last_error = Some(e),
        }
    }

    fn status_tab(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, repo_root: &Path) {
        if let Some(err) = &self.last_error {
            ui.colored_label(egui::Color32::RED, err.as_str());
            ui.separator();
        }

        if self.keys.is_none() {
            self.init_panel(ui, ctx, repo_root);
            return;
        }
        if self.keys.as_ref().and_then(|k| k.handle.as_ref()).is_none() {
            self.register_panel(ui, ctx);
            return;
        }
        self.status_panel(ui, ctx);
    }

    fn init_panel(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, repo_root: &Path) {
        ui.heading("Set up zkmsg");
        ui.label("No keys found under this home — generate a scan identity to get started.");
        ui.horizontal(|ui| {
            ui.label("sncast account:");
            ui.text_edit_singleline(&mut self.account_input);
        });
        ui.add_enabled_ui(!self.busy, |ui| {
            if ui.button("Init").clicked() {
                self.busy = true;
                self.last_error = None;
                self.rx = Some(worker::spawn_init(
                    self.home.dir.clone(),
                    self.account_input.clone(),
                    repo_root.to_path_buf(),
                    ctx.clone(),
                ));
            }
        });
        if self.busy {
            ui.label("working…");
        }
        if let Some(pubkey) = &self.init_pubkey {
            ui.separator();
            ui.label(format!("scan pubkey: {pubkey}"));
        }
    }

    fn register_panel(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.heading("Register a handle");
        if let Some(scan_pub) = self.keys.as_ref().map(|k| k.scan_pub.clone()) {
            ui.label(format!("scan pubkey: {scan_pub}"));
        }
        ui.horizontal(|ui| {
            ui.label("handle:");
            ui.text_edit_singleline(&mut self.handle_input);
        });
        ui.add_enabled_ui(!self.busy, |ui| {
            if ui.button("Register").clicked() {
                if self.handle_input.trim().is_empty() {
                    self.last_error = Some("handle cannot be empty".to_string());
                } else {
                    self.busy = true;
                    self.last_error = None;
                    self.rx = Some(worker::spawn_register(
                        self.home.dir.clone(),
                        self.handle_input.trim().to_string(),
                        ctx.clone(),
                    ));
                }
            }
        });
        if self.busy {
            ui.label("working… (sends a transaction and waits for the receipt)");
        }
        if let Some(outcome) = &self.register_outcome {
            ui.separator();
            match outcome {
                RegisterOutcome::Registered { tx_hash, leaf_index } => {
                    ui.label(format!("registered — tx {tx_hash}, leaf {leaf_index}"));
                }
                RegisterOutcome::AlreadyRegistered { leaf_index } => {
                    ui.label(format!("already registered — leaf {leaf_index}"));
                }
            }
        }
    }

    fn status_panel(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        // Kick the first live fetch automatically, exactly once; after
        // that (success OR error) only the Refresh button re-fires it —
        // otherwise a persistent RPC failure would re-spawn a fetch on
        // every frame (status stays None on Err, so the naive check
        // would never latch).
        if !self.fetched_once && !self.busy && self.rx.is_none() {
            self.fetched_once = true;
            self.busy = true;
            self.rx = Some(worker::spawn_status(self.home.dir.clone(), ctx.clone()));
        }

        ui.add_enabled_ui(!self.busy, |ui| {
            if ui.button("Refresh").clicked() {
                self.busy = true;
                self.last_error = None;
                self.rx = Some(worker::spawn_status(self.home.dir.clone(), ctx.clone()));
            }
        });
        if self.busy {
            ui.label("refreshing…");
        }
        ui.separator();

        let Some(report) = &self.status else {
            // Local config is cheap and already loaded; show it while the
            // live (networked) report is still in flight.
            if let Some(config) = &self.config {
                ui.label(format!("account: {}", config.account));
                ui.label(format!("registry: {}", config.registry));
                ui.label(format!("store: {}", config.store));
            }
            ui.label("loading live status…");
            return;
        };

        egui::Grid::new("status_grid").num_columns(2).striped(true).show(ui, |ui| {
            ui.label("handle");
            ui.label(report.handle.as_deref().unwrap_or("(not registered)"));
            ui.end_row();

            ui.label("leaf index");
            ui.label(report.leaf_index.map(|i| i.to_string()).unwrap_or_else(|| "-".into()));
            ui.end_row();

            ui.label("scan pubkey");
            ui.label(report.scan_pub.as_deref().unwrap_or("-"));
            ui.end_row();

            ui.label("account");
            ui.label(&report.account);
            ui.end_row();

            ui.label("registry");
            ui.label(&report.registry);
            ui.end_row();

            ui.label("store");
            ui.label(if report.store.is_empty() { "(not deployed)" } else { &report.store });
            ui.end_row();

            ui.label("rpc");
            ui.label(&report.rpc);
            ui.end_row();

            ui.label("messages");
            ui.label(report.n_messages.as_deref().unwrap_or("-"));
            ui.end_row();

            ui.label("balance");
            match report.balance_strk {
                Some(strk) => {
                    ui.label(format!("~{strk} STRK"));
                }
                None => {
                    let e = report.balance_error.as_deref().unwrap_or("?");
                    ui.label(format!("unavailable ({e})"));
                }
            }
            ui.end_row();
        });
    }
}
