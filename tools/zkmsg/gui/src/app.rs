//! The eframe app: a Status/Compose/Inbox tab bar, plus the Status tab's
//! onboarding flow (no keys -> Init, keys but no handle -> Register,
//! else the live `StatusReport`). Compose and Inbox are placeholders
//! wired up in later tasks.

use std::path::PathBuf;
use std::sync::mpsc::Receiver;

use eframe::egui;

use zkmsg_core::app::{RegisterOutcome, StatusReport};
use zkmsg_core::chain::felt_hex;
use zkmsg_core::config::{Config, Home, Keys};

use crate::worker::{self, StatusWorkerMsg};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Status,
    Compose,
    Inbox,
}

pub struct ZkmsgApp {
    home: Home,
    repo_root: PathBuf,
    config: Option<Config>,
    keys: Option<Keys>,
    tab: Tab,

    account_input: String,
    handle_input: String,

    status: Option<StatusReport>,
    init_pubkey: Option<String>,
    register_outcome: Option<RegisterOutcome>,
    last_error: Option<String>,

    busy: bool,
    rx: Option<Receiver<StatusWorkerMsg>>,
}

impl ZkmsgApp {
    pub fn new(home: Home) -> Self {
        let config = home.load_config().ok();
        let keys = home.load_keys().ok();
        Self {
            home,
            repo_root: repo_root(),
            config,
            keys,
            tab: Tab::Status,
            account_input: "funded-deployer".to_string(),
            handle_input: String::new(),
            status: None,
            init_pubkey: None,
            register_outcome: None,
            last_error: None,
            busy: false,
            rx: None,
        }
    }

    /// Re-reads `config.json`/`keys.json` after a background call wrote
    /// them (init, register). Cheap local fs reads — fine on the UI thread.
    fn reload_local_state(&mut self) {
        self.config = self.home.load_config().ok();
        self.keys = self.home.load_keys().ok();
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

    fn status_tab(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        if let Some(err) = &self.last_error {
            ui.colored_label(egui::Color32::RED, err.as_str());
            ui.separator();
        }

        if self.keys.is_none() {
            self.init_panel(ui, ctx);
            return;
        }
        if self.keys.as_ref().and_then(|k| k.handle.as_ref()).is_none() {
            self.register_panel(ui, ctx);
            return;
        }
        self.status_panel(ui, ctx);
    }

    fn init_panel(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
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
                    self.repo_root.clone(),
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
            if ui.button("Register").clicked() && !self.handle_input.trim().is_empty() {
                self.busy = true;
                self.last_error = None;
                self.rx = Some(worker::spawn_register(
                    self.home.dir.clone(),
                    self.handle_input.trim().to_string(),
                    ctx.clone(),
                ));
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
        // Kick the first live fetch automatically; after that only the
        // Refresh button re-fires it.
        if self.status.is_none() && !self.busy && self.rx.is_none() {
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

impl eframe::App for ZkmsgApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_worker();

        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Status, "Status");
                ui.selectable_value(&mut self.tab, Tab::Compose, "Compose");
                ui.selectable_value(&mut self.tab, Tab::Inbox, "Inbox");
            });
        });

        let tab = self.tab;
        egui::CentralPanel::default().show(ctx, |ui| match tab {
            Tab::Status => self.status_tab(ui, ctx),
            Tab::Compose => {
                ui.label("Compose — coming soon");
            }
            Tab::Inbox => {
                ui.label("Inbox — coming soon");
            }
        });

        if self.busy {
            ctx.request_repaint();
        }
    }
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
