//! The New-profile wizard: a confirm-gated create → fund → deploy → init →
//! register checklist, resumable from the picker. Renders as a floating
//! window over the active session (which supplies the funding source
//! account). All chain work runs on `worker::spawn_setup`; this module owns
//! only the form, the confirm dialog, and the live checklist fed by
//! `SetupFlow`.
//!
//! The confirm dialog is the wizard's spend gate: it is the ONLY path that
//! starts a run while the Fund step is still pending. A resume whose Fund is
//! already done skips it (the money has already moved); a resume whose Fund
//! is still pending re-opens it.

use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;

use eframe::egui;

use zkmsg_core::profiles::PROFILE_PREFIX;
use zkmsg_core::setup::{SetupState, SetupStepKind};

use crate::send_flow::StepStatus;
use crate::setup_flow::SetupFlow;
use crate::worker::{self, SetupWorkerMsg};

/// Per-frame context the wizard needs but does not own: the profile root,
/// the repo root (for `init_identity`'s artifact paths), and the funding
/// source (the active session's account + rpc url).
pub struct WizardCtx<'a> {
    pub egui_ctx: &'a egui::Context,
    pub root: &'a Path,
    pub repo_root: &'a Path,
    pub rpc_url: &'a str,
    pub source_account: &'a str,
    /// The active session has a send being prepared/run. The wizard's Fund
    /// draws on that same account, so its spend actions (Create / Confirm /
    /// Resume) must be blocked while a send is in flight — symmetric with the
    /// Compose side, where the wizard's run blocks the send button.
    pub session_busy: bool,
}

/// What the app should do after a frame's wizard render.
pub enum WizardOutcome {
    /// Keep the wizard open.
    None,
    /// Close the wizard without opening a profile (Cancel / Close).
    Cancelled,
    /// Setup finished — open this profile and drop the wizard.
    Completed { name: String, dir: PathBuf },
}

pub struct WizardUi {
    name: String,
    handle: String,
    account_name: String,
    fund_strk: String,
    /// Once the user edits handle/account_name we stop re-deriving them from
    /// the name (they stay editable either way).
    handle_touched: bool,
    account_touched: bool,

    confirm_open: bool,
    flow: Option<SetupFlow>,
    rx: Option<Receiver<SetupWorkerMsg>>,
    profile_dir: Option<PathBuf>,
    error: Option<String>,
    /// For a resumed run, the `source_account` captured in `setup.json` at
    /// creation — the account that actually pays the Fund. `None` for a
    /// brand-new form, where the active profile's account is the payer. The
    /// confirm dialog shows this in place of the active account so it never
    /// misnames the payer.
    resume_source: Option<String>,
}

impl WizardUi {
    /// A blank form for a brand-new profile.
    pub fn new_profile() -> Self {
        Self {
            name: String::new(),
            handle: String::new(),
            account_name: String::new(),
            fund_strk: "60".to_string(),
            handle_touched: false,
            account_touched: false,
            confirm_open: false,
            flow: None,
            rx: None,
            profile_dir: None,
            error: None,
            resume_source: None,
        }
    }

    /// Resume an incomplete setup from its checkpoint dir. Opens straight to
    /// the checklist; if the Fund step has not run yet the confirm dialog is
    /// re-armed (money has not moved), otherwise a plain Resume button is
    /// enough.
    pub fn resume(dir: PathBuf) -> Result<Self, String> {
        let state = SetupState::load(&dir).map_err(|e| format!("{e:#}"))?;
        let fund_pending =
            !state.steps.iter().any(|s| matches!(s.kind, SetupStepKind::Fund) && s.done);
        Ok(Self {
            name: state.profile_name.clone(),
            handle: state.handle.clone(),
            account_name: state.account_name.clone(),
            fund_strk: state.fund_strk.to_string(),
            handle_touched: true,
            account_touched: true,
            confirm_open: fund_pending,
            flow: Some(SetupFlow::from_state(&state)),
            rx: None,
            profile_dir: Some(dir),
            error: None,
            resume_source: Some(state.source_account.clone()),
        })
    }

    /// True while the setup worker is in flight — the app-level
    /// `work_in_flight` folds this in to disable the picker and the Compose
    /// send button.
    pub fn running(&self) -> bool {
        self.rx.is_some()
    }

    pub fn update(&mut self, wctx: &WizardCtx) -> WizardOutcome {
        self.poll();
        if self.running() {
            wctx.egui_ctx.request_repaint();
        }
        // Completion is auto-handled: open the freshly built profile and drop
        // the wizard (the final checklist lives on in the opened session).
        if self.flow.as_ref().is_some_and(|f| f.completed) {
            if let Some(dir) = self.profile_dir.clone() {
                return WizardOutcome::Completed { name: self.name.trim().to_string(), dir };
            }
        }

        let has_flow = self.flow.is_some();
        let mut outcome = WizardOutcome::None;
        egui::Window::new("New profile")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(wctx.egui_ctx, |ui| {
                if has_flow {
                    outcome = self.render_checklist(ui, wctx);
                } else {
                    outcome = self.render_form(ui, wctx);
                }
            });
        self.render_confirm(wctx);
        outcome
    }

    fn poll(&mut self) {
        let Some(rx) = &self.rx else { return };
        let Ok(msg) = rx.try_recv() else { return };
        match msg {
            SetupWorkerMsg::Progress(event) => {
                if let Some(flow) = &mut self.flow {
                    flow.apply(event);
                }
            }
            SetupWorkerMsg::Done(Ok(())) => self.rx = None,
            SetupWorkerMsg::Done(Err(e)) => {
                if let Some(flow) = &mut self.flow {
                    flow.fail(e.clone());
                }
                self.error = Some(e);
                self.rx = None;
            }
        }
    }

    fn render_form(&mut self, ui: &mut egui::Ui, wctx: &WizardCtx) -> WizardOutcome {
        let mut outcome = WizardOutcome::None;
        ui.heading("Create a new profile");
        ui.label(format!("funded from '{}' (the active profile's account)", wctx.source_account));
        if let Some(err) = &self.error {
            ui.colored_label(egui::Color32::RED, err.as_str());
        }
        ui.separator();

        egui::Grid::new("wizard_form").num_columns(2).show(ui, |ui| {
            ui.label("name");
            if ui.text_edit_singleline(&mut self.name).changed() {
                // Auto-derive handle/account until the user edits them.
                let name = self.name.trim().to_string();
                if !self.handle_touched {
                    self.handle = name.clone();
                }
                if !self.account_touched {
                    self.account_name = format!("zkmsg-{name}");
                }
            }
            ui.end_row();

            ui.label("handle");
            if ui.text_edit_singleline(&mut self.handle).changed() {
                self.handle_touched = true;
            }
            ui.end_row();

            ui.label("account name");
            if ui.text_edit_singleline(&mut self.account_name).changed() {
                self.account_touched = true;
            }
            ui.end_row();

            ui.label("fund (STRK)");
            ui.text_edit_singleline(&mut self.fund_strk);
            ui.end_row();
        });

        let val_err = self.validation_error(wctx.root);
        ui.separator();
        ui.horizontal(|ui| {
            ui.add_enabled_ui(val_err.is_none() && !wctx.session_busy, |ui| {
                if ui.button("Create…").clicked() {
                    // Compute the dir but do NOT create it — that happens
                    // only on Confirm, so a cancel leaves no trace.
                    self.profile_dir =
                        Some(wctx.root.join(format!("{PROFILE_PREFIX}{}", self.name.trim())));
                    self.error = None;
                    self.confirm_open = true;
                }
            });
            if ui.button("Cancel").clicked() {
                outcome = WizardOutcome::Cancelled;
            }
        });
        if let Some(e) = &val_err {
            ui.colored_label(ui.visuals().weak_text_color(), e.as_str());
        } else if wctx.session_busy {
            ui.label("a send is running — profile setup is paused until it finishes");
        }
        outcome
    }

    /// `Some(message)` while the form is not yet ready to Create.
    fn validation_error(&self, root: &Path) -> Option<String> {
        let name = self.name.trim();
        if name.is_empty() {
            return Some("name cannot be empty".into());
        }
        if !name.is_ascii() {
            return Some("name must be ASCII".into());
        }
        if name.contains('/') || name.contains('\\') {
            // Parity with plan_migration: no path separators in a profile name.
            return Some("name cannot contain '/' or '\\'".into());
        }
        if root.join(format!("{PROFILE_PREFIX}{name}")).exists() {
            return Some(format!("{PROFILE_PREFIX}{name} already exists"));
        }
        if self.handle.trim().is_empty() {
            return Some("handle cannot be empty".into());
        }
        if self.account_name.trim().is_empty() {
            return Some("account name cannot be empty".into());
        }
        match self.fund_strk.trim().parse::<u64>() {
            Ok(0) | Err(_) => Some("fund amount must be a positive whole number of STRK".into()),
            Ok(_) => None,
        }
    }

    fn render_confirm(&mut self, wctx: &WizardCtx) {
        if !self.confirm_open {
            return;
        }
        let account = self.account_name.trim().to_string();
        let handle = self.handle.trim().to_string();
        let n = self.fund_strk.trim().to_string();
        // A resumed run pays from the account captured in setup.json at
        // creation, not the currently active profile — show that account so
        // the dialog never misnames the payer. `session_busy` still guards
        // only the ACTIVE profile while a resumed wizard runs, so the payer
        // may differ from the profile that lock covers; that mismatch is
        // corrected here for display, and the actual overlap risk (two spends
        // from the resume's source) is bounded by the single-wizard guard
        // (`rx.is_some()` in `spawn`), not by `session_busy`.
        let source = self.resume_source.clone().unwrap_or_else(|| wctx.source_account.to_string());
        let payer_is_active = self.resume_source.is_none() || source == wctx.source_account;
        let source_gloss = if payer_is_active { " (the active profile's account)" } else { "" };
        let mut open = true;
        egui::Window::new("Confirm profile setup")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 40.0])
            .open(&mut open)
            .show(wctx.egui_ctx, |ui| {
                ui.label(format!(
                    "Create account '{account}', fund it with {n} STRK from '{source}'\
                     {source_gloss}, deploy it, and register '{handle}'? \
                     The {n} STRK moves to the new account — it stays yours. \
                     Fees ≈ under 1 STRK."
                ));
                if !payer_is_active {
                    ui.colored_label(
                        egui::Color32::from_rgb(200, 140, 40),
                        format!(
                            "note: funding comes from '{source}' (the profile that started this \
                             setup), not the active profile"
                        ),
                    );
                }
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        self.confirm_open = false;
                    }
                    // Disabled while a send is running; `spawn` also refuses
                    // in that case, so the gate never rests on button state.
                    ui.add_enabled_ui(!wctx.session_busy, |ui| {
                        if ui.button("Confirm").clicked() {
                            self.confirm_open = false;
                            self.spawn(wctx);
                        }
                    });
                });
            });
        if !open {
            self.confirm_open = false;
        }
    }

    fn render_checklist(&mut self, ui: &mut egui::Ui, wctx: &WizardCtx) -> WizardOutcome {
        let mut outcome = WizardOutcome::None;
        // Cloned so the Resume/Close buttons can call `&mut self` methods
        // without fighting a borrow of `self.flow` across the render.
        let Some(flow) = self.flow.clone() else { return outcome };

        ui.heading(format!("Setting up '{}'", self.name.trim()));
        if let Some(err) = &flow.error {
            ui.colored_label(egui::Color32::RED, err.as_str());
        }
        ui.separator();

        for step in &flow.steps {
            ui.horizontal(|ui| {
                match step.status {
                    StepStatus::Pending => {
                        ui.label("·");
                    }
                    StepStatus::Running => {
                        ui.spinner();
                    }
                    StepStatus::Done => {
                        ui.colored_label(egui::Color32::from_rgb(60, 180, 60), "\u{2713}");
                    }
                    StepStatus::Failed => {
                        ui.colored_label(egui::Color32::RED, "\u{2717}");
                    }
                }
                ui.label(setup_step_label(&step.kind));
                if let Some(tx) = &step.tx_hash {
                    ui.hyperlink_to(short_hash(tx), voyager_url(tx));
                }
            });
        }

        ui.separator();
        if self.running() {
            ui.label("working…");
            return outcome;
        }
        // Not running and not complete → offer a resume. `request_resume`
        // routes through the confirm dialog whenever Fund is still pending,
        // so no spend ever starts without it.
        let can_resume = !flow.completed && !wctx.session_busy;
        ui.horizontal(|ui| {
            if can_resume && ui.button("Resume").clicked() {
                self.request_resume(wctx);
            }
            if ui.button("Close").clicked() {
                // Leaves setup.json + a "(setup incomplete)" picker entry to
                // resume later.
                outcome = WizardOutcome::Cancelled;
            }
        });
        if !flow.completed && wctx.session_busy {
            ui.label("a send is running — resume is paused until it finishes");
        }
        outcome
    }

    /// True once the Fund step is checkpointed done — the point past which a
    /// resume no longer needs the spend confirm.
    fn fund_done(&self) -> bool {
        self.flow.as_ref().is_some_and(|f| {
            f.steps
                .iter()
                .any(|s| matches!(s.kind, SetupStepKind::Fund) && s.status == StepStatus::Done)
        })
    }

    fn request_resume(&mut self, wctx: &WizardCtx) {
        if self.fund_done() {
            self.spawn(wctx);
        } else {
            // Money has not moved — re-gate on the confirm dialog.
            self.confirm_open = true;
        }
    }

    /// Starts (or resumes) the setup worker. Loads an existing checkpoint if
    /// there is one; otherwise builds the plan and saves it — which is what
    /// creates the profile dir, so the dir first appears here, only ever
    /// downstream of a Confirm.
    fn spawn(&mut self, wctx: &WizardCtx) {
        if self.rx.is_some() {
            return; // never run two setups at once
        }
        if wctx.session_busy {
            // A send is in flight on the same funding account — refuse
            // regardless of button state, so the paid-path lock is symmetric
            // and does not depend on the disabled Confirm alone.
            self.error = Some("a send is running — wait for it to finish".into());
            return;
        }
        let Some(dir) = self.profile_dir.clone() else {
            self.error = Some("no profile directory set".into());
            return;
        };
        let state = match SetupState::load(&dir) {
            Ok(s) => s,
            Err(_) => {
                let fund = match self.fund_strk.trim().parse::<u64>() {
                    Ok(f) => f,
                    Err(_) => {
                        self.error = Some("fund amount must be a whole number".into());
                        return;
                    }
                };
                let s = SetupState::new_plan(
                    self.name.trim().to_string(),
                    self.handle.trim().to_string(),
                    self.account_name.trim().to_string(),
                    fund,
                    wctx.source_account.to_string(),
                );
                if let Err(e) = s.save(&dir) {
                    self.error = Some(format!("{e:#}"));
                    return;
                }
                s
            }
        };
        self.error = None;
        self.flow = Some(SetupFlow::from_state(&state));
        self.rx = Some(worker::spawn_setup(
            wctx.rpc_url.to_string(),
            dir,
            wctx.repo_root.to_path_buf(),
            state,
            wctx.egui_ctx.clone(),
        ));
    }
}

fn setup_step_label(kind: &SetupStepKind) -> &'static str {
    match kind {
        SetupStepKind::CreateAccount => "create account",
        SetupStepKind::Fund => "fund",
        SetupStepKind::Deploy => "deploy",
        SetupStepKind::Init => "init identity",
        SetupStepKind::Register => "register handle",
    }
}

fn voyager_url(tx: &str) -> String {
    format!("https://sepolia.voyager.online/tx/{tx}")
}

fn short_hash(tx: &str) -> String {
    if tx.len() > 14 {
        format!("{}…{}", &tx[..8], &tx[tx.len() - 4..])
    } else {
        tx.to_string()
    }
}
