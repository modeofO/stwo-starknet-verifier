//! Compose tab: recipient resolve, byte counter, the STRK-cost confirm
//! dialog, and the live send-progress checklist. State lives on
//! `ZkmsgApp`; this module renders it and drives the worker handoff —
//! resolve runs in the background, Confirm kicks off `prepare_send` in
//! the background, and once that returns a plan `worker::spawn_send`
//! takes over (also background) feeding `SendFlow::apply`.
//!
//! Both `resolve_recipient` and the send itself do chain RPC, so neither
//! may run on the UI thread — see worker.rs's threading rule.

use eframe::egui;

use zkmsg_core::chain::felt_hex;
use zkmsg_core::config::Home;
use zkmsg_core::state::{SendState, StepKind};

use crate::app::ZkmsgApp;
use crate::send_flow::{SendFlow, StepStatus};
use crate::worker::{self, PrepareWorkerMsg, ResolveWorkerMsg, WorkerMsg};

const BYTE_SOFT_CAP: usize = 1_000;
/// Display-only estimate (docs/lane1-results.md measured lane-1 Sepolia
/// cost) — NOT what gates the spend; the pipeline's own gas bounds are
/// the real enforcement. This is what the confirm dialog and cost line
/// show the user before they commit.
const ESTIMATED_COST_STRK: u32 = 48;

impl ZkmsgApp {
    pub(crate) fn poll_compose_worker(&mut self, ctx: &egui::Context) {
        if let Some(rx) = &self.compose_resolve_rx {
            if let Ok(ResolveWorkerMsg::Resolved(result)) = rx.try_recv() {
                self.compose_resolving = false;
                self.compose_resolve_rx = None;
                self.compose_resolved = Some(result);
            }
        }
        if let Some(rx) = &self.compose_prepare_rx {
            if let Ok(PrepareWorkerMsg::Prepared(result)) = rx.try_recv() {
                self.compose_preparing = false;
                self.compose_prepare_rx = None;
                match result {
                    Ok(state) => self.start_send(state, ctx),
                    Err(e) => self.last_error = Some(e),
                }
            }
        }
    }

    pub(crate) fn poll_send_worker(&mut self) {
        let Some(rx) = &self.send_rx else { return };
        let Ok(msg) = rx.try_recv() else { return };
        match msg {
            WorkerMsg::Progress(event) => {
                if let Some(flow) = &mut self.send_flow {
                    flow.apply(event);
                }
            }
            WorkerMsg::Done(Ok(())) => {
                self.send_rx = None;
                self.refresh_pending();
            }
            WorkerMsg::Done(Err(e)) => {
                if let Some(flow) = &mut self.send_flow {
                    flow.fail(e);
                }
                self.send_rx = None;
                self.refresh_pending();
            }
        }
    }

    pub(crate) fn compose_tab(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        if self.send_flow.is_some() {
            self.render_send_progress(ui, ctx);
        } else {
            self.render_compose_form(ui, ctx);
        }
        self.render_confirm_dialog(ctx);
    }

    fn render_compose_form(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        if let Some(err) = &self.last_error {
            ui.colored_label(egui::Color32::RED, err.as_str());
            ui.separator();
        }

        if self.keys.as_ref().and_then(|k| k.leaf_index).is_none() {
            ui.label("register a handle on the Status tab before composing");
            return;
        }

        ui.horizontal(|ui| {
            ui.label("to:");
            let handle_response = ui.text_edit_singleline(&mut self.compose_handle);
            if handle_response.changed() {
                // The old resolution (and any resolve still in flight) is
                // now for a DIFFERENT handle than what's displayed —
                // drop it so Send can't fire against an unverified
                // recipient, and so a stale in-flight result can't land
                // and get shown as if it resolved the new text.
                self.compose_resolved = None;
                self.compose_resolve_rx = None;
                self.compose_resolving = false;
            }
            ui.add_enabled_ui(
                !self.compose_resolving && !self.compose_handle.trim().is_empty(),
                |ui| {
                    if ui.button("Resolve").clicked() {
                        self.compose_resolving = true;
                        self.compose_resolved = None;
                        self.last_error = None;
                        self.compose_resolve_rx = Some(worker::spawn_resolve(
                            self.home_dir(),
                            self.compose_handle.trim().to_string(),
                            ctx.clone(),
                        ));
                    }
                },
            );
        });
        if self.compose_resolving {
            ui.label("resolving…");
        }
        match &self.compose_resolved {
            Some(Ok((pubkey, leaf))) => {
                ui.label(format!("resolved — leaf {leaf}, pubkey {}", felt_hex(pubkey)));
            }
            Some(Err(e)) => {
                ui.colored_label(egui::Color32::RED, format!("unknown handle: {e}"));
            }
            None => {}
        }

        ui.separator();
        ui.label("message:");
        ui.add(egui::TextEdit::multiline(&mut self.compose_text).desired_rows(6));
        let n_bytes = self.compose_text.len();
        let counter_color = if n_bytes > BYTE_SOFT_CAP {
            egui::Color32::from_rgb(220, 120, 0)
        } else {
            ui.visuals().text_color()
        };
        ui.colored_label(counter_color, format!("{n_bytes} / {BYTE_SOFT_CAP} bytes"));

        ui.separator();
        let balance_line = match self.status.as_ref().and_then(|r| r.balance_strk) {
            Some(strk) => format!("send costs ~{ESTIMATED_COST_STRK} STRK · balance ~{strk} STRK"),
            None => format!(
                "send costs ~{ESTIMATED_COST_STRK} STRK · balance unknown (see Status tab)"
            ),
        };
        ui.label(balance_line);

        let can_send = matches!(self.compose_resolved, Some(Ok(_)))
            && !self.compose_text.trim().is_empty()
            && !self.compose_preparing;
        ui.add_enabled_ui(can_send, |ui| {
            if ui.button("Send").clicked() {
                self.compose_show_confirm = true;
            }
        });
        if self.compose_preparing {
            ui.label("preparing send (root + merkle paths + encrypt)…");
        }
    }

    fn render_confirm_dialog(&mut self, ctx: &egui::Context) {
        if !self.compose_show_confirm {
            return;
        }
        // Send is only enabled while `compose_resolved` matches the
        // currently-displayed `compose_handle` (any edit clears the old
        // resolution), so by the time this dialog can be open, the two
        // are guaranteed to describe the same, freshly-verified recipient.
        let handle = self.compose_handle.trim().to_string();
        let leaf = match &self.compose_resolved {
            Some(Ok((_, leaf))) => Some(*leaf),
            _ => None,
        };
        let recipient = match leaf {
            Some(leaf) => format!("'{handle}' (leaf {leaf})"),
            None => format!("'{handle}'"),
        };
        let mut open = true;
        egui::Window::new("Confirm send")
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.label(format!(
                    "Publish this message to {recipient}? This spends \
                     ~{ESTIMATED_COST_STRK} STRK on Sepolia and cannot be undone."
                ));
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        self.compose_show_confirm = false;
                    }
                    if ui.button("Confirm").clicked() {
                        self.compose_show_confirm = false;
                        self.start_prepare(ctx);
                    }
                });
            });
        if !open {
            self.compose_show_confirm = false;
        }
    }

    fn start_prepare(&mut self, ctx: &egui::Context) {
        let Some(sender_leaf) = self.keys.as_ref().and_then(|k| k.leaf_index) else {
            self.last_error = Some("not registered".to_string());
            return;
        };
        self.compose_preparing = true;
        self.last_error = None;
        self.compose_prepare_rx = Some(worker::spawn_prepare(
            self.home_dir(),
            sender_leaf,
            self.compose_handle.trim().to_string(),
            self.compose_text.clone(),
            ctx.clone(),
        ));
    }

    fn start_send(&mut self, state: SendState, ctx: &egui::Context) {
        let Some(config) = self.config.clone() else {
            self.last_error = Some("no config loaded".to_string());
            return;
        };
        self.send_state_id = Some(state.id.clone());
        self.send_flow = Some(SendFlow::from_state(&state));
        self.send_rx =
            Some(worker::spawn_send(Home::new(self.home_dir()), config, state, ctx.clone()));
    }

    /// Loads `id`'s checkpoint, builds a fresh `SendFlow` from it, and
    /// spawns the (resumed) send worker. Shared by the Failed-step Resume
    /// button below and the launch-time resume banner (`app.rs`) — both
    /// end up here rather than duplicating the `spawn_send` wiring.
    pub(crate) fn resume_send(&mut self, id: &str, ctx: &egui::Context) {
        let Some(config) = self.config.clone() else {
            self.last_error = Some("no config loaded".to_string());
            return;
        };
        match SendState::load(&Home::new(self.home_dir()), id) {
            Ok(state) => {
                self.send_state_id = Some(state.id.clone());
                self.send_flow = Some(SendFlow::from_state(&state));
                self.send_rx = Some(worker::spawn_send(
                    Home::new(self.home_dir()),
                    config,
                    state,
                    ctx.clone(),
                ));
            }
            Err(e) => self.last_error = Some(format!("{e:#}")),
        }
    }

    fn reset_compose(&mut self) {
        self.compose_handle.clear();
        self.compose_text.clear();
        self.compose_resolving = false;
        self.compose_resolved = None;
        self.compose_resolve_rx = None;
        self.compose_show_confirm = false;
        self.compose_preparing = false;
        self.compose_prepare_rx = None;
        self.send_flow = None;
        self.send_rx = None;
        self.send_state_id = None;
    }

    fn render_send_progress(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        // Cloned (not borrowed): the checklist is tiny, and owning a copy
        // here lets the Resume/Compose-another buttons below call `&mut
        // self` methods without fighting an immutable borrow of
        // `self.send_flow` across the whole render.
        let Some(flow) = self.send_flow.clone() else { return };

        if let Some(fact) = &flow.fact {
            ui.colored_label(
                egui::Color32::from_rgb(60, 180, 60),
                format!("published — fact {fact}"),
            );
            ui.separator();
        }
        if let Some(err) = &flow.error {
            ui.colored_label(egui::Color32::RED, err.as_str());
            ui.separator();
        }

        let wrap_running = flow
            .steps
            .iter()
            .any(|s| matches!(s.kind, StepKind::Wrap) && s.status == StepStatus::Running);

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
                ui.label(step_label(&step.kind));
                if let Some(tx) = &step.tx_hash {
                    ui.hyperlink_to(short_hash(tx), voyager_url(tx));
                }
            });
        }
        if wrap_running {
            ui.label("wrap uses ~25 GB RAM");
        }

        let has_failed = flow.steps.iter().any(|s| s.status == StepStatus::Failed);
        let is_done = flow.fact.is_some();

        ui.separator();
        if has_failed && ui.button("Resume").clicked() {
            if let Some(id) = self.send_state_id.clone() {
                self.resume_send(&id, ctx);
            }
        }
        if is_done && ui.button("Compose another").clicked() {
            self.reset_compose();
        }
    }
}

fn step_label(kind: &StepKind) -> String {
    match kind {
        StepKind::Prove => "prove".to_string(),
        StepKind::Wrap => "wrap".to_string(),
        StepKind::Pack => "pack".to_string(),
        StepKind::Stage { offset } => format!("stage @ {offset}"),
        StepKind::Phase1 => "verify phase 1".to_string(),
        StepKind::Phase2 => "verify phase 2".to_string(),
        StepKind::SendMessage => "send message".to_string(),
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
