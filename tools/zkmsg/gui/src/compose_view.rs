//! Compose tab: recipient resolve, byte counter, the ticket-spend confirm
//! dialog, and the live send-progress checklist. State lives on
//! `ProfileSession`; this module renders it and drives the worker handoff —
//! resolve runs in the background, and Confirm starts one worker that
//! prepares, proves and publishes (`worker::spawn_virtual_send`), feeding
//! `SendFlow::apply`.
//!
//! Both `resolve_recipient` and the send itself do chain RPC, so neither
//! may run on the UI thread — see worker.rs's threading rule.

use eframe::egui;

use zkmsg_core::chain::felt_hex;
use zkmsg_core::config::Home;
use zkmsg_core::pipeline::PipelineEvent;
use zkmsg_core::state::{SendState, StepKind};

use crate::send_flow::{SendFlow, StepStatus};
use crate::session::ProfileSession;
use crate::worker::{self, ResolveWorkerMsg, WorkerMsg};

const BYTE_SOFT_CAP: usize = 1_000;
/// What a send spends: one ticket, bought earlier at the pool's price.
fn ticket_strk() -> u128 {
    zkmsg_core::config::SEPOLIA_V4_TICKET_PRICE_FRI / 1_000_000_000_000_000_000
}

impl ProfileSession {
    pub(crate) fn poll_compose_worker(&mut self) {
        if let Some(rx) = &self.compose_resolve_rx {
            if let Ok(ResolveWorkerMsg::Resolved(result)) = rx.try_recv() {
                self.compose_resolving = false;
                self.compose_resolve_rx = None;
                self.compose_resolved = Some(result);
            }
        }
    }

    pub(crate) fn poll_send_worker(&mut self) {
        let Some(rx) = &self.send_rx else { return };
        let Ok(msg) = rx.try_recv() else { return };
        match msg {
            WorkerMsg::Progress(event) => {
                if let PipelineEvent::Checkpointed { id } = &event {
                    self.send_state_id = Some(id.clone());
                }
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

    /// `locked` is the app-level wizard-running flag: while a profile-setup
    /// wizard is spending, no send (compose or resume) may start, or two
    /// paid flows would draw on the same account at once.
    pub(crate) fn compose_tab(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, locked: bool) {
        if self.send_flow.is_some() {
            self.render_send_progress(ui, ctx, locked);
        } else {
            self.render_compose_form(ui, ctx, locked);
        }
        self.render_confirm_dialog(ctx, locked);
    }

    fn render_compose_form(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, locked: bool) {
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
        let cost = self.cost_line();
        let tickets = self.status.as_ref().and_then(|r| r.tickets);
        let ticket_line = match tickets {
            Some(c) => format!("{cost} · {} unspent ticket(s)", c.unspent),
            None => format!("{cost} · tickets unknown (see Status tab)"),
        };
        ui.label(ticket_line);
        // Known-empty wallet: nothing to spend. Unknown: let the send's own
        // check decide (it refuses before proving).
        let out_of_tickets = tickets.is_some_and(|c| c.unspent == 0);

        let can_send = matches!(self.compose_resolved, Some(Ok(_)))
            && !self.compose_text.trim().is_empty()
            && !self.work_in_flight()
            && self.is_virtual_route()
            && !out_of_tickets
            && !locked;
        ui.add_enabled_ui(can_send, |ui| {
            if ui.button("Send").clicked() {
                self.compose_show_confirm = true;
            }
        });
        if !self.is_virtual_route() {
            ui.label("this profile's store is retired — move it to the v4 pool on the Status tab");
        }
        if out_of_tickets {
            ui.label("no unspent ticket — buy one on the Status tab");
        }
        if locked {
            ui.label("a profile setup is running — sending is paused until it finishes");
        }
    }

    fn render_confirm_dialog(&mut self, ctx: &egui::Context, locked: bool) {
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
                    "Publish this message to {recipient}? This spends one ticket \
                     ({} STRK, already paid) and cannot be undone. The pool publishes \
                     it; your account is not involved.",
                    ticket_strk()
                ));
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        self.compose_show_confirm = false;
                    }
                    // Disabled while a wizard is spending — same guard as the
                    // Send button, in case the dialog was already open.
                    ui.add_enabled_ui(!locked, |ui| {
                        if ui.button("Confirm").clicked() {
                            self.compose_show_confirm = false;
                            self.start_send(ctx);
                        }
                    });
                });
            });
        if !open {
            self.compose_show_confirm = false;
        }
    }

    fn is_virtual_route(&self) -> bool {
        self.config.as_ref().is_some_and(zkmsg_core::app::on_current_store)
    }

    fn cost_line(&self) -> String {
        format!("a send spends one ticket ({} STRK); the pool publishes and pays for it", ticket_strk())
    }

    /// Prepare, prove and publish run as one worker (the witness never
    /// leaves memory), so there is no separate prepare window — the
    /// checklist opens at once on the fixed three-step plan.
    fn start_send(&mut self, ctx: &egui::Context) {
        if self.keys.as_ref().and_then(|k| k.leaf_index).is_none() {
            self.last_error = Some("not registered".to_string());
            return;
        }
        if self.work_in_flight() {
            self.last_error = Some("a send is already running".to_string());
            return;
        }
        self.last_error = None;
        self.send_state_id = None;
        self.send_flow = Some(SendFlow::virtual_plan());
        self.send_rx = Some(worker::spawn_virtual_send(
            self.home_dir(),
            self.compose_handle.trim().to_string(),
            self.compose_text.clone(),
            ctx.clone(),
        ));
    }

    /// True while a send runs — the window during which NO other send
    /// (compose or resume) may start, or two paid sends would race the same
    /// account (double-spend). Prepare runs inside the send worker, so
    /// `send_rx` covers it.
    pub(crate) fn work_in_flight(&self) -> bool {
        self.send_rx.is_some()
    }

    /// Loads `id`'s checkpoint, builds a fresh `SendFlow` from it, and
    /// spawns the (resumed) send worker. Shared by the Failed-step Resume
    /// button below and the launch-time resume banner (`app.rs`) — both
    /// end up here rather than duplicating the `spawn_send` wiring.
    pub(crate) fn resume_send(&mut self, id: &str, ctx: &egui::Context) {
        // Belt-and-suspenders on a spend action: never spawn a second send
        // while one is in flight OR being prepared (a compose prepare RPC is
        // running with send_rx still None) — else two paid pipelines could
        // run concurrently and double-spend. poll_send_worker clears send_rx
        // in both Done arms before a step is observable as Failed, so the
        // Failed-step Resume path always sees this false and is unaffected.
        if self.work_in_flight() {
            self.last_error = Some("a send is already running".to_string());
            return;
        }
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
        self.send_flow = None;
        self.send_rx = None;
        self.send_state_id = None;
    }

    fn render_send_progress(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, locked: bool) {
        // Cloned (not borrowed): the checklist is tiny, and owning a copy
        // here lets the Resume/Compose-another buttons below call `&mut
        // self` methods without fighting an immutable borrow of
        // `self.send_flow` across the whole render.
        let Some(flow) = self.send_flow.clone() else { return };

        if flow.published {
            ui.colored_label(egui::Color32::from_rgb(60, 180, 60), "published");
            ui.separator();
        }
        if let Some(err) = &flow.error {
            ui.colored_label(egui::Color32::RED, err.as_str());
            ui.separator();
        }

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
        if flow.steps.iter().any(|s| s.kind == StepKind::Prove && s.status == StepStatus::Running) {
            ui.label("proving takes ~20 s on an M-series Mac");
        }

        let has_failed = flow.steps.iter().any(|s| s.status == StepStatus::Failed);
        let is_done = flow.published;

        ui.separator();
        // A failed send resumes from its saved state when there is one. A
        // send that failed before its proof was saved has none (the
        // witness is never written down): it goes back to the form, message
        // intact, to be sent again.
        let resumable = self.send_state_id.as_deref().is_some_and(|id| {
            SendState::path(&Home::new(self.home_dir()), id).exists()
        });
        if has_failed && !locked && resumable && ui.button("Resume").clicked() {
            if let Some(id) = self.send_state_id.clone() {
                self.resume_send(&id, ctx);
            }
        }
        if has_failed && !resumable && ui.button("Back to message").clicked() {
            self.send_flow = None;
            self.send_state_id = None;
        }
        if is_done && ui.button("Compose another").clicked() {
            self.reset_compose();
        }
        if is_done
            && self.config.as_ref().is_some_and(|c| c.burner)
            && ui.button("Archive this burner…").clicked()
        {
            self.retire_offer = true;
        }
    }
}

fn step_label(kind: &StepKind) -> String {
    match kind {
        StepKind::Prove => "prove (virtual OS, on this machine)".to_string(),
        StepKind::Prepare => "prepare (tree, paths, nonce at one block)".to_string(),
        StepKind::Publish => "publish (one transaction, proof attached)".to_string(),
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
