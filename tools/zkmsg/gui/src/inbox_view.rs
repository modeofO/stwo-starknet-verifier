//! Inbox tab rendering: Refresh button, optional 30s auto-refresh, and a
//! decrypted-message table. State (`inbox`, `inbox_loading`, `inbox_rx`,
//! `inbox_auto_refresh`, `last_refresh`) lives on `ProfileSession`; this
//! module only renders and decides when to spawn a scan.

use eframe::egui;

use crate::session::ProfileSession;
use crate::worker;

const AUTO_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

impl ProfileSession {
    pub(crate) fn poll_inbox_worker(&mut self) {
        let Some(rx) = &self.inbox_rx else { return };
        let Ok(msg) = rx.try_recv() else { return };
        self.inbox_loading = false;
        self.inbox_rx = None;
        match msg {
            worker::InboxWorkerMsg::Scan(Ok(messages)) => {
                self.inbox = messages;
                self.last_error = None;
            }
            worker::InboxWorkerMsg::Scan(Err(e)) => self.last_error = Some(e),
        }
    }

    fn refresh_inbox(&mut self, ctx: &egui::Context) {
        self.inbox_loading = true;
        self.last_error = None;
        self.last_refresh = Some(std::time::Instant::now());
        self.inbox_rx = Some(worker::spawn_inbox(self.home_dir(), ctx.clone()));
    }

    pub(crate) fn inbox_tab(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        // Auto-refresh: fire a scan if enabled and >30s since the last one
        // (or none has run yet), same one-shot-per-tick shape as the
        // manual Refresh button below.
        if self.inbox_auto_refresh
            && !self.inbox_loading
            && self.inbox_rx.is_none()
            && self.last_refresh.map(|t| t.elapsed() >= AUTO_REFRESH_INTERVAL).unwrap_or(true)
        {
            self.refresh_inbox(ctx);
        }

        if let Some(err) = &self.last_error {
            ui.colored_label(egui::Color32::RED, err.as_str());
            ui.separator();
        }

        ui.horizontal(|ui| {
            ui.add_enabled_ui(!self.inbox_loading, |ui| {
                if ui.button("Refresh").clicked() {
                    self.refresh_inbox(ctx);
                }
            });
            ui.checkbox(&mut self.inbox_auto_refresh, "auto-refresh (30s)");
            if self.inbox_loading {
                ui.label("scanning…");
            }
        });
        ui.separator();

        if self.inbox.is_empty() {
            ui.label("inbox empty (no envelopes match your scan key)");
            return;
        }

        egui::Grid::new("inbox_grid").num_columns(3).striped(true).show(ui, |ui| {
            ui.strong("nonce");
            ui.strong("commitment");
            ui.strong("text");
            ui.end_row();

            // `inbox::scan` returns messages sorted by ascending nonce
            // already, so iterating in order puts the newest last.
            for m in &self.inbox {
                ui.label(m.nonce.to_string());
                ui.label(&m.commitment[..m.commitment.len().min(18)]);
                match crate::fromline::split_from_line(&m.text) {
                    Some((handle, body)) => {
                        ui.vertical(|ui| {
                            ui.colored_label(
                                egui::Color32::from_rgb(120, 160, 220),
                                format!("from: {handle}"),
                            );
                            ui.label(body);
                        });
                    }
                    None => {
                        ui.label(&m.text);
                    }
                }
                ui.end_row();
            }
        });
    }
}
