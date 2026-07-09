//! The burner retirement dialog: optional sweep (with the linking
//! warning shown verbatim) then archive-by-rename. Owned by ZkmsgApp
//! (it outlives the session it may close); all chain work runs on
//! worker threads.

use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;

use eframe::egui;

use zkmsg_core::app::{SWEEP_HEADROOM_FRI, sweep_amount_fri};
use zkmsg_core::profiles::archive_profile;

use crate::worker::{self, RetireWorkerMsg};

pub enum RetireOutcome {
    None,
    Cancelled,
    /// Archived (post-sweep or archive-only) — the app drops the session
    /// if it was this profile and rescans.
    Archived { name: String },
}

/// Whether a retire action (sweep or archive) may fire: nothing else
/// paid in flight app-wide, and no own sweep already running.
pub(crate) fn can_act(app_work_in_flight: bool, sweeping: bool) -> bool {
    !app_work_in_flight && !sweeping
}

/// A button the render closure asked to fire, collected inside the
/// closure and acted on after it (both spawn and archive need `&mut
/// self`, which the closure can't re-borrow while it holds `self`).
enum RetireAct {
    None,
    Sweep,
    Archive,
    Cancel,
}

pub struct RetireUi {
    profile_name: String,
    profile_dir: PathBuf,
    /// (profile name, account address) sweep targets — every OTHER
    /// complete profile whose account resolves.
    targets: Vec<(String, String)>,
    target_idx: usize,
    balance_fri: Option<u128>,
    rx: Option<Receiver<RetireWorkerMsg>>,
    sweeping: bool,
    swept_tx: Option<String>,
    error: Option<String>,
    /// App-level work_in_flight snapshot, fed per-frame by the app.
    pub app_busy: bool,
}

impl RetireUi {
    pub fn new(profile_name: String, profile_dir: PathBuf, targets: Vec<(String, String)>) -> Self {
        Self {
            profile_name,
            profile_dir,
            targets,
            target_idx: 0,
            balance_fri: None,
            rx: None,
            sweeping: false,
            swept_tx: None,
            error: None,
            app_busy: false,
        }
    }

    pub fn sweeping(&self) -> bool {
        self.sweeping
    }

    /// Archives the burner by rename (used by both the post-sweep path and
    /// the Archive-only button). On success the app drops the session and
    /// rescans; on failure the error is surfaced and the dialog stays open.
    fn archive(&mut self, root: &Path) -> RetireOutcome {
        match archive_profile(root, &self.profile_name) {
            Ok(_) => RetireOutcome::Archived { name: self.profile_name.clone() },
            Err(e) => {
                self.error = Some(format!("{e:#}"));
                RetireOutcome::None
            }
        }
    }

    pub fn update(&mut self, ctx: &egui::Context, root: &Path) -> RetireOutcome {
        // Kick the one-shot balance read on first frame (chain RPC — worker
        // thread only; the UI thread just polls the channel below).
        if self.balance_fri.is_none() && self.rx.is_none() {
            self.rx = Some(worker::spawn_retire_balance(self.profile_dir.clone(), ctx.clone()));
        }

        // Drain the worker channel. Copy the message out before mutating so
        // the immutable borrow of `self.rx` is released first.
        let msg = self.rx.as_ref().and_then(|rx| rx.try_recv().ok());
        if let Some(msg) = msg {
            match msg {
                RetireWorkerMsg::Balance(Ok(b)) => {
                    self.balance_fri = Some(b);
                    self.rx = None;
                }
                RetireWorkerMsg::Balance(Err(e)) => {
                    // Balance read failed — archive-only is still possible, so
                    // treat it as zero-sweepable rather than blocking the dialog.
                    self.error = Some(e);
                    self.balance_fri = Some(0);
                    self.rx = None;
                }
                RetireWorkerMsg::Swept(Ok((tx, _))) => {
                    self.sweeping = false;
                    self.swept_tx = Some(tx);
                    self.rx = None;
                    // The paid edge landed — immediately archive. On archive
                    // failure the error is set and the dialog stays (the sweep
                    // link still shows; the user can retry Archive only).
                    if let RetireOutcome::Archived { name } = self.archive(root) {
                        return RetireOutcome::Archived { name };
                    }
                }
                RetireWorkerMsg::Swept(Err(e)) => {
                    // Sweep failed — the archive did NOT run; retry is possible.
                    self.sweeping = false;
                    self.error = Some(e);
                    self.rx = None;
                }
            }
        }

        // Precompute the render-only bits so the window closure needs no
        // immutable borrow of `self.targets` alongside `&mut self.target_idx`.
        let target_names: Vec<String> = self.targets.iter().map(|(n, _)| n.clone()).collect();
        let has_target = !self.targets.is_empty();
        let sweepable = self.balance_fri.and_then(|b| sweep_amount_fri(b, SWEEP_HEADROOM_FRI));
        let can_act_now = can_act(self.app_busy, self.sweeping);

        let mut act = RetireAct::None;
        egui::Window::new(format!("Retire burner '{}'", self.profile_name))
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .show(ctx, |ui| {
                // Balance / sweepable line.
                let balance_line = match self.balance_fri {
                    None => "reading balance…".to_string(),
                    Some(b) => match sweep_amount_fri(b, SWEEP_HEADROOM_FRI) {
                        Some(a) => {
                            format!("sweepable: ~{} STRK (0.2 kept for the fee)", a / 10u128.pow(18))
                        }
                        None => "balance too low to sweep — archive only".to_string(),
                    },
                };
                ui.label(balance_line);

                // The linking warning, verbatim, in orange.
                ui.colored_label(
                    egui::Color32::from_rgb(220, 120, 0),
                    "the sweep transfer is a public on-chain edge linking this burner to the target",
                );

                // Sweep target combo (disabled with a note when empty).
                ui.add_enabled_ui(has_target, |ui| {
                    let selected_text =
                        target_names.get(self.target_idx).cloned().unwrap_or_default();
                    egui::ComboBox::from_label("sweep to")
                        .selected_text(selected_text)
                        .show_ui(ui, |ui| {
                            for (i, name) in target_names.iter().enumerate() {
                                ui.selectable_value(&mut self.target_idx, i, name);
                            }
                        });
                });
                if !has_target {
                    ui.label("no other profiles to sweep to");
                }

                if let Some(err) = &self.error {
                    ui.colored_label(egui::Color32::RED, err.as_str());
                }
                if let Some(tx) = &self.swept_tx {
                    ui.hyperlink_to(short_hash(tx), voyager_url(tx));
                }

                ui.separator();
                ui.add_enabled_ui(can_act_now, |ui| {
                    ui.horizontal(|ui| {
                        // Sweep needs both a target and a non-dust balance.
                        ui.add_enabled_ui(has_target && sweepable.is_some(), |ui| {
                            if ui.button("Sweep & archive").clicked() {
                                act = RetireAct::Sweep;
                            }
                        });
                        if ui.button("Archive only").clicked() {
                            act = RetireAct::Archive;
                        }
                        if ui.button("Cancel").clicked() {
                            act = RetireAct::Cancel;
                        }
                    });
                });

                if self.sweeping {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("sweeping…");
                    });
                    ctx.request_repaint();
                }
            });

        match act {
            RetireAct::None => RetireOutcome::None,
            RetireAct::Sweep => {
                self.sweeping = true;
                self.error = None;
                self.rx = Some(worker::spawn_sweep(
                    self.profile_dir.clone(),
                    self.targets[self.target_idx].1.clone(),
                    ctx.clone(),
                ));
                RetireOutcome::None
            }
            RetireAct::Archive => self.archive(root),
            RetireAct::Cancel => RetireOutcome::Cancelled,
        }
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

#[cfg(test)]
mod tests {
    use super::can_act;

    #[test]
    fn retire_actions_blocked_while_any_work_runs() {
        assert!(can_act(false, false));
        assert!(!can_act(true, false)); // app-level paid work in flight
        assert!(!can_act(false, true)); // own sweep in flight
        assert!(!can_act(true, true));
    }
}
