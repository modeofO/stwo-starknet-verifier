//! The burner retirement dialog: archive-by-rename. There is no sweep —
//! any STRK left on the burner stays there, because moving it anywhere
//! would be a public on-chain edge linking the burner to the target.
//! Owned by ZkmsgApp (it outlives the session it may close).

use std::path::Path;

use eframe::egui;

use zkmsg_core::profiles::archive_profile;

pub enum RetireOutcome {
    None,
    Cancelled,
    /// Archived — the app drops the session if it was this profile and
    /// rescans.
    Archived { name: String },
}

/// A button the render closure asked to fire, collected inside the
/// closure and acted on after it (archive needs `&mut self`, which the
/// closure can't re-borrow while it holds `self`).
enum RetireAct {
    None,
    Archive,
    Cancel,
}

pub struct RetireUi {
    profile_name: String,
    error: Option<String>,
    /// App-level work_in_flight snapshot, fed per-frame by the app. Archive
    /// waits while a send or setup is running on any profile, so a rename
    /// never pulls a directory out from under a running pipeline.
    pub app_busy: bool,
}

impl RetireUi {
    pub fn new(profile_name: String) -> Self {
        Self { profile_name, error: None, app_busy: false }
    }

    /// Archives the burner by rename. On success the app drops the session
    /// and rescans; on failure the error is surfaced and the dialog stays.
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
        let mut act = RetireAct::None;
        egui::Window::new(format!("Retire burner '{}'", self.profile_name))
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .show(ctx, |ui| {
                ui.label(
                    "Archiving hides this burner from the profile list and keeps its directory \
                     (scan key included) under the archive folder. Any STRK left on its account \
                     stays there.",
                );
                if let Some(err) = &self.error {
                    ui.colored_label(egui::Color32::RED, err.as_str());
                }
                if self.app_busy {
                    ui.label("waiting for the running send or setup to finish");
                }
                ui.separator();
                ui.horizontal(|ui| {
                    ui.add_enabled_ui(!self.app_busy, |ui| {
                        if ui.button("Archive").clicked() {
                            act = RetireAct::Archive;
                        }
                    });
                    if ui.button("Cancel").clicked() {
                        act = RetireAct::Cancel;
                    }
                });
            });

        match act {
            RetireAct::None => RetireOutcome::None,
            RetireAct::Archive => self.archive(root),
            RetireAct::Cancel => RetireOutcome::Cancelled,
        }
    }
}
