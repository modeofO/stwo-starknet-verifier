//! The delete dialog: wipe a profile from this machine for good
//! (`zkmsg_core::wipe`). Tickets can move to another profile first; the
//! account's balance is abandoned, never swept (a sweep is a
//! public edge linking the two accounts). The user confirms by typing the
//! handle. Owned by ZkmsgApp, like the archive dialog: it may delete the
//! active profile and so outlive its session.

use std::path::Path;

use eframe::egui;

use zkmsg_core::wipe::{self, DeletePlan, WipeOptions};

pub enum DeleteOutcome {
    None,
    Cancelled,
    /// Deleted. `new_current` is what `current` now names, if it named the
    /// deleted profile (`Some(None)`: no profile left).
    Deleted { name: String, archived: bool, new_current: Option<Option<String>> },
}

enum DeleteAct {
    None,
    Delete,
    Cancel,
}

pub struct DeleteUi {
    plan: DeletePlan,
    /// Where the unspent tickets go; `None` abandons them.
    ticket_target: Option<String>,
    keep_account_key: bool,
    typed: String,
    error: Option<String>,
    /// App-level busy snapshot, fed per frame: a delete waits for any send,
    /// setup or register in flight, so it never pulls a directory out from
    /// under a running flow.
    pub app_busy: bool,
}

impl DeleteUi {
    pub fn new(root: &Path, name: &str, archived: bool) -> Result<Self, String> {
        let plan = wipe::plan_delete(root, name, archived).map_err(|e| format!("{e:#}"))?;
        // Tickets are value: default to keeping them when there is somewhere
        // to put them.
        let ticket_target =
            (plan.movable_tickets > 0).then(|| plan.ticket_targets.first().cloned()).flatten();
        Ok(Self {
            plan,
            ticket_target,
            keep_account_key: false,
            typed: String::new(),
            error: None,
            app_busy: false,
        })
    }

    fn delete(&mut self, root: &Path) -> DeleteOutcome {
        let opts = WipeOptions { delete_account_key: !self.keep_account_key };
        match wipe::delete_profile(root, &self.plan, &self.typed, self.ticket_target.as_deref(), opts) {
            Ok((_, report)) => {
                DeleteOutcome::Deleted {
                    name: self.plan.name.clone(),
                    archived: self.plan.archived,
                    new_current: report.new_current,
                }
            }
            Err(e) => {
                self.error = Some(format!("{e:#}"));
                DeleteOutcome::None
            }
        }
    }

    pub fn update(&mut self, ctx: &egui::Context, root: &Path) -> DeleteOutcome {
        let mut act = DeleteAct::None;
        let plan = &self.plan;
        let opts = WipeOptions { delete_account_key: !self.keep_account_key };
        let title = if plan.archived { format!("Delete archived '{}'", plan.name) } else { format!("Delete '{}'", plan.name) };
        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .show(ctx, |ui| {
                ui.label(
                    "Deleting wipes this identity from this computer for good: its keys, \
                     tickets, sends and inbox. Nothing on chain changes — the registration \
                     stays, and messages sent to this handle become unreadable to everyone.",
                );
                ui.separator();

                if plan.movable_tickets > 0 {
                    ui.label(format!("{} unspent ticket(s):", plan.movable_tickets));
                    let selected = match &self.ticket_target {
                        Some(t) => format!("move to '{t}'"),
                        None => "abandon them".to_string(),
                    };
                    egui::ComboBox::from_id_salt("delete_ticket_target").selected_text(selected).show_ui(
                        ui,
                        |ui| {
                            for t in &plan.ticket_targets {
                                ui.selectable_value(
                                    &mut self.ticket_target,
                                    Some(t.clone()),
                                    format!("move to '{t}'"),
                                );
                            }
                            ui.selectable_value(&mut self.ticket_target, None, "abandon them");
                        },
                    );
                    ui.small("Moving tickets stays on this computer; nothing on chain ties a ticket to an identity.");
                }
                if plan.tickets_in_flight > 0 {
                    ui.label(format!(
                        "{} ticket(s) reserved by a submitted send stay behind (they may be spent).",
                        plan.tickets_in_flight
                    ));
                }
                if plan.incomplete_sends > 0 {
                    ui.label(format!("{} incomplete send(s) are abandoned.", plan.incomplete_sends));
                }

                if !plan.key_shared_with.is_empty() {
                    ui.label(format!(
                        "Copies of this directory share its Keychain key ({}), so the key is not \
                         shredded; only this directory is removed.",
                        plan.key_shared_with.join(", ")
                    ));
                }

                if let Some(account) = &plan.account {
                    ui.separator();
                    ui.label(format!(
                        "Account {account} ({})",
                        plan.account_address.as_deref().unwrap_or("address unknown")
                    ));
                    ui.label(
                        "Any STRK left on it is not moved anywhere: a transfer to another of your accounts would \
                         link the two on chain. Deleting abandons it.",
                    );
                    if plan.account_address.is_none() {
                        ui.label("Its key is not in sncast's accounts file.");
                    } else if plan.account_shared_with.is_empty() {
                        ui.checkbox(
                            &mut self.keep_account_key,
                            "keep the account's key in sncast's accounts file (it is used outside zkmsg)",
                        );
                    } else {
                        ui.label(format!(
                            "Its key stays: {} also use(s) it.",
                            plan.account_shared_with.join(", ")
                        ));
                    }
                    if plan.removes_account_key(&opts) {
                        ui.colored_label(
                            egui::Color32::from_rgb(220, 120, 0),
                            "The account's private key is deleted too: its balance is lost for good.",
                        );
                    }
                }

                ui.separator();
                ui.label(format!("Type '{}' to confirm:", plan.confirm_text()));
                ui.text_edit_singleline(&mut self.typed);
                if let Some(err) = &self.error {
                    ui.colored_label(egui::Color32::RED, err.as_str());
                }
                if self.app_busy {
                    ui.label("waiting for the running send, setup or register to finish");
                }
                ui.horizontal(|ui| {
                    let ready = self.typed == plan.confirm_text() && !self.app_busy;
                    let button = egui::Button::new(
                        egui::RichText::new("Delete for good").color(egui::Color32::WHITE),
                    )
                    .fill(egui::Color32::from_rgb(170, 30, 30));
                    if ui.add_enabled(ready, button).clicked() {
                        act = DeleteAct::Delete;
                    }
                    if ui.button("Cancel").clicked() {
                        act = DeleteAct::Cancel;
                    }
                });
            });

        match act {
            DeleteAct::None => DeleteOutcome::None,
            DeleteAct::Delete => self.delete(root),
            DeleteAct::Cancel => DeleteOutcome::Cancelled,
        }
    }
}
