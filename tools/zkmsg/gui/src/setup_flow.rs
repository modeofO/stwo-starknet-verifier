//! Pure reducer: `SetupEvent` -> a checklist view model for the profile
//! setup wizard. The setup analogue of `send_flow.rs` — deliberately a
//! second concrete reducer over `SetupStepKind` rather than a generic one,
//! so each stays a plain, unit-testable state machine feeding its view.

use zkmsg_core::setup::{SetupEvent, SetupState, SetupStepKind};

use crate::send_flow::StepStatus;

#[derive(Debug, Clone)]
pub struct SetupStepView {
    pub kind: SetupStepKind,
    pub status: StepStatus,
    pub tx_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SetupFlow {
    pub steps: Vec<SetupStepView>,
    pub error: Option<String>,
    pub completed: bool,
}

impl SetupFlow {
    pub fn from_state(state: &SetupState) -> Self {
        let steps = state
            .steps
            .iter()
            .map(|s| SetupStepView {
                kind: s.kind.clone(),
                status: if s.done { StepStatus::Done } else { StepStatus::Pending },
                tx_hash: s.tx_hash.clone(),
            })
            .collect();
        let completed = state.steps.iter().all(|s| s.done);
        Self { steps, error: None, completed }
    }

    /// The first not-yet-Done step matching `kind`; the setup plan has no
    /// repeated kinds, but this guards against re-matching a step a resume
    /// already finished (same shape as `send_flow`'s).
    fn find_pending_mut(&mut self, kind: &SetupStepKind) -> Option<&mut SetupStepView> {
        self.steps.iter_mut().find(|s| &s.kind == kind && s.status != StepStatus::Done)
    }

    pub fn apply(&mut self, event: SetupEvent) {
        match event {
            SetupEvent::StepStarted { kind, .. } => {
                if let Some(step) = self.find_pending_mut(&kind) {
                    step.status = StepStatus::Running;
                }
            }
            SetupEvent::TxSubmitted { kind, tx_hash } => {
                if let Some(step) = self.find_pending_mut(&kind) {
                    step.tx_hash = Some(tx_hash);
                }
            }
            SetupEvent::StepCompleted { kind, tx_hash, .. } => {
                if let Some(step) = self.find_pending_mut(&kind) {
                    step.status = StepStatus::Done;
                    if tx_hash.is_some() {
                        step.tx_hash = tx_hash;
                    }
                }
            }
            SetupEvent::Completed => {
                self.completed = true;
                for step in &mut self.steps {
                    if step.status != StepStatus::Failed {
                        step.status = StepStatus::Done;
                    }
                }
            }
        }
    }

    /// The currently-Running step failed; record the message and mark it.
    pub fn fail(&mut self, msg: String) {
        if let Some(step) = self.steps.iter_mut().find(|s| s.status == StepStatus::Running) {
            step.status = StepStatus::Failed;
        }
        self.error = Some(msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkmsg_core::setup::{SetupEvent as E, SetupStepKind as K};

    #[test]
    fn reducer_tracks_running_done_and_completed() {
        let mut f = SetupFlow {
            steps: vec![
                SetupStepView { kind: K::CreateAccount, status: StepStatus::Pending, tx_hash: None },
                SetupStepView { kind: K::Fund, status: StepStatus::Pending, tx_hash: None },
            ],
            error: None,
            completed: false,
        };
        f.apply(E::StepStarted { index: 0, total: 2, kind: K::CreateAccount });
        assert!(matches!(f.steps[0].status, StepStatus::Running));
        f.apply(E::StepCompleted { kind: K::CreateAccount, tx_hash: None, note: None });
        assert!(matches!(f.steps[0].status, StepStatus::Done));
        f.apply(E::TxSubmitted { kind: K::Fund, tx_hash: "0xabc".into() });
        assert_eq!(f.steps[1].tx_hash.as_deref(), Some("0xabc"));
        // Completed sets the flag AND marks every non-failed step done.
        f.apply(E::Completed);
        assert!(f.completed);
        assert!(f.steps.iter().all(|s| matches!(s.status, StepStatus::Done)));
    }

    #[test]
    fn fail_marks_running_step_and_sets_error() {
        let mut f = SetupFlow {
            steps: vec![
                SetupStepView { kind: K::CreateAccount, status: StepStatus::Pending, tx_hash: None },
                SetupStepView { kind: K::Fund, status: StepStatus::Pending, tx_hash: None },
            ],
            error: None,
            completed: false,
        };
        f.apply(E::StepStarted { index: 1, total: 2, kind: K::Fund });
        // CreateAccount was never started, so Fund is the running one.
        f.steps[0].status = StepStatus::Done;
        f.fail("transfer reverted".to_string());
        assert!(matches!(f.steps[1].status, StepStatus::Failed));
        assert_eq!(f.error.as_deref(), Some("transfer reverted"));
    }
}
