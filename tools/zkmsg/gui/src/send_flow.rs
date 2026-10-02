//! Pure reducer: `PipelineEvent` -> a checklist view model. No egui, no
//! network — the whole point is that this is unit-testable in isolation
//! from the worker-thread plumbing that feeds it real events.

use zkmsg_core::pipeline::PipelineEvent;
use zkmsg_core::state::{SendState, StepKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepStatus {
    Pending,
    Running,
    Done,
    Failed,
}

#[derive(Debug, Clone)]
pub struct StepView {
    pub kind: StepKind,
    pub status: StepStatus,
    pub tx_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SendFlow {
    pub steps: Vec<StepView>,
    pub fact: Option<String>,
    pub error: Option<String>,
    /// Set by `Completed`. A SNIP-36 send finishes with no fact, so this —
    /// not `fact` — is what says the message is out.
    pub published: bool,
    /// The saved state's id once one exists (`Checkpointed`). A SNIP-36 send
    /// that fails before its proof is saved has nothing to resume.
    pub checkpoint: Option<String>,
}

impl SendFlow {
    pub fn from_state(state: &SendState) -> Self {
        let steps = state
            .steps
            .iter()
            .map(|s| StepView {
                kind: s.kind.clone(),
                status: if s.done { StepStatus::Done } else { StepStatus::Pending },
                tx_hash: s.tx_hash.clone(),
            })
            .collect();
        let published = !state.steps.is_empty() && state.steps.iter().all(|s| s.done);
        Self { steps, fact: state.fact.clone(), error: None, published, checkpoint: None }
    }

    /// The SNIP-36 checklist, before Prepare has produced a state.
    pub fn virtual_plan() -> Self {
        let steps = [StepKind::Prepare, StepKind::Prove, StepKind::Publish]
            .into_iter()
            .map(|kind| StepView { kind, status: StepStatus::Pending, tx_hash: None })
            .collect();
        Self { steps, fact: None, error: None, published: false, checkpoint: None }
    }

    /// The first not-yet-Done step matching `kind` — plans can repeat a
    /// kind (multiple `Stage{offset}` steps carry distinct offsets, so
    /// they're distinct `kind`s already; this guard just protects against
    /// re-matching a step a later resume already finished).
    fn find_pending_mut(&mut self, kind: &StepKind) -> Option<&mut StepView> {
        self.steps.iter_mut().find(|s| &s.kind == kind && s.status != StepStatus::Done)
    }

    pub fn apply(&mut self, event: PipelineEvent) {
        match event {
            PipelineEvent::StepStarted { kind, .. } => {
                if let Some(step) = self.find_pending_mut(&kind) {
                    step.status = StepStatus::Running;
                }
            }
            PipelineEvent::TxSubmitted { kind, tx_hash } => {
                if let Some(step) = self.find_pending_mut(&kind) {
                    step.tx_hash = Some(tx_hash);
                }
            }
            PipelineEvent::StepCompleted { kind, tx_hash, .. } => {
                if let Some(step) = self.find_pending_mut(&kind) {
                    step.status = StepStatus::Done;
                    if tx_hash.is_some() {
                        step.tx_hash = tx_hash;
                    }
                }
            }
            PipelineEvent::Completed { fact } => {
                self.fact = fact;
                for step in &mut self.steps {
                    if step.status != StepStatus::Failed {
                        step.status = StepStatus::Done;
                    }
                }
                self.published = true;
            }
            PipelineEvent::Checkpointed { id } => self.checkpoint = Some(id),
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

    #[test]
    fn reducer_tracks_running_then_done() {
        use zkmsg_core::state::StepKind;
        use zkmsg_core::pipeline::PipelineEvent as E;
        let mut f = SendFlow {
            steps: vec![
                StepView { kind: StepKind::Prove, status: StepStatus::Pending, tx_hash: None },
                StepView { kind: StepKind::Phase1, status: StepStatus::Pending, tx_hash: None },
            ],
            fact: None,
            error: None,
            published: false,
            checkpoint: None,
        };
        f.apply(E::StepStarted { index: 0, total: 2, kind: StepKind::Prove });
        assert!(matches!(f.steps[0].status, StepStatus::Running));
        f.apply(E::StepCompleted { kind: StepKind::Prove, tx_hash: None, note: None });
        assert!(matches!(f.steps[0].status, StepStatus::Done));
        f.apply(E::TxSubmitted { kind: StepKind::Phase1, tx_hash: "0xabc".into() });
        assert_eq!(f.steps[1].tx_hash.as_deref(), Some("0xabc"));
        f.apply(E::Completed { fact: Some("0xf".into()) });
        assert_eq!(f.fact.as_deref(), Some("0xf"));
        assert!(f.published);
    }

    #[test]
    fn virtual_send_publishes_without_a_fact() {
        use zkmsg_core::pipeline::PipelineEvent as E;
        let mut f = SendFlow::virtual_plan();
        f.apply(E::StepStarted { index: 0, total: 3, kind: StepKind::Prepare });
        f.apply(E::StepCompleted { kind: StepKind::Prepare, tx_hash: None, note: None });
        f.apply(E::Checkpointed { id: "abc".into() });
        assert_eq!(f.checkpoint.as_deref(), Some("abc"));
        f.apply(E::TxSubmitted { kind: StepKind::Publish, tx_hash: "0x1".into() });
        assert_eq!(f.steps[2].tx_hash.as_deref(), Some("0x1"));
        f.apply(E::Completed { fact: None });
        assert!(f.published);
        assert!(f.fact.is_none());
    }

    #[test]
    fn fail_marks_running_step_and_sets_error() {
        use zkmsg_core::state::StepKind;
        use zkmsg_core::pipeline::PipelineEvent as E;
        let mut f = SendFlow {
            steps: vec![
                StepView { kind: StepKind::Prove, status: StepStatus::Pending, tx_hash: None },
                StepView { kind: StepKind::Wrap, status: StepStatus::Pending, tx_hash: None },
            ],
            fact: None,
            error: None,
            published: false,
            checkpoint: None,
        };
        f.apply(E::StepStarted { index: 0, total: 2, kind: StepKind::Prove });
        f.fail("bridge prove failed".to_string());
        assert!(matches!(f.steps[0].status, StepStatus::Failed));
        assert!(matches!(f.steps[1].status, StepStatus::Pending));
        assert_eq!(f.error.as_deref(), Some("bridge prove failed"));
    }
}
