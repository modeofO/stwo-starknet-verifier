//! The pipeline behind a trait, so tests drive a send with scripted events
//! instead of a real 8GB+ prove. The real runner is a one-line wrapper over
//! `Pipeline::run`; the daemon never calls `Pipeline` directly, always this
//! trait, so a test can swap in a scripted implementation.

use anyhow::Result;
use zkmsg_core::config::{Config, Home};
use zkmsg_core::pipeline::{Pipeline, PipelineEvent};
use zkmsg_core::state::SendState;

/// Runs the remaining steps of a send, emitting progress via `sink` — the
/// same contract as `Pipeline::run`.
pub trait SendRunner: Send + Sync {
    fn run(
        &self,
        home: &Home,
        config: &Config,
        state: &mut SendState,
        sink: &mut dyn FnMut(PipelineEvent),
    ) -> Result<()>;
}

/// Production runner: the real checkpointed pipeline (prove/wrap/pack/stage/
/// phase1/phase2/send).
pub struct PipelineRunner;

impl SendRunner for PipelineRunner {
    fn run(
        &self,
        home: &Home,
        config: &Config,
        state: &mut SendState,
        sink: &mut dyn FnMut(PipelineEvent),
    ) -> Result<()> {
        Pipeline::new(home, config).run(state, sink)
    }
}

#[cfg(test)]
pub mod testing {
    use super::*;
    use zkmsg_core::state::StepKind;

    /// Emits a scripted event sequence, then returns a scripted result. Lets
    /// a route/hub test observe the full started -> submitted -> completed ->
    /// done (or failed) fan-out with no chain and no prove.
    pub struct ScriptedRunner {
        pub events: Vec<PipelineEvent>,
        pub result: fn() -> Result<()>,
    }

    impl ScriptedRunner {
        /// A clean run: start each pending step, complete it, then Completed.
        pub fn happy_path(state: &SendState) -> Self {
            let total = state.steps.len();
            let mut events = vec![];
            for (index, step) in state.steps.iter().enumerate() {
                // Local legs (Prove/Wrap/Pack) carry no tx; the paid legs do.
                let local = matches!(
                    step.kind,
                    StepKind::Prove | StepKind::Wrap | StepKind::Pack
                );
                events.push(PipelineEvent::StepStarted { index, total, kind: step.kind.clone() });
                events.push(PipelineEvent::StepCompleted {
                    kind: step.kind.clone(),
                    tx_hash: (!local).then(|| "0xdead".to_string()),
                    note: None,
                });
            }
            events.push(PipelineEvent::Completed { fact: Some("0xfact".into()) });
            Self { events, result: || Ok(()) }
        }
    }

    impl SendRunner for ScriptedRunner {
        fn run(
            &self,
            _home: &Home,
            _config: &Config,
            _state: &mut SendState,
            sink: &mut dyn FnMut(PipelineEvent),
        ) -> Result<()> {
            for ev in &self.events {
                sink(ev.clone());
            }
            (self.result)()
        }
    }
}
