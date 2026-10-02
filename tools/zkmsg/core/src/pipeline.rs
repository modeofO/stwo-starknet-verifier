//! Send progress events, shared by the CLI and GUI sinks.
//!
//! The lane-1 pipeline that used to live here (bridge prove/wrap, pack,
//! stage, fact-registry verify phases, then MessageStore v3) was removed
//! 2026-10-01: every send now goes through SNIP-36 (`virtual_send.rs`).

use crate::state::StepKind;

#[derive(Debug, Clone)]
pub enum PipelineEvent {
    StepStarted { index: usize, total: usize, kind: StepKind },
    TxSubmitted { kind: StepKind, tx_hash: String },
    StepCompleted { kind: StepKind, tx_hash: Option<String>, note: Option<String> },
    /// The message is published.
    Completed,
    /// The send's state was first written to disk under `id`; from here on it
    /// can be resumed (it is saved once its proof exists).
    Checkpointed { id: String },
}
