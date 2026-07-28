//! The send registry and its event fan-out. One `SendEntry` per send holds
//! every wire event it has emitted (each with a monotonic id) AND the live
//! listeners currently streaming it. Recording and fan-out happen under one
//! lock, so a listener that registers mid-send replays the recorded prefix
//! and then reads the live tail with no gap and no duplicate:
//!
//!   * a producer `record`s under the entry lock: assign id, push to the
//!     log, send to every live listener;
//!   * a `subscribe` takes the same lock: snapshot the log (optionally from
//!     a `Last-Event-ID`), then register the listener.
//!
//! Because both take the lock, any event logged before a subscribe is in
//! that subscribe's replay and was NOT sent to its channel; any event after
//! is sent to the channel and is not in the replay. The listener plays the
//! replay, then the channel.

use std::collections::HashMap;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Mutex;
use std::time::SystemTime;

use serde_json::Value;
use zkmsg_core::pipeline::PipelineEvent;
use zkmsg_core::state::StepKind;

use crate::wire;

/// One recorded wire event, tagged with its per-send id (for SSE
/// `Last-Event-ID` replay) and whether it closes the stream.
#[derive(Clone, Debug)]
pub struct Frame {
    pub id: u64,
    pub json: Value,
    pub terminal: bool,
}

/// The lifecycle state the protocol exposes: `running`, `done`, `failed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Running,
    Done,
    Failed,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Running => "running",
            Phase::Done => "done",
            Phase::Failed => "failed",
        }
    }
}

/// What a subscriber gets back: the replay prefix, plus — only while the
/// send is still running — a live channel for the tail.
pub enum Subscription {
    /// The send already reached a terminal event. The replay is the whole
    /// story; there is nothing more to stream.
    Finished { replay: Vec<Frame> },
    /// The send is live. Play `replay`, then read `rx` until a terminal
    /// frame arrives (or the sender drops).
    Live { replay: Vec<Frame>, rx: Receiver<Frame> },
}

struct Inner {
    phase: Phase,
    fact: Option<String>,
    error: Option<String>,
    next_id: u64,
    log: Vec<Frame>,
    listeners: Vec<Sender<Frame>>,
}

pub struct SendEntry {
    pub id: String,
    pub recipient_handle: String,
    /// Sort key for the newest-first list. Live sends use "now"; sends
    /// recovered from disk at startup use the state file's mtime.
    pub created: SystemTime,
    inner: Mutex<Inner>,
}

impl SendEntry {
    fn new(id: String, recipient_handle: String, created: SystemTime, phase: Phase) -> Self {
        Self {
            id,
            recipient_handle,
            created,
            inner: Mutex::new(Inner {
                phase,
                fact: None,
                error: None,
                next_id: 1,
                log: Vec::new(),
                listeners: Vec::new(),
            }),
        }
    }

    /// Assigns the next id, appends to the log, and fans out to every live
    /// listener (dropping any whose receiver has hung up). One critical
    /// section — this is what keeps replay and live-tail seamless.
    fn record(&self, json: Value, terminal: bool) -> u64 {
        let mut inner = self.inner.lock().unwrap();
        let id = inner.next_id;
        inner.next_id += 1;
        let frame = Frame { id, json, terminal };
        inner.log.push(frame.clone());
        inner.listeners.retain(|tx| tx.send(frame.clone()).is_ok());
        id
    }

    /// Seeds a recovered (startup-loaded) send's terminal outcome without
    /// emitting a frame — the log stays empty, so a listener falls back to
    /// the snapshot endpoint (there are no live events to replay).
    pub fn set_outcome(&self, fact: Option<String>, error: Option<String>) {
        let mut inner = self.inner.lock().unwrap();
        inner.fact = fact;
        inner.error = error;
    }

    pub fn phase(&self) -> Phase {
        self.inner.lock().unwrap().phase
    }

    pub fn fact(&self) -> Option<String> {
        self.inner.lock().unwrap().fact.clone()
    }

    pub fn error(&self) -> Option<String> {
        self.inner.lock().unwrap().error.clone()
    }

    /// Snapshot the log (from `after_id` exclusive, or all when `None`) and,
    /// while running, hand back a fresh live channel.
    pub fn subscribe(&self, after_id: Option<u64>) -> Subscription {
        let mut inner = self.inner.lock().unwrap();
        let replay: Vec<Frame> = inner
            .log
            .iter()
            .filter(|f| after_id.is_none_or(|a| f.id > a))
            .cloned()
            .collect();
        if inner.phase == Phase::Running {
            let (tx, rx) = channel();
            inner.listeners.push(tx);
            Subscription::Live { replay, rx }
        } else {
            Subscription::Finished { replay }
        }
    }
}

/// The set of all sends the daemon knows about. Behind one lock; entries are
/// `Arc` so a streaming handler holds its entry without holding the map.
pub struct SendHub {
    entries: Mutex<HashMap<String, std::sync::Arc<SendEntry>>>,
}

impl Default for SendHub {
    fn default() -> Self {
        Self::new()
    }
}

impl SendHub {
    pub fn new() -> Self {
        Self { entries: Mutex::new(HashMap::new()) }
    }

    /// Registers a send (or returns the existing entry). `created`/`phase`
    /// apply only to a freshly inserted entry.
    pub fn upsert(
        &self,
        id: &str,
        recipient_handle: &str,
        created: SystemTime,
        phase: Phase,
    ) -> std::sync::Arc<SendEntry> {
        let mut entries = self.entries.lock().unwrap();
        entries
            .entry(id.to_string())
            .or_insert_with(|| {
                std::sync::Arc::new(SendEntry::new(
                    id.to_string(),
                    recipient_handle.to_string(),
                    created,
                    phase,
                ))
            })
            .clone()
    }

    pub fn get(&self, id: &str) -> Option<std::sync::Arc<SendEntry>> {
        self.entries.lock().unwrap().get(id).cloned()
    }

    /// All entries, newest first (by `created`, then id for stability).
    pub fn list(&self) -> Vec<std::sync::Arc<SendEntry>> {
        let mut out: Vec<_> = self.entries.lock().unwrap().values().cloned().collect();
        out.sort_by(|a, b| b.created.cmp(&a.created).then(b.id.cmp(&a.id)));
        out
    }

    /// Marks a send running (start / resume). Re-entering a running send is
    /// the caller's job to reject; this only flips the flag.
    pub fn mark_running(&self, id: &str) {
        if let Some(entry) = self.get(id) {
            entry.inner.lock().unwrap().phase = Phase::Running;
        }
    }

    /// Records one pipeline event. `Completed` also flips the entry to `done`
    /// and stores the fact. Returns the emitted frame's id.
    pub fn record_pipeline_event(&self, id: &str, event: &PipelineEvent) -> Option<u64> {
        let entry = self.get(id)?;
        let (json, terminal) = wire::event_to_wire(event);
        if let PipelineEvent::Completed { fact } = event {
            let mut inner = entry.inner.lock().unwrap();
            inner.phase = Phase::Done;
            inner.fact = fact.clone();
        }
        Some(entry.record(json, terminal))
    }

    /// Records the daemon-level `failed` event and flips the entry to
    /// `failed`. `kind` is the step that was running when the error hit.
    pub fn record_failed(&self, id: &str, kind: Option<&StepKind>, error: &str) -> Option<u64> {
        let entry = self.get(id)?;
        {
            let mut inner = entry.inner.lock().unwrap();
            inner.phase = Phase::Failed;
            inner.error = Some(error.to_string());
        }
        Some(entry.record(wire::failed_event(kind, error), true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkmsg_core::state::StepKind;

    fn hub_with_send() -> (SendHub, std::sync::Arc<SendEntry>) {
        let hub = SendHub::new();
        let entry = hub.upsert("s1", "bob", SystemTime::now(), Phase::Running);
        (hub, entry)
    }

    #[test]
    fn live_listener_receives_events_and_terminal_closes() {
        let (hub, entry) = hub_with_send();
        // Subscribe before any event: empty replay, live channel.
        let sub = entry.subscribe(None);
        let rx = match sub {
            Subscription::Live { replay, rx } => {
                assert!(replay.is_empty());
                rx
            }
            _ => panic!("running send must yield a live subscription"),
        };

        hub.record_pipeline_event(
            "s1",
            &PipelineEvent::StepStarted { index: 0, total: 6, kind: StepKind::Prove },
        );
        hub.record_pipeline_event("s1", &PipelineEvent::Completed { fact: Some("0xfa".into()) });

        let first = rx.recv().unwrap();
        assert_eq!(first.id, 1);
        assert_eq!(first.json["type"], "step_started");
        assert!(!first.terminal);
        let last = rx.recv().unwrap();
        assert_eq!(last.id, 2);
        assert_eq!(last.json, serde_json::json!({ "type": "done", "fact": "0xfa" }));
        assert!(last.terminal);

        assert_eq!(entry.phase(), Phase::Done);
        assert_eq!(entry.fact().as_deref(), Some("0xfa"));
    }

    #[test]
    fn late_subscriber_replays_log_then_finishes() {
        let (hub, entry) = hub_with_send();
        hub.record_pipeline_event(
            "s1",
            &PipelineEvent::StepStarted { index: 0, total: 6, kind: StepKind::Prove },
        );
        hub.record_pipeline_event("s1", &PipelineEvent::Completed { fact: None });
        // Subscribing after completion: full replay, no live channel.
        match entry.subscribe(None) {
            Subscription::Finished { replay } => {
                assert_eq!(replay.len(), 2);
                assert_eq!(replay[0].id, 1);
                assert_eq!(replay[1].json["type"], "done");
            }
            _ => panic!("finished send must not open a live channel"),
        }
    }

    #[test]
    fn last_event_id_replays_only_newer_frames() {
        let (hub, entry) = hub_with_send();
        for i in 0..3 {
            hub.record_pipeline_event(
                "s1",
                &PipelineEvent::StepStarted { index: i, total: 6, kind: StepKind::Prove },
            );
        }
        // Reconnect having seen id 1: replay must start at id 2.
        match entry.subscribe(Some(1)) {
            Subscription::Live { replay, .. } => {
                assert_eq!(replay.iter().map(|f| f.id).collect::<Vec<_>>(), vec![2, 3]);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn failed_records_terminal_and_flips_phase() {
        let (hub, entry) = hub_with_send();
        hub.record_pipeline_event(
            "s1",
            &PipelineEvent::StepStarted { index: 4, total: 6, kind: StepKind::Phase2 },
        );
        let id = hub.record_failed("s1", Some(&StepKind::Phase2), "tx reverted").unwrap();
        assert_eq!(id, 2);
        assert_eq!(entry.phase(), Phase::Failed);
        assert_eq!(entry.error().as_deref(), Some("tx reverted"));
        match entry.subscribe(None) {
            Subscription::Finished { replay } => {
                assert_eq!(replay.last().unwrap().json["type"], "failed");
                assert!(replay.last().unwrap().terminal);
            }
            _ => panic!("failed send is terminal"),
        }
    }

    #[test]
    fn list_is_newest_first() {
        let hub = SendHub::new();
        let early = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(100);
        let late = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(200);
        hub.upsert("old", "bob", early, Phase::Done);
        hub.upsert("new", "carol", late, Phase::Running);
        let ids: Vec<_> = hub.list().iter().map(|e| e.id.clone()).collect();
        assert_eq!(ids, vec!["new".to_string(), "old".to_string()]);
    }
}
