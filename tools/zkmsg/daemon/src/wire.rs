//! The wire contract, in one place: `PipelineEvent` -> SSE JSON, step
//! records -> snapshot/plan JSON, and the health/resolve bodies. The `kind`
//! strings are the exact `StepKind` variant names the protocol pins.

use serde_json::{json, Value};
use zkmsg_core::pipeline::PipelineEvent;
use zkmsg_core::state::{StepKind, StepRecord};

/// The bare wire name of a step kind — `Prove`, `Wrap`, `Pack`, `Stage`,
/// `Phase1`, `Phase2`, `SendMessage`. A `Stage` step's offset rides in a
/// separate field (snapshot only), never inside this name.
pub fn kind_name(kind: &StepKind) -> &'static str {
    match kind {
        StepKind::Prove => "Prove",
        StepKind::Wrap => "Wrap",
        StepKind::Pack => "Pack",
        StepKind::Stage { .. } => "Stage",
        StepKind::Phase1 => "Phase1",
        StepKind::Phase2 => "Phase2",
        StepKind::SendMessage => "SendMessage",
    }
}

/// Maps a core `PipelineEvent` to its SSE object and whether it closes the
/// stream. `StepStarted`/`TxSubmitted`/`StepCompleted` map one to one and
/// keep the stream open; `Completed` becomes the daemon-level `done` and
/// closes it. (`failed` has no `PipelineEvent`; it is minted by the run
/// thread when `Pipeline::run` returns `Err` — see `failed_event`.)
pub fn event_to_wire(event: &PipelineEvent) -> (Value, bool) {
    match event {
        PipelineEvent::StepStarted { index, total, kind } => (
            json!({ "type": "step_started", "index": index, "total": total,
                    "kind": kind_name(kind) }),
            false,
        ),
        PipelineEvent::TxSubmitted { kind, tx_hash } => (
            json!({ "type": "tx_submitted", "kind": kind_name(kind), "tx_hash": tx_hash }),
            false,
        ),
        // step_completed keeps the stream open; only `done`/`failed` close it.
        PipelineEvent::StepCompleted { kind, tx_hash, note } => (
            json!({ "type": "step_completed", "kind": kind_name(kind),
                    "tx_hash": tx_hash, "note": note }),
            false,
        ),
        PipelineEvent::Completed { fact } => (json!({ "type": "done", "fact": fact }), true),
    }
}

/// The daemon-level `failed` event that closes a stream when the pipeline
/// errored. `kind` is the step that was running when it failed, if known.
pub fn failed_event(kind: Option<&StepKind>, error: &str) -> Value {
    json!({ "type": "failed", "kind": kind.map(kind_name), "error": error })
}

/// A step in the pre-staging plan, as returned by POST /v1/sends: just the
/// kind name and its done flag (no Stage steps exist yet at that point).
pub fn plan_step_json(step: &StepRecord) -> Value {
    json!({ "kind": kind_name(&step.kind), "done": step.done })
}

/// A step in a full snapshot (GET /v1/sends/{id}): kind, done, tx_hash,
/// note, plus `offset` for a `Stage` step.
pub fn snapshot_step_json(step: &StepRecord) -> Value {
    let mut obj = json!({
        "kind": kind_name(&step.kind),
        "done": step.done,
        "tx_hash": step.tx_hash,
        "note": step.note,
    });
    if let StepKind::Stage { offset } = step.kind {
        obj["offset"] = json!(offset);
    }
    obj
}

/// The GET /v1/health body. `chain_id` is best-effort (null when the RPC
/// read failed); `ready` is false without a registered handle or funds.
#[allow(clippy::too_many_arguments)]
pub fn health_json(
    chain_id: Option<&str>,
    handle: Option<&str>,
    account_address: Option<&str>,
    store: &str,
    registry: &str,
    ready: bool,
) -> Value {
    json!({
        "version": "1",
        "chain_id": chain_id,
        "handle": handle,
        // null, never "", when there is no account — an empty string is not a
        // felt, so a client that types this field as an optional felt would
        // fail to decode "" (the not-ready state is exactly first pairing).
        "account_address": account_address,
        "store": store,
        "registry": registry,
        "ready": ready,
    })
}

/// The 200 body for GET /v1/resolve.
pub fn resolve_ok_json(handle: &str, leaf_index: u32, scan_pub: &str) -> Value {
    json!({ "handle": handle, "leaf_index": leaf_index, "scan_pub": scan_pub })
}

/// A `{ "error": <msg> }` body, used for 404/409/422/500.
pub fn error_json(message: &str) -> Value {
    json!({ "error": message })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_started_maps_and_stays_open() {
        let ev = PipelineEvent::StepStarted { index: 3, total: 6, kind: StepKind::Phase1 };
        let (v, terminal) = event_to_wire(&ev);
        assert!(!terminal);
        assert_eq!(v, json!({ "type": "step_started", "index": 3, "total": 6, "kind": "Phase1" }));
    }

    #[test]
    fn tx_submitted_maps() {
        let ev = PipelineEvent::TxSubmitted {
            kind: StepKind::Stage { offset: 1900 },
            tx_hash: "0xabc".into(),
        };
        let (v, terminal) = event_to_wire(&ev);
        assert!(!terminal);
        // Stage's offset does NOT leak into the event kind name.
        assert_eq!(v, json!({ "type": "tx_submitted", "kind": "Stage", "tx_hash": "0xabc" }));
    }

    #[test]
    fn step_completed_carries_nullable_fields_and_stays_open() {
        let with = PipelineEvent::StepCompleted {
            kind: StepKind::Phase1,
            tx_hash: Some("0xdef".into()),
            note: Some("fri_offset 812".into()),
        };
        let (v, terminal) = event_to_wire(&with);
        assert!(!terminal);
        assert_eq!(
            v,
            json!({ "type": "step_completed", "kind": "Phase1",
                    "tx_hash": "0xdef", "note": "fri_offset 812" })
        );
        let without = PipelineEvent::StepCompleted {
            kind: StepKind::Pack,
            tx_hash: None,
            note: None,
        };
        let (v, _) = event_to_wire(&without);
        assert_eq!(v["tx_hash"], Value::Null);
        assert_eq!(v["note"], Value::Null);
    }

    #[test]
    fn completed_becomes_terminal_done() {
        let ev = PipelineEvent::Completed { fact: Some("0x4535".into()) };
        let (v, terminal) = event_to_wire(&ev);
        assert!(terminal, "done closes the stream");
        assert_eq!(v, json!({ "type": "done", "fact": "0x4535" }));
    }

    #[test]
    fn failed_event_shape() {
        let v = failed_event(Some(&StepKind::Phase2), "tx reverted: bad");
        assert_eq!(v, json!({ "type": "failed", "kind": "Phase2", "error": "tx reverted: bad" }));
        let unknown = failed_event(None, "state load failed");
        assert_eq!(unknown["kind"], Value::Null);
    }

    #[test]
    fn snapshot_step_includes_offset_for_stage_only() {
        let stage = StepRecord {
            kind: StepKind::Stage { offset: 0 },
            done: true,
            tx_hash: Some("0x1".into()),
            note: None,
        };
        let v = snapshot_step_json(&stage);
        assert_eq!(v["offset"], json!(0u32));
        assert_eq!(v["kind"], "Stage");

        let phase1 = StepRecord { kind: StepKind::Phase1, done: false, tx_hash: None, note: None };
        let v = snapshot_step_json(&phase1);
        assert!(v.get("offset").is_none(), "non-Stage steps carry no offset");
    }

    #[test]
    fn plan_step_is_kind_and_done_only() {
        let step = StepRecord { kind: StepKind::Prove, done: false, tx_hash: None, note: None };
        assert_eq!(plan_step_json(&step), json!({ "kind": "Prove", "done": false }));
    }

    #[test]
    fn health_body_shape() {
        let v = health_json(Some("0x534e5f5345504f4c4941"), Some("alice"), Some("0x073"), "0x2d6", "0x194", true);
        assert_eq!(v["version"], "1");
        assert_eq!(v["chain_id"], "0x534e5f5345504f4c4941");
        assert_eq!(v["handle"], "alice");
        assert_eq!(v["ready"], true);
        // Unregistered / unknown chain id serialize as null.
        let v = health_json(None, None, None, "", "", false);
        assert_eq!(v["chain_id"], Value::Null);
        assert_eq!(v["handle"], Value::Null);
        // No account serializes as null, never "" — a client typing this as an
        // optional felt must be able to decode the not-ready state.
        assert_eq!(v["account_address"], Value::Null);
        assert_eq!(v["ready"], false);
    }
}
