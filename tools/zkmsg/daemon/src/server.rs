//! The HTTP surface: shared state, request routing, the endpoint handlers,
//! and the SSE streaming reader. Each request is served on its own thread
//! (an SSE stream blocks its thread for the life of the stream), but the
//! actual pipeline RUNS are serialized behind one `run_lock` — proving is
//! RAM-heavy and two proves at once would thrash. Health, resolve, snapshot,
//! and event streaming never touch that lock, so they stay responsive while
//! a send proves.

use std::collections::VecDeque;
use std::io::{self, Read};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use serde_json::{json, Value};
use tiny_http::{Header, Method, Request, Response, StatusCode};

use zkmsg_core::app;
use zkmsg_core::chain::account_address;
use zkmsg_core::config::{Config, Home};
use zkmsg_core::pipeline::PipelineEvent;
use zkmsg_core::state::{SendState, StepKind};

use crate::hub::{Frame, Phase, SendHub, Subscription};
use crate::reads::ChainReader;
use crate::runner::SendRunner;
use crate::wire;

/// The daemon's hard message ceiling. The GUI shows a 1,000-byte soft cap;
/// the daemon is more generous but still bounds the request so a stray large
/// body cannot allocate without limit. Empty messages are rejected too.
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 4_096;

/// Everything a handler needs, shared across request threads behind an `Arc`.
/// `Home`/`Config` are read fresh from disk where identity can change out of
/// band (keys.json handle after a `register`); addresses are stable.
pub struct AppState {
    pub home: Home,
    pub config: Config,
    pub token: String,
    pub hub: SendHub,
    /// Serializes pipeline runs. A run thread holds this for its whole
    /// duration; a second send queues behind it. Never held by the
    /// read-only handlers.
    pub run_lock: Mutex<()>,
    pub runner: Arc<dyn SendRunner>,
    pub reads: Arc<dyn ChainReader>,
    pub max_message_bytes: usize,
}

impl AppState {
    pub fn new(
        home: Home,
        config: Config,
        token: String,
        runner: Arc<dyn SendRunner>,
        reads: Arc<dyn ChainReader>,
    ) -> Self {
        Self {
            home,
            config,
            token,
            hub: SendHub::new(),
            run_lock: Mutex::new(()),
            runner,
            reads,
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
        }
    }
}

/// Scans the sends directory into the hub at startup, so a daemon restart
/// lists prior sends and can resume them. A send with no pending step is
/// `done` (its fact seeded from disk); an interrupted one is `failed` with a
/// null error — POST resume re-enters it cleanly.
pub fn load_existing_sends(app: &AppState) {
    let dir = app.home.sends_dir();
    let Ok(read) = std::fs::read_dir(&dir) else { return };
    for entry in read.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Some(id) = path.file_stem().and_then(|s| s.to_str()) else { continue };
        let Ok(state) = SendState::load(&app.home, id) else { continue };
        let created = std::fs::metadata(&path).and_then(|m| m.modified()).unwrap_or_else(|_| SystemTime::now());
        let done = state.next_pending().is_none();
        let phase = if done { Phase::Done } else { Phase::Failed };
        let entry = app.hub.upsert(id, &state.recipient_handle, created, phase);
        entry.set_outcome(if done { state.fact.clone() } else { None }, None);
    }
}

// --- routing ----------------------------------------------------------------

/// Authenticates, then routes one request. Every route requires the bearer
/// token; a mismatch is 401 with no fallback.
pub fn dispatch(app: &Arc<AppState>, request: Request) -> io::Result<()> {
    let auth = header_value(&request, "Authorization");
    if !crate::auth::bearer_ok(auth.as_deref(), &app.token) {
        return respond_json(request, 401, &wire::error_json("unauthorized"));
    }

    let url = request.url().to_string();
    let path = url.split('?').next().unwrap_or("");
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    match (request.method().clone(), segs.as_slice()) {
        (Method::Get, ["v1", "health"]) => handle_health(app, request),
        (Method::Get, ["v1", "resolve"]) => handle_resolve(app, request),
        (Method::Post, ["v1", "sends"]) => handle_create_send(app, request),
        (Method::Get, ["v1", "sends"]) => handle_list_sends(app, request),
        (Method::Get, ["v1", "sends", id]) => handle_get_send(app, request, id.to_string()),
        (Method::Get, ["v1", "sends", id, "events"]) => {
            handle_events(app, request, id.to_string())
        }
        (Method::Post, ["v1", "sends", id, "resume"]) => {
            handle_resume(app, request, id.to_string())
        }
        _ => respond_json(request, 404, &wire::error_json("not found")),
    }
}

// --- handlers ---------------------------------------------------------------

fn handle_health(app: &Arc<AppState>, request: Request) -> io::Result<()> {
    let keys = app.home.load_keys().ok();
    let handle = keys.as_ref().and_then(|k| k.handle.clone());
    let registered = keys.as_ref().and_then(|k| k.leaf_index).is_some();
    let account_address = account_address(&app.config.account).ok();
    let chain_id = app.reads.chain_id().ok();
    let balance = app.reads.balance_strk().ok();
    let ready = readiness(registered, balance);
    let body = wire::health_json(
        chain_id.as_deref(),
        handle.as_deref(),
        account_address.as_deref(),
        &app.config.store,
        &app.config.registry,
        ready,
    );
    respond_json(request, 200, &body)
}

fn handle_resolve(app: &Arc<AppState>, request: Request) -> io::Result<()> {
    let handle = query_param(request.url(), "handle");
    let (status, body) = resolve_response(app.reads.as_ref(), handle.as_deref());
    respond_json(request, status, &body)
}

fn handle_create_send(app: &Arc<AppState>, request: Request) -> io::Result<()> {
    let mut request = request;
    let body = read_body(&mut request);
    let Ok(parsed) = serde_json::from_str::<Value>(&body) else {
        return respond_json(request, 422, &wire::error_json("invalid JSON body"));
    };
    let handle = parsed["recipient_handle"].as_str().unwrap_or("").to_string();
    let message = parsed["message"].as_str().unwrap_or("").to_string();

    if handle.trim().is_empty() {
        return respond_json(request, 422, &wire::error_json("recipient_handle is empty"));
    }
    if let Some(reason) = message_error(&message, app.max_message_bytes) {
        return respond_json(request, 422, &wire::error_json(reason));
    }

    // Readiness gate: a registered handle and a funded account.
    let keys = match app.home.load_keys() {
        Ok(k) => k,
        Err(_) => return respond_json(request, 409, &wire::error_json("daemon has no identity")),
    };
    let balance = app.reads.balance_strk().ok();
    if !readiness(keys.leaf_index.is_some(), balance) {
        return respond_json(request, 409, &wire::error_json("daemon not ready (no handle or no funds)"));
    }
    let sender_leaf = keys.leaf_index.expect("readiness checked leaf_index");

    // Resolve first for a clean 404 (prepare_send would also fail, less legibly).
    if app.reads.resolve(&handle).is_err() {
        return respond_json(request, 404, &wire::error_json("handle not registered"));
    }

    let send_state = match app::prepare_send(&app.home, &app.config, &keys, sender_leaf, &handle, &message) {
        Ok(s) => s,
        Err(e) => return respond_json(request, 500, &wire::error_json(&format!("prepare_send: {e}"))),
    };

    let steps: Vec<Value> = send_state.steps.iter().map(wire::plan_step_json).collect();
    let body = json!({
        "send_id": send_state.id,
        "recipient_handle": send_state.recipient_handle,
        "ciphertext_bytes": send_state.ciphertext_hex.len() / 2,
        "steps": steps,
    });

    app.hub.upsert(&send_state.id, &handle, SystemTime::now(), Phase::Running);
    spawn_run(Arc::clone(app), send_state.id.clone());

    respond_json(request, 201, &body)
}

fn handle_list_sends(app: &Arc<AppState>, request: Request) -> io::Result<()> {
    let sends: Vec<Value> = app
        .hub
        .list()
        .iter()
        .map(|e| {
            json!({
                "send_id": e.id,
                "recipient_handle": e.recipient_handle,
                "state": e.phase().as_str(),
                "fact": e.fact(),
            })
        })
        .collect();
    respond_json(request, 200, &json!({ "sends": sends }))
}

fn handle_get_send(app: &Arc<AppState>, request: Request, id: String) -> io::Result<()> {
    let entry = app.hub.get(&id);
    let state = SendState::load(&app.home, &id).ok();
    if entry.is_none() && state.is_none() {
        return respond_json(request, 404, &wire::error_json("no such send"));
    }

    let (state_str, fact, error, recipient_handle) = match &entry {
        Some(e) => (
            e.phase().as_str().to_string(),
            e.fact().or_else(|| state.as_ref().and_then(|s| s.fact.clone())),
            e.error(),
            e.recipient_handle.clone(),
        ),
        None => {
            let s = state.as_ref().unwrap();
            let done = s.next_pending().is_none();
            (
                if done { "done" } else { "failed" }.to_string(),
                s.fact.clone(),
                None,
                s.recipient_handle.clone(),
            )
        }
    };

    let steps: Vec<Value> = state
        .as_ref()
        .map(|s| s.steps.iter().map(wire::snapshot_step_json).collect())
        .unwrap_or_default();

    let body = json!({
        "send_id": id,
        "recipient_handle": recipient_handle,
        "state": state_str,
        "fact": fact,
        "error": error,
        "steps": steps,
    });
    respond_json(request, 200, &body)
}

fn handle_resume(app: &Arc<AppState>, request: Request, id: String) -> io::Result<()> {
    let Ok(state) = SendState::load(&app.home, &id) else {
        return respond_json(request, 404, &wire::error_json("no such send"));
    };
    // Resume is idempotent: the pipeline re-enters at the first pending step,
    // and the run_lock serializes proving even if resume is called twice, so
    // we do not reject a resume on a send that already looks running.
    app.hub.upsert(&id, &state.recipient_handle, SystemTime::now(), Phase::Running);

    let steps: Vec<Value> = state.steps.iter().map(wire::plan_step_json).collect();
    let body = json!({
        "send_id": state.id,
        "recipient_handle": state.recipient_handle,
        "ciphertext_bytes": state.ciphertext_hex.len() / 2,
        "steps": steps,
    });

    app.hub.mark_running(&id);
    spawn_run(Arc::clone(app), id);
    respond_json(request, 200, &body)
}

fn handle_events(app: &Arc<AppState>, request: Request, id: String) -> io::Result<()> {
    let Some(entry) = app.hub.get(&id) else {
        return respond_json(request, 404, &wire::error_json("no such send"));
    };
    let last_event_id = header_value(&request, "Last-Event-ID").and_then(|v| v.trim().parse::<u64>().ok());
    let sub = entry.subscribe(last_event_id);
    let reader = SseReader::from_subscription(sub);

    let headers = vec![
        Header::from_bytes(&b"Content-Type"[..], &b"text/event-stream"[..]).unwrap(),
        Header::from_bytes(&b"Cache-Control"[..], &b"no-cache"[..]).unwrap(),
        // The stream length is unknown; tiny_http chunk-encodes it.
        Header::from_bytes(&b"X-Accel-Buffering"[..], &b"no"[..]).unwrap(),
    ];
    let response = Response::new(StatusCode(200), headers, reader, None, None);
    request.respond(response)
}

// --- the run thread ---------------------------------------------------------

/// Runs a send on its own thread. Acquires `run_lock` first, so proving is
/// serialized across sends. Maps each `PipelineEvent` into the hub (which
/// fans it out to listeners and records it for replay); on error, records a
/// daemon-level `failed` tagged with the step that was running.
pub fn spawn_run(app: Arc<AppState>, send_id: String) {
    std::thread::spawn(move || {
        let _guard = app.run_lock.lock().unwrap();
        app.hub.mark_running(&send_id);

        let mut state = match SendState::load(&app.home, &send_id) {
            Ok(s) => s,
            Err(e) => {
                app.hub.record_failed(&send_id, None, &format!("load send state: {e}"));
                return;
            }
        };

        let mut last_kind: Option<StepKind> = None;
        let result = {
            let hub = &app.hub;
            let id = send_id.as_str();
            app.runner.run(&app.home, &app.config, &mut state, &mut |event: PipelineEvent| {
                if let PipelineEvent::StepStarted { kind, .. } = &event {
                    last_kind = Some(kind.clone());
                }
                hub.record_pipeline_event(id, &event);
            })
        };

        if let Err(e) = result {
            app.hub.record_failed(&send_id, last_kind.as_ref(), &e.to_string());
        }
    });
}

// --- SSE reader -------------------------------------------------------------

/// A chunk of stream bytes plus whether it ends the stream.
struct FrameBytes {
    bytes: Vec<u8>,
    terminal: bool,
}

/// Serializes one recorded frame to its SSE lines: an `id:` for
/// `Last-Event-ID` reconnects and a single-line `data:` JSON object.
fn frame_bytes(frame: &Frame) -> Vec<u8> {
    let json = serde_json::to_string(&frame.json).unwrap_or_else(|_| "{}".into());
    format!("id: {}\ndata: {}\n\n", frame.id, json).into_bytes()
}

/// Streams a send's events. Plays the replay prefix first, then (while live)
/// blocks on the channel, emitting a `:keep-alive` comment every 15s so the
/// phone tells a live stall from a dead socket. EOF closes the stream after
/// the terminal frame.
pub struct SseReader {
    initial: VecDeque<FrameBytes>,
    rx: Option<Receiver<Frame>>,
    buf: Vec<u8>,
    pos: usize,
    eof_after_buf: bool,
}

impl SseReader {
    pub fn from_subscription(sub: Subscription) -> Self {
        let to_fb = |f: Frame| FrameBytes { bytes: frame_bytes(&f), terminal: f.terminal };
        match sub {
            Subscription::Finished { replay } => Self {
                initial: replay.into_iter().map(to_fb).collect(),
                rx: None,
                buf: Vec::new(),
                pos: 0,
                eof_after_buf: false,
            },
            Subscription::Live { replay, rx } => Self {
                initial: replay.into_iter().map(to_fb).collect(),
                rx: Some(rx),
                buf: Vec::new(),
                pos: 0,
                eof_after_buf: false,
            },
        }
    }
}

impl Read for SseReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.pos < self.buf.len() {
                let n = std::cmp::min(out.len(), self.buf.len() - self.pos);
                out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            if self.eof_after_buf {
                return Ok(0);
            }
            if let Some(fb) = self.initial.pop_front() {
                self.buf = fb.bytes;
                self.pos = 0;
                self.eof_after_buf = fb.terminal;
                continue;
            }
            match &self.rx {
                None => return Ok(0), // finished subscription: replay done
                Some(rx) => match rx.recv_timeout(Duration::from_secs(15)) {
                    Ok(frame) => {
                        self.eof_after_buf = frame.terminal;
                        self.buf = frame_bytes(&frame);
                        self.pos = 0;
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        self.buf = b":keep-alive\n\n".to_vec();
                        self.pos = 0;
                    }
                    Err(RecvTimeoutError::Disconnected) => return Ok(0),
                },
            }
        }
    }
}

// --- pure helpers (unit-tested) ---------------------------------------------

/// The daemon is ready to compose when it has a registered handle and a
/// funded account. A balance that could not be read counts as not funded.
pub fn readiness(registered: bool, balance_strk: Option<u128>) -> bool {
    registered && balance_strk.is_some_and(|b| b > 0)
}

/// Validates the compose message: rejects empty (after trim) and over-length.
/// Returns the 422 reason, or `None` when the message is acceptable.
pub fn message_error(message: &str, max_bytes: usize) -> Option<&'static str> {
    if message.trim().is_empty() {
        Some("message is empty")
    } else if message.len() > max_bytes {
        Some("message too long")
    } else {
        None
    }
}

/// The resolve endpoint's status + body, factored out for testing against a
/// fake `ChainReader`.
pub fn resolve_response(reads: &dyn ChainReader, handle: Option<&str>) -> (u16, Value) {
    match handle {
        None => (400, wire::error_json("missing 'handle' query parameter")),
        Some(h) => match reads.resolve(h) {
            Ok((scan_pub, leaf)) => (200, wire::resolve_ok_json(h, leaf, &scan_pub)),
            Err(_) => (404, wire::error_json("handle not registered")),
        },
    }
}

// --- request/response plumbing ----------------------------------------------

fn header_value(request: &Request, field: &str) -> Option<String> {
    // `HeaderField::equiv` wants a `&'static str`; compare by hand so the
    // field name can be a runtime string. HTTP header names are ASCII and
    // case-insensitive.
    request
        .headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(field))
        .map(|h| h.value.as_str().to_string())
}

fn read_body(request: &mut Request) -> String {
    let mut body = String::new();
    let _ = request.as_reader().read_to_string(&mut body);
    body
}

fn respond_json(request: Request, status: u16, body: &Value) -> io::Result<()> {
    let data = serde_json::to_string(body).unwrap_or_else(|_| "{}".into());
    let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
    let response = Response::from_string(data).with_status_code(status).with_header(header);
    request.respond(response)
}

/// A URL query parameter, percent-decoded. Handles are ASCII, but decoding
/// keeps the parser honest for spaces (`+`/`%20`) and stray escapes.
fn query_param(url: &str, key: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == key {
            return Some(percent_decode(v));
        }
    }
    None
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = |c: u8| (c as char).to_digit(16);
                match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    (Some(hi), Some(lo)) => {
                        out.push((hi * 16 + lo) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hub::SendHub;
    use crate::reads::testing::FakeReads;

    #[test]
    fn readiness_needs_handle_and_funds() {
        assert!(readiness(true, Some(5)));
        assert!(!readiness(false, Some(5)), "no handle -> not ready");
        assert!(!readiness(true, Some(0)), "zero balance -> not ready");
        assert!(!readiness(true, None), "unknown balance -> not ready");
    }

    #[test]
    fn message_validation() {
        assert_eq!(message_error("", 100), Some("message is empty"));
        assert_eq!(message_error("   ", 100), Some("message is empty"));
        assert_eq!(message_error(&"x".repeat(101), 100), Some("message too long"));
        assert_eq!(message_error("hello", 100), None);
    }

    #[test]
    fn resolve_response_maps_hit_miss_and_missing() {
        let mut reads = FakeReads::default();
        reads.handles.insert("bob".into(), ("0xbeef".into(), 4));

        let (status, body) = resolve_response(&reads, Some("bob"));
        assert_eq!(status, 200);
        assert_eq!(body, json!({ "handle": "bob", "leaf_index": 4, "scan_pub": "0xbeef" }));

        let (status, body) = resolve_response(&reads, Some("nobody"));
        assert_eq!(status, 404);
        assert_eq!(body, json!({ "error": "handle not registered" }));

        let (status, _) = resolve_response(&reads, None);
        assert_eq!(status, 400);
    }

    #[test]
    fn query_param_parses_and_decodes() {
        assert_eq!(query_param("/v1/resolve?handle=bob", "handle").as_deref(), Some("bob"));
        assert_eq!(query_param("/v1/resolve?handle=a%20b", "handle").as_deref(), Some("a b"));
        assert_eq!(query_param("/v1/resolve?x=1&handle=carol", "handle").as_deref(), Some("carol"));
        assert_eq!(query_param("/v1/resolve", "handle"), None);
    }

    /// End to end at the SSE-bytes boundary: record two events, subscribe to
    /// the finished send, and read the stream to a string. This exercises the
    /// exact framing (`id:`/`data:`) the phone parses, with no chain.
    #[test]
    fn sse_reader_serializes_replay_frames() {
        let hub = SendHub::new();
        hub.upsert("s1", "bob", SystemTime::now(), Phase::Running);
        hub.record_pipeline_event(
            "s1",
            &PipelineEvent::StepStarted { index: 0, total: 6, kind: StepKind::Prove },
        );
        hub.record_pipeline_event("s1", &PipelineEvent::Completed { fact: Some("0xfa".into()) });

        let entry = hub.get("s1").unwrap();
        let mut reader = SseReader::from_subscription(entry.subscribe(None));
        let mut out = String::new();
        reader.read_to_string(&mut out).unwrap();

        assert!(out.contains("id: 1\ndata: {\"index\":0"), "first frame is the step_started: {out}");
        assert!(out.contains("\"type\":\"step_started\""));
        assert!(out.contains("id: 2\ndata: "));
        assert!(out.contains("\"type\":\"done\""));
        assert!(out.ends_with("\n\n"), "stream ends on a blank line");
    }

    /// The run machinery, end to end, with a scripted runner: driving a send
    /// records the full started/completed/done sequence and flips the entry
    /// to done — no prove, no chain.
    #[test]
    fn scripted_run_records_full_sequence() {
        use crate::runner::testing::ScriptedRunner;

        let dir = std::env::temp_dir().join(format!("zkmsgd-run-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let home = Home::new(dir.clone());

        // A minimal persisted send (Prove..SendMessage plan).
        let state = SendState::new_plan(
            "s1".into(),
            "bob".into(),
            "0011".into(),
            vec!["0x1".into()],
            ("0xa".into(), "0xb".into(), "0xc".into()),
            "0xd".into(),
        );
        state.save(&home).unwrap();

        let runner = Arc::new(ScriptedRunner::happy_path(&state));
        let reads = Arc::new(FakeReads::default());
        let config = Config::default_sepolia(std::path::Path::new("/tmp"));
        let app = Arc::new(AppState::new(home, config, "tok".into(), runner, reads));

        app.hub.upsert("s1", "bob", SystemTime::now(), Phase::Running);
        let entry = app.hub.get("s1").unwrap();
        let sub = entry.subscribe(None);
        let rx = match sub {
            Subscription::Live { rx, .. } => rx,
            _ => panic!("running send is live"),
        };

        spawn_run(Arc::clone(&app), "s1".into());

        // Drain until the terminal frame.
        let mut kinds = vec![];
        loop {
            let f = rx.recv_timeout(Duration::from_secs(5)).expect("event within 5s");
            kinds.push(f.json["type"].as_str().unwrap().to_string());
            if f.terminal {
                assert_eq!(f.json["type"], "done");
                break;
            }
        }
        assert!(kinds.contains(&"step_started".to_string()));
        assert!(kinds.contains(&"step_completed".to_string()));
        assert_eq!(kinds.last().unwrap(), "done");
        assert_eq!(entry.phase(), Phase::Done);
        assert_eq!(entry.fact().as_deref(), Some("0xfact"));

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
