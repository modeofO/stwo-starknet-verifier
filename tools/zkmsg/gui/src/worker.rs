//! Background-thread bridge between long-running `zkmsg_core` calls
//! (chain RPC, subprocesses) and the egui UI thread, which must never
//! block on them. Every function here spawns a `std::thread`, does the
//! blocking work off-thread, and reports back over an `mpsc` channel —
//! `ctx.request_repaint()` after each send wakes the UI to drain it.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;

use eframe::egui;
use starknet_types_core::felt::Felt;

use zkmsg_core::app::{self, RegisterOutcome, StatusReport};
use zkmsg_core::chain::Chain;
use zkmsg_core::config::{Config, Home};
use zkmsg_core::inbox::{self, ReceivedMessage};
use zkmsg_core::pipeline::{Pipeline, PipelineEvent};
use zkmsg_core::state::SendState;

pub enum WorkerMsg {
    Progress(PipelineEvent),
    Done(Result<(), String>),
}

/// Runs (or resumes) a send on a worker thread; the returned receiver
/// yields progress until Done. `ctx` is repainted on each message.
pub fn spawn_send(
    home: Home, config: Config, mut state: SendState, ctx: egui::Context,
) -> Receiver<WorkerMsg> {
    let (tx, rx): (Sender<WorkerMsg>, Receiver<WorkerMsg>) = channel();
    thread::spawn(move || {
        let tx2 = tx.clone();
        let ctx2 = ctx.clone();
        let mut sink = move |e: PipelineEvent| {
            let _ = tx2.send(WorkerMsg::Progress(e));
            ctx2.request_repaint();
        };
        let result = Pipeline::new(&home, &config).run(&mut state, &mut sink);
        let _ = tx.send(WorkerMsg::Done(result.map_err(|e| format!("{e:#}"))));
        ctx.request_repaint();
    });
    rx
}

/// Onboarding + status calls. Each does chain RPC (and `register` also
/// waits on a receipt), so each gets its own one-shot thread that sends
/// exactly one message back.
pub enum StatusWorkerMsg {
    Status(Result<StatusReport, String>),
    Init(Result<Felt, String>),
    Register(Result<RegisterOutcome, String>),
}

/// `home_dir` (not `Home`) so the caller can keep its own `Home` alive —
/// `Home` has no `Clone`, and a fresh one from the same dir is equivalent.
pub fn spawn_status(home_dir: PathBuf, ctx: egui::Context) -> Receiver<StatusWorkerMsg> {
    let (tx, rx) = channel();
    thread::spawn(move || {
        let home = Home::new(home_dir);
        let result = app::status(&home).map_err(|e| format!("{e:#}"));
        let _ = tx.send(StatusWorkerMsg::Status(result));
        ctx.request_repaint();
    });
    rx
}

pub fn spawn_init(
    home_dir: PathBuf, account: String, repo_root: PathBuf, ctx: egui::Context,
) -> Receiver<StatusWorkerMsg> {
    let (tx, rx) = channel();
    thread::spawn(move || {
        let home = Home::new(home_dir);
        let result =
            app::init_identity(&home, &account, None, &repo_root).map_err(|e| format!("{e:#}"));
        let _ = tx.send(StatusWorkerMsg::Init(result));
        ctx.request_repaint();
    });
    rx
}

pub fn spawn_register(
    home_dir: PathBuf, handle: String, ctx: egui::Context,
) -> Receiver<StatusWorkerMsg> {
    let (tx, rx) = channel();
    thread::spawn(move || {
        let home = Home::new(home_dir);
        let result = app::register(&home, &handle).map_err(|e| format!("{e:#}"));
        let _ = tx.send(StatusWorkerMsg::Register(result));
        ctx.request_repaint();
    });
    rx
}

pub enum InboxWorkerMsg {
    Scan(Result<Vec<ReceivedMessage>, String>),
}

/// Inbox scan: `getEvents` over the store plus a local trial-decrypt per
/// event — read-only chain RPC, so it gets the same one-shot worker-thread
/// treatment as `spawn_status`.
pub fn spawn_inbox(home_dir: PathBuf, ctx: egui::Context) -> Receiver<InboxWorkerMsg> {
    let (tx, rx) = channel();
    thread::spawn(move || {
        let home = Home::new(home_dir);
        let result = (|| {
            let config = home.load_config().map_err(|e| format!("{e:#}"))?;
            let keys = home.load_keys().map_err(|e| format!("{e:#}"))?;
            let chain = Chain::new(&config.rpc_url, &config.account);
            let scan_priv = keys.scan_priv_felt().map_err(|e| format!("{e:#}"))?;
            inbox::scan(&chain, &config.store, &scan_priv).map_err(|e| format!("{e:#}"))
        })();
        let _ = tx.send(InboxWorkerMsg::Scan(result));
        ctx.request_repaint();
    });
    rx
}
