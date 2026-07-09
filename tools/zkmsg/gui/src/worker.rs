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
use zkmsg_core::setup::{SetupEvent, SetupRunner, SetupState};
use zkmsg_core::state::SendState;

pub enum WorkerMsg {
    Progress(PipelineEvent),
    Done(Result<(), String>),
}

/// Progress stream for the profile-setup wizard — same shape as
/// `WorkerMsg`, over `SetupEvent`.
pub enum SetupWorkerMsg {
    Progress(SetupEvent),
    Done(Result<(), String>),
}

pub enum RecommendMsg {
    Recommended(u64),
}

/// One-shot: live gas prices -> recommended funding, static fallback on
/// any read failure. Read-only RPC.
pub fn spawn_recommend(rpc_url: String, ctx: egui::Context) -> Receiver<RecommendMsg> {
    let (tx, rx) = channel();
    thread::spawn(move || {
        let chain = Chain::new(&rpc_url, "");
        let strk = chain
            .gas_prices()
            .map(zkmsg_core::setup::recommended_funding_strk)
            .unwrap_or(zkmsg_core::setup::FALLBACK_FUNDING_STRK);
        let _ = tx.send(RecommendMsg::Recommended(strk));
        ctx.request_repaint();
    });
    rx
}

/// Runs (or resumes) the identity-setup pipeline on a worker thread; the
/// returned receiver yields progress until Done. Mirrors `spawn_send`:
/// blocking chain RPC / subprocess work off the UI thread, one repaint per
/// message. The `SetupRunner` skips already-done steps, so a resumed
/// `state` picks up at the first incomplete step.
pub fn spawn_setup(
    rpc_url: String,
    profile_dir: PathBuf,
    repo_root: PathBuf,
    mut state: SetupState,
    ctx: egui::Context,
) -> Receiver<SetupWorkerMsg> {
    let (tx, rx): (Sender<SetupWorkerMsg>, Receiver<SetupWorkerMsg>) = channel();
    thread::spawn(move || {
        let tx2 = tx.clone();
        let ctx2 = ctx.clone();
        let mut sink = move |e: SetupEvent| {
            let _ = tx2.send(SetupWorkerMsg::Progress(e));
            ctx2.request_repaint();
        };
        let runner =
            SetupRunner { rpc_url: &rpc_url, profile_dir: &profile_dir, repo_root: &repo_root };
        let result = runner.run(&mut state, &mut sink);
        let _ = tx.send(SetupWorkerMsg::Done(result.map_err(|e| format!("{e:#}"))));
        ctx.request_repaint();
    });
    rx
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

/// Compose tab: recipient resolve (read-only) and prepare-before-spend
/// (resolve + root + both merkle paths + encrypt — still no transaction).
/// Both are chain RPC, so both get the one-shot worker-thread treatment;
/// `prepare_send` also persists the `SendState` before returning, so a
/// crash between here and `spawn_send` still leaves a resumable checkpoint.
pub enum ResolveWorkerMsg {
    Resolved(Result<(Felt, u32), String>),
}

pub fn spawn_resolve(home_dir: PathBuf, handle: String, ctx: egui::Context) -> Receiver<ResolveWorkerMsg> {
    let (tx, rx) = channel();
    thread::spawn(move || {
        let home = Home::new(home_dir);
        let result = (|| {
            let config = home.load_config().map_err(|e| format!("{e:#}"))?;
            let chain = Chain::new(&config.rpc_url, &config.account);
            app::resolve_recipient(&chain, &config.store, &handle).map_err(|e| format!("{e:#}"))
        })();
        let _ = tx.send(ResolveWorkerMsg::Resolved(result));
        ctx.request_repaint();
    });
    rx
}

pub enum PrepareWorkerMsg {
    Prepared(Result<SendState, String>),
}

pub fn spawn_prepare(
    home_dir: PathBuf, sender_leaf: u32, handle: String, text: String, ctx: egui::Context,
) -> Receiver<PrepareWorkerMsg> {
    let (tx, rx) = channel();
    thread::spawn(move || {
        let home = Home::new(home_dir);
        let result = (|| {
            let config = home.load_config().map_err(|e| format!("{e:#}"))?;
            let keys = home.load_keys().map_err(|e| format!("{e:#}"))?;
            app::prepare_send(&home, &config, &keys, sender_leaf, &handle, &text)
                .map_err(|e| format!("{e:#}"))
        })();
        let _ = tx.send(PrepareWorkerMsg::Prepared(result));
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

/// Burner retirement: a read-only balance probe and the paid sweep.
pub enum RetireWorkerMsg {
    Balance(Result<u128, String>),
    Swept(Result<(String, u128), String>),
}

/// Read-only: the burner profile's own account balance in fri.
pub fn spawn_retire_balance(home_dir: PathBuf, ctx: egui::Context) -> Receiver<RetireWorkerMsg> {
    let (tx, rx) = channel();
    thread::spawn(move || {
        let result = (|| {
            let config = Home::new(home_dir).load_config().map_err(|e| format!("{e:#}"))?;
            let chain = Chain::new(&config.rpc_url, &config.account);
            let address =
                zkmsg_core::chain::account_address(&config.account).map_err(|e| format!("{e:#}"))?;
            zkmsg_core::setup::read_balance_fri(&chain, &address).map_err(|e| format!("{e:#}"))
        })();
        let _ = tx.send(RetireWorkerMsg::Balance(result));
        ctx.request_repaint();
    });
    rx
}

/// Paid: sweep (balance - headroom) to `to_address` and wait the receipt.
pub fn spawn_sweep(
    home_dir: PathBuf,
    to_address: String,
    ctx: egui::Context,
) -> Receiver<RetireWorkerMsg> {
    let (tx, rx) = channel();
    thread::spawn(move || {
        let result = (|| {
            let config = Home::new(home_dir).load_config().map_err(|e| format!("{e:#}"))?;
            app::sweep_strk(&config, &to_address).map_err(|e| format!("{e:#}"))
        })();
        let _ = tx.send(RetireWorkerMsg::Swept(result));
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
