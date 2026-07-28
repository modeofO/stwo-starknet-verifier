//! zkmsg companion daemon — the "desktop is sender, phone drives it"
//! server (docs/companion-protocol.md). The phone composes and monitors;
//! the daemon holds the identity, builds the witness, proves, and sends.
//! The witness never leaves the desktop, because the phone never sends one.
//!
//! Everything here is a thin HTTP shell around `zkmsg-core`: `prepare_send`
//! then `Pipeline::run`, with the daemon's own Home/Config/Keys. The novel
//! parts — worth the modules they get — are the SSE fan-out/replay (`hub`)
//! and the wire mapping (`wire`); the rest is routing and auth.

pub mod auth;
pub mod hub;
pub mod reads;
pub mod runner;
pub mod server;
pub mod wire;
