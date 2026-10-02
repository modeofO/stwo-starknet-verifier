//! zkmsg core — all logic behind the CLI and GUI (crypto, Merkle tree,
//! the v1 witness builder, chain driver, the SNIP-36 send, send state,
//! config/home, inbox scan).
pub mod app;
pub mod args;
pub mod chain;
pub mod config;
pub mod crypto;
pub mod inbox;
pub mod invoke_v3;
pub mod pipeline;
pub mod profiles;
pub mod sequencer;
pub mod send;
pub mod setup;
pub mod state;
pub mod tree;
pub mod virtual_send;
