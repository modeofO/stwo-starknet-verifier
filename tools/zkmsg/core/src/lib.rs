//! zkmsg core — all logic behind the CLI and GUI (crypto, Merkle tree,
//! chain driver, the SNIP-36 send, send state, config/home, inbox scan).
pub mod app;
pub mod chain;
pub mod config;
pub mod crypto;
pub mod inbox;
pub mod invoke_v3;
pub mod pipeline;
pub mod profiles;
pub mod registry;
pub mod sequencer;
pub mod setup;
pub mod state;
pub mod tickets;
pub mod tree;
pub mod virtual_send;
