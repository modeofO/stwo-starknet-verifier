//! zkmsg core — all logic behind the CLI and GUI (crypto, Merkle tree,
//! circuit args, proof packing, chain driver, the resumable send
//! pipeline, send state, config/home, inbox scan).
pub mod app;
pub mod args;
pub mod chain;
pub mod config;
pub mod crypto;
pub mod inbox;
pub mod pack;
pub mod pipeline;
pub mod profiles;
pub mod state;
pub mod tree;
