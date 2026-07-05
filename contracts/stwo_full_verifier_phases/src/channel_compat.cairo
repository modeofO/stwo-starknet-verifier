//! Build-selected channel constructor. The machine code is written against
//! `Channel`/`ChannelTrait`/`Hash` generically; the only site the two builds
//! name differently is `new_channel` (module path). Checkpoint digest fields
//! are typed `Hash` — `felt252` under the poseidon build, `Blake2sHash`
//! (8 u32 words, vendored Serde) under the qm31/blake build — so the seam
//! discipline (checkpoint at n_draws==0 sites) is unchanged.

#[cfg(feature: "poseidon252_verifier")]
pub use stwo_verifier_core::channel::poseidon252::new_channel;

#[cfg(not(feature: "poseidon252_verifier"))]
pub use stwo_verifier_core::channel::blake2s::new_channel;
