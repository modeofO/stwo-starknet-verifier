//! The first v2 send (2026-10-01): proved on a Mac with snip36-phone-ffi's
//! prove_cli (142,905 virtual-OS steps) against the Sepolia alpha deployment,
//! then published in tx 0x135dec2b9689f390761d086a5b750e74468385c8287c9fcdec12dfd9d17612b
//! (block 15947222, 1.60 STRK). Test identity `mode`, sending to itself.

pub const STORE: felt252 = 0x04dc92ef9a90d336a79188c5408cdf9ce480f3ecd5b1ce55ef2ca207f2c3afe8;
pub const PROVER: felt252 = 0x02d993bd9e1229367fe9643151fdb7b2fb9fe06b28e6ff0d2f1d451894182d79;
pub const COMMITMENT: felt252 = 0x8f0adddb8f03377402ee878515d84f930e3e394181365d301a6fcf3e3553e9;
pub const EPHEMERAL_PUBKEY: felt252 = 0x221755f8aa4a3541268e86bd8cdcf22efe629b952c74bc1df61107bc43de8e0;
pub const MERKLE_ROOT: felt252 = 0x71ef7990dd66b8122459eb97809638744b958f5fa7258ba8b05c08f580d53d2;
pub const CONTENT_HASH: felt252 = 0x1cd8e959e3a60ecf8fba11eda0799699c3df27465a938de2510417996ec16b2;

/// The proof facts exactly as the proof carried them.
pub fn proof_facts() -> Array<felt252> {
    array![
        0x50524f4f4631,
        0x5649525455414c5f534e4f53,
        0x53f6c9fcfd31d27279ff7d7e422b44623550a732b59fe193354a7316a96daa1,
        0x5649525455414c5f534e4f5330,
        0xf355be,
        0x36871ec4cf17d9a0c29270fe6bad9d36348638726922132e00bd7fcb2a78a0b,
        0x57ed4d5e20d617d8cc087a5882eae4f71d005172326be6439b2e1fd8b4dc57,
        0x1,
        0x1d26348c673004a919dfb587d0f997c159b93c6936e28e251d221621cb8575f,
    ]
}
