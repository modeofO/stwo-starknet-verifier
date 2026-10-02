//! The first v3 send (2026-10-01): proved on a Mac with prove_cli
//! (142,983 virtual-OS steps) against the Sepolia alpha v3 deployment, then
//! published in tx 0x468b1a4f7db737f5d2a4d6ec15b2c566b072d3c0159524a7f1c8ded914bfd64
//! (block 15952478, 1.56 STRK). Test identity `mode`, sending to itself.

pub const STORE: felt252 = 0x0103de677e966a8a72669551093f0f5342621e635531fec146c4b04c5f5d3d9d;
pub const PROVER: felt252 = 0x03d4da714c3bb315fe54017d2556face941836c2d5dfa9cc0b6852b94c0b4f30;
pub const COMMITMENT: felt252 = 0x320839cc6d214aa2e3cf87830b62d74d53b661b6f0c57b17d92652e5f77d61;
pub const EPHEMERAL_PUBKEY: felt252 = 0x455cefc768724c107f19bacdb80131155a035b2d9d549e0e2f45d07a5bcafc9;
pub const MERKLE_ROOT: felt252 = 0x5c819a640d11c27787a6914bb793988b9874afcdb334612014749673e1f69df;
pub const CONTENT_HASH: felt252 = 0x4d93b6154f497b0a5faa35991c08517701ab262353af99f3e6ba0961a6d951d;

/// The proof facts exactly as the proof carried them.
pub fn proof_facts() -> Array<felt252> {
    array![
        0x50524f4f4631,
        0x5649525455414c5f534e4f53,
        0x53f6c9fcfd31d27279ff7d7e422b44623550a732b59fe193354a7316a96daa1,
        0x5649525455414c5f534e4f5330,
        0xf36a4b,
        0x46888aec676ca02a33373c9dc83b8405dd69543724e9c3e3889292d423ecada,
        0x57ed4d5e20d617d8cc087a5882eae4f71d005172326be6439b2e1fd8b4dc57,
        0x1,
        0x7fad8b51e6e99ebcbd1c34fe4a1f79eca9b9716c1fd13ed41b9ead1264315c7,
    ]
}
