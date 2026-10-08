//! The v4 golden vectors (tools/zkmsg/core/testdata/v4_vectors.json, built
//! by tools/zkmsg/core/tests/v4_vectors.rs), checked against the contracts'
//! own functions — the Rust client and this file must agree on every value.
//! The prove_send calldata is replayed verbatim through the real prover.

use snforge_std::MessageToL1SpyTrait;
use snforge_std::spy_messages_to_l1;
use starknet::SyscallResultTrait;
use starknet::syscalls::call_contract_syscall;
use zkmsg_pool_v4::facts::message_hash;
use zkmsg_pool_v4::merkle::{TREE_DEPTH, hash_pair, zero_hash};
use zkmsg_pool_v4::pool::{IZkmsgPoolV4DispatcherTrait, envelope_key};
use zkmsg_pool_v4::prover::{
    NULLIFIER_V4, TICKET_NULL_V4, TICKET_V4, leaf_v3, member_commit, nullifier_v4, send_payload_v4,
    ticket_leaf, ticket_nullifier,
};
use crate::common::{QUOTA, deploy_pool_with, deploy_prover, ticket_secret};

const STORE: felt252 = 0x50f98ee98a0c1a583529c115f394ad79d18686ff66dc1ee25ba0f7bc53669b9;
const MEMBER_SECRET: felt252 = 0x4d3b2a1f00112233445566778899aabbccddeeff00112233445566778899aab;
const SEPOLIA_PROVER: felt252 = 0x0496b7e39ea515c48e8f37dd588ed1ff16c86b3ff7619c6a30ae7b473f902973;

const NULLIFIER_3251_0: felt252 = 0x76326b96000472e47c449966dbadc5eae260e9f1c177f1ffd49fbee2493496a;
const NULLIFIER_3251_9: felt252 = 0x6080365b3613f41eec560b2340abb59badef5ca4e3222c42ec9da9966bd6d31;
const NULLIFIER_3252_0: felt252 = 0x1b606afacdfdce9390016cd7629b79e8961fecce14fd04dabfd9faca4b5281f;
const TICKET1_LEAF: felt252 = 0x6893299d164e622ebf235843d161bc42370da5d44a55f4d8d722dac56f36def;
const TICKET1_NULLIFIER: felt252 = 0xd0aa28a392959e32bbc4cae5d753c3a96dcbd5051743b2ec42843f4131e403;
const TICKET_ROOT_8: felt252 = 0x642fdbf0f58b3405e7ee922139b205c611a8d8512cea14290298e85e840ec4b;
const COMMITMENT: felt252 = 0x8bd512dc0383b1b8;
const CONTENT_HASH: felt252 = 0x1b6038df051fc98a724400633f4776c41f09ae7e9e8a2f03fc25e654874ef06;
const ENVELOPE_KEY: felt252 = 0xdb5df8796eb0f72f8fe37edcb415ac738ca66c55607d6811e1d1d7d4d9b9a;
const SCAN_PUB: felt252 = 0x3948102149cf2d831e1a91e9014fd63216b6b83cdbbbba17fe82ccddf2df054;
const KEM_DIGEST: felt252 = 0x3d9aebb2f9823b47e55d0a962f225afa89da234c4ec60e3e8a366f079775f2e;
const MEMBER_ROOT: felt252 = 0x7a938f628321a57d574fb07c044c64795a9d1954fee29736bfc81b0459dafa6;
const MESSAGE_HASH: felt252 = 0x2c545f9f495912fe51e1e76c5d0e4d23a1ff02aee9a6250b36acdd3fc431e34;

#[test]
fn domains_match() {
    assert_eq!(NULLIFIER_V4, 0x7a6b6d73672d6e756c6c69666965722d7634);
    assert_eq!(TICKET_V4, 0x7a6b6d73672d7469636b65742d7634);
    assert_eq!(TICKET_NULL_V4, 0x7a6b6d73672d7469636b65742d6e756c6c2d7634);
}

#[test]
fn nullifiers_tickets_and_envelope_match() {
    assert_eq!(nullifier_v4(STORE, MEMBER_SECRET, 3251, 0), NULLIFIER_3251_0);
    assert_eq!(nullifier_v4(STORE, MEMBER_SECRET, 3251, 9), NULLIFIER_3251_9);
    assert_eq!(nullifier_v4(STORE, MEMBER_SECRET, 3252, 0), NULLIFIER_3252_0);
    assert_eq!(ticket_secret(1), 0x7111c3700001);
    assert_eq!(ticket_leaf(ticket_secret(1)), TICKET1_LEAF);
    assert_eq!(ticket_nullifier(STORE, ticket_secret(1)), TICKET1_NULLIFIER);
    assert_eq!(envelope_key(COMMITMENT, CONTENT_HASH), ENVELOPE_KEY);
}

/// The fixture pool bought tickets 0..8 in order: its ticket tree is the
/// vectors' (root and ticket 1's path).
#[test]
fn ticket_tree_matches() {
    let (pool, _, _) = deploy_pool_with(deploy_prover().contract_address, QUOTA);
    assert_eq!(pool.n_tickets(), 8);
    assert_eq!(pool.get_ticket_root(), TICKET_ROOT_8);
    assert_eq!(
        pool.get_ticket_path(1),
        array![
            0x251386f00dd769bd9a0132431343bc3bee14393c5c467276b9f06b2908b0bc5,
            0x6cbe0b9beaf9fdab1c0c009a7e575d3ca3056ed0202e5ae6dd3c0c5407e66d2,
            0x52b8c9b2cf16ec833149721744bbd34dff1d8d0d1eb0c9ed0d447f635e73921,
            0x4268c203f18d361afc33a2d15356a4e64f2ca1f507bcefaf6e0daa5a2c4c4b8,
            0x31f82f7b110cf0fedec4381eb2b4ef7bbfb6241276ad81e99f23e64ea3457d2,
            0x55ce2b27b18dc167740cea55bfba4c920bf41455caf86c7ea4b9f7a614b3ac,
            0x1d2fd418edbc17be7e37a4d07fb3f910801b4a469fdcb6ba2ee6156294668,
            0x4f9b1a51a3ec0964b97c108efe065f54e6edd63cf2ef40dfc93f590437cae58,
            0x11d6400cced0057f253dd0f4906d202daec97295c251c1eb3a3ae13bf4442c5,
            0x2828ea3570ae2642abdf689ca78220d7dc45b7be0cc1ae97089a8fe89c739e1,
            0x54355cfccf17e98bf076e119955b58d531ab864c4f8b9606779ec0117ef3fac,
            0x3e170baf04d290e76759a1e2b67fa63739578d9883b7bdc6ba98afffc8992c5,
            0xce682ba73ca032d5dd0f2ccb29a1834b51d4dc850486cf08fdce6969203917,
            0x36480f71ded7948935f02b3755f9c79c3419476c69dfbe5ff9dc742b7136623,
            0x27a7269fa0c704fb77ff85b9579c7b81591a63ac1a68f5763e972d2941b10d1,
            0x1efdc54c79b7b0830cf54eaf000851aea6c543f7d12a193d4e2d596e905a7d8,
            0x3378095e3b6b35069a13555a585e41a8497cacf482520ed422d8a6addf0115a,
            0x1b31d8bdb4b4ca31bbf3902884c8be863315e8433a22e4aa2090c55f236b9a1,
            0x20a0570911d8a00c74573184ac517730de6f8cc0ca547f3449865eeb62b5b45,
            0x57ae865f1792ab222addcd9174fa8ef11d8d4e70149324ec901f7674a18d575,
        ],
    );
}

/// [0xaaa, sender leaf] fold to the vectors' member root.
#[test]
fn member_root_matches() {
    let leaf = leaf_v3(SCAN_PUB, KEM_DIGEST, member_commit(MEMBER_SECRET));
    assert_eq!(leaf, 0x434d12eafde8962c898632cbc11ccd05ca53702b1b2b582a54b1827f45b7ad);
    let mut node = hash_pair(0xaaa, leaf);
    for level in 1..TREE_DEPTH {
        node = hash_pair(node, zero_hash(level));
    }
    assert_eq!(node, MEMBER_ROOT);
}

/// The vectors' prove_send calldata, replayed verbatim through the prover:
/// it emits exactly the vectors' payload, whose message hash (as sent from
/// the Sepolia prover address) is the vectors' MESSAGE_HASH.
#[test]
fn prove_send_calldata_replays() {
    let prover = deploy_prover();
    let calldata = array![
        0x50f98ee98a0c1a583529c115f394ad79d18686ff66dc1ee25ba0f7bc53669b9,
        0x1b6038df051fc98a724400633f4776c41f09ae7e9e8a2f03fc25e654874ef06,
        0x8bd512dc0383b1b8,
        0xe0e0,
        0x7a938f628321a57d574fb07c044c64795a9d1954fee29736bfc81b0459dafa6,
        0xcb3,
        0xa,
        0x642fdbf0f58b3405e7ee922139b205c611a8d8512cea14290298e85e840ec4b,
        0x3948102149cf2d831e1a91e9014fd63216b6b83cdbbbba17fe82ccddf2df054,
        0x3d9aebb2f9823b47e55d0a962f225afa89da234c4ec60e3e8a366f079775f2e,
        0x4d3b2a1f00112233445566778899aabbccddeeff00112233445566778899aab,
        0x2,
        0x1,
        0x14,
        0xaaa,
        0x1fb7169b936dd880cb7ebc50e932a495a60e0084cdab94a681040cb4006e1a0,
        0x17b96a8cee53f9566e4a318ccfe4bd54669d13d4e0ad518ce2905ac58ab6fcd,
        0x4268c203f18d361afc33a2d15356a4e64f2ca1f507bcefaf6e0daa5a2c4c4b8,
        0x31f82f7b110cf0fedec4381eb2b4ef7bbfb6241276ad81e99f23e64ea3457d2,
        0x55ce2b27b18dc167740cea55bfba4c920bf41455caf86c7ea4b9f7a614b3ac,
        0x1d2fd418edbc17be7e37a4d07fb3f910801b4a469fdcb6ba2ee6156294668,
        0x4f9b1a51a3ec0964b97c108efe065f54e6edd63cf2ef40dfc93f590437cae58,
        0x11d6400cced0057f253dd0f4906d202daec97295c251c1eb3a3ae13bf4442c5,
        0x2828ea3570ae2642abdf689ca78220d7dc45b7be0cc1ae97089a8fe89c739e1,
        0x54355cfccf17e98bf076e119955b58d531ab864c4f8b9606779ec0117ef3fac,
        0x3e170baf04d290e76759a1e2b67fa63739578d9883b7bdc6ba98afffc8992c5,
        0xce682ba73ca032d5dd0f2ccb29a1834b51d4dc850486cf08fdce6969203917,
        0x36480f71ded7948935f02b3755f9c79c3419476c69dfbe5ff9dc742b7136623,
        0x27a7269fa0c704fb77ff85b9579c7b81591a63ac1a68f5763e972d2941b10d1,
        0x1efdc54c79b7b0830cf54eaf000851aea6c543f7d12a193d4e2d596e905a7d8,
        0x3378095e3b6b35069a13555a585e41a8497cacf482520ed422d8a6addf0115a,
        0x1b31d8bdb4b4ca31bbf3902884c8be863315e8433a22e4aa2090c55f236b9a1,
        0x20a0570911d8a00c74573184ac517730de6f8cc0ca547f3449865eeb62b5b45,
        0x57ae865f1792ab222addcd9174fa8ef11d8d4e70149324ec901f7674a18d575,
        0x7111c3700001,
        0x1,
        0x14,
        0x251386f00dd769bd9a0132431343bc3bee14393c5c467276b9f06b2908b0bc5,
        0x6cbe0b9beaf9fdab1c0c009a7e575d3ca3056ed0202e5ae6dd3c0c5407e66d2,
        0x52b8c9b2cf16ec833149721744bbd34dff1d8d0d1eb0c9ed0d447f635e73921,
        0x4268c203f18d361afc33a2d15356a4e64f2ca1f507bcefaf6e0daa5a2c4c4b8,
        0x31f82f7b110cf0fedec4381eb2b4ef7bbfb6241276ad81e99f23e64ea3457d2,
        0x55ce2b27b18dc167740cea55bfba4c920bf41455caf86c7ea4b9f7a614b3ac,
        0x1d2fd418edbc17be7e37a4d07fb3f910801b4a469fdcb6ba2ee6156294668,
        0x4f9b1a51a3ec0964b97c108efe065f54e6edd63cf2ef40dfc93f590437cae58,
        0x11d6400cced0057f253dd0f4906d202daec97295c251c1eb3a3ae13bf4442c5,
        0x2828ea3570ae2642abdf689ca78220d7dc45b7be0cc1ae97089a8fe89c739e1,
        0x54355cfccf17e98bf076e119955b58d531ab864c4f8b9606779ec0117ef3fac,
        0x3e170baf04d290e76759a1e2b67fa63739578d9883b7bdc6ba98afffc8992c5,
        0xce682ba73ca032d5dd0f2ccb29a1834b51d4dc850486cf08fdce6969203917,
        0x36480f71ded7948935f02b3755f9c79c3419476c69dfbe5ff9dc742b7136623,
        0x27a7269fa0c704fb77ff85b9579c7b81591a63ac1a68f5763e972d2941b10d1,
        0x1efdc54c79b7b0830cf54eaf000851aea6c543f7d12a193d4e2d596e905a7d8,
        0x3378095e3b6b35069a13555a585e41a8497cacf482520ed422d8a6addf0115a,
        0x1b31d8bdb4b4ca31bbf3902884c8be863315e8433a22e4aa2090c55f236b9a1,
        0x20a0570911d8a00c74573184ac517730de6f8cc0ca547f3449865eeb62b5b45,
        0x57ae865f1792ab222addcd9174fa8ef11d8d4e70149324ec901f7674a18d575,
    ];
    let mut spy = spy_messages_to_l1();
    call_contract_syscall(prover.contract_address, selector!("prove_send"), calldata.span())
        .unwrap_syscall();
    let messages = spy.get_messages().messages;
    assert_eq!(messages.len(), 1);
    let (_, message) = messages.at(0);
    let expected = send_payload_v4(
        STORE,
        COMMITMENT,
        0xe0e0,
        MEMBER_ROOT,
        CONTENT_HASH,
        nullifier_v4(STORE, MEMBER_SECRET, 3251, 2),
        3251,
        10,
        TICKET_ROOT_8,
        TICKET1_NULLIFIER,
    );
    assert_eq!(message.payload.span(), expected.span());
    assert_eq!(message_hash(SEPOLIA_PROVER, 0, expected.span()), MESSAGE_HASH);
}
