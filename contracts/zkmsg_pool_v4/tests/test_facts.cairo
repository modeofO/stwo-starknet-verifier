//! facts.cairo: pure parsing and epoch rules, no transaction needed.

use zkmsg_pool_v4::facts::{
    PROOF_VERSION_V1, SendFacts, VIRTUAL_OS_OUTPUT_VERSION, VIRTUAL_SNOS, epoch_is_fresh, epoch_of,
    parse_send_facts, round_block,
};
use crate::common::facts;

#[test]
fn parses_one_message() {
    let f = facts(15850106, 0x1234);
    assert_eq!(
        parse_send_facts(f.span()), SendFacts { base_block_number: 15850106, message_hash: 0x1234 },
    );
}

/// The facts of the first real v3 proof (Sepolia, 2026-10-01) parse; its
/// base block is the one the proof says.
#[test]
fn parses_the_mac_proof() {
    let f = crate::mac_proof::proof_facts();
    let parsed = parse_send_facts(f.span());
    assert_eq!(parsed.base_block_number, 0xf36a4b);
    assert_eq!(parsed.message_hash, *f.at(8));
}

fn with(index: u32, value: felt252) -> Array<felt252> {
    let f = facts(15850106, 0x1234);
    let mut out = array![];
    for i in 0..f.len() {
        out.append(if i == index {
            value
        } else {
            *f.at(i)
        });
    }
    out
}

#[test]
#[should_panic(expected: ('expected one proven message',))]
fn rejects_empty_facts() {
    parse_send_facts(array![].span());
}

#[test]
#[should_panic(expected: ('expected one proven message',))]
fn rejects_two_messages() {
    let mut f = with(7, 2);
    f.append(0x5678);
    parse_send_facts(f.span());
}

#[test]
#[should_panic(expected: ('expected one proven message',))]
fn rejects_a_wrong_message_count() {
    parse_send_facts(with(7, 0).span());
}

#[test]
#[should_panic(expected: ('unsupported proof version',))]
fn rejects_another_proof_version() {
    parse_send_facts(with(0, 'PROOF2').span());
}

#[test]
#[should_panic(expected: ('not a virtual OS proof',))]
fn rejects_another_variant() {
    parse_send_facts(with(1, 'OTHER').span());
}

#[test]
#[should_panic(expected: ('unknown OS output',))]
fn rejects_another_output_version() {
    parse_send_facts(with(3, 'VIRTUAL_SNOS1').span());
}

#[test]
#[should_panic(expected: ('bad base block number',))]
fn rejects_a_non_u64_base_block() {
    parse_send_facts(with(4, 0x10000000000000000).span());
}

#[test]
fn markers_are_the_os_strings() {
    assert_eq!(PROOF_VERSION_V1, 0x50524f4f4631);
    assert_eq!(VIRTUAL_SNOS, 0x5649525455414c5f534e4f53);
    assert_eq!(VIRTUAL_OS_OUTPUT_VERSION, 0x5649525455414c5f534e4f5330);
}

#[test]
fn epochs_and_rounding() {
    assert_eq!(epoch_of(15850106, 1000), 15850);
    assert_eq!(round_block(15850199), 15850100);
    // Current epoch and one behind are fresh; two behind is stale.
    assert!(epoch_is_fresh(15850, 15850126, 1000, 1));
    assert!(epoch_is_fresh(15849, 15850126, 1000, 1));
    assert!(!epoch_is_fresh(15848, 15850126, 1000, 1));
    assert!(!epoch_is_fresh(15849, 15850126, 1000, 0));
    // A proof cannot claim a future epoch.
    assert!(!epoch_is_fresh(15851, 15850126, 1000, 1));
    // Rounding: a base block just past an epoch boundary is still "now"
    // once the head is past it too (epoch_blocks is a multiple of 100).
    assert!(epoch_is_fresh(15851, 15851000 + 10, 1000, 0));
}
