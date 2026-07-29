//! Live tests against sepolia-integration's feeder gateway.
//!
//! These hit the network, so they are `#[ignore]` by default:
//!     cargo test -p zkmsg-gateway -- --ignored --nocapture
//!
//! They pin the claim this crate rests on — that a feeder-only network still
//! yields the event history zkmsg needs — against on-chain facts from the qm31
//! campaign (tools/qm31-gate-probe/README.md), which cannot be reproduced
//! locally and would silently rot if the feeder's shape changed.

use zkmsg_gateway::{feeder::Feeder, normalize_felt, Index};

/// STRK fee token on integration: every transaction pays fees, so its Transfer
/// events are a dense, always-present signal for validating decoding.
const STRK: &str = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";

/// The canonical Starknet `Transfer` event selector.
const TRANSFER_SELECTOR: &str = "0x99cd8bde557814842a3121e8ddfd433a539b8c9f14bf31ebf108d12e6196e9";

/// Block containing the campaign's `mul_qm31(100)` call — the first qm31
/// execution on a StarkWare-operated network.
const CAMPAIGN_BLOCK: u64 = 13_888_040;

#[test]
#[ignore = "network"]
fn feeder_serves_blocks_with_receipts_and_events() {
    let feeder = Feeder::integration();
    let block = feeder.block(CAMPAIGN_BLOCK).expect("campaign block");

    assert_eq!(block.block_number, CAMPAIGN_BLOCK);
    assert!(!block.transaction_receipts.is_empty(), "no receipts — feeder shape changed");
    let events: usize = block.transaction_receipts.iter().map(|r| r.events.len()).sum();
    assert!(events > 0, "no events in receipts — feeder shape changed");
    assert!(!block.l2_gas_price.price_in_fri.is_empty(), "no l2 gas price");
}

#[test]
#[ignore = "network"]
fn head_is_live_and_ahead_of_the_campaign() {
    let latest = Feeder::integration().latest().expect("latest block");
    assert!(
        latest.block_number > CAMPAIGN_BLOCK,
        "chain head {} is behind the campaign block {CAMPAIGN_BLOCK}",
        latest.block_number
    );
}

#[test]
#[ignore = "network"]
fn indexes_events_for_one_contract_without_rpc() {
    let feeder = Feeder::integration();
    let from = CAMPAIGN_BLOCK - 5;
    let to = CAMPAIGN_BLOCK + 5;

    let mut index = Index::new(STRK, from);
    for block in feeder.blocks(from, to, 8).expect("sync range") {
        index.absorb(&block);
    }

    assert!(!index.events.is_empty(), "no STRK events across 10 blocks — decoding is wrong");
    assert_eq!(index.next_block, to, "sync cursor did not advance to the end of the range");

    // Every event must be attributed to the requested contract, and fee
    // transfers must decode as Transfer with (from, to) keys and (lo, hi) data.
    for e in &index.events {
        assert_eq!(normalize_felt(&e.from_address), normalize_felt(STRK));
        assert_eq!(normalize_felt(&e.keys[0]), normalize_felt(TRANSFER_SELECTOR));
        assert_eq!(e.keys.len(), 3, "Transfer should carry [selector, from, to]");
        assert_eq!(e.data.len(), 2, "u256 amount should be (low, high)");
        assert!((from..to).contains(&e.block_number));
    }
}

#[test]
#[ignore = "network"]
fn selector_filter_selects() {
    let feeder = Feeder::integration();
    let mut index = Index::new(STRK, CAMPAIGN_BLOCK);
    index.absorb(&feeder.block(CAMPAIGN_BLOCK).expect("campaign block"));

    let transfer = zkmsg_core::chain::snkeccak("Transfer");
    assert_eq!(
        normalize_felt(&format!("{transfer:#x}")),
        normalize_felt(TRANSFER_SELECTOR),
        "snkeccak disagrees with the canonical Transfer selector"
    );

    let hits = index.with_key0(transfer).count();
    let misses = index.with_key0(zkmsg_core::chain::snkeccak("NoSuchEventName")).count();
    assert!(hits > 0, "no Transfer events matched");
    assert_eq!(misses, 0, "a nonexistent selector matched events");
}
