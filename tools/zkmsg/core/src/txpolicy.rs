//! The one transaction-shape policy every zkmsg client follows, so a phone's
//! transactions and a desktop's look the same on chain (red team 2026-10,
//! fingerprints F3/F4: phone register used hard-coded July prices, desktop
//! register went through sncast at 1.5× everything, CLI/GUI/phone publish
//! bounds all differed). Pinned in `testdata/v4_vectors.json` ("policy")
//! for zkmsg-ios.
//!
//! Per transaction kind: fixed `max_amount`s; each `max_price_per_unit` =
//! ceil(price × 3/2) rounded UP to two significant figures (two clients
//! reading the same block's prices get identical bounds); one tip for all;
//! L1 DA modes; empty paymaster and deployment data.
//!
//! And the publish schedule: the proof's base block is rounded down to a
//! multiple of 32 (hiding when Send was pressed within ~55 s), and the
//! publish waits until a random 90–110 blocks after it (hiding how fast the
//! device proved).

use anyhow::{Result, ensure};

use crate::invoke_v3::{Bounds, ResourceBounds};

/// The tip of every zkmsg transaction, in fri per L2 gas: the modal tip of
/// ordinary Sepolia INVOKE v3 transactions (1,235 of 1,277 in blocks
/// 16257334–16257733, 2026-10-07: 96.7%), within the pool's 1e9 cap.
pub const TIP: u64 = 100_000_000;

/// L1 data gas of every kind (measured ≤ 3,040 for register, 384–512 for a
/// publish).
pub const L1_DATA_GAS: u64 = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxKind {
    /// The pool's unsigned `send_message`. Its L2 amount is the pool's
    /// `min_l2_gas` (100M; a publish measures ~79.5M).
    Publish,
    /// `register` from the member's account (measured 9.3–17.7M L2 gas).
    Register,
    /// `[approve, buy_tickets]` in one multicall from the member's account,
    /// at most `MAX_TICKETS_PER_PURCHASE` tickets (measured 2 tickets:
    /// approve 1.6M + buy 10.6–19.1M as separate transactions).
    BuyTickets,
    /// The setup wizard's STRK transfer to a new account (an ERC20
    /// `transfer`, ~1.6M L2 gas like `approve`).
    Transfer,
}

/// Tickets per purchase the `BuyTickets` amount is sized for.
pub const MAX_TICKETS_PER_PURCHASE: usize = 8;

impl TxKind {
    pub fn l2_gas(self) -> u64 {
        match self {
            Self::Publish => 100_000_000,
            Self::Register => 30_000_000,
            Self::BuyTickets => 80_000_000,
            Self::Transfer => 10_000_000,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Publish => "publish",
            Self::Register => "register",
            Self::BuyTickets => "buy_tickets",
            Self::Transfer => "transfer",
        }
    }
}

/// `x` rounded UP to two significant figures (0 stays 0).
pub fn round_up_2sf(x: u128) -> u128 {
    let mut scale = 1u128;
    while x / scale >= 100 {
        scale *= 10;
    }
    x.div_ceil(scale) * scale
}

/// `x` rounded DOWN to two significant figures.
pub fn round_down_2sf(x: u128) -> u128 {
    let mut scale = 1u128;
    while x / scale >= 100 {
        scale *= 10;
    }
    x / scale * scale
}

/// The price bound for a current price: ceil(p × 3/2), up to 2 s.f.
pub fn price_bound(price: u128) -> u128 {
    round_up_2sf((price * 3).div_ceil(2))
}

/// Bounds for `kind` at the latest block's `(l1, l2, l1_data)` prices.
pub fn bounds(kind: TxKind, (l1, l2, l1_data): (u128, u128, u128)) -> Bounds {
    Bounds {
        l1_gas: ResourceBounds { max_amount: 0, max_price_per_unit: price_bound(l1) },
        l2_gas: ResourceBounds { max_amount: kind.l2_gas(), max_price_per_unit: price_bound(l2) },
        l1_data_gas: ResourceBounds { max_amount: L1_DATA_GAS, max_price_per_unit: price_bound(l1_data) },
    }
}

/// The most a transaction with `bounds` and `tip` can be charged (the
/// pool's `max_possible_fee`).
pub fn max_fee(bounds: &Bounds, tip: u64) -> u128 {
    [bounds.l1_gas, bounds.l2_gas, bounds.l1_data_gas]
        .iter()
        .map(|b| (b.max_amount as u128).saturating_mul(b.max_price_per_unit))
        .fold(0u128, u128::saturating_add)
        .saturating_add((bounds.l2_gas.max_amount as u128).saturating_mul(tip as u128))
}

/// Publish bounds within the pool's fee policy. The L2 price bound is the
/// shared rule, lowered (to 2 s.f., down) to what the ticket allows when
/// the rule would exceed it; refused when that leaves less than 1.1× the
/// current price, where the publish could sit unincluded.
pub fn publish_bounds(
    prices: (u128, u128, u128),
    pool_max_fee: u128,
    pool_max_tip: u128,
    pool_min_l2_gas: u64,
) -> Result<Bounds> {
    ensure!(TIP as u128 <= pool_max_tip, "the shared tip exceeds the pool's tip cap");
    ensure!(
        TxKind::Publish.l2_gas() >= pool_min_l2_gas,
        "the pool wants at least {pool_min_l2_gas} L2 gas; the shared publish bound is {}",
        TxKind::Publish.l2_gas()
    );
    let mut b = bounds(TxKind::Publish, prices);
    let l1_data = L1_DATA_GAS as u128 * b.l1_data_gas.max_price_per_unit;
    let cap = pool_max_fee
        .saturating_sub(l1_data)
        .checked_div(b.l2_gas.max_amount as u128)
        .unwrap_or(0)
        .saturating_sub(TIP as u128);
    if b.l2_gas.max_price_per_unit > cap {
        b.l2_gas.max_price_per_unit = round_down_2sf(cap);
    }
    ensure!(
        b.l2_gas.max_price_per_unit >= (prices.1 * 11).div_ceil(10),
        "L2 gas costs {} fri now; a ticket covers at most {} — wait for cheaper gas",
        prices.1,
        b.l2_gas.max_price_per_unit
    );
    ensure!(max_fee(&b, TIP) <= pool_max_fee, "publish bounds exceed the pool's fee cap");
    Ok(b)
}

// --- the publish schedule ---------------------------------------------------

/// The base block is a multiple of this…
pub const BASE_ROUND: u64 = 32;
/// …at least this many blocks behind the head (the gateway refuses a proof
/// on a block fewer than 10 behind).
pub const BASE_MIN_AGE: u64 = 10;
/// The publish waits until `base + PUBLISH_DELAY + j`…
pub const PUBLISH_DELAY: u64 = 90;
/// …with j uniform in `0..=PUBLISH_JITTER`.
pub const PUBLISH_JITTER: u64 = 20;

/// base = floor((head − 10) / 32) × 32.
pub fn base_block(head: u64) -> u64 {
    head.saturating_sub(BASE_MIN_AGE) / BASE_ROUND * BASE_ROUND
}

/// The first head at which the publish may go out, for jitter `j`.
pub fn publish_after(base: u64, j: u64) -> u64 {
    base + PUBLISH_DELAY + j.min(PUBLISH_JITTER)
}

/// Display-only: Sepolia's block time, for "publishing in ~N min".
pub const SECONDS_PER_BLOCK_ESTIMATE: f64 = 1.7;

/// "~2 min" for a wait of `blocks`.
pub fn wait_label(blocks: u64) -> String {
    let secs = blocks as f64 * SECONDS_PER_BLOCK_ESTIMATE;
    if secs < 90.0 { format!("~{:.0} s", secs.max(1.0)) } else { format!("~{:.0} min", secs / 60.0) }
}

/// A fresh uniform jitter.
pub fn jitter() -> u64 {
    use rand::Rng;
    rand::rngs::OsRng.gen_range(0..=PUBLISH_JITTER)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounding_to_two_significant_figures() {
        assert_eq!(round_up_2sf(0), 0);
        assert_eq!(round_up_2sf(7), 7);
        assert_eq!(round_up_2sf(99), 99);
        assert_eq!(round_up_2sf(100), 100);
        assert_eq!(round_up_2sf(101), 110);
        assert_eq!(round_up_2sf(27_136_347_273), 28_000_000_000);
        assert_eq!(round_up_2sf(27_000_000_000), 27_000_000_000);
        assert_eq!(round_down_2sf(29_899_996_764), 29_000_000_000);
        // Sepolia 2026-10-07 prices.
        assert_eq!(price_bound(18_090_898_182), 28_000_000_000);
        assert_eq!(price_bound(52_616_363_968_810), 79_000_000_000_000);
        assert_eq!(price_bound(52_616), 79_000);
    }

    #[test]
    fn bounds_per_kind() {
        let prices = (52_616_363_968_810, 18_090_898_182, 52_616);
        for (kind, l2) in [(TxKind::Publish, 100_000_000), (TxKind::Register, 30_000_000), (TxKind::BuyTickets, 80_000_000)] {
            let b = bounds(kind, prices);
            assert_eq!(b.l1_gas, ResourceBounds { max_amount: 0, max_price_per_unit: 79_000_000_000_000 });
            assert_eq!(b.l2_gas, ResourceBounds { max_amount: l2, max_price_per_unit: 28_000_000_000 });
            assert_eq!(b.l1_data_gas, ResourceBounds { max_amount: 4_096, max_price_per_unit: 79_000 });
        }
        // Nearby reads of the same block agree; a price change inside the
        // rounding step does not move the bound.
        assert_eq!(bounds(TxKind::Register, (0, 18_100_000_000, 0)), bounds(TxKind::Register, (0, 18_090_898_182, 0)));
    }

    #[test]
    fn publish_bounds_fit_the_ticket() {
        let (fee, tip, min) = (3_000_000_000_000_000_000, 1_000_000_000, 100_000_000);
        let b = publish_bounds((52_616_363_968_810, 18_090_898_182, 52_616), fee, tip, min).unwrap();
        assert_eq!(b.l2_gas.max_price_per_unit, 28_000_000_000);
        assert!(max_fee(&b, TIP) <= fee);
        // Pricier: the shared rule (36e9) is capped at 29e9.
        let b = publish_bounds((0, 24_000_000_000, 0), fee, tip, min).unwrap();
        assert_eq!(b.l2_gas.max_price_per_unit, 29_000_000_000);
        assert!(max_fee(&b, TIP) <= fee);
        // Past 1.1x of the cap: refused before anything is sent.
        assert!(publish_bounds((0, 27_000_000_000, 0), fee, tip, min).is_err());
        // A pool asking for more L2 gas than the shared bound is refused.
        assert!(publish_bounds((0, 1, 0), fee, tip, 150_000_000).is_err());
    }

    #[test]
    fn base_and_schedule() {
        assert_eq!(base_block(16_257_200), 16_257_184);
        assert_eq!(base_block(16_257_194), 16_257_184);
        assert_eq!(base_block(16_257_193), 16_257_152);
        for head in 16_000_000..16_000_100 {
            let base = base_block(head);
            assert_eq!(base % BASE_ROUND, 0);
            assert!(head - base >= BASE_MIN_AGE && head - base < BASE_MIN_AGE + BASE_ROUND);
        }
        assert_eq!(publish_after(1_000, 0), 1_090);
        assert_eq!(publish_after(1_000, 20), 1_110);
        assert_eq!(publish_after(1_000, 99), 1_110, "jitter is clamped");
        for _ in 0..200 {
            assert!(jitter() <= PUBLISH_JITTER);
        }
    }
}
