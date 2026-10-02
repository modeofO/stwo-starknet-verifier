//! Spike driver for the self-serving client.
//!
//!   zkmsg-gateway head
//!       Latest block number, status and gas prices from the feeder.
//!
//!   zkmsg-gateway events <address> <from_block> [to_block]
//!       Sync blocks and print the events that contract emitted. Proves the
//!       whole premise: event history without an RPC provider.
//!
//!   zkmsg-gateway registry <store_address> <from_block> [to_block]
//!       Same, then rebuild the membership tree locally and print the root,
//!       every handle and its Merkle path — the replacement for the
//!       get_merkle_root / get_merkle_path / get_user view calls.

use anyhow::{anyhow, Result};
use zkmsg_gateway::{feeder::Feeder, Index, Registry};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let feeder = Feeder::integration();

    match args.first().map(String::as_str) {
        Some("head") => {
            let b = feeder.latest()?;
            println!("block   {} ({})", b.block_number, b.status);
            println!("hash    {}", b.block_hash);
            println!(
                "gas fri l1={} l2={} l1_data={}",
                b.l1_gas_price.price_in_fri,
                b.l2_gas_price.price_in_fri,
                b.l1_data_gas_price.price_in_fri
            );
        }
        Some("events") | Some("registry") => {
            let mode = args[0].clone();
            let address = args.get(1).ok_or_else(|| anyhow!("usage: {mode} <address> <from> [to]"))?;
            let from: u64 = args.get(2).ok_or_else(|| anyhow!("missing <from_block>"))?.parse()?;
            let to: u64 = match args.get(3) {
                Some(s) => s.parse()?,
                None => feeder.latest()?.block_number + 1,
            };

            // The feeder rate-limits per IP; 16 workers earns a 429 within a
            // couple of thousand blocks. Tune with ZKMSG_SYNC_WORKERS.
            let workers: usize = std::env::var("ZKMSG_SYNC_WORKERS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(4);
            let started = std::time::Instant::now();
            let mut index = Index::new(address, from);
            let blocks = feeder.blocks(from, to, workers)?;
            for b in &blocks {
                index.absorb(b);
            }
            let secs = started.elapsed().as_secs_f64();
            eprintln!(
                "synced {} blocks [{from}, {to}) in {secs:.1}s ({:.0} blocks/s, {workers} workers) \
                 — {} events from {address}",
                blocks.len(),
                blocks.len() as f64 / secs,
                index.events.len()
            );

            if mode == "events" {
                for e in &index.events {
                    println!("block {} keys={:?} data_len={}", e.block_number, e.keys, e.data.len());
                }
            } else {
                let registry = Registry::rebuild(&index)?;
                println!("root      {:#x}", registry.root());
                println!("members   {}", registry.handles.len());
                for (handle, idx) in &registry.handles {
                    let path = registry.path(*idx);
                    println!("  handle {handle} leaf {idx} path_len {}", path.len());
                }
            }
        }
        _ => {
            eprintln!(
                "usage:\n  zkmsg-gateway head\n  zkmsg-gateway events <address> <from> [to]\n  \
                 zkmsg-gateway registry <store_address> <from> [to]"
            );
            std::process::exit(2);
        }
    }
    Ok(())
}
