# Memory-optimized SNIP-36 prover (phone build only)

Originally by frontboat (`b8669c4`, branch `prover-memory-opt`). Build, layout and
A/B instructions are in [`../README.md`](../README.md#phone-build-memory-optimized);
this file covers what the patches do.

The phone prover spends most of its time paging: an iPhone 14 Pro spilled 13.9 GB
for one send, against an estimated 30–40 s of compute. These patches to stwo and
proving-utils stop the prover keeping data it never reads again. Peak spill drops
from 13.1 GiB to ~3.1 GiB and the proof is byte-identical. On the phone, prove +
publish went from 261 s to 76 s. On a Mac it is ~35% slower (more recomputation,
no paging to save), so the desktop does not use it.

## What changed

Measured on a Mac (M-series, spill on) with one recorded zkmsg send request; every
row is cumulative and produced the same proof bytes. The switches are compile-time
constants in `stwo/crates/stwo/src/prover/memopt.rs`; all of them are on unless the
build environment has `SNIP36_MEMOPT=0`.

| Step | Constant | Peak spill | Wall |
|---|---|---|---|
| Original | – | 13.14 GiB | 9.4 s |
| Build each preprocessed tree just before its proof; free the column pool after the Cairo proof | `LAZY_TREES`, `CLEAR_POOL` | 10.56 | 9.3 |
| After hashing, keep only the first 2/blowup of each extended column; decommit re-extends from coefficients | `TRUNCATE_LDE` | 6.91 | 11.9 |
| Extend and hash 16 columns at a time | `STREAM_COMMIT`, `STREAM_CHUNKS = 1` | 6.32 | 12.4 |
| Don't store the bottom 4 Merkle layers; rebuild the queried subtrees at decommit | `MERKLE_DROP = 4` | 4.34 | 12.4 |
| Drop coefficients of truncated columns; interpolate them from the kept prefix when needed | `DROP_COEFFS` | 3.36 | 13.6 |
| After constraint evaluation, cut those columns to their first 1/blowup | `SHRINK_AFTER_COMPOSITION` | 3.17 | 13.7 |
| Commit one bit-reversed block (a trace-size coset) at a time, so no column is ever fully extended | `BLOCK_COMMIT` | **3.11** | **13.5** |

`PAR_DECOMMIT` gathers decommitted values in parallel, which matters once reads
fault. The extra time is mostly decommit, which re-extends every column to read a
few hundred rows.

Changes from the original commit: the switches were `BENCH_*` environment variables
that the FFI set with `std::env::set_var` on every prove and that stwo and
privacy_prove read with `getenv` while proving. They are now constants, so nothing
reads or writes the environment at run time. The unused `BENCH_STORE_COEFFS` knob
(and with it the stwo-circuits patch), the span-profiling layer
(`SNIP36_SPAN_PROFILE`), `SNIP36_LOG`, and the per-stage timing logs in the
sequencer were dropped; the per-tree memory accounting runs only at debug log level.

## Files

- `stwo.patch`, `proving-utils.patch`: against the revisions pinned in `setup.sh`.
  `stwo.patch` adds `crates/stwo/src/prover/memopt.rs`.
- `sequencer.patch`: adds `snip36_phone_ffi` to the workspace and points stwo and
  proving-utils at `.prover/patched-phone`.
- `setup.sh`: creates or updates `.prover/patched-phone` and `.prover/sequencer-phone`
  and builds. It never touches `.prover/sequencer`.
