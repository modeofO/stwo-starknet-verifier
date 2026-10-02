# Memory-optimized SNIP-36 prover

The phone prover spends most of its time paging: an iPhone 14 Pro proves a send
in 279 s with 13.9 GB of spill, against an estimated 30–40 s of compute. These
patches to stwo, stwo-circuits and proving-utils stop the prover keeping data it
never reads again. Peak spill drops from 13.1 GiB to 3.1 GiB, and the proof is
byte-identical.

`snip36_phone_ffi` turns the optimizations on by default; `SNIP36_OPTIMIZE=0`
turns them all off. They are not yet measured on a phone.

## What changed

Measured on a Mac (M-series, spill on) with one recorded zkmsg send request;
every row is cumulative and produced the same proof bytes.

| Step | Flag | Peak spill | Wall |
|---|---|---|---|
| Original | – | 13.14 GiB | 9.4 s |
| Build each preprocessed tree just before its proof; free the column pool after the Cairo proof | `BENCH_LAZY_TREES`, `BENCH_CLEAR_POOL` | 10.56 | 9.3 |
| After hashing, keep only the first 2/blowup of each extended column; decommit re-extends from coefficients | `BENCH_TRUNCATE_LDE` | 6.91 | 11.9 |
| Extend and hash 16 columns at a time | `BENCH_STREAM_COMMIT`, `BENCH_STREAM_CHUNKS=1` | 6.32 | 12.4 |
| Don't store the bottom 4 Merkle layers; rebuild the queried subtrees at decommit | `BENCH_MERKLE_DROP=4` | 4.34 | 12.4 |
| Drop coefficients of truncated columns; interpolate them from the kept prefix when needed | `BENCH_DROP_COEFFS` | 3.36 | 13.6 |
| After constraint evaluation, cut those columns to their first 1/blowup | `BENCH_SHRINK_AFTER_COMPOSITION` | 3.17 | 13.7 |
| Commit one bit-reversed block (a trace-size coset) at a time, so no column is ever fully extended | `BENCH_BLOCK_COMMIT` | **3.11** | **13.5** |

`BENCH_PAR_DECOMMIT` gathers decommitted values in parallel, which matters once
reads fault. The extra time is mostly decommit, which re-extends every column to
read a few hundred rows.

Every flag can be set individually in the environment; one already set keeps
its value.

## Run it on a phone

1. Build the patched prover library:

   ```sh
   tools/snip36-phone-ffi/memory-opt/setup.sh ios
   ```

   This clones sequencer, stwo, stwo-circuits and proving-utils at their pinned
   revisions into `.prover/` (gitignored), applies the patches, and builds
   `.prover/sequencer/target/aarch64-apple-ios/release/libsnip36_phone_ffi.a`.
   It needs `rustup`, `uv`, and several GB of disk; the first build takes a while.

2. Build the app's other two static libraries as usual (`privacy-prove-cairo-bridge`
   and `zkmsg-ffi`; see the `OTHER_LDFLAGS` comment in zkmsg-ios `App/project.yml`).

3. In zkmsg-ios (branch `phone-send-integration`), set your own team and bundle id,
   then generate the project:

   ```sh
   cd App
   export DEVELOPMENT_TEAM=<your team id>
   # edit PRODUCT_BUNDLE_IDENTIFIER in project.yml if local.zkmsg.app is taken
   xcodegen generate
   ```

   The `extended-virtual-addressing` entitlement needs a paid developer team.

4. Run on the device from Xcode and send a message. Proving logs go to the Xcode
   console; the summary line is

   ```
   snip36 prove finished precompute_ms=… prove_ms=… peak_spill_mib=… optimized=true
   ```

   Compare `prove_ms`. `peak_spill_mib` comes from this library's copy of the
   spill allocator, but the app links one allocator for both prover libraries
   (the first archive in `OTHER_LDFLAGS`), so on the phone it may read 0.

5. For a baseline on the same phone, add `SNIP36_OPTIMIZE=0` under Product → Scheme
   → Edit Scheme → Run → Environment Variables, run again, and send another message.

Each test is a real send: a message and a Sepolia transaction.

## Check on a Mac

```sh
tools/snip36-phone-ffi/memory-opt/setup.sh mac
cd .prover/sequencer
ZKMSG_SPILL_DIR=/tmp/spill target/release/examples/prove_cli request.json out
SNIP36_OPTIMIZE=0 ZKMSG_SPILL_DIR=/tmp/spill target/release/examples/prove_cli request.json out-base
shasum -a 256 out.proof out-base.proof   # identical
```

`prove_cli` prints the timings, peak spill and disk I/O. `request.json` has the
same shape as the app's request (`rpc_url`, `chain_id`, `block_id`, `transaction`);
use a recent block, since public RPCs keep storage proofs for only a few blocks.
`SNIP36_SPAN_PROFILE=<file>` writes live and peak spill at every span boundary.

## Files

- `stwo.patch`, `stwo-circuits.patch`, `proving-utils.patch`: against the
  revisions pinned in `setup.sh`.
- `sequencer.patch`: adds `snip36_phone_ffi` to the workspace, points the three
  crates above at the patched checkouts, and logs per-stage timings.
- `setup.sh`: applies all of it and builds.
