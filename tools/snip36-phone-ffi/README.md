# snip36-phone-ffi

C ABI over StarkWare's SNIP-36 transaction prover (`starknet_transaction_prover`:
the virtual Starknet OS plus the recursive Stwo prover), so the iOS app proves a
send in-process — no proving service. One call:

    snip36_prove(request_json) -> response_json   // free with snip36_free_string

Request: `{"rpc_url", "chain_id", "block_id": {"block_number": N}, "transaction": <RPC INVOKE v3>}`.
Response: the `starknet_proveTransaction` result (`proof`, `proof_facts`,
`l2_to_l1_messages`) plus timings, or `{"error": "..."}`.

**The witness never goes to the RPC.** The virtual transaction's calldata is the
send's witness (membership secret, leaf, Merkle path). `starknet_transaction_prover`
prefetches state by default: before executing, it sends the whole transaction to
the RPC as `starknet_simulateTransactions`. `prover_config` turns that off
(through the runner config's serde form; the field is crate-private), so the
executor reads state key by key instead. A send's prover reads are then the
block header, the account's nonce, class and one storage slot, the prover
contract's class hash, the two classes, and one `getStorageProof` for those two
contracts: nothing that depends on the witness, and no slower (measured
2026-10-07 through a recording proxy: 10 requests, ~11 s of a 21 s prove, either
way). A unit test pins the flag.

Large allocations spill to `$ZKMSG_SPILL_DIR` (see `src/spill_alloc.rs`). The
threshold must equal `tools/privacy-prove-cairo-bridge`'s: both libraries are
built by the same nightly, so the app links one copy of the allocator for both.

## Build

The crate is a member of StarkWare's sequencer workspace (it inherits the
workspace's pinned dependencies), so it is built from a checkout of that
repository, the same way `privacy-prove-cairo-bridge` is built from
proving-utils:

```sh
cd .prover   # gitignored
git clone https://github.com/starkware-libs/sequencer.git
git -C sequencer checkout e6b6fd2e9932909107833579e5b6efd6c75fa0af   # PRIVACY-0.14.3-RC.2
cp -R ../tools/snip36-phone-ffi sequencer/crates/snip36_phone_ffi
# add "crates/snip36_phone_ffi" to [workspace] members in sequencer/Cargo.toml

# the virtual OS program is compiled by a build script that needs Cairo 0
uv venv --python 3.12 sequencer_venv
VIRTUAL_ENV=$PWD/sequencer_venv uv pip install -r sequencer/scripts/requirements.txt

cd sequencer
PATH=$PWD/../sequencer_venv/bin:$PATH RUSTC_WRAPPER= \
  cargo +nightly-2026-01-15 build --release --target aarch64-apple-ios -p snip36_phone_ffi --lib
```

`RUSTC_WRAPPER=` overrides the workspace's sccache setting. There is no
simulator build: `tikv-jemalloc-sys` fails to configure for
`aarch64-apple-ios-sim`.

Desktop: the `snip36-prove` binary (`src/bin/snip36-prove.rs`) is the same code
path for zkmsg-core's SNIP-36 send, run as a subprocess. It reads the request on
stdin (the virtual transaction's calldata is the send's witness, so it never
touches disk) and writes the result to the path it's given:

```sh
cd .prover/sequencer
PATH=$PWD/../sequencer_venv/bin:$PATH RUSTC_WRAPPER= \
  cargo +nightly-2026-01-15 build --release -p snip36_phone_ffi --bin snip36-prove
```

Check before a device run: `cargo run --release -p snip36_phone_ffi --example
prove_cli <request.json> <out>` on the Mac produces a proof byte-identical to
StarkWare's prebuilt prover for the same request (verified 2026-09-29); the
virtual OS program hash is `0x53f6c9fc…6daa1`.

## Measured (zkmsg send statement, ~150k Cairo steps)

| | wall | peak phys_footprint | peak spill |
|---|---|---|---|
| Mac (M-series, 36 GB, spill on) | 16 s | 315 MB | 13.5 GB |
| iPhone 14 Pro (6 GB) | 279 s | 266 MB | 13.9 GB |

The phone needs the `com.apple.developer.kernel.extended-virtual-addressing`
entitlement (paid developer team): without it iOS refuses mappings past
~6.75 GB.

Those numbers are the unpatched stack, which is what the desktop builds.

## Phone build (memory-optimized)

The iOS app links a separately built, patched proving stack. The desktop does
not: its build (`.prover/sequencer`, above) stays as it is.

**Why phone only.** The phone prover is paging-bound: the iPhone 14 Pro spends
most of a send faulting spilled pages in and out, not computing.
[`memory-opt/`](memory-opt/README.md) patches stwo and proving-utils so the
prover stops holding data it never reads again. Peak spill drops from ~13 GiB to
~3.1–3.3 GiB, and the proof is byte-identical. That costs recomputation: on a
Mac, which has the RAM to keep everything resident, it is ~35% slower, so the
desktop keeps the unpatched stack.

| | prove + publish |
|---|---|
| iPhone 14 Pro, unpatched | 261 s |
| iPhone 14 Pro, memory-optimized | 76 s |

(Mac, spill on: peak spill 13.1 → 3.1 GiB, wall 9.4 → 13.5 s.)

**Layout.** Everything is gitignored under the main checkout's `.prover/`
(also when you work from a git worktree):

- `.prover/patched-phone/{stwo,proving-utils}`: upstream checkouts at the
  revisions pinned in `memory-opt/setup.sh`, with `stwo.patch` and
  `proving-utils.patch` applied;
- `.prover/sequencer-phone`: sequencer at `e6b6fd2` (PRIVACY-0.14.3-RC.2) with
  `sequencer.patch` (adds this crate to the workspace and `[patch]`es stwo and
  proving-utils to `../patched-phone`), plus a copy of this crate;
- `.prover/sequencer_venv`: shared with the desktop build, created only if missing.

**Build.**

```sh
tools/snip36-phone-ffi/memory-opt/setup.sh          # = ios
# -> .prover/sequencer-phone/target/aarch64-apple-ios/release/libsnip36_phone_ffi.a
```

`setup.sh [prepare|ios|mac|both]` clones whatever is missing, applies the
patches and copies this crate into `sequencer-phone`, then builds. It is safe to
re-run: it never resets, cleans or deletes. A checkout is moved to its pinned
revision only if its working tree is clean; a patch already applied is left
alone; a patch applied by an earlier run is reversed before its new version
goes on; copying this crate updates files but never removes extra ones (such as
a local `src/bin`). If something conflicts it stops and says what. It never
touches `.prover/sequencer`. `prepare` stops before building; after it, the
build is the usual command run in `.prover/sequencer-phone`:

```sh
cd .prover/sequencer-phone
PATH=$PWD/../sequencer_venv/bin:$PATH RUSTC_WRAPPER= \
  cargo +nightly-2026-01-15 build --release --target aarch64-apple-ios -p snip36_phone_ffi --lib
```

Point zkmsg-ios `App/project.yml` (`LIBRARY_SEARCH_PATHS`) at
`.prover/sequencer-phone/target/aarch64-apple-ios/release`.

**Switches.** The optimizations are compile-time constants in the patched
stwo (`crates/stwo/src/prover/memopt.rs`, read by privacy_prove too). Nothing
reads or sets an environment variable at run time. They are on by default;
building with `SNIP36_MEMOPT=0` in the environment compiles them out (upstream
behavior, same proof bytes). Cargo rebuilds stwo and its dependents when that
variable changes, so keep the baseline in its own target dir.

**A/B.**

```sh
cd .prover/sequencer-phone
export PATH=$PWD/../sequencer_venv/bin:$PATH RUSTC_WRAPPER=
B="cargo +nightly-2026-01-15 build --release"
# phone
$B --target aarch64-apple-ios -p snip36_phone_ffi --lib
SNIP36_MEMOPT=0 CARGO_TARGET_DIR=target-baseline $B --target aarch64-apple-ios -p snip36_phone_ffi --lib
# Mac: prove one fresh request both ways, compare, verify
$B -p snip36_phone_ffi --example prove_cli --example verify_cli
SNIP36_MEMOPT=0 CARGO_TARGET_DIR=target-baseline $B -p snip36_phone_ffi --example prove_cli
ZKMSG_SPILL_DIR=/tmp/spill target/release/examples/prove_cli request.json opt
ZKMSG_SPILL_DIR=/tmp/spill target-baseline/release/examples/prove_cli request.json base
cmp opt.proof base.proof && target/release/examples/verify_cli opt
```

For the phone, link one library or the other and compare the
`snip36 prove finished … prove_ms=… peak_spill_mib=…` log line. `peak_spill_mib`
comes from this library's copy of the spill allocator; the app links one
allocator for both prover libraries, so on the phone it may read 0. A request
must use a recent block: public RPCs keep storage proofs for only a few blocks.

Development only: `--features profiling` turns on `SNIP36_LIVE_PROFILE=<file>`
(live spill sampled every 100 ms). It is off in normal builds.
