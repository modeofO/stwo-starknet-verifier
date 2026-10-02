# snip36-phone-ffi

C ABI over StarkWare's SNIP-36 transaction prover (`starknet_transaction_prover`:
the virtual Starknet OS plus the recursive Stwo prover), so the iOS app proves a
send in-process — no proving service. One call:

    snip36_prove(request_json) -> response_json   // free with snip36_free_string

Request: `{"rpc_url", "chain_id", "block_id": {"block_number": N}, "transaction": <RPC INVOKE v3>}`.
Response: the `starknet_proveTransaction` result (`proof`, `proof_facts`,
`l2_to_l1_messages`) plus timings, or `{"error": "..."}`.

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

Those numbers are the unpatched stack. [`memory-opt/`](memory-opt/README.md)
patches stwo, stwo-circuits and proving-utils to cut peak spill to ~3.1 GiB
with a byte-identical proof; build with `memory-opt/setup.sh` instead of the
steps above. The optimizations are on by default and `SNIP36_OPTIMIZE=0` turns
them off.
