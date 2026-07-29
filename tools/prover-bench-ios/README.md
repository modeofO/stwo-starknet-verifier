# iOS prover bench

Runs the real Stwo `prove` + `wrap` pipeline on an iPhone and reports peak
`phys_footprint` — the memory ledger iOS jetsam actually enforces. The app
links `privacy_prove_cairo_bridge` as a staticlib through the `zkmsg_prove` /
`zkmsg_wrap` C entry points in `tools/privacy-prove-cairo-bridge/src/lib.rs`,
so it exercises the same soundness-critical code the desktop CLI runs.

Workload is the public `poseidon_chain(100)` fixture. No key material is
bundled.

## Result (2026-07-29, iPhone 12 Pro, A14, 5.6 GB RAM, iOS 27.0)

| Leg | wall | peak phys_footprint | peak live spill |
|---|---|---|---|
| prove | 31.8 s | 14 MB | 5.8 GB |
| wrap (bundled input) | 495 s | 295 MB | 14.4 GB |
| wrap (phone's own proof) | 547 s | 165 MB | 14.4 GB |

Both wrap outputs are 36,022 felts, byte-identical to host wraps of the same
inputs. End-to-end phone-only is 9m39s. Analysis: `docs/phone-first-design.md`.

The enabling piece is the spill allocator (`spill_alloc.rs`), which routes
allocations ≥ 4 MiB into unlinked file-backed mappings — excluded from
`phys_footprint` and evictable — activated by setting `ZKMSG_SPILL_DIR`.

## Requirements

- **`com.apple.developer.kernel.extended-virtual-addressing`** (already in
  the generated entitlements). Without it, iOS caps the process near ~7 GB of
  mappings and the wrap leg dies on `mmap` ENOMEM. `increased-memory-limit`
  is NOT needed — footprint never approaches the jetsam ceiling.
- ~20 GB free flash for the wrap leg's spill files (the app preflights this
  and skips wrap if short).
- A device build. Simulator runs work too but validate only the toolchain,
  not jetsam or paging.

## Build and run

```sh
cd fixtures && scarb build && cd ..          # once: build the task
./scripts/setup-prover.sh                    # once: build the host bridge
cd tools/prover-bench-ios
./prepare-fixtures.sh                        # stage bundled workload

rustup target add aarch64-apple-ios
(cd ../../.prover/proving-utils && cargo build --release --target aarch64-apple-ios -p privacy-prove-cairo-bridge)

export DEVELOPMENT_TEAM=XXXXXXXXXX           # your Apple team id
xcodegen generate
xcodebuild -project ProverBench.xcodeproj -scheme ProverBench \
    -destination "id=<device-udid>" \
    -allowProvisioningUpdates -allowProvisioningDeviceRegistration \
    -derivedDataPath build build
xcrun devicectl device install app --device <device-udid> \
    build/Build/Products/Debug-iphoneos/ProverBench.app
xcrun devicectl device process launch --device <device-udid> \
    --console --terminate-existing dev.frontboat.zkmsg-prover-bench
```

The bench auto-runs on launch and prints `[bench] <leg>: exit=… wall=… peak_footprint=… peak_spill=…`
per leg, then `ALL LEGS COMPLETE`. Retrieve the produced proof with:

```sh
xcrun devicectl device copy from --device <device-udid> \
    --domain-type appDataContainer --domain-identifier dev.frontboat.zkmsg-prover-bench \
    --source tmp/bench_felts.json --destination phone_felts.json
```

Notes: a free personal team works, but needs
`-allowProvisioningDeviceRegistration` on the first build for a new device.
Targeting an iOS version newer than the release SDK requires the matching
Xcode beta (`DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer`).
