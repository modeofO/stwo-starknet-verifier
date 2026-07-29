# Phone-first zkmsg — design for the qm31 era

Written 2026-07-29, the day qm31 landed on sepolia-integration
(tools/qm31-gate-probe/README.md). Goal: **everything — identity, send,
receive — from a phone, with minimal STRK**, eliminating the desktop as
trusted infrastructure. This doc is the redesign the qm31 unlock makes
possible; the measurement campaign at the end is what turns its estimates
into numbers.

## Where the pieces already are

The Phase A/B split left the system in a surprisingly phone-ready state:

| Capability | Status |
|---|---|
| Crypto (Poseidon, Pedersen, Stark ECDSA/ECDH, AES-GCM), Keychain custody | **native Swift, shipped** (`zkmsg-ios/Sources/ZkmsgCore`) |
| Starknet RPC, SNIP-8 v3 tx hashing, sign + submit invoke/deploy_account | **native Swift, shipped** (`StarknetAccount.swift` already submits register + deploy_account) |
| Inbox scan (trial-ECDH over `MessageSent` events, incremental checkpoints) | **native Swift, shipped** |
| Burner ceremony (keys → counterfactual address → await deposit → deploy → register), resumable | **native Swift, shipped** (`BurnerSetup.swift`) |
| Witness build + encrypt + prove | desktop (`privacy_prove_cairo_bridge prove`, ~30 s, **7.0–7.9 GB peak**) |
| Wrap (cairo-verifier circuit → multiverifier → ~36k felts) | desktop (`… wrap`, ~10–13 s, **13.6–24.6 GB peak**) |
| Stage / verify / publish txs | desktop daemon signs + submits via sncast |

The trust boundary is sharp and lucky:

- **Prove touches the witness** (scan key, Merkle path, ECDH secret →
  content key). It can never be outsourced. It must run on the phone.
- **Wrap's inputs are entirely public** — the 2.2 MB `CairoProof` JSON and
  the 4-felt output preimage (docs/proof-only-wrapping.md). Anyone may run
  it. It does not need to be *your* desktop, or trusted at all.
- Everything else (signing, submission, reading) the phone already does.

## The architecture

```
┌─ iPhone ─────────────────────────────┐
│ keys · witness · encrypt · PROVE     │      ┌─ wrap relay (untrusted) ─┐
│ verify wrapped proof (native, cheap) │ ───▶ │ CairoProof + preimage in │
│ sign + submit ONE tx                 │ ◀─── │ 36k-felt stream out      │
│ inbox scan                           │      └──────────────────────────┘
└──────────────┬───────────────────────┘
               ▼
   Starknet: [ verify_and_register(proof) , send_message(...) ]  ← one invoke
```

1. **Contracts v4 (qm31 build).** Rebuild lane-1 phases with
   `--features qm31_opcode` (already declared on integration: verify total
   1.087e9 gas < the 1.21e9 invoke cap). Collapse `verify_phase1`/`phase2`
   back to the vendored monolithic `verify_circuit`: delete
   `resumable.cairo`'s `Checkpoint`, the `checkpoint_words` storage, the
   `fri_value_offset` plumbing, and the query-position rebinding — all of
   it existed only because verify couldn't fit one tx. Keep `stage_proof`
   as the oversize fallback. The two-library-class split stays (that's the
   81,920-felt CASM cap, an independent constraint).
2. **One transaction per message.** An account multicall:
   `[registry.verify_and_register(calldata proof), store.send_message(commitment, eph_pub, root, ct)]`.
   1.087e9 + 3.3M fits the cap. When the packed proof exceeds the
   ~4,960-slot calldata budget (5,000 minus envelope), fall back to
   stage (+~0.8 STRK) then verify+publish — 2 txs, still down from 4.
3. **Wrap relay replaces the daemon.** A stateless HTTP service:
   `POST {cairo_proof, preimage}` → felts. No pairing, no bearer token
   ceremony, no Tailscale; rate-limit and go. Anyone can run one
   (community, or your own box). The phone defends itself two ways:
   - pre-spend gate: check the printed inner root against the pinned
     `INNER_ROOT` (as `pipeline.rs` does today);
   - **verify the wrapped proof on-device** with the native Rust stwo
     verifier (fast, low-memory) before submitting — a malicious or buggy
     relay can then waste your time but never your provisioned fee. This
     kills the burned-fee griefing vector (24.47 STRK was burned once on a
     bad bound; a bad proof would do the same).
4. **On-device proving.** Cross-compile the bridge's `prove` leg
   (stwo-cairo + privacy bootloader, pinned `proving-utils` rev) as a Rust
   static library for `aarch64-apple-ios`, Swift FFI on top. stwo is
   portable Rust (wasm32/wasm64 are CI-enforced targets; portable-SIMD →
   NEON). The blocker is memory, not portability — see below.
5. **No sncast, no scarb at runtime.** The phone speaks raw RPC (it
   already does); the circuit executable ships as a bundled fixture.
6. **Fees.** Keep the pinned-bounds discipline (`l1_data_gas` headroom
   included). Optionally, an `execute_from_outside_v3` paymaster path
   later (costs ~30 felts of calldata envelope) so burners can spend
   sponsor-held STRK — orthogonal to this design.

## The proving-memory problem — measured (2026-07-29)

7.9 GB peak does not fit an iPhone (a 15/16/17 Pro with the
increased-memory entitlement gets roughly 5–6 GB usable; iPad Pro 16 GB is
comfortable today). The docs called the peak "a parameter artifact, not
physics" — now measured, on the real send-`12cd279d7e` witness:

**Where the memory goes.** The bootloaded messagezk_scan run is 59,663
steps; the largest trace component is `blake_g` at 2^16 rows. Yet peak RSS
is 8.22 GB and program-independent, because the Cairo AIR's fixed
preprocessed lookup tables dominate: 84 columns at native 2^20
(range-check/xor tables, `include_all_preprocessed_columns: true`) are
LDE-extended at **blowup 3** to 2^23 — 2.8 GB of table LDEs alone, ~4 GB
of column data total, ~2× in overheads. The workload is irrelevant; the
constants (`CAIRO_PCS_CONFIG`: pow 27 / blowup 3 / 23 queries, sized for
StarkWare's original privacy-transaction workload with its pedersen
components — all disabled in our proofs) are everything.

**The fix, validated end-to-end** (`tools/phone-prover-blowup2.patch`):
inner blowup 3 → 2, queries 23 → 35 (security 27 + 70 = 97 bits vs 96):

| Config | prove peak RSS | inner proof | wrap | outer proof |
|---|---|---|---|---|
| baseline (blowup 3, 23 q) | 8.22 GB | 2.2 MB | 13.6–24.6 GB | 36,022 felts |
| **blowup 2, 35 q** | **4.62 GB** | 3.0 MB | 23.0 GB, 19 s | **35,906 felts** |
| blowup 1, 70 q | 2.76 GB | 5.3 MB | overflows circuit (qm31_ops → 2^22) | would grow |

The blowup-2 point is the sweet spot: the wrap circuit's `qm31_ops`
(1.97M rows) still fits 2^21, so the outer trace log size — and therefore
on-chain proof size and verify gas shape — is unchanged; only the `eq`
(2^18) and `blake_g_gate` (2^21) padding targets move one notch. Blowup 1
would halve phone RAM again but pushes `qm31_ops` to 2^22, growing the
on-chain proof — the wrong trade unless verify gas keeps falling.

Two prover flags measured as duds: `store_polynomials_coefficients:
false` saves ~2% RSS and is 70% slower; `include_all_preprocessed_columns:
false` saves nothing (the tables are used by enabled components) and
breaks the wrap's proof-shape conversion.

The decoupling holds as designed: inner params tune for phone RAM, outer
params for calldata/gas, and the relay absorbs the slack. Costs of
adopting blowup 2: new inner circuit root and multiverifier preprocessed
root → re-pin verifier consts + `INNER_ROOT`, redeploy registry/store —
all forced by the qm31 rebuild anyway. (Also observed: base-trace
generation is not byte-deterministic across runs — same witness, same
salt, different trace commitments; validity is unaffected but don't build
anything on proof-byte reproducibility.)

The remaining 4.6 GB floor is structural (2^20 tables at blowup 2 +
witness + interaction trace); the next big lever is not parameters but a
bootloader/AIR change (e.g. a poseidon-output bootloader dropping the
blake component family), which is soundness-critical circuit surgery.

## Wrap memory — measured (2026-07-29, same session)

RSS-profiled the wrap over the blowup-2 inner proof. Two humps: the
cairo-verifier circuit prove peaks ~20.8 GB, the multiverifier ~18 GB;
the original 25.2 GB peak was overlap — stage-1 state (`context`,
`novalue_context`, `preprocessed`) held alive through the multiverifier
build, plus the inner proof (with aux) cloned into BOTH multiverifier
inputs. Explicit drops + single clone (now in
`tools/phone-prover-blowup2.patch`): **25.2 → 20.8 GB, 18.6 → 13.9 s**,
byte-identical 35,906-felt output.

The per-stage floor decomposes as ~12.3 GB of committed LDEs (151
columns at 2^24 — the 2^21 circuit trace at outer blowup 3) + several GB
of context/witness materialization. Outer blowup 3→2 halves the LDEs
(peak 18.5 GB, wall 9.7 s) but grows the on-chain proof 35,906 → 49,114
felts (+37%, back over the calldata budget) — measured and rejected for
production; it is a dial for a RAM-constrained relay only.

Mem-mark attribution (instrumented run): all bridge-level phases —
prepare, value-context build, validity, padding, novalue build,
preprocess — complete by t≈0.5 s at ~7 GB. **The peak is entirely inside
stwo's `prove_circuit_assignment`** (~13.7 GB allocated and freed per
stage: LDE evaluations, commit, composition, FRI).

## Wrap under a phone budget: the spill allocator (SHIPPED 2026-07-29)

`tools/privacy-prove-cairo-bridge/src/spill_alloc.rs` — a global allocator
in the bridge that routes every allocation ≥ 4 MiB (LDE columns, Merkle
layers, value contexts) into unlinked file-backed `MAP_SHARED` mappings.
On Darwin those pages are "external" memory: excluded from
`phys_footprint`, the ledger iOS jetsam enforces, and evictable/
writeback-able under pressure. Opt-in via `ZKMSG_SPILL_DIR` (unset =
pure-RAM desktop behavior, unchanged). Zero stwo changes.

Measured, real messagezk witness, blowup-2 params:

| Leg | default footprint | spill footprint | wall |
|---|---|---|---|
| prove | 4.62 GB | **764 MB** | 2.3 s |
| wrap | 22.3 GB | **377–401 MB** | 17.8–18.1 s (vs 13.8) |

Outputs byte-identical in every configuration; the canonical bridge at
baseline params reproduces the landed on-chain send-`12cd279d7e` stream
(36,074 felts) byte-for-byte, so the refactor (drops/single-clone
hygiene, derived preprocessed sizes, allocator) is root-neutral and lives
in the canonical crate — `tools/phone-prover-blowup2.patch` is now
params-only.

**iOS-simulator validation (2026-07-29, same day):** the entire pinned
prover tree (stwo, stwo-circuits, stwo-cairo, cairo-vm, bridge)
cross-compiles for `aarch64-apple-ios-sim` on the pinned nightly with
**zero code changes** (2 m 03 s build). Spawned inside the iPhone 17 Pro
(iOS 26.4) simulator via `simctl spawn` with `ZKMSG_SPILL_DIR` in the
sim's tmp, baseline params:

| Leg (in-simulator) | wall | sampled phys_footprint peak | RSS (host page cache) |
|---|---|---|---|
| prove (real witness) | 4.0 s | 777 MB | 6.9 GB |
| wrap (campaign artifact) | 13.9 s | 86–94 MB | 14.3 GB |

The in-simulator wrap of the campaign `cairo_proof.json` reproduces the
**byte-identical 36,074-felt stream that landed on Sepolia-integration.**
(Sampled at 0.3 s — treat the host `/usr/bin/time -l` lifetime-max
377–401 MB as the rigorous footprint number.)

## ON REAL HARDWARE (2026-07-29): the whole pipeline runs on a 2020 iPhone

Bench harness: `tools/prover-bench-ios` (XcodeGen app, links the bridge as a
staticlib through the `zkmsg_prove` / `zkmsg_wrap` C FFI added in
`tools/privacy-prove-cairo-bridge/src/lib.rs`). Device: **iPhone 12 Pro,
A14, 5.6 GB RAM, iOS 27.0**, wirelessly paired, free personal team, signed
with Xcode 27 beta. Workload: public `poseidon_chain(100)` fixture.

| Leg | wall | peak phys_footprint | peak live spill |
|---|---|---|---|
| prove | **31.8 s** | **14 MB** | 5.8 GB |
| wrap (Mac-made input) | **495 s (8m15s)** | **295 MB** | **14.4 GB** |
| wrap (phone's own proof) | **547 s (9m07s)** | **165 MB** | **14.4 GB** |

**End-to-end phone-only: 9m39s**, witness → on-chain-ready felt stream, no
desktop artifact anywhere in the chain. Both wrap outputs are 36,022 felts
and **byte-identical to Mac wraps of the same inputs** (verified separately
for the bundled input and for the phone's own proof) — so device SIMD,
allocator and paging reproduce the reference bit-for-bit. Footprint — the
ledger jetsam enforces — stayed three to four orders of magnitude below the
data held. Independent check of the deterministic-wrap property: the two
legs wrapped different inner proofs and produced identical streams, since
this fixture's prove output is reproducible run-to-run.

**The binding constraint is virtual address space, not memory or storage.**
Default iOS caps a process near ~7 GB of mappings: measured
`mmap size=33554432 errno=12 (ENOMEM) live_mb=6848 maps=337` with 45 GB free
disk. prove (5.8 GB) fits under it; wrap (14.4 GB) does not. The fix is the
**`com.apple.developer.kernel.extended-virtual-addressing` entitlement**
(signs fine on a free personal team) — with it, wrap runs to completion.
Note `increased-memory-limit` is NOT needed: footprint never approaches the
jetsam ceiling.

Cost of the spill design on-device: prove 8× slower than the Mac (compute-
bound), wrap 33× slower (paging-bound, ~14 GB of writeback on a 5.6 GB
phone). Wrap wants ~20 GB transient free flash — preflight it.

Consequences: the relay is now **optional, not architectural** — a phone can
run the whole pipeline unaided, so the wrap relay becomes a latency
optimization users may decline. Remaining work if the 8-minute wrap is too
slow for the product: chunked constraint-eval and the recursion-tree split
(which also buys real aggregation) attack the paging directly; a newer phone
with more RAM will also close much of the 33× gap.

A second on-chain lever the unlock re-opened: **the outer channel hash.**
Phase1 improved only 16% under qm31 because it is blake2s/deserialize-
bound. The vendored crates ship `poseidon252_verifier`, and Poseidon is a
native Starknet builtin; the extra proving cost lands on the relay.
Poseidon-channel proofs also carry fewer felts (lane-2 measured 301k vs
376k — poseidon digests are full felts but fewer of them), helping the
calldata fit.

## Cost model (estimates until measured)

| Configuration | Txs/msg | ~STRK/msg | Burner funding |
|---|---|---|---|
| Today (emulated, measured ×4) | 3–4 | 47.7–49.9 | 79–80 |
| qm31 rebuild (measured, integration) | 3 | ~37 | ~40 |
| + single-tx multicall, calldata proof | **1** | ~31–35 | ~35 |
| + poseidon outer channel (unmeasured) | 1 | ~20–25 | ~25 |
| + 2-way aggregation (multiverifier already takes two inputs) | 1 per 2 msgs | **~10–13** | ~15 |

Reading stays free. The aggregation row needs a batching story (two
senders sharing a proof is a coordination problem; one sender batching
two messages is trivial and honest).

## What gets deleted

- `zkmsgd` entirely: the companion protocol, pairing (token file, QR-free
  carriers, `.zkmsgpair`), SSE streaming, the GUI's daemon control tab.
- iOS: `CompanionClient.swift`, `CompanionPairing.swift`, the pairing half
  of `ComposeView`, the `zkmsg://` scheme + UTI, the ATS cleartext
  exceptions (`NSAllowsArbitraryLoads` dies with the plaintext-HTTP LAN
  daemon).
- Contracts: `resumable.cairo`, checkpoint storage, phase-boundary
  plumbing. Staging shrinks to a fallback.
- sncast as a runtime dependency (desktop CLI/GUI keep it or move to raw
  RPC; the phone never had it).

The desktop CLI/GUI survive as a dev bench and as the reference
implementation, not as user-facing infrastructure. The witness/step
checkpoint model survives on the phone — `BurnerSetup`'s resumable state
machine is the template for the send pipeline, exactly as the daemon's
step vocabulary was.

## Gating realities

qm31 is open **only on sepolia-integration** (`audited_libfuncs_only:
false`); alpha and mainnet still reject the declare. Nothing above is
wasted meanwhile: integration is a full-fidelity bench (real gateway, real
fees, gas within 1% of alpha's estimates), and the early-warning signal
for the production unlock is a qm31 PR against `audited.json` in
starkware-libs/cairo. Design, build, and measure now; the alpha deploy is
a re-declare on unlock day.

## Measurement campaign (ordered; each re-prices the next)

1. **Single-tx multicall on integration**: qm31 registry with monolithic
   `verify_and_register` + `send_message` in one invoke, calldata-borne
   proof. Confirms the 1-tx row and the calldata envelope math.
2. ~~Inner-parameter sweep for prove RSS~~ **DONE 2026-07-29** (see the
   measured section above): blowup 2 / 35 queries → 4.62 GB prove peak,
   outer proof unchanged at 35,906 felts. Patch:
   `tools/phone-prover-blowup2.patch`.
3. **Outer-parameter + channel sweep**: packed-slot count and on-chain
   gas for the current blake config vs `poseidon252_verifier`, both under
   qm31. Target: proof ≤ 4,960 slots, phase1's hash bill collapsed.
4. **iOS prover spike**: build the `prove` leg for `aarch64-apple-ios`
   (or Mac Catalyst first), run the real witness on device hardware,
   measure wall/RSS against the tier-2 parameter point.
5. **Aggregation**: two real payloads through the multiverifier (today
   the same payload is passed twice), splitting the verify bill.
6. **Wrap relay**: extract `wrap` behind a stateless HTTP endpoint; add
   the phone-side native verify of the returned stream.
