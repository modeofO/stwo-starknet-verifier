# stwo-starknet-verifier

R&D: compiling StarkWare's [stwo-cairo](https://github.com/starkware-libs/stwo-cairo)
**Stwo (Circle-STARK) verifier** as a **Starknet smart contract**, so proofs of
custom Cairo programs — including browser-generated ones — can be verified
on-chain by contract code. Nobody has shipped this as of July 2026.

Full background, constraints, and plan: [`stwostarknetverifierhandoff.md`](./stwostarknetverifierhandoff.md).
Results so far: [`docs/spike1-results.md`](./docs/spike1-results.md).

## Status

- **Spike 1 (compile probe): done** — [`docs/spike1-results.md`](./docs/spike1-results.md).
  The full Cairo verifier compiles as a `starknet-contract` with gas on and
  passes the `audited.json` libfunc allowlist — the only deployment blocker
  is class size (~5.5× over the Sierra bytecode cap). The newer *circuit*
  verifier fits **all** size caps today.
- **Spike 2 (step-count measurement): done** — [`docs/spike2-results.md`](./docs/spike2-results.md).
  First public numbers: verifying even the smallest Stwo proof with the full
  Cairo verifier costs **10.0–15.9M steps** (at or 1.5× over the 1.1e9 L2
  gas/tx budget) plus 65k–223k felts of proof vs a 5k-felt calldata cap.
  The **circuit verifier** (recursion route) costs **3.79M steps ≈ 38% of
  one tx** with a 35.7k-felt proof — single-tx verification is viable there.
- **Spike 3 (recursion route end-to-end): done — it works.** —
  [`docs/spike3-results.md`](./docs/spike3-results.md). A scarb-built Cairo 1
  program was proven via StarkWare's privacy bootloader + recursion circuits
  ([proving-utils](https://github.com/starkware-libs/proving-utils) +
  [stwo-circuits](https://github.com/starkware-libs/stwo-circuits)) and the
  resulting 36k-felt proof was **accepted by the deployable circuit-verifier
  contract in 3.81M steps (~38% of one tx)**, with the statement binding the
  program hash and exact program output. One-command repro:

  ```sh
  scripts/setup-prover.sh          # once
  scripts/prove-and-verify.sh fixtures/target/dev/poseidon_chain.executable.json \
      fixtures/poseidon_chain_args_100.json
  ```
- **Lane 1 (FactRegistry): built and measured** —
  [`docs/lane1-results.md`](./docs/lane1-results.md),
  [`docs/architecture.md`](./docs/architecture.md).
  `contracts/stwo_fact_registry` verifies real multiverifier proofs
  end-to-end in snforge: **3 transactions per fact** (2 packed staging txs +
  one verify tx at ~8.9e8 gas, 81% of the per-tx cap), 49,740 Sierra felts,
  audited libfuncs. Consumers integrate via `is_valid(fact)`.
- **Lane 1 SHIPPED on Sepolia (2026-07-03)** — registry
  `0x0194f440…c6aa`, fact
  `0x640299e8…615c` verifies as `true` on-chain: the first on-chain-verified
  Stwo fact anywhere. Two-phase resumable verification (the 1.21e9
  per-invoke cap forced a FRI-boundary split), 3 classes, 3 txs per fact.
  See the Sepolia addenda in [`docs/lane1-results.md`](./docs/lane1-results.md).
- **Proof-only wrapping: done** —
  [`docs/proof-only-wrapping.md`](./docs/proof-only-wrapping.md). The bridge
  is split into `prove` (client side; witness never leaves) and `wrap`
  (middleman sees only a 2.2 MB proof + 4-felt preimage); output is
  byte-identical to the shipped fixture. Build-order gate (a) satisfied.
  WASM verdict: wasm32 is dead (7.9–13.6+ GB peaks); browser = custom WASM64
  build; native desktop client unaffected.
- **Lane 2 groundwork: measured and designed** —
  [`docs/lane2-design.md`](./docs/lane2-design.md). First real
  poseidon-config proof of our fixture (301,143 felts;
  `prove-poseidon` bridge subcommand) verified by the full vendored
  verifier at **34.2M steps**, with a per-phase cost map from
  `tools/lane2-probe` (claim mix 6.5M, logup 3.7M, fri_answers 12.7M, …).
  Design: ~15-tx checkpoint state machine, storage-free section feeding
  (self-authenticating / channel-bound / checkpoint classes).
- **Consumer fact binding: done** — `contracts/stwo_fact_binding`, the
  one-function consumer integration
  (`compute_fact(program_hash, outputs, inner_root)` + `is_valid`); its
  test reproduces the live Sepolia fact from application data (~0.8M gas).
- **Controller envelope: quantified** (from `controller-rs` ABI types) —
  direct session invokes don't touch the calldata cap (token rides in the
  signature); the paymaster `execute_from_outside_v3` path costs ~31–34
  calldata felts (cached auth), so the phase-1 head shrinks to ~4,960
  slots. See the client section in
  [`docs/architecture.md`](./docs/architecture.md).
- **Lane 2 skeleton: two-phase resumable FULL verifier passes on the real
  proof** — `contracts/stwo_full_verifier_phases`: the full Cairo verifier
  (poseidon config) split at the lookup-elements seam, checkpoint = 3
  felts, equivalent to the monolithic verifier in snforge; tamper and
  forged-checkpoint rejections proven. Plus the resumable
  `poseidon_hash_span` sponge (the chunking primitive for the claim-mix
  and fri_answers monsters) and packing v2.
- **Both lane-2 monsters solved** — chunked claim mixing
  (`claim_mix.cairo`: pipeline over two pausable absorbers reproduces the
  monolithic digest across 7 checkpointed chunks) and chunked
  `fri_answers` (`fri_chunks.cairo`: query-range chunks over sliced
  queried values, no fork needed — answers are per-query independent).
  Both proven equivalent over the real fixture proof.
- **Witness splitter shipped** — `split-witness` in the bridge
  synthesizes per-query-group Merkle decommitments from
  `ExtendedStarkProof.aux` (no re-proving; per-group witnesses cost only
  +2.5% calldata vs the union witness), self-checked against the proof's
  own witness and validated in snforge: vendored `MerkleVerifier::verify`
  accepts all 5 groups × 4 trees against the monolithic roots, tamper
  cases rejected. All 20 lane-2 tests green (incl. the constants probes).
- **The N-phase machine: built and proven equivalent (2026-07-03)** —
  `stwo_full_verifier_phases/src/machine.cairo`: the full production-shaped
  sequence (begin → claim chunks → lookup chunks → OODS+mix → FRI commit →
  fused Merkle/fri_answers group txs → FRI decommit + fact, **21 txs** on
  the fixture) runs as pure functions with serde checkpoints between every
  transaction and per-section binding digests, and produces exactly the
  monolithic verifier's output on the real proof (tamper cases rejected).
  Incremental claim pipeline included: chunked `lookup_sum`
  (`lookup_chunks.cairo`), `verify_claim` proven prefix-only, and the
  settled constants verdict (one-time packed store; measured in
  `test_constants_probe.cairo`). Class sizes: **4 of 5 machine classes fit
  the caps today** (25–36%); only the OODS class (composition-eval
  component zoo, 762k Sierra felts) needs splitting.
- **OODS split: built and proven equivalent (2026-07-03)** —
  `oods_chunks.cairo`: the component zoo now runs as `oods_begin` → group
  txs over a 40-family sequence (sub-air granularity) → `oods_finalize`,
  with the sum accumulator, stream counters and a preprocessed-usage
  bitmask riding the checkpoint; chunked == monolithic on the real proof
  including the transcript seam. Class sizes v2: **22 of 26 machine
  classes fit the caps today**; the last four are single generated
  component evals (blake_compress 92k, blake_round 94k,
  poseidon_aggregator 134k, cube_252 133k Sierra felts) — shrink via the
  qm31-opcode watch item or a build-time constraint-range slicer.
- **Class-size problem CLOSED (2026-07-04): all 36 deployable classes
  fit both declare caps** — `scripts/split_component_evals.py` forks
  the four oversized component evals at their generated
  `lookup_constraints` seam and, where a half still exceeded a cap,
  cuts again along size-driven boundaries (blake_round 4 parts,
  poseidon_aggregator 4 parts — the 869-line hades permutation is its
  own class — cube_252 3 parts with a logup-boundary cut). Seam values
  ride the checkpoint as a `carry` (228–796 felts); trace-mask columns
  are re-read per part (digest-bound), not carried — carrying costs
  ~90 Sierra felts per value. 49-family chunked == monolithic on the
  real proof, carry tamper rejected, 26/26 tests green. Also surfaced:
  the 4,089,446-byte class cap binds before the 81,920-felt cap
  (~66k felts); the mul group was regrouped for it. Largest class:
  63,647 felts / 3.94M bytes (96% of the byte cap). The qm31 opcode
  remains a cost (not deployability) watch item.
- **Router SHIPPED in snforge (2026-07-05)** —
  `StwoVerifierRouter` (6.1k felts): caller-keyed
  `(tag, poseidon(state))` checkpoint slot, library-calls into the 36
  pinned machine classes, packed-v2 section calldata, tag-typed
  write-once sequencing. The real fixture proof verified end-to-end
  through the deployed router in **52 transactions** (~24.3e9 L2 gas
  total, ~470M/tx average — under the 1.21e9 per-invoke cap), fact
  registered; proof-id reuse / wrong-tag / tampered-state all rejected.
  29/29 tests green.
- **Calldata emitter shipped (2026-07-05)** — `emit-calldata` in the
  bridge: per-tx packed-v2 router transport (head surgery, program
  chunks, sampled/fri, per-group rows + synthesized witnesses,
  manifest), self-checking against the proof's own cairo-serde stream
  and cross-validated byte-for-byte in snforge (30/30 tests green).
  Measured vs the ~5k-felt calldata cap: everything fits except the fri
  section (8,873 slots → needs lane-1-style write-once staging) and
  16-query group rows (7,983 → needs the settled constants store or
  ~4-query groups) — both already scoped in the design doc.
- **Devnet declare pre-flight done (2026-07-05): 35 of 37 classes
  declare** — including the router and every phase class. A third cap
  surfaced beyond the two Sierra caps: compiled CASM bytecode (81,920
  felts), with a wildly non-uniform CASM/Sierra ratio (0.68–2.9× by
  instruction mix). Two classes fail it: mul_opcode (172k CASM) and
  cube_252 half A (180k CASM), both dominated by the shared
  mul_252/karatsuba subroutines (252-bit mul under bounded_int
  emulation) — shared Sierra functions, so seam-fork cuts can't shrink
  them further. **These two now carry the qm31-opcode dependency**; all
  other machinery is declare-ready. See "Declare pre-flight" in
  [`docs/lane2-design.md`](./docs/lane2-design.md).
- **The qm31 gate located precisely (2026-07-05)** —
  [`tools/qm31-gate-probe`](./tools/qm31-gate-probe): a qm31 contract
  declares/deploys/EXECUTES on starknet-devnet 0.9.0 and fee-estimates
  on Sepolia RPC nodes, but the **Sepolia gateway (0.14.3) rejects the
  real declare** ("Contract failed to compile in starknet") — the
  enforcement point `audited.json` mirrors. Devnet and estimation are
  not deployability oracles. Post-opcode shape measured: qm31-build
  monolithic verifier = 3.0M Sierra / 405k CASM (still needs the
  machine split + router, but ~5× less total CASM, no mul_252 blowup,
  and the client reverts to the fast blake2s prover). The probe README
  is the 30-second re-test.
- **The qm31 pivot measured AND the machine ported (2026-07-05)** — the
  gate re-probe still rejects at the Sepolia gateway, but snforge 0.61
  EXECUTES qm31 libfuncs (proven in `tools/qm31-gate-probe`'s tests), so
  the pivot is fully locally testable. `prove-blake` shipped in the
  bridge (two traps found: the verifier's default build wants the PLAIN
  `blake2s` channel, not `blake2s_m31`, and pins the `canonical`
  WITH-pedersen trace): client proving drops **257 s → ~6 s** (14.1 GB
  peak); verification drops 34.2M → **26.6M steps** on the qm31 build
  (per-stage map in the design doc — the opcode annihilates OODS eval
  11× but fri_answers/prologue are bookkeeping-bound). The machine now
  builds BOTH channels from one source (`Hash`-typed checkpoints,
  `claim_mix_blake` pausable blake2s absorbers, `split-witness --blake`)
  and the full blake machine sequence == monolithic on the real blake
  proof in snforge; poseidon suite still 30/30.
- **Blake OODS split + sizing: ALL 36 deployable classes fit
  (2026-07-05)** — the canonical trace forced a 2-limb preprocessed
  bitmask (161 columns) and the blake builtins family (8 components,
  807k Sierra) is now 8 per-component families with loud `is_none`
  stubs for the four builtins outside the program envelope (56 families
  total, `FAMILY_SHIFT`). Measured on the qm31 build: the two
  poseidon-lane killers collapse (mul 172k → 53.7k CASM, cube_252-A
  180k → 58.9k CASM) and every deployable class clears all three caps
  (`scripts/size_classes.sh --blake`). 56-family chunked == monolithic
  on the real blake proof. **The blake machinery is
  declare-shape-complete — only the gateway's qm31 gate blocks the
  public network.**
- **Blake transport measured** — `emit-calldata --blake` (emitter
  genericized over the Merkle hasher, self-checks pass): head 69 /
  chunks ≤781 / sampled 2,617 slots as before; the fri section packs
  7:1 (56,311 u32-word felts) but still lands at **8,045 slots > the
  ~4,996 cap — fri staging stays**; group rows 8,111 → the constants
  store / smaller groups stays. Both transport work items survive the
  pivot unchanged.
- **Transport CLOSED + the registry route (2026-07-05)** — the two
  over-cap calldata items are gone: the router gained a write-once
  **staged-section store** (lane-1 `stage_proof` precedent; caller-keyed
  `(proof_id, section, slot)` packed storage). The fri section (8,045
  slots) stages in 3 txs and is read back by `fri_commit` AND `finalize`,
  bound by a new `d_fri` checkpoint digest (+ the lane-1 query-equality
  re-derivation); the sampled section (2,617 slots) stages in 1 tx and
  serves 41 transactions (OODS begin/30 groups/finalize + all fused
  group txs) — superseding the derived-constants store: raw sampled
  serves everyone with no derivation tx. Fused groups drop to **8
  queries/tx** (worst group tx measured 4,872 felts < the ~4,996 cap;
  getting there also required packing the checkpoint's accumulated
  fri-answer M31s 7-per-felt — unpacked they overflowed by 11 felts,
  caught by the per-tx assert, not by estimation). `finalize` now
  registers into **`StwoSharedFactRegistry`** — the
  two-lane convergence contract with an owner-governed, freezable route
  list (fact definition unchanged). The blake drive
  (`tests/test_router_blake.cairo`) runs the real proof through the
  deployed router in **60 transactions with every tx's calldata counted
  and asserted under the cap** — the "everything fits" claim, executed.
  Poseidon drive: 56 txs. Both suites green.
- **OODS group classes merged 30 → 15 — the measured floor (2026-07-05)**
  — the last tx-count lever: each group class carries a ~11k-Sierra/
  ~30k-CASM fixed prologue base (head deser + sampled deser + element
  redraw), so merging neighbours under the caps cut the class count to
  **21 deployable classes** and the drives to **blake 45 txs / ~30.3e9
  gas** (was 60 / 35.0e9) and **poseidon 41 txs / ~29.5e9** (was 56 /
  34.2e9). All 15 merged classes fit all three caps on the qm31 build
  (worst: 95.2% of the byte cap); every remaining adjacent pair-merge
  exceeds a cap — the earlier "~10–12" guess missed that the byte cap
  (~66k Sierra felts), not CASM, binds. Family functions, machine and
  router unchanged; the qm31 gate re-probe the same day: still rejected.
- **Devnet drive: the gas oracle falsifies the staged-fri design
  (2026-07-05)** — `scripts/devnet_drive.py` declared all 23 blake
  classes, froze the registry route list and drove the real proof with
  per-tx receipts. Three corrections the estimates missed: the state-diff
  cap counts FELTS (2/write → `STAGE_CHUNK` 3,900 → 1,900; staging txs
  4 → 7); storage writes bill ~495k gas each (a staging tx = 946M, 78%
  of the invoke cap); loading a packed section costs ~120k gas/slot
  (processing — the read syscall itself is ~3k), so `fri_commit`'s
  8,045-slot load needs 2.22e9 sierra gas — **over the ~1e9 per-invoke
  execute budget: the staged-fri store is dead on 0.14 pricing**. Everything else measured production-ready (OODS group txs
  328–381M each). Fix designed (fri transport v3): the fri bulk is
  self-authenticating against the layer commitments and `FriProof`
  serializes per layer — commitment slice via calldata in fri_commit,
  layer-batched calldata decommit chunks, fri staging deleted. See the
  devnet section in [`docs/lane2-design.md`](./docs/lane2-design.md).
- **FRI transport v3 + the sovereign lane priced end-to-end on devnet
  (2026-07-05)** — the fri section is never stored: `fri_transport.cairo`
  forks the vendored (private) FRI layer verifiers; the 24-slot
  `FriHead` commitment slice rides every FRI-phase tx as calldata
  (d_fri-bound, Fiat-Shamir-authenticated) and the decommit walk chunks
  at layer boundaries with the folded (queries, evals) in the checkpoint.
  Devnet round 2 ran the FULL drive: **45 transactions, 21.43e9 L2 gas,
  fact registered under the frozen route list**
  ([per-tx record](./docs/devnet-drive-v3-2026-07-05.json)) — fri_commit
  33M (was unincludable), layer chunks 599M/752M, finalize 33.8M. New
  binding constraint: the fused 8-query group txs at **95.7% of the
  1.21e9 invoke cap** (7-query groups or the constants store are the
  levers before the real messagezk-sized circuit). Both suites green
  (blake 5/5, poseidon 30/30); 21 deployable classes, all under the caps.
- **The fused-group margin closed (2026-07-05)** — the constants store
  is dead by arithmetic (the ~2.9k-slot derived section costs ~350M/tx
  to load at the measured ~120k/slot processing, vs the ≲97M recompute
  it would remove — processing dominance kills derived-data stores the
  same way it killed staged fri), so the lane took **7-query groups**:
  devnet round 3 ran **46 txs, 21.85e9 L2 gas, fact registered**, with
  the 10 fused group txs at 1,059–1,066M = **88.1% of the invoke cap at
  worst** (target ≤~90%; the 91M/query marginal model predicted 1,066M).
  Per-tx record: [`docs/devnet-drive-g7-2026-07-05.json`](./docs/devnet-drive-g7-2026-07-05.json).
  Blake 5/5, poseidon 30/30; the poseidon suite deliberately keeps 16/5
  groups (group-size flexibility is tested). qm31 gate re-probed a third
  time the same day: still rejected.
- **zkmsg SHIPPED (2026-07-05): the first natively-proven private message
  on Starknet** — [`docs/zkmsg-deployment.md`](./docs/zkmsg-deployment.md).
  The FULL messagezk circuit (2×depth-20 Merkle membership + ephemeral
  ECDH + Poseidon commitment, `ec_op` — provable on lane 1's recursion
  route, never on lane 2's contract config) ported to a bootloader
  executable (`fixtures/messagezk_scan`: the public tuple moves from
  asserted args to OUTPUTS), proven+wrapped natively by a Rust CLI
  (`tools/zkmsg`: checkpointed resumable sends, two pre-spend gates,
  trial-ECDH inbox), verified through the LIVE lane-1 registry and
  published to an immutable `MessageStoreV3`
  (`0x02d66a02…91b7`, pinned route, replay guard, no `set_verifier`).
  Fact `0x2dc0a370…4145f`; send cost 47.7 STRK / 1.68e9 gas — flat in
  circuit size, within 1.5% of the fixture's lane-1 numbers. Recipient
  decrypts by trial-ECDH; sender's own inbox correctly empty. Now also a
  native egui GUI (2026-07-07): `tools/zkmsg` split into a core lib +
  CLI (byte-identical stdout) + `zkmsg-gui` — compose/confirm/live step
  checklist, trial-decrypt inbox, resume banner; first GUI-driven send
  fact `0x5b824d25…f6e25`, 47.2 STRK. Profiles + identity wizard
  (2026-07-08): in-app switching over a root-`.zkmsg` layout (one-time
  rename-only migration) and one-confirm funded-identity creation
  (create/fund/deploy/init/register, checkpointed + resumable) — first
  wizard-born identity `carol` sent fact `0x18dbb303…305a`, surviving
  a real mid-send balance stall via Resume. Suites: store 12/12,
  zkmsg-core 39/39 + gui 5/5, blake 5/5, poseidon 30/30.
- **Next:** the qm31 gate-probe re-test on Starknet version bumps (the
  only blocker for the public network), the messagezk-circuit sizing
  pass (re-run `prove-blake` + the devnet drive on the real circuit;
  drop to 6-query groups if the margin thins), Sepolia campaign under
  the registry's governed route list once the gate opens; confirm the
  Controller envelope with a live Sepolia session transaction.

## Layout

- `vendor/stwo_cairo_verifier/` — vendored verifier crates, pinned upstream
  commit, unmodified (Apache-2.0; see `VENDORED.md` there).
- `contracts/stwo_verifier_contract/` — thin contract wrapper around the full
  Cairo verifier (`poseidon252_verifier` config).
- `contracts/stwo_circuit_verifier_contract/` — thin contract wrapper around
  the circuit verifier (blake2s config).

## Build

Requires Scarb 2.18.0 (see `.tool-versions`).

```sh
scarb build
```

## Honest framing

- The incumbent is SNIP-36: one tx, ~cents, seconds — but it requires a local
  native proving service and only proves virtual-SNOS executions. This
  project's win condition is UX + generality (browser proofs of arbitrary
  Cairo executables), accepting higher on-chain cost.
- Stwo proofs are not formally ZK; this route posts the full proof into
  public calldata permanently. Do not put long-lived secrets in witnesses.
- Any `set_verifier`-style integration in consumer contracts must be
  owner-gated and eventually immutable — a swappable verifier is a rug vector.

## License

Apache-2.0. Vendored code is Copyright StarkWare Industries Ltd., also
Apache-2.0.
