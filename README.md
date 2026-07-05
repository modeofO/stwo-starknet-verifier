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
- **Next:** fri-section staging + the one-time constants store (the two
  calldata-cap items), the qm31 gate-probe re-test on Starknet version
  bumps (pivot plan documented), Sepolia campaign under the registry's
  governed route list; confirm the Controller envelope with a live
  Sepolia session transaction.

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
