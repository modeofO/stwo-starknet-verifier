# Architecture: two lanes into one FactRegistry

The project's goal state, decided after Spikes 1–3 (see the spike results
docs for the measurements behind every claim here).

## The principle

Applications never talk to a verifier directly. They check facts:

```
MessageStore (or any consumer)
      │  is_valid(fact)?
      ▼
StwoFactRegistry  ◄── lane 1: recursion route (shipped first)
                  ◄── lane 2: sovereign route (the desired end state)
```

A **fact** is `poseidon(output_hash words)` where `output_hash` binds — via a
blake2s hash chain — the application program's hash and its public outputs
(for messagezk: `(commitment, ephemeral_pubkey, merkle_root)`). Both lanes
prove the *same statement*, so consumers are lane-agnostic. The set of
verifier routes that may write facts must be owner-gated and eventually
frozen — a swappable verifier is a rug vector.

## Lane 1 — recursion route (built; this repo)

```
browser: prove app program (Stwo WASM prover)
   │ proof (public data — witness never leaves the client)
   ▼
wrap: bootloader run + cairo-verifier circuit + multiverifier circuit
   │ 36k-felt proof                     [tools/privacy-prove-cairo-bridge]
   ▼
StwoFactRegistry.stage_proof × ~9       (5,000-felt calldata cap)
StwoFactRegistry.verify_and_register    (~3.8M steps ≈ 38% of one tx)
```

- Contract: `contracts/stwo_fact_registry` — 49,740 Sierra felts, fits all
  deployment limits, audited libfuncs only. Measured end-to-end costs in
  [`lane1-results.md`](./lane1-results.md): **3 transactions per fact**
  (2 packed staging txs + one ~8.9e8-gas verify tx, 81% of the per-tx cap).
- The wrap step currently runs natively (2–3 min on a laptop). Who runs it:
  - a permissionless relayer (can't forge, can't read secrets; sees
    submission metadata — the trust cost),
  - or, pending the WASM feasibility probe, **the client's browser** —
    which would make lane 1 fully serverless. Risk: wasm32's 4 GB memory
    cap vs the prover's peak usage.
- Cost per fact: ≈1.23e9 L2 gas across 3 txs. The multiverifier aggregates
  two payloads per proof; the upstream `recursive_tree` tooling suggests
  deeper batching later.

## Lane 2 — sovereign route (the end state; not yet built)

The client and the chain, nothing else:

```
browser: prove app program (poseidon channel config)
   │ 65k+ felt proof
   ▼
stage_proof × 13–45                     (user's own wallet)
resumable full Cairo verifier           (10–16M steps split across N txs,
   │                                     channel/FRI state checkpointed in storage)
   ▼
same FactRegistry, same fact format
```

Slow and gas-expensive by choice — its value is that **no third party exists
in the flow, not even a censorship-only one** (metadata privacy). Known
engineering walls, all measured in Spikes 1–2:

- the full verifier is ~450k Sierra felts → split across ~6+ classes wired
  by library calls;
- verification is 10–16M steps → resumable state machine (Integrity-style);
- the contract-legal (poseidon) configuration has no `ec_op`/`pedersen`
  builtins → messagezk's EC math must be pure field arithmetic;
- browser proofs must be bootloader-shaped (all-11-builtin public segments).

Watch item: if the qm31 opcode ever enters `audited.json`, most of the size
and step cost collapses and lane 2 gets dramatically cheaper.

## Build order rationale

Lane 1 first because it ships a working end-to-end product soonest and every
piece of it — registry, staging, fact format, consumer integration — is
reused verbatim by lane 2. The sovereign lane is the destination; lane 1 is
the road that happens to pass through it.

## Client architecture (decided direction, not yet built)

Desktop-first native app (Rust + egui), deferred until the research below
progresses. Rationale and design:

- The entire proving stack (stwo, stwo-cairo, stwo-circuits, proving-utils,
  our bridge) is Rust — an egui app links it in-process: prove → wrap →
  sign → submit in one binary, no servers, no WASM ceiling, full SIMD.
  `tools/privacy-prove-cairo-bridge` is effectively its backend already.
- **Key management via Cartridge Controller sessions** (`account_sdk` from
  cartridge-gg/controller-rs — native Rust): the user's root account is a
  Controller smart wallet authenticated by passkey/social (no seed phrases,
  nothing to back up). The app holds only an ephemeral session key,
  approved once in the system browser against explicit policies (registry
  entrypoints, messaging calls, capped payments). Compromise of the app
  leaks only a scoped, expiring session — never the root identity.
- Cartridge's paymaster can sponsor fees (users need not hold STRK);
  at ~1.7e9 gas per fact the sponsorship economics are an app decision.
- Integration caveat to verify: `verify_phase1` uses 4,999/5,000 calldata
  felts with a plain account envelope; session `execute_from_outside`
  wrapping is larger, so the calldata head must shrink by a few slots —
  measure with a real Controller transaction before hardcoding.
- Mobile is explicitly deferred (egui is weak there; desktop/laptop is the
  target).

**Build order gate:** no app scaffolding until at least one of these lands —
(a) proof-only wrapping (client hands the middleman a *proof*, not a
program+witness: embed the app program in the cairo-verifier circuit config
and match the browser prover's channel/parameters), or (b) the wrap chain
compiling to wasm32 (memory feasibility probe first). And the golden goose
remains **lane 2**: the sovereign resumable full-Cairo verifier, for which
the phase-checkpoint machinery in `stwo_verifier_phases` is the seed.
