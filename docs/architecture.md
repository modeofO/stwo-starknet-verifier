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

A **fact** binds the application program's hash and its public outputs
(for messagezk: `(commitment, ephemeral_pubkey, merkle_root)`). Lane 1
registers `poseidon(output_hash words)` where `output_hash` reaches the
program via a blake2s hash chain through the recursion circuits
(`stwo_fact_binding` recomputes it from application data); lane 2
registers `poseidon(program_hash, output_hash)` from the vendored
poseidon section hashes directly. Both lanes prove the *same statement*.
The set of verifier routes that may write facts must be owner-gated and
eventually frozen — a swappable verifier is a rug vector. This is now a
contract: `StwoSharedFactRegistry`
(`contracts/stwo_full_verifier_phases/src/fact_registry.cairo`) with an
owner-governed route list and a one-way `freeze_routes()`; consumers
should check `routes_frozen()` before trusting a deployment.

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

## Lane 2 — sovereign route (built in snforge; gateway-gated on qm31)

The client and the chain, nothing else:

```
client: prove app program (~6 s blake2s channel / 257 s poseidon)
   │ 301–376k-felt proof, packed ~7:1
   ▼
StwoVerifierRouter.stage × 4            (sampled + fri sections, write-once)
56 machine transactions                 (26.6–34.2M steps; 36 stateless library
   │                                     classes driven by the router's tagged
   │                                     (caller, proof_id) checkpoint slot)
   ▼
StwoSharedFactRegistry                  (governed, freezable route list;
                                         fact = poseidon(program_hash, output_hash))
```

Slow and gas-expensive by choice — its value is that **no third party exists
in the flow, not even a censorship-only one** (metadata privacy). The
engineering walls from Spikes 1–2 are all closed (docs/lane2-design.md):
class splitting (36 deployable classes, all under the three declare caps on
the qm31 build), the resumable machine (proven == monolithic on real
proofs, both channels), and transport (every one of the 60 transactions'
calldata asserted under the ~4,996-felt cap in `test_router_blake`).

What remains is not engineering: the Sepolia **gateway rejects qm31
declares** (`tools/qm31-gate-probe` is the 30-second re-test). The
poseidon build declares today but its mul_opcode/cube_252-A classes
exceed the CASM cap; the qm31/blake build fits everything and waits on
the gate.

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
- Integration caveat, now quantified from `controller-rs` ABI types
  (2026-07-03; live-tx confirmation still pending):
  - **Direct session invoke** (the app's session key signs the tx from the
    Controller account): the `SessionToken` rides in the tx *signature*
    field, not calldata — the 4,991-slot phase-1 head is unaffected.
  - **Paymaster path** (`execute_from_outside_v3`): the token becomes
    calldata. Envelope = 4 (outer `__execute__`) + 6 (`OutsideExecutionV3`
    header: caller, 2-felt nonce, after, before, calls len) + 3 (inner call
    header) + 1 + (17 + merkle_depth) (signature span with cached
    authorization: Session 5, cache flag 1, empty auth 1, two Starknet
    `SignerSignature`s 4+4, proofs 2+d) ≈ **31–34 felts** — the head
    shrinks to ~4,960 slots and the storage tail grows by ~30 slots. The
    *first* session use carries the WebAuthn authorization in
    `session_authorization` (~hundreds of felts) — do the session's first
    use on a cheap call, not on `verify_phase1`.
- Mobile is explicitly deferred (egui is weak there; desktop/laptop is the
  target).

**Build order gate:** no app scaffolding until at least one of these lands —
(a) proof-only wrapping (client hands the middleman a *proof*, not a
program+witness), or (b) the wrap chain compiling to wasm32 (memory
feasibility probe first). **Status 2026-07-03: (a) landed**
([`proof-only-wrapping.md`](./proof-only-wrapping.md)) — the bridge's
`prove`/`wrap` split gives clients a proof-only relayer boundary today, with
the bootloader running client-side. (b) is dead as wasm32 (7.9–13.6+ GB
peaks vs the 4 GB ceiling); the browser story is a custom WASM64 build of
the pinned privacy stack. App scaffolding is therefore unblocked, but the
golden goose remains **lane 2**: the sovereign resumable full-Cairo
verifier, for which the phase-checkpoint machinery in
`stwo_verifier_phases` is the seed — it stays ahead of the client app in
priority.
