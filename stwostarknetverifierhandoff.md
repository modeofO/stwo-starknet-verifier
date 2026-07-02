# Project Handoff: `stwo-starknet-verifier`

**Goal:** Determine whether StarkWare's stwo-cairo **verifier** can be compiled
and deployed as a **Starknet smart contract**, so that Stwo (S-two /
Circle-STARK) proofs of custom Cairo programs can be verified on-chain in
contract code — something nobody in the ecosystem has built as of July 2026.

This document is a self-contained briefing for a fresh session in a new,
standalone repository. It assumes no access to the originating project.

---

## 1. Why this project exists

The originating project is **messagezk** (github.com/modeofO/messagezk), a
private messaging app on Starknet Sepolia. Its clients generate Stwo proofs
in the browser (via the `stwo-cairo` npm WASM prover) of a custom Cairo
executable circuit that proves: sender membership in a Poseidon Merkle tree
of registered users, recipient membership, correct ephemeral-key derivation,
ECDH, and correct formation of a Poseidon commitment. Public inputs:
`(commitment, ephemeral_pubkey, merkle_root)`.

Problem: **there is no way to verify that proof on-chain.** The contract
currently accepts any junk in the proof parameter. messagezk is pursuing
SNIP-36 in-protocol verification as its shipping path (that restructures the
app around a local proving service). This project is the parallel R&D track:
if a Stwo verifier can run *as a contract*, the browser-generated proof
becomes directly usable on-chain — no local prover companion, no
restructuring — and the result is general-purpose ecosystem infrastructure
useful far beyond messagezk (plausibly grant-fundable: Starknet Foundation,
StarkWare, OnlyDust — "the missing on-chain Stwo verifier").

Constraint from the owner: **Stwo only.** No Garaga/Noir/Groth16 migration.

## 2. State of the world (verified July 2026)

All of the following was verified against primary sources in early July 2026.

- **stwo-cairo** (https://github.com/starkware-libs/stwo-cairo) ships a
  complete Stwo verifier written in Cairo: workspace
  `stwo_cairo_verifier/crates/` with `cairo_verifier` (entry point),
  `cairo_air`, `verifier_core` (FRI/PCS/channel), `constraint_framework`,
  `bounded_int`, `verifier_utils`. It is production software (SHARP recursion
  secures Starknet mainnet with it since Jan 2026). **But every crate is an
  executable/lib target — there is no `starknet-contract` target, no
  deployment story, and no community wrapper exists** (searched GitHub
  thoroughly; the only artifact is a 2024 wish-list issue,
  keep-starknet-strange/backlog#55).
- **Feature flags** (verified in `verifier_core/Scarb.toml` and workspace):
  `poseidon252_verifier`, `qm31_opcode`, `blake_outputs_packing`,
  `poseidon_outputs_packing`. Two facts matter enormously:
  1. **`qm31_opcode` is optional and default-off** → a software-emulation
     fallback for M31/CM31/QM31 tower arithmetic exists (the `bounded_int`
     crate, felt252 arithmetic). Compilation without the opcode is an
     intended configuration.
  2. **`poseidon252_verifier`** swaps the Blake2s channel/hash for
     Poseidon252 — and Poseidon **is** a native Starknet contract builtin.
     README describes this configuration as suited for on-chain settlement.
- **QM31 opcodes are banned in Starknet contracts**: `corelib/src/qm31.cairo`
  says "Only available for local proofs"; the qm31 libfuncs are in
  `allowed_libfuncs_lists/all.json` but **absent from `audited.json`**, the
  allowlist enforced for declared contract classes
  (https://github.com/starkware-libs/cairo, `cairo-lang-starknet-classes`).
  So the fast path is unavailable; only the emulated path can possibly work.
- **Starknet per-tx limits (v0.14.2+)** (https://docs.starknet.io/resources/chain-info/):
  calldata **5,000 felts**; **1.1e9 L2 gas** (~11M Cairo steps, L2gas ≈
  steps×100); Sierra class size cap **4,089,446 bytes**; `__validate__`
  capped at 1e8 L2 gas.
- **Proof sizes**: Stwo proofs of small programs run roughly **tens of KB to
  ~500 KB** → far beyond calldata in one tx; must be staged into storage
  across multiple txs. FRI parameters (blowup, PoW, n_queries) trade prover
  time for proof size but won't get below tens of KB.
- **Cost anchors** (no public step benchmark of the Cairo verifier exists —
  producing one is this project's first deliverable):
  - SNIP-36 reserves **10M L2 gas** for the *native Rust* verification of a
    virtual-SNOS proof (https://community.starknet.io/t/snip-36-in-protocol-proof-verification/116123).
  - StarkWare's recursion blog (Mar 2026): proving the *Cairo verifier's
    execution* takes ~1 minute on dedicated hardware vs 3 s for their newer
    circuit verifier — i.e. the Cairo verifier is a heavyweight program.
  - Without the qm31 opcode every field op costs multiple felt252 ops — the
    opcode exists because emulation is slow. Educated guess: tens of
    millions of steps for a real proof → likely exceeds the ~11M step/tx
    budget → multi-tx verification needed. **This guess is the thing to
    replace with a measurement.**
- **Prior art / competitive landscape:**
  - **Integrity** (https://github.com/HerodotusDev/integrity): the on-chain
    STARK FactRegistry on Starknet — **Stone proofs only**, dormant since
    Sep 2025, zero Stwo work. Its architecture is the blueprint for
    multi-tx verification: proofs split across "step transactions", FRI
    witness chunks fed in separate txs, final fact registered in a registry
    contract that consumer contracts query.
  - Herodotus's Stwo strategy is Groth16-wrapping for **EVM**
    (https://github.com/HerodotusDev/stwo-gnark-verifier), not Starknet.
    Their Atlantic API: "S-two is currently supported only for L1
    verification" (https://docs.herodotus.cloud/atlantic-api/stwo).
  - **SNIP-36** (Starknet v0.14.2, mainnet Apr 2026): consensus-level Stwo
    verification, but ONLY of virtual-SNOS transaction executions (program
    hash allowlist of exactly 2 entries — custom programs rejected). It is
    the incumbent alternative this project competes with on UX (browser
    proof, no local prover) and loses to on cost (see §5).
- **Toolchain**: Cairo/Scarb 2.19.x is current (June 2026). stwo-cairo
  proving flow: `scarb build` executable → `scarb execute` → `scarb prove` /
  `stwo-cairo` npm (WASM) in browsers. Verifier runs via
  `scarb --profile proving execute --package stwo_cairo_verifier` with a
  special `all_cairo_stwo` layout (a layout contracts don't get — another
  thing to watch when retargeting).

## 3. The three walls (in order of expected pain)

1. **Retargeting executable → contract.**
   - Crates build with `enable-gas = false`; contracts require gas
     accounting. Recompile with gas on (loops get `withdraw_gas` — usually
     mechanical, occasionally needs code changes).
   - Must use only `audited.json` libfuncs (no qm31; check what
     `bounded_int` lowers to — plain felt252 arithmetic should be fine).
   - Sierra class size cap ~4 MB — the verifier is big; may need splitting
     into a couple of classes (library calls) if exceeded.
2. **Step cost.** Unknown; decides single-tx vs multi-tx architecture. Under
   ~10M steps → single verification tx is thinkable. Far above → build an
   Integrity-style resumable verification state machine (verify in chunks
   across N txs, persist channel/FRI state in storage between txs).
3. **Calldata.** 5,000 felts/tx → a proof-staging contract: upload proof
   chunks across ~5–30 txs into storage, then run verification over stored
   data. Mechanical but adds storage gas cost and latency.

## 4. Spike plan (do these in order; each gate is cheap)

**Spike 1 — compile probe (days).**
1. New Scarb workspace. Vendor (git submodule or copy, Apache-2.0 —
   preserve headers) `stwo_cairo_verifier` crates from
   starkware-libs/stwo-cairo at a pinned commit.
2. Create a thin `#[starknet::contract]` wrapper exposing
   `verify_proof(proof: <serialized form>) -> PublicOutputs` calling into
   `cairo_verifier`'s verify entry with features
   `poseidon252_verifier` ON, `qm31_opcode` OFF, gas ON.
3. `scarb build` with `[[target.starknet-contract]]`. Deliverable: it
   compiles (note Sierra class size), or an exact blocker list (which
   libfunc/feature/layout dependency breaks).

**Spike 2 — the number (days).**
1. Produce a real fixture: a small Cairo executable (e.g. the messagezk
   circuit: two depth-20 Poseidon Merkle proofs + 3 Stark-curve ec-muls +
   Poseidon commitment; or anything comparable), `scarb prove` it with the
   **Poseidon channel** configuration matching the verifier features.
2. Run the vendored verifier over that proof as an *executable* with
   `scarb execute --print-resource-usage` (and cairo-profiler if useful).
3. Deliverables: total Cairo steps, builtin counts, proof size in felts.
   Publish these numbers regardless of outcome — no public benchmark exists
   and the ecosystem wants it.

**Gate after Spike 2:**
- steps ≲ 10M → **single-tx verification viable**: remaining work is the
  proof-staging contract + gas measurement on devnet. High-value, weeks.
- steps ≫ 10M → the project becomes "Integrity for Stwo" (resumable
  verifier state machine). Genuine public good, likely grant-worthy,
  multi-month. Decide deliberately before proceeding.
- doesn't compile for contract target at all → document blockers, file
  upstream issues (starkware-libs/stwo-cairo), park the project, and watch
  for QM31 libfuncs entering `audited.json` (StarkWare built the opcode for
  verifier efficiency; if it's ever contract-enabled, wall 2 mostly falls).

**If green — full build sketch (FactRegistry model, mirrors Integrity):**
- `ProofStage` contract: chunked upload keyed by proof hash.
- `StwoVerifier` contract/class: verify staged proof (one tx or resumable).
- `FactRegistry`: on success, register
  `fact = poseidon(program_hash, poseidon(public_outputs))`.
- Consumer contracts (e.g. messagezk's MessageStore) check
  `is_valid(fact)` — one storage read, composable for everyone.

## 5. Honest framing (keep in the README of the new repo)

- The incumbent is SNIP-36: one tx, ~cents, seconds — but requires a local
  native proving service per user and only proves virtual-SNOS executions.
  This project's win condition is UX + generality (browser-generated proofs
  of arbitrary Cairo executables, verified by contracts), accepting a much
  higher on-chain cost (multiple txs, plausibly dollars per proof). It is
  infrastructure for *occasional* high-value proofs first; per-chat-message
  use only becomes plausible if costs land far below expectations.
- Witness privacy caveat: Stwo proofs are not formally ZK, and this route
  posts the full proof into public calldata permanently. Applications must
  not put long-lived secrets in the witness (messagezk plans a dedicated
  auth key in its Merkle leaves for exactly this reason).
- `set_verifier`-style integration in consumers must be owner-gated and
  eventually immutable — a swappable verifier is a rug vector.

## 6. Key sources

- stwo-cairo (verifier crates, features, proving flow):
  https://github.com/starkware-libs/stwo-cairo
- Cairo corelib qm31 gating + audited libfunc allowlist:
  https://github.com/starkware-libs/cairo
  (`corelib/src/qm31.cairo`, `crates/cairo-lang-starknet-classes/src/allowed_libfuncs_lists/`)
- Starknet limits: https://docs.starknet.io/resources/chain-info/
- SNIP-36 (the incumbent):
  https://community.starknet.io/t/snip-36-in-protocol-proof-verification/116123
- Integrity (the architectural blueprint): https://github.com/HerodotusDev/integrity
- Herodotus Stwo status: https://github.com/HerodotusDev/stwo-gnark-verifier,
  https://docs.herodotus.cloud/atlantic-api/stwo
- Recursion cost anchor:
  https://starkware.co/blog/minutes-to-seconds-efficiency-gains-with-recursive-circuit-proving/
- Ecosystem index: https://github.com/keep-starknet-strange/awesome-stwo
- Browser prover used by messagezk: `stwo-cairo` on npm;
  demo: https://github.com/Okm165/stwo-web-stark

## 7. Relationship to messagezk (for coordination, not dependency)

- messagezk proceeds independently on the SNIP-36 enforcement track
  (see its `docs/superpowers/specs/2026-07-02-snip36-proof-enforcement-design.md`
  and the 2026-07-01 assessment in the same repo, branch
  `claude/stwo-proof-validation-wqaitr`).
- If this project succeeds, messagezk's integration is:
  client uploads proof chunks + verify tx (or single tx), then
  `send_message` checks the FactRegistry for
  `fact(program_hash_of_circuit, [commitment, ephemeral_pubkey, merkle_root])`
  — replacing the SNIP-36 fact-matching path with a registry lookup.
- Suggested repo name: `stwo-starknet-verifier` (ecosystem-facing, not
  messagezk-branded). License: Apache-2.0 (matches vendored code).
