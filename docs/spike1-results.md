# Spike 1 results — compile probe (2026-07-02)

**Question:** does the stwo-cairo verifier compile as a `starknet-contract`
target with gas accounting on and only `audited.json` libfuncs?

**Answer: yes — it compiles cleanly and passes the audited-libfuncs check.
The only blocker to deployment is class size** (~5.5× over the Sierra
bytecode cap for the full Cairo verifier). A second, unplanned finding: the
new circuit verifier (`circuit_air`) **fits all deployment limits today**,
but only verifies one hardcoded recursion circuit.

## Environment

- stwo-cairo pinned commit: `92bfd1d3e203dc7f7af3e39f46e9e06abc3be844` (2026-06-30)
- Scarb 2.18.0 (`e6144df0f`, Cairo 2.18.0, Sierra 1.8.0), aarch64-apple-darwin —
  matches upstream `.tool-versions`
- universal-sierra-compiler 2.8.0 (for Sierra → CASM)
- Wrapper contracts in `contracts/`, thin `#[starknet::contract]` around the
  vendored `verify_*` entry points; `[[target.starknet-contract]]` with
  `allowed-libfuncs-list.name = "audited"`; gas ON (workspace does not set
  `enable-gas = false`); default inlining unless noted.

## Results

| Build | Compiles | Audited libfuncs | Sierra program (cap 81,920 felts) | Class w/o debug info (cap 4,089,446 B) | CASM bytecode |
|---|---|---|---|---|---|
| Full Cairo verifier (`cairo_air`), `poseidon252_verifier`, no outputs packing | ✅ | ✅ pass | **451,965** (5.5× over) | **27,638,373 B** (6.8× over) | not attempted (pointless at this size) |
| Same, `inlining-strategy = "avoid"` | ✅ | ✅ pass | 448,281 (−0.8%) | 27,064,540 B | — |
| Circuit verifier (`circuit_air`), blake2s (no features) | ✅ | ✅ pass | **48,789 ✓** | **2,885,030 B ✓** | **78,185 felts** |
| Circuit verifier, `poseidon252_verifier` | compiles but **is a brick** | — | 1,418 (collapsed) | — | 3,931 |

Notes on methodology:

- The allowed-libfuncs check is genuinely enforced: substituting a bogus list
  name fails the build with `failed to check allowed libfuncs`. So the clean
  passes above are real, including **blake2s libfuncs being audited**.
- The `poseidon252_verifier` feature was verifiably active in the full-verifier
  build: `cairo_air/src/features_check.cairo` emits `compile_error!` unless
  exactly one of `qm31_opcode`/`poseidon252_verifier` is enabled.
- The circuit-verifier + poseidon row: `circuit_air::get_verification_output`
  **unconditionally panics** under `poseidon252_verifier` ("the privacy
  recursive circuit verifier only supports the blake2s hasher"). With default
  inlining the optimizer folds the entire entry point into that panic
  (1,418 felts). Lesson recorded: always sanity-check artifact size/CASM,
  a tiny artifact means the body collapsed, not that you won.

## Findings

1. **Wall 1 (retargeting) is 90% down.** Gas-on compilation needed zero code
   changes. `bounded_int`'s QM31 emulation lowers entirely to audited
   libfuncs — the qm31-opcode ban is a non-issue on this path, as the
   handoff predicted.
2. **The one real blocker is class size, and it's structural.** The Sierra
   program is dominated by ~100 AIR component evaluators in `cairo_air`;
   `inlining-strategy = "avoid"` recovers <1%. Deploying the full verifier
   means splitting across ≥6 classes wired by library calls (Integrity-style),
   or upstream size reduction.
3. **The circuit verifier fits on-chain today** (all three size caps), with
   two big caveats:
   - It verifies proofs of **one hardcoded circuit** (the "privacy /
     multiverifier" recursion circuit; topology + preprocessed root baked in
     from StarkWare's Rust-side `stwo-circuits` `build_verification_circuit`).
     It is not a verifier for arbitrary Cairo programs.
   - It is **blake2s-only** — fine for contracts (blake2s libfuncs are
     audited), but it means the poseidon-for-on-chain assumption from the
     handoff doesn't apply to this route.
4. **Strategic implication:** if StarkWare's multiverifier circuit can verify
   a Stwo proof of an *arbitrary* Cairo program (recursion wrapper: prove
   your program → circuit-prove the verification of that proof), then the
   deployable contract is the *small* circuit verifier, and the full Cairo
   verifier never needs to go on-chain at all. Upstream comments
   (`TODO(Gali): Change to MultiVerifier consts`) suggest this is actively
   evolving. This is now the most promising route and needs research into
   the `stwo-circuits` Rust crates and whether the circuit-proving flow is
   usable outside StarkWare.

## Open questions

- Does the 81,920-felt bytecode cap apply to Sierra, CASM, or both?
  docs.starknet.io doesn't say. The circuit verifier's CASM is 78,185 felts —
  only 4.6% of headroom if the cap applies to CASM. **Resolve with a real
  `declare` on devnet/Sepolia** (also validates the class end-to-end).
- Can the multiverifier circuit wrap proofs of arbitrary Cairo executables,
  and is the circuit prover (`stwo-circuits`) public/usable?
- Step cost of verification — Spike 2, unchanged: run the vendored
  executable verifier over a real proof with
  `scarb execute --print-resource-usage`. This decides single-tx vs
  resumable verification for whichever route wins.

## Gate verdict (per handoff §4)

Not "doesn't compile — park" and not yet "green". The compile probe passed
with a single, well-understood blocker (size). Proceed to Spike 2 (step
measurement); in parallel, research the circuit-verifier route, which may
obsolete the class-splitting work entirely.
