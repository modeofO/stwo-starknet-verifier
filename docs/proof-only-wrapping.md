# Proof-only wrapping spike (2026-07-03)

**Question (build-order gate, item a):** can the recursion wrapper accept a
*proof* instead of a program+witness — so the client keeps everything private
and the middleman is a pure compressor? And can the app program be embedded
directly in the cairo-verifier circuit config, instead of going through the
privacy bootloader? Is the `stwo-cairo` npm/WASM browser prover's output
compatible with `build_fixed_cairo_circuit`?

**Answer: proof-only wrapping works today — shipped in the bridge as
`prove` / `wrap` subcommands and validated byte-for-byte against the Sepolia
fixture.** Direct app-program embedding also works *mechanically*
(`wrap-app`), but only for bootloader-shaped proofs; raw standalone-executable
proofs hit a structural 11-segment wall in the circuit statement. The npm
browser prover as shipped is incompatible on every axis that matters; a
custom WASM64 build of the pinned privacy stack is the browser path.

## What shipped

`tools/privacy-prove-cairo-bridge` now has an explicit client/wrapper
boundary (`scripts/prove-and-verify.sh` exercises it):

```
prove <task> <cairo_proof.json> <preimage.json> [args]     CLIENT SIDE
    bootloader run + Stwo proof (Blake2sM31, privacy params, extended proof).
    The witness never leaves this stage.

wrap <cairo_proof.json> <preimage.json> <felts.json>       WRAPPER SIDE
    cairo-verifier circuit -> multiverifier -> 36,022 felts.
    Inputs are 100% public: the proof (serde-JSON CairoProof, 2.2 MB for our
    fixture) and the 4-felt output preimage. The wrapper cross-checks
    blake2s(preimage) against the proof's output value before doing any work.

wrap-app <cairo_proof.json> <felts.json>                   EXPERIMENTAL
    Design B: embeds the *proven program itself* in the circuit config —
    program, outputs, component set all read from the proof's public data;
    preprocessed root and privacy PCS config pinned, never taken from the
    proof. No bootloader JSON involved.
```

Measured on the `poseidon_chain(100)` fixture (M-series laptop):

| Stage | Wall time | Peak RSS | Artifact |
|---|---|---|---|
| `prove` (client) | 3.3 s | **7.9 GB** | 2.2 MB `CairoProof` JSON + 4-felt preimage |
| `wrap` (middleman) | 13.1 s | **13.6–21.9 GB** (run variance) | 36,022 felts |
| verify (vendored Cairo verifier) | — | — | **3,814,641 steps — accepted** |

The two-stage output is **byte-identical** to the single-shot fixture proof
(`fixtures/poseidon_chain_n100.multiverifier_proof.json`) — proving is
deterministic at `channel_salt: 0`, so splitting the pipeline loses nothing.
`wrap-app` over the same (bootloader-shaped) proof also produces the
identical stream, confirming the program-embedding code path end to end.

## Why this matters for trust

The wrapper (relayer) previously needed the executable + program args — it
re-ran the program. Now it receives only:

- the Stwo proof of the bootloader run (public by construction — it goes in
  calldata eventually), including the prover aux data
  (`ExtendedStarkProof.aux`: unsorted query locations, Merkle node hashes,
  FRI aux — all recomputable-by-a-verifier public data, all serde-JSON), and
- the output preimage `[n_tasks, output_len, app_program_hash, app_outputs…]`
  (exactly what the fact ultimately binds).

The middleman can refuse, but cannot forge and never sees a witness. This
satisfies build-order gate (a): **client apps can now be built against a
proof-only relayer API.**

## Design B: embedding the app program (`wrap-app`)

`CairoVerifierConfig.program` is just memory cells; the circuit binds them as
constants and mixes a blake2s program hash at circuit-construction time
(stwo-circuits `cairo_verifier/src/statement.rs`, `claims_to_mix`). So the
inner circuit **root** binds: program, component set, n_outputs, PCS config,
preprocessed root. The multiverifier hashes that root with the inner output
values (`blake2s(app outputs)`) into the final statement. A consumer
whitelists the expected inner root per application — it is deterministic and
computable offline. `wrap-app` implements exactly this (mirroring upstream's
`verify_cairo_with_component_set`, but proving instead of verifying).

**The wall: raw standalone-executable proofs are not circuit-compatible.**
The circuit statement hardcodes the full 11-builtin public-segment layout:
`N_SEGMENTS = 11` in `AuxData` (statement.rs:44), `AUX_DATA_FIXED_LEN`
depends on it, `AuxData::parse_from_vars` destructures exactly 11 ranges, and
`CairoStatement::new` asserts the aux-data length (statement.rs:341).
scarb-built executables declare only the builtins they use
(`poseidon_chain`: `[output, range_check, poseidon]` → a 3-segment claim,
see spike 2 and `tools/prover-executable-segment-context.patch`), and the
missing windows physically don't exist in the proven memory — the logup sum
over 11 windows cannot balance. The bootloader exists precisely to give
every execution the 11-window shape (simulating absent builtins).

Two ways forward, in preference order:

1. **Bootloader moves client-side (what `prove`/`wrap` implement).** Zero
   circuit changes, zero new soundness surface. Native clients (the egui
   direction) link `privacy_prove` and run the bootloader locally — done.
   Browsers need the bootloader runner (cairo-vm + proving-utils hints) in
   WASM — part of the WASM64 build below, not a new problem.
2. **Fork `CairoStatement` for segment subsets** (a `present: [bool; 11]`
   mask baked into the topology: aux-data length, `return_value_address =
   final_ap - n_present`, `verify_builtins` skipping absent segments while
   statically requiring their components disabled, and claim mixing kept
   byte-compatible with `CairoClaim::mix_into` for subset claims). Entirely
   off-chain, root-bound, feasible — but soundness-critical circuit surgery
   for a benefit (skipping the ~30k-step bootloader run client-side) that is
   small next to the 10-second wrap. **Not pursued for now.**

## Browser prover compatibility (the npm reality check)

The `stwo-cairo` npm package (v1.1.1, the one messagezk uses) is
[clealabs/stwo-cairo-ts](https://github.com/clealabs/stwo-cairo-ts) — a
WASM64 (Memory64) wrapper of StarkWare's `cairo-prove` at stwo-cairo
~`335de15d`, with `fix-wasm64` forks of both stwo-cairo and the cairo repo.
Its output is a serde-JSON `CairoProof<Blake2sMerkleHasher>` — the right
*kind* of object, but incompatible with the wrap chain on every axis:

| Axis | npm as shipped | wrap chain requires |
|---|---|---|
| channel | `Blake2sMerkleChannel` | `Blake2sM31MerkleChannel` |
| PCS config | pow 26, blowup 1, 70 queries | privacy config: pow 27 + `CAIRO_PCS_CONFIG` (lifted commitments) |
| preprocessed trace | `Canonical` / `CanonicalWithoutPedersen` | `CanonicalSmall` |
| proof struct | plain `StarkProof` (pre-`vcs_lifted` rev) | `ExtendedStarkProof` incl. prover aux |
| segment shape | standalone (declared builtins only) | bootloader-shaped (all 11) |

None of these are fundamental: they are parameter/rev choices in a ~450-line
custom wasm `lib.rs`. The browser path is therefore **a custom WASM64 build
of the pinned privacy stack** (stwo `5ea05973` + stwo-cairo `68b4af6d` +
proving-utils bootloader runner), not the npm package as shipped.

## WASM feasibility (memory verdict)

- `prove` peaks at **7.9 GB** and `wrap` at **13.6+ GB** on the smallest
  real fixture — both far beyond wasm32's 4 GB ceiling. **wasm32 is dead**
  for both stages regardless of compile-ability; Memory64 is mandatory
  (consistent with the npm package targeting WASM64, and with their needing
  `fix-wasm64` forks).
- Browser support therefore means: WASM64 + SharedArrayBuffer headers +
  multi-GB browser memory budgets — real, but an engineering project of its
  own. The native desktop client dodges all of it, which reinforces the
  egui-first client decision in `architecture.md`.
- **wasm32 compile attempt: succeeds.** `cargo build --target
  wasm32-unknown-unknown -p circuit-prover` at the pinned stwo-circuits rev
  (nightly-2026-01-15) compiles the entire wrap-chain dependency tree —
  stwo, cairo-air, cairo-vm, all circuit crates — cleanly in 25 min.
  Compilation is a non-issue; memory is the only (fatal) wasm32 blocker.

## Status of the build-order gate

Gate (a) — proof-only wrapping — **landed**. Client-app scaffolding is
unblocked per `architecture.md`; lane 2 remains the priority before starting
it.
