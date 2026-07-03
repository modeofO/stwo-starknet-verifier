# Spike 2 results — the number (2026-07-02)

**Question:** how many Cairo steps does it take to verify a real Stwo proof
with the Cairo verifier in its on-chain (`poseidon252_verifier`)
configuration — and does that fit Starknet's per-transaction budget
(1.1e9 L2 gas ≈ 11M steps, at 100 gas/step, before builtin costs)?

**Answer: 10.0M–15.9M steps for the smallest possible proofs.
Single-transaction verification with the full Cairo verifier is
borderline-impossible today.** Meanwhile the circuit verifier (recursion
route) measures far below budget — see below. No public benchmark of these
numbers existed before this.

## Environment

- stwo-cairo pinned commit `92bfd1d3` for both the Rust prover
  (built from source, release, `target-cpu=native`) and the vendored Cairo
  verifier. Scarb 2.18.0. Apple M-series (aarch64-darwin).
- Verifier executed with
  `scarb execute -p stwo_cairo_verifier --features <config> --target
  standalone --print-resource-usage --arguments-file <proof>`
  (gas off — step counts are hardware/gas-independent).
- Prover params (96-bit security): poseidon252 channel, blowup 1,
  `canonical_without_pedersen` preprocessed trace. Two parameter sets used:
  upstream-reference (pow_bits 20, 90 queries) and ours (pow_bits 26,
  70 queries) — see `fixtures/prover_params_poseidon.json`.

## Measurements

| Proven program | Proof size (felts) | Verifier build | Verifier steps | range_check | poseidon |
|---|---|---|---|---|---|
| `ret_opcode` (minimal; upstream reference proof, pow 20/q 90) | 65,291 | `poseidon252_verifier` | **10,042,975** | 1,075,690 | 22,625 |
| `poseidon_builtin` (uses poseidon builtin; pow 26/q 70) | 161,903 | `poseidon252_verifier,poseidon_outputs_packing` | **15,883,736** | 1,395,132 | 24,825 |
| privacy/multiverifier circuit (upstream test circuit proof, blake2s) | 35,658 | `stwo_circuit_verifier` (blake2s, no features) | **3,789,243** | 506,777 | — |

Cross-check: our Rust proving pipeline reproduces upstream's checked-in
reference proof **byte-for-byte** (`proof_ret_opcode` — 65,291 felts,
identical), so the measurements are of correctly-formed proofs, and every
proof was additionally verified by the Rust verifier (`--verify`) before
being fed to the Cairo verifier.

### L2 gas arithmetic

Steps convert at 100 L2 gas/step; builtins add more on top (range_check ≈ 70
gas each ⇒ ~75–98M extra here). So:

- `ret_opcode`: ≥ 1.004e9 + ~0.08e9 ≈ **1.08e9 L2 gas — ~98% of the 1.1e9
  cap** for the *smallest proof the system can produce*.
- `poseidon_builtin`: ≈ **1.7e9 L2 gas — 1.5× over the cap.**
- circuit verifier: ≈ 3.79e8 + 0.35e8 ≈ **4.1e8 L2 gas — ~38% of the cap.
  Single-tx on-chain verification is viable on this route.**

Any real application proof will be at or above the second row. Verdict per
the handoff's gate: **steps ≫ 10M — single-tx full verification is out;
the full-verifier route means an Integrity-style resumable verification
state machine** (or waiting for qm31 libfuncs to be audited).

## Proof sizes vs calldata

Proofs came out **far larger than the handoff's estimate**: 65k–223k felts
(~2–7 MB serialized) against a 5,000-felt calldata cap — i.e. **13–45
upload transactions** per proof, before any verification. There is a large
fixed floor: a 239-step program still yields a 162k-felt proof at pow 26 /
70 queries (the claim structure + query openings over lifted preprocessed
traces dominate). Fewer queries / higher blowup trades this down; measuring
that curve is future work. The circuit proof is much smaller: 35,658 felts
(~8 upload txs).

## What we learned along the way (all of it load-bearing)

1. **The builtin support matrix constrains applications hard.** Which
   builtins a *proven program* may use depends on the verifier build:

   | Verifier build | Builtins allowed in proven program |
   |---|---|
   | blake2s (`not poseidon252_verifier` ⇒ requires `qm31_opcode` ⇒ **cannot be a contract**) | output, bitwise, range_check, range_check96, add_mod, mul_mod, pedersen, poseidon, ec_op |
   | `poseidon252_verifier` | output, bitwise, range_check **only** |
   | `poseidon252_verifier` + `poseidon_outputs_packing` | output, bitwise, range_check, **poseidon** |

   Nothing supports `ecdsa`/`keccak` builtins, and — critically — **the only
   contract-legal configuration has no `ec_op` and no `pedersen`**. An app
   like messagezk (Poseidon Merkle proofs + Stark-curve ec-muls) must use
   the `poseidon_outputs_packing` build *and* implement its EC math without
   the ec_op builtin — or take the recursion route, whose blake2s leg
   supports everything.

2. **Programs are proven bootloader-style, not as raw scarb executables.**
   The proof format's public-segment layout requires all 11 builtin pointer
   windows (the cairo-serde serializer `unwrap()`s them). scarb-built
   executables only carry the builtins they use, so raw executables with
   partial builtin lists can't produce Cairo1-verifier-compatible proofs.
   (We patched the pinned prover's dev binary to at least *prove* such
   executables — `tools/prover-executable-segment-context.patch` — but the
   cairo-serde output path still requires the full segment set.) Practical
   consequence: application programs run *under a bootloader* (as SHARP and
   StarkWare's privacy stack do) — e.g. the "privacy simple bootloader" in
   stwo-circuits' test data.

3. **The generic opcode is unsupported** by the verifier
   (`assert cairo_claim.generic_opcode.is_none()`), which is why the
   `all_opcode_components` upstream test program can't be used as a fixture
   for this configuration.

4. **`unsafe-panic` (the `proving` profile) turns verifier rejections into
   opaque `ASSERT_EQ` failures.** Debug verification runs with the dev
   profile to see real panic messages.

5. **The recursion stack is public.** `starkware-libs/stwo-circuits`
   contains: a circuit that verifies arbitrary `cairo_air::CairoProof`s
   (`crates/cairo_verifier`), a privacy configuration of it pinned to the
   "privacy simple bootloader" program (trace log-size 20), a circuit
   prover, and a multiverifier. Its output proof is exactly what our
   already-deployable circuit-verifier contract (Spike 1: 48,789 felts,
   under every limit) checks on-chain. Pipeline:
   *app program under bootloader → Stwo blake2s proof → circuit proof of
   its verification → small on-chain circuit verifier*.

## Gate verdict & routes

- **Route A (full verifier on-chain):** dead as a single tx. Alive only as
  a resumable multi-tx state machine ("Integrity for Stwo"): ~13–45 staging
  txs + N verification txs. Multi-month, grant-scale work, high ongoing
  cost per proof.
- **Route B (recursion/circuit route):** the contract already fits
  (Spike 1), and verification measures **3.79M steps ≈ 38% of one
  transaction's gas** with a 35,658-felt proof (~8 staging txs). The open
  work is off-chain: drive stwo-circuits' prover to wrap an arbitrary
  program's proof, and check the produced circuit topology matches the
  hardcoded constants in the on-chain `circuit_air`
  (`privacy_consts.cairo`; upstream TODO says these move to MultiVerifier).
  **This is Spike 3, and it is now clearly the primary route.**

## Reproduce

```sh
# Prove (Rust, pinned commit; see tools/ patch for scarb executables):
run_and_prove --program <compiled.json> --program_type json \
  --params_json fixtures/prover_params_poseidon.json \
  --proof_path proof.json --proof-format cairo-serde --verify

# Verify + measure (from vendor/stwo_cairo_verifier):
scarb execute -p stwo_cairo_verifier \
  --features poseidon252_verifier,poseidon_outputs_packing \
  --target standalone --output standard \
  --print-resource-usage --arguments-file proof.json
```
