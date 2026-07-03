# Lane 2 groundwork — resumable full-Cairo verification (2026-07-03)

**Goal (the golden goose):** the sovereign lane — a user's wallet stages a
poseidon-config Stwo proof of their own program and the chain verifies it
with the **full Cairo verifier** across N transactions, no third party
anywhere in the flow. This doc turns spike-2's "10–16M steps, multi-tx state
machine" sketch into a measured, phase-by-phase design, built on the
checkpoint machinery shipped in lane 1
(`contracts/stwo_verifier_phases/src/resumable.cairo`).

## Measured baseline (new, this session)

Fixture: `poseidon_chain(100)` under the privacy bootloader, proven with
`fixtures/prover_params_poseidon.json` (poseidon252 channel, pow 26,
blowup 1, **70 queries, fold_step 1**, `canonical_without_pedersen`), via
`privacy_prove_cairo_bridge prove-poseidon`. Verified end-to-end by the
vendored `stwo_cairo_verifier` (poseidon252_verifier +
poseidon_outputs_packing — the contract-legal build).

- **Proof: 301,143 felts** — 96.4% u32-valued (packs 7/slot, lane-1 style),
  3.6% full felts (poseidon hashes). Packed ≈ 52k slots / ≈ 45k calldata
  felts.
- **Client-side proving: 257 s wall, 11.3 GB peak** on an M-series laptop
  (the poseidon Merkle commitments are ~80× slower than lane 1's blake2s
  SIMD path — the sovereign lane's client cost).
- **Verification: 34,229,840 steps** (3.12M range_check, 37.7k poseidon) —
  2–3× spike 2's "smallest proof" numbers; our fixture carries the
  bootloader + a 2,597-cell program and n=100 payload.

### Per-phase cost map (tools/lane2-probe)

`tools/lane2-probe` is `verify_cairo` truncated at each candidate phase
boundary (stage argument selects the prefix; visibility patches logged in
`vendor/stwo_cairo_verifier/VENDORED.md`). Measured over the fixture proof:

| # | Block (cumulative boundary) | Steps (Δ) | Splittable further? |
|---|---|---|---|
| 0 | full-proof Serde deserialization | 4.96M | **avoid**: feed per-phase sections instead |
| 1 | `verify_claim` | 0.01M | — |
| 2a | channel init + config mix + preprocessed commit + `claim.mix_into` + trace commit + interaction PoW | 6.45M | yes — poseidon sponge state is checkpointable mid-absorb; cost ∝ program size |
| 2b | lookup elements draw + `lookup_sum` (incl. public-memory logup) | 3.67M | yes — pure accumulator over entries/components |
| 2c | interaction claim mix + interaction commit | 0.14M | — |
| 3 | composition commit + OODS draw + composition eval + OODS check | 1.72M | single block (fits one tx) |
| 4 | `mix_sampled_values` + FRI commitment phase + queries PoW + query sampling | 0.25M | — |
| 5 | Merkle decommitments × 4 trees | 1.62M | per tree |
| 6 | `fri_answers` (quotient accumulation, 70 queries × all columns) | 12.75M | yes — accumulator per query / column group |
| 7 | FRI decommit (folding walk, ~20+ layers at fold_step 1) | 2.56M | per layer group |
|   | **Total** | **34.1M** | |

Production gas: lane 1 measured 3.81M steps ⇒ 1.43e9 L2 gas on
Sepolia/devnet (≈ 375 gas/step for a similar profile). Scaling:
**34.1M steps ≈ 12.8e9 gas ≈ 11 invokes of pure compute** at the 1.21e9
per-invoke cap — before section-feeding overhead. Realistic estimate
including feeding: **15–25 verification txs per fact**. At lane-1's spiky
Sepolia prices that is hundreds of STRK per fact. This is the price of
sovereignty until the qm31 opcode enters `audited.json` (watch item — it
collapses the bounded_int emulation that dominates these counts).

## Architecture: the generalized checkpoint machine

Lane 1's two-phase trick generalizes. Three classes of proof data, each
with its own transport:

1. **Self-authenticating sections** — Merkle `decommitments`,
   `queried_values`, FRI inner-layer witnesses. Tampering makes their own
   verification fail against roots/queries already bound upstream. Pure
   calldata, no storage, no extra binding needed (lane 1's phase 2 already
   works this way for the FriProof, via the query-position equality check).
2. **Channel-bound sections** — claim, commitments, sampled values, PoW
   nonces: everything `mix_*`ed into the transcript. Their bytes are bound
   by the channel digest that crosses phases in the checkpoint. When a
   later phase needs the same bytes again (e.g. `sampled_values` feeds both
   the OODS check and `fri_answers`), it re-supplies them as calldata and
   the phase **re-hashes and compares** against a digest stored in the
   checkpoint — cost: one hash pass.
3. **Checkpoint state** — storage, tens-to-hundreds of felts between txs:
   - Poseidon channel state: `(digest: felt252, n_draws: u32)` — *simpler*
     than lane 1's blake2s 8-word digest. (Needs `Poseidon252Channel.digest`
     made pub — same VENDORED.md pattern as blake2s.)
   - mid-sponge state `(s0, s1, s2, odd)` when a big absorb
     (`claim.mix_into`'s `hash_small_vals`) is split across txs — the
     hades sponge is checkpointable between absorptions with a
     byte-identical transcript.
   - running accumulators: logup sum (QM31), `fri_answers` partial
     quotient sums, composition partial sums if ever needed.
   - OODS point, random coefficients, 70 query positions, first-layer
     evals, tree metadata (roots + column log-size spans or their hash).

### Draft phase plan (tx budget ~2.5–3M steps each)

| Tx | Work | Checkpoint out |
|---|---|---|
| 1 | `verify_claim` + config/salt mix + preprocessed commit + start `claim.mix_into` (chunk 1) | sponge state, claim digest so far |
| 2..k | `claim.mix_into` chunks (program section ∝ app size) + trace commit + interaction PoW | channel digest |
| k+1..m | `lookup_sum` in accumulator chunks (claim sections re-supplied, hash-compared) | partial logup sum |
| m+1 | interaction mix/commit + composition commit + OODS draw + **composition eval + OODS check** (1.72M, single tx) | channel, OODS point, random coeff |
| m+2 | `mix_sampled_values` (sampled values as calldata; digest saved for reuse) + FRI commit + PoW + query sampling | query positions, FRI alphas/roots digest |
| m+3..m+4 | Merkle decommits, ~2 trees per tx (calldata sections, self-authenticating) | per-tree done-bits |
| m+5..p | `fri_answers` in chunks (sampled+queried values re-supplied per chunk, hash-compared; accumulate per query) | partial answers |
| p+1..q | FRI decommit by layer groups | folding state |
| q | final assert + fact registration in the shared `StwoFactRegistry` (governed route list) | `FactRegistered` |

With our fixture's numbers: k≈3, m≈5, p≈11, q≈15 — **~15 txs**, matching
the estimate above. Every section arrives packed (7 u32/felt + full-felt
escape — extend lane 1's u64 escape to a felt252 escape for the 3.6%
poseidon hashes) in the same tx that consumes it: ~45k packed calldata
felts spread over ~15 txs ≈ 3k felts/tx — comfortably under the 4,996
usable cap. **No storage staging at all** — the 27-tx staging estimate is
obsolete; storage holds only checkpoints.

### Soundness invariants (carried from resumable.cairo, extended)

- The concatenated transcript across phases must be byte-identical to the
  monolithic verifier's — checkpoint only at sites where the channel state
  is exactly `(digest, n_draws)` (any site works for poseidon since both
  are stored; prefer post-`update_digest` sites where `n_draws == 0`).
- Any section used in ≥2 phases must be bound in every later use
  (re-hash + compare, or self-authentication). The lane-1 query-equality
  trick is the special case for the FRI section.
- A phase may only run if the previous phase's checkpoint exists and is
  keyed to the same (caller, proof_id); the fact registers only after the
  final phase.
- Checkpoints are write-once per (proof_id, phase) — re-running a phase
  with different calldata must either produce the identical checkpoint or
  abort (prevents mid-flight state swaps).

## Class splitting

Spike 1: the full verifier is ~450k Sierra felts vs the 81,920-felt CASM
cap (lane 1 measured CASM ≈ 1.6–2× Sierra for this code). Expect **~8–12
immutable phase-library classes**, pinned in a registry constructor exactly
like lane 1's `StwoPhase1`/`StwoPhase2`. The phase boundaries above are
natural class boundaries; `eval_composition_polynomial_at_point` (the
component zoo) is the biggest single class and may itself need splitting
per component group — measure Sierra size per phase crate early.

## Client side

`prove-poseidon` in the bridge is the client reference path (bootloader →
`create_and_serialize_proof` with the poseidon params). 257 s / 11.3 GB on
a laptop today; native desktop client only (WASM64 eventually, same caveats
as lane 1 — see proof-only-wrapping.md).

## Build order

1. ~~**Packing v2**~~ **done (2026-07-03):** `pack_proof.py --v2` +
   `unpack_proof_v2` (`0xFFFFFFFE` escapes a full felt252 as 8 LE limbs);
   the fixture proof packs to 55,540 slots; v1 output byte-identical for
   lane 1.
2. ~~**Channel checkpoint + skeleton**~~ **done (2026-07-03), beyond plan:**
   `contracts/stwo_full_verifier_phases/src/resumable_full.cairo` splits the
   full verifier at the lookup-elements seam with *no stubbed middle* —
   phase A (claim checks + Fiat-Shamir prologue) and phase B (re-draws the
   lookup elements from the checkpointed pre-draw digest, rebuilds the
   trees without re-mixing, runs verify() + verify_values()). snforge over
   the real fixture proof: two-phase == monolithic; tampered proof and
   forged checkpoint digest both rejected. The Poseidon channel crosses the
   boundary as a single felt (vendored patch logged in VENDORED.md).
   Also landed: `src/sponge.cairo`, the resumable `poseidon_hash_span`
   (4-felt checkpoint state) — tests prove chunked absorption with a serde
   round-trip between chunks reproduces `mix_felts` and
   `hash_u32s_with_state` exactly. This is the chunking primitive for both
   monsters in step 3.
3. **The two monsters**: chunked `claim.mix_into` and chunked
   `fri_answers` (the 6.45M and 12.75M blocks) — refactor phase A/B into
   sub-phases using the sponge (claim mix) and per-query accumulators
   (fri_answers), with per-chunk snforge cost probes.
4. Wire the remaining blocks (OODS tx, Merkle txs, FRI txs), per-section
   binding digests replacing the whole-stream `proof_hash`, devnet
   pre-flight (gas per phase, digit-exact per lane-1 experience), Sepolia
   campaign under the registry's governed route list.
5. Re-measure everything the day qm31 libfuncs appear in `audited.json`.

## Open questions

- Exact per-section felt offsets/format for the calldata feeding (needs a
  section-aware serializer on the client side; the Serde layout is already
  linear and self-describing).
- Whether `lookup_sum`'s per-component terms can be verified per-chunk
  without materializing all `common_lookup_elements` powers each tx
  (probably yes — they are drawn once and can ride the checkpoint).
- devnet gas/step calibration for this workload's builtin mix (9% rc
  density vs lane 1's 13%; the 375 gas/step figure is conservative).
- messagezk's circuit is bigger than `poseidon_chain(100)` — re-run
  `prove-poseidon` + the probe on the real circuit once it exists to size
  the production tx count.
