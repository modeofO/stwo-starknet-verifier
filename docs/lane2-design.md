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

Measured (2026-07-03, the skeleton's library-class wrappers, audited
allowlist **passing**):

| Class | Sierra felts | vs 81,920 cap |
|---|---|---|
| `StwoFullPhaseA` (claim checks + prologue) | **31,075** | **fits already** |
| `StwoFullPhaseB` (AIR eval + PCS + FRI) | **778,271** | ~9.5× over |

The split burden is entirely in phase B, dominated by
`eval_composition_polynomial_at_point`'s component zoo. Expect **~10–15
immutable phase-library classes** once phase B is sub-phased (Merkle, FRI,
fri_answers separate naturally; the air eval itself must split by component
group), pinned in a registry constructor exactly like lane 1's
`StwoPhase1`/`StwoPhase2`. Note CASM runs 1.6–2× Sierra for this code and
the CASM cap binds too (lane 1's hard lesson).

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
3. **The two monsters**:
   - ~~chunked `claim.mix_into`~~ **done (2026-07-03):**
     `src/claim_mix.cairo` — the pipeline (`claim_mix_begin` → N
     `claim_mix_absorb_program_entries` chunks → `claim_mix_finalize`)
     reproduces the monolithic claim-mix digest exactly over the real
     fixture claim, with checkpoint serde round-trips between chunks. Two
     pausable absorbers: `ChunkedU32Mix` (the `mix_felts ∘ pack_into_qm31s`
     stream: 8 u32 → 2 QM31 → 1 pair-packed felt, zero-padded/odd tails
     mirrored) and `ChunkedSmallVals` (the `hash_small_vals` stream: 8
     values per `M31_SHIFT` word, length-padded tail). Program entries are
     the chunk unit (9 serde felts each → ~540/tx within the calldata
     budget; the fixture's 2,597 entries ≈ 5 txs). The output hash is
     precomputed in `begin` and applied at its transcript position in
     `finalize`.
   - ~~chunked `fri_answers`~~ **done (2026-07-03), and no fork was
     needed:** each query's answer is independent and the queried values
     are consumed query-major with a fixed per-tree stride (one M31 per
     column), so a transaction computes any contiguous query range by
     calling the *vendored* `fri_answers` verbatim over the range's
     positions and per-tree queried-values slices
     (`src/fri_chunks.cairo`: `queried_values_strides` +
     `slice_queried_values`). Cross-chunk state is just the accumulated
     answers; the per-group quotient constants recompute per tx (≈ one
     extra query's cost). Equivalence over the real proof: 5 chunks of ≤16
     queries == single-shot (`tests/test_fri_chunks.cairo`). Production
     binding of a chunk's slice: per-tree queried-values digests from the
     Merkle phases.
4. Wire the remaining blocks (OODS tx, Merkle txs, FRI txs), per-section
   binding digests replacing the whole-stream `proof_hash`, devnet
   pre-flight (gas per phase, digit-exact per lane-1 experience), Sepolia
   campaign under the registry's governed route list. See "Machine plan
   v2" below for the section-driven transaction plan.
   - ~~witness splitter~~ **done (2026-07-03):** `split-witness` in the
     bridge + `tests/test_witness_groups.cairo` — see the machine-plan
     bullet below for the numbers. The extended-proof fixture is
     regenerable (deterministic) at
     `fixtures/poseidon_chain_n100.extended_proof.json` (gitignored).
   - ~~incremental verify_claim + lookup_sum~~ **done (2026-07-03):**
     `src/lookup_chunks.cairo` + `tests/test_lookup_chunks.cairo`.
     Two findings collapsed this into a small module:
     1. **`verify_claim` needs no chunking.** It reads the first 6
        program entries (`verify_program` pops exactly 6), the
        builtin/segment ranges and the per-component claims — all
        small-claim data. Proven on the real proof: a doctored claim
        whose program span holds only a 6-entry prefix deserializes and
        passes the vendored `verify_claim` verbatim. The begin tx runs
        it over the small claim + first program chunk.
     2. **`lookup_sum` is a flat field sum** — per-entry inverse terms
        + state terms + claimed sums — so it chunks by program-entry
        ranges with one QM31 accumulator in the checkpoint.
        `lookup_sum_program_chunk` builds `PublicMemoryEntries` from a
        chunk (base address = `initial_pc + offset`) and calls the
        vendored `sum_public_memory_entries` verbatim (made pub, logged
        in VENDORED.md); `lookup_sum_rest` covers the non-program terms
        via `get_entries` over an emptied program section (non-program
        addresses never depend on it). Chunked (5 × 540 entries) ==
        monolithic == 0 on the real claim; a tampered entry limb breaks
        the sum. The lookup elements are re-drawn per tx from the
        checkpointed pre-draw digest — nothing else rides the
        checkpoint but the accumulator. No binding digest needed: the
        same chunk bytes feed the claim-mix absorber in the same tx.
5. Re-measure everything the day qm31 libfuncs appear in `audited.json`.

## Section map (measured 2026-07-03, `tests/test_sections.cairo`)

| Section | Felts | Share | Transport plan |
|---|---|---|---|
| claim | 23,538 | 7.8% | 165 felts of non-program claim (one tx!) + 23,373 program-entry felts (chunk-fed, the claim_mix pipeline) |
| interaction_pow + interaction_claim | 214 | — | rides the begin tx |
| pcs_config + commitments | 11 | — | rides the begin tx |
| sampled_values | 18,261 | 6.1% | chunk-fed to the mix (sponge); see the constants dilemma below |
| decommitments | 4,259 | 1.4% | one tx per witness group (client emits per-group witnesses) |
| **queried_values** | **244,445** | **81.2%** | pure M31s → 7:1 packed ≈ 35k felts; per (tree × query-group) rows |
| fri_proof | 10,413 | 3.5% | 2–3 txs, lane-1-style query-position binding |

## Machine plan v2 (post-measurement)

- **The elephant is queried_values.** 70 queries × 3,492 total columns.
  A Merkle *row* (one query, one tree, all its columns — leaf hashes span
  every column) is irreducible but small: the trace tree is ~286 packed
  felts per query. Phases chunk by **(tree × query-group)** with rows in
  calldata — storage-free transport at ~8–12 txs.
- ~~**Per-group decommitment witnesses are a client-side (bridge) work
  item.**~~ **Done (2026-07-03) — the witness splitter ships in the
  bridge.** The serialized witness is deduplicated across the 70-query
  union; a query subset needs a *different* sibling set, so the on-chain
  side cannot slice the union witness. `split-witness` synthesizes one
  witness per query group from `ExtendedStarkProof.aux` alone (no
  re-proving: `MerkleDecommitmentLiftedAux.all_node_values` records both
  children of every internal node the union walk visits, and a subset's
  paths ⊆ the union's paths). The synthesis replays the verifier's
  bottom-up walk over the subset positions — the emitted sibling order
  (per layer, ascending position, leaves → root) is exactly what both the
  Rust prover emits and the vendored Cairo `MerkleVerifier::verify`
  consumes, which the splitter proves to itself on every run: the witness
  synthesized for the FULL query set must equal the proof's own
  `hash_witness`, per tree, byte for byte. Measured over the fixture
  (group size 16 → 5 groups):
  - Tree heights [26, 21, 21, 21] — the preprocessed tree is *taller*
    than the lifting size (26 > 21), so the pp query remap takes the
    up-shift branch; `prepare_preprocessed_query_positions` is applied
    per group and re-sorted (the remap is not monotonic).
  - Per-query row strides (columns per tree): [105, 2059, 1320, 8]
    = 3,492 total.
  - Witness sizes per group of 16: pp 301–322 felts, other trees
    221–242; the 6-query tail group 117/87. **Σ per-group witnesses =
    4,366 felts vs 4,259 in the union proof — splitting costs only
    +2.5% calldata.** (Witnesses are full felts — poseidon hashes — and
    don't pack.)
  - Rows per group of 16: trace tree 32,944 M31 ≈ 4,706 packed felts —
    at the ~4,996-felt usable cap *before* any overhead. The trace tree
    needs smaller groups (8–12 queries/tx) or a two-tx split per group;
    pp+interaction+composition groups fit comfortably.
  - snforge over the real proof (`tests/test_witness_groups.cairo`):
    vendored `MerkleVerifier::verify` accepts every (group × tree) pair
    against the monolithic roots — 5 groups × 4 trees — with the group's
    row slices equal to the on-chain `slice_queried_values` of the full
    stream; tampering one witness felt or one row value → Root Mismatch.
  - Repro: `prove-poseidon … --extended ext.json` (the re-prove is
    deterministic — repacked output is byte-identical to the committed
    fixture, PoW grind included), then
    `split-witness ext.json <dir> 16`.
- **Fusion:** a (tree × query-group) tx Merkle-verifies its rows on
  arrival and can immediately absorb them into per-(tree, group) digests
  or feed the fri_answers accumulator — data is consumed in the tx that
  transports it wherever possible.
- ~~**The sampled-values/constants dilemma**~~ **measured and settled
  (2026-07-03, `tests/test_constants_probe.cairo`).** The isolated costs
  over the real proof (l2_gas deltas between probes sharing one replay):
  - fri_answers **prelude** (build_samples_with_randomness + sample
    batches + `QuotientConstantsImpl::gen` over all sampled values) =
    **184.3e6 gas ≈ 15% of a 1.21e9 tx** — this is what a
    recompute-per-chunk tx pays.
  - **per query: 21.1e6 gas**, exactly linear (1-query and 16-query
    probes agree to 4 digits). Compute never binds: even 50 queries/tx
    ≈ 1.1e9 would fit — **queries per tx is calldata-bound, not
    compute-bound.**
  - Sizes (from the extended proof): 3,903 samples in the α chain
    (212 columns × 3 + 3,267 × 1); constants =
    3,903 α·c QM31s + per-batch sums ≈ **2.9k packed slots** (column
    indices are derivable on-chain from the claim, so they need not be
    stored); sampled-values re-supply ≈ **2.6k packed felts**. Rows cost
    ≈ 499 packed felts/query (3,492 cols / 7) + ~60 witness felts/query.
  - Consequences for a fused (Merkle + fri_answers) group tx under the
    ~4,996-felt calldata cap: with samples re-supplied per tx (stateless
    recompute), fixed 2.6k felts leaves room for only ~4 queries/tx →
    **~18 fused txs**; with a **one-time packed constants store** the
    group tx carries rows only → ~8–9 queries/tx → **~8 fused txs + 1
    store tx** (store: 2.9k slots < the 4,000-entry state-diff cap,
    derivation 184e6 gas, input = digest-bound samples, write-once
    checkpoint semantics; per-tx reads ~3e6 gas, negligible).
  - **Verdict: (a) the one-time packed constants store** — halves the
    fri_answers tx count at equal soundness (constants are deterministic
    state derived from channel-bound samples). Stateless recompute (c)
    stays the zero-storage fallback and is what the equivalence tests
    exercise today; column-range slicing (b) matches (a)'s tx count only
    by forking the vendored accumulation loop and transposing the row
    binding — not worth the surgery.
- **Revised tx estimate: ~25–40 per fact** (the 12.8e9-gas compute floor
  said ~11; transport, rebinding and the constants overhead roughly double
  to triple the count at lower per-tx gas). Still storage-free except
  checkpoints. Honest sovereign-lane pricing pending devnet calibration.

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
