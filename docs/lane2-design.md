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

## The machine (built 2026-07-03, `src/machine.cairo`)

The production-shaped N-phase state machine exists as pure functions — one
per transaction type, serde-able checkpoints between them, per-section
binding digests replacing the skeleton's whole-stream `proof_hash`:

```
begin → claim chunks × N → claim finalize (trace commit + interaction PoW)
      → lookup chunks × N (rolling-digest-bound program re-supply)
      → lookup finalize (zero check + interaction mix/commit)
      → OODS + sampled mix → FRI commit + queries PoW + sampling
      → fused Merkle+fri_answers group txs × G → FRI decommit + fact
```

Fixture instantiation: **21 transactions** (1 + 5 + 1 + 5 + 1 + 1 + 1 + 5 +
1). `tests/test_machine.cairo` drives the full sequence over the real proof
with a checkpoint serde round-trip between every pair of transactions:
output == `verify_full_monolithic`, and the machine lands on the skeleton's
seam digests (pre-draw, post-prologue) exactly. Tamper tests: a flipped
head felt and a lookup re-supply at different chunk boundaries are both
rejected. Binding per section class:

- **head** (small claim with a 6-entry program prefix + pow + interaction
  claim + config + commitments + queries-PoW nonce + salt, ~600 felts):
  `d_head` saved at begin, checked on every re-supply.
- **program entries**: transcript-bound via the claim-mix pipeline +
  rolling chunk digest for the lookup phase's second pass (boundary-exact).
- **sampled values**: `d_sampled` saved at the OODS tx (also
  transcript-bound by `mix_sampled_values`).
- **rows/witnesses**: self-authenticating (Merkle-verified on arrival).
- **fri section**: lane-1 query-equality — finalize re-runs the FRI
  commitment transcript from the checkpointed digest and requires the
  re-derived query positions to equal the checkpointed ones.
- **fact material**: `program_hash` rides the checkpoint as a resumable
  sponge over `construct_f252(value)` per entry (≡ the vendored
  `hash_memory_section`), so the finalize tx never needs the program.

Notes: the lookup phase re-transports the program (~3.4k packed felts —
the transcript needs it twice: claim mix before the element draw, logup
after); group txs currently recompute quotient constants statelessly (the
one-time packed store is a contract-level optimization, see the settled
dilemma above); a chunk/group can be any size, so bigger programs or
different query counts only change N and G.

## Class splitting

Measured (2026-07-03, machine-phase library classes, audited allowlist
**passing**, `lib.cairo` wrappers):

| Class | Entrypoints | Sierra felts | vs 81,920 cap |
|---|---|---|---|
| `StwoMachineClaim` | begin, claim_chunk, claim_finalize | **29,251** | **fits (36%)** |
| `StwoMachineLookup` | lookup_chunk, lookup_finalize | **20,731** | **fits (25%)** |
| `StwoMachineOods` | oods_mix | **762,148** | **9.3× over** |
| `StwoMachineGroup` | group (Merkle + fri_answers) | **27,335** | **fits (33%)** |
| `StwoMachineFri` | fri_commit, finalize | **28,386** | **fits (35%)** |

(Historical: the pre-machine skeleton measured `StwoFullPhaseA` 31,075 /
`StwoFullPhaseB` 778,271.) **The entire class-size problem has collapsed
to one function**: `eval_composition_polynomial_at_point`'s component zoo
inside the OODS transaction. Everything else deploys as-is (4 classes at
25–36% of the cap; CASM expected 1.6–2× Sierra — verify at declare).
The remaining work is splitting the air eval by component group
(chunk-fed accumulator over component ranges, same pattern as claim/logup
— but it forks generated component code, so it wants a build-time slicer
over the vendored source). Expect ~10–14 component-group classes.

### The OODS split (built 2026-07-03, `src/oods_chunks.cairo`)

`machine_oods_mix` is now split as `oods_begin → oods_group × N →
oods_finalize` over a **40-family sequence** (the 13 top-level eval call
sites, with the three oversized composites — opcodes, blake context,
poseidon context — split one level deeper into their sub-airs, which are
themselves flat `try_new → evaluate` sequences). Mechanics:

- Each group transaction re-supplies head + sampled (digest-bound),
  fast-forwards the three sequentially-consumed streams — trace masks,
  interaction masks, AND the interaction claim's `claimed_sums` (family
  *construction* consumes them in the same order) — to the checkpointed
  offsets, rebuilds only its families' components from the claim + the
  re-drawn lookup elements, evaluates into the `sum` accumulator, and
  checkpoints `(sum, families_done, trace/interaction/sums counters,
  pp_used_mask)`.
- `validate_mask_usage` splits as: counters must equal the totals at
  finalize, and each transaction ORs its preprocessed-column usage bits
  into a u128 checkpoint mask (column count asserted ≤ 128; fixture has
  105) that finalize compares against the columns carrying samples —
  preserving the anti-junk-quotient check across transactions.
- Family order is enforced (`families_done == first_family` per group,
  all 40 at finalize), so the concatenated consumption is exactly the
  monolithic sequence. The blake/poseidon all-or-nothing gates and their
  `is_none` asserts live in each context's first sub-family.
- `oods_finalize` checks completeness, asserts the OODS equation over the
  accumulated sum, runs `mix_sampled_values`, and emits the SAME
  `FriCommitPhaseState` the monolithic `machine_oods_mix` produces — the
  rest of the machine is untouched.

`tests/test_oods_chunks.cairo`: chunked (begin + 16 grouped txs +
finalize, serde round-trips between all) == `machine_oods_mix` on every
output field including the transcript seam digest; family-skip rejected.

**Class sizes v2** (all 40 families wrapped in 20 measurement classes,
audited allowlist passing):

| Class(es) | Sierra felts | vs 81,920 cap |
|---|---|---|
| OodsBegin / OodsFinalize | 11,821 / 21,412 | fit |
| 16 group classes (36 families: all opcodes except blake_compress, verify_instruction, blake_g/sigma/xor12/triple_xor, builtins, poseidon 3_partial+full_round+round_keys+rc_252_w27, memory, range_checks, xor4–9) | 14,294 – 69,078 | **all fit** |
| `blake_compress_opcode` (alone) | 92,377 | 1.13× over |
| `blake_round` (alone) | 93,875 | 1.15× over |
| `cube_252` (alone) | 133,115 | 1.62× over |
| `poseidon_aggregator` (alone) | 133,888 | 1.63× over |

**The last blocker is exactly four generated single-component evals.**
Each is a ~2,600–3,000-line generated `evaluate_constraints_at_point`
(~50 `constraint_quotient` statements + logup), and every
privacy-bootloader proof enables all four (the bootloader uses blake;
the payload uses the poseidon builtin). Paths, in preference order:
1. **qm31 opcode in `audited.json`** (existing watch item): these felts
   are dominated by the bounded_int QM31-arithmetic lowering; the
   `qm31_opcode` cfg variants already exist upstream and would shrink all
   four dramatically (likely under the cap) with zero fork.
2. ~~**Two-half fork along the generated seam.**~~ **Built and proven
   equivalent (2026-07-04) — see "The two-half seam fork" below.**
3. The four families cannot be skipped for bootloader-shaped proofs, so
   there is no configuration dodge.

### The multi-part seam fork (built 2026-07-04, `src/split/`) — SOLVED

`scripts/split_component_evals.py` forks each oversized component file
along its generated seam: `evaluate_constraints_at_point` factors as
intermediates + constraint quotients over the TRACE masks followed by a
single call to a file-private `lookup_constraints(ref sum, random_coeff,
claimed_sum, numerator_0.., column_size, ref interaction_masks,
<combined lookup sums>..)` (logup over the INTERACTION masks). Every
part is its own family in `oods_chunks.cairo` (N_FAMILIES 40 → 49,
ordered by the existing family-order counter), and the seam values ride
the `OodsEvalState` checkpoint as a `carry` array (production stores
`poseidon(state)`, so the cost is calldata-only). Construction (one
claimed sum) happens in the component's first part; later parts rebuild
the Component from the carried claimed_sum via `NewComponentImpl::new`.
The trace counter advances in the LAST A part, the interaction counter
in the B part(s).

Sizing findings that shaped the cuts (scarb 2.18.0):
- **Two caps bind at declare**: 81,920 Sierra felts AND 4,089,446 bytes
  of contract-class JSON (without debug info). The byte cap binds first,
  at ~66k felts for this code shape — it was not checked in the v2
  numbers, and it also caught the pre-existing mul+mul_small group
  (69,270 felts / 4.295M bytes → regrouped as two classes).
- **Carrying a value across a transaction costs ~90 Sierra felts**
  (append + pop with panic paths), so naive statement cuts that carry
  hundreds of crossing column values ADD more code than they remove
  (blake_round's first 2-part attempt: 67.6k → 40.3k + 89.5k).
- **The trace-mask unpack is nearly free; re-reading beats carrying.**
  Every A part re-reads the trace destructure itself (the sampled
  values are digest-bound and re-supplied to every transaction) and
  unboxes only the columns its own statements use; earlier parts read a
  COPY of the trace span (their wrappers do not advance the counter),
  only the last A part pops for real. The inter-part carry collapses to
  claimed_sum + the relation accumulators + a handful of tmp
  intermediates (57–119 QM31s = 228–476 felts).
- **The heavy statements are the inlined subroutine calls and the wide
  `combine_qm31` combines** (~5–6k felts each for blake_round's
  blake_g/blake_round combines; the 869-line hades permutation ≈ 47k),
  so cuts isolate those: blake_round = reads | blake_g combines |
  blake_round combines | logup; poseidon_aggregator = reads | hades |
  felt_252_unpacks + combines | logup; cube_252's heavy half is the
  99-relation LOGUP, cut at constraint boundary 23 (telescoping
  structure: the extra carry is just the boundary column quad).

**Class sizes v4 — every class fits both caps:**

| Component (was) | Parts | Sierra felts |
|---|---|---|
| blake_compress (92k) | A \| B | 52,000 / 58,749 |
| blake_round (94k) | A1 \| A2 \| A3 \| B | 26,871 / 43,143 / 27,806 / 43,520 |
| cube_252 (133k) | A \| B1 \| B2 | 61,908 / 62,907 / 46,470 |
| poseidon_aggregator (134k) | A1 \| A2 \| A3 \| B | 23,909 / 61,095 / 24,242 / 20,187 |
| mul group (regrouped) | mul \| mul_small | 63,647 / 18,477 |

All 30 group classes + OodsBegin (11,880) + OodsFinalize (21,598) +
StwoMachineClaim/Lookup/Group/Fri (29,251 / 20,731 / 27,335 / 28,386):
**36 of 36 deployable classes under both Sierra caps**.
`tests/test_oods_chunks.cairo`: 49-family chunked ==
`machine_oods_mix` on the real proof with a serde round-trip between
every pair of transactions (carry included), and a tampered carry felt
between parts is rejected at the OODS equation ("Invalid OODS eval").

### Declare pre-flight: the third cap (devnet, 2026-07-05)

There is a THIRD declare cap the scarb warnings don't check: the
compiled CASM bytecode size (81,920 felts; measured with
`universal-sierra-compiler` and confirmed by starknet-devnet 0.9.0
declares — a 75,206-CASM class declares, 172k+ is rejected with
"Contract class size is too large"). Findings:

- The CASM/Sierra felt ratio is **not uniform: 0.68–2.90 by instruction
  mix.** Logup/combine-heavy code COMPRESSES (blake_round B 0.68×);
  252-bit-multiplication code EXPLODES (~2.8×) — the mul_252 /
  verify_mul_252 / karatsuba subroutine family.
- Those subroutines compile as **shared Sierra functions** (one copy per
  class, confirmed via `sierra_program_debug_info.user_func_names`), so
  seam-fork statement cuts cannot shrink a class below the size of the
  biggest subroutine it calls — every part calling `mul_252_evaluate`
  carries all of it.
- **Devnet declares: 35 of 37 classes declared successfully** (the 34
  machine/OODS/router classes plus F18 and F05B), including the router
  and every phase of the fixture flow EXCEPT two: `StwoOodsF05A`
  (mul_opcode, 63,647 Sierra / 172,130 CASM) and `StwoOodsF16A`
  (cube_252 half A, 61,908 Sierra / 179,655 CASM) — both dominated by
  the shared 252-bit-mul subroutines.

The two blocked classes are exactly the shape the **qm31 opcode**
watch item fixes (the bounded_int lowering of QM31 multiplication is
what makes those subroutines huge); the alternative — forking the
subroutine INTERNALS with carry-connected halves — is deliberately not
pursued (deep surgery, shared across components, superseded the day the
opcode lands in `audited.json`). Until then the fixture flow cannot run
end-to-end on a public network; everything else (49-family OODS,
router, transport) is declare-ready.

### The qm31 gate, measured (2026-07-05)

The opcode's status was tested empirically at every layer
(`tools/qm31-gate-probe/`, a minimal qm31-arithmetic contract):

- The Cairo VM / S-two AIR support the opcode (extension 3,
  `QM31Operation`) and scarb 2.18's corelib ships `core::qm31` — the
  PROVING stack is ready.
- **starknet-devnet 0.9.0 declares, deploys and executes it** (100
  rounds of qm31 mul/add/sub verified), and Sepolia RPC nodes
  fee-estimate the declare successfully — neither is a valid
  deployability oracle.
- **The Sepolia gateway (Starknet 0.14.3) rejects the real declare:**
  `Contract failed to compile in starknet`. The enforcement point is
  the gateway's declare-time class compilation, which is what
  `audited.json` mirrors. The rejection costs nothing; the probe README
  has the 30-second re-test.

**The post-opcode shape is also measured**: the monolithic vendored
verifier built with `feature = qm31_opcode` is 2,996,065 Sierra felts /
**405,569 CASM felts** — still ~5× the CASM cap, so the machine/OODS
splitting and the router survive the pivot; but total CASM drops ~5×
vs the poseidon build (≈1.9M across today's 37 classes), the
mul_252/karatsuba blowup that blocks mul_opcode and cube_252-half-A
disappears, the 34.2M-step budget should collapse comparably (re-probe
on pivot), and the client reverts from the poseidon-Merkle prover
(257 s / 11.3 GB) to the fast blake2s path. Pivot work when the gate
opens: port the checkpoint channel poseidon → blake2s (lane 1 has the
pattern), re-prove fixtures with blake params, re-run the generator +
measurement pyramid.

With merging of small neighbours the eventual OODS phase is ~10–12
group txs; today's fine-grained shape is 32 (begin + 30 groups +
finalize).

### The qm31 pivot, measured end-to-end (2026-07-05)

All of the pivot's prep is local (snforge executes qm31 libfuncs —
proven by `tools/qm31-gate-probe`'s own test suite — so only the public
declare is gateway-gated). Measured this session:

- **Blake proof fixture**: `prove-blake` in the bridge (mirrors
  prove-poseidon; cairo-serde + `--extended`). Two configuration traps,
  both found empirically: the vendored default build expects the PLAIN
  `blake2s` channel — `blake2s_m31`'s per-hash M31 output reduction is
  for the recursion circuits and fails the interaction PoW — and it pins
  the `canonical` (WITH-pedersen) preprocessed root, not
  `canonical_without_pedersen`. Params otherwise identical to poseidon
  (70 queries, blowup 1, fold_step 1): `fixtures/prover_params_blake.json`.
- **Client proving collapses ~45×: 6 s wall / 14.1 GB peak** (vs 257 s /
  11.3 GB poseidon). Same output preimage — same statement, new channel.
  Peak memory RISES slightly (the canonical trace carries the pedersen
  columns); proof = **376,275 cairo-serde felts** (vs 301,143) but
  blake hashes are 8×u32 words that pack ~7:1 in packed-v2, where
  poseidon hashes were unpackable full felts.
- **Verification: 26,603,848 steps** (2.19M range_check, 16 bitwise) —
  the full vendored verifier, qm31_opcode build, over the real blake
  proof (`tools/lane2-probe --features qm31_opcode,blake_outputs_packing`;
  note the vendored `features_check` REQUIRES qm31_opcode outside the
  poseidon build, so there is no non-opcode blake baseline). Down 22%
  from poseidon's 34.2M — NOT the hoped collapse. Where it went, per
  stage (Δ steps, poseidon → blake+qm31):

  | Block | poseidon | blake+qm31 |
  |---|---|---|
  | 0 serde deserialization | 4.96M | 5.88M (bigger stream) |
  | 1 verify_claim | 0.01M | 0.01M |
  | 2 FS prologue + lookup_sum | 10.26M | 7.26M |
  | 3 composition/OODS eval | 1.72M | **0.15M** (pure QM31 → opcode) |
  | 4 mix + FRI commit | 0.25M | 0.30M |
  | 5 Merkle decommits | 1.62M | 1.04M |
  | 6 fri_answers | 12.75M | 9.93M |
  | 7 FRI folding walk | 2.56M | 2.03M |
  | **total** | **34.1M** | **26.6M** |

  The opcode annihilates the arithmetic-dominated stage (OODS eval,
  11×) — and QM31 div/inverse IS opcode-backed — but fri_answers and
  the prologue are bookkeeping-dominated (span walks, M31 reads,
  per-query position handling), and deserialization grew with the
  stream. **Compute budget ≈ 8–9 pure invokes** at 375 gas/step ≈
  10.0e9 gas (vs 11 poseidon) — the tx-count win must come from the
  OODS phase merging (the component evals shrink ~5× in CASM) and
  cheaper transport, not from raw steps.

## The router (built 2026-07-05, `src/router.cairo`)

`StwoVerifierRouter` (6,103 Sierra felts) is the production contract that
drives the machine across transactions. The 36 machine classes stay
stateless library classes; the router owns the only storage — one
checkpoint slot per (caller, proof_id) holding `(tag, poseidon(state))`
(~2 storage felts per in-flight proof, total). Every transaction:

1. the caller echoes the previous serialized state as calldata;
2. the router checks `poseidon(state)` against the slot AND that the
   slot's tag matches the state type the entrypoint consumes
   (`CLAIM/LOOKUP/OODS/OODS_EVAL/FRI_COMMIT/GROUP` — one tag per machine
   state struct, preventing cross-phase type confusion);
3. it library-calls the fixed class for that step (constructor-pinned
   class hashes; `oods_group(i)` selects among the 30 group classes, the
   in-state family counter enforces their order);
4. it stores the new tagged hash, emits `Step`, and returns the new
   state for the next echo.

Write-once sequencing falls out of the tag chain: `begin` requires an
empty slot ('router: proof id in use'), and every step overwrites the
slot, so a phase can never re-run against a stale state. Big sections
arrive packed (v2; `unpack_proof_v2` in the router; `src/pack.cairo` is
the in-Cairo packer used by tests). `finalize` stores
`poseidon(program_hash, output_hash)` in a local fact map — a
placeholder for the shared `StwoFactRegistry` route.

`tests/test_router.cairo`: the REAL fixture proof driven through the
deployed router end-to-end — **52 transactions** (begin + 5 claim chunks
+ claim finalize + 5 lookup chunks + lookup finalize + oods begin + 30
OODS groups + oods finalize + fri commit + 5 fused group txs + finalize),
all sections packed-v2, ~24.3e9 total L2 gas ≈ **~470M gas/tx average**
(well under the 1.21e9 per-invoke cap; the devnet pre-flight measures
the real per-tx spread). The registered fact's hashes equal the vendored
`encode_and_hash_memory_section` of the claim's program/output sections.
Rejections: proof-id reuse, wrong-tag state, tampered state echo — all
against one deployment, honest step still lands afterwards.

## The calldata emitter (built 2026-07-05, bridge `emit-calldata`)

`privacy_prove_cairo_bridge emit-calldata <extended_proof.json> <dir>`
emits the router's per-transaction transport, all packed v2: `head.txt`
(head surgery in Rust: the claim with its program truncated to the
6-entry prefix + pow + interaction claim + config + commitments +
queries-PoW nonce + salt), `chunk_NN.txt` (serde `MemorySection` slices,
replayed by both the claim and lookup phases), `sampled.txt`, `fri.txt`,
`group_NN_{rows,witnesses}.txt` (router serde shapes, witnesses
synthesized from the aux as in split-witness) and a `manifest.json` with
every router argument's unpacked `n_values`. Self-checks on every run:
the per-section Rust serializations must concatenate to exactly the
proof's full cairo-serde stream, the chunk streams must reproduce the
claim's program section, and the full-set synthesized witnesses must
equal the proof's own. Cross-validated in snforge
(`tests/test_emitter_calldata.cairo`): unpacking every emitted fixture
file reproduces byte-for-byte the sections the Cairo side carves from
the committed proof fixture.

**Measured per-tx calldata (packed slots, fixture)** against the ~4,996
usable felt cap: head 69, program chunks ≤781, sampled 2,609 — the
claim/lookup/OODS transactions all fit comfortably (worst OODS group tx:
head + sampled + state echo + carry ≈ 3.6k). Two transport items exceed
the cap, both already scoped in "Machine plan v2":

- **fri section: 8,873 slots** (10,413 felts, mostly unpackable poseidon
  hashes) — consumed whole by fri_commit AND finalize; needs lane-1
  style write-once storage staging (~3 staging txs under the 4,000-entry
  state-diff cap) before those phases.
- **group rows at 16 queries/tx: 7,983 slots** — needs the settled
  one-time packed constants store (drops the 2.6k sampled re-supply from
  group txs → 8–9 queries/tx) or group size ~4 with stateless recompute.

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
