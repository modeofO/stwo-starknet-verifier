# Spike 3 results — recursion route end-to-end (2026-07-02)

**Question:** can an arbitrary Cairo program's execution be proven with Stwo
and verified by the *deployable* circuit-verifier contract — i.e. does the
recursion route work outside StarkWare's own fixtures?

**Answer: yes — demonstrated end-to-end on our own program.** A scarb-built
Cairo 1 executable (`fixtures/poseidon_chain`, n=100) went through the full
chain and its proof was **accepted by the vendored on-chain Cairo circuit
verifier in 3,814,641 steps (~38% of one transaction's L2 gas)**, with the
verified statement binding the program hash and the exact program output
(`poseidon_chain(100) = 0x10bd76b…721`, matching a direct `scarb execute`).

## The pipeline (all public code)

```
scarb-built executable (.executable.json) + args
  │  Task::Cairo1Program                        [proving-utils]
  ▼
privacy simple bootloader run  →  ProverInput + output preimage
  │  prove_cairo::<Blake2sM31MerkleChannel>     [stwo-cairo]
  ▼
CairoProof of the bootloader execution          (~40s wall for our fixture)
  │  build_fixed_cairo_circuit + prove_circuit_assignment   [stwo-circuits]
  ▼
cairo-verifier circuit proof                    (proof of "I verified that CairoProof")
  │  build_multiverifier_circuit (two inputs) + prove with Blake2sMerkleChannel
  ▼
multiverifier circuit proof
  │  prepare_circuit_proof_for_cairo_verifier   [stwo-circuits circuit_cairo_serialize]
  ▼
felt252 JSON (36,022 felts ≈ 8 calldata-staging txs)
  │  scarb execute -p stwo_circuit_verifier     [our vendored verifier = the contract]
  ▼
ACCEPTED — 3.81M steps, VerificationOutput = blake2s(mv_root ‖ outputs)
```

Repos: [proving-utils](https://github.com/starkware-libs/proving-utils) @ `b6fe5d3b`
(bootloader hints, prover glue) and its pins: stwo-cairo @ `68b4af6d`,
stwo-circuits @ `0451681a`, stwo @ `5ea05973`. The on-chain verifier is our
Spike-1 vendored `stwo_circuit_verifier` (stwo-cairo @ `92bfd1d3`) — its
hardcoded multiverifier topology (preprocessed root `[4268871180, …]`,
PCS pow 27 / blowup 3 / 23 queries / fold 4 / lifting 24, N_OUTPUTS 8)
**matches stwo-circuits across these revs**, verified empirically both with
their fixture and with our self-generated proofs.

## What we built (`tools/`, `scripts/`)

- `tools/privacy-prove-cairo-bridge/` — a ~230-line Rust bin added to the
  proving-utils workspace that drives the whole chain and emits the
  felt252 stream the Cairo verifier consumes. Key departures from
  StarkWare's in-repo flows, all discovered the hard way:
  1. **Circuit config must embed the bootloader actually proven.**
     stwo-circuits' test config embeds *its* test-data bootloader; proving-utils
     ships a different build of it. Mismatch ⇒ garbage witness ⇒ opaque
     panics deep in xor-lookup generation.
  2. **Per-proof component set.** The canonical privacy config fixes the
     component set of StarkWare's privacy transaction (includes pedersen).
     Arbitrary payloads enable different sets, so the bridge rebuilds
     `enabled_bits` + `ProofConfig` from the proof's own `FlatClaim`. The
     inner circuit's root changes per component set — sound, because it
     enters the multiverifier as a *free input* that the final statement
     binds (consumers must whitelist expected inner roots).
  3. **Multiverifier-compatible padding**: `pad_to_targets` (eq 2^17,
     qm31_ops 2^21, m31_to_u32 2^18, triple_xor 2^17, blake_g 2^20) on both
     the assignment and NoValue contexts, instead of the single-recursion
     flow's zk-blinding path. (Consequence: **no zk blinding in this spike**
     — witness privacy of the recursion layer is future work.)
  4. **The outer multiverifier proof uses the lossless `Blake2sMerkleChannel`**
     (what the Cairo verifier implements), while inner layers use `Blake2sM31`.
- `tools/proving-utils-bridge.patch` — 116-line patch to proving-utils
  (exposes `run_privacy_bootloader_task`, adds the bridge to the workspace).
- `scripts/setup-prover.sh` — one-time: clone proving-utils @ pin, apply
  patch, install bridge crate, build.
- `scripts/prove-and-verify.sh <executable.json|pie.zip> [args.json]` — the
  whole pipeline in one command, ending in the Cairo verifier run.

## How applications plug in

The bootloader accepts **`Task::Cairo1Program`: a scarb `.executable.json`
plus serialized args** — no Cairo PIE needed. (PIEs from
`scarb execute --output cairo-pie` are *rejected* by the bootloader's
relocation hint — Cairo1 PIEs don't meet its Cairo0 layout expectations,
even with merged segments. The executable path sidesteps this entirely.)

The final on-chain `VerificationOutput.output_hash` =
`blake2s(multiverifier_root ‖ outputs)` where outputs =
`blake2s(inner_root₀ ‖ inner_outputs₀ ‖ inner_root₁ ‖ inner_outputs₁)` and each
inner output is `blake2s(program_hash_of_bootloader ‖ … ‖ blake2s(output_preimage))`
with `output_preimage = [n_tasks, output_len, task_program_hash, task_output…]`.
For our fixture the preimage was
`[0x1, 0x3, 0x30443b…1f3 (poseidon_chain program hash), 0x10bd76…721 (the chain result)]`.
A consumer contract verifies the proof, then checks the recomputed hash chain
against the expected program hash + claimed outputs. (The multiverifier takes
*two* inputs; for a single payload the same inner proof is passed twice —
aggregating two real payloads per proof halves the per-app cost.)

## Measurements (all on the deployable verifier)

| Proof | Felts | Verifier steps | range_check |
|---|---|---|---|
| stwo-circuits' own multiverifier fixture | 35,522 | 3,785,065 | 506,230 |
| Self-generated, StarkWare sample privacy-tx PIE | 35,542 | 3,768,061 | 503,394 |
| **Self-generated, our `poseidon_chain(100)` executable** | **36,022** | **3,814,641** | 510,587 |

≈ 4.2e8 L2 gas including builtins — **~38% of the 1.1e9 per-tx cap**, single
transaction, every time (the circuit is fixed-topology, so verification cost
is essentially constant regardless of payload size).

Off-chain proving cost for our small fixture on an M-series laptop: roughly
2–3 minutes wall for the whole chain (dominated by the bootloader Cairo
proof and the two circuit proofs; StarkWare's blog numbers suggest seconds
on server hardware).

## Caveats / open items

- **Version coupling.** The on-chain verifier's hardcoded topology must match
  the stwo-circuits rev that produced the proof. It matched across
  92bfd1d3 ↔ 0451681a ↔ main today, but upstream comments
  (`TODO(Gali): Change to MultiVerifier consts`) say this is actively moving.
  Pin everything (we did) and re-validate on upgrade.
- **No zk blinding** in the multiverifier-compatible path we used (the
  single-recursion privacy flow has it; the multiverifier test flow doesn't).
  Matters for witness-privacy applications (messagezk) — investigate
  `add_zk_blinding` + multiverifier compatibility.
- The statement binds the *bootloader's* program hash chain; consumer
  contracts must implement the blake2s output-preimage recomputation
  (blake2s is cheap on Starknet — audited libfuncs).
- Sepolia `declare` + real gas measurement still pending (Spike 1's open
  question about the 81,920-felt cap applying to CASM: our class is 78,185
  CASM felts — 4.6% headroom).

## Verdict

The recursion route is **real, public, and works for arbitrary programs
today**. What remains is productization, not research: a FactRegistry
contract around the verifier, proof staging (8 txs of calldata), a devnet
declare/deploy, and the zk-blinding + consumer-side hash-chain story.
