# Lane 1 results — StwoFactRegistry (2026-07-02)

**Deliverable:** a deployable FactRegistry contract that verifies Stwo
multiverifier proofs (the recursion route) and registers facts for consumer
contracts — tested end-to-end against the real `poseidon_chain(100)` proof
from Spike 3. **Total cost per fact: 3 transactions**, all within limits.

## Contract

`contracts/stwo_fact_registry` — embeds the Stwo circuit verifier (blake2s
configuration, audited libfuncs only), 49,740 Sierra felts (cap 81,920).

- `stage_proof(proof_id, offset, slots)` — chunked upload of the *packed*
  proof; slots keyed by caller so uploads can't be griefed.
- `verify_and_register(proof_id, n_slots, n_values) -> fact` — unpack,
  deserialize, verify, register `fact = poseidon(output_hash words)`.
- `is_valid(fact) -> bool` — the consumer's one-line integration.

## The packing insight (what made it fit)

Storage syscalls dominate: naively staging 36,022 proof felts word-per-slot
cost ~2.4e9 gas to write and ~1.4e9 to read back — the verify transaction was
**25% over** the 1.1e9 per-tx cap even though verification itself is only
~4e8. Since proof streams are almost entirely u32-valued (36,020 of 36,022
felts in our fixture), the registry stores **7 little-endian u32 limbs per
storage slot** with an escape encoding for u64 values (`0xFFFFFFFF`, then
low/high limbs). 36,022 felts → 5,147 slots.

Second trap: the first unpack implementation used u256 div-rem per limb —
**6.7e8 gas just to unpack**, dwarfing verification. Rewriting it as u128
div-rem over the slot's two halves (with a hoisted `NonZero` constant) cut
unpacking to 1.8e8.

## Measured costs (snforge, real proof, `--detailed-resources`)

| Piece | Sierra gas | Note |
|---|---|---|
| Staging (2 txs, 5,147 slots total) | 3.4e8 (~1.7e8/tx) | was 10 txs / 2.4e9 unpacked |
| unpack (in verify tx) | 1.8e8 | was 6.7e8 with u256 div-rem |
| deserialize + verify + fact | ~5.2e8 | the actual STARK verification |
| storage reads (5,149) + call overhead | ~1.8e8 | |
| **verify_and_register tx total** | **≈ 8.9e8** | **~81% of the 1.1e9 cap ✓** |
| **Per fact (3 txs)** | **≈ 1.23e9** | plus L1 data gas for calldata |

Tests (`contracts/stwo_fact_registry/tests/`): the real 36,022-felt proof
stages → verifies → registers, `is_valid` answers correctly, a corrupted
proof panics, plus the staging-only / unpack-only / bare-verification cost
probes. Test fixture regenerable with `scripts/prove-and-verify.sh` +
`scripts/pack_proof.py`.

## Remaining before mainnet-grade

- Sepolia declare/deploy (`scripts/declare-sepolia.sh`) — also settles the
  Sierra-vs-CASM bytecode-cap question empirically.
- Consumer-side helper for the blake2s output-preimage recomputation
  (binding fact → application program hash + outputs).
- Storage-slot reuse/cleanup policy for staged proofs (currently staged data
  persists; rewriting the same proof_id overwrites).
- The verifier-route allowlist + ownership freeze in the registry (currently
  the registry *is* the single verifier; when lane 2 lands it must write to
  the same registry under a governed route list).
- Headroom watch: 19% under the cap on this fixture; proofs of bigger
  payloads are the same size (fixed circuit topology), so this should hold,
  but re-measure after any upstream topology change.

---

# Sepolia campaign addendum (2026-07-02, same day)

**Declared and deployed on Starknet Sepolia** — to our knowledge the first
Stwo verifier ever declared on a public Starknet network:

- Class [`0x049cb29…9629`](https://sepolia.voyager.online/class/0x049cb29261b5ba43e4a9446f9950bd1b6b33d6cee9c607d61021da8441f39629)
  (declare fee: **151.05 STRK / 5.33e9 L2 gas** — declares are exempt from
  the invoke gas cap; this also settles Spike 1's CASM-cap question).
- Instance at `0x05878fb0708fe63863f2d66bc8a79357b867cef8e00079cee83894f47408023c`;
  all 6 staging transactions of the real proof landed on Sepolia.

**But the verify transaction is blocked — production reality vs snforge:**

| | snforge estimate | devnet/Sepolia actual |
|---|---|---|
| verify (all-storage) | 8.9e8 | **1.429e9** |
| verify (head-in-calldata, 152-slot tail) | — | **1.423e9** |
| Starknet invoke L2-gas cap (empirical, from sequencer rejection) | — | **1.21e9** |

Key learnings:

1. **The per-invoke cap is 1.21e9 L2 gas** (the sequencer rejects higher
   bounds outright: "maximum allowed gas amount: 1210000000"). Declares are
   not subject to it.
2. **snforge's gas constants understate production by ~1.6×** for this
   workload. Devnet (starknet-devnet 0.9) matches Sepolia's estimates
   exactly; use devnet for go/no-go gas decisions.
3. **Storage reads were never the bottleneck** — moving 4,995 of 5,147
   packed slots into calldata saved only 0.5%. The verification *compute*
   is ~1.4e9 by itself.
4. Other levers measured/checked and exhausted: release-profile build
   (byte-identical Sierra), qm31 libfuncs in `audited.json` (still absent —
   0 entries as of today), devnet block state-diff cap (4,000 entries)
   limits staging chunks to <2,000 slots/tx.

**Conclusion: single-transaction verification is ~18% over today's invoke
cap.** The path forward is splitting verification across two transactions
with a small checkpoint (channel state + derived randomness, ~tens of felts)
persisted between them — i.e. pulling lane 2's resumable-verifier machinery
forward, at 2-tx granularity. Natural split point: constraint/OODS phase in
tx1, FRI decommitment phase in tx2; both re-read the staged proof, only the
Fiat-Shamir state crosses. Alternatively, the moment qm31 libfuncs enter
`audited.json`, the emulation overhead collapses and single-tx verification
almost certainly fits.
