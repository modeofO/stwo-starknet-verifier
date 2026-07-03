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

---

# Lane 1 SHIPPED: first Stwo fact registered on a public Starknet network (2026-07-03)

The 1.21e9 per-invoke cap forced a redesign, and the result is live on
Sepolia:

## Final architecture (3 classes, 3 transactions per fact)

| Class | Sierra | CASM | Sepolia class hash |
|---|---|---|---|
| `StwoPhase1` (library) | 46,805 | 73,546 | `0x511ab692d6e4291e47407580642d25263151c216381ba36814f6f90914f3843` |
| `StwoPhase2` (library) | 11,677 | 22,500 | `0x541b2817d6e6a5732afb75adcfb99ce50eb7a4af79809c97b63e59992009442` |
| `StwoFactRegistry` | 1,707 | 4,139 | `0x7308e2210332bab2c98aa58600dd7fae574084edce2d0098bad6d7e13e77a38` |

Registry instance: `0x0194f44002b4af71e58ba7d30667ed565f1d420d3fb1e7c578de35170309c6aa`
(phase class hashes pinned immutably in the constructor).

Verification is split at the FRI boundary (`stwo_verifier_phases::resumable`,
soundness notes in the module doc): phase 1 = prologue + OODS + tree Merkle
decommitments + FRI first-layer answers, checkpointing the Fiat-Shamir digest
(at an `n_draws == 0` site), PoW nonce, query positions, answers, and fact
material (~130 felts of storage); phase 2 = FRI commitment replay over a
calldata-supplied FriProof — bound to phase 1 by query-position equality —
plus decommitment and fact registration.

## The registered fact (poseidon_chain(100), recursion route)

- stage tx: `0x0131383f667dfbf91afbdd60daef3902026205fa693ba9a203ca0ba8aa5fd437` (156 slots)
- phase 1: [`0x0681808c…79a0`](https://sepolia.voyager.online/tx/0x0681808ccfaa92f35dfe9ddb44474bf718c07ef0dd40f6f0517e3d22aa3a79a0) — **873,757,120 L2 gas (72% of cap)**
- phase 2: [`0x06b7f69f…8730`](https://sepolia.voyager.online/tx/0x06b7f69fcc931cf1e93cbae5a14e254de539e6f91609fceed60b3f93b8188730) — **815,669,840 L2 gas (67% of cap)**
- fact: `0x640299e88691d8a8eaf2c71bcde2c72334ad177e64c4485be069c5f6dcd615c`
  — `is_valid(fact) == true`, queryable by anyone.

Devnet receipts predicted both figures to the digit — starknet-devnet 0.9 is
a faithful pre-flight for this workload.

## Operational lessons (hard-won, for the runbook)

- **CASM bytecode is capped at 81,920 felts on declare** — combining both
  phases + registry in one class hits it; the library-class split is
  mandatory. (Settles Spike 1's cap question: it binds BOTH Sierra and CASM.)
- sncast's automatic fee estimation multiplies by 1.5, which pushes
  legitimately-large transactions over the per-invoke bound check; explicit
  `--l2-gas`/`--l1-data-gas` (+prices) bounds are required. Under-provisioned
  `l1-data-gas` REVERTS (fees burned) rather than rejecting.
- The account `__execute__` envelope costs ~4 calldata felts: the phase-1
  head is 4,991 slots, not 4,995.
- Total cost of the registered fact at (spiky) Sepolia gas prices: ~49 STRK
  across the two verify transactions; declares were ~180 STRK one-time.
