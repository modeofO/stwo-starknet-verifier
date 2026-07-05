# zkmsg milestone-1 addendum — the messagezk circuit through lane 1 (2026-07-05)

The gate from the plan (task 4): the ported circuit
(`fixtures/messagezk_scan`, ec_op + poseidon) proven under the privacy
bootloader and wrapped proof-only, accepted by the deployable circuit
verifier. ALL GREEN — measured on the dev machine (M-series, same box as
all repo numbers):

| leg | wall | peak RSS | notes |
|---|---|---|---|
| `prove` (bootloader + Blake2sM31) | ~30 s | 7.03 GB | witness: 2-user tree, keys 5/7, eph 6 |
| `wrap` (circuit + multiverifier) | 10.0 s | 24.6 GB | proof-only; prints the inner root |
| circuit-verifier `scarb execute` | ~1 min | — | accepts; prints the output-hash words |

Pinned production constants (v3 store constructor + zkmsg config):

- `PROGRAM_HASH = 0x250cb04a129e5259221ad4635950ac983bccf1de574893a2fae75c3c64385c`
  (the bootloader output preimage's third felt for messagezk_scan)
- `INNER_ROOT = [2674953418, 3988685724, 1385424428, 1661362028, 3534442848, 356489633, 2101289576, 2757001180]`
  (wrap's "inner circuit root (consumers whitelist this)" — QM31 words
  decoded lo16 + hi16·2^16)
- Wrapped proof: **35,154 felts** (poseidon_chain fixture: 36,022 — the
  fixed multiverifier shape holds; on-chain cost is flat in circuit size).

Gate-run public tuple (synthetic 2-user tree; scan privs 5 and 7,
ephemeral 6 — matches the starknet.js-computed expectation EXACTLY,
sealing Rust/JS/Cairo crypto equivalence end-to-end):

- commitment `0x24768d5e47fb400baf0a349b5b6b8213ab2bc6d21e142ba9245f4c6a5ac9f9d`
- ephemeral_pubkey `0x1efc3d7c9649900fcbd03f578a8248d095bc4b6a13b3c25f9886ef971ff96fa`
- merkle_root `0x225510ca702ebc9c1dad406f8cd08923fd3f8aea5a0ed58eb753265421522cd`
- verifier output-hash words (fact = poseidon over them):
  `[3110578688, 528312754, 1818420841, 1584490969, 406408838, 3678385441, 1556530268, 4142792485]`
  — the store test suite asserts `compute_fact(PROGRAM_HASH, tuple,
  INNER_ROOT)` reproduces exactly this fact.

Discovered along the way: `scarb execute --target standalone` cannot run
ec_op executables ("Memory addresses must be relocatable") — irrelevant
to the pipeline (the bootloader leg supports ec_op, as spike 2's table
said), but it means golden vectors for EC primitives come from
starknet.js, not a Cairo dump (see fixtures/zkmsg_vectors).
