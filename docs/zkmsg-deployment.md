# zkmsg SHIPPED on Sepolia — the first natively-proven private message (2026-07-05)

The full messagezk model — sender/recipient membership in a registered-user
Merkle tree + ephemeral ECDH + Poseidon commitment — proven in a native
Rust app (`tools/zkmsg`), verified on the PUBLIC network through the live
lane-1 `StwoFactRegistry`, and published to an immutable MessageStore v3.
The recipient found and decrypted it by trial-ECDH; the sender's own inbox
(correctly) shows nothing.

## Deployed contracts (Starknet Sepolia)

| What | Value |
|---|---|
| `MessageStoreV3` | `0x02d66a02b2efdddb5282bf7d7931cbb7a724f191478843b1fccbf3b9729e91b7` |
| class hash | `0x04dc67c0ad76d9674a80d6dcb717cec7334014f2d5df986c440ed1aa62765745` |
| declare / deploy tx | `0x0086f065…e6b8` (17.58 STRK) / `0x0097dc39…7e5d` |
| pinned registry | `0x0194f44002b4af71e58ba7d30667ed565f1d420d3fb1e7c578de35170309c6aa` (live lane-1) |
| pinned program_hash | `0x250cb04a129e5259221ad4635950ac983bccf1de574893a2fae75c3c64385c` (messagezk_scan) |
| pinned inner_root | `[2674953418, 3988685724, 1385424428, 1661362028, 3534442848, 356489633, 2101289576, 2757001180]` |

No owner, no setters: the verification route is immutable (v2's un-gated
`set_verifier` rug vector does not exist here).

## The first message (send id `6d3671ecef`, alice → bob)

Registered users: `alice` (leaf 0, account `funded-deployer`), `bob`
(leaf 1, account `deployer`; account deploy `0x03b19b9a…9495`; register
txs `0x0389351f…57fd` / `0x00a342a3…64d2`).

Local legs (M-series laptop): prove ~30 s / 7.0 GB (bootloader preimage
tuple verified pre-spend), wrap ~10 s / 24.6 GB (inner root verified
pre-spend), pack 5,045 slots (35,310 values; head 4,991 + 54-slot tail).

| leg | tx | l2_gas | fee |
|---|---|---|---|
| stage tail (54 slots) | `0x06b9d3b3…5cc0` | 27.8M | 0.79 STRK |
| verify_phase1 | `0x06e8ab1a…185f` | 862.6M | 24.47 STRK |
| verify_phase2 → fact | `0x04c0ee5d…34b0` | 786.7M | 22.32 STRK |
| send_message | `0x065854ac…e113` | 3.3M | 0.10 STRK |

**fact `0x2dc0a3703c2703c471591c64307ebb8a50f8c4eae35f0c916d6fca56014145f`
— `is_valid == true` on the live registry**; message #0 published with
115 bytes of AES-256-GCM ciphertext; `zkmsg inbox` as bob trial-decrypts
it, alice's inbox shows nothing (she is not the ECDH recipient).

Happy-path send cost: **47.7 STRK** at l2 price 28.4 fri/gas — within the
runbook's ~49 estimate, and gas (862.6M + 786.7M) is within 1.5% of the
lane-1 fixture's numbers (873.8M + 815.7M): the recursion route's
fixed-shape claim, priced twice. One lesson re-paid: an early phase-1
attempt with `l1_data_gas` bounded at 4,096 (actual: 13,248) REVERTED and
burned 24.47 STRK — under-provisioned data gas reverts rather than
rejecting (docs/lane1-results.md said so; now it is measured twice).
Bounds now: amounts pinned per step, prices fetched from the latest block
×1.5, `l1_data_gas` 32,768.

Total campaign spend ≈ 90 STRK incl. the declare and the burned revert;
~612 STRK remain on `funded-deployer`.

## The first GUI-driven send (2026-07-07, send id `4a1b2e966b`)

The `zkmsg-gui` egui app (workspace split: `zkmsg-core` lib / `zkmsg` CLI
/ `zkmsg-gui`) drove a complete send end-to-end — compose to `bob`,
recipient resolved in-app, the ~48-STRK cost confirmed in an explicit
dialog, the checklist run green through Publish — and bob's GUI inbox
trial-decrypted it on Refresh. Message #3, 64 bytes of ciphertext.

Both pre-spend gates passed (bootloader preimage tuple + pinned inner
root); this proof packed to 4,926 head slots with a zero-length tail, so
no stage tx was needed — a 5-step on-chain plan instead of the first
send's 6.

| leg | tx | fee |
|---|---|---|
| verify_phase1 (849.7M l2_gas) | `0x014aaf82…f81a` | 24.65 STRK |
| verify_phase2 → fact (773.5M l2_gas) | `0x00bef71b…be60` | 22.43 STRK |
| send_message | `0x0507d18c…cbd4` | 0.09 STRK |

**fact `0x5b824d25e6a93dcc352e9ab1e14d8f418f7f067bbd65e10f0058708272f6e25`
— `is_valid == true` on the live registry.** Total 47.2 STRK; ~456 STRK
remain on `funded-deployer`. The CLI survived the refactor byte-identical
(hard parity gate); the GUI adds nothing to the trust surface — same
pipeline, same checkpoints, same pre-spend gates.

## What this demonstrates

- Lane 1 verifies arbitrary app circuits TODAY — including `ec_op`-using
  circuits that lane 2's contract-legal config can never run — at a flat
  ~47 STRK / ~1.68e9 L2 gas per fact regardless of circuit size.
- The proof-only boundary holds end-to-end in a product: the witness
  (sender identity, recipient identity, message) never left the machine;
  only the 35k-felt wrapped proof and the ciphertext went on-chain.
- Consumer integration is exactly the two-line pattern the fact-binding
  crate promises: `compute_fact(...)` + `registry.is_valid(fact)`.

## Repro / try it

See `tools/zkmsg/README.md` (quickstart). The deployed store address is
baked into `zkmsg init`'s defaults.
