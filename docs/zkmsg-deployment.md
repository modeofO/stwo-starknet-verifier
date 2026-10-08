# zkmsg SHIPPED on Sepolia — the first natively-proven private message (2026-07-05)

> **Current: v4, the pool** — `ZkmsgPoolV4` `0x050f98ee…69b9` (store AND
> publishing account, paid by single-send tickets) + `ZkmsgSendProverV4` +
> `ZkmsgVirtualSenderV4`; see "zkmsg v4: the pool and tickets" at the end
> of this file. Everything above that section is the record of retired
> routes and stores: the lane-1 send route and its store (sections through
> "Repro / try it"), the SNIP-36 v1 store, v2 and v3 (retired 2026-10-07:
> every v3 send was published by the sender's own registering account).

The full messagezk model — sender/recipient membership in a registered-user
Merkle tree + ephemeral ECDH + Poseidon commitment — proven in a native
Rust app (`tools/zkmsg`), verified on the PUBLIC network through the live
lane-1 `StwoFactRegistry`, and published to an immutable MessageStore v3.
The recipient found and decrypted it by trial-ECDH; the sender's own inbox
(correctly) shows nothing.

## Deployed contracts (Starknet Sepolia)

| What | Value |
|---|---|
| lane-1 `MessageStoreV3` (retired 2026-10-01; not the v3 store below) | `0x02d66a02b2efdddb5282bf7d7931cbb7a724f191478843b1fccbf3b9729e91b7` |
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

## Profiles + the identity wizard (2026-07-08, first wizard-born sender)

The GUI gained in-app profiles (root `~/.zkmsg/` of `.zkmsg-<name>/`
homes + `current`; alice and bob migrated by atomic rename via the
one-time migration screen) and a one-confirm identity wizard. `carol`
was created entirely in-app — account `zkmsg-carol`
(`0x012466d1…f80`), funded 60 STRK from alice, deployed, scan-keygen'd,
registered at leaf 2 — for 0.35 STRK of fees on top of the retained
funding:

| wizard leg | tx | fee |
|---|---|---|
| fund (60 STRK from alice) | `0x049be4d1…8b39` | 0.05 STRK |
| deploy account | `0x042c0d7e…0eba` | 0.07 STRK |
| register `carol` (leaf 2) | `0x03451d68…072f` | 0.23 STRK |

Carol's first send (id `1d0acab64b`, carol → alice, message #4) also
proved the checkpoint system on a REAL failure: Sepolia gas was at
~43.9 Gfri (~1.5× the first send's price), so after phase 1 landed,
phase 2's worst-case resource bounds (~44 STRK) exceeded carol's
remaining 33.3 STRK and validation refused the tx — nothing burned. A
25 STRK top-up + one Resume click re-entered at phase 2 without
re-paying anything:

| send leg | tx | fee |
|---|---|---|
| stage tail (71 slots) | `0x065900fd…693e` | 1.07 STRK |
| verify_phase1 (864.4M l2_gas) | `0x06bbcfb6…e64b` | 25.31 STRK |
| verify_phase2 → fact (799.2M l2_gas) | `0x0358f27b…fec5` | 23.39 STRK |
| send_message | `0x0700a0d4…2ef2` | 0.08 STRK |

**fact `0x18dbb303f3ba506b5e8da3ccc614c896c60e55d12d44dfde455b57f1f00305a`
— `is_valid == true` on the live registry**; alice trial-decrypted
"first message from carol to alice". Send total 49.9 STRK at spiky
prices — the flat-cost claim holds at the fourth data point. Known
follow-up: the wizard's 60-STRK default funding is thin at elevated
gas; scale it by live prices.

## Burners (2026-07-10, the first unlinkable sender)

The GUI gained burner accounts: throwaway sender profiles with **no
on-chain edge to any account the user owns**. `burner-7ec070`
(auto-named from OS randomness, account
`0x0733887f…600c`) was funded by an **external deposit** — the wizard
parks at the Fund step (no lock held, app fully usable) until the
address holds the target, which is now computed from live gas prices
(79 STRK recommended at ~29 Gfri; the flat-60 default died with
carol's stall). None of the user's accounts signed anything: deploy,
register (leaf 4) and the whole send were paid by the burner itself.

| leg | tx | fee |
|---|---|---|
| deploy account | `0x018235ea…1a88` | 0.07 STRK |
| register `burner-7ec070` (leaf 4) | `0x0174b418…e884` | 0.24 STRK |
| stage tail (96 slots) | `0x0587b90e…f10a` | 1.40 STRK |
| verify_phase1 | `0x063611a7…880c` | 24.92 STRK |
| verify_phase2 → fact | `0x06fd8a83…da01` | 23.16 STRK |
| send_message | `0x03565291…c1e9` | 0.08 STRK |
| sweep 49.94 STRK → `deployer` (bob) | `0x04f3a859…d7bb` | 0.04 STRK |

**fact `0x4535d6880c0f959c7a1a1864173df3b2d22a699759648cee274c7ce1d88c46a`
— `is_valid == true` on the live registry** (send id `eeca22558f`,
burner → alice, carrying the optional encrypted `from:` line so alice
knows who to reply to). Send total 49.9 STRK. After the send, one
retire prompt swept the leftover 49.94 STRK out (the UI states
verbatim that the sweep is a public linking edge — declining leaves
the burner unlinkable) and archived the profile by rename to
`~/.zkmsg/archive/.zkmsg-burner-7ec070/` — keys intact, restorable.

Honest limits (also in the README): tiny anonymity set on Sepolia,
timing correlation, burner reuse links its sends, and the `from:`
line is an unauthenticated plaintext claim.

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

See `tools/zkmsg/README.md` (quickstart). `zkmsg init` now defaults to
the v4 pool (`SEPOLIA_STORE_DEFAULT` in `tools/zkmsg/core/src/config.rs`);
the lane-1 store above is no longer read, and the lane-1 send route was
removed from the client 2026-10-01.

## SNIP-36 v1 store (Sepolia alpha, 2026-09-29; retired)

`MessageStoreSnip36` + `ZkmsgSendProver` (`contracts/messagezk_store_snip36`,
commit `8e391f1`): the lane-1 store's interface with the fact-registry
check replaced by a `proof_facts` check — the first one-transaction route.

| What | Value |
|---|---|
| `MessageStoreSnip36` | `0x002b9c6f617b3197dfed76401c32aa3b4b597ebdd01a7eba4b5657236bc8084f` |
| store deploy block | 15850710 |
| `ZkmsgSendProver` | `0x012b85a4b5e6918eb6f18a07fddc1667d67beaac0ab647928105b8ccf7ee5346` |

Addresses and block from commits `8e391f1` and `ff4cb9d`. The declare and
deploy transactions and their fees were not recorded. Measured v1 sends
appear in the v2 comparison table below and in `tools/zkmsg/README.md`
(first desktop send).

## zkmsg v2: hybrid ML-KEM-768 + ECDH, SNIP-36 route (Sepolia alpha, 2026-10-01)

Design: `docs/superpowers/specs/2026-10-01-zkmsg-pq-hybrid-kem-design.md`.
Code: `contracts/messagezk_store_pq` (Scarb 2.18, sierra 1.8), branch `pq-v2`
(merged to `main` in `09834e0`).
Declared and deployed from account `deployer`
(`0x6f3eee3cc01225d84e31c1696411afb129201a60ea44c06f96e0e422d8fa1ce`) via
`https://api.zan.top/public/starknet-sepolia/rpc/v0_10`.

| What | Value |
|---|---|
| `MessageStoreV2PQ` | `0x04dc92ef9a90d336a79188c5408cdf9ce480f3ecd5b1ce55ef2ca207f2c3afe8` |
| store class hash | `0x0181e2549f10fe48772038b5940951acd93dd7910f53286030883bde27d0c5be` |
| store deploy block | **15947092** (scan start) |
| `ZkmsgSendProverV2` | `0x02d993bd9e1229367fe9643151fdb7b2fb9fe06b28e6ff0d2f1d451894182d79` |
| prover class hash | `0x07c8b5fb5fd93955698f1818bfad816f24ca26aa0ae851b6a1492d8b74fa864e` |
| prover deploy block | 15947067 |
| root history | 64 |

| tx | hash | block | fee |
|---|---|---|---|
| declare prover | `0x04e23d7b37714bc34d596c74fa4ed432179568d8c72607803ff23ae977a9a8ad` | 15947061 | 1.58 STRK |
| deploy prover | `0x010f9f637203027b154a752e6234a85ff232daf95a417e3e01b695b32dabe165` | 15947067 | 0.03 STRK |
| declare store | `0x07d0d891f0c2894c1d679ce72e9ed255560097dacb85252402263422c76ff3da` | 15947082 | 9.19 STRK |
| deploy store (pinned to the prover) | `0x0776b67f9bb80da2cd34775d641b494cdcab33e63d7b5de5fa60b3db72caefc6` | 15947092 | 0.04 STRK |

Total 10.83 STRK. Checked after deploy: `prover()` returns the prover
address, the root is 0, and `n_messages` is 0. No users are registered yet.
Every identity must register again with `register(handle, scan_pubkey,
kem_pubkey)`; the v1 store (`0x002b9c6f…8084f`) is no longer read.

### First v2 send (Mac prove, 2026-10-01)

Test identity `mode`: scan key from the desktop `.zkmsg-mode` keys, a fresh
ML-KEM seed, registered from `deployer` at leaf 0. The register tx
`0x02d8e350e7662c8dcc58e4158d8d1c88498b06053e9192d34750c0d5310e4a0c` cost
0.36 STRK and 17.6M L2 gas. `get_user('mode')` returns the same
`kem_digest` as the client computes from the `ek` in the event.

The message went from `mode` to itself, built with
`cargo run -p zkmsg-core --example v2_cli -- send`. It was proved with
snip36-phone-ffi's `prove_cli` on the Mac and published with `snip36 submit`:

| | v2 | v1 (2026-09-29) |
|---|---|---|
| virtual OS steps | 142,905 (ec_op 4, poseidon 151) | ~148k |
| Mac prove wall | 19 s (precompute 1.2 s + run and prove 16.9 s), footprint 335 MB, spill 13.8 GB | 15–16 s |
| publish tx | `0x135dec2b9689f390761d086a5b750e74468385c8287c9fcdec12dfd9d17612b`, SUCCEEDED | |
| fee | 1.60 STRK, 78.0M L2 gas, 384 L1 data gas | 1.60 STRK, 77M L2 gas |
| content | 1,167 bytes (kem_ct 1088 ‖ nonce 12 ‖ 51 ‖ tag 16) | |

`v2_cli open` with `mode`'s keys decrypts the event. A different scan key
gives "not ours". The proof's facts are pinned in
`contracts/messagezk_store_pq/tests/mac_proof.cairo`.

The v1 prover's ~148k steps already included two Merkle paths and an ECDH.
Dropping one path and the ECDH saves only ~5k steps, because the virtual
OS's fixed cost dominates. The fee is the same, so the extra 1088 bytes of
`kem_ct` are negligible.

### First phone v2 registration and send (iPhone 14 Pro, 2026-10-01)

zkmsg-ios `pq-v2` at 332fbf4. The phone's original profile kept its scan
key and gained a KEM seed on launch.

| | tx | result |
|---|---|---|
| register `mode2` (leaf 2) from the phone's own account | `0x4ab780bcff07a5d60d81c6801242db16b777df0d73a4f63faabe18652fd4c95` | 0.185 STRK, 9.15M L2 gas, 2,368 data gas. The event ek's digest (`v2_cli digest`) equals the stored `kem_digest` |
| desktop `carol` → `mode2` | `0x757d2f311f088aac984372a91e23152239f2dadfc11682439337154770099e3` | 1.559 STRK, 77.6M L2 gas. The phone Inbox decrypts it |
| phone `mode2` → `carol` | `0x1c6f7006110ed5ca4623d9c40ea7edf77af953597766e07b2326a363ec57e5b` | 1.554 STRK, 77.5M L2 gas, 352 data gas. carol's desktop inbox decrypts "new store test 21:11" |

Phone send: proved against block 15950141 and published in block 15950293.
The chain time between those two blocks is 261 s, which covers prove and
publish; the virtual OS ran at the prepare block. The proof was 317,092
base64 bytes. The prove note reads "spill class A". The content was 1,136
bytes. The publish transaction was signed and saved before the POST
(nonce 0x8), per the double-pay fix.

## zkmsg v3: hash-based membership, SNIP-36 route (Sepolia alpha, 2026-10-01; retired 2026-10-07)

Design: `docs/superpowers/specs/2026-10-01-zkmsg-v3-pq-membership-design.md`.
Code: `contracts/messagezk_store_v3` (Scarb 2.18), branch `pq-v3` (on `main`
through `d4d9da7`). Declared
and deployed from `deployer` via zan.

| What | Value |
|---|---|
| `MessageStoreV3` | `0x0103de677e966a8a72669551093f0f5342621e635531fec146c4b04c5f5d3d9d` |
| store class hash | `0x0726c71cc88be208ac9b2033b1f68764facf278a45df8b5563bffffe7513f82d` |
| store deploy block | **15952418** (scan start) |
| `ZkmsgSendProverV3` | `0x03d4da714c3bb315fe54017d2556face941836c2d5dfa9cc0b6852b94c0b4f30` |
| prover class hash | `0x01ad0a16a941298103c36be0e3014bbd768acf7755c55a91bb543f2dfbb9d333` |
| prover deploy block | 15952394 |
| root history | 64 |

| tx | hash | block | fee |
|---|---|---|---|
| declare prover | `0x0177e9904bcb02e1b4ae991c7a05db5ff06dfee77a635561370ac19ec113b898` | 15952387 | 1.49 STRK |
| deploy prover | `0x015696af63a883ea191cace529911f280d961f40d095f4b5e8189ea19c9dc08e` | 15952394 | 0.03 STRK |
| declare store | `0x01c4a0f38b4dd55ab3bf20383b20dfedb6961d4dbafd980708c4d8d0c3c3dab8` | 15952411 | 9.50 STRK |
| deploy store (pinned to the prover) | `0x06d5dc5f7bd7b73e226a094c8ce06e6e153a4520b3f5416a43e2ae16ebbc2981` | 15952418 | 0.04 STRK |

Total 11.05 STRK. `prover()` returns the prover.

ABI (pinned in the spec):
- `register(handle, scan_pubkey, kem_pubkey: ByteArray, m_commit)`
- `UserRegistered` data `[handle, scan_pubkey, leaf_index, m_commit, kem_pubkey...]`
- `get_user(handle) -> (owner, scan_pubkey, kem_digest, m_commit, leaf_index)`
- `get_m_commit(owner)`
- `prove_send(store, content_hash, commitment, ephemeral_pubkey, merkle_root,
  sender_scan_pub, sender_kem_digest, member_secret, sender_leaf_index,
  sender_path)`

### First v3 send (Mac prove)

Test identity `mode` (leaf 0, owner `deployer`): the scan key from
`.zkmsg-mode`, plus a fresh KEM seed and member secret (keys in
`~/.zkmsg-test-keys/mode-v3/`, outside the repo).

- Register tx `0x03a4838356b7784d0d8979c8bfb21093ec3a426359a199ac76909bd0246cc1a2`:
  0.365 STRK, 18.1M L2 gas. `get_user` returns the expected `m_commit`.
- Self-send, built with `v2_cli send3` and proved with `prove_cli`:
  - 142,983 steps (ec_op 3, poseidon 163; v2 was 142,905: one EC op fewer,
    a few more Poseidon calls);
  - 16 s on the Mac, 321 MB footprint.
- Publish tx `0x0468b1a4f7db737f5d2a4d6ec15b2c566b072d3c0159524a7f1c8ded914bfd64`:
  1.565 STRK, 78.0M L2 gas.
- `v2_cli open` decrypts it. The facts are pinned in
  `contracts/messagezk_store_v3/tests/mac_proof.cairo`.

### First phone v3 registration and phone↔desktop sends (iPhone 14 Pro, 2026-10-01)

The phone ran zkmsg-ios `pq-v3` at ce2b36b with the memory-optimized prover
(`.prover/sequencer-phone`). Its original profile kept its scan key and
KEM seed from v2 and gained a member secret on launch.

| | tx | result |
|---|---|---|
| register `mode2` (leaf 2) from the phone's own account | `0x02e2d9a48f1e1c915bca1b782ee64122d49196ac8ce9d9d6695e8f1dac099c90` | 0.196 STRK, 9.68M L2 gas. `get_user` gives the expected `m_commit`, and the event ek's digest equals the stored `kem_digest` |
| phone `mode2` → `carol` | `0x0341df049fcc3c9f52ed3faf140dfb3ec6a604b504170902837bbd5fead2bc66` | 73 s from the prove block to the publish block, 1.543 STRK, prove note "spill class A". carol's desktop inbox decrypts "v3 test 22:31" |
| desktop `carol` → `mode2` | `0x045f7346b6e85c9461df1d5e11f0ec27115bf017f7b063c76918c378a43b60aa` | 34 s, 1.544 STRK. The phone Inbox decrypts it |

Membership in both sends was proved by knowledge of `m`, with no EC step,
and the scan private key was not in the witness.

## zkmsg v4: the pool and tickets (Sepolia alpha, 2026-10-07)

Design: `docs/superpowers/specs/2026-10-07-zkmsg-v4-pool-tickets-design.md`.
Code: `contracts/zkmsg_pool_v4` (Scarb 2.18, sierra 1.8; 87 snforge tests,
`scripts/devnet_e2e.sh`), client `tools/zkmsg` — branch `pool-spike`.
Declared and deployed from `deployer` (`0x6f3eee3c…a1ce`) via zan.

Why: the 2026-10 red team showed every v1–v3 send was published, and paid
for, by the same account that registered the sender's handle, so the chain
named the sender. In v4 the store is itself the account that publishes
every send (unsigned; its `__validate__` admits only a proven
`send_message`), paid from single-send tickets bought earlier at a fixed
price; the virtual proof runs from a shared zero-fee account. No member's
account signs, pays for or appears in a send.

| What | Value |
|---|---|
| `ZkmsgPoolV4` (store + account) | `0x050f98ee98a0c1a583529c115f394ad79d18686ff66dc1ee25ba0f7bc53669b9` |
| pool class hash | `0x031324653c4269f8f3356e28817a7d8b63f5afc471a62336f0275d64087cc343` |
| pool deploy block | **16257012** (scan start) |
| `ZkmsgSendProverV4` | `0x0496b7e39ea515c48e8f37dd588ed1ff16c86b3ff7619c6a30ae7b473f902973` |
| prover class hash | `0x07f3d3ab8cc1d1ced37217846eaa356962e0647c09ed8a3dfddc0949e0cda8d2` |
| prover deploy block | 16256600 |
| `ZkmsgVirtualSenderV4` | `0x01e9fefc5d5848690330af81644736e90cc1e7192357d06fe40080da2ddd94a4` |
| virtual sender class hash | `0x00edf5292ff19af31c8c54c28d728a42d92b1e8ee08b9a2d1319ed68095e889a` |
| virtual sender deploy block | 16256605 (nonce 0 forever) |

Constructor (read back with `prover()`, `ticket_price()`, `rate_limit()`,
`fee_policy()`): prover = the prover above; STRK =
`0x04718f5a…c938d`; `ticket_price` 3 STRK (3e18 fri); `epoch_blocks`
5,000 (≈2.4 h at Sepolia's ~1.7 s blocks; a multiple of the 100-block
validate rounding); `max_epoch_lag` 1; `quota` 10 sends per member per
epoch; fee policy `max_fee` 3 STRK (= the ticket price: one send can never
cost the pool more than the ticket it burns), `max_tip` 1e9 fri,
`min_l2_gas` 100M. Fee math at 2026-10-07 prices (L2 18.09 gfri): a
publish measured 79.3–79.7M L2 gas (snforge/devnet put the pool's own
validate+execute at ~4.6M on top of the ~75M proof), so the 100M floor
leaves ~25% margin; worst case 100M × 30 gfri = 3.0 STRK fits the ticket
while allowing the price to rise 1.66×; actual cost ≈1.43 STRK, the rest
stays in the pool (no refunds: a refund needs a destination).

Pre-deploy hardening (this branch): the store's replay key is now the
envelope, poseidon(commitment, content_hash), not the commitment alone, so
a member who front-runs a pending send with its commitment over other
content no longer blocks it (red team 04-crypto F9; snforge
`a_front_run_commitment_does_not_block_the_real_send`).

Read-only checks after deploy: `prover()` = the prover; `ticket_price()` =
3e18; `rate_limit()` = (5000, 1, 10); `fee_policy()` = (3e18, 1e9, 100M);
both roots = zero_hash(20); `n_tickets()` = `n_messages()` = 0. The real
`snip36-prove` proved a `prove_send` from the virtual sender at nonce 0
before the pool existed (`core/examples/v4_prove_probe.rs`, 22 s, facts
attest the v4 message hash), and `adversarial::live_current_store_is_pinned_to_our_prover`
passes against the deployed pool.

### Deployment transactions (from `deployer`)

| tx | hash | block | fee |
|---|---|---|---|
| declare prover | `0x0600dc7693ff7da77fcee49229c8caca00a4da7c0b337092db2c7cb51c9a8a85` | 16256572 | 2.1631 STRK |
| declare virtual sender | `0x07f606955b1a1d4088f2bb1a3e1daba914ad269a193f5938b7d3cd0121747b20` | 16256591 | 1.2425 STRK |
| deploy prover | `0x063c242cc0301ad88768ea0c9e5bbb0abfd2b6476f047c96f86df414c1feedd2` | 16256600 | 0.0227 STRK |
| deploy virtual sender | `0x01912a0ab01c5d8212efc05076e563dec9d317ebf11f9b73623c9327723768c3` | 16256605 | 0.0227 STRK |
| declare pool | `0x06ce4f4136a2d238ddad181be6c8b697f9ce9e6cfcc6b55b73d02a642aa99425` | 16257002 | 16.6450 STRK |
| deploy pool | `0x05f183fe07455e5c36002d31dee9c54f9b1f0c22f81cf5835274c292a0974b15` | 16257012 | 0.1243 STRK |

Deploy total 20.22 STRK (the pool class is ~7k sierra felts; its declare
alone is 16.6 STRK at these prices).

### Re-key, registrations and tickets (2026-10-07)

carol (`~/.zkmsg/.zkmsg-carol`, account `zkmsg-carol`) and mode
(`~/.zkmsg/.zkmsg-mode`, now account `deployer`) were first copied to
`~/.zkmsg-test-keys/{carol,mode}-v3-final-2026-10-07/` (700/600, `diff -r`
clean), then moved with `zkmsg migrate-store` to fresh scan keys, ML-KEM
seeds and member secrets (the red team's prefetch finding means every
earlier key must be treated as exposed). mode2 (the phone) was not touched.

| tx | hash | block | fee |
|---|---|---|---|
| register carol (leaf 0) | `0x06951b6f71090d843f9f8a4218ff61aab488baa68f298964e292229caae27a53` | 16257132 | 0.3199 STRK |
| register mode (leaf 1) | `0x061e587f843affe5dadfac1f606134e9e8572d7c582d820f2a7bc73c47455561` | 16257135 | 0.1682 STRK |
| carol approve 6 STRK | `0x07afc51a8dd402a83bf494880c3442aff96ce24a5424988ba6877ec9e46ac423` | 16257144 | 0.0290 STRK |
| carol `buy_tickets` × 2 | `0x07bb8277fe35e2686f12e7cbe936cf868afcbd96f851c2264b2a6a034eb89459` | 16257147 | 0.3447 STRK + 6 STRK |
| mode approve 6 STRK | `0x05dda4dd1ac2ddfb0167161b754c2c005db2981dd178d1584d1792dc24a9c728` | 16257215 | 0.0290 STRK |
| mode `buy_tickets` × 2 | `0x076a22677b370aaf3fc2f67deec735ce3baba2e73844528ce77f78d13f73f7f0` | 16257216 | 0.1916 STRK + 6 STRK |

### Sends through the pool

Every publish: `sender_address` = the pool, `signature` = `[]`, tip 0,
bounds L2 100M @ ≤30 gfri / L1 data 4,096 / L1 0, one call to the pool's
own `send_message`; neither `zkmsg-carol` (`0x12466d1c…7f80`) nor
`deployer` (`0x6f3eee3c…a1ce`) appears anywhere in the transaction or its
receipt. Each recipient's `zkmsg inbox` decrypts; each sender's does not.
After each, `is_ticket_spent(ticket_nullifier)` and
`is_nullifier_spent(nullifier)` read 1.

| send | publish tx | pool nonce | base → block | fee (from the ticket) | L2 gas |
|---|---|---|---|---|---|
| carol → mode "v4 pool test carol->mode 23:27" | `0x7f4e68b7385d34c40cb45e76cd515eea4782132f9d90e8ab62e35332d22470` | 0 | 16257164 → 16257185 | 1.4390 STRK | 79,735,400 |
| mode → carol "v4 pool test mode->carol 23:31" | `0x7eb39d960bda032108aef2a8d88f0f9e450acb88ef23572fa97641bca9a36a5` | 1 | 16257228 → 16257248 | 1.4317 STRK | 79,333,400 |
| mode → carol (concurrent) | `0x6a4e3423c1e62bac2fbb87b67624f9472d132f4228faf1abadbeb354da814f1` | 2 | 16257263 → 16257284 | 1.4317 STRK | 79,333,400 |
| carol → mode (concurrent) | `0x6f0110c3801233361e0e06619a29b26dd6937778087e8151948ea6122b0ed08` | 3 | 16257263 → 16257287 | 1.4317 STRK | 79,333,400 |

~36 s wall per send (prove 19–23 s). The last two ran at the same time,
proved on the same base block and both landed, at consecutive pool nonces.
The first send's feeder record is pinned as
`tools/zkmsg/core/testdata/v4_pool_publish_tx.json`
(`core/tests/v4_vectors.rs::live_pool_publish_reproduces` rebuilds its hash
and facts from its calldata).

Pool accounting after the run: 4 tickets bought (12 STRK in), 4 burnt,
fees 5.7341 STRK, balance 6.2659 STRK = 12 − 5.7341; `n_messages` 4,
nonce 4. The surplus can only ever pay for future sends (no owner, no
withdraw).

Total spent on v4, everything included: 33.30 STRK (deploy 20.22,
registrations 0.49, tickets 12.00, approve/buy fees 0.59).

Golden vectors for the iOS port: `tools/zkmsg/core/testdata/v4_vectors.json`
(built and checked by `tools/zkmsg/core/tests/v4_vectors.rs`; the same
values asserted against the contracts in
`contracts/zkmsg_pool_v4/tests/test_vectors_v4.cairo`, which also replays
the vectors' `prove_send` calldata through the prover).

### Padding, shared transaction policy, fixed publish timing (client-side, 2026-10-07)

Added after the first four sends (they used v2 sealing, tip 0 and the
older bounds; the v4 inbox no longer opens them):

- **Padding + v4 sealing**: the plaintext is padded inside the AEAD to
  256 / 1024 / 4096 bytes (`u16 BE length ‖ plaintext ‖ zeros`), under
  HKDF labels `zkmsg-v4` / `zkmsg-v4 aead` / `zkmsg-v4 tag`, so content is
  1372, 2140 or 5212 bytes. The top bucket fits the event cap (171
  ByteArray felts + 2 = 173 of 300). The DEPLOYED pool still accepts
  1116..8192 bytes, i.e. bucket sizes are enforced by the clients only.
- **Shared transaction policy** (`tools/zkmsg/core/src/txpolicy.rs`):
  price bound = ceil(1.5 × price) rounded up to 2 significant figures;
  tip 1e8 fri (96.7% of 1,277 Sepolia INVOKE v3 txs in blocks
  16257334–16257733); L1 data 4,096; L2 publish 100M / register 30M /
  `[approve, buy_tickets]` 80M (≤ 8 tickets); L1 DA; empty paymaster and
  deployment data. Register and ticket purchases are now signed natively
  (`account_tx.rs`), not via sncast.
- **Schedule**: base = floor((head − 10)/32) × 32; publish once the head
  reaches base + 90 + j, j uniform in 0..=20.
- **Front-run copies**: a tag match that fails to open is dropped silently.

| tx | hash | block | fee |
|---|---|---|---|
| carol `[approve, buy_tickets]` × 1 (native, policy bounds) | `0x062d12e709580a2333deea39c1652225311a767d056bdfd008cb9c8ed14eb2e1` | 16257927 | 0.1354 STRK + 3 STRK |
| carol → mode (padded 1372 B, scheduled) | `0x06434b6b01fbeb82ad44b72fd66c1b2d4f610aba4c720028bcca847bec195510` | 16258049 | 1.4355 STRK (ticket), 79,523,568 L2 gas |

The scheduled send: base 16257952 (≡ 0 mod 32), target 16258043, landed
16258049 (97 blocks after base), tip 0x5f5e100, L2 bound 27 gfri; mode's
inbox decrypts it; neither member account appears in it. Pool after:
5 tickets bought, 5 burnt, 5 messages, nonce 5, balance 7.8303 STRK.
Running total on v4: 36.44 STRK.
