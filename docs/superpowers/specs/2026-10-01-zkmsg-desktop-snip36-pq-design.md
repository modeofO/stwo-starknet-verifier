# zkmsg desktop: SNIP-36 send + v2 (post-quantum) store (2026-10-01)

**Blocked on** phase 2 of `2026-10-01-zkmsg-pq-hybrid-kem-design.md`: the v2
prover and store must be deployed on Sepolia alpha, with addresses recorded in
`docs/zkmsg-deployment.md`. Work that doesn't need those addresses can start
earlier; it's marked **(unblocked)**.

Goal: the desktop app (`tools/zkmsg`: core, cli, gui, daemon, gateway, ffi)
reaches parity with the phone:

- sends through SNIP-36 in one transaction,
- reads and writes only the v2 store, with v2 hybrid crypto,
- drops the features the owner retired.

## Where the desktop is today (`snip36-route` @ `ad21e40`)

- **Store:** the default is MessageStoreSnip36 (v1). `inbox --legacy` also
  reads MessageStore V3.
- **Send to the SNIP-36 store is refused** with a pointer to the phone; the
  guard is in `core/src/config.rs`.
- **The send pipeline** (`core/src/pipeline.rs`) is the lane-1 route:
  - `bridge_bin` subprocess for prove and wrap,
  - then stage, verify phase 1/2, publish through `sncast` (`core/src/chain.rs`),
  - all against the qm31 fact registry on sepolia-integration.
- **Profiles:**
  - each profile is a directory `~/.zkmsg/.zkmsg-<name>`,
  - burners (`burner: true`, `reply_handle`) live in `config.json`
    (`docs/superpowers/specs/2026-07-08-zkmsg-burners-design.md`),
  - existing profiles still point at the V3 store.
- **From-line:** the GUI prepends `from: <handle>` to the plaintext by default
  (`gui/src/fromline.rs`, compose).
- **Companion daemon** (`daemon/`, GUI `pair_view.rs`, `daemon_control.rs`)
  serves the phone's old companion route. **The phone side was removed
  2026-09-30.**

## Owner decisions this doc applies

1. **Remove the from-line entirely**, both writing and parsing. Messages carry
   no sender line. `reply_handle` goes with it.
2. **No sweep** after a burner send.
3. **Read only the current store.** Drop V3, drop SNIP-36 v1, drop `--legacy`.
   Nobody else uses the project.
4. **Archive profiles, don't delete them.** Permanent delete is a later
   feature.
5. **Inbox shows only the active profile.** This is the desktop's existing
   behaviour; keep it.

## Work

### A. Retirements (unblocked)

1. **Remove the from-line:**
   - delete `gui/src/fromline.rs` and its compose toggle and inbox rendering;
   - drop `reply_handle` from `Config`, and keep reading old configs: serde
     must ignore the unknown field, so don't use `deny_unknown_fields`.
2. **Remove the companion daemon:**
   - the `daemon` crate, GUI `pair_view.rs` and `daemon_control.rs`;
   - `docs/companion-protocol.md` (mark it retired rather than delete it);
   - the workspace member and the `tiny_http` dependency.
3. **Remove the sweep** offer from `retire_view.rs`, if present. Keep
   "archive burner".
4. **Remove `inbox --legacy`** and the V3/SNIP-36-v1 constants once item C
   lands. Until then, keep the v1 store readable for testing.

### B. SNIP-36 send pipeline (unblocked on v1, finished on v2)

The phone's `VirtualSendExecutor` (zkmsg-ios `Sources/ZkmsgCore/VirtualSend.swift`)
is the reference. Port its rules exactly:

```
prepare  read tree root, both members, both paths, nonce — all AT ONE BLOCK N
prove    virtual-OS proof of an invoke calling prover.prove_send(...) on block N
check    facts: len 9, facts[4]==N, facts[7]==1, facts[8]==poseidon([prover,0,5,...payload])
publish  is_known_root(root) at latest, else discard the proof and re-prepare
         sign INVOKE v3 with proof_facts in the hash; attach proof + proof_facts
         save the tx hash the moment the gateway accepts it; a resume polls it first
```

Proving:

- Build `tools/snip36-phone-ffi` for the host (`aarch64-apple-darwin`) from
  the sequencer workspace (`.prover/sequencer`, crate `snip36_phone_ffi`). Its
  `examples/prove_cli` already proves a request JSON to a proof on a Mac, with
  output byte-identical to StarkWare's prebuilt prover.
- Promote that example to a `[[bin]]` (`snip36-prove`) and call it as a
  subprocess, the way `bridge_bin` is called today. Add a `config.json` key
  `virtual_prover_bin`.
- Set `ZKMSG_SPILL_DIR` for the subprocess. A Mac proof has 13.5 GB live
  without spill (15 s on M-series).
- The RPC must serve `starknet_getStorageProof` for recent blocks. zan does
  (`https://api.zan.top/public/starknet-sepolia/rpc/v0_10`); publicnode
  doesn't. Fetch state promptly: zan refuses storage proofs for blocks more
  than about 6 minutes old.

Signing and submission. `sncast` can't attach `proof` / `proof_facts`, so the
publish leg signs natively:

- The INVOKE v3 hash with `proof_facts` appended per SNIP-36: port
  `TransactionHashV3.invokeV3Hash(… proofFacts:)` from zkmsg-ios, or reuse
  `snip-36-prover-backend/crates/snip36-core` (it signs with proof facts), in
  `snip36-spike`.
- Sign with `starknet-crypto` using the profile's account key. The desktop
  currently keeps keys in sncast's accounts file; read the key from there, or
  move it into `keys.json`. Decide in implementation and write the decision
  down.
- Submit to the **gateway** (`https://alpha-sepolia.starknet.io/gateway/add_transaction`):
  - check that the gateway echoes the hash we signed (the phone does this);
  - nonce correction from rejection messages, and a "too recent" retry: the
    base block must trail the head by 10 blocks.
- Fee bounds are pinned, as on the phone: L2 gas 120M, L1 data gas 4096, L1
  gas 0, ×1.5 on price. A send uses about 77M L2 gas, and the account must
  hold about 4 STRK of fee ceiling.

The virtual transaction (the one proved, never sent) is an INVOKE v3 by the
same account calling `prover.prove_send`. It has a real signature over the
ordinary, fact-less hash, because the account's `__validate__` runs in the
virtual OS. Its resource bounds are `l2_gas 0x7000000`, `l1_data_gas 0x1b0`,
prices 0. See the phone's `Snip36.virtualInvoke`.

State lives in `SendState`, as today, with a `virtual` plan: prepare / prove /
publish. Keep the witness in memory only, and persist the proof JSON plus
facts. Neither variant adopts the other's state.

### C. v2 store and crypto (blocked on deploy)

- The v2 crypto lives in `core/src/crypto.rs`. The PQ doc's phase 1 adds it
  there with golden vectors, and it is shared with the phone.
- `keys.json` gains the KEM seed (64 bytes). It is generated on `init`, and
  lazily for existing profiles.
- Register: `register(handle, scan_pubkey, kem_pubkey: ByteArray)`; parse the
  v2 `UserRegistered` event to get recipients' `ek`, and check it against
  `get_user`'s `kem_digest`.
- Send: build `content = kem_ct ‖ blob` and the v2 `prove_send` calldata (no
  recipient inputs).
- Inbox: the v2 detect-and-decrypt.
- Config:
  - the default store, prover and deploy block become v2;
  - a `zkmsg migrate-store <profile>` command rewrites `config.json` to v2,
    clears the leaf index, and tells the user to register again (registration
    is per store);
  - the GUI offers the same per profile.
- The send guard that refuses SNIP-36 stores is removed once B and C work end
  to end.

### D. Burners and profiles

- New burners get a fresh scan key **and** a fresh KEM seed. Funding stays
  external only.
- Archive: hide the profile in the picker and keep its directory.
  Unarchive is the reverse.
- No `reply_handle`, no sweep.

## Tests and gates

- `RUSTC_WRAPPER= cargo test --workspace` green; v2 vectors match the phone's
  copy byte for byte.
- Live (ignored by default):
  - desktop register → phone send → desktop inbox decrypts;
  - desktop send → phone inbox decrypts.
- A desktop send of about one transaction, about 1.6 STRK, under a minute on
  an M-series Mac. Record the wall time and the fee.
- The GUI compose → send → done path, checked by hand.

## Order

1. A (retirements). Independent and small; do it first.
2. B on the **v1** SNIP-36 store. This proves the desktop pipeline against
   the live v1 deployment before v2 exists: send to `mode2` and check that
   the phone decrypts.
3. When v2 is deployed: C, then D, then drop the v1 constants and the
   `--legacy` remnants.
