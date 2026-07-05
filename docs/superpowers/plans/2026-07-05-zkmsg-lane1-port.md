# zkmsg (messagezk → lane 1, native Rust) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the messagezk private-messaging circuit onto the shipped lane-1 pipeline (prove → wrap → live Sepolia `StwoFactRegistry`) with a fresh immutable MessageStore v3 and a native Rust CLI (`zkmsg`) replacing the browser client.

**Architecture:** Three layers, gated in order: (1) the circuit as a bootloader-provable scarb executable whose public tuple `(commitment, ephemeral_pubkey, merkle_root)` is RETURNED (outputs are public; args are witness); (2) MessageStore v3 pinning `(registry, program_hash, inner_root)` at construction and checking `registry.is_valid(compute_fact(...))` per send; (3) a Rust orchestrator that shells out to the bridge (prove/wrap) and sncast (txs), with checkpointed resumable sends.

**Tech Stack:** Cairo/scarb 2.18.0 (PATH prefix `~/.local/share/scarb-install/2.18.0/bin` — bare `scarb` is 2.13.1, wrong), snforge 0.61, Rust (clap, serde_json, ureq, starknet-crypto, starknet-curve, hkdf, sha2, aes-gcm, rand), the bridge binary at `.prover/proving-utils/target/release/privacy_prove_cairo_bridge`, sncast 0.61.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-05-zkmsg-lane1-port-design.md`.
- Live lane-1 registry (Sepolia): `0x0194f44002b4af71e58ba7d30667ed565f1d420d3fb1e7c578de35170309c6aa`. Never redeploy it; v3 store points at it.
- The live browser MessageStore `0x03b105fc…e041` is untouched.
- TREE_DEPTH = 20 everywhere; poseidon2(a,b) = `hades_permutation(a, b, 2).r0`; hash_pair = Poseidon builder over two children — golden vectors decide every cross-language question, never memory.
- Bridge/prove wall times: milestone-1 records them; nothing else may run `scarb`/`snforge` while a bridge rebuild or devnet drive is active.
- v1 packing: 7 LE u32 limbs/slot, `0xFFFFFFFF` escapes (lo, hi) u64 pair; values ≥ 2^64 are illegal in lane-1 streams.
- Registry drive shape (from `contracts/stwo_fact_registry/tests/test_fact_registry.cairo`): head = first 4,991 packed slots via `verify_phase1` calldata; tail staged at offset 0; phase 2 gets the re-packed fri section `values[fri_offset .. n_values-1]` (fri_offset = phase-1 return; trailing channel_salt excluded).
- Sepolia invokes: explicit `--l2-gas`/`--l1-data-gas` bounds (sncast auto-estimation ×1.5 breaks the big txs; under-provisioned l1-data-gas REVERTS and burns fees).
- Fixtures workspace (`fixtures/Scarb.toml`) is gas-OFF and separate from the contracts workspaces; contracts build gas-ON.
- Commit after every task; run the affected test suite before each commit.

---

### Task 1: The circuit package (`fixtures/messagezk_scan`)

**Files:**
- Create: `fixtures/messagezk_scan/Scarb.toml`
- Create: `fixtures/messagezk_scan/src/lib.cairo`
- Modify: `fixtures/Scarb.toml` (add workspace member)

**Interfaces:**
- Produces: executable artifact `fixtures/target/dev/messagezk_scan.executable.json`; `main` arg order (46 felts, flattened) consumed by Task 4's args builder verbatim: `[merkle_root, sender_scan_priv, recipient_scan_pub, ephemeral_priv, sender_leaf_index, recipient_leaf_index, s0..s19, r0..r19]`; returns `(commitment, ephemeral_pubkey, merkle_root)`.

- [ ] **Step 1: Add the workspace member** — in `fixtures/Scarb.toml` change `members = ["poseidon_chain"]` to `members = ["poseidon_chain", "messagezk_scan"]`.

- [ ] **Step 2: Write `fixtures/messagezk_scan/Scarb.toml`**

```toml
[package]
name = "messagezk_scan"
version = "0.1.0"
edition = "2024_07"

[[target.executable]]

[dependencies]
cairo_execute = "2.18.0"
```

- [ ] **Step 3: Write `fixtures/messagezk_scan/src/lib.cairo`** — the port. Body logic is verbatim from `~/Apps/messagezk/circuit/src/lib.cairo` (hash_pair via Poseidon builder, poseidon2 via hades, verify_merkle, ec_mul, ecdh — copy those functions unchanged); `main` changes as follows: `commitment`/`ephemeral_pubkey` are no longer parameters; `merkle_root` stays a parameter (the membership reference) and is RETURNED; the two asserts on commitment/ephemeral become computations:

```cairo
#[executable]
fn main(
    merkle_root: felt252,
    sender_scan_priv: felt252,
    recipient_scan_pub: felt252,
    ephemeral_priv: felt252,
    sender_leaf_index: u32,
    recipient_leaf_index: u32,
    s0: felt252, /* … s1..s19 exactly as in the source … */ s19: felt252,
    r0: felt252, /* … r1..r19 … */ r19: felt252,
) -> (felt252, felt252, felt252) {
    let sender_proof = array![s0, /* … */ s19];
    let recipient_proof = array![r0, /* … */ r19];

    let sender_scan_pub = ec_mul(sender_scan_priv);
    verify_merkle(merkle_root, sender_scan_pub, sender_leaf_index, sender_proof.span());
    verify_merkle(merkle_root, recipient_scan_pub, recipient_leaf_index, recipient_proof.span());

    let ephemeral_pubkey = ec_mul(ephemeral_priv);
    let shared_x = ecdh(ephemeral_priv, recipient_scan_pub);
    let commitment = poseidon2(shared_x, 0);

    (commitment, ephemeral_pubkey, merkle_root)
}
```

(Write out all 40 sibling parameters explicitly — the `/* … */` above is display shorthand for THIS document only; the file must enumerate s0..s19, r0..r19.)

- [ ] **Step 4: Build** — `cd fixtures && PATH="$HOME/.local/share/scarb-install/2.18.0/bin:$PATH" scarb build`. Expected: `messagezk_scan.executable.json` under `fixtures/target/dev/`, no warnings about gas (workspace is gas-off).

- [ ] **Step 5: Commit** — `git add fixtures/ && git commit -m "zkmsg task 1: messagezk_scan executable — public tuple moves to outputs"`.

### Task 2: Golden-vector dump executable (`fixtures/zkmsg_vectors`)

Cross-language truth source: a tiny executable printing every primitive the Rust side must match.

**Files:**
- Create: `fixtures/zkmsg_vectors/Scarb.toml` (same shape as Task 1's, name `zkmsg_vectors`)
- Create: `fixtures/zkmsg_vectors/src/lib.cairo`
- Modify: `fixtures/Scarb.toml` (add member)

**Interfaces:**
- Produces: printed felt vector consumed as literal constants by Task 3's Rust tests: `[hash_pair(1,2), poseidon2(3,4), ec_mul(5), ecdh(6, ec_mul(7)), commitment_for(6, ec_mul(7))]`.

- [ ] **Step 1: Write the dump executable** (reuses the same primitive fns copy-pasted from Task 1's lib):

```cairo
#[executable]
fn main() -> (felt252, felt252, felt252, felt252, felt252) {
    let hp = hash_pair(1, 2);
    let p2 = poseidon2(3, 4);
    let pk = ec_mul(5);
    let sh = ecdh(6, ec_mul(7));
    let cm = poseidon2(sh, 0);
    (hp, p2, pk, sh, cm)
}
```

- [ ] **Step 2: Run and record** — `cd fixtures && PATH=… scarb execute -p zkmsg_vectors --target standalone --output standard`. Copy the five printed felts into a comment block AND into Task 3's test constants.

- [ ] **Step 3: Commit** — `git add fixtures/ && git commit -m "zkmsg task 2: cross-language golden vector dump"`.

### Task 3: Rust crate skeleton + crypto module (`tools/zkmsg`)

**Files:**
- Create: `tools/zkmsg/Cargo.toml`, `tools/zkmsg/src/main.rs` (clap skeleton: subcommands init/register/send/inbox/status wired to stubs returning `anyhow::bail!("not implemented")`), `tools/zkmsg/src/crypto.rs`, `tools/zkmsg/src/tree.rs`
- Test: inline `#[cfg(test)]` in `crypto.rs` and `tree.rs`

**Interfaces:**
- Produces (used by Tasks 4, 7, 8, 9):
  - `crypto::scan_keygen() -> (Felt, Felt)` (priv, pub_x via curve mul on the stark generator)
  - `crypto::ec_mul_gen_x(priv: &Felt) -> Felt`
  - `crypto::ecdh_shared_x(priv: &Felt, peer_pub_x: &Felt) -> Result<Felt>` (lift x to a point — either y works, x(k·P) is y-invariant)
  - `crypto::poseidon2(a: &Felt, b: &Felt) -> Felt` (= starknet-crypto `poseidon_hash`)
  - `crypto::hash_pair(l: &Felt, r: &Felt) -> Felt` (whichever starknet-crypto call reproduces the golden vector — decided by the test, not assumed)
  - `crypto::commitment(shared_x: &Felt) -> Felt` (= poseidon2(shared_x, 0))
  - `crypto::encrypt(shared_x: &Felt, plaintext: &[u8]) -> Vec<u8>` / `crypto::decrypt(shared_x: &Felt, blob: &[u8]) -> Result<Vec<u8>>` — HKDF-SHA256(shared_x BE bytes, info=`zkmsg-v1`) → AES-256-GCM, blob = nonce(12) ‖ ct ‖ tag
  - `tree::MerkleTree::new(depth=20)`, `.insert(leaf) -> u32`, `.root()`, `.path(index) -> Vec<Felt>` — mirrors the store's `insert_leaf`/`zero_hash` exactly (zero leaf = 0, zero_hash(l) = hash_pair(zero_hash(l-1), zero_hash(l-1)))

- [ ] **Step 1: Write failing golden tests in `crypto.rs`** — the five Task-2 constants asserted against each function; round-trip test for encrypt/decrypt; tamper test (flip one ct byte → decrypt errs).
- [ ] **Step 2: `cargo test -p zkmsg`** → FAIL (unimplemented).
- [ ] **Step 3: Implement `crypto.rs`** with starknet-crypto/starknet-curve; if `hash_pair` golden doesn't match `poseidon_hash_many([l,r])`, try the two-update sponge equivalent until the vector passes — the vector is the spec.
- [ ] **Step 4: Write failing tree tests** — insert one leaf → `path(0)` verifies against `root()` by folding with `hash_pair` (mirror of the circuit's verify_merkle in the test); two-leaf case; empty-tree root equals `zero_hash(20)`.
- [ ] **Step 5: Implement `tree.rs`** (sparse map `(level, index) -> Felt`, exactly the store's walk).
- [ ] **Step 6: `cargo test -p zkmsg`** → PASS. Commit: `"zkmsg task 3: crate + crypto/tree with Cairo golden vectors"`.

### Task 4: Args builder + MILESTONE-1 GATE (prove + wrap the real circuit)

**Files:**
- Create: `tools/zkmsg/src/args.rs` (`build_circuit_args(tree, sender, recipient, eph_priv) -> Vec<Felt>` in Task 1's exact 46-felt order, serialized as the JSON hex array format of `fixtures/poseidon_chain_args_100.json`; also returns the locally computed expected tuple `(commitment, eph_pub, root)`)
- Create: `tools/zkmsg/tests/milestone1.rs` — `#[ignore]`d integration test that shells the whole gate (run explicitly)
- Create: `docs/superpowers/specs/2026-07-05-zkmsg-milestone1-addendum.md` — records program_hash, inner_root, prove/wrap timings

**Interfaces:**
- Consumes: Task 1 executable, Task 3 crypto/tree.
- Produces: `PROGRAM_HASH` and `INNER_ROOT: [u32; 8]` literals for Task 5's constructor and Task 9's config; the proof/preimage JSON pair pattern for Task 7.

- [ ] **Step 1: Implement `args.rs`** with a unit test: build a 2-user tree from fixed keys, assert the args vector length is 46 and the expected commitment matches `crypto::commitment(ecdh(eph, recipient_pub))`.
- [ ] **Step 2: Run the gate manually** (and encode the same steps in `milestone1.rs`):

```sh
cd fixtures && PATH=… scarb build && cd ..
cargo run -p zkmsg -- dev-args /tmp/mzk_args.json        # dev-only hidden subcommand writing a valid args file from a synthetic 2-user tree
/usr/bin/time -l .prover/proving-utils/target/release/privacy_prove_cairo_bridge \
    prove fixtures/target/dev/messagezk_scan.executable.json \
    /tmp/mzk_cairo_proof.json /tmp/mzk_preimage.json /tmp/mzk_args.json
/usr/bin/time -l .prover/proving-utils/target/release/privacy_prove_cairo_bridge \
    wrap /tmp/mzk_cairo_proof.json /tmp/mzk_preimage.json /tmp/mzk_proof.json
```

Expected: prove succeeds (bootloader accepts ec_op circuit); wrap prints `[wrap 1/3] inner circuit root (consumers whitelist this): [w0..w7]` — RECORD IT; `/tmp/mzk_preimage.json` = `[1, 5, program_hash, commitment, eph_pub, root]` (output_len = 3 outputs + 2) and the three outputs equal the args builder's expected tuple. GATE FAILS if any step errors — STOP and investigate before later tasks.
- [ ] **Step 3: Local circuit-verifier acceptance** — `cd vendor/stwo_cairo_verifier && PATH=… scarb execute -p stwo_circuit_verifier --target standalone --output standard --arguments-file /tmp/mzk_proof.json`. Expected: verification output printed (same pattern as `scripts/prove-and-verify.sh` stage 3).
- [ ] **Step 4: Write the addendum doc** (program_hash, inner_root words, proof slot/value counts from packing, prove/wrap wall+RSS) and commit: `"zkmsg task 4: MILESTONE 1 GREEN — messagezk circuit proves+wraps; program_hash/inner_root pinned"`.

### Task 5: MessageStore v3 contract

**Files:**
- Create: `contracts/messagezk_store/Scarb.toml` (gas-ON starknet-contract package, deps: `starknet 2.18.0`, `stwo_fact_binding = { path = "../stwo_fact_binding" }`; snforge dev-deps mirroring `contracts/stwo_fact_registry`'s)
- Create: `contracts/messagezk_store/src/lib.cairo` (module decl), `src/merkle.cairo` (verbatim port of messagezk `merkle_tree.cairo`: `hash_pair`, `zero_hash`, `TREE_DEPTH`, `verify_proof`), `src/store.cairo`
- Test: `contracts/messagezk_store/tests/test_store.cairo` + `tests/mock_registry.cairo`

**Interfaces:**
- Consumes: `stwo_fact_binding::compute_fact(program_hash, outputs, inner_root)`; Task 4's PROGRAM_HASH/INNER_ROOT (tests use synthetic values — binding to real ones happens at deploy).
- Produces (Task 8/9 call these): `register(handle: felt252, scan_pubkey: felt252)`; `send_message(commitment: felt252, ephemeral_pubkey: felt252, merkle_root: felt252, content: ByteArray)`; views `get_user(handle) -> (ContractAddress, felt252, u32)`, `get_merkle_root() -> felt252`, `get_merkle_path(u32) -> Array<felt252>`, `get_leaf_index(ContractAddress) -> u32`, `is_known_root(felt252) -> bool`, `n_messages() -> u64`; event `MessageSent { #[key] commitment, ephemeral_pubkey, nonce, content }`; constructor `(registry: ContractAddress, program_hash: felt252, inner_root: [u32; 8])`.

Store skeleton (complete the storage/entrypoints from v2's `message_store.cairo`, minus bundles/handshakes/verifier indirection):

```cairo
#[starknet::contract]
mod MessageStoreV3 {
    // storage: registered, scan_pubkeys, handles, leaf_indices, tree_nodes,
    // next_leaf_index, merkle_root, root_history(20 ring), root_history_index,
    // message_nonce, consumed_commitments,
    // + immutables: registry, program_hash, inner_root (8 u32s as felts)
    …
    fn send_message(ref self, commitment, ephemeral_pubkey, merkle_root, content: ByteArray) {
        assert(!self.consumed_commitments.read(commitment), 'commitment consumed');
        assert(is_known_root_internal(@self, merkle_root), 'unknown merkle root');
        let fact = stwo_fact_binding::compute_fact(
            self.program_hash.read(),
            array![commitment, ephemeral_pubkey, merkle_root].span(),
            self.read_inner_root(),
        );
        let registry = IStwoFactRegistryDispatcher { contract_address: self.registry.read() };
        assert(registry.is_valid(fact), 'no proof for this send');
        self.consumed_commitments.write(commitment, true);
        let nonce = self.message_nonce.read();
        self.message_nonce.write(nonce + 1);
        self.emit(MessageSent { commitment, ephemeral_pubkey, nonce, content });
    }
}
```

`register` rejects duplicate handles (`assert(self.handles.read(handle).is_zero())`) and double registration; inserts scan_pubkey as leaf (v2's `insert_leaf` walk verbatim). `IStwoFactRegistry` minimal local interface: just `is_valid`.

- [ ] **Step 1: Write `mock_registry.cairo`** — contract with `set_valid(fact: felt252)`, `is_valid(fact) -> bool`.
- [ ] **Step 2: Write failing snforge tests**: register→root changes & path verifies (port of v2's tests via `merkle::verify_proof`); duplicate handle rejected; send with mock-valid fact emits event + bumps nonce; send with invalid fact panics `'no proof for this send'`; replayed commitment panics `'commitment consumed'`; stale-but-ringed root accepted, unknown root panics; **fact-assembly test**: the fact the store computes for a known tuple equals a direct `compute_fact` call in the test (same inputs) — pins the outputs ordering.
- [ ] **Step 3: `snforge test` in the package** → FAIL, implement, → PASS (expect ~10 tests).
- [ ] **Step 4: Commit** `"zkmsg task 5: MessageStore v3 — pinned lane-1 fact check, replay guard, no set_verifier"`.

### Task 6: v1 packing + proof-stream utilities in Rust

**Files:**
- Create: `tools/zkmsg/src/pack.rs`
- Test: golden against Python — fixture `contracts/stwo_fact_registry/tests/data/poseidon_chain_n100_proof_packed.txt`

**Interfaces:**
- Produces: `pack::pack_v1(values: &[Felt]) -> Vec<Felt>`; `pack::load_proof_json(path) -> Vec<Felt>` (the wrap output is a JSON array of hex felts); consumed by Task 7.

- [ ] **Step 1: Failing golden test** — `pack_v1(load_proof_json("fixtures/poseidon_chain_n100.multiverifier_proof.json"))` equals the committed packed fixture line-for-line (5,147 slots).
- [ ] **Step 2: Port `scripts/pack_proof.py` v1 branch** (literal < 0xFFFFFFFF; escape (lo,hi); reject ≥ 2^64), 7 limbs/slot LE.
- [ ] **Step 3: PASS + commit** `"zkmsg task 6: v1 packing ported, golden vs shipped fixture"`.

### Task 7: Chain driver + the resumable send pipeline

**Files:**
- Create: `tools/zkmsg/src/chain.rs` — `sncast_invoke(account, addr, fn, calldata, gas_bounds) -> TxHash` (subprocess `sncast --json`, parse last JSON line), `wait_receipt`, `trace_retdata(tx) -> Vec<Felt>` (`starknet_traceTransaction`, mirrors `scripts/devnet_drive.py`), `call(addr, fn, calldata)` (`starknet_call`), `get_events(addr, from_block, keys)` (`starknet_getEvents`, chunked continuation)
- Create: `tools/zkmsg/src/pipeline.rs`, `tools/zkmsg/src/state.rs`
- Test: `state.rs` unit tests (checkpoint progression, resume-point selection); `chain.rs` JSON-parsing unit tests on captured sncast output strings

**Interfaces:**
- Consumes: Tasks 3/4/6 modules; bridge binary path + registry drive shape from Global Constraints.
- Produces: `pipeline::run_send(cfg, send_state) -> Result<Fact>` executing steps `[BuildArgs, Prove, Wrap, Pack, Stage{i}, Phase1, Phase2, SendMessage]`, each recorded in `~/.zkmsg/sends/<id>.json` BEFORE execution with tx hashes after; `pipeline::resume(id)`.

- [ ] **Step 1: `state.rs`** — `SendState { id, recipient, plaintext_path, args, expected: (Felt,Felt,Felt), steps: Vec<StepRecord> }`, serde to disk, `next_step()`; tests first.
- [ ] **Step 2: `chain.rs`** with parsing tests (feed canned `sncast --json` output lines).
- [ ] **Step 3: `pipeline.rs`**: prove → assert preimage outputs == expected tuple (abort loudly on mismatch BEFORE spending) → wrap (capture inner_root from stderr, assert == pinned config) → pack → `stage_proof` txs in ≤1,900-slot chunks of the tail (head = first 4,991 slots) → `verify_phase1(proof_id, head, n_tail, n_values)` with gas bounds `l2 ≈ 1.1e9` → fri_offset from `trace_retdata` → re-pack `values[fri_offset..n_values-1]` → `verify_phase2` → fact from retdata → `send_message(commitment, eph, root, ciphertext)`. `proof_id = poseidon2(commitment, 'zkmsg')`.
- [ ] **Step 4: `cargo test -p zkmsg`** (unit layers) PASS; commit `"zkmsg task 7: chain driver + checkpointed send pipeline"`.

### Task 8: CLI wiring (init/register/send/inbox/status)

**Files:**
- Modify: `tools/zkmsg/src/main.rs`
- Create: `tools/zkmsg/src/config.rs` (`~/.zkmsg/{config,keys}.json`, 0600 via `std::os::unix::fs::PermissionsExt`), `tools/zkmsg/src/inbox.rs`

**Interfaces:**
- Consumes: everything above; store ABI from Task 5.
- Produces: user-facing commands per the spec; `inbox::scan(cfg) -> Vec<DecryptedMessage>` (get_events → for each: `ecdh_shared_x(scan_priv, eph_pub)`, match `poseidon2(shared,0) == commitment`, decrypt content ByteArray).

- [ ] **Step 1:** `init` (keygen + config write; refuses to overwrite), `status` (balance via STRK `balanceOf`, config echo, projected send cost line), `register` (invoke + record leaf index from `get_leaf_index` call).
- [ ] **Step 2:** `send <handle> <text>`: resolve `get_user`, fetch root + both paths (`get_merkle_path`), build args (Task 4), encrypt, then `pipeline::run_send`; `--resume <id>`.
- [ ] **Step 3:** `inbox`: ByteArray event decoding (port the length-prefixed felt chunking from `~/Apps/messagezk/src/web/chain-client.ts` `decodeByteArrayFromEvent`), local seen-cache.
- [ ] **Step 4:** `cargo build --release -p zkmsg`; commit `"zkmsg task 8: CLI complete"`.

### Task 9: Sepolia deployment + E2E first message

**Files:**
- Create: `docs/zkmsg-deployment.md` (addresses, tx hashes, costs — the shipping evidence)
- Modify: `tools/zkmsg/src/config.rs` (bake deployed store address as sepolia default)

- [ ] **Step 1:** Declare + deploy `MessageStoreV3` with constructor `(0x0194f440…c6aa, PROGRAM_HASH, INNER_ROOT)` from Task 4's addendum (sncast, account `funded-deployer`). Record class hash + address.
- [ ] **Step 2:** Two identities: `zkmsg init` ×2 (separate `--home` dirs), `register alice` / `register bob` from two funded accounts.
- [ ] **Step 3:** `zkmsg send bob "the first natively-proven private message on Starknet"` from alice — full pipeline against the LIVE registry (~50 STRK; balance check first). Record every tx hash + gas.
- [ ] **Step 4:** `zkmsg inbox` as bob → plaintext decrypts. Negative check: bob's inbox shows nothing for a foreign commitment; alice's inbox does not decrypt her own send (she's not the ECDH recipient) — both asserted manually and recorded.
- [ ] **Step 5:** Write `docs/zkmsg-deployment.md`, update README status bullet + spec addendum; commit `"zkmsg task 9: SHIPPED — first lane-1-verified private message"` and push.

## Self-Review Notes

- Spec coverage: circuit (T1/T4), store incl. replay guard + immutability (T5), packing (T6), pipeline + resume (T7), CLI + inbox trial-ECDH (T8), deployment + honest-properties docs (T9), golden vectors (T2/T3), milestone-1 gate ordering enforced (T4 before T5+).
- inner_root is threaded T4 → T5 constructor → T9 deploy (the spec's "pins (registry, program_hash)" line is corrected by this plan: THREE pinned values).
- Type consistency: `(commitment, ephemeral_pubkey, merkle_root)` tuple order identical in circuit return, preimage outputs, compute_fact span, send_message args, event fields.
