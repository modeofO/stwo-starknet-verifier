# zkmsg — the messagezk port onto lane 1, as a native Rust app (2026-07-05)

Approved design. The full messagezk private-messaging model (sender/recipient
membership in a registered-user Merkle tree + ephemeral ECDH + Poseidon
commitment), proven client-side through the lane-1 recursion pipeline and
enforced on-chain against the LIVE Sepolia `StwoFactRegistry`
(`0x0194f44002b4af71e58ba7d30667ed565f1d420d3fb1e7c578de35170309c6aa`) —
replacing the browser prover with a native Rust CLI.

Decisions taken during brainstorming (owner-confirmed):

- **Full circuit port** (not the trimmed sealed-board demo; that idea is
  parked as its own future product — "provable commitments for public
  trust").
- **Straight to Sepolia** (devnet only as incidental tooling).
- **Fresh MessageStore v3** in this repo; the live browser MessageStore
  (`0x03b105fc…e041`) is untouched. No pluggable verifier: the lane-1 fact
  check is pinned at construction (closes v2's un-gated `set_verifier` rug
  vector).
- **Circuit-native content crypto for v1** (HKDF(shared_x) → AES-256-GCM);
  the double-ratchet session layer is deferred, schema kept portable.
- **Approach A app architecture**: thin Rust orchestrator; subprocess to
  the bridge for prove/wrap and to sncast for txs; v1 felt packing ported
  to Rust.

## Why lane 1 fits this exactly

- The recursion route's blake2s client leg supports `ec_op`/`pedersen` —
  the messagezk circuit's stark-curve ECDH is provable here and NEVER
  provable under lane 2's contract-legal config.
- Recursion normalizes every app proof to the same multiverifier shape:
  on-chain cost is FLAT in circuit size (measured on the shipped fixture:
  156-slot stage tx + 873.8M + 815.7M L2 gas ≈ ~50 STRK at spiky Sepolia
  prices). Only client-side prove/wrap time grows.
- The fact statement `(program_hash, outputs)` is exactly messagezk's
  public-inputs tuple once the circuit RETURNS them.

## Component 1 — the circuit (`fixtures/messagezk_scan`)

Port of `~/Apps/messagezk/circuit/src/lib.cairo`, one structural change:
under the privacy bootloader, program ARGUMENTS are witness and OUTPUTS are
public — so the public tuple moves from asserted args to returned outputs.

```cairo
#[executable]
fn main(
    merkle_root: felt252,          // witness arg, returned as output
    sender_scan_priv: felt252,     // witness
    recipient_scan_pub: felt252,   // witness
    ephemeral_priv: felt252,       // witness
    sender_leaf_index: u32,        // witness
    recipient_leaf_index: u32,     // witness
    s0..s19: felt252,              // witness (sender Merkle path, depth 20)
    r0..r19: felt252,              // witness (recipient Merkle path)
) -> (felt252, felt252, felt252)   // (commitment, ephemeral_pubkey, merkle_root)
```

Body verbatim from messagezk (hash_pair = poseidon builder over two
children; poseidon2 = hades_permutation(a, b, 2).r0; TREE_DEPTH = 20):
derive `sender_scan_pub = ec_mul(sender_scan_priv)`; verify sender AND
recipient membership against `merkle_root`; `ephemeral_pubkey =
ec_mul(ephemeral_priv)` (computed, not asserted); `shared_x =
ecdh(ephemeral_priv, recipient_scan_pub)`; `commitment =
poseidon2(shared_x, 0)` (computed, not asserted). Return the tuple.

**Milestone-1 gate (the only unproven step in the design):** prove this
executable with the bridge (`prove` — Blake2sM31 privacy params, witness
never leaves), `wrap` it proof-only, and assert the multiverifier proof is
accepted by the deployable circuit-verifier contract in snforge, with the
bootloader output preimage carrying exactly
`[n_tasks=1, output_len, program_hash, (commitment, eph, root)]`. No
contract or app code before this passes. Also record prove/wrap wall time
and peak RSS (product-facing numbers).

## Component 2 — MessageStore v3 (`contracts/messagezk_store`)

Fork of messagezk v2's `message_store.cairo`, same tree machinery, new
verification path, slimmer v1 schema:

- **Kept identical**: depth-20 incremental Poseidon Merkle tree
  (`tree_nodes`, `zero_hash`, `insert_leaf`), 20-slot root-history ring
  buffer + `is_known_root` (absorbs the registration race between
  prove-time and send-time), `handles` map, `leaf_indices` (with the
  registered-guard), `get_merkle_path`, `message_nonce`, `MessageSent`
  event carrying `(commitment [key], ephemeral_pubkey, nonce, content)`.
- **Changed**:
  - `register(handle: felt252, scan_pubkey: felt252)` replaces
    `register_bundle` (X3DH bundle fields deferred with the ratchet; new
    fields come back in a v4 when that layer ports). Handle collision =
    reject (v2 silently overwrote — fix it). One registration per address.
  - `send_message(commitment, ephemeral_pubkey, merkle_root, content)` —
    NO proof param. Requires `is_known_root(merkle_root)` and
    `registry.is_valid(fact)` where
    `fact = stwo_fact_binding::compute_fact(CIRCUIT_PROGRAM_HASH,
    [commitment, ephemeral_pubkey, merkle_root].span(), …)` (the crate
    bakes the multiverifier inner root and reproduces the live Sepolia
    fact from application data — proven by its existing test).
  - Constructor pins `(registry_address, circuit_program_hash,
    inner_root)` — the inner cairo-verifier circuit root is app-shape
    dependent and printed by the wrap stage; all three are immutable. No
    owner, no setters. `set_verifier` does not exist.
  - `send_handshake` dropped (v1 has no ratchet).
  - **Replay guard**: `consumed_commitments: Map<felt252, bool>` — a
    registered fact is world-readable, so without this anyone could
    re-send someone else's `(commitment, eph, root)` tuple with junk
    content once it's on-chain. First send consumes the commitment.
- Views: `get_user(handle) -> (address, scan_pubkey, leaf_index)`,
  `get_merkle_root`, `get_merkle_path`, `get_leaf_index`,
  `is_known_root`, `n_messages`.

## Component 3 — the Rust app (`tools/zkmsg`, binary `zkmsg`)

Standalone crate (NOT in the .prover workspace). Subprocess seams:
bridge binary for `prove`/`wrap`; `sncast --json` for declare/deploy/
invoke/call (reusing the account file and the runbook's explicit gas
bounds — sncast auto-estimation ×1.5 overruns the invoke bound on the
big verify txs); raw JSON-RPC (`ureq`) for `starknet_getEvents` and
receipt polling.

Native Rust pieces:
- **v1 felt packing** ported from `scripts/pack_proof.py` (7 u32 limbs
  per slot, `0xFFFFFFFF` u64 escape), golden-tested against the Python
  output for the shipped fixture proof.
- **Crypto** (`starknet-crypto` + RustCrypto): stark-curve keygen and
  ECDH shared-x (MUST match `core::ec` — cross-language golden vectors),
  `poseidon2` = Hades permutation (matches `hades_permutation(a,b,2)`),
  `poseidon_hash_span` for fact assembly, HKDF-SHA256(shared_x,
  info="zkmsg-v1") → AES-256-GCM for content (random 96-bit nonce,
  ciphertext = nonce ‖ ct ‖ tag as the event ByteArray).
- **State** in `~/.zkmsg/`: `keys.json` (scan keypair, 0600),
  `config.json` (network, account name, store + registry addresses),
  `sends/<id>.json` pipeline checkpoints.

Commands:
- `init` — keygen; prints scan pubkey.
- `register <handle>` — `register` tx; records leaf index.
- `send <handle> <text>` — resolve recipient via `get_user`, fetch both
  Merkle paths + current root, fresh ephemeral key, write args JSON,
  then: bridge prove → assert preimage outputs == locally computed
  `(C, eph_pub, root)` → bridge wrap → pack v1 → stage chunks →
  phase 1 → phase 2 → `send_message(C, eph_pub, root, ciphertext)`.
  Every step checkpointed BEFORE it runs; `--resume` re-enters at the
  first incomplete step (a mid-pipeline failure never re-pays completed
  ~30-STRK txs). Refuses to start if the account balance < projected
  cost unless `--force`.
- `inbox` — `starknet_getEvents` over `MessageSent`, trial-ECDH each
  `(commitment, ephemeral_pubkey)` with the local scan key
  (`poseidon2(ecdh(scan_priv, eph_pub), 0) == commitment`), decrypt
  hits, cache locally.
- `status` — config, balance, projected per-send cost, store/registry
  addresses + `is_valid` sanity on a known fact.

## Deployment order (Sepolia)

1. Milestone-1 gate passes locally; extract `program_hash` from the
   bootloader preimage.
2. Declare + deploy `MessageStore` v3 pinning
   (live registry, program_hash). Record addresses in this spec's
   addendum + the app's default config.
3. Two identities (both funded from the existing account): `init` +
   `register` ×2, `send` A→B (~50 STRK), `inbox` at B decrypts. That
   run's tx hashes are the shipping evidence.

## Honest properties (README section, verbatim commitments)

- Recipient anonymity: cryptographic (the circuit's purpose).
- Sender anonymity: NOT in v1 — send + verify txs come from the sender's
  account (same model as messagezk's live V1; burner accounts are the
  shared V2 fix).
- Scan-key compromise exposes v1 content (not just detection metadata as
  in ratchet-messagezk) — fixed when the ratchet layer ports.
- Stwo is not formally ZK; witnesses ride in public calldata permanently.
  Scan keys are the app's only long-lived witness secret — same exposure
  class messagezk already accepts; rotate by re-registering.
- ~50 STRK per send at spiky Sepolia prices; flat in circuit size.

## Testing

- Golden cross-language vectors (generated once from Cairo, asserted in
  Rust unit tests): poseidon2, hash_pair, ECDH shared-x, ec_mul pubkey
  derivation, commitment, v1 packing vs `pack_proof.py`.
- snforge (`contracts/messagezk_store`): registration/tree/root-history
  ports of v2's tests; handle collision; `send_message` against a mock
  registry (both verdicts); commitment replay rejected; fact input
  assembly cross-checked against `stwo_fact_binding`'s live-fact test
  pattern.
- Milestone-1 snforge acceptance of the wrapped circuit proof.
- E2E = the Sepolia deployment run above.

## Out of scope (parked)

- Double-ratchet session layer + handshakes (v4 store schema).
- Sender-anonymity burner accounts; Cartridge Controller integration
  (paymaster envelope already quantified in docs/architecture.md).
- Browser interop; upstreaming v3 into the messagezk repo.
- The sealed-board product (separate future spec).
- Lane-2 migration (same fact definition; store is redeployed, not
  upgraded, if v3 ever moves — immutability is the point).
