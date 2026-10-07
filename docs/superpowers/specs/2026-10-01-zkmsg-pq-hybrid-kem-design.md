# zkmsg v2: hybrid post-quantum key exchange (ML-KEM-768 + ECDH) (2026-10-01)

Status: **shipped 2026-10-01** on Sepolia alpha, phone and desktop (merged
`09834e0`; deployment and runs in `docs/zkmsg-deployment.md`). The hybrid
content key and recipient tag carry forward unchanged; membership is superseded
by v3 (`2026-10-01-zkmsg-v3-pq-membership-design.md`).

Owner decision: **option B**. The content key and the recipient tag come from a
hybrid of ML-KEM-768 and the existing Stark-curve ECDH. The recipient check
leaves the zk statement, which keeps only sender membership. New prover
contract, new store, everyone re-registers.

This doc is self-contained, so a fresh session can implement it. It covers
the protocol, contracts, Rust reference and iOS client. The desktop client has
its own doc (`2026-10-01-zkmsg-desktop-snip36-pq-design.md`), which waits for
the contracts here to be deployed.

## Why

Every ciphertext stays on a public chain forever, so "harvest now, decrypt
later" is a real threat here, not a theoretical one. Today the content key is
`HKDF(x(e·R))`. A quantum adversary recovers every recipient's scan key `r`
from the `scan_pubkey` in their public `UserRegistered` event, then reads
everything ever sent to them. It can also recompute
`commitment = poseidon(x(r·E), 0)` for every message, so it learns who
received what.

Hybrid rather than ML-KEM alone: if ML-KEM is ever broken, security falls back
to today's ECDH, never below it. This is the shape of X-Wing, Signal PQXDH and
iMessage PQ3.

## Current system (v1, what changes)

The repos at the time of writing:

- zkmsg-ios `phone-send-integration`
- stwo-starknet-verifier `snip36-route`

| Piece | v1 | Where |
|---|---|---|
| Identity | scan key `r`, `R = r·G` (Stark curve, x only) | `tools/zkmsg/core/src/crypto.rs`, `zkmsg-ios/Sources/ZkmsgCore/ZkmsgCrypto.swift` |
| Leaf | `R` (scan pub x) | `contracts/messagezk_store_snip36/src/store.cairo` |
| Content key | `HKDF-SHA256(ikm = x(e·R), info "zkmsg-v1")` → AES-256-GCM, `blob = nonce12 ‖ ct ‖ tag16` | crypto.rs / ZkmsgCrypto.swift |
| Recipient tag | `commitment = poseidon(x(e·R), 0)`, **constrained in the proof** | `contracts/messagezk_store_snip36/src/prover.cairo` |
| Statement | `prove_send`: sender ∈ tree, recipient ∈ tree, commitment from ECDH | prover.cairo |
| Public output | L2→L1 msg to 0, payload `[store, commitment, E, root, content_hash]` | prover.cairo, store.cairo |
| Store check | `poseidon([prover, 0, 5, ...payload]) == proof_facts[8]`, root in last 20, commitment unused | store.cairo |
| `content_hash` | `poseidon(ByteArray serialization of blob)`, a pass-through input (encryption is not proven) | store.cairo `content_hash` |
| Live (alpha) | store `0x002b9c6f…8084f`, prover `0x012b85a4…5346` | `zkmsg-ios/Sources/ZkmsgCore/LiveZkmsgClient.swift` (`ZkmsgSepolia`) |

How verification actually works on the SNIP-36 route is unchanged by this doc,
and so is its trust model. The gateway and every consensus validator verify the
proof. The settling block proof checks only the facts' header. See zkmsg-ios
README, "How a send is verified".

## v2 protocol

### Keys per identity

- Scan key `r` / `R` (Stark curve): kept. It proves sender membership and is
  the ECDH half of the hybrid.
- **KEM key**: ML-KEM-768 (FIPS 203). Store the 64-byte seed `d ‖ z` and derive
  `(dk, ek)` from it. `ek` is 1184 bytes; a ciphertext is 1088 bytes; the
  shared secret is 32 bytes.
- `kem_digest = poseidon_hash_many(byte_array_calldata(ek))`. This is the same
  ByteArray serialization `content_hash` uses, so Cairo computes it the same
  way.

### Leaf

```
leaf = poseidon_hash_many([LEAF_V2, R, kem_digest])      LEAF_V2 = 'zkmsg-leaf-v2' (short string)
```

The tag keeps a leaf from ever being confused with an internal node
(`hash_pair = poseidon_hash_many([l, r])`). Tree depth (20) and the 20-root
history are unchanged. Optionally raise the history to 64: proofs don't expire,
so a bigger window means fewer stale-root re-proves. Decide in phase 2.

### Registration

```
register(handle: felt252, scan_pubkey: felt252, kem_pubkey: ByteArray)
```

- The store computes `kem_digest` from `kem_pubkey` and checks its length is
  exactly 1184 bytes. It inserts `leaf` and stores `(owner, scan_pubkey,
  kem_digest, leaf_index)` per handle.
- It emits `UserRegistered { owner (key), handle, scan_pubkey, leaf_index,
  kem_pubkey }`, so the event data is `[handle, scan_pubkey, leaf_index,
  kem_pubkey ByteArray...]`. `leaf_index` comes before the ByteArray so that
  `data[0..3]` keep v1's positions. The full `ek` goes only in the event,
  which is far cheaper than 38 storage felts.
- One registration per account (`already registered`), so the owner-keyed
  views (`get_kem_digest(owner)`, `get_scan_pubkey(owner)`) are unambiguous.
- `get_user(handle) -> (owner, scan_pubkey, kem_digest, leaf_index)`.
- A sender gets the recipient's `ek` from the event log and **must** check
  that `kem_digest(ek) == get_user(handle).kem_digest` before encapsulating.

### Send (sender)

```
e ←$ [1, n);  E = x(e·G)
ss_ec = x(e·R_recipient)                                       32 bytes BE
(kem_ct, ss_kem) = ML-KEM-768.Encaps(ek_recipient)             1088 B, 32 B
prk   = HKDF-Extract(salt = "zkmsg-v2",
                     ikm  = ss_kem ‖ ss_ec ‖ E ‖ R_recipient ‖ SHA3-256(kem_ct))
k     = HKDF-Expand(prk, "zkmsg-v2 aead", 32)
tag   = HKDF-Expand(prk, "zkmsg-v2 tag", 31)  → felt (31 bytes BE, always < p)
blob  = nonce12 ‖ AES-256-GCM(k, nonce12, plaintext, aad = tag ‖ E) ‖ tag16
content = kem_ct ‖ blob                                        one ByteArray
content_hash = poseidon_hash_many(byte_array_calldata(content))
```

- `commitment := tag`. It is the recipient's detection tag and the store's
  replay key (`consumed_commitments`).
- Binding `E`, `R`, and a hash of `kem_ct` into the input follows X-Wing's
  binding. Fix the exact byte encodings in phase 1 (felts as 32-byte big
  endian) and pin them in the golden vectors.

### Detect and decrypt (recipient), per `MessageSent` event

```
kem_ct, blob = content[..1088], content[1088..]
ss_ec  = x(r·E)
ss_kem = ML-KEM-768.Decaps(dk, kem_ct)       (implicit rejection: wrong key → random, never an error)
recompute prk, tag;  tag == commitment ?  → ours: derive k, AES-GCM open with aad = tag ‖ E
```

Cost per event: one Stark-curve multiplication plus one ML-KEM decapsulation
(tens of µs). The scan loop and checkpoints are unchanged.

### Privacy properties

- **Content:** hybrid, so an attacker must break both ML-KEM and ECDH.
- **Recipient:** the tag needs both shared secrets. ML-KEM ciphertexts are
  believed not to reveal the public key they were made for (ANO-CCA;
  Grubbs–Maram–Paterson 2022), so `kem_ct` doesn't identify the recipient.
- **Sender:** unchanged. The S-two proof is hash-based and zero-knowledge by
  design (heuristic blinding; corrected 2026-10-07, see `tools/zkmsg/README.md`).
  - A quantum adversary can forge *membership*: compute a member's `r` and
    prove as them. That is spam or impersonation of "a member sent this". It
    breaks neither confidentiality nor recipient privacy.
  - Making membership post-quantum needs a hash-based leaf secret. Out of
    scope; record it as known.
- **Lost guarantee:** "the recipient is a member" is no longer inside the
  proof. It was weak anyway, because `content_hash` was already pass-through:
  a sender could always attach garbage. A sender can now also address a
  non-member, and only harms themselves.

## Contracts (phase 2)

New package `contracts/messagezk_store_pq` (copy `messagezk_store_snip36`).
It needs Scarb 2.18: the binary is in `snip36-spike/scarb-v2.18.0-*`, and
`get_execution_info_v3_syscall` is gated to sierra 1.8.

`ZkmsgSendProverV2.prove_send` takes:

- public: `store`, `content_hash`, `commitment`, `ephemeral_pubkey`,
  `merkle_root`
- private: `sender_scan_priv`, `sender_kem_digest`, `sender_leaf_index`,
  `sender_path`

What it does:

- `R_s = x(sender_scan_priv·G)`, `leaf = poseidon([LEAF_V2, R_s, sender_kem_digest])`,
  then `assert verify_proof(root, leaf, index, path)`.
- Emit the same 5-felt payload to 0. `commitment` and `E` pass through,
  bound by the message hash.
- No recipient inputs, no ECDH. That means fewer steps than v1 (one fewer EC
  multiplication and one fewer path), so proving should be faster. Measure it.

`MessageStoreV2PQ` is the snip36 store with:

- the v2 leaf,
- the `register` signature and event above,
- a `get_user` that returns the 4-tuple,
- `send_message(commitment, ephemeral_pubkey, merkle_root, content: ByteArray)`.
  The signature is unchanged; `content` now carries `kem_ct ‖ blob`. Optionally
  require `content.len() >= 1088 + 12 + 16`.

Facts checking is identical to v1. The facts layout is
`[PROOF1, VIRTUAL_SNOS, program_hash, VIRTUAL_SNOS0, block_number, block_hash,
os_config_hash, n_messages, message_hash]`: check `n_messages == 1` and
`facts[8] == poseidon([prover, 0, 5, ...payload])`.

snforge tests:
- leaf vector, register and event shape, the `kem_digest` length check;
- send with valid facts, wrong facts, a replayed commitment, a stale root;
- a fixture lifted from a real phone proof, as v1's `Snip36Tests` did.

Deploy on Sepolia alpha: declare both, deploy the prover, deploy the store
pinned to the prover. Record addresses, class hashes and the deploy block in
`docs/zkmsg-deployment.md`. **This unblocks the desktop doc.**

## Rust reference (phase 1, in `tools/zkmsg/core`)

- Add the `ml-kem` crate (RustCrypto, FIPS 203 final), plus the `sha3` already
  in the workspace.
- `crypto.rs`: `kem_keygen_from_seed`, `kem_digest`, `leaf_v2`, `encap_v2`,
  `decap_tag_v2`, `seal_v2` / `open_v2`. Keep the v1 functions until phase 4
  cleanup.
- Extend `examples/export_vectors` to add v2 vectors:
  - seed → `ek`, `dk`, `kem_digest`, leaf;
  - a full send with a fixed `e`, a fixed nonce, and **deterministic
    encapsulation randomness**, which `ml-kem` exposes for tests;
  - `kem_ct`, `prk`, `k`, `tag`, the blob and `content_hash`;
  - a decaps vector.

  Both clients pin to these.

## iOS client (phase 3, zkmsg-ios)

1. **Phase 0 spike (do first):** check that CryptoKit's `MLKEM768` (iOS 26 /
   macOS 26):
   - (a) derives the same `ek` from a 64-byte seed as RustCrypto,
   - (b) decapsulates the Rust vector's `kem_ct` to the same secret.

   If CryptoKit can't take a seed or doesn't match, use RustCrypto `ml-kem`
   through `zkmsg_ffi` (already linked) instead. Either way, the golden
   vectors decide.

   Raising the deployment target (16.0 → 26.0) and the package platform
   (macOS 14 → 26) is acceptable: proving already needs a recent phone, and
   the dev Mac runs macOS 26.
2. **Identity:**
   - Add a `ZkmsgIdentity.Slot.kemSeed = "kem.seed"`, generated in
     `createIfNeeded` for new identities and lazily for existing ones.
   - Bump the backup bundle to v2 to carry the KEM seed (`ZkmsgBackupKit`,
     `zkmsgtool`).
   - Each profile already has its own Keychain service, so nothing else
     changes there.
3. **Crypto:** `ZkmsgCrypto` v2, mirroring the Rust functions, with tests
   against the vectors.
4. **Registration:**
   - `LiveZkmsgClient.register` sends the `ek` ByteArray, and the burner
     flow's register step does the same.
   - `RegistrationLog` parses the v2 event and keeps `ek` per handle.
   - Recipients are resolved through `get_user`, and the digest is checked
     against the event's `ek`.
5. **Send** (`VirtualSend.swift`):
   - `prepareSend` moves to v2: in Swift, or in `zkmsg_ffi` if the KEM lives
     there.
   - `proveSendCalldata` builds the new layout.
   - The witness drops the recipient path.
   - `Snip36.payload` is unchanged.
   - Keep the stale-root check, the facts check and the publish-hash-first
     rules as they are.
6. **Inbox** (`InboxScanner`): split `content`, run the v2 detect-and-decrypt.
7. **Constants:** `ZkmsgSepolia.store`, `.prover`, `.storeDeploymentBlock` move
   to the v2 deployment. The app reads only the v2 store: older stores are
   dropped, matching the 2026-09-30 decision to stop reading V3.
8. **Device run:**
   - register two profiles, send, decrypt;
   - record wall time and fee;
   - run the full `swift test`, and a live test gated on `SEPOLIA_RPC_URL`.

## Phases and gates

| Phase | Output | Gate |
|---|---|---|
| 0 | CryptoKit ↔ RustCrypto ML-KEM interop note | seed→ek and decaps match |
| 1 | Rust v2 crypto + vectors | `cargo test -p zkmsg-core`, vectors exported |
| 2 | Contracts, snforge, Sepolia alpha deploy | addresses in `zkmsg-deployment.md` |
| 3 | iOS v2 end to end | phone→phone send decrypts; `swift test` green |
| 4 | Desktop (separate doc), cleanup of v1 code | desktop doc gates |

## Costs to measure (phase 3)

- Register: the event carries `ek`, about 1.2 KB more data.
- Send: `kem_ct` adds 1088 bytes of calldata, small next to the ~300 KB proof.
  Expect the fee to stay near 1.6 STRK.
- Proving time: expected lower than v1's ~280 s on an iPhone 14 Pro.

## Out of scope / recorded

- Post-quantum sender membership (needs a hash-based identity secret).
- PQ account signatures (Starknet account abstraction; unrelated to message
  confidentiality).
- The trust model of SNIP-36 verification (unchanged; see the README).
