# zkmsg v3: hash-based (post-quantum) membership (2026-10-01)

Status: **in progress** (branch `pq-v3`). The pinned encodings and ABI are
in "v3 pinned encodings and ABI" below. Comes after v2 (`2026-10-01-zkmsg-pq-hybrid-kem-design.md`)
ships on both clients.

## The gap v2 leaves

v2 makes message confidentiality and recipient privacy hybrid post-quantum
(ML-KEM-768 + ECDH). One property stays classical: **membership**.

`prove_send` proves the sender knows `r` such that `R = r·G` and
`poseidon([LEAF_V2, R, kem_digest])` is a leaf under the root. `R` is public:
it's in every `UserRegistered` event. A quantum adversary recovers `r` from
`R` (Shor) and can then prove membership as any member.

What that buys the adversary:
- **It can** forge "a member sent this". That means spam, and passing as a
  member to a recipient who trusts the tree.
- **It cannot** read messages (v2 also needs the ML-KEM `dk`, which never
  appears on chain).
- **It cannot** learn recipients, or tell which member actually sent a real
  message (the proof is zero-knowledge).

This is an integrity gap, not a confidentiality one. And it isn't a "harvest
now" risk: forgery needs the quantum computer at sending time.

## v3 change

Give each identity a **membership secret** `m` (32 random bytes, reduced to a
felt) that is never published. Commit to it in the leaf with Poseidon:

```
m_commit = poseidon_hash_many([MEMBER_V3, m])
leaf     = poseidon_hash_many([LEAF_V3, R, kem_digest, m_commit])
```

`prove_send` drops the elliptic-curve step: it proves knowledge of `m` (and
`R`, `kem_digest`) whose leaf is under the root. Security then rests on
Poseidon preimage resistance, which is believed to hold against quantum
computers. The S-two proof itself is already hash-based, so the whole
membership argument becomes post-quantum.

Side effects:
- **Cheaper:** one EC scalar multiplication in Cairo is replaced by one
  Poseidon call. Small next to the virtual OS's fixed cost (v2 measured
  ~143k steps), so expect the fee to stay about the same.
- **Membership no longer needs the scan key.** That splits the two roles:
  - `r` is used only for the ECDH half of decryption;
  - `m` is used only for proving membership.
- **Enables rate limits later.** With `m`, a per-member nullifier
  (`poseidon([NULLIFIER, m, epoch])`) becomes possible: "one message per
  member per epoch" without revealing who. This is a known anti-spam tool;
  it isn't in v3's scope, but v3's leaf makes it possible.

Registration carries `m_commit` alongside `scan_pubkey` and `kem_pubkey`. A
new store and prover follow, and everyone registers again, as with every
leaf change.

Keys and backup: `m` is a new secret slot (`member.secret`) on the phone,
`member_secret` in desktop `keys.json`, and part of the backup bundle (v3).

## v3 pinned encodings and ABI

Agreed in review (2026-10-01). These override any looser wording above.

### The membership secret `m`

- Sample 32 random bytes and clear the top 5 bits of byte 0, so
  `m < 2^251 < p`: always a felt, uniform over 251 bits, with no modular
  reduction and no bias. Reject `m = 0`.
- Stored form: the 32-byte big-endian value.
  - Phone: Keychain slot `member.secret` holds the raw 32 bytes.
  - Desktop: `keys.json` `member_secret` holds `"0x"` + 64 lowercase hex.
  - Loaders reject a value `>= 2^251` and `0`.
- Fresh per identity and per store. `m_commit` is public and stable, so
  reusing `m` links registrations publicly. Clients never reuse one, and the
  store does not police it.
- Grover against `m_commit` costs about 2^125, matching Poseidon's own
  security level.

### `m` is the send credential

- Whoever holds `m` (with the public `R` and `kem_digest`) can prove
  membership as that member.
- The scan key alone can no longer send. It only decrypts, together with
  the KEM key.
- **Losing `m`** loses the ability to send, but not to read.
- **Leaking `m`** lets someone send as you, but not read your mail.
- So `m` gets the same custody as the other secrets:
  - phone: `member.secret` lives in the profile's Keychain service, with
    the same protection class as `scan.private` and `kem.seed`;
  - desktop: `keys.json` stays 0600.

### Hashes

```
MEMBER_V3 = 'zkmsg-member-v3'      (Cairo short string)
LEAF_V3   = 'zkmsg-leaf-v3'        (Cairo short string)
m_commit  = poseidon_hash_many([MEMBER_V3, m])
leaf      = poseidon_hash_many([LEAF_V3, R, kem_digest, m_commit])
```

`kem_digest` is v2's: Poseidon over the ByteArray serialization of `ek`.
Tree depth (20) and `hash_pair` are unchanged. The four-element leaf
cannot collide with a two-element internal node or a three-element v2
leaf.

### Store `MessageStoreV3`

- `register(handle, scan_pubkey, kem_pubkey: ByteArray, m_commit)`:
  - `kem_pubkey` must be exactly 1184 bytes;
  - `m_commit != 0`;
  - one registration per account, first-come handles (as v2).
- `UserRegistered` keys `[selector, owner]`. Data:
  `[handle, scan_pubkey, leaf_index, m_commit, kem_pubkey ByteArray...]`.
  The fixed fields stay ahead of the ByteArray, and `data[0..3]` keep the
  v1/v2 positions.
- `get_user(handle) -> (owner, scan_pubkey, kem_digest, m_commit, leaf_index)`.
- `get_kem_digest(owner)`, `get_m_commit(owner)`.
- `send_message`, the facts check, `content >= 1116` bytes, and the 64-root
  history are unchanged from v2.

### Prover `ZkmsgSendProverV3.prove_send`

- Public: `store, content_hash, commitment, ephemeral_pubkey, merkle_root`.
- Private: `sender_scan_pub (R), sender_kem_digest, member_secret (m),
  sender_leaf_index, sender_path (20)`.
- It computes `m_commit` and the leaf by Poseidon, asserts the path folds
  to the root, and emits the v2 payload
  `[store, commitment, E, root, content_hash]` to address 0.
- No EC operation, and the scan private key never enters the proof.
  `R` and `kem_digest` are bound by the leaf; only the member knows `m`.

### Clients

- **Before proving:** the sender's `scan_pubkey`, `kem_digest` and
  `m_commit` must all equal `get_user(sender handle)`, and the recomputed
  leaf must fold to the root.
- **Phone backup bundle v3** carries `member.secret`, and v3 import
  requires it. A v2 bundle still imports, and `createIfNeeded` then adds a
  fresh `m`.
- **Desktop:** like `kem_seed`, never mint a `member_secret` for a profile
  that already holds a v3 handle (its on-chain `m_commit` commits to a lost
  `m`). `zkmsgtool` warns when `keys.json` has no `member_secret`.

## Sender signature (optional, if inbox threading is built)

Threading the inbox by sender would put an authenticated sender inside the
**encrypted** body (the chain never sees it):

- the sender signs `(commitment, content_hash)`;
- the recipient verifies the signature after decrypting.

**Priority is low.** A quantum adversary doesn't extract anything from the
proof: it's zero-knowledge and the witness never leaves the sender. It would
attack the sender's *public* signing key and forge new signatures. That only
lets it impersonate a known sender to a recipient, and only once the quantum
computer exists (no harvest-now risk). Classical ECDSA would therefore be
acceptable at first. If it's built, use a hybrid of ECDSA and ML-DSA-65
(CryptoKit in iOS 26; RustCrypto `ml-dsa`), costing about 3.3 KB of signature
plus about 1.9 KB of public key per message, or a per-conversation key sent
once.

## Not planned

**Post-quantum Starknet account signatures (ML-DSA in `__validate__`).**
- Verifying ML-DSA in Cairo would cost far more than ECDSA.
- A forger could only spend a burner's leftover fee or send as that account.
  It's Starknet's and Ethereum's protocol problem first.
- Revisit if Starknet ships native PQ account support.
