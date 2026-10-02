# zkmsg v3: hash-based (post-quantum) membership (2026-10-01, planned)

Status: **planned, not started.** Comes after v2 (`2026-10-01-zkmsg-pq-hybrid-kem-design.md`)
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
