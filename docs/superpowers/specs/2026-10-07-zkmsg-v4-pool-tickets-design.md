# zkmsg v4: the pool account and single-send tickets (2026-10-07)

Status: **shipped 2026-10-07** on Sepolia alpha, desktop only (pool
`ZkmsgPoolV4`, prover `ZkmsgSendProverV4`, virtual sender
`ZkmsgVirtualSenderV4`; addresses, transactions and the live run in
`docs/zkmsg-deployment.md`, "zkmsg v4"). Builds on v3
(`2026-10-01-zkmsg-v3-pq-membership-design.md`): the leaf, registration and
the message envelope are v3's, unchanged. The phone (zkmsg-ios) has not been
ported; its golden vectors are `tools/zkmsg/core/testdata/v4_vectors.json`.

## The gap v3 leaves

The 2026-10 red team: every v1–v3 send was published and paid for by an
ordinary account, and that account was the one that registered the
sender's handle. The `UserRegistered` event names its `owner`; the publish
transaction names its `sender_address`. They were equal, so the chain said
who sent each message, whatever the zero-knowledge proof hid. Separately,
send preparation read `get_nonce` / `balance_of` of that same account, so
the RPC provider saw it too.

Constraints from the owner:
- No operator-paid fees. The pool must never be able to spend more than
  users paid in.
- Payment can't happen at send time from the user's account (that re-links).
- No "prepay N messages" account balance; single-send tickets, bought any
  time in any quantity, are acceptable.

## v4 change

Three contracts (`contracts/zkmsg_pool_v4`):

1. **`ZkmsgPoolV4` is the store and an account.** A send is an INVOKE v3
   with `sender_address` = the pool and an empty signature. The pool's
   `__validate__` admits exactly one call, to its own `send_message`, and
   checks everything `__execute__` would: the SNIP-36 facts attest the v4
   message hash for this call (with the epoch the pool derives from the
   facts' base block and the quota it was built with), the member root is
   known, the envelope is unused, the quota nullifier is unspent, the epoch
   is fresh, the ticket root is known and the ticket unspent, the content is
   within [1116, 8192] bytes, and the fee fields are within policy. Then it
   **burns the ticket** (validate's writes survive an execute revert).
   Blockifier forbids `call_contract` to other contracts in validate, which
   is why store and account must be one contract.
2. **`ZkmsgSendProverV4`** (runs only in the virtual OS) proves v3
   membership plus `slot < quota`, the quota nullifier, and knowledge of a
   ticket secret under the ticket root, and emits one L2→L1 message.
3. **`ZkmsgVirtualSenderV4`** is the shared account every member's virtual
   `prove_send` runs from: any signature, zero fees only (so it can never
   transact for real and its nonce stays 0), forwards its calls.

### Tickets

`buy_tickets(leaves)` takes `ticket_price` STRK per leaf (approve first) and
appends each `leaf = poseidon([TICKET_V4, t])` to an append-only depth-20
ticket tree, emitting `TicketBought { leaf, index }`. Every root the tree
ever had stays valid (no eviction race). A send reveals only
`ticket_nullifier = poseidon([TICKET_NULL_V4, store, t])`.

Solvency: the fee policy's `max_fee` is checked ≤ `ticket_price` at
construction, and validate caps `Σ max_amount × max_price + tip × l2` at
`max_fee`. So total fees ≤ tickets burnt × price ≤ tickets bought × price.
Surplus stays in the pool; there is no owner, no withdraw and no refund (a
refund needs a destination, which re-links the send).

### Quota

`nullifier = poseidon([NULLIFIER_V4, store, m, epoch, slot])`, `slot <
quota`, `epoch = base_block / epoch_blocks`. A member gets `quota` sends per
epoch; two sends of one member are unlinkable. The pool rejects epochs more
than `max_epoch_lag` behind the (100-rounded) current block, so an old base
block can't mint fresh quota.

### Replay key (red team F9)

The consumed set is keyed on `poseidon([commitment, content_hash])`, not the
commitment alone, so front-running a pending send with its commitment over
other content no longer blocks it.

## Deployed parameters

`ticket_price` 3 STRK; `epoch_blocks` 5,000 (~2.4 h); `max_epoch_lag` 1;
`quota` 10; fee policy `max_fee` 3 STRK, `max_tip` 1e9 fri, `min_l2_gas`
100M. A publish uses ~79.5M L2 gas (~1.43 STRK at 18 gfri). The client sets
L2 100M at min(2× current, what the ticket allows) and refuses to send if
that is under 1.1× the current price.

## Client (tools/zkmsg)

- **Prepare** at one block N: all `UserRegistered` and all `TicketBought`
  events up to N, rebuilt locally and checked against `get_merkle_root` and
  `get_ticket_root` at N; `rate_limit()` at N; the virtual sender's nonce at
  N. No request names a handle, leaf, ticket or the user's account (a unit
  test records them all). Pick an unspent ticket (`tickets.json`, 0600),
  take the epoch's next slot (`quota.json`), reserve the ticket.
- **Prove**: the virtual invoke from the shared sender, unsigned, zero fee;
  `snip36-prove` gets it on stdin. Check the facts. Save proof and state.
  A prove failure releases the ticket.
- **Publish**: unsigned INVOKE v3 from the pool, nonce from the chain,
  bounds per policy, hash saved before the POST. A nonce rejection resends
  the same proof at the next nonce. A validate refusal of `ticket spent`
  marks the ticket spent; `nullifier spent`, `envelope consumed`,
  `stale epoch` and `unknown merkle root` release it and retire the send.
  Accepted (or reverted after validate) marks the ticket spent.
- **Tickets**: `buy-tickets n` writes fresh secrets before approve + buy
  (from the profile's account: the chain shows that account bought tickets,
  never which sends used them), then settles indices from the event tree.
- **migrate-store** mints a fresh scan key, ML-KEM seed and member secret
  (keys reused across stores would link identities).

## v4 pinned encodings

```
nullifier        = poseidon_hash_many([NULLIFIER_V4, store, m, epoch, slot])
ticket leaf      = poseidon_hash_many([TICKET_V4, t])
ticket nullifier = poseidon_hash_many([TICKET_NULL_V4, store, t])
envelope key     = poseidon_hash_many([commitment, content_hash])
payload          = [store, commitment, E, merkle_root, content_hash,
                    nullifier, epoch, quota, ticket_root, ticket_nullifier]
message hash     = poseidon_hash_many([prover, 0, 10, ...payload])
prove_send       = (store, content_hash, commitment, E, merkle_root, epoch,
                    quota, ticket_root, scan_pub, kem_digest, m, slot,
                    leaf_index, path: Span[20], t, ticket_index,
                    ticket_path: Span[20])
send_message     = (commitment, E, merkle_root, nullifier, ticket_root,
                    ticket_nullifier, content: ByteArray)
```

`t` has `m`'s form (32 bytes, top 5 bits clear, nonzero). Domain tags are
Cairo short strings: `'zkmsg-nullifier-v4'`, `'zkmsg-ticket-v4'`,
`'zkmsg-ticket-null-v4'`.

## Client-side additions (same day, both clients)

- **Padding**: inside the AEAD, `padded = u16be(len) ‖ plaintext ‖ 0…`,
  `|padded| ∈ {256, 1024, 4096}` (smallest that fits; > 4094 refused);
  open requires `len ≤ |padded| − 2` and an all-zero tail. HKDF labels
  "zkmsg-v4" / "zkmsg-v4 aead" / "zkmsg-v4 tag" (v2's construction
  otherwise). Content ∈ {1372, 2140, 5212} bytes. On-chain enforcement of
  bucket sizes needs a pool redeploy (pending decision); the deployed pool
  accepts 1116..8192.
- **Inbox**: a tag match that fails to open or unpad is dropped silently.
- **Transaction policy** (`txpolicy.rs`): per kind fixed amounts (publish
  L2 100M, register 30M, `[approve, buy_tickets]` 80M; L1 data 4,096; L1
  0), price bound `round_up_2sf(ceil(1.5 × price))`, publish L2 bound
  capped at `round_down_2sf((max_fee − l1_data_cost)/l2 − tip)` and
  refused under `ceil(1.1 × price)`, tip 1e8, L1 DA, empty paymaster and
  deployment data, member signature `[r, s]`.
- **Schedule**: base `= ⌊(head − 10)/32⌋·32`; publish when head
  `≥ base + 90 + j`, `j ∈ [0, 20]` uniform. Epoch (5,000 blocks, lag 1),
  the 64-root member history and the never-evicted ticket roots all
  tolerate base + 110.

All of it is pinned in `v4_vectors.json` (`sealing_v4`, `policy`,
`schedule`).

## What v4 does not fix

- Registration is still from the member's own account, so the member set is
  public and each handle is tied to an account.
- Ticket purchases are from an account too: with few buyers, "bought a
  ticket shortly before a send" narrows the sender down.
- Ciphertext length is bucketed and timing is scheduled (above), but
  only by convention until the pool enforces bucket sizes.
- The phone still sends on v3, which the desktop no longer reads.
