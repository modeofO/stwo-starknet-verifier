# zkmsg — private messages on Starknet, proven natively

A serverless dead drop on Starknet. A message proves its sender is a
registered member without saying which one, and only the recipient can
tell it is theirs. The proof is generated on YOUR machine (the witness —
who you are, who you're messaging — never leaves it) by StarkWare's
virtual Starknet OS, and rides inside the one transaction that publishes
the message; the sequencer verifies it natively (SNIP-36). Since v4 that
transaction is sent and paid by the store itself (the pool), out of a
single-send ticket you bought earlier, so your account never touches a
send. No browser, no proving service, no relay.

Specs: `docs/superpowers/specs/2026-10-07-zkmsg-v4-pool-tickets-design.md`
(current), `docs/superpowers/specs/2026-10-01-zkmsg-v3-pq-membership-design.md`,
`docs/superpowers/specs/2026-10-01-zkmsg-desktop-snip36-pq-design.md`,
`docs/superpowers/specs/2026-10-01-zkmsg-pq-hybrid-kem-design.md`.
Deployment record: `docs/zkmsg-deployment.md`. (The first route, lane 1 —
prove, wrap, then verify through the `StwoFactRegistry` in two ~24 STRK
transactions plus staging and the publish — shipped 2026-07-05 and was removed from this client
2026-10-01; its history is in the deployment record.)

## Prerequisites

- The SNIP-36 prover binary, built once from the sequencer checkout:
  `.prover/sequencer/target/release/snip36-prove` (see
  `tools/snip36-phone-ffi/README.md`, "Desktop").
- `sncast` 0.61 with a funded Sepolia account in
  `~/.starknet_accounts/starknet_open_zeppelin_accounts.json`. It pays
  registration (~0.2–0.3 STRK) and ticket purchases (3 STRK per send,
  plus ~0.2–0.4 STRK of fees per purchase), never a send itself.

## Quickstart

```sh
cd tools/zkmsg && cargo build --release
alias zkmsg=$PWD/target/release/zkmsg

zkmsg init --account <your-sncast-account>   # scan key + ML-KEM seed + member secret + config
zkmsg register <your-handle>                 # one cheap tx (~0.2 STRK)
zkmsg buy-tickets 2                          # 2 x 3 STRK in one tx, secrets saved to tickets.json first
zkmsg tickets                                # unspent / reserved / pending / spent
zkmsg status                                 # balance, tickets, addresses, count

zkmsg send <their-handle> "hello"            # ~2.5 min: prepare, prove, scheduled publish — one ticket
zkmsg inbox                                  # detect and decrypt what's addressed to you
```

`send` is resumable once its proof exists: the state is saved to
`sends/<id>.json` in the profile's home (`~/.zkmsg/.zkmsg-<name>/`; the
proof beside it in `sends/<id>/`; the witness never), and
the publish hash is recorded the moment the gateway accepts it, so
`zkmsg resume <id>` polls that hash before it would ever resubmit. A send
that fails before proving has nothing to resume — send it again.

## v4: the pool and tickets (the current store, 2026-10-07)

The 2026-10 red team found that every send was published, and paid for,
by the account that registered the sender's handle: the chain named the
sender outright, whatever the proof hid. `ZkmsgPoolV4`
(`contracts/zkmsg_pool_v4`, spec
`docs/superpowers/specs/2026-10-07-zkmsg-v4-pool-tickets-design.md`) takes
every member's account out of the send:

- **The store is the account that publishes.** A send is an INVOKE v3
  whose `sender_address` is the pool and whose signature is empty. The
  pool's `__validate__` admits exactly one proven `send_message` (facts,
  roots, nullifiers, epoch, content size, fee policy) and nothing else —
  no transfer, no other call.
- **Tickets pay.** `zkmsg buy-tickets <n>` picks n fresh secrets t,
  writes them to `tickets.json` (0600, bearer value) and only then calls
  `buy_tickets(leaves)` at 3 STRK per leaf poseidon(TICKET_V4, t). A send
  proves knowledge of some ticket's t under the ticket root and reveals
  only poseidon(TICKET_NULL_V4, store, t); `__validate__` burns it and
  caps the transaction's worst-case fee at the ticket price, so the pool
  can never pay out more than tickets brought in. What a send doesn't
  use (~1.55 of the 3 STRK) stays in the pool — a refund would need a
  destination, which would re-link the send. The purchase shows that your
  account bought tickets; nothing ties a send to the tickets it spent.
- **The proof runs from a shared account.** The virtual `prove_send`
  invoke comes from `ZkmsgVirtualSenderV4` (zero fee only, nonce 0
  forever), so the prover's state requests name no member's account.
- **A quota per member.** Each send also reveals
  poseidon(NULLIFIER_V4, store, m, epoch, slot) for a private slot
  `< quota` (10 per 5,000-block epoch, ≈2.4 h): a member can send at most
  10 per epoch, and two sends of one member stay unlinkable. The client
  keeps the epoch's used slots in `quota.json`.
- **No read names you.** The member tree and the ticket tree are both
  rebuilt locally from all events; the send path's RPC requests are the
  same for every sender (`virtual_send::tests::
  prepare_reads_name_no_handle_leaf_ticket_or_account`).

- **Padded, versioned sealing.** Plaintext is padded inside the AEAD to
  256 / 1024 / 4096 bytes (u16 length prefix, zero fill; over 4094 bytes
  is refused), sealed under "zkmsg-v4" HKDF labels: on chain a message is
  1372, 2140 or 5212 bytes, the only sizes the pool accepts. A tag match
  that does not open (someone
  front-running a commitment over other content) is dropped silently.
- **One transaction shape for every client** (`core/src/txpolicy.rs`):
  fixed gas amounts per kind, price bounds ceil(1.5×) rounded up to 2
  significant figures, tip 1e8 fri; register and ticket purchases are
  signed natively (`core/src/account_tx.rs`), not through sncast.
- **Fixed timing.** A send proves on block floor((head − 10)/32)×32 and
  publishes once the head is 90 + (0..=20 random) blocks past it, so the
  base block reveals neither when Send was pressed nor how fast the device
  proved: a send takes ~2.5–3 min ("publishing in ~2 min").

`zkmsg migrate-store [<profile>] [--account <name>]` moves a profile to
the pool with a FRESH scan key, ML-KEM seed and member secret (the old
keys are overwritten — copy the profile directory first), then
`zkmsg register <handle>` and `zkmsg buy-tickets`. A send that the pool
refuses in validate costs nothing (its ticket goes back to the wallet
unless the refusal was "ticket spent"); a lost race for the pool's nonce
is resubmitted at the next nonce with the same proof.

Golden vectors for ports: `core/testdata/v4_vectors.json`
(`core/tests/v4_vectors.rs`; the same values are asserted against the
contracts in `contracts/zkmsg_pool_v4/tests/test_vectors_v4.cairo`).

Live, padded pool (2026-10-08): one send per bucket, 79.9M / 80.1M /
82.5M L2 gas (1.45–1.50 STRK from the ticket), published 99–116 blocks
after a 32-aligned base. First live run on the retired unpadded pool,
2026-10-07: carol ↔ mode, four sends through the pool
(two of them concurrent, at pool nonces 2 and 3), 1.43–1.44 STRK each from
tickets, ~79.5M L2 gas, ~35 s wall; every recipient decrypts, neither
user's account appears in any publish. See `docs/zkmsg-deployment.md`.

## v3: post-quantum membership (2026-10-01)

`MessageStoreV3` (`docs/superpowers/specs/2026-10-01-zkmsg-v3-pq-membership-design.md`)
makes the sender's membership proof hash-only. Each identity holds a
membership secret `m` (`keys.json` `member_secret`, `0x` + 64 hex, < 2^251,
never 0 — the SEND credential, irreplaceable like the other keys). The
leaf commits to `poseidon(MEMBER_V3, m)` beside the scan pubkey and the
ML-KEM digest, and `prove_send` proves knowledge of `m` under the root:
no elliptic-curve step, so the membership argument rests on Poseidon
alone. The scan private key is no longer a proving input; it only opens
mail. Content and recipient detection are v2's hybrid ML-KEM + ECDH,
unchanged.

`m` is minted on `init`, and fresh for every store a profile moves to
(`zkmsg migrate-store`: registration is per store). It is never re-minted
for a profile that already holds a handle. (v3 was then the only store
read; the v4 pool has since replaced it and keeps its leaf.)

## v2: post-quantum key exchange (2026-10-01)

Fresh profiles use `MessageStoreV2PQ`
(`docs/superpowers/specs/2026-10-01-zkmsg-pq-hybrid-kem-design.md`): the
content key and the recipient tag come from ML-KEM-768 **and** Stark-curve
ECDH, so a future quantum attacker who records today's chain still needs
to break ML-KEM. `keys.json` gains `kem_seed` (64 bytes, `0x` hex; made
on `init`, or on first v2 use for an older profile — irreplaceable, like
the scan key). Registering publishes the 1184-byte ML-KEM key; a sender
reads it from the `UserRegistered` event and checks it against the
store's `kem_digest`. The zk statement now proves only the sender's
membership; the recipient finds its mail by recomputing the hybrid tag.

(v2 was then the only store read; v3 has since replaced it, see above.)
Older profiles move with `zkmsg migrate-store [<profile>]` (or the Status
tab's "Move to v3 store…"): it rewrites `config.json`, clears the handle
and leaf index (registration is per store), keeps the scan key, mints a
fresh member secret, and you `zkmsg register <handle>` again.

First desktop v2 run, 2026-10-01: carol registered at leaf 1
(`0x03e1ddad…bbb7`, 0.18 STRK) and sent to `mode`
(`0x452a95d9…592b`, **32 s wall, prove 16 s, 1.60 STRK**, 77.6M L2 gas;
content 1,179 bytes = kem_ct 1088 ‖ AES-GCM blob). `mode`'s desktop
inbox decrypts it; carol's own inbox does not.

## SNIP-36 sends

On the v4 pool (as on the v3, v2 and SNIP-36 v1 stores before it) a send
is **one transaction**: the zkmsg statement runs inside StarkWare's
virtual Starknet OS (contract `ZkmsgSendProverV4`, executed only here),
the S-two proof of that run rides in the invoke's `proof` field, and the
sequencer verifies it natively before the pool checks the proof's one
L2→L1 message against the public tuple. No wrap, no staging, no fact
registry. `core/src/virtual_send.rs` started as a port of the phone's
`VirtualSendExecutor`, rules included: trees/paths read at one block,
witness only in memory (it reaches the prover on stdin), facts checked
before publishing, `is_known_root` before publish, the publish hash saved
the moment before the gateway takes it.

Needs the prover binary, built once from the sequencer checkout (see
`tools/snip36-phone-ffi/README.md`, "Desktop"):
`.prover/sequencer/target/release/snip36-prove` (config key
`virtual_prover_bin`). Reads and proving go through an RPC that serves
`starknet_getStorageProof` for recent blocks (`prover_rpc_url`, default
zan); the publish goes to the Sepolia gateway, because JSON-RPC can't
carry `proof` / `proof_facts`.

**Signing:** since v4 the publish is not signed at all (the pool
authorizes by proof); `core/src/invoke_v3.rs` still computes its INVOKE v3
hash, with `proof_facts` appended per SNIP-36, so the client knows the
hash before the POST. Account keys stay where sncast put them
(`~/.starknet_accounts/…`) and only sign registration and ticket
purchases, through sncast. `keys.json` carries the scan key, `kem_seed`
and `member_secret` (plus handle and leaf index); `tickets.json` the
ticket secrets.

First desktop send, 2026-10-01: carol → mode2 on the v1 store, tx
`0x7106fea0…e4a7`, **35 s wall on an M-series Mac (prove 19 s), 1.58 STRK**
(76.9M L2 gas, 352 data gas). (Before v4 the account had to hold ~4 STRK
of fee ceiling per send; now the pool holds it, out of tickets.)

## GUI

The same product as a native egui app (macOS/Apple Silicon):

```sh
cargo run --release -p zkmsg-gui -- --home ~/.zkmsg   # same --home as the CLI
```

Three tabs — **Status** (identity, balances, tickets with a "Buy 1
ticket" button, addresses; doubles as init/register onboarding),
**Compose** (recipient resolve, byte counter, and a send gated behind an
explicit confirm dialog stating that it spends a ticket), **Inbox** (trial-decrypt scan with manual Refresh + optional 30 s
auto-refresh). During a send the compose view becomes a live checklist —
one row per step (prepare, prove, publish), the publish hash as a
Voyager link the moment it is submitted.
Incomplete sends surface as a resume banner on launch: the GUI face of
the same checkpoint files the CLI's `resume` uses.

The workspace is three crates: `zkmsg-core` (all logic, emits typed
`PipelineEvent`s through a sink), `zkmsg` (the CLI), `zkmsg-gui`
(egui/eframe; the send runs on a worker thread feeding an `mpsc` channel —
the UI thread never blocks on RPC or the prover subprocess, and no async
runtime is involved).

**Profiles (2026-07-08):** `~/.zkmsg` is a profile root — one
`.zkmsg-<name>/` dir per identity plus a `current` pointer — and the
GUI switches identities in-app from a top-bar picker (window title
always names the active profile; switching is blocked while paid work
runs). First launch offers a one-time migration of legacy homes
(atomic renames only; nothing is copied, deleted, or overwritten).
**New profile…** creates a funded identity in one confirm:
`sncast account create` → STRK transfer from the active profile →
deploy → init → register, as a checkpointed checklist that resumes
after failures without re-paying landed steps (the Fund step
balance-checks so a resume can never double-transfer). The CLI follows
the layout transparently: profile dirs passed to `--home` work
unchanged; the bare default resolves through `current`.

**Burners (2026-07-10):** `New burner…` creates a throwaway sender —
auto-named `burner-<hex>` from OS randomness, **externally funded**:
the wizard parks at the Fund step showing a deposit address and a
funding target computed from live gas prices (the flat default died
with carol's stall), and none of your existing accounts ever signs
anything for it. While parked it holds no lock — switch profiles,
read inboxes, come back and hit Refresh when the deposit lands.
After the send, a prompt offers to archive the burner. Any profile can be
archived from the picker ("archive…"): its directory is renamed into
`~/.zkmsg/archive/` — keys are never deleted — and the picker's
"archived" list moves it back ("unarchive"). There is no sweep: leftover STRK stays on the burner,
because moving it anywhere would draw the on-chain edge the burner
exists to avoid. (Retired 2026-10-01, along with the optional
`from:` line: messages carry no sender line.)

## Deleting an identity, and secrets at rest (2026-10-08)

A profile's secret files — `keys.json`, `tickets*.json`, `quota.json`,
`inbox.json` and `sends/*.json` — are sealed (AES-256-GCM, the file's
path as associated data) under a random per-profile key that lives in
the macOS login Keychain (service `zkmsg.profile-key`, account = the id
in the profile's `vault.json`), never on disk. Older profiles are sealed
in place the first time the CLI or GUI opens them. `core/src/vault.rs`.

Deleting a profile (`zkmsg delete-profile <name>`, or "delete…" in the
GUI picker, live or archived) is a crypto-shred: the Keychain key goes
first, so every sealed byte an SSD still holds stops decrypting; then the
account's entry in sncast's accounts file (unless another profile uses it,
or `--keep-account-key`), then the directory, then `current`. Before
that, unspent tickets can move to another profile on the same pool
(`--move-tickets-to`): a ticket is a bearer secret nothing on chain ties
to an identity. The account's balance is read only on request
(`--check-balance`, or "check" in the dialog: it asks the RPC about the
address from your connection) and is **abandoned, never swept** — a transfer to another account would link the two on chain.
Nothing happens on chain: the registration stays, and messages sent to
the deleted handle become unreadable to everyone. You confirm by typing
the handle. `core/src/wipe.rs`.

**App PIN** (`core/src/applock.rs`). On first use the CLI or GUI asks you
to set an app PIN (at least 6 characters; not your login password, never
biometrics). One random master key wraps every profile key, and the
master key is itself kept only as AES-256-GCM under
Argon2id(PIN, salt; 256 MiB, 3 passes) in the login Keychain
(`zkmsg.app-lock`). The CLI asks for the PIN on every command
(`ZKMSG_PIN` for scripts); the GUI shows a lock screen at launch, after
10 idle minutes and on "Lock". From the 5th wrong PIN each try waits
(30 s up to 1 h); the 10th in a row runs the panic wipe. `zkmsg
change-pin` re-wraps the master key. Strength, honestly: guessing offline
needs the login Keychain item first and then ~1 s of 256 MiB work per
guess, so a 6-digit PIN falls in days to someone who has both; use a
longer PIN or a passphrase on a laptop. (The phone binds its PIN to the
Secure Enclave instead.)

**Panic wipe**: `zkmsg panic-wipe` (one confirmation, no PIN, no
network) or "Panic wipe…" on the GUI's lock screen and top bar. It
deletes every profile key and the app lock from the Keychain first (all
sealed files become unreadable at once), then the profiles' account keys
from sncast's accounts file, then the whole profile root (`~/.zkmsg`).
`ZKMSG_KEYCHAIN_NAMESPACE=<word>` prefixes the Keychain services, for
test runs that must not touch your real items.

Limits, honestly: the account's private key sits in sncast's plain
accounts file, which delete rewrites (an ordinary file rewrite, not a
shred); a deleted Keychain item can linger in the keychain database,
encrypted under the login keychain; any plain copy you made of a profile
(a backup directory) is untouched.

First GUI-driven send shipped 2026-07-07 (fact `0x5b824d25…f6e25`,
47.2 STRK); first wizard-born identity (carol) created, funded and
registered in-app 2026-07-08, and her first send (fact
`0x18dbb303…305a`) survived a real mid-send balance stall via
top-up + Resume; first burner (`burner-7ec070`) ran the full
unlinkable loop 2026-07-10 — external deposit, send to alice (fact
`0x4535d688…c46a`), sweep + archive: see
`docs/zkmsg-deployment.md`.

## What's public, what's private (v4, honest)

- **Private, cryptographically**: message content (AES-256-GCM under a
  key derived from BOTH ML-KEM-768 and ephemeral Stark-curve ECDH — a
  recorded ciphertext stays sealed unless both are broken) and the
  RECIPIENT — the detection tag comes from the same hybrid secret, so
  observers can't tell who a message is for; recipients find their mail
  by recomputing the tag against every envelope.
- **Sender, among members**: the proof shows *a* registered member sent
  the message, not which. Under v3 the witness is the member secret `m`,
  the sender's scan PUBLIC key, `kem_digest`, leaf index and path — the
  scan private key is not in it. The witness never leaves the device.
- **Public**: that *a member* sent something, through the pool; the
  registered-user set (handles, scan pubkeys, ML-KEM keys, `m_commit`s —
  each registered from its owner's account); which accounts bought how
  many tickets, and when; each send's quota and ticket nullifiers (which
  link to nothing), its epoch and base block, timing and ciphertext
  length. Before v4 the paying account was YOURS; since v4 every send's
  sender is the pool. With few members and few ticket buyers, timing
  (a purchase shortly before a send, a send right after a registration)
  still narrows things down.
- **Burners** are pre-v4: their point was an unlinked paying account,
  which the pool now gives every profile.
- **Burner caveats, honestly**: the anonymity set is the registered-user
  count (tiny on Sepolia); timing correlates (a registration shortly
  before a send); reusing a burner links its sends to each other. Fund
  a burner from your own account and you've drawn the very
  edge it exists to avoid.
- **Membership integrity is a sequencer trust**: on SNIP-36 the gateway
  and consensus validators verify the proof; the settling block proof
  checks only the facts' header (v2 spec, "Current system"). A send with
  an invalid membership proof would have to get past the
  sequencer/validators, but L1 settlement would not catch it. The retired
  lane-1 route had settlement coverage.
- **The proof**: it rides in the publish transaction's `proof` field. It is
  a recursive proof from StarkWare's privacy prover: the inner Cairo proof
  of the virtual-OS run (not ZK) stays on the device, and the outer proof
  that verifies it gets ZK blinding (`add_zk_blinding`, 35 random rows per
  component). The blinding is heuristic, not proven ZK; no attack that
  recovers the witness is known. The proof is not in public block data (the
  feeder returns `proof_facts`, not `proof`), but the gateway stores it and
  archives it to StarkWare's cloud storage. Under v3 the only long-lived
  secret in the witness is `m`.
- **Caveats**: `keys.json` compromise (scan key + KEM seed) exposes past
  content (the double-ratchet layer is deferred); a leaked `m` lets its
  holder send as a member, not read mail. Rotate by re-registering a new
  handle.
