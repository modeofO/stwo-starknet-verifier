# zkmsg — private messages on Starknet, proven natively

A serverless dead drop on Starknet. A message proves its sender is a
registered member without saying which one, and only the recipient can
tell it is theirs. The proof is generated on YOUR machine (the witness —
who you are, who you're messaging — never leaves it) by StarkWare's
virtual Starknet OS, and rides inside the one transaction that publishes
the message; the sequencer verifies it natively (SNIP-36). No browser, no
proving service, no relay.

Specs: `docs/superpowers/specs/2026-10-01-zkmsg-desktop-snip36-pq-design.md`,
`docs/superpowers/specs/2026-10-01-zkmsg-pq-hybrid-kem-design.md`.
Deployment record: `docs/zkmsg-deployment.md`. (The first route, lane 1 —
prove, wrap, then verify through the `StwoFactRegistry` in several ~24 STRK
transactions — shipped 2026-07-05 and was removed from this client
2026-10-01; its history is in the deployment record.)

## Prerequisites

- The SNIP-36 prover binary, built once from the sequencer checkout:
  `.prover/sequencer/target/release/snip36-prove` (see
  `tools/snip36-phone-ffi/README.md`, "Desktop").
- `sncast` 0.61 with a funded Sepolia account in
  `~/.starknet_accounts/starknet_open_zeppelin_accounts.json` (~4 STRK
  of fee ceiling per send).

## Quickstart

```sh
cd tools/zkmsg && cargo build --release
alias zkmsg=$PWD/target/release/zkmsg

zkmsg init --account <your-sncast-account>   # scan key + ML-KEM seed + config
zkmsg register <your-handle>                 # one cheap tx (~0.2 STRK)
zkmsg status                                 # balance, addresses, count

zkmsg send <their-handle> "hello"            # ~30 s: prepare, prove, publish (~1.6 STRK)
zkmsg inbox                                  # detect and decrypt what's addressed to you
```

`send` is resumable once its proof exists: the state is saved to
`~/.zkmsg/sends/<id>.json` (the proof beside it; the witness never), and
the publish hash is recorded the moment the gateway accepts it, so
`zkmsg resume <id>` polls that hash before it would ever resubmit. A send
that fails before proving has nothing to resume — send it again.

## v2: post-quantum key exchange (the default store, 2026-10-01)

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

The v2 store is the only one this client reads or writes: MessageStore v3
and the SNIP-36 v1 store are no longer read (`inbox --legacy` is gone).
Older profiles move with `zkmsg migrate-store [<profile>]` (or the Status
tab's "Move to v2 store…"): it rewrites `config.json`, clears the handle
and leaf index (registration is per store), keeps the scan key, and you
`zkmsg register <handle>` again.

First desktop v2 run, 2026-10-01: carol registered at leaf 1
(`0x03e1ddad…bbb7`, 0.18 STRK) and sent to `mode`
(`0x452a95d9…592b`, **32 s wall, prove 16 s, 1.60 STRK**, 77.6M L2 gas;
content 1,179 bytes = kem_ct 1088 ‖ AES-GCM blob). `mode`'s desktop
inbox decrypts it; carol's own inbox does not.

## SNIP-36 sends

On the v2 store (as on the SNIP-36 v1 store before it) a send is **one
transaction**: the zkmsg statement runs inside StarkWare's virtual
Starknet OS (contract `ZkmsgSendProver`, executed only here), the S-two
proof of that run rides in the invoke's `proof` field, and the sequencer
verifies it natively before `send_message` checks the proof's one L2→L1
message against the public tuple. No wrap, no staging, no fact registry.
`core/src/virtual_send.rs` is a port of the phone's
`VirtualSendExecutor`, rules included: tree/paths/nonce read at one block,
witness only in memory (it reaches the prover on stdin), facts checked
before signing, `is_known_root` before publish, the publish hash saved the
moment the gateway takes it.

Needs the prover binary, built once from the sequencer checkout (see
`tools/snip36-phone-ffi/README.md`, "Desktop"):
`.prover/sequencer/target/release/snip36-prove` (config key
`virtual_prover_bin`). Reads and proving go through an RPC that serves
`starknet_getStorageProof` for recent blocks (`prover_rpc_url`, default
zan); the publish goes to the Sepolia gateway, because JSON-RPC can't
carry `proof` / `proof_facts`.

**Signing key decision:** the publish leg signs natively
(`core/src/invoke_v3.rs`: INVOKE v3 hash with `proof_facts` appended, per
SNIP-36), with the key read from sncast's accounts file — the one place
every desktop account key already lives (`sncast account create` made
them all). `keys.json` stays the scan key only.

First desktop send, 2026-10-01: carol → mode2 on the v1 store, tx
`0x7106fea0…e4a7`, **35 s wall on an M-series Mac (prove 19 s), 1.58 STRK**
(76.9M L2 gas, 352 data gas). The account must hold ~4 STRK of fee
ceiling (120M L2 gas × price × 1.5), not just the ~1.6 a send costs.

## GUI

The same product as a native egui app (macOS/Apple Silicon):

```sh
cargo run --release -p zkmsg-gui -- --home ~/.zkmsg   # same --home as the CLI
```

Three tabs — **Status** (identity, balances, addresses; doubles as
init/register onboarding), **Compose** (recipient resolve, byte counter,
and a send gated behind an explicit confirm dialog stating the STRK
cost), **Inbox** (trial-decrypt scan with manual Refresh + optional 30 s
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

First GUI-driven send shipped 2026-07-07 (fact `0x5b824d25…f6e25`,
47.2 STRK); first wizard-born identity (carol) created, funded and
registered in-app 2026-07-08, and her first send (fact
`0x18dbb303…305a`) survived a real mid-send balance stall via
top-up + Resume; first burner (`burner-7ec070`) ran the full
unlinkable loop 2026-07-10 — external deposit, send to alice (fact
`0x4535d688…c46a`), sweep + archive: see
`docs/zkmsg-deployment.md`.

## What's public, what's private (v1, honest)

- **Private, cryptographically**: message content (AES-256-GCM under the
  ephemeral ECDH secret) and the RECIPIENT — observers can't tell who a
  message is for, or that any particular registered user received one.
  Recipients find their mail by trial-ECDH against every envelope; that
  asymmetry is the anonymity.
- **Public**: that *some* registered account sent something, the
  registered-user set, and timing. With a normal profile that account
  is YOURS (same as messagezk's live V1). With a **burner** (shipped
  2026-07-10) the sending account is a fresh, externally-funded
  throwaway with no on-chain edge to any account you own — the app
  never draws one.
- **Burner caveats, honestly**: the anonymity set is the registered-user
  count (tiny on Sepolia); timing correlates (a registration shortly
  before a send); reusing a burner links its sends to each other. Fund
  a burner from your own account and you've drawn the very
  edge it exists to avoid.
- **Caveats**: scan-key compromise exposes past content (the
  double-ratchet layer is deferred); Stwo proofs are not formally ZK and
  ride in public calldata permanently — the scan key is the only
  long-lived witness secret, rotate by re-registering a new handle.
