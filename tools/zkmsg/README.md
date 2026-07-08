# zkmsg — private messages on Starknet, proven natively

The messagezk model (sender/recipient membership in a registered-user
Merkle tree + ephemeral ECDH + Poseidon commitment) as a native Rust CLI:
the ZK proof is generated on YOUR machine (the witness — who you are, who
you're messaging — never leaves it), verified on Starknet Sepolia through
the live lane-1 `StwoFactRegistry`, and the message published to an
immutable `MessageStoreV3`. No browser, no proving service.

Spec: `docs/superpowers/specs/2026-07-05-zkmsg-lane1-port-design.md`.
Deployment record: `docs/zkmsg-deployment.md`.

## Prerequisites

- The repo's prover checkout (`scripts/setup-prover.sh` once) and the
  bridge binary built (`.prover/proving-utils/target/release/…` — see
  the bridge rebuild note in the repo docs).
- The circuit built once: `cd fixtures && scarb build` (scarb 2.18.0).
- `sncast` 0.61 with a funded Sepolia account in
  `~/.starknet_accounts/starknet_open_zeppelin_accounts.json`.
- ~64 GB RAM helps: the wrap leg peaks at ~25 GB.

## Quickstart

```sh
cd tools/zkmsg && cargo build --release
alias zkmsg=$PWD/target/release/zkmsg

zkmsg init --account <your-sncast-account>   # keygen + config (~/.zkmsg)
zkmsg register <your-handle>                 # one cheap tx
zkmsg status                                 # balance, addresses, count

zkmsg send <their-handle> "hello"            # ~1 min local proving + 5 txs (~50 STRK)
zkmsg inbox                                  # trial-decrypt everything addressed to you
```

`send` is resumable: every step (prove → wrap → pack → stage → phase 1 →
phase 2 → publish) checkpoints to `~/.zkmsg/sends/<id>.json` BEFORE it
runs; if anything fails mid-flight (gas spike, RPC flake), `zkmsg resume
<id>` re-enters at the first incomplete step without re-paying landed
transactions. Two pre-spend gates abort BEFORE any money moves if the
proof doesn't carry exactly the expected public tuple or the wrap's
inner circuit root drifts from the pinned route.

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
one row per pipeline step, tx hashes as Voyager links as they land.
Incomplete sends surface as a resume banner on launch: the GUI face of
the same checkpoint files the CLI's `resume` uses.

The workspace is three crates: `zkmsg-core` (all logic, emits typed
`PipelineEvent`s through a sink), `zkmsg` (the CLI, stdout byte-identical
to the pre-refactor tool), `zkmsg-gui` (egui/eframe; the pipeline runs on
a worker thread feeding an `mpsc` channel — the UI thread never blocks on
RPC or subprocesses, and no async runtime is involved).

First GUI-driven send shipped 2026-07-07 (fact `0x5b824d25…f6e25`,
47.2 STRK): see `docs/zkmsg-deployment.md`.

## What's public, what's private (v1, honest)

- **Private, cryptographically**: message content (AES-256-GCM under the
  ephemeral ECDH secret) and the RECIPIENT — observers can't tell who a
  message is for, or that any particular registered user received one.
  Recipients find their mail by trial-ECDH against every envelope; that
  asymmetry is the anonymity.
- **Public**: that YOUR account sent something (the send + verify txs are
  yours — same as messagezk's live V1; burner accounts are the shared V2
  fix), the registered-user set, and timing.
- **Caveats**: scan-key compromise exposes past content (the
  double-ratchet layer is deferred); Stwo proofs are not formally ZK and
  ride in public calldata permanently — the scan key is the only
  long-lived witness secret, rotate by re-registering a new handle.
