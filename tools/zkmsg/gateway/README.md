# zkmsg-gateway — the client that needs no RPC provider

Answers zkmsg's chain queries by syncing raw blocks from a **feeder gateway**
and replaying contract logic locally, instead of calling a JSON-RPC provider.

Two reasons it exists:

1. **sepolia-integration has no RPC provider at all** — public or paid. It is
   where qm31 is enabled (the whole single-transaction verifier design), so
   without this the phone can never reach the network its future depends on.
2. **On any network it removes a trusted third party.** An RPC provider sees
   your IP alongside the exact events you ask for — the deanonymisation vector
   `docs/THREAT_MODEL.md` calls out. A client that syncs whole blocks reveals
   nothing about which of them it cares about.

## The idea

zkmsg never actually needs general state reads. Its five queries are all
derivable from the event stream plus logic we already have:

| Query | Served by |
|---|---|
| resolve handle → leaf index, scan key | `UserRegistered` events |
| membership root | local tree replay (`zkmsg_core::tree`) |
| Merkle path | local tree replay |
| inbox | `MessageSent` events (existing trial-decrypt) |
| account nonce | local ledger; a rejection corrects it |

The membership tree is an ordinary depth-20 incremental Poseidon tree, already
implemented and golden-vector-pinned against the contract. Replaying every
`UserRegistered` event reproduces the root and every path exactly — so the
`get_merkle_root` / `get_merkle_path` / `get_user` view calls are redundant,
not merely unavailable.

## Endpoint reality (probed 2026-07-29, sepolia-integration)

| Endpoint | Status |
|---|---|
| `get_block` | **serves full blocks**, incl. `transaction_receipts[].events` |
| `call_contract` | `DEPRECATED_ENDPOINT` since 0.12.3 |
| `get_nonce` | `DEPRECATED_ENDPOINT` since 0.12.3 |

Events survive; state reads do not. Everything here follows from that.

## Sync cost — the honest constraint

There is no event filter, so sync is block-by-block, and **the feeder
rate-limits per IP**. Measured against integration:

| Workers | Throughput | Outcome |
|---|---|---|
| 1 | 4 blocks/s | sustained |
| 2 | **12 blocks/s** | sustained |
| 4+ | — | HTTP 429 within a few hundred blocks |

At 12 blocks/s and ~30 s block times, that is roughly **4 minutes per day of
chain history**, or two hours per month. Practical consequences:

- Sync from the store's **deployment height**, never genesis.
- Persist the cursor and the derived tree; only the delta matters after the
  first run.
- On a phone, treat first sync as a one-time setup cost, and expect the
  limiter to punish aggressive parallelism — 2 workers is the measured sweet
  spot, and backoff (250 ms → 4 s, 6 attempts) is not optional.

## What this does not do

Trust is **relocated, not eliminated**: block data comes from StarkWare's
feeder rather than an RPC provider — the same operator that runs the
sequencer. Verifying block headers against L1 would make this a light client;
that is a much larger build and is not attempted here.

## Try it

```sh
cargo run --release -p zkmsg-gateway -- head
cargo run --release -p zkmsg-gateway -- events <contract> <from_block> [to_block]
cargo run --release -p zkmsg-gateway -- registry <store_address> <from_block> [to_block]

ZKMSG_SYNC_WORKERS=2 cargo run --release -p zkmsg-gateway -- events ...
cargo test -p zkmsg-gateway -- --ignored   # live tests against integration
```

`registry` is the payoff: it rebuilds the membership tree from events and
prints the root, members and paths — the view calls, served locally.
(It needs a store deployed on the target network; on integration the campaign
deployed only the verifier and registry, so point it at alpha-sepolia's store
or deploy one there first.)
