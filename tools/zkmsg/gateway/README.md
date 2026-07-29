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

## Live on sepolia-integration (deployed 2026-07-29)

The store now exists next to the qm31 verifier, so the full phone-first
architecture has a home on the network where single-transaction verification
is possible:

| Thing | Address |
|---|---|
| `MessageStoreV3` class | `0x4dc67c0ad76d9674a80d6dcb717cec7334014f2d5df986c440ed1aa62765745` |
| store instance (salt `qm31`) | `0x6f3db45f5a5bbef78dd7f8c93b76894c453fce935423fc40bb68475df64a30b` |
| pinned fact registry (qm31) | `0xae46627b660dfc659e00e21e5c03660f1c891e8230cd5900ddc564fe36cf22` |

Declared for 620M L2 gas (the gateway pre-executes and reports actual usage on
an under-provisioned bound), deployed via UDC, and seeded with one member —
handle `boat` at leaf 0. Declares there need the gateway's own compiled class
hash, recoverable free of charge from the `INVALID_COMPILED_CLASS_HASH`
rejection.

**The approach is verified against the chain, not just self-consistent.**
`get_merkle_root` cannot be called on integration, so the check runs through
`get_state_update`: the root this crate derives from `UserRegistered` events —
`0x2883a854ab57d90076c43e80f268f244b651e6876183710340c2f2121bd335d` — appears
in the store's own storage writes for that block. Pinned by
`derived_root_matches_onchain_storage`. State diffs are also the general
escape hatch for reading state on a feeder-only network, should anything ever
need a slot the event stream cannot reconstruct.

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
