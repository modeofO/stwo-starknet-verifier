# qm31 gate probe

A minimal contract exercising the `core::qm31` libfuncs (pack, mul, add,
sub, unpack, is_zero) — the canonical re-test for whether Starknet's
declare gateway accepts qm31 classes yet. The day this declares, the
lane-2 qm31 pivot (docs/lane2-design.md, "The qm31 gate, measured")
unblocks.

## Status (measured 2026-07-05, Starknet Sepolia 0.14.3)

Where the gate actually lives, established empirically:

| Layer | qm31 classes | Evidence |
|---|---|---|
| Cairo VM / S-two AIR | **supported** | opcode extension 3 (`QM31Operation`) in the Starknet docs; corelib ships `core::qm31` |
| scarb 2.18 `audited.json` | not listed | build against the list emits a warning (a lint, not an error) |
| starknet-devnet 0.9.0 | **declares, deploys, executes** | this probe ran 100 rounds of qm31 arithmetic on devnet |
| Sepolia RPC nodes | estimate fine | `starknet_estimateFee` for the declare succeeds (~24.6M L2 gas) |
| **Sepolia gateway (declare)** | **REJECTED** | `Error: Contract failed to compile in starknet` — the enforcement point |

Devnet and RPC estimation are NOT valid deployability oracles for new
libfuncs; only a real gateway declare is.

**Re-tested 2026-07-05 (same day, later): still rejected** — identical
gateway error, gate unchanged. **Third probe 2026-07-05 (later still):
rejected again**, same error.

**Re-tested 2026-07-08: rejected**, same gateway error. Also checked
upstream `starkware-libs/cairo` `main` that day: the qm31 libfuncs
appear only in `all.json` — absent from BOTH `audited.json` and
`experimental.json` — so no scarb/compiler upgrade (released or
imminent) changes the outcome; the unlock is StarkWare auditing the
libfuncs and the gateway accepting them, i.e. a network-side change.
Local sequencers (devnet, and katana likewise) execute qm31 happily
and remain non-oracles for deployability.

## snforge executes qm31 (measured 2026-07-05)

`snforge test` in this package runs two probes
(`tests/test_qm31_execution.cairo`), both PASS on snforge 0.61.0 /
scarb 2.18.0:

- 100 rounds of qm31 mul/add/sub directly in the test runner's VM;
- the same chain through a **declared + deployed contract call**
  (`declare("Qm31Probe")` → `deploy` → `mul_qm31(100)`).

So the lane-2 qm31 pivot can be developed and equivalence-tested
entirely locally in snforge — the gateway gate blocks only the public
declare, not the local pyramid.

## Re-test (free on rejection; ~0.7 STRK if it lands)

```sh
cd tools/qm31-gate-probe && scarb build
sncast --account funded-deployer declare --contract-name Qm31Probe \
    --url https://starknet-sepolia-rpc.publicnode.com
```

If it succeeds, deploy and call `mul_qm31(100)` (expect `true`), then
start the lane-2 qm31 pivot.
