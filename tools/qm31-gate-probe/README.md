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

## Re-test (free on rejection; ~0.7 STRK if it lands)

```sh
cd tools/qm31-gate-probe && scarb build
sncast --account funded-deployer declare --contract-name Qm31Probe \
    --url https://starknet-sepolia-rpc.publicnode.com
```

If it succeeds, deploy and call `mul_qm31(100)` (expect `true`), then
start the lane-2 qm31 pivot.
