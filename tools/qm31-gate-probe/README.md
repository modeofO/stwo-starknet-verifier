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

**Katana claim verified 2026-07-29** (it had been an inference): katana
1.8.0-rc.9 declares, deploys and executes this probe (`mul_qm31(100)` →
`true`) — but only for **Sierra ≤ 1.7.0** classes. Its embedded
sierra→casm compiler panics on Sierra 1.8.0 (scarb 2.18 output):
`UnsupportedSierraVersion { version_in_contract: 1.8.0,
version_of_compiler: 1.7.0 }`. The working build was scarb 2.12.2
(sierra 1.7.0) with the `starknet` dep pinned to match; devnet 0.9.0
remains the local sequencer that takes the repo's native scarb 2.18
classes.

**Re-tested 2026-07-29: rejected**, same gateway error. Sepolia still
on 0.14.3 (block 12,612,382); upstream `cairo` `main` unchanged (qm31
libfuncs in `all.json` only — 0 hits in `audited.json`;
`experimental.json` has been *deleted* from `main`, so the middle tier
no longer exists).

## Where the allowlist actually lives (established 2026-07-29)

The gate is a **runtime config flag, not a compiler property**. The
sequencer (`starkware-libs/sequencer`,
`crates/apollo_compile_to_casm/src/compiler.rs`) shells out to
`starknet-sierra-compile` with `--allowed-libfuncs-list-name` set from
`sierra_compiler_config.audited_libfuncs_only`. Public deployment
overlays (`deployments/sequencer/configs/overlays/hybrid/`):

| Network | `audited_libfuncs_only` |
|---|---|
| mainnet | `true` |
| sepolia-alpha | `true` |
| **sepolia-integration** | **`false`** — all libfuncs allowed |

So sepolia-alpha probes are a faithful mainnet-policy proxy, and the
unlock has two shapes: qm31 entering `audited.json` upstream (visible
as a cairo-repo PR — the early-warning signal to watch), or StarkWare
flipping the flag (invisible; only a declare probe detects it).

## Sepolia-integration: the gate is OPEN (measured 2026-07-29)

Confirmed live, not just in config. Method: handcrafted DECLARE v3
POSTed straight to the gateway (`scripts/declare_probe.py`; no RPC
provider serves integration) with a **nonexistent sender and dummy
signature** — the gateway's rejection error reveals which check fired,
and compilation is checked first, so no funds are needed.

Endpoints: feeder `https://feeder.integration-sepolia.starknet.io`
(Starknet 0.14.3, APOLLO-0.14.2-RC.7); write gateway
`https://integration-sepolia.starknet.io/gateway/add_transaction`
(POST only — GETs 404).

The error ladder, same class artifact (scarb 2.18, Sierra 1.8.0):

| Submission | Result |
|---|---|
| sepolia-alpha, any hash | `COMPILATION_FAILED: Libfunc qm31_const is not allowed in the libfuncs list 'audited'` |
| integration, local compiled hash | `INVALID_COMPILED_CLASS_HASH` — **the gateway compiled qm31 CASM** and reported its own hash |
| integration, gateway's hash | `VALIDATE_FAILURE: Resources bounds ... exceed balance (0)` — class fully accepted, fee-side only |

Two consequences:

- **Integration's compiler produces different qm31 CASM than local
  universal-sierra-compiler 2.8.0**: gateway-computed compiled class
  hash `0x2758889b6f6c9c0568b2e0faa35ae49b654ab7c88f960624c70ce57276d08b6`
  vs local `0x05df8b456facd3485f7a830e31f2cf3f2ef1a24b2666fd73181b374ab3c72f79`.
  A real declare there must use the gateway's hash (recoverable from
  the `INVALID_COMPILED_CLASS_HASH` error, as above) — sncast's
  locally-computed hash would be rejected.
- **The only blocker to actually landing qm31 on integration is
  funding** — no public faucet; the plausible route is an L1 deposit
  via the integration Starknet core contract on Ethereum Sepolia
  (`0x4737c0c1B4D5b1A687B42610DdabEE781152359c`, per the deployment
  overlay).

## qm31 DECLARED, DEPLOYED, EXECUTED on sepolia-integration (2026-07-29)

The full campaign, same day. To our knowledge the first qm31 contract
class ever declared and executed on a StarkWare-operated Starknet
network.

**Funding route** (no faucet exists — verified: zero faucet mentions in
the starkware-libs org; all 27 bridge deposits in 30 days came from one
StarkWare wallet `0x164ff8…dde8` in 10M-STRK chunks): withdraw STRK
from an alpha-sepolia account → claim on Ethereum Sepolia after the
state update (~28-min cadence, stalls of 1–3.5h ~4×/day, burst
recovery) → approve + `deposit(uint256,uint256)` on the integration
StarkGate ERC20 bridge `0x6FE45B…` → sequencer consumes the L1
message in minutes. Scripts: `scripts/l1_leg.py` (claim/deposit with
an eth_call claimability oracle), `scripts/integration_ops.py`
(gateway-POSTed v3 txs signed via starknet.py, chain id
`SN_INTEGRATION_SEPOLIA`; nonces tracked by counting — every feeder
state-read endpoint is deprecated, but rejection errors double as a
balance oracle).

Account: `0x734ac02467bd6c7cc021e5ff0b378451ae1e3d6464ecc1f95d03aa0757440aa`
(sncast OZ class, declared on integration along with Argent/Braavos).
Probe instance: `0x2b833e57fc5213a877fb97606541fda02ad42166ef4825d9e0cf0fc5a57604a`
(UDC exists on integration at the canonical address).

| Tx | Hash | Block | Fee | L2 gas |
|---|---|---|---|---|
| deploy_account | `0x20a5e2ed…bbd7` | 13887982 | 0.0712 STRK | 2,241,840 |
| **DECLARE Qm31Probe** | `0x98599f1f…11c9` | 13888013 | **0.7866 STRK** | **24,854,400** |
| UDC deploy | `0x516a1788…1468` | 13888021 | 0.0372 STRK | 1,172,160 |
| **mul_qm31(100)** | `0x7f7c87d8…4fec` | 13888040 | 0.0367 STRK | **1,155,840** |
| greet | `0x9834bd6e…9a71` | 13888062 | 0.0447 STRK | 1,407,040 |

Class hash `0x19392fe1876a8a2471e1a5675109e9232d761ba7740a15e58fb37426c64360d`,
declared with the gateway's own compiled class hash `0x2758…08b6`
(local USC 2.8.0 CASM differs — see above). All ACCEPTED_ON_L2,
executions SUCCEEDED. Total spend: 0.98 STRK.

- **The declare cost 24,854,400 L2 gas — within 1% of alpha's
  `starknet_estimateFee` (24.6M)** from the original probe. RPC
  estimation was accurate all along; only the allowlist policy blocked.
- `mul_qm31(100)` (100 rounds of native qm31 mul/add/sub through an
  account call): 1,155,840 L2 gas — barely above the ~1.1M-gas floor
  of an account invoke; the qm31 arithmetic itself is nearly free.
- Next: declare the lane-2 `feature = qm31_opcode` verifier build here
  and measure real qm31 verification gas months before the audited-list
  unlock.

(The `greet` tx transfers 0x716d3331 fri — ascii `qm31` — to the
StarkWare funding account `0x027125dc…80f5`, pairing with an L1
calldata note to their funding EOA, Ethereum Sepolia tx
`0xabbfba2a…0b72`.)

## The qm31 verifier, measured on a real messagezk proof (2026-07-29, same day)

The lane-1 classes built with `--features qm31_opcode` (new forwarding
features in `contracts/stwo_verifier_phases` and
`contracts/stwo_fact_registry`), declared on integration and fed the
real send-`12cd279d7e` messagezk proof (36,074 values / 5,154 packed
slots):

**Class sizes** (audited build → qm31 build): StwoPhase1 46,805 →
41,769 Sierra (−11%), 73,546 → 53,572 CASM (−27%). StwoPhase2 11,677 →
10,236 Sierra. StwoFactRegistry byte-identical (`0x7308e22…` — no
verifier code in it; phases pinned via constructor).

Classes on integration: Phase1 `0x671610f3…3af7f`, Phase2
`0x62e6cf65…b3f6e`, registry instance
`0xae46627b660dfc659e00e21e5c03660f1c891e8230cd5900ddc564fe36cf22`
(salt 0x716d3331). Declared via `declare-file` with the per-class
gateway compiled-hash dance; the registry declare also revealed the
gateway pre-executes declares and reports actual gas on
under-provisioned bounds ("Insufficient max L2Gas ... actual used").

**Gas, emulated (alpha lane-1) vs qm31-native (integration), same
proof shape** — txs `0x6708fadc…`, `0x6de41e3a…`, `0x7ab1fe53…`:

| leg | emulated | qm31 | Δ |
|---|---|---|---|
| verify_phase1 | 873.8M | 735.9M | −16% |
| verify_phase2 | 815.7M | 351.2M | −57% |
| verify total | 1,689M | **1,087M** | **−36%** |
| pipeline total | ~1.72e9 | 1.17e9 | −32% |

- **Single-tx verification fits**: 1.087e9 < the 1.21e9 invoke cap.
  A zkmsg message drops from 5 txs to 3 (stage → verify → publish) and
  the phase-checkpoint machinery becomes deletable.
- **The bottleneck moved**: phase2 (FRI, nearly pure qm31) collapsed
  57%; phase1 only 16% — it is dominated by blake2s channel hashing,
  deserialization, and u128 unpacking, none of which qm31 touches.
  Next cost target is the channel/deserialize path, not arithmetic.
- ~37 STRK/message at integration prices vs ~49 on alpha (gas is the
  honest metric; prices differ).
- Operational relearn: staging REVERTED on the default 8,192
  l1-data-gas bound (actual 15,840) — storage-heavy txs need explicit
  data-gas provisioning (lane-1 runbook rule, now with an integration
  data point; fee burned on the revert, ~2.6 STRK).

Pipeline driver: `integration_ops.py run-proof <nonce> <send_dir>
<registry> <fri_offset> <proof_id>` — python port of the zkmsg send
pipeline with a pack_v1 parity assertion against `packed.txt`.

## PROVEN: ACCEPTED_ON_L1 (2026-07-29, same day)

Every campaign transaction — the qm31 declare, `mul_qm31(100)`, and the
full messagezk verify pipeline on the qm31 registry — reached
**ACCEPTED_ON_L1**: StarkWare's production prover proved the blocks
containing native qm31-opcode execution and Ethereum Sepolia accepted
the state updates at the integration core contract
(`0x4737c0c1…`, LogStateUpdate cadence ~2 min / 200 L2 blocks).
End-to-end, the entire qm31 story is now demonstrated on production
infrastructure: declared through the real gateway, executed by the real
sequencer, proven by the real prover, settled on the real L1.

## Design choices the unlock opens (assessment, 2026-07-29)

Emulated qm31 was an architectural constraint, not just a cost; with it
gone, several previously-dominated designs become live options —
ordered so each measurement re-prices the next, all runnable on the
integration bench:

1. **Delete the staging layer.** Storage staging + u32 packing + the
   1.8e8-gas unpack exist only because verify couldn't share a tx with
   its proof under the invoke cap. Single-tx verify at ~1.09e9 opens a
   calldata-borne proof (calldata ≪ storage writes; raw felts kill the
   unpack). Binding constraint: the ~5,000-felt calldata ceiling vs the
   5,154-slot proof — hence (2).
2. **Re-tune proof parameters.** Lane 1 tuned FRI blowup/queries/pow to
   minimize on-chain verify (the scarce resource under emulation). qm31
   inverts the scarcity: verify is cheap, calldata/storage are not —
   the optimum shifts toward more verify work / smaller proofs, which
   feeds (1).
3. **Revisit the channel hash.** Phase1 improved only 16% because it is
   hash/deserialize-bound, not arithmetic-bound. The vendor crates ship
   `poseidon252_verifier`, and Poseidon is a native Starknet builtin —
   a blake-vs-poseidon on-chain measurement is now meaningful (cost
   moves to the desktop prover, the right direction).
4. **Batch/aggregate proofs.** Verify cost is largely per-proof
   structure; one wrapped proof attesting N messages divides the
   marginal cost by N. Never affordable under emulation; now the
   largest available multiplier.
5. **Privacy side effects.** 5 txs → 1–3 txs shrinks the per-message
   on-chain fingerprint, and cheaper sends lower burner funding
   (~70–108 → ~40 STRK), buying more unlinkability per budget.
6. **Lane-2 full-VM verifier revival.** Phase1's −27% CASM shrink
   suggests the 36-class full verifier recompiles far smaller —
   possibly few enough classes to deploy the general "verify any Cairo
   program" route.

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
