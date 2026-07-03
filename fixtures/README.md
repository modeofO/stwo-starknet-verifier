# Fixtures

- `poseidon_chain/` — Poseidon hash-chain executable (`main(n: u32)`), the
  eventual app-shaped fixture. Currently provable only with the patched
  prover (`tools/prover-executable-segment-context.patch`) and not yet
  verifiable by the Cairo1 verifier (scarb executables lack the full
  11-builtin segment layout the proof format requires — see
  docs/spike2-results.md §2).
- `poseidon_chain_args_100.json` — arguments file (n = 100).
- `prover_params_poseidon.json` — prover parameters for the on-chain
  (poseidon252 channel) verifier configuration, 96-bit security.
