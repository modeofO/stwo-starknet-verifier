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
- `poseidon_chain_n100.multiverifier_proof.json` — end-to-end artifact of
  Spike 3: the multiverifier proof of `poseidon_chain(100)`'s bootloader
  execution, in the felt252 format the Cairo circuit verifier consumes
  (verified at 3,814,641 steps).
- `poseidon_chain_n100.output_preimage.json` — the bootloader output preimage
  `[n_tasks, output_len, program_hash, output]` for that proof.
- `prover_params_blake.json` — prover parameters for the qm31-pivot (blake2s
  channel) verifier configuration: identical PCS shape to the poseidon params
  (70 queries, blowup 1, fold_step 1) but PLAIN `blake2s` channel (NOT
  `blake2s_m31`; the vendored default build keeps raw blake digests) and
  `canonical` preprocessed trace (the default build pins the WITH-pedersen
  root). Regenerate the gitignored blake fixtures (~6 s wall, 14.1 GB peak,
  deterministic):

  ```sh
  .prover/proving-utils/target/release/privacy_prove_cairo_bridge prove-blake \
      fixtures/target/dev/poseidon_chain.executable.json \
      fixtures/poseidon_chain_n100.blake_proof_serde.json \
      fixtures/prover_params_blake.json fixtures/poseidon_chain_args_100.json \
      --extended fixtures/poseidon_chain_n100.blake_extended_proof.json
  ```

  The committed blake witness-group test fixtures
  (`contracts/stwo_full_verifier_phases/tests/data/blake/`) are the
  **8-query** split (the production group size — see "The staged-section
  store" in docs/lane2-design.md), regenerated from the extended proof:

  ```sh
  .prover/proving-utils/target/release/privacy_prove_cairo_bridge split-witness \
      fixtures/poseidon_chain_n100.blake_extended_proof.json \
      contracts/stwo_full_verifier_phases/tests/data/blake 8 --blake
  ```

  (The poseidon set `tests/data/witness_group_*.txt` remains the 16-query
  split, group-size flexibility being part of what the tests prove.)
