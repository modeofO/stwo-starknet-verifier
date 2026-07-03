# stwo-starknet-verifier

R&D: compiling StarkWare's [stwo-cairo](https://github.com/starkware-libs/stwo-cairo)
**Stwo (Circle-STARK) verifier** as a **Starknet smart contract**, so proofs of
custom Cairo programs — including browser-generated ones — can be verified
on-chain by contract code. Nobody has shipped this as of July 2026.

Full background, constraints, and plan: [`stwostarknetverifierhandoff.md`](./stwostarknetverifierhandoff.md).
Results so far: [`docs/spike1-results.md`](./docs/spike1-results.md).

## Status

- **Spike 1 (compile probe): done** — [`docs/spike1-results.md`](./docs/spike1-results.md).
  The full Cairo verifier compiles as a `starknet-contract` with gas on and
  passes the `audited.json` libfunc allowlist — the only deployment blocker
  is class size (~5.5× over the Sierra bytecode cap). The newer *circuit*
  verifier fits **all** size caps today.
- **Spike 2 (step-count measurement): done** — [`docs/spike2-results.md`](./docs/spike2-results.md).
  First public numbers: verifying even the smallest Stwo proof with the full
  Cairo verifier costs **10.0–15.9M steps** (at or 1.5× over the 1.1e9 L2
  gas/tx budget) plus 65k–223k felts of proof vs a 5k-felt calldata cap.
  The **circuit verifier** (recursion route) costs **3.79M steps ≈ 38% of
  one tx** with a 35.7k-felt proof — single-tx verification is viable there.
- **Spike 3 (recursion route end-to-end): next.** Drive
  [stwo-circuits](https://github.com/starkware-libs/stwo-circuits) to wrap
  an arbitrary program's proof in a circuit proof and check topology match
  with the on-chain circuit verifier.

## Layout

- `vendor/stwo_cairo_verifier/` — vendored verifier crates, pinned upstream
  commit, unmodified (Apache-2.0; see `VENDORED.md` there).
- `contracts/stwo_verifier_contract/` — thin contract wrapper around the full
  Cairo verifier (`poseidon252_verifier` config).
- `contracts/stwo_circuit_verifier_contract/` — thin contract wrapper around
  the circuit verifier (blake2s config).

## Build

Requires Scarb 2.18.0 (see `.tool-versions`).

```sh
scarb build
```

## Honest framing

- The incumbent is SNIP-36: one tx, ~cents, seconds — but it requires a local
  native proving service and only proves virtual-SNOS executions. This
  project's win condition is UX + generality (browser proofs of arbitrary
  Cairo executables), accepting higher on-chain cost.
- Stwo proofs are not formally ZK; this route posts the full proof into
  public calldata permanently. Do not put long-lived secrets in witnesses.
- Any `set_verifier`-style integration in consumer contracts must be
  owner-gated and eventually immutable — a swappable verifier is a rug vector.

## License

Apache-2.0. Vendored code is Copyright StarkWare Industries Ltd., also
Apache-2.0.
