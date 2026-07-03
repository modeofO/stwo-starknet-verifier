# Vendored code: stwo_cairo_verifier

The crates under `crates/` are vendored, unmodified, from:

- **Source:** https://github.com/starkware-libs/stwo-cairo
- **Path in source repo:** `stwo_cairo_verifier/crates/`
- **Pinned commit:** `92bfd1d3e203dc7f7af3e39f46e9e06abc3be844` (2026-06-30, "Add add_remainder function (#1807)")
- **License:** Apache-2.0 (see repo-root `LICENSE`; upstream declares Apache-2.0 in its README and crate manifests — there is no standalone LICENSE file upstream at the pinned commit)
- **Upstream toolchain pin:** scarb 2.18.0 (from upstream `.tool-versions`)

Crates vendored (the `cairo_verifier` executable's full dependency tree):

| Crate | Package name | Role |
|---|---|---|
| `cairo_verifier` | `stwo_cairo_verifier` | Executable entry point (`main(proof: CairoProof) -> VerificationOutput`). **Not** a member of the root workspace — executable targets require `enable-gas = false`, which conflicts with the contract build. Kept for Spike 2 (step-count measurement). |
| `cairo_air` | `stwo_cairo_air` | Cairo AIR: `CairoProof`, `verify_cairo`, `get_verification_output` |
| `verifier_core` | `stwo_verifier_core` | FRI / PCS / channel |
| `constraint_framework` | `stwo_constraint_framework` | Constraint evaluation framework |
| `verifier_utils` | `stwo_verifier_utils` | Hash / memory-section utilities |
| `bounded_int` | `bounded_int` | M31/CM31/QM31 emulation over felt252 (the no-`qm31_opcode` path) |
| `circuit_air` | `stwo_circuit_air` | AIR for the hardcoded privacy/multiverifier recursion circuit. **Blake2s-only**: under `poseidon252_verifier` its `get_verification_output` unconditionally panics. |
| `circuit_verifier` | `stwo_circuit_verifier` | Executable entry point for the circuit verifier. Not a root-workspace member (same `enable-gas` conflict as `cairo_verifier`). |

Feature model (from upstream `cairo_air/src/features_check.cairo`): exactly one of
`qm31_opcode` / `poseidon252_verifier` must be enabled. The contract build uses
`poseidon252_verifier` (Poseidon is a Starknet builtin; the qm31 libfuncs are absent
from the `audited.json` allowlist enforced for declared contract classes).

Any local modifications to these crates must be documented here.

## Local modifications

Manifests only — no Cairo source has been modified:

- In each crate's `Scarb.toml`, workspace-inherited entries were made
  self-contained, because the crates are consumed here as path dependencies
  rather than workspace members (non-members cannot inherit from
  `[workspace.dependencies]`):
  - `cairo_test.workspace = true` → `cairo_test = "2.18.0"`
  - `cairo_execute.workspace = true` → `cairo_execute = "2.18.0"`
  - the `[tool] cairo-lint.workspace = true` entries were removed.
