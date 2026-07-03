#!/usr/bin/env bash
# End-to-end pipeline: Cairo program -> Stwo proof -> recursion circuit proofs ->
# felt252 stream -> verified by the (deployable) Cairo circuit verifier.
#
# Usage:
#   scripts/prove-and-verify.sh <task> [program_args_file.json]
#
#   <task>  a scarb-built executable JSON (e.g. fixtures/target/dev/poseidon_chain.executable.json)
#           or a Cairo PIE zip.
#
# Prereqs: scripts/setup-prover.sh has been run; scarb 2.18.0 on PATH or at
# ~/.local/share/scarb-install/2.18.0/bin/scarb.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TASK="${1:?usage: prove-and-verify.sh <executable.json|pie.zip> [args_file.json]}"
ARGS_FILE="${2:-}"
BRIDGE="$REPO_ROOT/.prover/proving-utils/target/release/privacy_prove_cairo_bridge"
SCARB="${SCARB:-$(command -v scarb || echo "$HOME/.local/share/scarb-install/2.18.0/bin/scarb")}"
OUT_DIR="$REPO_ROOT/target/pipeline"
mkdir -p "$OUT_DIR"

[ -x "$BRIDGE" ] || { echo "bridge not built - run scripts/setup-prover.sh first" >&2; exit 1; }

PROOF_JSON="$OUT_DIR/multiverifier_proof.json"
PREIMAGE_JSON="$OUT_DIR/output_preimage.json"
CAIRO_PROOF_JSON="$OUT_DIR/cairo_proof.json"

# Two stages across the proof-only boundary (docs/proof-only-wrapping.md):
# `prove` is the client side (program + witness stay here), `wrap` is the
# untrusted middleman side (sees only the proof + public output preimage).
echo "=== stage 1: prove (client side: bootloader -> stwo proof) ==="
"$BRIDGE" prove "$TASK" "$CAIRO_PROOF_JSON" "$PREIMAGE_JSON" ${ARGS_FILE:+"$ARGS_FILE"}

echo
echo "=== stage 2: wrap (proof-only: circuit -> multiverifier) ==="
"$BRIDGE" wrap "$CAIRO_PROOF_JSON" "$PREIMAGE_JSON" "$PROOF_JSON"

echo
echo "=== verifying with the Cairo circuit verifier (the deployable one) ==="
cd "$REPO_ROOT/vendor/stwo_cairo_verifier"
"$SCARB" execute -p stwo_circuit_verifier --target standalone --output standard \
  --print-resource-usage --arguments-file "$PROOF_JSON"

echo
echo "cairo proof:      $CAIRO_PROOF_JSON  (the client->wrapper handoff)"
echo "proof:            $PROOF_JSON"
echo "output preimage:  $PREIMAGE_JSON"
