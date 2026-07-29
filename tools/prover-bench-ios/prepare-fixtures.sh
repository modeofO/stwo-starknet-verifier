#!/usr/bin/env bash
# Stages the bench's bundled workload: the public poseidon_chain(100) task and
# a wrap input proved for it. Both are regenerable and gitignored (repo
# convention for large prover artifacts).
#
# Prerequisites: scripts/setup-prover.sh has built the bridge, and
# `cd fixtures && scarb build` has produced the executable.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RES="$REPO_ROOT/tools/prover-bench-ios/Resources"
BRIDGE="${ZKMSG_BRIDGE_BIN:-$REPO_ROOT/.prover/proving-utils/target/release/privacy_prove_cairo_bridge}"
TASK="$REPO_ROOT/fixtures/target/dev/poseidon_chain.executable.json"

[ -x "$BRIDGE" ] || { echo "missing bridge binary: $BRIDGE (run scripts/setup-prover.sh)" >&2; exit 1; }
[ -f "$TASK" ] || { echo "missing task: $TASK (run: cd fixtures && scarb build)" >&2; exit 1; }

mkdir -p "$RES"
cp "$TASK" "$RES/task.executable.json"
cp "$REPO_ROOT/fixtures/poseidon_chain_args_100.json" "$RES/task_args.json"

# The wrap leg needs an inner proof to consume; prove one on the host so the
# bench can time wrap independently of prove.
"$BRIDGE" prove "$TASK" "$RES/wrap_input_proof.json" "$RES/wrap_input_preimage.json" \
    "$RES/task_args.json"

echo "staged bench fixtures in $RES"
