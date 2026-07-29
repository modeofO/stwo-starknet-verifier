#!/usr/bin/env bash
# One-time setup for the proving side of the pipeline: clones StarkWare's
# proving-utils at the pinned commit, adds our bridge crate
# (tools/privacy-prove-cairo-bridge) to its workspace, applies the small
# patch that exposes the bootloader-run helper, and builds the bridge binary.
#
# Usage: scripts/setup-prover.sh [checkout-dir]   (default: .prover/)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHECKOUT_DIR="${1:-$REPO_ROOT/.prover}"
PROVING_UTILS_REV="b6fe5d3be948aceecea9fa973f33d1b25296b682"

mkdir -p "$CHECKOUT_DIR"
if [ ! -d "$CHECKOUT_DIR/proving-utils/.git" ]; then
  git clone https://github.com/starkware-libs/proving-utils.git "$CHECKOUT_DIR/proving-utils"
fi
cd "$CHECKOUT_DIR/proving-utils"
git fetch origin "$PROVING_UTILS_REV"
git checkout -q "$PROVING_UTILS_REV"
git reset -q --hard && git clean -qfd crates/privacy_prove_cairo_bridge 2>/dev/null || true

# Apply the privacy_prove patch (exposes run_privacy_bootloader_task and the raw
# recursive prover; adds the bridge crate to the workspace members).
git apply "$REPO_ROOT/tools/proving-utils-bridge.patch"

# Drop in the bridge crate.
mkdir -p crates/privacy_prove_cairo_bridge/src
cp "$REPO_ROOT/tools/privacy-prove-cairo-bridge/Cargo.toml" crates/privacy_prove_cairo_bridge/
cp "$REPO_ROOT"/tools/privacy-prove-cairo-bridge/src/*.rs crates/privacy_prove_cairo_bridge/src/

cargo build --release -p privacy-prove-cairo-bridge
echo
echo "OK: $CHECKOUT_DIR/proving-utils/target/release/privacy_prove_cairo_bridge"
