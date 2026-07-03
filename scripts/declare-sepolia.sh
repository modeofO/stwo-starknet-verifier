#!/usr/bin/env bash
# Declare (and optionally deploy) the StwoFactRegistry class on Starknet Sepolia.
#
# This also settles Spike 1's open question empirically: whether the
# 81,920-felt bytecode cap is enforced on Sierra or CASM (our class is
# 49,432 Sierra felts; CASM headroom is the thing to watch).
#
# Prereqs: an sncast account configured and funded on Sepolia, e.g.
#   sncast account create --network sepolia --name deployer
#   (fund the address, then) sncast account deploy --network sepolia --name deployer
#
# Usage:
#   scripts/declare-sepolia.sh                # declare only
#   scripts/declare-sepolia.sh <class_hash>   # deploy an already-declared class
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ACCOUNT="${ACCOUNT:-deployer}"
export PATH="$HOME/.local/share/scarb-install/2.18.0/bin:$PATH"

cd "$REPO_ROOT"
if [ $# -eq 0 ]; then
  scarb build -p stwo_fact_registry
  sncast --account "$ACCOUNT" declare --network sepolia \
    --contract-name StwoFactRegistry --package stwo_fact_registry
else
  sncast --account "$ACCOUNT" deploy --network sepolia --class-hash "$1"
fi
