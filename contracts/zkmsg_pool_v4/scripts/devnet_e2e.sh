#!/usr/bin/env bash
# Local-only end to end of the pool spike on starknet-devnet (>= 0.9).
# CONTENT_LEN=1372|2140|5212 picks the padded size; POOL_ONLY=1 skips the virtual phase.
# For each phase: start a throwaway devnet on 127.0.0.1, declare the three
# classes with a predeployed account, run scripts/devnet_e2e.py, stop it.
#   virtual: --proof-mode devnet (starknet_proveTransaction, virtual sender)
#   pool:    --proof-mode none   (real-layout facts, real validate/execute)
set -euo pipefail
cd "$(dirname "$0")/.."
SCARB_BIN=${SCARB_BIN:-/Users/modeofo/Apps/snip36-spike/scarb-v2.18.0-aarch64-apple-darwin/bin}
export PATH="$SCARB_BIN:$PATH"
PORT=${PORT:-5051}
URL=http://127.0.0.1:$PORT

[ -x scripts/poseidon/target/release/poseidon-many ] ||
  cargo build --release --offline -q --manifest-path scripts/poseidon/Cargo.toml
scarb build > /dev/null

run_phase() {
  local phase=$1 mode=$2 work
  work=$(mktemp -d)
  starknet-devnet --seed 0 --accounts 2 --port "$PORT" --proof-mode "$mode" \
    --state-archive-capacity full > "$work/devnet.log" 2>&1 &
  local devnet=$!
  until curl -s "$URL/is_alive" > /dev/null; do sleep 0.2; done
  local acc="$work/accounts.json"
  sncast --accounts-file "$acc" account import --url "$URL" --name dev0 --type oz --silent \
    --address 0x064b48806902a367c8598f4f95c305e8c1a1acba5f082d294a43793113115691 \
    --private-key 0x71d7bb07b9a64f6f78ac4c816aff4da9 > /dev/null
  sncast --accounts-file "$acc" account import --url "$URL" --name dev1 --type oz --silent \
    --address 0x078662e7352d062084b0010068b99288486c2d8b914f6e2a55ce945f8792c8b1 \
    --private-key 0xe1406455b7d66b1690803be066cbe5e > /dev/null
  declare_class() {
    sncast --accounts-file "$acc" --account dev0 declare --url "$URL" --contract-name "$1" \
      | sed -n 's/^Class Hash: *//p'
  }
  local prover pool vsender status=0
  prover=$(declare_class ZkmsgSendProverV4)
  pool=$(declare_class ZkmsgPoolV4)
  vsender=$(declare_class ZkmsgVirtualSenderV4)
  echo "##### phase $phase (devnet --proof-mode $mode)"
  python3 scripts/devnet_e2e.py "$phase" "$URL" "$acc" "$prover" "$pool" "$vsender" || status=$?
  kill "$devnet"; wait "$devnet" 2>/dev/null || true
  rm -rf "$work"
  return $status
}

[ -n "${POOL_ONLY:-}" ] || run_phase virtual devnet
run_phase pool none
