#!/usr/bin/env bash
# Local-only end to end of the pool spike on starknet-devnet (>= 0.9).
# Starts a throwaway devnet on 127.0.0.1, declares the three classes with a
# predeployed account, runs scripts/devnet_e2e.py, stops devnet.
set -euo pipefail
cd "$(dirname "$0")/.."
SCARB_BIN=${SCARB_BIN:-/Users/modeofo/Apps/snip36-spike/scarb-v2.18.0-aarch64-apple-darwin/bin}
export PATH="$SCARB_BIN:$PATH"
PORT=${PORT:-5051}
URL=http://127.0.0.1:$PORT
WORK=$(mktemp -d)
trap 'kill $DEVNET 2>/dev/null || true; rm -rf "$WORK"' EXIT

starknet-devnet --seed 0 --accounts 2 --port "$PORT" --proof-mode devnet \
  --state-archive-capacity full > "$WORK/devnet.log" 2>&1 &
DEVNET=$!
until curl -s "$URL/is_alive" > /dev/null; do sleep 0.2; done

ACC="$WORK/accounts.json"
sncast --accounts-file "$ACC" account import --url "$URL" --name dev0 --type oz --silent \
  --address 0x064b48806902a367c8598f4f95c305e8c1a1acba5f082d294a43793113115691 \
  --private-key 0x71d7bb07b9a64f6f78ac4c816aff4da9 > /dev/null
sncast --accounts-file "$ACC" account import --url "$URL" --name dev1 --type oz --silent \
  --address 0x078662e7352d062084b0010068b99288486c2d8b914f6e2a55ce945f8792c8b1 \
  --private-key 0xe1406455b7d66b1690803be066cbe5e > /dev/null

declare_class() {
  sncast --accounts-file "$ACC" --account dev0 declare --url "$URL" --contract-name "$1" \
    | sed -n 's/^Class Hash: *//p'
}
PROVER=$(declare_class ZkmsgSendProverV4)
POOL=$(declare_class ZkmsgPoolV4)
VSENDER=$(declare_class ZkmsgVirtualSenderV4)

python3 scripts/devnet_e2e.py "$URL" "$ACC" "$PROVER" "$POOL" "$VSENDER"
