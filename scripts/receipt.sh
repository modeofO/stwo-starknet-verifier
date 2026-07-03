#!/usr/bin/env bash
# Pretty-print a Starknet tx receipt (status, fee, gas resources, events).
# Usage: scripts/receipt.sh <tx_hash> [rpc_url]
set -euo pipefail
TX="${1:?usage: receipt.sh <tx_hash> [rpc_url]}"
URL="${2:-https://api.zan.top/public/starknet-sepolia/rpc/v0_10}"
RESP=$(curl -s -X POST -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"starknet_getTransactionReceipt\",\"params\":[\"$TX\"],\"id\":1}" "$URL")
python3 - "$RESP" <<'PYEOF'
import json, sys
resp = json.loads(sys.argv[1])
if "error" in resp:
    print("error:", resp["error"]); sys.exit(1)
r = resp["result"]
print("status :", r["execution_status"], "/", r.get("finality_status", "?"))
print("fee    :", round(int(r["actual_fee"]["amount"], 16) / 1e18, 4), "STRK")
print("gas    :", r["execution_resources"])
if r.get("revert_reason"):
    print("revert :", r["revert_reason"][:500])
for e in r.get("events", []):
    print("event  :", e["keys"][0][:18], "… data:", [d[:14] for d in e["data"][:4]])
PYEOF
