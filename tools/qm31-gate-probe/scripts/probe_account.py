#!/usr/bin/env python3
"""Free balance/nonce oracle for sepolia-integration.

Integration's feeder deprecated every state-read endpoint (get_nonce,
call_contract) in 0.12.3, so there is no way to *ask* for an account's balance
or nonce. But the gateway validates a submission before accepting it, and its
rejection text names what failed:

    VALIDATE_FAILURE: ... Resources bounds ... exceed balance (N)   -> balance N
    INVALID_TRANSACTION_NONCE: ... expected N, got M                -> nonce N

A rejected transaction never enters a block and costs nothing, so submitting
one deliberately doomed transaction is a free query. This sends an invoke with
absurd resource bounds (guaranteed to exceed any balance) so the reply carries
the number we want.

Usage: probe_account.py [nonce]
"""
import json
import pathlib
import sys
import urllib.error
import urllib.request

from starknet_py.hash.transaction import (
    TransactionHashPrefix,
    compute_invoke_v3_transaction_hash,
)
from starknet_py.hash.utils import message_signature
from starknet_py.net.client_models import (
    DAMode,
    ResourceBounds,
    ResourceBoundsMapping,
)
from starknet_py.hash.selector import get_selector_from_name
from starknet_py.net.models.transaction import CommonTransactionV3Fields

GATEWAY = "https://integration-sepolia.starknet.io/gateway"
CHAIN_ID = int.from_bytes(b"SN_INTEGRATION_SEPOLIA", "big")
STRK = 0x04718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D

keys = json.loads((pathlib.Path.home() / ".config/qm31-integration/keys.json").read_text())
PRIV = int(keys["stark_private_key"], 16)
ACCOUNT = int(keys["l2_account_address"], 16)

nonce = int(sys.argv[1]) if len(sys.argv) > 1 else 0

# Deliberately unaffordable: 1e9 L2 gas at 1e18 fri/unit. No balance covers it,
# so validation must fail on funds — and say by how much.
rb = ResourceBoundsMapping(
    l1_gas=ResourceBounds(0, 10**18),
    l2_gas=ResourceBounds(10**9, 10**18),
    l1_data_gas=ResourceBounds(0x2000, 10**18),
)

# A harmless call that would never execute: balance_of on the fee token.
calldata = [1, STRK, get_selector_from_name("balance_of"), 1, ACCOUNT]

common = CommonTransactionV3Fields(
    tx_prefix=TransactionHashPrefix.INVOKE,
    version=3,
    address=ACCOUNT,
    tip=0,
    resource_bounds=rb,
    paymaster_data=[],
    chain_id=CHAIN_ID,
    nonce=nonce,
    nonce_data_availability_mode=DAMode.L1,
    fee_data_availability_mode=DAMode.L1,
)
h = compute_invoke_v3_transaction_hash(
    account_deployment_data=[], calldata=calldata, common_fields=common
)

payload = {
    "type": "INVOKE_FUNCTION",
    "sender_address": hex(ACCOUNT),
    "calldata": [hex(c) for c in calldata],
    "account_deployment_data": [],
    "version": "0x3",
    "signature": [hex(s) for s in message_signature(h, PRIV)],
    "nonce": hex(nonce),
    "resource_bounds": {
        "L1_GAS": {"max_amount": hex(rb.l1_gas.max_amount),
                   "max_price_per_unit": hex(rb.l1_gas.max_price_per_unit)},
        "L2_GAS": {"max_amount": hex(rb.l2_gas.max_amount),
                   "max_price_per_unit": hex(rb.l2_gas.max_price_per_unit)},
        "L1_DATA_GAS": {"max_amount": hex(rb.l1_data_gas.max_amount),
                        "max_price_per_unit": hex(rb.l1_data_gas.max_price_per_unit)},
    },
    "tip": "0x0",
    "paymaster_data": [],
    "nonce_data_availability_mode": 0,
    "fee_data_availability_mode": 0,
}

print(f"probing account {hex(ACCOUNT)} at nonce {nonce} (expect rejection)")
req = urllib.request.Request(
    f"{GATEWAY}/add_transaction",
    data=json.dumps(payload).encode(),
    headers={"Content-Type": "application/json"},
)
try:
    with urllib.request.urlopen(req, timeout=120) as resp:
        print("UNEXPECTED ACCEPT", resp.status, resp.read().decode())
except urllib.error.HTTPError as e:
    body = e.read().decode()
    print(f"HTTP {e.code}")
    print(body)
