"""Submit a DECLARE v3 of Qm31Probe to a Starknet sequencer gateway and print the response.

Usage: python3 declare_probe.py {alpha|integration} [compiled_class_hash]

The sender is a nonexistent account with a dummy signature: the point is not to land
the declare but to observe WHICH check rejects it. The gateway checks compilation
before account existence, signature, or balance, so this needs no funds:

  COMPILATION_FAILED            -> the libfunc allowlist gate fired (gate closed)
  INVALID_COMPILED_CLASS_HASH   -> compilation SUCCEEDED (gate open); the error
                                   carries the gateway's own CASM hash — pass it
                                   as argv[2] to step past this check
  VALIDATE_FAILURE (balance)    -> class fully accepted, only fees stand in the way

Build the artifact first: cd tools/qm31-gate-probe && scarb build
Default compiled_class_hash is from universal-sierra-compiler 2.8.0 (scarb 2.18
artifact); integration's compiler generates different qm31 CASM, so expect to
need the two-step dance there.
"""
import base64
import gzip
import json
import pathlib
import sys
import urllib.request
import urllib.error

ARTIFACT = (
    pathlib.Path(__file__).resolve().parents[1]
    / "target/dev/qm31_gate_probe_Qm31Probe.contract_class.json"
)
USC_2_8_0_COMPILED_CLASS_HASH = (
    "0x05df8b456facd3485f7a830e31f2cf3f2ef1a24b2666fd73181b374ab3c72f79"
)
GATEWAYS = {
    "alpha": "https://alpha-sepolia.starknet.io/gateway/add_transaction",
    "integration": "https://integration-sepolia.starknet.io/gateway/add_transaction",
}

target = sys.argv[1]
compiled_class_hash = sys.argv[2] if len(sys.argv) > 2 else USC_2_8_0_COMPILED_CLASS_HASH

artifact = json.loads(ARTIFACT.read_text())

payload = {
    "type": "DECLARE",
    "version": "0x3",
    "sender_address": "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
    "compiled_class_hash": compiled_class_hash,
    "signature": ["0x1", "0x2"],
    "nonce": "0x0",
    "contract_class": {
        "sierra_program": base64.b64encode(
            gzip.compress(json.dumps(artifact["sierra_program"]).encode())
        ).decode(),
        "contract_class_version": artifact["contract_class_version"],
        "entry_points_by_type": artifact["entry_points_by_type"],
        "abi": json.dumps(artifact["abi"]),
    },
    "resource_bounds": {
        "L1_GAS": {"max_amount": "0x0", "max_price_per_unit": "0x1000000000000"},
        "L2_GAS": {"max_amount": "0x1c9c380", "max_price_per_unit": "0x10000000000"},
        "L1_DATA_GAS": {"max_amount": "0x1000", "max_price_per_unit": "0x10000000000"},
    },
    "tip": "0x0",
    "paymaster_data": [],
    "account_deployment_data": [],
    "nonce_data_availability_mode": 0,
    "fee_data_availability_mode": 0,
}

req = urllib.request.Request(
    GATEWAYS[target],
    data=json.dumps(payload).encode(),
    headers={"Content-Type": "application/json"},
)
try:
    with urllib.request.urlopen(req, timeout=120) as resp:
        print(f"HTTP {resp.status}")
        print(resp.read().decode())
except urllib.error.HTTPError as e:
    print(f"HTTP {e.code}")
    print(e.read().decode())
