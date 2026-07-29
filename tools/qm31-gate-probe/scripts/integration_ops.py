"""L2 leg of the integration qm31 campaign: signed v3 transactions POSTed straight
to the integration-sepolia gateway (no RPC provider serves this network).

Usage:
  integration_ops.py deploy-account
  integration_ops.py declare <nonce>
  integration_ops.py deploy-probe <nonce>
  integration_ops.py invoke-mul <nonce> <rounds>
  integration_ops.py greet <nonce>     # dust STRK to StarkWare's funding account,
                                       # amount 0x716d3331 fri = ascii "qm31"
  integration_ops.py status <tx_hash>
  integration_ops.py declare-file <nonce> <artifact.json> <compiled_class_hash> [l2_gas]
  integration_ops.py deploy-udc <nonce> <class_hash> <salt> [constructor_felts...]

Nonces are passed explicitly because every state-read feeder endpoint is
deprecated: deploy-account is nonce 0 implicitly, the account's next nonce is 1,
and each accepted transaction increments it. Track by counting accepted txs.

Keys from ~/.config/qm31-integration/keys.json. Signing uses starknet.py's v3
Poseidon transaction hashes with chain id SN_INTEGRATION_SEPOLIA; wire format
matches apollo_starknet_client writer objects (established in declare_probe.py).
"""
import base64
import gzip
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

from starknet_py.hash.selector import get_selector_from_name
from starknet_py.hash.transaction import (
    CommonTransactionV3Fields,
    TransactionHashPrefix,
    compute_declare_v3_transaction_hash,
    compute_deploy_account_v3_transaction_hash,
    compute_invoke_v3_transaction_hash,
    compute_sierra_class_hash,
)
from starknet_py.hash.utils import message_signature
from starknet_py.net.client_models import DAMode, ResourceBounds, ResourceBoundsMapping
from starknet_py.net.schemas.rpc.contract import SierraContractClassSchema

GATEWAY = "https://integration-sepolia.starknet.io/gateway"
FEEDER = "https://feeder.integration-sepolia.starknet.io/feeder_gateway"
CHAIN_ID = int.from_bytes(b"SN_INTEGRATION_SEPOLIA", "big")
UDC = 0x041A78E741E5AF2FEC34B695679BC6891742439F7AFB8484ECD7766661AD02BF
STRK_FEE_TOKEN = 0x04718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D

ARTIFACT = (
    pathlib.Path(__file__).resolve().parents[1]
    / "target/dev/qm31_gate_probe_Qm31Probe.contract_class.json"
)
# Integration's compiler emits different qm31 CASM than local USC 2.8.0; this is
# the hash the gateway itself computed (recovered via INVALID_COMPILED_CLASS_HASH).
GATEWAY_COMPILED_CLASS_HASH = 0x2758889B6F6C9C0568B2E0FAA35AE49B654AB7C88F960624C70CE57276D08B6
PROBE_DEPLOY_SALT = 0x716D3331  # 'qm31'

# ZKMSG_KEYS selects the identity: the campaign account by default, or a
# second one (e.g. a message recipient, which needs its own address because
# the store permits one registration per caller).
_keyfile = os.environ.get(
    "ZKMSG_KEYS", str(pathlib.Path.home() / ".config/qm31-integration/keys.json")
)
keys = json.loads(pathlib.Path(_keyfile).read_text())
PRIV = int(keys["stark_private_key"], 16)
PUB = int(keys["stark_public_key"], 16)
ACCOUNT = int(keys["l2_account_address"], 16)
OZ_CLASS = int(keys["l2_account_class"], 16)


def current_gas_prices():
    with urllib.request.urlopen(f"{FEEDER}/get_block?blockNumber=latest", timeout=30) as r:
        b = json.load(r)
    return (
        int(b["l1_gas_price"]["price_in_fri"], 16),
        int(b["l2_gas_price"]["price_in_fri"], 16),
        int(b["l1_data_gas_price"]["price_in_fri"], 16),
    )


def bounds(l2_amount, price_mult=3.0, data_amount=0x2000):
    l1_price, l2_price, data_price = current_gas_prices()
    return ResourceBoundsMapping(
        l1_gas=ResourceBounds(0, int(l1_price * price_mult)),
        l2_gas=ResourceBounds(l2_amount, int(l2_price * price_mult)),
        l1_data_gas=ResourceBounds(data_amount, int(data_price * price_mult)),
    )


def bounds_json(rb):
    return {
        "L1_GAS": {"max_amount": hex(rb.l1_gas.max_amount),
                   "max_price_per_unit": hex(rb.l1_gas.max_price_per_unit)},
        "L2_GAS": {"max_amount": hex(rb.l2_gas.max_amount),
                   "max_price_per_unit": hex(rb.l2_gas.max_price_per_unit)},
        "L1_DATA_GAS": {"max_amount": hex(rb.l1_data_gas.max_amount),
                        "max_price_per_unit": hex(rb.l1_data_gas.max_price_per_unit)},
    }


def common(prefix, address, nonce, rb):
    return CommonTransactionV3Fields(
        tx_prefix=prefix, version=3, address=address, tip=0, resource_bounds=rb,
        paymaster_data=[], chain_id=CHAIN_ID, nonce=nonce,
        nonce_data_availability_mode=DAMode.L1, fee_data_availability_mode=DAMode.L1,
    )


def post(payload):
    req = urllib.request.Request(
        f"{GATEWAY}/add_transaction",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            print(f"HTTP {resp.status}")
            print(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code}")
        print(e.read().decode())


def v3_base(signature, nonce, rb):
    return {
        "version": "0x3",
        "signature": [hex(s) for s in signature],
        "nonce": hex(nonce),
        "resource_bounds": bounds_json(rb),
        "tip": "0x0",
        "paymaster_data": [],
        "nonce_data_availability_mode": 0,
        "fee_data_availability_mode": 0,
    }


cmd = sys.argv[1]

if cmd == "deploy-account":
    rb = bounds(30_000_000)
    h = compute_deploy_account_v3_transaction_hash(
        class_hash=OZ_CLASS, constructor_calldata=[PUB], contract_address_salt=PUB,
        common_fields=common(TransactionHashPrefix.DEPLOY_ACCOUNT, ACCOUNT, 0, rb),
    )
    payload = {
        "type": "DEPLOY_ACCOUNT",
        "class_hash": hex(OZ_CLASS),
        "contract_address_salt": hex(PUB),
        "constructor_calldata": [hex(PUB)],
        **v3_base(message_signature(h, PRIV), 0, rb),
    }
    print("deploying account", hex(ACCOUNT), "tx hash", hex(h))
    post(payload)

elif cmd == "declare":
    nonce = int(sys.argv[2])
    artifact = json.loads(ARTIFACT.read_text())
    sierra_class = SierraContractClassSchema().load({
        "sierra_program": artifact["sierra_program"],
        "contract_class_version": artifact["contract_class_version"],
        "entry_points_by_type": artifact["entry_points_by_type"],
        "abi": json.dumps(artifact["abi"]),
    })
    class_hash = compute_sierra_class_hash(sierra_class)
    rb = bounds(40_000_000)
    h = compute_declare_v3_transaction_hash(
        class_hash=class_hash, account_deployment_data=[],
        compiled_class_hash=GATEWAY_COMPILED_CLASS_HASH,
        common_fields=common(TransactionHashPrefix.DECLARE, ACCOUNT, nonce, rb),
    )
    payload = {
        "type": "DECLARE",
        "sender_address": hex(ACCOUNT),
        "compiled_class_hash": hex(GATEWAY_COMPILED_CLASS_HASH),
        "contract_class": {
            "sierra_program": base64.b64encode(
                gzip.compress(json.dumps(artifact["sierra_program"]).encode())
            ).decode(),
            "contract_class_version": artifact["contract_class_version"],
            "entry_points_by_type": artifact["entry_points_by_type"],
            "abi": json.dumps(artifact["abi"]),
        },
        "account_deployment_data": [],
        **v3_base(message_signature(h, PRIV), nonce, rb),
    }
    print("declaring class", hex(class_hash), "tx hash", hex(h))
    post(payload)

elif cmd in ("deploy-probe", "invoke-mul"):
    nonce = int(sys.argv[2])
    artifact = json.loads(ARTIFACT.read_text())
    sierra_class = SierraContractClassSchema().load({
        "sierra_program": artifact["sierra_program"],
        "contract_class_version": artifact["contract_class_version"],
        "entry_points_by_type": artifact["entry_points_by_type"],
        "abi": json.dumps(artifact["abi"]),
    })
    class_hash = compute_sierra_class_hash(sierra_class)
    if cmd == "deploy-probe":
        # UDC deployContract(classHash, salt, unique=0, calldata=[])
        inner = [class_hash, PROBE_DEPLOY_SALT, 0, 0]
        calls = [(UDC, get_selector_from_name("deployContract"), inner)]
    else:
        from starknet_py.hash.address import compute_address
        probe_addr = compute_address(
            class_hash=class_hash, constructor_calldata=[],
            salt=PROBE_DEPLOY_SALT, deployer_address=0,
        )
        rounds = int(sys.argv[3])
        calls = [(probe_addr, get_selector_from_name("mul_qm31"), [rounds])]
        print("probe address", hex(probe_addr))
    calldata = [len(calls)]
    for to, sel, inner in calls:
        calldata += [to, sel, len(inner)] + inner
    rb = bounds(20_000_000)
    h = compute_invoke_v3_transaction_hash(
        account_deployment_data=[], calldata=calldata,
        common_fields=common(TransactionHashPrefix.INVOKE, ACCOUNT, nonce, rb),
    )
    payload = {
        "type": "INVOKE_FUNCTION",
        "sender_address": hex(ACCOUNT),
        "calldata": [hex(c) for c in calldata],
        "account_deployment_data": [],
        **v3_base(message_signature(h, PRIV), nonce, rb),
    }
    print("invoke tx hash", hex(h))
    post(payload)

elif cmd == "greet":
    # On-chain hello to the account StarkWare tops up with 10M STRK/day; pairs
    # with the L1 calldata note sent to their funding EOA (0xabbfba2a...0b72).
    nonce = int(sys.argv[2])
    STARKWARE_L2 = 0x027125DC293A66E3DF8784C51ED07C7011CF02F5FE53DE3163AE78CBAB7E80F5
    QM31_FRI = 0x716D3331  # ascii "qm31"
    calldata = [1, STRK_FEE_TOKEN, get_selector_from_name("transfer"), 3,
                STARKWARE_L2, QM31_FRI, 0]
    rb = bounds(5_000_000)
    h = compute_invoke_v3_transaction_hash(
        account_deployment_data=[], calldata=calldata,
        common_fields=common(TransactionHashPrefix.INVOKE, ACCOUNT, nonce, rb),
    )
    payload = {
        "type": "INVOKE_FUNCTION",
        "sender_address": hex(ACCOUNT),
        "calldata": [hex(c) for c in calldata],
        "account_deployment_data": [],
        **v3_base(message_signature(h, PRIV), nonce, rb),
    }
    print("greeting tx hash", hex(h), "-> transfer 0x716d3331 fri ('qm31') to", hex(STARKWARE_L2))
    post(payload)

elif cmd == "declare-file":
    nonce = int(sys.argv[2])
    artifact = json.loads(pathlib.Path(sys.argv[3]).read_text())
    compiled_hash = int(sys.argv[4], 16)
    l2_amount = int(sys.argv[5]) if len(sys.argv) > 5 else 100_000_000
    price_mult = float(sys.argv[6]) if len(sys.argv) > 6 else 3.0
    sierra_class = SierraContractClassSchema().load({
        "sierra_program": artifact["sierra_program"],
        "contract_class_version": artifact["contract_class_version"],
        "entry_points_by_type": artifact["entry_points_by_type"],
        "abi": json.dumps(artifact["abi"]),
    })
    class_hash = compute_sierra_class_hash(sierra_class)
    rb = bounds(l2_amount, price_mult)
    h = compute_declare_v3_transaction_hash(
        class_hash=class_hash, account_deployment_data=[],
        compiled_class_hash=compiled_hash,
        common_fields=common(TransactionHashPrefix.DECLARE, ACCOUNT, nonce, rb),
    )
    payload = {
        "type": "DECLARE",
        "sender_address": hex(ACCOUNT),
        "compiled_class_hash": hex(compiled_hash),
        "contract_class": {
            "sierra_program": base64.b64encode(
                gzip.compress(json.dumps(artifact["sierra_program"]).encode())
            ).decode(),
            "contract_class_version": artifact["contract_class_version"],
            "entry_points_by_type": artifact["entry_points_by_type"],
            "abi": json.dumps(artifact["abi"]),
        },
        "account_deployment_data": [],
        **v3_base(message_signature(h, PRIV), nonce, rb),
    }
    print("declaring class", hex(class_hash), "tx hash", hex(h))
    post(payload)

elif cmd == "invoke":
    # Generic single-call invoke: invoke <nonce> <contract> <selector> [felt args...]
    # Used to drive contracts on integration, where no RPC provider exists and
    # sncast therefore cannot reach the network.
    nonce = int(sys.argv[2])
    contract = int(sys.argv[3], 16)
    selector = get_selector_from_name(sys.argv[4])
    call_args = [int(x, 16) if x.startswith("0x") else int(x) for x in sys.argv[5:]]
    l2_amount = int(os.environ.get("L2_GAS", "40000000"))
    calldata = [1, contract, selector, len(call_args)] + call_args
    rb = bounds(l2_amount)
    h = compute_invoke_v3_transaction_hash(
        account_deployment_data=[], calldata=calldata,
        common_fields=common(TransactionHashPrefix.INVOKE, ACCOUNT, nonce, rb),
    )
    payload = {
        "type": "INVOKE_FUNCTION",
        "sender_address": hex(ACCOUNT),
        "calldata": [hex(c) for c in calldata],
        "account_deployment_data": [],
        **v3_base(message_signature(h, PRIV), nonce, rb),
    }
    print(f"invoking {sys.argv[4]} on {hex(contract)} tx hash {hex(h)}")
    post(payload)

elif cmd == "deploy-udc":
    nonce = int(sys.argv[2])
    class_hash = int(sys.argv[3], 16)
    salt = int(sys.argv[4], 16)
    ctor = [int(x, 16) for x in sys.argv[5:]]
    inner = [class_hash, salt, 0, len(ctor)] + ctor
    calldata = [1, UDC, get_selector_from_name("deployContract"), len(inner)] + inner
    rb = bounds(20_000_000)
    h = compute_invoke_v3_transaction_hash(
        account_deployment_data=[], calldata=calldata,
        common_fields=common(TransactionHashPrefix.INVOKE, ACCOUNT, nonce, rb),
    )
    payload = {
        "type": "INVOKE_FUNCTION",
        "sender_address": hex(ACCOUNT),
        "calldata": [hex(c) for c in calldata],
        "account_deployment_data": [],
        **v3_base(message_signature(h, PRIV), nonce, rb),
    }
    from starknet_py.hash.address import compute_address
    print("deploying", hex(class_hash), "-> address",
          hex(compute_address(class_hash=class_hash, constructor_calldata=ctor,
                              salt=salt, deployer_address=0)),
          "tx hash", hex(h))
    post(payload)

elif cmd == "run-proof":
    # Mirror of the zkmsg send pipeline (tools/zkmsg core/src/pipeline.rs)
    # against a lane-1-shaped registry: stage tail -> verify_phase1 (head in
    # calldata) -> verify_phase2 (fri section re-packed into calldata).
    # fri_offset comes from the send checkpoint (deterministic per proof).
    import time

    nonce = int(sys.argv[2])
    send_dir = pathlib.Path(sys.argv[3])
    registry = int(sys.argv[4], 16)
    fri_offset = int(sys.argv[5])
    proof_id = int(sys.argv[6], 16)
    HEAD_LEN, STAGE_CHUNK = 4_991, 1_900
    U32_MAX = 0xFFFFFFFF

    def pack_v1(values):
        limbs = []
        for v in values:
            assert v < 2**64, "v1 packing has no felt escape"
            if v < U32_MAX:
                limbs.append(v)
            else:
                limbs += [U32_MAX, v & U32_MAX, (v >> 32) & U32_MAX]
        return [
            sum(l << (32 * i) for i, l in enumerate(limbs[o:o + 7]))
            for o in range(0, len(limbs), 7)
        ]

    packed = [int(l, 16) for l in (send_dir / "packed.txt").read_text().split()]
    values = [int(s, 16) for s in json.loads((send_dir / "proof.json").read_text())]
    assert pack_v1(values) == packed, "python pack_v1 does not reproduce packed.txt"
    print(f"pack_v1 parity OK: {len(values)} values -> {len(packed)} slots")

    head, tail = packed[:HEAD_LEN], packed[HEAD_LEN:]
    n_fri_values = len(values) - fri_offset - 1
    fri_slots = pack_v1(values[fri_offset:fri_offset + n_fri_values])

    def invoke(entrypoint, args, l2_amount, n, data_amount=0x10000):
        calldata_inner = [registry, get_selector_from_name(entrypoint), len(args)] + args
        calldata = [1] + calldata_inner
        rb = bounds(l2_amount, 1.5, data_amount)
        h = compute_invoke_v3_transaction_hash(
            account_deployment_data=[], calldata=calldata,
            common_fields=common(TransactionHashPrefix.INVOKE, ACCOUNT, n, rb),
        )
        payload = {
            "type": "INVOKE_FUNCTION",
            "sender_address": hex(ACCOUNT),
            "calldata": [hex(c) for c in calldata],
            "account_deployment_data": [],
            **v3_base(message_signature(h, PRIV), n, rb),
        }
        print(f"{entrypoint} (nonce {n}) tx {hex(h)}")
        post(payload)
        while True:
            with urllib.request.urlopen(
                f"{FEEDER}/get_transaction_status?transactionHash={hex(h)}", timeout=30
            ) as r:
                st = json.load(r)
            if st.get("finality_status") in ("ACCEPTED_ON_L2", "ACCEPTED_ON_L1"):
                print(f"  -> {st['execution_status']}")
                assert st["execution_status"] == "SUCCEEDED", f"{entrypoint} reverted"
                return
            if st.get("tx_status") in ("REJECTED", "REVERTED"):
                raise SystemExit(f"{entrypoint} {st}")
            time.sleep(8)

    for off in range(0, len(tail), STAGE_CHUNK):
        chunk = tail[off:off + STAGE_CHUNK]
        invoke("stage_proof", [proof_id, off, len(chunk)] + chunk, 400_000_000, nonce)
        nonce += 1
    invoke("verify_phase1",
           [proof_id, len(head)] + head + [len(tail), len(values)],
           1_150_000_000, nonce)
    nonce += 1
    invoke("verify_phase2",
           [proof_id, len(fri_slots)] + fri_slots + [n_fri_values],
           1_150_000_000, nonce)
    print("proof verified + fact registered on the qm31 registry")

elif cmd == "status":
    with urllib.request.urlopen(
        f"{FEEDER}/get_transaction_status?transactionHash={sys.argv[2]}", timeout=30
    ) as r:
        print(r.read().decode())
