#!/usr/bin/env python3
"""Pool-spike end to end on a LOCAL starknet-devnet (>= 0.9, --proof-mode devnet).

Never points at a public network: refuses any RPC URL that isn't localhost.

    starknet-devnet --seed 0 --accounts 2 --port 5051 --proof-mode devnet
    python3 scripts/devnet_e2e.py http://127.0.0.1:5051 <accounts.json> \
        <prover_class> <pool_class> <virtual_sender_class>

The accounts file holds devnet's predeployed accounts as sncast `dev0`/`dev1`
(sncast account import ...). Classes are declared beforehand (sncast
declare). What runs here, against devnet's real blockifier:

  1. deploy prover, virtual sender, pool; fund the pool with STRK; register
     alice (dev0) and bob (dev1) with the v3 vector keys;
  2. prove alice's send with `starknet_proveTransaction`: a zero-fee virtual
     invoke FROM THE SHARED VIRTUAL SENDER calling prover.prove_send;
  3. publish it as an invoke v3 FROM THE POOL with an empty signature,
     carrying the proof and facts. No member account signs or pays;
  4. failure paths, checking the pool's balance after each: a re-used slot
     (nullifier) and a griefing tip must be REJECTED (validate) and cost
     nothing; two sends racing for one pool nonce; the loser is re-sent
     under the next nonce with the SAME proof (no re-proving).
"""

import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

RPC, ACCOUNTS, PROVER_CLASS, POOL_CLASS, VSENDER_CLASS = sys.argv[1:6]
assert re.match(r"^http://(127\.0\.0\.1|localhost)(:\d+)?/?$", RPC), "local devnet only"

HERE = Path(__file__).resolve().parent.parent
STRK = 0x4718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D
SEL = {
    "send_message": 0x012EAD94AE9D3F9D2BDB6B847CF255F1F398193A1F88884A0AE8E18F24A037B6,
    "prove_send": 0x003582CC3692039CEBA7D632FE9C3656562ACF5CC91671AFF5032F9FEE73852E,
}
EPOCH_BLOCKS, MAX_LAG, QUOTA = 100, 1, 3
ONE_STRK = 10**18
# Devnet prices every resource at 1e9 fri.
MAX_FEE, MAX_TIP, MIN_L2_GAS = ONE_STRK, 10**9, 100_000_000


def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(RPC, body, {"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        out = json.load(r)
    if "error" in out:
        raise RuntimeError(f"{method}: {json.dumps(out['error'])[:600]}")
    return out["result"]


def hx(x):
    return hex(x)


def sncast(account, *args):
    cmd = ["sncast", "--accounts-file", ACCOUNTS, "--account", account, *args]
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"sncast {' '.join(args[:2])}: {out.stdout}{out.stderr}")
    return out.stdout


def deploy(class_hash, calldata):
    extra = ["--constructor-calldata", *[hx(x) for x in calldata]] if calldata else []
    out = sncast("dev0", "deploy", "--url", RPC, "--class-hash", class_hash, *extra)
    return int(re.search(r"Contract Address:\s+(0x[0-9a-fA-F]+)", out).group(1), 16)


def invoke(account, to, function, calldata):
    sncast(account, "invoke", "--url", RPC, "--contract-address", hx(to), "--function", function,
           "--calldata", *[hx(x) for x in calldata])


def call(to, selector_name, calldata=()):
    sel = SEL.get(selector_name)
    if sel is None:
        out = subprocess.run(["sncast", "utils", "selector", selector_name], capture_output=True, text=True)
        sel = int(out.stdout.split()[-1], 16)
    return [int(x, 16) for x in rpc("starknet_call", [
        {"contract_address": hx(to), "entry_point_selector": hx(sel), "calldata": [hx(c) for c in calldata]},
        "latest"])]


def balance(addr):
    low, high = call(STRK, "balance_of", [addr])
    return low + (high << 128)


# --- the v3 vector, parsed from the Cairo test file ------------------------------

VEC = (HERE / "tests" / "vector.cairo").read_text()


def const(name):
    return int(re.search(rf"pub const {name}: felt252 = (0x[0-9a-f]+);", VEC).group(1), 16)


def bytearray_fn(name):
    body = re.search(rf"pub fn {name}\(\) -> ByteArray \{{(.*?)\n\}}", VEC, re.S).group(1)
    data = b""
    for word, n in re.findall(r"append_word\((0x[0-9a-f]+), (\d+)\)", body):
        data += int(word, 16).to_bytes(int(n), "big")
    return data


def ser_bytearray(b):
    full = [int.from_bytes(b[i:i + 31], "big") for i in range(0, len(b) - len(b) % 31, 31)]
    rest = b[len(full) * 31:]
    return [len(full), *full, int.from_bytes(rest, "big") if rest else 0, len(rest)]


def path():
    body = re.search(r"pub fn alice_path\(\) -> Array<felt252> \{(.*?)\n\}", VEC, re.S).group(1)
    return [int(x, 16) for x in re.findall(r"0x[0-9a-f]+", body)]


CONTENT = bytearray_fn("content")
CONTENT_HASH = const("CONTENT_HASH")
E = const("EPHEMERAL_PUBKEY")
ROOT = const("ROOT")


def bounds(l2_amount=150_000_000, price=2 * 10**9, l1_data=2000):
    return {
        "l1_gas": {"max_amount": hx(0), "max_price_per_unit": hx(price)},
        "l2_gas": {"max_amount": hx(l2_amount), "max_price_per_unit": hx(price)},
        "l1_data_gas": {"max_amount": hx(l1_data), "max_price_per_unit": hx(price)},
    }


def invoke_v3(sender, calls, nonce, rb, tip=0, signature=(), proof_facts=None, proof=None):
    calldata = [len(calls)]
    for to, sel, cd in calls:
        calldata += [to, sel, len(cd), *cd]
    tx = {
        "type": "INVOKE", "version": "0x3", "sender_address": hx(sender),
        "calldata": [hx(c) for c in calldata], "signature": [hx(s) for s in signature],
        "nonce": hx(nonce), "resource_bounds": rb, "tip": hx(tip), "paymaster_data": [],
        "account_deployment_data": [], "nonce_data_availability_mode": "L1",
        "fee_data_availability_mode": "L1",
    }
    if proof_facts is not None:
        tx["proof_facts"] = proof_facts
        tx["proof"] = proof
    return tx


def block_number():
    return rpc("starknet_blockNumber", [])


def mine(n):
    for _ in range(n):
        rpc("devnet_createBlock", [])


def prove(vsender, prover, pool, commitment, slot, base):
    """A zero-fee virtual invoke from the SHARED virtual sender (nonce 0)."""
    witness = [pool, CONTENT_HASH, commitment, E, ROOT, base // EPOCH_BLOCKS, QUOTA,
               const("ALICE_SCAN_PUB"), const("ALICE_KEM_DIGEST"), const("ALICE_MEMBER_SECRET"),
               slot, 0, 20, *path()]
    vtx = invoke_v3(vsender, [(prover, SEL["prove_send"], witness)], 0,
                    {"l1_gas": {"max_amount": "0x0", "max_price_per_unit": "0x0"},
                     "l2_gas": {"max_amount": hx(10**9), "max_price_per_unit": "0x0"},
                     "l1_data_gas": {"max_amount": "0x0", "max_price_per_unit": "0x0"}})
    out = rpc("starknet_proveTransaction", {"block_id": {"block_number": base}, "transaction": vtx})
    msgs = out["l2_to_l1_messages"]
    assert len(msgs) == 1, msgs
    nullifier = int(msgs[0]["payload"][5], 16)
    return out["proof"], out["proof_facts"], nullifier, msgs[0]


def publish_tx(pool, commitment, nullifier, proof, facts, nonce, tip=0, content=CONTENT):
    cd = [commitment, E, ROOT, nullifier, *ser_bytearray(content)]
    return invoke_v3(pool, [(pool, SEL["send_message"], cd)], nonce, bounds(), tip=tip,
                     proof_facts=facts, proof=proof)


def receipt(h):
    return rpc("starknet_getTransactionReceipt", [h])


def submit(tx):
    return rpc("starknet_addInvokeTransaction", {"invoke_transaction": tx})["transaction_hash"]


def nonce_of(addr):
    return int(rpc("starknet_getNonce", ["latest", hx(addr)]), 16)


def expect_rejected(label, tx, pool):
    before, n_before = balance(pool), nonce_of(pool)
    try:
        h = submit(tx)
    except RuntimeError as e:
        reason = str(e)
        assert balance(pool) == before and nonce_of(pool) == n_before
        print(f"  {label}: REJECTED at submit, pool paid 0, nonce unchanged\n    {reason[:300]}")
        return
    r = receipt(h)
    raise AssertionError(f"{label}: accepted ({r['execution_status']}), fee {r['actual_fee']}")


def main():
    print("== deploy")
    prover = deploy(PROVER_CLASS, [])
    vsender = deploy(VSENDER_CLASS, [])
    pool = deploy(POOL_CLASS, [prover, EPOCH_BLOCKS, MAX_LAG, QUOTA, MAX_FEE, MAX_TIP, MIN_L2_GAS])
    print(f"  prover {hx(prover)}\n  virtual sender {hx(vsender)}\n  pool {hx(pool)}")
    invoke("dev0", STRK, "transfer", [pool, 20 * ONE_STRK, 0])
    invoke("dev0", pool, "register", [int.from_bytes(b"alice", "big"), const("ALICE_SCAN_PUB"),
           *ser_bytearray(bytearray_fn("alice_kem_pubkey")), const("ALICE_M_COMMIT")])
    invoke("dev1", pool, "register", [int.from_bytes(b"bob", "big"), const("BOB_SCAN_PUB"),
           *ser_bytearray(bytearray_fn("bob_kem_pubkey")), const("BOB_M_COMMIT")])
    assert call(pool, "get_merkle_root") == [ROOT], "root mismatch"
    print(f"  pool funded: {balance(pool) / ONE_STRK} STRK; alice+bob registered; root = vector root")

    mine(12)
    base = block_number() - 10
    print(f"== prove (virtual sender, base block {base}, epoch {base // EPOCH_BLOCKS})")
    c1 = const("COMMITMENT")
    proof, facts, n1, msg = prove(vsender, prover, pool, c1, 0, base)
    Path("/tmp/claude-501/pool_dump.json").write_text(json.dumps({"facts": facts, "msg": msg, "prover": hx(prover)}))
    print(f"  facts {facts}\n  message from {msg['from_address']} (the prover, not the sender)")
    print(f"  proof: {len(proof)} chars; payload {msg['payload']} to {msg['to_address']}")

    print("== publish from the pool (empty signature)")
    b0 = balance(pool)
    h = submit(publish_tx(pool, c1, n1, proof, facts, nonce_of(pool)))
    r = receipt(h)
    paid = b0 - balance(pool)
    print(f"  {h} {r['execution_status']} fee {int(r['actual_fee']['amount'], 16) / ONE_STRK} STRK, "
          f"pool paid {paid / ONE_STRK} STRK")
    assert r["execution_status"] == "SUCCEEDED", r
    assert call(pool, "n_messages") == [1]
    tx = rpc("starknet_getTransactionByHash", [h])
    print(f"  on-chain sender_address {tx['sender_address']} signature {tx['signature']}")

    print("== failure paths")
    mine(1)
    proof2, facts2, n2, _ = prove(vsender, prover, pool, c1 + 1, 0, base)
    assert n2 == n1
    expect_rejected("re-used slot (same nullifier, new commitment)",
                    publish_tx(pool, c1 + 1, n2, proof2, facts2, nonce_of(pool)), pool)
    proof3, facts3, n3, _ = prove(vsender, prover, pool, c1 + 2, 1, base)
    expect_rejected("griefing tip", publish_tx(pool, c1 + 2, n3, proof3, facts3, nonce_of(pool), tip=10**12), pool)
    expect_rejected("forged nullifier", publish_tx(pool, c1 + 2, n3 + 1, proof3, facts3, nonce_of(pool)), pool)

    print("== nonce race: two senders, one pool nonce")
    proof4, facts4, n4, _ = prove(vsender, prover, pool, c1 + 3, 2, base)
    nonce = nonce_of(pool)
    ha = submit(publish_tx(pool, c1 + 2, n3, proof3, facts3, nonce))
    try:
        hb = submit(publish_tx(pool, c1 + 3, n4, proof4, facts4, nonce))
        rb = receipt(hb)
        print(f"  second tx at the same nonce accepted?! {rb['execution_status']}")
    except RuntimeError as e:
        print(f"  loser rejected at submit: {str(e)[:200]}")
    ra = receipt(ha)
    print(f"  winner {ra['execution_status']}")
    hb = submit(publish_tx(pool, c1 + 3, n4, proof4, facts4, nonce_of(pool)))
    print(f"  loser re-sent at nonce {nonce_of(pool) - 1} with the SAME proof: {receipt(hb)['execution_status']}")
    assert call(pool, "n_messages") == [3]

    print("== quota spent: slot 3 cannot be proven")
    try:
        prove(vsender, prover, pool, c1 + 4, 3, base)
        raise AssertionError("slot 3 proved")
    except RuntimeError as e:
        print(f"  prove refused: {'slot over quota' in str(e) or str(e)[:200]}")

    print(f"== done: 3 messages, pool balance {balance(pool) / ONE_STRK} STRK, "
          f"virtual sender nonce {nonce_of(vsender)}")


if __name__ == "__main__":
    main()
