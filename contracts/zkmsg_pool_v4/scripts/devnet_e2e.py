#!/usr/bin/env python3
"""Pool-spike end to end on a LOCAL starknet-devnet (>= 0.9). Run via
scripts/devnet_e2e.sh. Refuses any RPC URL that isn't localhost.

Two phases, one devnet each (the .sh starts them):

  virtual  (--proof-mode devnet): `starknet_proveTransaction` runs alice's
           zero-fee virtual invoke FROM THE SHARED VIRTUAL SENDER calling
           prover.prove_send. Shows the virtual sender works and the message
           is from the prover. (Devnet's mock facts do NOT follow the real
           virtual-OS layout -- facts[7..] are not [n_messages,
           message_hash] -- so they cannot drive the pool.)

  pool     (--proof-mode none): proofs are ignored, so this phase attaches
           facts in the REAL layout (as the virtual OS writes them, with the
           program and config hashes devnet's mock facts carry and the base
           block hash from devnet), with the message hash computed locally
           from the v4 payload. Devnet's real blockifier then runs the
           pool's __validate__ / __execute__ in their real modes:
           validate-mode syscall rules, fees charged to the pool, nonces.

Signed setup transactions (deploy, register, buy) go through sncast with
devnet's predeployed accounts dev0/dev1. The pool's publish transactions
are raw invoke v3 with an EMPTY signature.
"""

import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

PHASE, RPC, ACCOUNTS, PROVER_CLASS, POOL_CLASS, VSENDER_CLASS = sys.argv[1:7]
assert re.match(r"^http://(127\.0\.0\.1|localhost)(:\d+)?/?$", RPC), "local devnet only"

HERE = Path(__file__).resolve().parent.parent
POSEIDON = HERE / "scripts" / "poseidon" / "target" / "release" / "poseidon-many"
STRK = 0x4718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D
EPOCH_BLOCKS, MAX_LAG, QUOTA = 100, 1, 3
ONE_STRK = 10**18
# Devnet prices every resource at 1e9 fri: a 0.3 STRK ticket covers
# 140M L2 gas at 2e9 (2x). Same shape as Sepolia's 3 STRK at 30e9.
TICKET_PRICE = 3 * ONE_STRK // 10
MAX_FEE, MAX_TIP, MIN_L2_GAS = TICKET_PRICE, 10**9, 100_000_000
# Devnet's mock facts carry these (equal to Sepolia's).
PROGRAM_HASH = 0x53F6C9FCFD31D27279FF7D7E422B44623550A732B59FE193354A7316A96DAA1
OS_CONFIG_HASH = 0x57ED4D5E20D617D8CC087A5882EAE4F71D005172326BE6439B2E1FD8B4DC57


def ss(s):
    return int.from_bytes(s.encode(), "big")


def H(xs):
    return int(subprocess.check_output([str(POSEIDON), *[hex(x) for x in xs]]).decode(), 16)


_SEL = {}


def selector(name):
    if name not in _SEL:
        out = subprocess.run(["sncast", "utils", "selector", name], capture_output=True, text=True)
        _SEL[name] = int(out.stdout.split()[-1], 16)
    return _SEL[name]


def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(RPC, body, {"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        out = json.load(r)
    if "error" in out:
        raise RuntimeError(f"{method}: {json.dumps(out['error'])[:700]}")
    return out["result"]


hx = hex


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


def call(to, name, calldata=()):
    return [int(x, 16) for x in rpc("starknet_call", [
        {"contract_address": hx(to), "entry_point_selector": hx(selector(name)),
         "calldata": [hx(c) for c in calldata]},
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


def alice_path():
    body = re.search(r"pub fn alice_path\(\) -> Array<felt252> \{(.*?)\n\}", VEC, re.S).group(1)
    return [int(x, 16) for x in re.findall(r"0x[0-9a-f]+", body)]


# The v3 vector's ciphertext zero-filled to the smallest padded size: the
# pool accepts only 1372 / 2140 / 5212-byte content.
CONTENT = bytearray_fn("content").ljust(int(__import__("os").environ.get("CONTENT_LEN", "1372")), b"\0")
CONTENT_HASH = H(ser_bytearray(CONTENT))
E, ROOT, M = const("EPHEMERAL_PUBKEY"), const("ROOT"), const("ALICE_MEMBER_SECRET")


def bounds(l2_amount=140_000_000, price=2 * 10**9, l1_data=2000):
    return {
        "l1_gas": {"max_amount": hx(0), "max_price_per_unit": hx(price)},
        "l2_gas": {"max_amount": hx(l2_amount), "max_price_per_unit": hx(price)},
        "l1_data_gas": {"max_amount": hx(l1_data), "max_price_per_unit": hx(price)},
    }


def invoke_v3(sender, calls, nonce, rb, tip=0, proof_facts=None):
    calldata = [len(calls)]
    for to, sel, cd in calls:
        calldata += [to, sel, len(cd), *cd]
    tx = {
        "type": "INVOKE", "version": "0x3", "sender_address": hx(sender),
        "calldata": [hx(c) for c in calldata], "signature": [], "nonce": hx(nonce),
        "resource_bounds": rb, "tip": hx(tip), "paymaster_data": [],
        "account_deployment_data": [], "nonce_data_availability_mode": "L1",
        "fee_data_availability_mode": "L1",
    }
    if proof_facts is not None:
        tx["proof_facts"] = [hx(f) for f in proof_facts]
        tx["proof"] = "AAAA"  # ignored by --proof-mode none
    return tx


def mine(n):
    for _ in range(n):
        rpc("devnet_createBlock", [])


def submit(tx):
    return rpc("starknet_addInvokeTransaction", {"invoke_transaction": tx})["transaction_hash"]


def receipt(h):
    return rpc("starknet_getTransactionReceipt", [h])


def nonce_of(addr):
    return int(rpc("starknet_getNonce", ["latest", hx(addr)]), 16)


def ticket_secret(i):
    return 0x7111C3700000 + i


N_TICKETS = 6


def setup():
    print("== deploy, register, buy tickets")
    prover = deploy(PROVER_CLASS, [])
    vsender = deploy(VSENDER_CLASS, [])
    pool = deploy(POOL_CLASS, [prover, STRK, TICKET_PRICE, EPOCH_BLOCKS, MAX_LAG, QUOTA,
                               MAX_FEE, MAX_TIP, MIN_L2_GAS])
    invoke("dev0", pool, "register", [ss("alice"), const("ALICE_SCAN_PUB"),
           *ser_bytearray(bytearray_fn("alice_kem_pubkey")), const("ALICE_M_COMMIT")])
    invoke("dev1", pool, "register", [ss("bob"), const("BOB_SCAN_PUB"),
           *ser_bytearray(bytearray_fn("bob_kem_pubkey")), const("BOB_M_COMMIT")])
    assert call(pool, "get_merkle_root") == [ROOT], "root mismatch"
    # dev1 buys the tickets alice (dev0's member) will spend: bearer notes.
    invoke("dev1", STRK, "approve", [pool, N_TICKETS * TICKET_PRICE, 0])
    leaves = [H([ss("zkmsg-ticket-v4"), ticket_secret(i)]) for i in range(N_TICKETS)]
    invoke("dev1", pool, "buy_tickets", [N_TICKETS, *leaves])
    print(f"  pool {hx(pool)}\n  prover {hx(prover)}\n  virtual sender {hx(vsender)}")
    print(f"  {call(pool, 'n_tickets')[0]} tickets bought by dev1; pool holds "
          f"{balance(pool) / ONE_STRK} STRK = {N_TICKETS} x {TICKET_PRICE / ONE_STRK}")
    return prover, vsender, pool


def witness(pool, commitment, slot, base, ticket):
    ticket_root = call(pool, "get_ticket_root")[0]
    ticket_path = call(pool, "get_ticket_path", [ticket])[1:]
    return [pool, CONTENT_HASH, commitment, E, ROOT, base // EPOCH_BLOCKS, QUOTA, ticket_root,
            const("ALICE_SCAN_PUB"), const("ALICE_KEM_DIGEST"), M, slot, 0, 20, *alice_path(),
            ticket_secret(ticket), ticket, 20, *ticket_path]


def phase_virtual():
    prover, vsender, pool = setup()
    mine(12)
    base = rpc("starknet_blockNumber", []) - 10
    vtx = invoke_v3(vsender, [(prover, selector("prove_send"),
                               witness(pool, const("COMMITMENT"), 0, base, 0))], 0,
                    {"l1_gas": {"max_amount": "0x0", "max_price_per_unit": "0x0"},
                     "l2_gas": {"max_amount": hx(10**9), "max_price_per_unit": "0x0"},
                     "l1_data_gas": {"max_amount": "0x0", "max_price_per_unit": "0x0"}})
    out = rpc("starknet_proveTransaction", {"block_id": {"block_number": base}, "transaction": vtx})
    (msg,) = out["l2_to_l1_messages"]
    assert int(msg["from_address"], 16) == prover
    print(f"== virtual: proved at base block {base} from the shared virtual sender (nonce 0)")
    print(f"  message from {msg['from_address']} = the PROVER; payload {len(msg['payload'])} felts")
    print(f"  devnet mock facts: {out['proof_facts']}")
    print(f"  virtual sender on-chain nonce stays {nonce_of(vsender)}")


def payload(pool, commitment, slot, base, ticket):
    epoch = base // EPOCH_BLOCKS
    nullifier = H([ss("zkmsg-nullifier-v4"), pool, M, epoch, slot])
    ticket_nullifier = H([ss("zkmsg-ticket-null-v4"), pool, ticket_secret(ticket)])
    ticket_root = call(pool, "get_ticket_root")[0]
    return [pool, commitment, E, ROOT, CONTENT_HASH, nullifier, epoch, QUOTA, ticket_root,
            ticket_nullifier]


def real_facts(prover, base, pl):
    block_hash = int(rpc("starknet_getBlockWithTxHashes", [{"block_number": base}])["block_hash"], 16)
    mh = H([prover, 0, len(pl), *pl])
    return [ss("PROOF1"), ss("VIRTUAL_SNOS"), PROGRAM_HASH, ss("VIRTUAL_SNOS0"), base, block_hash,
            OS_CONFIG_HASH, 1, mh]


def publish_tx(pool, pl, facts, nonce, tip=0, rb=None, nullifier=None):
    _, commitment, e, root, _, nul, _, _, troot, tnul = pl
    cd = [commitment, e, root, nullifier if nullifier is not None else nul, troot, tnul,
          *ser_bytearray(CONTENT)]
    return invoke_v3(pool, [(pool, selector("send_message"), cd)], nonce, rb or bounds(), tip=tip,
                     proof_facts=facts)


def expect_rejected(label, tx, pool):
    before, n_before = balance(pool), nonce_of(pool)
    try:
        h = submit(tx)
    except RuntimeError as e:
        assert balance(pool) == before and nonce_of(pool) == n_before
        reason = re.search(r"0x[0-9a-f]+ \('([^']*)'\)", str(e))
        print(f"  {label}: REJECTED, pool paid 0, nonce unchanged "
              f"[{reason.group(1) if reason else str(e)[:200]}]")
        return
    r = receipt(h)
    raise AssertionError(f"{label}: accepted ({r['execution_status']}), fee {r['actual_fee']}")


def phase_pool():
    prover, _, pool = setup()
    mine(12)
    base = rpc("starknet_blockNumber", []) - 10
    c = const("COMMITMENT")

    print(f"== publish from the pool, empty signature, base block {base}")
    pl1 = payload(pool, c, 0, base, 0)
    b0 = balance(pool)
    h = submit(publish_tx(pool, pl1, real_facts(prover, base, pl1), nonce_of(pool)))
    r = receipt(h)
    fee = int(r["actual_fee"]["amount"], 16)
    tx = rpc("starknet_getTransactionByHash", {"transaction_hash": h})
    print(f"  {r['execution_status']}: fee {fee / ONE_STRK} STRK (ticket {TICKET_PRICE / ONE_STRK}), "
          f"pool paid {(b0 - balance(pool)) / ONE_STRK}")
    print(f"  sender_address {tx['sender_address']} (the pool), signature {tx['signature']}")
    print(f"  execution resources {json.dumps(r['execution_resources'])}")
    assert r["execution_status"] == "SUCCEEDED", r
    assert call(pool, "n_messages") == [1]
    assert call(pool, "is_ticket_spent", [pl1[9]]) == [1]

    print("== rejected in validate: nothing charged")
    pl = payload(pool, c + 1, 1, base, 0)
    expect_rejected("spent ticket (new slot + commitment)",
                    publish_tx(pool, pl, real_facts(prover, base, pl), nonce_of(pool)), pool)
    pl = payload(pool, c + 1, 0, base, 1)
    expect_rejected("spent quota slot (new ticket)",
                    publish_tx(pool, pl, real_facts(prover, base, pl), nonce_of(pool)), pool)
    pl = payload(pool, c + 1, 1, base, 1)
    f = real_facts(prover, base, pl)
    expect_rejected("griefing tip", publish_tx(pool, pl, f, nonce_of(pool), tip=2 * 10**9), pool)
    expect_rejected("fee bound over the ticket",
                    publish_tx(pool, pl, f, nonce_of(pool), rb=bounds(price=3 * 10**9)), pool)
    expect_rejected("forged member nullifier",
                    publish_tx(pool, pl, f, nonce_of(pool), nullifier=pl[5] + 1), pool)
    expect_rejected("STRK transfer out of the pool",
                    invoke_v3(pool, [(STRK, selector("transfer"), [0xBAD, 10**18, 0])],
                              nonce_of(pool), bounds(), proof_facts=f), pool)

    print("== nonce race: two senders, one pool nonce")
    pl2, pl3 = payload(pool, c + 1, 1, base, 1), payload(pool, c + 2, 2, base, 2)
    f2, f3 = real_facts(prover, base, pl2), real_facts(prover, base, pl3)
    nonce = nonce_of(pool)
    ha = submit(publish_tx(pool, pl2, f2, nonce))
    try:
        hb = submit(publish_tx(pool, pl3, f3, nonce))
        print(f"  second tx at the same nonce: {receipt(hb)['execution_status']}")
    except RuntimeError as e:
        print(f"  loser rejected at submit: {str(e)[:200]}")
    print(f"  winner {receipt(ha)['execution_status']}")
    hb = submit(publish_tx(pool, pl3, f3, nonce_of(pool)))
    print(f"  loser re-sent at the next nonce with the SAME facts (no re-proving): "
          f"{receipt(hb)['execution_status']}")
    assert call(pool, "n_messages") == [3]

    print("== solvency")
    left = balance(pool)
    print(f"  6 tickets in ({6 * TICKET_PRICE / ONE_STRK} STRK), 3 burnt; fees paid "
          f"{(N_TICKETS * TICKET_PRICE - left) / ONE_STRK} STRK; pool holds {left / ONE_STRK} "
          f">= 3 unspent tickets ({3 * TICKET_PRICE / ONE_STRK})")
    assert left >= 3 * TICKET_PRICE


if __name__ == "__main__":
    {"virtual": phase_virtual, "pool": phase_pool}[PHASE]()
