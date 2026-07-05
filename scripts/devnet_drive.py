#!/usr/bin/env python3
"""Devnet router drive: declare the blake-build machinery, deploy the
governed registry + router, and drive the full transaction sequence from
`emit-calldata --blake` artifacts, recording digit-exact per-transaction
L2 gas — the gas oracle for the sovereign lane (devnet is NOT a
deployability oracle; only a real gateway declare is).

Usage:
  starknet-devnet --seed 42          # in another terminal (or --start-devnet)
  scripts/devnet_drive.py <calldata_dir> [--account devnet42]
      [--url http://127.0.0.1:5050/rpc] [--out devnet_drive_results.json]
      [--skip-declare <hashes.json>]

The calldata dir is the output of
  privacy_prove_cairo_bridge emit-calldata \
      fixtures/poseidon_chain_n100.blake_extended_proof.json <dir> --blake
(group size 8 — the default).

Declares run `sncast declare`, which rebuilds via scarb with DEFAULT
features — so this script temporarily flips the phases package's default
feature set to the qm31/blake build and restores Scarb.toml afterwards.

Every step entrypoint returns the next serialized machine state, but an
invoke's return value is not available over RPC — and a read-only CALL
cannot stand in for it, because starknet_call runs with caller 0x0 and
the router's checkpoints are caller-keyed. So each step INVOKEs and then
extracts the entrypoint's retdata from starknet_traceTransaction (the
router call's `result` inside the account's execute_invocation).
"""

import argparse
import json
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PKG_DIR = REPO / "contracts" / "stwo_full_verifier_phases"
SCARB_TOML = PKG_DIR / "Scarb.toml"

POSEIDON_DEFAULT = 'default = ["poseidon252_verifier", "poseidon_outputs_packing"]'
BLAKE_DEFAULT = 'default = ["qm31_opcode", "blake_outputs_packing"]'

GROUP_CLASSES = [f"StwoOodsG{i:02d}" for i in range(15)]
SINGLE_CLASSES = [
    "StwoMachineClaim", "StwoMachineLookup", "StwoOodsBegin",
    "StwoOodsFinalize", "StwoMachineGroup", "StwoMachineFri",
    "StwoSharedFactRegistry", "StwoVerifierRouter",
]
ALL_CLASSES = SINGLE_CLASSES[:3] + GROUP_CLASSES + SINGLE_CLASSES[3:]

CHUNK_ENTRIES = 540
# The bouncer counts state-diff FELTS (key + value = 2 per storage write,
# plus account nonce/fee-transfer overhead) against a 4,000-felt cap —
# measured on devnet: a 2,617-write staging tx weighs state_diff_size
# 5,214. So the write budget is ~1,950 slots per staging tx; 1,900 is the
# safe production chunk.
STAGE_CHUNK = 1_900
SECTION_SAMPLED = hex(int.from_bytes(b"sampled", "big"))
SECTION_FRI = hex(int.from_bytes(b"fri", "big"))
PROOF_ID = hex(int.from_bytes(b"devnet_blake_drive", "big"))


def sncast(args, account, url, cwd=None, retries=2):
    cmd = ["sncast", "--json", "--account", account] + args + ["--url", url]
    for attempt in range(retries + 1):
        r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
        if r.returncode == 0:
            break
        if attempt == retries:
            sys.exit(f"sncast failed: {' '.join(cmd[:8])}...\n{r.stdout}\n{r.stderr}")
        time.sleep(2)
    # sncast --json emits one JSON object per line; the result is the last.
    out = [l for l in r.stdout.strip().splitlines() if l.strip().startswith("{")]
    return json.loads(out[-1]) if out else {}


def rpc(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": params}).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        reply = json.load(resp)
    if "error" in reply:
        raise RuntimeError(f"{method}: {reply['error']}")
    return reply["result"]


def wait_receipt(url, tx_hash, timeout=600):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            rec = rpc(url, "starknet_getTransactionReceipt", [tx_hash])
        except RuntimeError:
            time.sleep(0.5)
            continue
        status = rec.get("execution_status")
        if status == "REVERTED":
            sys.exit(f"tx {tx_hash} REVERTED: {rec.get('revert_reason')}")
        if status == "SUCCEEDED":
            return rec
        time.sleep(0.5)
    sys.exit(f"tx {tx_hash}: no receipt after {timeout}s")


def read_slots(path):
    return [l.strip() for l in open(path) if l.strip()]


def felts(values):
    return [v if isinstance(v, str) else hex(v) for v in values]


class Driver:
    def __init__(self, url, account, router, results):
        self.url, self.account, self.router = url, account, router
        self.results = results

    def step(self, label, function, calldata, returns_state=True):
        calldata = felts(calldata)
        n_felts = len(calldata)
        inv = sncast(["invoke", "--contract-address", self.router,
                      "--function", function, "--calldata"] + calldata,
                     self.account, self.url)
        rec = wait_receipt(self.url, inv["transaction_hash"])
        new_state = None
        if returns_state:
            trace = rpc(self.url, "starknet_traceTransaction",
                        [inv["transaction_hash"]])
            retdata = trace["execute_invocation"]["calls"][0]["result"]
            if function == "finalize":
                new_state = retdata  # (program_hash, output_hash)
            else:
                # Array<felt252> retdata = [len, elements...]; echoing it as a
                # Span argument re-serializes to exactly the same shape.
                assert int(retdata[0], 16) == len(retdata) - 1, retdata[:3]
                new_state = retdata[1:]
        res_gas = rec["execution_resources"]
        row = {
            "label": label,
            "function": function,
            "calldata_felts": n_felts,
            "l2_gas": res_gas.get("l2_gas"),
            "l1_gas": res_gas.get("l1_gas"),
            "l1_data_gas": res_gas.get("l1_data_gas"),
            "actual_fee_fri": int(rec["actual_fee"]["amount"], 16),
        }
        self.results.append(row)
        print(f"  {label:<22} calldata {n_felts:>5}  l2_gas {row['l2_gas']:>13,}")
        return new_state


def flip_features(to_blake):
    src = SCARB_TOML.read_text()
    old, new = (POSEIDON_DEFAULT, BLAKE_DEFAULT) if to_blake else (BLAKE_DEFAULT, POSEIDON_DEFAULT)
    assert old in src, f"Scarb.toml default features not in expected state ({old})"
    SCARB_TOML.write_text(src.replace(old, new))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("calldata_dir", type=Path)
    ap.add_argument("--account", default="devnet42")
    ap.add_argument("--url", default="http://127.0.0.1:5050/rpc")
    ap.add_argument("--out", type=Path, default=Path("devnet_drive_results.json"))
    ap.add_argument("--skip-declare", type=Path,
                    help="JSON file of class hashes from a previous run")
    args = ap.parse_args()

    manifest = json.load(open(args.calldata_dir / "manifest.json"))
    assert manifest["group_size"] == 8, "expected 8-query groups"

    # --- declares ---------------------------------------------------------
    if args.skip_declare:
        hashes = json.load(open(args.skip_declare))
    else:
        hashes = {}
        flip_features(to_blake=True)
        try:
            for name in ALL_CLASSES:
                res = sncast(["declare", "--contract-name", name,
                              "--package", "stwo_full_verifier_phases"],
                             args.account, args.url, cwd=PKG_DIR)
                hashes[name] = res["class_hash"]
                print(f"declared {name:<22} {res['class_hash']}")
        finally:
            flip_features(to_blake=False)
        json.dump(hashes, open(args.out.with_suffix(".classes.json"), "w"), indent=1)

    # --- deploys + governance --------------------------------------------
    accounts = json.load(open(Path.home() / ".starknet_accounts" /
                              "starknet_open_zeppelin_accounts.json"))
    owner = next(v["address"] for k, v in accounts["alpha-sepolia"].items()
                 if k == args.account)

    reg = sncast(["deploy", "--class-hash", hashes["StwoSharedFactRegistry"],
                  "--constructor-calldata", owner], args.account, args.url)
    registry = reg["contract_address"]
    print("registry", registry)

    ctor = ([hashes["StwoMachineClaim"], hashes["StwoMachineLookup"],
             hashes["StwoOodsBegin"], hex(len(GROUP_CLASSES))]
            + [hashes[g] for g in GROUP_CLASSES]
            + [hashes["StwoOodsFinalize"], hashes["StwoMachineGroup"],
               hashes["StwoMachineFri"], registry])
    rtr = sncast(["deploy", "--class-hash", hashes["StwoVerifierRouter"],
                  "--constructor-calldata"] + ctor, args.account, args.url)
    router = rtr["contract_address"]
    print("router", router)

    for fn, cd in [("add_route", [router]), ("freeze_routes", [])]:
        inv = sncast(["invoke", "--contract-address", registry, "--function", fn,
                      "--calldata"] + cd if cd else
                     ["invoke", "--contract-address", registry, "--function", fn],
                     args.account, args.url)
        wait_receipt(args.url, inv["transaction_hash"])
        print(f"registry.{fn} ok")

    # --- the drive --------------------------------------------------------
    results = []
    d = Driver(args.url, args.account, router, results)
    m = manifest

    head = read_slots(args.calldata_dir / "head.txt")
    head_n = m["head"]["n_values"]
    sampled = read_slots(args.calldata_dir / "sampled.txt")
    fri = read_slots(args.calldata_dir / "fri.txt")
    sampled_slots, sampled_n = len(sampled), m["sampled"]["n_values"]
    fri_slots, fri_n = len(fri), m["fri"]["n_values"]
    program_len = m["program_len"]

    def span(v):
        return [hex(len(v))] + felts(v)

    print("== staging ==")
    for section, slots in ((SECTION_SAMPLED, sampled), (SECTION_FRI, fri)):
        for off in range(0, len(slots), STAGE_CHUNK):
            chunk = slots[off:off + STAGE_CHUNK]
            d.step(f"stage {('sampled' if section == SECTION_SAMPLED else 'fri')}@{off}",
                   "stage", [PROOF_ID, section, hex(off)] + span(chunk),
                   returns_state=False)

    print("== machine ==")
    state = d.step("begin", "begin",
                   [PROOF_ID] + span(head) + [hex(head_n), hex(program_len)])

    for phase in ("claim", "lookup"):
        for c in m["chunks"]:
            chunk = read_slots(args.calldata_dir / c["file"])
            state = d.step(f"{phase}_chunk {c['file']}", f"{phase}_chunk",
                           [PROOF_ID] + span(state) + span(chunk) + [hex(c["n_values"])])
        state = d.step(f"{phase}_finalize", f"{phase}_finalize",
                       [PROOF_ID] + span(state) + span(head) + [hex(head_n)])

    sampled_args = [hex(sampled_slots), hex(sampled_n)]
    state = d.step("oods_begin", "oods_begin",
                   [PROOF_ID] + span(state) + span(head) + [hex(head_n)] + sampled_args)
    for g in range(len(GROUP_CLASSES)):
        state = d.step(f"oods_group {g:02d}", "oods_group",
                       [PROOF_ID, hex(g)] + span(state) + span(head)
                       + [hex(head_n)] + sampled_args)
    state = d.step("oods_finalize", "oods_finalize",
                   [PROOF_ID] + span(state) + span(head) + [hex(head_n)] + sampled_args)

    state = d.step("fri_commit", "fri_commit",
                   [PROOF_ID] + span(state) + span(head)
                   + [hex(head_n), hex(fri_slots), hex(fri_n)])

    for i, g in enumerate(m["groups"]):
        rows = read_slots(args.calldata_dir / g["rows"]["file"])
        wits = read_slots(args.calldata_dir / g["witnesses"]["file"])
        state = d.step(f"group {i:02d}", "group",
                       [PROOF_ID] + span(state) + span(head) + [hex(head_n)]
                       + sampled_args + span(rows) + [hex(g["rows"]["n_values"])]
                       + span(wits) + [hex(g["witnesses"]["n_values"])])

    out = d.step("finalize", "finalize",
                 [PROOF_ID] + span(state) + span(head)
                 + [hex(head_n), hex(fri_slots), hex(fri_n)])
    program_hash, output_hash = out[0], out[1]
    print("fact:", program_hash, output_hash)

    total = sum(r["l2_gas"] for r in results)
    worst = max(results, key=lambda r: r["l2_gas"])
    print(f"\n{len(results)} txs, total l2_gas {total:,}, "
          f"worst {worst['label']} at {worst['l2_gas']:,}")
    json.dump({"router": router, "registry": registry,
               "program_hash": program_hash, "output_hash": output_hash,
               "txs": results}, open(args.out, "w"), indent=1)
    print("results ->", args.out)


if __name__ == "__main__":
    main()
