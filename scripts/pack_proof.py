#!/usr/bin/env python3
"""Packs a cairo-serde proof (JSON array of hex felts) into the packed
staging/calldata format: 7 little-endian 32-bit limbs per felt252 slot.

Formats:
  v1 (default; the deployed lane-1 StwoFactRegistry format):
     limbs < 0xFFFFFFFF are literal values; `0xFFFFFFFF` escapes a
     (low, high) u64 pair. Values >= 2^64 are rejected.
  v2 (lane 2; poseidon-config proof streams contain full felt252 hashes):
     limbs < 0xFFFFFFFE are literal values; `0xFFFFFFFF` escapes a
     (low, high) u64 pair (used for any value in [0xFFFFFFFE, 2^64));
     `0xFFFFFFFE` escapes a full felt252 as 8 little-endian u32 limbs.

Usage: pack_proof.py [--v2] <proof.json> <packed_out.json|.txt>
Prints n_slots and n_values.
"""
import json
import sys

U32_MAX = 0xFFFFFFFF
FELT_ESCAPE = 0xFFFFFFFE


def pack(values: list[int], v2: bool) -> list[int]:
    literal_bound = FELT_ESCAPE if v2 else U32_MAX
    limbs: list[int] = []
    for v in values:
        if v < literal_bound:
            limbs.append(v)
        elif v < 2**64:
            limbs += [U32_MAX, v & U32_MAX, (v >> 32) & U32_MAX]
        else:
            assert v2, f"value {v:#x} exceeds u64 — use --v2"
            limbs.append(FELT_ESCAPE)
            limbs += [(v >> (32 * i)) & U32_MAX for i in range(8)]
    slots = []
    for j in range(0, len(limbs), 7):
        chunk = limbs[j : j + 7]
        slots.append(sum(l << (32 * i) for i, l in enumerate(chunk)))
    return slots


def unpack(slots: list[int], n_values: int, v2: bool) -> list[int]:
    """Mirrors the contract-side unpack (v1: stwo_verifier_phases::unpack_proof,
    v2: stwo_full_verifier_phases::unpack_proof_v2)."""
    limbs = []
    for s in slots:
        for i in range(7):
            limbs.append((s >> (32 * i)) & U32_MAX)
    out, i = [], 0
    while len(out) != n_values:
        limb = limbs[i]
        if limb == U32_MAX:
            out.append(limbs[i + 1] | (limbs[i + 2] << 32))
            i += 3
        elif v2 and limb == FELT_ESCAPE:
            out.append(sum(limbs[i + 1 + k] << (32 * k) for k in range(8)))
            i += 9
        else:
            out.append(limb)
            i += 1
    return out


def main() -> None:
    args = [a for a in sys.argv[1:] if a != "--v2"]
    v2 = "--v2" in sys.argv[1:]
    src, dst = args[0], args[1]
    values = [int(x, 16) for x in json.load(open(src))]
    slots = pack(values, v2)
    assert unpack(slots, len(values), v2) == values, "round-trip mismatch"

    if dst.endswith(".txt"):
        with open(dst, "w") as f:
            f.write("\n".join(hex(s) for s in slots))
    else:
        json.dump([hex(s) for s in slots], open(dst, "w"))
    print(f"n_slots={len(slots)} n_values={len(values)}")


if __name__ == "__main__":
    main()
