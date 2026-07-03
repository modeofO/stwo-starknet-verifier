#!/usr/bin/env python3
"""Packs a cairo-serde proof (JSON array of hex felts) into the
StwoFactRegistry staging format: 7 little-endian 32-bit limbs per felt252
slot, with `0xFFFFFFFF` escaping a u64 (low, high) limb pair.

Usage: pack_proof.py <proof.json> <packed_out.json|.txt>
Prints n_slots and n_values (the two verify_and_register arguments).
"""
import json
import sys


def pack(values: list[int]) -> list[int]:
    limbs: list[int] = []
    for v in values:
        if v < 0xFFFFFFFF:
            limbs.append(v)
        else:
            assert v < 2**64, f"value {v:#x} exceeds u64 — unsupported in proof streams"
            limbs += [0xFFFFFFFF, v & 0xFFFFFFFF, v >> 32]
    slots = []
    for j in range(0, len(limbs), 7):
        chunk = limbs[j : j + 7]
        slots.append(sum(l << (32 * i) for i, l in enumerate(chunk)))
    return slots


def main() -> None:
    src, dst = sys.argv[1], sys.argv[2]
    values = [int(x, 16) for x in json.load(open(src))]
    slots = pack(values)

    # Round-trip check mirroring the contract's unpack_proof.
    limbs = []
    for s in slots:
        for i in range(7):
            limbs.append((s >> (32 * i)) & 0xFFFFFFFF)
    out, i = [], 0
    while len(out) != len(values):
        if limbs[i] == 0xFFFFFFFF:
            out.append(limbs[i + 1] | (limbs[i + 2] << 32))
            i += 3
        else:
            out.append(limbs[i])
            i += 1
    assert out == values, "round-trip mismatch"

    if dst.endswith(".txt"):
        with open(dst, "w") as f:
            f.write("\n".join(hex(s) for s in slots))
    else:
        json.dump([hex(s) for s in slots], open(dst, "w"))
    print(f"n_slots={len(slots)} n_values={len(values)}")


if __name__ == "__main__":
    main()
