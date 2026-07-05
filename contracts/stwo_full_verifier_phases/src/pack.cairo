//! In-Cairo packing v2 — the exact mirror of [`crate::unpack_proof_v2`]
//! and of `scripts/pack_proof.py --v2`: 7 little-endian u32 limbs per
//! felt252 slot; a value < 2^32 is one limb; a value < 2^64 is escaped as
//! `[0xFFFFFFFF, lo, hi]`; anything larger as `[0xFFFFFFFE, l0..l7]`
//! (8 LE u32 limbs of the full felt252). Used by the router tests to
//! produce production-shaped per-transaction calldata; the bridge-side
//! emitter is the production packer.

const U64_ESCAPE: u32 = 0xFFFFFFFF;
const FELT_ESCAPE: u32 = 0xFFFFFFFE;

pub fn pack_v2(values: Span<felt252>) -> Array<felt252> {
    let nz32: NonZero<u128> = 0x100000000_u128.try_into().unwrap();
    let mut limbs: Array<u32> = array![];
    for value in values {
        let v: u256 = (*value).into();
        if v.high == 0 && v.low < 0x100000000 {
            let limb: u32 = v.low.try_into().unwrap();
            // A raw limb must not collide with the escape markers.
            if limb == U64_ESCAPE || limb == FELT_ESCAPE {
                limbs.append(U64_ESCAPE);
                limbs.append(limb);
                limbs.append(0);
            } else {
                limbs.append(limb);
            }
        } else if v.high == 0 && v.low < 0x10000000000000000 {
            let (hi, lo) = DivRem::div_rem(v.low, nz32);
            limbs.append(U64_ESCAPE);
            limbs.append(lo.try_into().unwrap());
            limbs.append(hi.try_into().unwrap());
        } else {
            limbs.append(FELT_ESCAPE);
            let (q, l0) = DivRem::div_rem(v.low, nz32);
            let (q, l1) = DivRem::div_rem(q, nz32);
            let (l3, l2) = DivRem::div_rem(q, nz32);
            let (q, l4) = DivRem::div_rem(v.high, nz32);
            let (q, l5) = DivRem::div_rem(q, nz32);
            let (l7, l6) = DivRem::div_rem(q, nz32);
            limbs.append(l0.try_into().unwrap());
            limbs.append(l1.try_into().unwrap());
            limbs.append(l2.try_into().unwrap());
            limbs.append(l3.try_into().unwrap());
            limbs.append(l4.try_into().unwrap());
            limbs.append(l5.try_into().unwrap());
            limbs.append(l6.try_into().unwrap());
            limbs.append(l7.try_into().unwrap());
        }
    }

    // 7 limbs per slot, little-endian; zero-padded tail.
    let mut packed: Array<felt252> = array![];
    let mut limbs = limbs.span();
    while !limbs.is_empty() {
        let mut slot: felt252 = 0;
        let mut shift: felt252 = 1;
        let mut k = 0_u32;
        while k != 7 {
            let limb: felt252 = match limbs.pop_front() {
                Some(l) => (*l).into(),
                None => 0,
            };
            slot += limb * shift;
            shift *= 0x100000000;
            k += 1;
        }
        packed.append(slot);
    }
    packed
}

#[cfg(test)]
mod tests {
    use crate::unpack_proof_v2;
    use super::pack_v2;

    #[test]
    fn test_pack_unpack_roundtrip() {
        let values: Array<felt252> = array![
            0, 1, 0xFFFFFFFE, 0xFFFFFFFF, 0x100000000, 0xFFFFFFFFFFFFFFFF, 0x10000000000000000,
            -1, 12345, 0x800000000000011000000000000000000000000000000000000000000000000,
        ];
        let packed = pack_v2(values.span());
        let unpacked = unpack_proof_v2(packed.span(), values.len());
        assert!(unpacked == values, "roundtrip");
    }
}
