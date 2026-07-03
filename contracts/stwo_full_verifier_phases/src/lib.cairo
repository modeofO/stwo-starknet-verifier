//! Lane 2: resumable verification of the full Cairo verifier
//! (poseidon252 configuration). See docs/lane2-design.md.

pub mod resumable_full;
pub mod sponge;

/// Escape markers of the packed-proof v2 encoding (see `unpack_proof_v2`).
const U64_ESCAPE: u32 = 0xFFFFFFFF;
const FELT_ESCAPE: u32 = 0xFFFFFFFE;

/// Decodes the v2 packed limb stream back into the proof's felt252 stream:
/// 7 little-endian u32 limbs per felt252 slot; a limb of `0xFFFFFFFF`
/// escapes a (low, high) u64 pair; a limb of `0xFFFFFFFE` escapes a full
/// felt252 as 8 little-endian u32 limbs (poseidon proof streams carry full
/// felt252 hashes). Mirrors `scripts/pack_proof.py --v2`.
pub fn unpack_proof_v2(packed: Span<felt252>, n_values: u32) -> Array<felt252> {
    let nz32: NonZero<u128> = 0x100000000_u128.try_into().unwrap();
    let mut limbs: Array<u32> = array![];
    for slot in packed {
        let v: u256 = (*slot).into();
        let (q, l0) = DivRem::div_rem(v.low, nz32);
        let (q, l1) = DivRem::div_rem(q, nz32);
        let (l3, l2) = DivRem::div_rem(q, nz32);
        let (q, l4) = DivRem::div_rem(v.high, nz32);
        let (l6, l5) = DivRem::div_rem(q, nz32);
        limbs.append(l0.try_into().unwrap());
        limbs.append(l1.try_into().unwrap());
        limbs.append(l2.try_into().unwrap());
        limbs.append(l3.try_into().unwrap());
        limbs.append(l4.try_into().unwrap());
        limbs.append(l5.try_into().unwrap());
        limbs.append(l6.try_into().unwrap());
    }

    let limbs = limbs.span();
    let mut values: Array<felt252> = array![];
    let mut i: usize = 0;
    while values.len() != n_values {
        let limb = *limbs[i];
        if limb == U64_ESCAPE {
            let lo: felt252 = (*limbs[i + 1]).into();
            let hi: felt252 = (*limbs[i + 2]).into();
            values.append(lo + hi * 0x100000000);
            i += 3;
        } else if limb == FELT_ESCAPE {
            let mut v: felt252 = 0;
            let mut k: usize = 8;
            while k != 0 {
                v = v * 0x100000000 + (*limbs[i + k]).into();
                k -= 1;
            }
            values.append(v);
            i += 9;
        } else {
            values.append(limb.into());
            i += 1;
        }
    }
    values
}
