//! v1 felt packing: canonical encoding of message payloads into felt arrays.
//!
//! Ports the v1 branch of `scripts/pack_proof.py`: 7 little-endian u32 limbs
//! per felt252 slot. Limbs < 0xFFFFFFFF are literal; 0xFFFFFFFF escapes a
//! (low, high) u64 pair. Values >= 2^64 are rejected (v1 has no felt-escape).

use anyhow::{bail, Result};
use starknet_types_core::felt::Felt;

const U32_MAX: u64 = 0xFFFFFFFF;

/// Converts a felt to its u64 value, erroring if it doesn't fit.
fn felt_to_u64(value: &Felt) -> Result<u64> {
    let bytes = value.to_bytes_be();
    if bytes[..24].iter().any(|&b| b != 0) {
        bail!("value {:#x} exceeds u64 — v1 packing has no felt escape", value);
    }
    let mut low = [0u8; 8];
    low.copy_from_slice(&bytes[24..32]);
    Ok(u64::from_be_bytes(low))
}

/// Packs 32-bit limbs (up to 7 of them) into a single felt252 slot, matching
/// the Python `sum(l << (32 * i) for i, l in enumerate(chunk))`.
fn limbs_to_slot(limbs: &[u32]) -> Felt {
    let mut bytes = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        bytes[4 * i..4 * i + 4].copy_from_slice(&limb.to_le_bytes());
    }
    Felt::from_bytes_le(&bytes)
}

/// v1 packing: 7 little-endian u32 limbs per felt252 slot; limbs < 0xFFFFFFFF
/// are literal; 0xFFFFFFFF escapes a (low, high) u64 pair. Values >= 2^64 error.
pub fn pack_v1(values: &[Felt]) -> Result<Vec<Felt>> {
    let mut limbs: Vec<u32> = Vec::with_capacity(values.len());
    for value in values {
        let v = felt_to_u64(value)?;
        if v < U32_MAX {
            limbs.push(v as u32);
        } else {
            limbs.push(U32_MAX as u32);
            limbs.push((v & U32_MAX) as u32);
            limbs.push(((v >> 32) & U32_MAX) as u32);
        }
    }
    Ok(limbs.chunks(7).map(limbs_to_slot).collect())
}

/// Loads a wrap-output proof JSON (array of hex felt strings) into felts.
pub fn load_proof_json(path: &std::path::Path) -> Result<Vec<Felt>> {
    let text = std::fs::read_to_string(path)?;
    let raw: Vec<String> = serde_json::from_str(&text)?;
    raw.iter().map(|s| Ok(Felt::from_hex(s)?)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(rel: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
    }

    #[test]
    fn golden_against_shipped_fixture() {
        let proof_path = fixture("../../fixtures/poseidon_chain_n100.multiverifier_proof.json");
        let packed_path = fixture(
            "../../contracts/stwo_fact_registry/tests/data/poseidon_chain_n100_proof_packed.txt",
        );

        let values = load_proof_json(&proof_path).expect("load proof json");
        let got = pack_v1(&values).expect("pack_v1");

        let packed_text = std::fs::read_to_string(&packed_path).expect("read packed fixture");
        let expected: Vec<Felt> = packed_text
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| Felt::from_hex(l).expect("parse packed hex felt"))
            .collect();

        assert_eq!(
            got.len(),
            expected.len(),
            "slot count mismatch: got {} expected {}",
            got.len(),
            expected.len()
        );
        for (i, (g, e)) in got.iter().zip(expected.iter()).enumerate() {
            assert_eq!(g, e, "first differing slot at index {}", i);
        }
    }

    fn unpack_limbs(slot: &Felt) -> [u32; 7] {
        let bytes = slot.to_bytes_le();
        let mut out = [0u32; 7];
        for i in 0..7 {
            let mut chunk = [0u8; 4];
            chunk.copy_from_slice(&bytes[4 * i..4 * i + 4]);
            out[i] = u32::from_le_bytes(chunk);
        }
        out
    }

    #[test]
    fn escape_boundary_cases() {
        // Literal: value just below the escape sentinel.
        let slots = pack_v1(&[Felt::from(0xFFFFFFFEu64)]).unwrap();
        assert_eq!(slots.len(), 1);
        let limbs = unpack_limbs(&slots[0]);
        assert_eq!(limbs[0], 0xFFFFFFFE);
        assert_eq!(limbs[1], 0);

        // Escaped: value at the sentinel itself.
        let slots = pack_v1(&[Felt::from(0xFFFFFFFFu64)]).unwrap();
        assert_eq!(slots.len(), 1);
        let limbs = unpack_limbs(&slots[0]);
        assert_eq!(limbs[0], 0xFFFFFFFF);
        assert_eq!(limbs[1], 0xFFFFFFFF);
        assert_eq!(limbs[2], 0);

        // Escaped: a value requiring the high limb.
        let v: u64 = 1u64 << 40;
        let slots = pack_v1(&[Felt::from(v)]).unwrap();
        assert_eq!(slots.len(), 1);
        let limbs = unpack_limbs(&slots[0]);
        assert_eq!(limbs[0], 0xFFFFFFFF);
        assert_eq!(limbs[1], (v & 0xFFFFFFFF) as u32);
        assert_eq!(limbs[2], ((v >> 32) & 0xFFFFFFFF) as u32);

        // Rejected: value >= 2^64 has no v1 representation.
        let too_big = Felt::from(u128::MAX);
        assert!(pack_v1(&[too_big]).is_err());
    }
}
