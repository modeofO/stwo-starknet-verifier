//! Cross-language golden-vector dump for the zkmsg Rust crypto module
//! (tools/zkmsg). Primitives are copies of fixtures/messagezk_scan (which
//! copies messagezk's circuit).
//!
//! CAVEAT (measured 2026-07-05): `scarb execute --target standalone`
//! REJECTS ec_op programs ("Memory addresses must be relocatable"), so
//! `main` dumps only the poseidon vectors; the EC functions stay here for
//! provenance but are exercised via starknet.js (messagezk's production
//! client stack) and sealed end-to-end by the milestone-1 bootloader
//! preimage equality (the bridge's blake2s leg DOES support ec_op).
//!
//! Golden vectors (Cairo dump + starknet.js, cross-validated — poseidon2
//! agrees across both stacks; run `scarb execute -p zkmsg_vectors
//! --target standalone --print-program-output` to reproduce 1, 2, 5):
//!
//! 1. hash_pair(1, 2)      = 1557996165160500454210437319447297236715335099509187222888255133199463084263
//!    (== starknet.js computePoseidonHashOnElements([1,2]) — so Rust uses
//!    poseidon_hash_many(&[l, r]))
//! 2. poseidon2(3, 4)      = 2277075937292600178032240350608862537017378088372682623665183773811299784717
//!    (dump prints the signed form P − 1341426851373531035665082432486207568605729126958914076307908282324572235764;
//!    == starknet.js computePoseidonHash(3, 4) — Rust uses poseidon_hash(a, b))
//! 3. ec_mul(5)            = 3406946075390113347849186141614382943859026331139362801098460541807050012492
//! 4. ecdh(6, ec_mul(7))   = 116790107469130620194501433118398966236215846997329127478236149064647078075
//! 5. poseidon2(0, 0)      = 1165814756574493433332935684348403390128033890862827107228326727661107483845
//! 6. commitment(vector 4) = poseidon2(sh, 0)
//!                         = 1030795386918240909424940654827557726691387512779373992039088349375326101405

use core::ec::{EcPointTrait, EcStateTrait, stark_curve};
use core::poseidon::{PoseidonTrait, hades_permutation};
use core::hash::HashStateTrait;

fn hash_pair(left: felt252, right: felt252) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(left);
    state = state.update(right);
    state.finalize()
}

fn poseidon2(a: felt252, b: felt252) -> felt252 {
    let (r, _, _) = hades_permutation(a, b, 2);
    r
}

fn ec_mul(scalar: felt252) -> felt252 {
    let gen = EcPointTrait::new_nz(stark_curve::GEN_X, stark_curve::GEN_Y).unwrap();
    let mut state = EcStateTrait::init();
    state.add_mul(scalar, gen);
    let result = state.finalize_nz().unwrap();
    let (x, _) = result.coordinates();
    x
}

fn ecdh(priv_key: felt252, pub_x: felt252) -> felt252 {
    let pub_point = EcPointTrait::new_nz_from_x(pub_x).unwrap();
    let mut state = EcStateTrait::init();
    state.add_mul(priv_key, pub_point);
    let result = state.finalize_nz().unwrap();
    let (x, _) = result.coordinates();
    x
}

#[executable]
fn main() -> (felt252, felt252, felt252, felt252, felt252) {
    let hp = hash_pair(1, 2);
    let p2 = poseidon2(3, 4);
    let pk = 0;
    let sh = 0;
    let cm = poseidon2(0, 0);
    (hp, p2, pk, sh, cm)
}
