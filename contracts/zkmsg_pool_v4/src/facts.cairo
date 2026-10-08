//! Pure parsing of a send's SNIP-36 proof facts and the v4 binding hashes.
//!
//! No syscalls here, so every rule is unit-testable without a transaction:
//! the store (execute) and the pool account (validate) both reduce
//! `tx_info.proof_facts` through these functions.
//!
//! Layout the virtual OS writes for one proven L2->L1 message:
//!
//!   [PROOF1, VIRTUAL_SNOS, program_hash, VIRTUAL_SNOS0, base_block_number,
//!    base_block_hash, os_config_hash, n_l2_to_l1_messages, message_hash]

pub const PROOF_VERSION_V1: felt252 = 'PROOF1';
pub const VIRTUAL_SNOS: felt252 = 'VIRTUAL_SNOS';
pub const VIRTUAL_OS_OUTPUT_VERSION: felt252 = 'VIRTUAL_SNOS0';

pub const FACTS_LEN_ONE_MESSAGE: u32 = 9;
const IDX_VERSION: u32 = 0;
const IDX_VARIANT: u32 = 1;
const IDX_OUTPUT_VERSION: u32 = 3;
const IDX_BASE_BLOCK_NUMBER: u32 = 4;
const IDX_N_MESSAGES: u32 = 7;
const IDX_MESSAGE_HASH: u32 = 8;

/// What a send's facts attest, once the shape is checked.
#[derive(Drop, Copy, PartialEq, Debug)]
pub struct SendFacts {
    /// The block the virtual OS ran on. The OS checked its hash against the
    /// chain before this transaction executed, so it is not client-chosen
    /// beyond "some real past block".
    pub base_block_number: u64,
    /// poseidon([from_address, to_address, payload_len, ...payload]).
    pub message_hash: felt252,
}

/// Checks the shape of the facts and extracts what the store binds. Panics
/// with a reason on anything other than one virtual-OS message.
pub fn parse_send_facts(facts: Span<felt252>) -> SendFacts {
    assert(facts.len() == FACTS_LEN_ONE_MESSAGE, 'expected one proven message');
    // The OS already rejects anything else; checked again so a future proof
    // variant cannot be read with this layout.
    assert(*facts.at(IDX_VERSION) == PROOF_VERSION_V1, 'unsupported proof version');
    assert(*facts.at(IDX_VARIANT) == VIRTUAL_SNOS, 'not a virtual OS proof');
    assert(*facts.at(IDX_OUTPUT_VERSION) == VIRTUAL_OS_OUTPUT_VERSION, 'unknown OS output');
    assert(*facts.at(IDX_N_MESSAGES) == 1, 'expected one proven message');
    let base_block_number: u64 = (*facts.at(IDX_BASE_BLOCK_NUMBER))
        .try_into()
        .expect('bad base block number');
    SendFacts { base_block_number, message_hash: *facts.at(IDX_MESSAGE_HASH) }
}

/// The message hash the virtual OS writes into the proof facts:
/// poseidon([from_address, to_address, payload_size, ...payload]).
pub fn message_hash(from_address: felt252, to_address: felt252, payload: Span<felt252>) -> felt252 {
    let mut preimage: Array<felt252> = array![from_address, to_address, payload.len().into()];
    for item in payload {
        preimage.append(*item);
    }
    core::poseidon::poseidon_hash_span(preimage.span())
}

/// The epoch a base block falls in. Epochs are counted in blocks because the
/// base block NUMBER is in the facts (OS-checked) and its timestamp is not.
pub fn epoch_of(block_number: u64, epoch_blocks: u64) -> u64 {
    block_number / epoch_blocks
}

/// The granularity blockifier rounds `block_number` to in `__validate__`
/// (versioned constants `validate_block_number_rounding`). The store rounds
/// the same way in execute, so a check that passed in validate cannot fail
/// in execute for the same block.
pub const VALIDATE_BLOCK_ROUNDING: u64 = 100;

pub fn round_block(block_number: u64) -> u64 {
    (block_number / VALIDATE_BLOCK_ROUNDING) * VALIDATE_BLOCK_ROUNDING
}

/// A proof's epoch is acceptable if it is the current epoch or at most
/// `max_lag` behind, judged against the ROUNDED current block. Without this
/// a member could prove against an ancient base block (whose root may still
/// be current if nobody registered since) and mint a fresh quota per epoch
/// of history.
pub fn epoch_is_fresh(proof_epoch: u64, now_block: u64, epoch_blocks: u64, max_lag: u64) -> bool {
    let now_epoch = epoch_of(round_block(now_block), epoch_blocks);
    proof_epoch <= now_epoch && proof_epoch + max_lag >= now_epoch
}
