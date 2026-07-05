//! FRI transport v3 test util: slices a carved fri section into the
//! packed-calldata pieces the router/machine consume — the FriHead
//! commitment slice and greedy layer-batched chunks (serialized
//! `Array<FriLayerProof>`, chunk 0 led by the first-layer proof), each
//! chunk's PACKED size capped so the full transaction (state echo + head
//! + fri_head + chunk) stays under the ~4,996-felt usable calldata cap.

use core::array::SpanTrait;
use stwo_full_verifier_phases::fri_transport::FriHead;
use stwo_full_verifier_phases::pack::pack_v2;
use stwo_verifier_core::fri::{FriLayerProof, FriProof};

/// Max packed slots for one layer chunk (~4,996 minus the state echo,
/// head, fri_head and scalar overhead).
pub const MAX_LAYER_CHUNK_SLOTS: u32 = 4_300;

#[derive(Drop)]
pub struct FriTransport {
    pub head_felts: Array<felt252>,
    /// Serialized Array<FriLayerProof> per chunk transaction.
    pub layer_chunks: Array<Array<felt252>>,
}

fn serialize_chunk(proofs: @Array<FriLayerProof>) -> Array<felt252> {
    let mut felts = array![];
    Serde::serialize(proofs, ref felts);
    felts
}

/// Deserializes the fri section and re-serializes it as (head, chunks).
pub fn build_fri_transport(fri_felts: Span<felt252>) -> FriTransport {
    let mut span = fri_felts;
    let proof: FriProof = Serde::deserialize(ref span).expect('friproof');
    assert!(SpanTrait::is_empty(span), "fri trailing");
    let FriProof { first_layer, inner_layers, last_layer_poly } = proof;

    let mut inner_commitments = array![];
    for layer in inner_layers {
        inner_commitments.append(*layer.commitment);
    }
    let head = FriHead {
        first_commitment: first_layer.commitment.clone(),
        inner_commitments: inner_commitments.span(),
        last_layer_poly,
    };
    let mut head_felts = array![];
    Serde::serialize(@head, ref head_felts);

    // Greedy layer batching under the packed-slot budget. Chunk 0 must
    // start with the first-layer proof.
    let mut layer_chunks: Array<Array<felt252>> = array![];
    let mut current: Array<FriLayerProof> = array![first_layer];
    for layer in inner_layers {
        let mut candidate = current.clone();
        candidate.append(layer.clone());
        if pack_v2(serialize_chunk(@candidate).span()).len() <= MAX_LAYER_CHUNK_SLOTS {
            current = candidate;
        } else {
            layer_chunks.append(serialize_chunk(@current));
            current = array![layer.clone()];
        }
    }
    layer_chunks.append(serialize_chunk(@current));
    FriTransport { head_felts, layer_chunks }
}
