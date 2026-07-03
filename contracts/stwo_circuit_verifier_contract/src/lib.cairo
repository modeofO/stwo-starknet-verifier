use stwo_circuit_air::{CircuitProof, VerificationOutput};

#[starknet::interface]
pub trait IStwoCircuitVerifier<TContractState> {
    /// Verifies a Stwo (Circle-STARK) proof of a circuit.
    /// Panics if the proof is invalid; returns the verification output on
    /// success.
    fn verify_proof(self: @TContractState, proof: CircuitProof) -> VerificationOutput;
}

#[starknet::contract]
mod StwoCircuitVerifier {
    use stwo_circuit_air::{CircuitProof, VerificationOutput, get_verification_output, verify_circuit};
    use super::IStwoCircuitVerifier;

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl StwoCircuitVerifierImpl of IStwoCircuitVerifier<ContractState> {
        fn verify_proof(self: @ContractState, proof: CircuitProof) -> VerificationOutput {
            let output = get_verification_output(@proof);
            verify_circuit(:proof);
            output
        }
    }
}
