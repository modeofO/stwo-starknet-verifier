use stwo_cairo_air::{CairoProof, VerificationOutput};

#[starknet::interface]
pub trait IStwoVerifier<TContractState> {
    /// Verifies a Stwo (Circle-STARK) proof of a Cairo executable.
    /// Panics if the proof is invalid; returns the program hash and program
    /// output on success.
    fn verify_proof(self: @TContractState, proof: CairoProof) -> VerificationOutput;
}

#[starknet::contract]
mod StwoVerifier {
    use stwo_cairo_air::{CairoProof, VerificationOutput, get_verification_output, verify_cairo};
    use super::IStwoVerifier;

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl StwoVerifierImpl of IStwoVerifier<ContractState> {
        fn verify_proof(self: @ContractState, proof: CairoProof) -> VerificationOutput {
            let output = get_verification_output(proof: @proof);
            verify_cairo(:proof);
            output
        }
    }
}
