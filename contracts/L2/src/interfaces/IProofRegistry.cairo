#[starknet::interface]
pub trait IProofRegistry<TContractState> {
    // Get the merkle root of commitment hash if it was verified.
    fn get_verified_merkle_root(self: @TContractState, commitment_hash: felt252) -> felt252;

    fn check_proof(self: @TContractState, commitment_hash: felt252, merkle_root: felt252) -> bool;

    // Prove given commitment_hash with proof verified by Integrity.
    fn register_deposit_proof(
        ref self: TContractState, commitment_hash: felt252, merkle_root: felt252,
    );
}
