use core::array::Array;

#[starknet::interface]
pub trait IMerkleManager<TContractState> {
    fn get_root_hash(self: @TContractState) -> felt252;
    fn get_element_count(self: @TContractState) -> felt252;
    fn get_commitment_index(self: @TContractState, commitment_hash: felt252) -> felt252;
    fn get_last_peaks(self: @TContractState) -> Array<felt252>;
    fn get_leaves_count(self: @TContractState) -> felt252;
    fn verify_proof(
        self: @TContractState,
        index: usize,
        commitment_hash: felt252,
        peaks: Array<felt252>,
        proof: Array<felt252>,
    ) -> Result<bool, felt252>;
}
