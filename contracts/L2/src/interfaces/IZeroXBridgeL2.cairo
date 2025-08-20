use core::option::Option;
use starknet::ContractAddress;

#[starknet::interface]
pub trait IZeroXBridgeL2<TContractState> {
    /// The proof structure assumes the first four elements contain recipient, usd_amount,
    /// block_hash
    fn mint_and_claim_xzb(
        ref self: TContractState,
        proof: Array<felt252>,
        commitment_hash: felt252,
        eth_address: felt252,
        r: u256,
        s: u256,
        y_parity: bool,
    );

    fn burn_xzb_for_unlock(ref self: TContractState, amount: core::integer::u256);
}

#[starknet::interface]
pub trait IDynamicRate<TContractState> {
    fn get_dynamic_rate(self: @TContractState) -> u256;
    fn get_current_xzb_supply(self: @TContractState) -> u256;
    fn set_rates(ref self: TContractState, min_rate: Option<u256>, max_rate: Option<u256>);
    fn set_oracle(ref self: TContractState, oracle: ContractAddress);
    fn set_xzb_token(ref self: TContractState, xzb_token: ContractAddress);
}
