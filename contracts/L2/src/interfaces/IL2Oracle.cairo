use starknet::ContractAddress;

#[starknet::interface]
pub trait IL2Oracle<TContractState> {
    fn get_total_tvl(self: @TContractState) -> u256;
    fn set_total_tvl(ref self: TContractState, tvl: u256);
    fn set_relayer(ref self: TContractState, relayer: ContractAddress, status: bool);
}
