use starknet::ContractAddress;

#[starknet::interface]
pub trait IXZBERC20<TContractState> {
    // Mintable functions
    fn mint(ref self: TContractState, recipient: ContractAddress, amount: u256);

    // Burnable functions
    fn burn(ref self: TContractState, amount: u256);

    // Manager functions
    fn set_bridge_address(ref self: TContractState, bridge: ContractAddress);
    fn get_bridge_address(self: @TContractState) -> ContractAddress;
}
