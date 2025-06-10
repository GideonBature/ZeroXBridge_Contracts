// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts for Cairo ^0.20.0

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

pub const BRIDGE_ROLE: felt252 = selector!("BRIDGE_ROLE");
pub const UPGRADER_ROLE: felt252 = selector!("UPGRADER_ROLE");

#[starknet::contract]
pub mod xZBERC20 {
    use openzeppelin_access::accesscontrol::{AccessControlComponent, DEFAULT_ADMIN_ROLE};
    use openzeppelin_introspection::src5::SRC5Component;
    use openzeppelin_token::erc20::{ERC20Component, ERC20HooksEmptyImpl};
    use openzeppelin_upgrades::UpgradeableComponent;
    use openzeppelin_upgrades::interface::IUpgradeable;
    use starknet::{ClassHash, ContractAddress, get_caller_address};

    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};

    use super::{IXZBERC20};
    use super::{BRIDGE_ROLE, UPGRADER_ROLE};

    component!(path: ERC20Component, storage: erc20, event: ERC20Event);
    component!(path: AccessControlComponent, storage: accesscontrol, event: AccessControlEvent);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);
    component!(path: UpgradeableComponent, storage: upgradeable, event: UpgradeableEvent);

    // External
    #[abi(embed_v0)]
    impl ERC20MixinImpl = ERC20Component::ERC20MixinImpl<ContractState>;
    #[abi(embed_v0)]
    impl AccessControlMixinImpl =
        AccessControlComponent::AccessControlMixinImpl<ContractState>;

    // Internal
    impl ERC20InternalImpl = ERC20Component::InternalImpl<ContractState>;
    impl AccessControlInternalImpl = AccessControlComponent::InternalImpl<ContractState>;
    impl UpgradeableInternalImpl = UpgradeableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        erc20: ERC20Component::Storage,
        #[substorage(v0)]
        accesscontrol: AccessControlComponent::Storage,
        #[substorage(v0)]
        src5: SRC5Component::Storage,
        #[substorage(v0)]
        upgradeable: UpgradeableComponent::Storage,
        bridge: ContractAddress,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        #[flat]
        ERC20Event: ERC20Component::Event,
        #[flat]
        AccessControlEvent: AccessControlComponent::Event,
        #[flat]
        SRC5Event: SRC5Component::Event,
        #[flat]
        UpgradeableEvent: UpgradeableComponent::Event,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        self.erc20.initializer("xZB", "XZB");
        self.accesscontrol.initializer();

        self.accesscontrol._grant_role(DEFAULT_ADMIN_ROLE, owner);
        self.accesscontrol._grant_role(UPGRADER_ROLE, owner);
        self.accesscontrol._grant_role(BRIDGE_ROLE, owner);
    }

    #[abi(embed_v0)]
    impl XZBERC20Impl of IXZBERC20<ContractState> {
        fn mint(ref self: ContractState, recipient: ContractAddress, amount: u256) {
            self.accesscontrol.assert_only_role(BRIDGE_ROLE);
            self.erc20.mint(recipient, amount);
        }

        fn burn(ref self: ContractState, amount: u256) {
            // self.accesscontrol.assert_only_role(BRIDGE_ROLE);
            let burner = get_caller_address();
            self.erc20.burn(burner, amount);
        }

        fn set_bridge_address(ref self: ContractState, bridge: ContractAddress) {
            self.accesscontrol.grant_role(BRIDGE_ROLE, bridge);
            self.bridge.write(bridge);
        }

        fn get_bridge_address(self: @ContractState) -> ContractAddress {
            self.bridge.read()
        }
    }

    //
    // Upgradeable
    //
    #[abi(embed_v0)]
    impl UpgradeableImpl of IUpgradeable<ContractState> {
        fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self.accesscontrol.assert_only_role(UPGRADER_ROLE);
            self.upgradeable.upgrade(new_class_hash);
        }
    }
}
