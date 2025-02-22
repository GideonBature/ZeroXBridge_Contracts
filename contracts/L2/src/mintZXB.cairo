use starknet::{ContractAddress};
use core::starknet::eth_address::EthAddress;
use starknet::secp256_trait::Signature;

#[starknet::interface]
pub trait IMintAndClaimZXB<TContractState> {
    fn set_zxb_contract_address(self: @TContractState, zxb_contract_address: ContractAddress);
    fn mint_and_claim_xzb(self: @TContractState, usd_deposited: u256);
    fn get_signature(self: @TContractState, r: u256, s: u256, v: u32) -> Signature;
    fn verify_eth_signature(
        self: @TContractState, eth_address: EthAddress, msg_hash: u256, r: u256, s: u256, v: u32,
    );
    fn recover_public_key(
        self: @TContractState, eth_address: EthAddress, msg_hash: u256, r: u256, s: u256, v: u32,
    );
}

#[starknet::contract]
pub mod MintAndClaimZXB {
    use core::num::traits::Zero;
    use core::starknet::eth_address::EthAddress;
    use starknet::{ContractAddress, get_caller_address};
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};
    use openzeppelin_access::ownable::OwnableComponent;
    use openzeppelin_token::erc20::{ERC20Component, ERC20HooksEmptyImpl};
    use openzeppelin_token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use starknet::secp256k1::Secp256k1Point;
    use starknet::secp256_trait::{Signature, signature_from_vrs, recover_public_key};
    use starknet::eth_signature::{verify_eth_signature, public_key_point_to_eth_address};

    component!(path: ERC20Component, storage: erc20, event: ERC20Event);
    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    #[abi(embed_v0)]
    impl OwnableMixinImpl = OwnableComponent::OwnableMixinImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[abi(embed_v0)]
    impl ERC20MixinImpl = ERC20Component::ERC20MixinImpl<ContractState>;
    impl ERC20InternalImpl = ERC20Component::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        erc20: ERC20Component::Storage,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
        zxb_contract_address: ContractAddress,
        pending_claims: Map<ContractAddress, bool>,
        msg_hash: u256,
        signature: Signature,
        eth_address: EthAddress,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
      #[flat]
      OwnableEvent: OwnableComponent::Event,
      #[flat]
      ERC20Event: ERC20Component::Event,
      ZXBMinted: ZXBMinted,
    }

    #[derive(starknet::Event, Drop)]
    pub struct ZXBMinted {
        pub user: ContractAddress,
        pub amount: u256,
    }

    #[abi(embed_v0)]
    impl MintAndClaimZXBImpl of super::IMintAndClaimZXB<ContractState> {
        fn set_zxb_contract_address(self: @ContractState, zxb_contract_address: ContractAddress) {
            self.ownable.assert_only_owner();
            assert(Zero::is_non_zero(@zxb_contract_address), 'Invalid contract address');

            self.zxb_contract_address.write(zxb_contract_address);
        }

        fn mint_and_claim_xzb(self: @ContractState, usd_deposited: u256) {
            assert(usd_deposited > 0, 'Must deposit a positive amount');

            let caller = get_caller_address();
            assert(!self.pending_claims.read(caller), 'Claim already pending');


            // TODO: Verify proof (wait for #8 to be merged)

            let mint_rate = 1; // TODO: wait for #7 to be merged
            let mint_amount = usd_deposited * mint_rate;
            
            self.pending_claims.write(caller, true);

            let zxb_token = IERC20Dispatcher { contract_address: self.zxb_contract_address.read() };
            zxb_token.mint(caller, mint_amount);
            let success = zxb_token.transfer(caller, mint_amount);

            assert(success, 'Mint failed');
            
            self.pending_claims.write(caller, false);

            self.emit(ZXBMinted { user: caller, amount: mint_amount });
        }

        fn get_signature(self: @ContractState, r: u256, s: u256, v: u32) -> Signature {
            // Create a Signature object from the given v, r, and s values.
            let signature: Signature = signature_from_vrs(v, r, s);
            signature
        }

        /// Verifies an Ethereum signature.
        ///
        /// # Arguments
        ///
        /// * `eth_address` - The Ethereum address to verify the signature against.
        /// * `msg_hash` - The hash of the message that was signed.
        /// * `r` - The R component of the signature.
        /// * `s` - The S component of the signature.
        /// * `v` - The V component of the signature.
        fn verify_eth_signature(
            self: @ContractState, eth_address: EthAddress, msg_hash: u256, r: u256, s: u256, v: u32,
        ) {
            let signature = self.get_signature(r, s, v);
            verify_eth_signature(:msg_hash, :signature, :eth_address);
        }
 
        /// Recovers the public key from an Ethereum signature and verifies that it matches the
        /// given Ethereum address.
        ///
        /// # Arguments
        ///
        /// * `eth_address` - The Ethereum address to verify the signature against.
        /// * `msg_hash` - The hash of the message that was signed.
        /// * `r` - The R component of the signature.
        /// * `s` - The S component of the signature.
        /// * `v` - The V component of the signature.
        fn recover_public_key(
            self: @ContractState, eth_address: EthAddress, msg_hash: u256, r: u256, s: u256, v: u32,
        ) {
            let signature = self.get_signature(r, s, v);
            let public_key_point = recover_public_key::<Secp256k1Point>(msg_hash, signature)
                .unwrap();
            let calculated_eth_address = public_key_point_to_eth_address(:public_key_point);
            assert(calculated_eth_address == eth_address, 'Invalid Address');
        }
    }
}