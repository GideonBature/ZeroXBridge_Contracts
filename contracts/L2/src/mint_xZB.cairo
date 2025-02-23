use core::starknet::eth_address::EthAddress;
use starknet::secp256_trait::Signature;

#[starknet::interface]
pub trait IMintAndClaimZXB<TContractState> {
    fn mint_and_claim_xzb(ref self: TContractState, usd_deposited: u256, msg_hash: u256, eth_address: EthAddress, signature: Signature, r: u256, s: u256, v: u32);
    fn get_signature(self: @TContractState, r: u256, s: u256, v: u32) -> Signature;
}

#[starknet::contract]
pub mod MintAndClaimZXB {
    use core::num::traits::Zero;
    use core::starknet::eth_address::EthAddress;
    use starknet::{ContractAddress, get_caller_address};
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess, StoragePointerWriteAccess};
    use openzeppelin_token::erc20::{ERC20Component, ERC20HooksEmptyImpl};
    use openzeppelin_token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use starknet::secp256_trait::{Signature, signature_from_vrs};
    use starknet::eth_signature::is_eth_signature_valid;
    
    component!(path: ERC20Component, storage: erc20, event: ERC20Event);

    #[abi(embed_v0)]
    impl ERC20MixinImpl = ERC20Component::ERC20MixinImpl<ContractState>;
    impl ERC20InternalImpl = ERC20Component::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        erc20: ERC20Component::Storage,
        pub zxb_contract_address: ContractAddress,
        pub pending_claims: Map<ContractAddress, bool>
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
      #[flat]
      ERC20Event: ERC20Component::Event,
      ZXBMinted: ZXBMinted,
    }

    #[derive(starknet::Event, Drop)]
    pub struct ZXBMinted {
        pub user: ContractAddress,
        pub amount: u256,
    }
    #[constructor]
    fn constructor(ref self: ContractState, zxb_contract_address: ContractAddress) {
        assert(!zxb_contract_address.is_zero(), 'MVG:VM_ZERO');
        self.zxb_contract_address.write(zxb_contract_address);
    }

    #[abi(embed_v0)]
    impl MintAndClaimZXBImpl of super::IMintAndClaimZXB<ContractState> {
        fn mint_and_claim_xzb(ref self: ContractState, usd_deposited: u256, msg_hash: u256, eth_address: EthAddress, signature: Signature, r: u256, s: u256, v: u32) {
            assert(usd_deposited > 0, 'Must deposit a positive amount');
            
            let signature = self.get_signature(r, s, v);
            assert(is_eth_signature_valid(msg_hash, signature, eth_address).is_ok(), 'Invalid signature');

            let caller = get_caller_address();
            assert(!self.pending_claims.read(caller), 'Claim already pending');


            // TODO: Verify proof (wait for #8 to be merged)

            let mint_rate = 1; // TODO: wait for #7 to be merged
            let mint_amount = usd_deposited * mint_rate;
            
            self.pending_claims.write(caller, true);
            
            let zxb_token = IERC20Dispatcher { contract_address: self.zxb_contract_address.read() };
            
            // TODO: wait for #6 to be merged
            // zxb_token.mint(caller, mint_amount);
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
    }
}