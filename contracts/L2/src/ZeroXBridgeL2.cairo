#[starknet::interface]
pub trait IZeroXBridgeL2<TContractState> {
    fn burn_xzb_for_unlock(ref self: TContractState, amount: core::integer::u256);
    /// The proof structure assumes the first four elements contain recipient, amount_low, and
    /// amount_high, block_hash
    fn process_mint_proof(
        ref self: TContractState, proof: Array<felt252>, commitment_hash: felt252,
    );
}

#[starknet::contract]
pub mod ZeroXBridgeL2 {
    use starknet::{ContractAddress, get_caller_address};
    use l2::xZBERC20::{
        IBurnableDispatcher, IBurnableDispatcherTrait, IMintableDispatcher,
        IMintableDispatcherTrait,
    };
    use core::pedersen::PedersenTrait;
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess, Map, StorageMapReadAccess,
        StorageMapWriteAccess,
    };
    use core::hash::{HashStateTrait, HashStateExTrait};
    use l2::ProofRegistry::{IProofRegistryDispatcher, IProofRegistryDispatcherTrait};

    #[storage]
    struct Storage {
        xzb_token: ContractAddress,
        proof_registry_address: ContractAddress,
        security_bits: u32,
        verified_commitments: Map<felt252, bool>,
        verified_roots: Map<felt252, felt252>,
    }

    #[derive(Drop, Hash)]
    pub struct BurnData {
        pub caller: felt252,
        pub amount_low: felt252,
        pub amount_high: felt252,
    }

    #[derive(Drop, Hash)]
    pub struct MintData {
        pub recipient: felt252,
        pub amount_low: felt252,
        pub amount_high: felt252,
        pub block_hash: felt252,
    }

    #[event]
    #[derive(Drop, Debug, starknet::Event)]
    pub enum Event {
        BurnEvent: BurnEvent,
        MintEvent: MintEvent,

    }

    #[derive(Drop, Debug, starknet::Event)]
    pub struct BurnEvent {
        pub user: ContractAddress,
        pub amount_low: felt252,
        pub amount_high: felt252,
        pub commitment_hash: felt252,
    }

    #[derive(Drop, Debug, starknet::Event)]
    pub struct MintEvent {
        pub recipient: ContractAddress,
        pub amount_low: felt252,
        pub amount_high: felt252,
        pub commitment_hash: felt252,
    }

  

    #[constructor]
    fn constructor(
        ref self: ContractState,
        token: ContractAddress,
        proof_registry_address: ContractAddress,
        security_bits: u32,
    ) {
        self.xzb_token.write(token);
        self.proof_registry_address.write(proof_registry_address);
        self.security_bits.write(security_bits);
    }

    #[abi(embed_v0)]
    impl BurnXzbImpl of super::IZeroXBridgeL2<ContractState> {
        fn burn_xzb_for_unlock(ref self: ContractState, amount: core::integer::u256) {
            let caller = get_caller_address();
            let token_addr = self.xzb_token.read();

            IBurnableDispatcher { contract_address: token_addr }.burn(amount);

            let data_to_hash = BurnData {
                caller: caller.try_into().unwrap(),
                amount_low: amount.low.try_into().unwrap(),
                amount_high: amount.high.try_into().unwrap(),
            };
            let commitment_hash = PedersenTrait::new(0).update_with(data_to_hash).finalize();

            self
                .emit(
                    BurnEvent {
                        user: caller,
                        amount_low: amount.low.into(),
                        amount_high: amount.high.into(),
                        commitment_hash: commitment_hash,
                    },
                );
        }

        fn process_mint_proof(
            ref self: ContractState, proof: Array<felt252>, commitment_hash: felt252,
        ) {
            assert(
                !self.verified_commitments.read(commitment_hash), 'Commitment already processed',
            );

            assert(proof.len() >= 4, 'Proof too short');

            let recipient_felt = *proof.at(0);
            let amount_low = *proof.at(1);
            let amount_high = *proof.at(2);
            let block_hash = *proof.at(3);

            let mint_data = MintData {
                recipient: recipient_felt, amount_low, amount_high, block_hash,
            };

            let computed_hash = PedersenTrait::new(0).update_with(mint_data).finalize();
            assert(computed_hash == commitment_hash, 'Proof does not match commitment');

            let proof_registry = IProofRegistryDispatcher {
                contract_address: self.proof_registry_address.read(),
            };

            let merkle_root = proof_registry.get_verified_merkle_root(commitment_hash);

            self.verified_commitments.write(commitment_hash, true);
            self.verified_roots.write(commitment_hash, merkle_root);

            let recipient: ContractAddress = recipient_felt.try_into().unwrap();

            let amount = core::integer::u256 {
                low: amount_low.try_into().unwrap(), high: amount_high.try_into().unwrap(),
            };

            let token_addr = self.xzb_token.read();
            IMintableDispatcher { contract_address: token_addr }.mint(recipient, amount);

            self
                .emit(
                    Event::MintEvent(
                        MintEvent { recipient, amount_low, amount_high, commitment_hash },
                    ),
                );
        }
    }
}
