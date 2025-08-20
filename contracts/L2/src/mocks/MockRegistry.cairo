#[starknet::interface]
pub trait IMockRegistry<TContractState> {
    fn set_should_succeed(ref self: TContractState, should_succeed: bool);
}

#[starknet::contract]
mod MockProofRegistry {
    use integrity::{Integrity, IntegrityWithConfig};
    use l2::interfaces::IProofRegistry::IProofRegistry;
    use starknet::storage::{
        Map, StoragePathEntry, StoragePointerReadAccess, StoragePointerWriteAccess,
    };
    use super::*;

    #[storage]
    struct Storage {
        verified_deposit_roots: Map<felt252, Option<felt252>>,
        should_succeed: bool,
    }

    #[derive(Drop, starknet::Event)]
    struct DepositCommitmentHashProven {
        commitment_hash: felt252,
        merkle_root: felt252,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        DepositCommitmentHashProven: DepositCommitmentHashProven,
    }

    #[abi(embed_v0)]
    impl MockRegistryImpl of IMockRegistry<ContractState> {
        fn set_should_succeed(ref self: ContractState, should_succeed: bool) {
            self.should_succeed.write(should_succeed);
        }
    }

    #[abi(embed_v0)]
    impl ProofRegistryImpl of IProofRegistry<ContractState> {
        fn get_verified_merkle_root(self: @ContractState, commitment_hash: felt252) -> felt252 {
            self.verified_deposit_roots.entry(commitment_hash).read().expect('Not found')
        }

        fn check_proof(
            self: @ContractState, commitment_hash: felt252, merkle_root: felt252,
        ) -> bool {
            self.should_succeed.read()
        }

        fn register_deposit_proof(
            ref self: ContractState, commitment_hash: felt252, merkle_root: felt252,
        ) {
            let is_valid = self.check_proof(commitment_hash, merkle_root);

            assert(is_valid, 'Proof not verified');

            // This is specific to your application.
            // After assert above, you are sure that Integrity verified the program.
            self.verified_deposit_roots.entry(commitment_hash).write(Option::Some(merkle_root));
            self
                .emit(
                    Event::DepositCommitmentHashProven(
                        DepositCommitmentHashProven { commitment_hash, merkle_root },
                    ),
                );
        }
    }
}
