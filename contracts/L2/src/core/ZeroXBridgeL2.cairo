use starknet::ContractAddress;
use core::option::Option;

#[starknet::interface]
pub trait IZeroXBridgeL2<TContractState> {
    /// The proof structure assumes the first four elements contain recipient, usd_amount,
    /// block_hash
    fn mint_and_claim_xzb(
        ref self: TContractState, proof: Array<felt252>, commitment_hash: felt252,
    );

    fn burn_xzb_for_unlock(ref self: TContractState, amount: core::integer::u256);
}

#[starknet::interface]
pub trait IDynamicRate<TContractState> {
    fn get_dynamic_rate(self: @TContractState, tvl: u256) -> u256;
    fn get_current_xzb_supply(self: @TContractState) -> u256;
    fn set_rates(ref self: TContractState, min_rate: Option<u256>, max_rate: Option<u256>);
    fn set_oracle(ref self: TContractState, oracle: ContractAddress);
    fn set_xzb_token(ref self: TContractState, xzb_token: ContractAddress);
}


#[starknet::contract]
pub mod ZeroXBridgeL2 {
    use openzeppelin_access::ownable::OwnableComponent;
    use openzeppelin_introspection::src5::SRC5Component;
    use openzeppelin_upgrades::UpgradeableComponent;
    use openzeppelin_upgrades::interface::IUpgradeable;
    use starknet::{ContractAddress, get_caller_address, ClassHash};
    use l2::core::xZBERC20::{
        IBurnableDispatcher, IBurnableDispatcherTrait, IMintableDispatcher,
        IMintableDispatcherTrait, ISupplyDispatcher, ISupplyDispatcherTrait,
    };
    use l2::core::L2Oracle::{IL2OracleDispatcher, IL2OracleDispatcherTrait};

    use core::option::Option;
    use core::pedersen::PedersenTrait;
    // use l2::utils::hash;

    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess, Map, StorageMapReadAccess,
        StorageMapWriteAccess,
    };
    use core::hash::{HashStateTrait, HashStateExTrait};
    use l2::core::ProofRegistry::{IProofRegistryDispatcher, IProofRegistryDispatcherTrait};

    const BASIS_POINTS: u256 = 10000;
    const PRECISION: u256 = 1000000; // 6 decimals for rate precision

    // Ownable Component
    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);
    component!(path: UpgradeableComponent, storage: upgradeable, event: UpgradeableEvent);


    // Ownable Mixin
    #[abi(embed_v0)]
    impl OwnableMixinImpl = OwnableComponent::OwnableMixinImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    impl UpgradeableInternalImpl = UpgradeableComponent::InternalImpl<ContractState>;


    #[derive(Drop, Serde, Copy, starknet::Store)]
    pub struct Rates {
        pub min_rate: u256,
        pub max_rate: u256,
    }

    #[storage]
    struct Storage {
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
        #[substorage(v0)]
        src5: SRC5Component::Storage,
        #[substorage(v0)]
        upgradeable: UpgradeableComponent::Storage,
        xzb_token: ContractAddress,
        oracle_address: ContractAddress,
        proof_registry_address: ContractAddress,
        verified_commitments: Map<felt252, bool>,
        verified_roots: Map<felt252, felt252>,
        rates: Rates,
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
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        BurnEvent: BurnEvent,
        MintEvent: MintEvent,
        RateUpdated: RateUpdated,
        OracleUpdated: OracleUpdated,
        XZBTokenUpdated: XZBTokenUpdated,
        RateLimitsUpdated: RateLimitsUpdated,
        #[flat]
        OwnableEvent: OwnableComponent::Event,
        #[flat]
        SRC5Event: SRC5Component::Event,
        #[flat]
        UpgradeableEvent: UpgradeableComponent::Event,
    }

    #[derive(Drop, Debug, starknet::Event)]
    struct RateUpdated {
        #[key]
        new_rate: u256,
        tvl: u256,
    }

    #[derive(Drop, Debug, starknet::Event)]
    struct OracleUpdated {
        #[key]
        oracle: ContractAddress,
    }

    #[derive(Drop, Debug, starknet::Event)]
    struct XZBTokenUpdated {
        #[key]
        xzb_token: ContractAddress,
    }

    #[derive(Drop, Debug, starknet::Event)]
    struct RateLimitsUpdated {
        min_rate: u256,
        max_rate: u256,
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
        owner: ContractAddress,
        token: ContractAddress,
        proof_registry_address: ContractAddress,
        oracle_address: ContractAddress,
        min_rate: u256,
        max_rate: u256,
    ) {
        self.ownable.initializer(owner);
        self.xzb_token.write(token);
        self.proof_registry_address.write(proof_registry_address);
        self.oracle_address.write(oracle_address);
        let rates = Rates { min_rate, max_rate };
        self.rates.write(rates);
    }

    #[abi(embed_v0)]
    impl MintBurnXzbImpl of super::IZeroXBridgeL2<ContractState> {
        fn mint_and_claim_xzb(
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

            let usd_amount = core::integer::u256 {
                low: amount_low.try_into().unwrap(), high: amount_high.try_into().unwrap(),
            };

            assert(computed_hash == commitment_hash, 'Proof does not match commitment');

            let proof_registry = IProofRegistryDispatcher {
                contract_address: self.proof_registry_address.read(),
            };

            let merkle_root = proof_registry.get_verified_merkle_root(commitment_hash);

            self.verified_commitments.write(commitment_hash, true);
            self.verified_roots.write(commitment_hash, merkle_root);

            let recipient: ContractAddress = recipient_felt.try_into().unwrap();

            let mint_rate = self.get_dynamic_rate(usd_amount);

            let mint_amount = (usd_amount * mint_rate) / PRECISION / PRECISION;

            let token_addr = self.xzb_token.read();
            IMintableDispatcher { contract_address: token_addr }.mint(recipient, mint_amount);

            self
                .emit(
                    Event::MintEvent(
                        MintEvent { recipient, amount_low, amount_high, commitment_hash },
                    ),
                );
        }


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
    }

    #[abi(embed_v0)]
    impl DynamicRateImpl of super::IDynamicRate<ContractState> {
        fn get_dynamic_rate(self: @ContractState, tvl: u256) -> u256 {
            // Get current total TVL from oracle
            let oracle_dispatcher = IL2OracleDispatcher {
                contract_address: self.oracle_address.read(),
            };
            let total_tvl = oracle_dispatcher.get_total_tvl();

            // Calculate new TVL including the incoming deposit
            let new_tvl = total_tvl + tvl; // WITH PRECISIONS
            assert(new_tvl > 0, 'TVL cannot be zero');

            // Get current xZB supply
            let xzb_supply = self.get_current_xzb_supply();

            // Calculate new protocol rate
            // new_rate = (current_xZB_supply / new_TLV) * PRECISION
            let raw_rate = (xzb_supply * PRECISION * PRECISION) / new_tvl;

            let rates = self.rates.read();

            // Apply rate limits
            let min_rate = rates.min_rate;
            let max_rate = rates.max_rate;

            let final_rate = if raw_rate == 0 {
                1 * PRECISION
            } else if raw_rate < min_rate {
                min_rate
            } else if raw_rate > max_rate {
                max_rate
            } else {
                raw_rate
            };

            final_rate
        }

        fn get_current_xzb_supply(self: @ContractState) -> u256 {
            let xzb_token = self.xzb_token.read();

            // Create dispatcher to call the ERC20 contract
            let xzb_dispatcher = ISupplyDispatcher { contract_address: xzb_token };

            // Get total supply from the token contract
            xzb_dispatcher.total_supply()
        }

        fn set_rates(ref self: ContractState, min_rate: Option<u256>, max_rate: Option<u256>) {
            self.ownable.assert_only_owner();
            let mut current_rates = self.rates.read();

            match min_rate {
                Option::Some(new_min) => { current_rates.min_rate = new_min; },
                Option::None => {},
            }

            match max_rate {
                Option::Some(new_max) => { current_rates.max_rate = new_max; },
                Option::None => {},
            }

            assert(current_rates.min_rate < current_rates.max_rate, 'Min rate must be < max rate');

            self.rates.write(current_rates);

            self
                .emit(
                    Event::RateLimitsUpdated(
                        RateLimitsUpdated {
                            min_rate: current_rates.min_rate, max_rate: current_rates.max_rate,
                        },
                    ),
                );
        }

        fn set_oracle(ref self: ContractState, oracle: ContractAddress) {
            self.ownable.assert_only_owner();
            self.oracle_address.write(oracle);
            self.emit(Event::OracleUpdated(OracleUpdated { oracle }));
        }

        fn set_xzb_token(ref self: ContractState, xzb_token: ContractAddress) {
            self.ownable.assert_only_owner();
            self.xzb_token.write(xzb_token);
            self.emit(Event::XZBTokenUpdated(XZBTokenUpdated { xzb_token }));
        }
    }

    #[abi(embed_v0)]
    impl UpgradeableImpl of IUpgradeable<ContractState> {
        fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self.upgradeable.upgrade(new_class_hash);
        }
    }
}
