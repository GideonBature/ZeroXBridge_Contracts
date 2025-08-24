#[starknet::contract]
pub mod ZeroXBridgeL2 {
    use cairo_lib::data_structures::mmr::mmr::{MMR, MMRTrait};
    use core::array::ArrayTrait;
    use core::hash::{HashStateExTrait, HashStateTrait};
    use core::option::Option;
    use core::poseidon::PoseidonTrait;
    use l2::interfaces::IL2Oracle::{IL2OracleDispatcher, IL2OracleDispatcherTrait};
    use l2::interfaces::IMerkleManager::IMerkleManager;
    use l2::interfaces::IProofRegistry::{IProofRegistryDispatcher, IProofRegistryDispatcherTrait};
    use l2::interfaces::IZeroXBridgeL2::{IDynamicRate, IZeroXBridgeL2};
    use l2::interfaces::IxZBErc20::{IXZBERC20Dispatcher, IXZBERC20DispatcherTrait};
    use openzeppelin_access::ownable::OwnableComponent;
    use openzeppelin_introspection::src5::SRC5Component;
    use openzeppelin_token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use openzeppelin_upgrades::UpgradeableComponent;
    use openzeppelin_upgrades::interface::IUpgradeable;
    use starknet::eth_address::EthAddress;
    use starknet::eth_signature::verify_eth_signature;
    use starknet::secp256_trait::Signature;
    use starknet::storage::{
        Map, MutableVecTrait, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess, Vec, VecTrait,
    };
    use starknet::{
        ClassHash, ContractAddress, get_block_timestamp, get_caller_address, get_contract_address,
    };


    const PRECISION: u256 = 1_000_000_000_000_000_000; // 18 decimals for precision

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
        burn_nonce: Map<ContractAddress, felt252>,
        rates: Rates,
        // Merkle Manager Storage
        mmr: MMR,
        node_index_to_root: Map<usize, felt252>,
        commitment_hash_to_index: Map<felt252, felt252>,
        last_peaks: Vec<felt252>,
        leaves_count: felt252,
    }

    #[derive(Drop, Hash)]
    pub struct BurnData {
        pub caller: felt252,
        pub amount: u256,
        pub nonce: felt252,
        pub time_stamp: felt252,
    }

    #[derive(Debug, Drop, Hash)]
    pub struct MintData {
        pub recipient: felt252,
        pub amount: felt252,
        pub nonce: felt252,
        pub time_stamp: felt252,
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
        WithdrawalHashAppended: WithdrawalHashAppended,
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
        pub amount: u256,
        pub nonce: felt252,
        pub commitment_hash: felt252,
    }

    #[derive(Drop, Debug, starknet::Event)]
    pub struct MintEvent {
        pub recipient: ContractAddress,
        pub amount: u256,
        pub nonce: felt252,
        pub commitment_hash: felt252,
    }

    #[derive(Drop, Debug, starknet::Event)]
    pub struct WithdrawalHashAppended {
        pub index: felt252,
        pub commitment_hash: felt252,
        pub root_hash: felt252,
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
        let mmr: MMR = Default::default();
        self.mmr.write(mmr);
        self.leaves_count.write(0);
    }

    #[abi(embed_v0)]
    impl MintBurnXzbImpl of IZeroXBridgeL2<ContractState> {
        fn mint_and_claim_xzb(
            ref self: ContractState,
            proof: Array<felt252>,
            commitment_hash: felt252,
            eth_address: felt252,
            r: u256,
            s: u256,
            y_parity: bool,
        ) {
            // Always check proof length first to avoid out-of-bounds and undefined behavior
            assert(proof.len() >= 4, 'Proof too short');

            // Then verify the signature for security
            let msg_hash: u256 = commitment_hash.into();
            let signature = Signature { r, s, y_parity };
            let eth_address: EthAddress = eth_address.try_into().unwrap();

            verify_eth_signature(msg_hash, signature, eth_address);

            // Now check for duplicate commitment
            assert(
                !self.verified_commitments.read(commitment_hash), 'Commitment already processed',
            );

            let recipient_felt = *proof.at(0);
            let amount = *proof.at(1);
            let nonce = *proof.at(2);
            let time_stamp = *proof.at(3);

            let mint_data = MintData { recipient: recipient_felt, amount, nonce, time_stamp };
            let computed_hash = PoseidonTrait::new().update_with(mint_data).finalize();

            let usd_amount: u256 = amount.into();

            assert(computed_hash == commitment_hash, 'Proof does not match commitment');

            let proof_registry = IProofRegistryDispatcher {
                contract_address: self.proof_registry_address.read(),
            };

            let merkle_root = proof_registry.get_verified_merkle_root(commitment_hash);

            self.verified_commitments.write(commitment_hash, true);
            self.verified_roots.write(commitment_hash, merkle_root);

            let recipient: ContractAddress = recipient_felt.try_into().unwrap();

            let mint_rate = self.get_dynamic_rate();

            let mint_amount = (usd_amount * mint_rate) / PRECISION;

            let token_addr = self.xzb_token.read();
            IXZBERC20Dispatcher { contract_address: token_addr }.mint(recipient, mint_amount);

            self
                .emit(
                    Event::MintEvent(
                        MintEvent { recipient, amount: usd_amount, nonce, commitment_hash },
                    ),
                );
        }


        fn burn_xzb_for_unlock(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();
            let token_addr = self.xzb_token.read();
            let protocol = get_contract_address();

            let mint_rate = self.get_dynamic_rate();
            let burn_amount_usd = (amount * PRECISION) / mint_rate;

            assert(burn_amount_usd > 0, 'Burn amount less than zero');

            // Transfer xZB tokens to the bridge
            IERC20Dispatcher { contract_address: token_addr }
                .transfer_from(caller, protocol, amount);

            // Burn the xZB tokens
            IXZBERC20Dispatcher { contract_address: token_addr }.burn(amount);

            let current_nonce = self.burn_nonce.read(caller);

            let data_to_hash = BurnData {
                caller: caller.try_into().unwrap(),
                amount: burn_amount_usd,
                nonce: current_nonce,
                time_stamp: get_block_timestamp().into(),
            };

            let commitment_hash = PoseidonTrait::new().update_with(data_to_hash).finalize();

            // Append the withdrawal hash to the Merkle tree
            self.append_withdrawal_hash(commitment_hash);

            self.burn_nonce.write(caller, current_nonce + 1);

            self
                .emit(
                    BurnEvent {
                        user: caller,
                        amount: burn_amount_usd,
                        nonce: current_nonce,
                        commitment_hash: commitment_hash,
                    },
                );
        }
    }

    #[abi(embed_v0)]
    impl DynamicRateImpl of IDynamicRate<ContractState> {
        fn get_dynamic_rate(self: @ContractState) -> u256 {
            // Get current total TVL from oracle
            let oracle_dispatcher = IL2OracleDispatcher {
                contract_address: self.oracle_address.read(),
            };
            let total_tvl = oracle_dispatcher.get_total_tvl();

            assert(total_tvl > 0, 'TVL cannot be zero');

            // Get current xZB supply
            let xzb_supply = self.get_current_xzb_supply();

            // Calculate new protocol rate
            let raw_rate = (xzb_supply * PRECISION) / total_tvl;

            let rates = self.rates.read();

            // Apply rate limits
            let min_rate = rates.min_rate;
            let max_rate = rates.max_rate;

            let final_rate = if raw_rate == 0 {
                PRECISION
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
            let xzb_dispatcher = IERC20Dispatcher { contract_address: xzb_token };

            // Get total supply from the token contract
            xzb_dispatcher.total_supply()
        }

        fn set_rates(ref self: ContractState, min_rate: Option<u256>, max_rate: Option<u256>) {
            self.ownable.assert_only_owner();
            let mut current_rates = self.rates.read();

            if let Option::Some(new_min) = min_rate {
                {
                    current_rates.min_rate = new_min;
                }
            }
            if let Option::Some(new_max) = max_rate {
                {
                    current_rates.max_rate = new_max;
                }
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

    #[abi(embed_v0)]
    impl MerkleImpl of IMerkleManager<ContractState> {
        fn get_root_hash(self: @ContractState) -> felt252 {
            let mmr = self.mmr.read();
            mmr.root
        }

        fn get_element_count(self: @ContractState) -> felt252 {
            let mmr = self.mmr.read();
            mmr.last_pos.into()
        }

        fn get_commitment_index(self: @ContractState, commitment_hash: felt252) -> felt252 {
            let index = self.commitment_hash_to_index.read(commitment_hash);
            assert(index != 0, 'Commitment not found');
            index
        }

        fn get_last_peaks(self: @ContractState) -> Array<felt252> {
            let mut peaks = array![];
            let len = self.last_peaks.len();
            for i in 0..len {
                let peak = self.last_peaks.at(i).read();
                if peak != 0 { // Only include non-zero peaks
                    peaks.append(peak);
                }
            }
            peaks
        }

        fn get_leaves_count(self: @ContractState) -> felt252 {
            self.leaves_count.read()
        }

        fn verify_proof(
            self: @ContractState,
            index: usize,
            commitment_hash: felt252,
            peaks: Array<felt252>,
            proof: Array<felt252>,
        ) -> Result<bool, felt252> {
            let mmr = self.mmr.read();
            MMRTrait::verify_proof(@mmr, index, commitment_hash, peaks.span(), proof.span())
        }
    }

    #[generate_trait]
    impl InternalFunctions of InternalFunctionsTrait {
        fn append_withdrawal_hash(ref self: ContractState, commitment_hash: felt252) {
            let mut mmr = self.mmr.read();
            let last_peaks = self.get_last_peaks();
            let mut leaves_count = self.leaves_count.read();

            match MMRTrait::append(ref mmr, commitment_hash, last_peaks.span()) {
                Result::Ok((
                    root_hash, peaks,
                )) => {
                    // Store the new root and last position
                    self.node_index_to_root.write(mmr.last_pos, root_hash);

                    // Calculate the correct MMR leaf index
                    let correct_leaf_index = Self::leaf_count_to_mmr_index(leaves_count) + 1;
                    self.commitment_hash_to_index.write(commitment_hash, correct_leaf_index);

                    println!("Leaf data");
                    println!("{:?}", leaves_count);
                    println!("{:?}", correct_leaf_index);

                    leaves_count += 1;
                    self.leaves_count.write(leaves_count);

                    // Clear and update peaks storage properly
                    self.clear_peaks_storage();
                    for i in 0..peaks.len() {
                        self.last_peaks.push(*peaks.at(i));
                    }

                    self
                        .emit(
                            Event::WithdrawalHashAppended(
                                WithdrawalHashAppended {
                                    index: correct_leaf_index,
                                    commitment_hash: commitment_hash,
                                    root_hash: root_hash,
                                },
                            ),
                        );

                    // Write the updated MMR back to storage
                    self.mmr.write(mmr);
                },
                Result::Err(err) => { panic(array![err]) },
            }
        }

        fn clear_peaks_storage(ref self: ContractState) {
            // Clear all existing peaks from storage
            let current_len = self.last_peaks.len();
            for _i in 0..current_len {
                self.last_peaks.pop();
            }
        }

        fn leaf_count_to_mmr_index(leaf_count: felt252) -> felt252 {
            if leaf_count == 0 {
                return 0;
            }

            // For MMR, the first leaf is at index 1, second at index 2, etc.
            // But we need to account for internal nodes
            let mut internal_nodes: u64 = 0;
            let mut temp: u64 = leaf_count.try_into().unwrap();

            // Count internal nodes created by building the MMR
            let mut level = 1_u64;
            while level < temp {
                internal_nodes += temp / (level * 2);
                level *= 2;
            }

            // The MMR index is leaf position + internal nodes before it
            let mmr_index = leaf_count + internal_nodes.into();
            mmr_index
        }
    }
}
