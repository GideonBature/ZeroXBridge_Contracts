#[starknet::interface]
pub trait IMockMerkleManager<TContractState> {
    fn append_withdrawal_hash(ref self: TContractState, commitment_hash: felt252);
    fn get_root_hash(self: @TContractState) -> felt252;
    fn get_element_count(self: @TContractState) -> felt252;
    fn get_commitment_index(self: @TContractState, commitment_hash: felt252) -> felt252;
    fn get_last_peaks(self: @TContractState) -> Array<felt252>;
    fn get_leaves_count(self: @TContractState) -> felt252;
    fn verify_proof(
        self: @TContractState,
        index: usize,
        commitment_hash: felt252,
        peaks: Array<felt252>,
        proof: Array<felt252>,
    ) -> Result<bool, felt252>;
}

#[starknet::contract]
pub mod MockMerkleManager {
    use core::array::ArrayTrait;
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess, Map, StorageMapReadAccess,
        StorageMapWriteAccess, Vec, VecTrait, MutableVecTrait,
    };

    use super::IMockMerkleManager;

    use cairo_lib::data_structures::mmr::mmr::MMR;
    use cairo_lib::data_structures::mmr::mmr::MMRTrait;

    #[storage]
    struct Storage {
        mmr: MMR,
        node_index_to_root: Map<usize, felt252>,
        commitment_hash_to_index: Map<felt252, felt252>,
        last_peaks: Vec<felt252>,
        leaves_count: felt252,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        WithdrawalHashAppended: WithdrawalHashAppended,
    }

    #[derive(Drop, Debug, starknet::Event)]
    pub struct WithdrawalHashAppended {
        #[key]
        pub index: felt252,
        pub commitment_hash: felt252,
        pub root_hash: felt252,
        pub elements_count: felt252,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {
        let mmr: MMR = Default::default();
        self.mmr.write(mmr);
    }

    #[abi(embed_v0)]
    impl MockManagerImpl of IMockMerkleManager<ContractState> {
        fn append_withdrawal_hash(ref self: ContractState, commitment_hash: felt252) {
            let mut mmr = self.mmr.read();
            let prev_peaks = self.get_last_peaks().span();
            let mut leaves_count = self.leaves_count.read();

            match mmr.append(commitment_hash, prev_peaks) {
                Result::Ok((
                    root_hash, peaks,
                )) => {
                    self.node_index_to_root.write(mmr.last_pos, root_hash);
                    leaves_count += 1;

                    self.commitment_hash_to_index.write(commitment_hash, leaves_count);
                    self.leaves_count.write(leaves_count);

                    let prev_peaks_len = prev_peaks.len();
                    let peaks_len = peaks.len();

                    if prev_peaks_len > peaks_len {
                        // Overwrite up to peaks_len, then set the rest to 0
                        for i in 0..peaks_len {
                            let mut storage_ptr = self.last_peaks.at(i.into());
                            storage_ptr.write(*peaks.at(i));
                        };
                        for i in peaks_len..prev_peaks_len {
                            let mut storage_ptr = self.last_peaks.at(i.into());
                            storage_ptr.write(0);
                        };
                    } else {
                        // Overwrite up to prev_peaks_len, then append the rest
                        for i in 0..prev_peaks_len {
                            let mut storage_ptr = self.last_peaks.at(i.into());
                            storage_ptr.write(*peaks.at(i));
                        };
                        for i in prev_peaks_len..peaks_len {
                            self.last_peaks.append().write(*peaks.at(i));
                        };
                    }

                    self.mmr.write(mmr);
                },
                Result::Err(err) => { panic(array![err]) },
            }
        }
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
            for i in 0..self.last_peaks.len() {
                let peak = self.last_peaks.at(i).read();
                if (peak != 0) {
                    peaks.append(peak)
                }
            };
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
            mmr.verify_proof(index, commitment_hash, peaks.span(), proof.span())
        }
    }
}
