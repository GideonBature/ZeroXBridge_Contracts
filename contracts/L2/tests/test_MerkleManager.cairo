use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::{ContractAddress};
use l2::mocks::MockMerkleManager::{IMockMerkleManagerDispatcher, IMockMerkleManagerDispatcherTrait};
use cairo_lib::hashing::poseidon::PoseidonHasher;

// Helper functions
fn deploy_merkle_manager() -> ContractAddress {
    let contract_class = declare("MockMerkleManager").unwrap().contract_class();
    let mut calldata = array![];
    let (contract_address, _) = contract_class.deploy(@calldata).unwrap();
    contract_address
}

fn err1() -> felt252 {
    'Invalid peaks count'
}

fn err2() -> felt252 {
    'Invalid peaks'
}

fn leaf_one() -> felt252 {
    PoseidonHasher::hash_single(1)
}

fn leaf_two() -> felt252 {
    PoseidonHasher::hash_single(2)
}

fn leaf_three() -> felt252 {
    PoseidonHasher::hash_single(3)
}

fn leaf_four() -> felt252 {
    PoseidonHasher::hash_single(4)
}

#[test]
fn test_append_one_leaf() {
    let contract_address = deploy_merkle_manager();
    let merkle_manager = IMockMerkleManagerDispatcher { contract_address };

    merkle_manager.append_withdrawal_hash(leaf_one());

    let last_peaks = merkle_manager.get_last_peaks();

    // Check peaks
    assert(last_peaks.len() == 1, 'Last peaks should not be empty');
    assert(last_peaks[0] != @0, 'First peak should not be zero');

    // Check root hash
    let root_hash = merkle_manager.get_root_hash();
    assert(root_hash != 0, 'Root hash should not be zero');

    // Check element count
    let element_count = merkle_manager.get_element_count();
    assert(element_count == 1, 'Element count should be 1');

    // Check leaves count
    let leaves_count = merkle_manager.get_leaves_count();
    assert(leaves_count == 1, 'Leaves count should be 1');

    println!("{:?}", last_peaks);
    println!("Root hash: {}", root_hash);
    println!("Element count: {}", element_count);
}


#[test]
fn test_append_two_leaves() {
    let contract_address = deploy_merkle_manager();
    let merkle_manager = IMockMerkleManagerDispatcher { contract_address };

    merkle_manager.append_withdrawal_hash(leaf_one());

    merkle_manager.append_withdrawal_hash(leaf_two());

    let last_peaks = merkle_manager.get_last_peaks();

    // Check peaks
    assert(last_peaks.len() == 1, 'Last peaks should not be empty');
    assert(last_peaks[0] != @0, 'First peak should not be zero');

    // Check root hash
    let root_hash = merkle_manager.get_root_hash();
    assert(root_hash != 0, 'Root hash should not be zero');

    // Check element count
    let element_count = merkle_manager.get_element_count();
    assert(element_count == 3, 'count should be 3 for 2 leaves');

    // Check leaves count
    let leaves_count = merkle_manager.get_leaves_count();
    assert(leaves_count == 2, 'Leaves count should be 2');
}


#[test]
fn test_append_three_leaves() {
    let contract_address = deploy_merkle_manager();
    let merkle_manager = IMockMerkleManagerDispatcher { contract_address };

    merkle_manager.append_withdrawal_hash(leaf_one());

    merkle_manager.append_withdrawal_hash(leaf_two());

    merkle_manager.append_withdrawal_hash(leaf_three());

    let last_peaks = merkle_manager.get_last_peaks();

    // Check peaks
    assert(last_peaks.len() == 2, 'Last peaks should not be empty');
    assert(last_peaks[0] != @0, 'First peak should not be zero');

    // Check root hash
    let root_hash = merkle_manager.get_root_hash();
    assert(root_hash != 0, 'Root hash should not be zero');

    // Check element count
    let element_count = merkle_manager.get_element_count();
    assert(element_count == 4, 'count should be 4 for 3 leaves');

    // Check leaves count
    let leaves_count = merkle_manager.get_leaves_count();
    assert(leaves_count == 3, 'Leaves count should be 3');
}

#[test]
fn test_append_four_leaves() {
    let contract_address = deploy_merkle_manager();
    let merkle_manager = IMockMerkleManagerDispatcher { contract_address };

    merkle_manager.append_withdrawal_hash(leaf_one());

    merkle_manager.append_withdrawal_hash(leaf_two());

    merkle_manager.append_withdrawal_hash(leaf_three());

    merkle_manager.append_withdrawal_hash(leaf_four());

    let last_peaks = merkle_manager.get_last_peaks();

    // Check peaks
    assert(last_peaks.len() == 1, 'Last peaks should not be empty');
    assert(last_peaks[0] != @0, 'First peak should not be zero');

    // Check root hash
    let root_hash = merkle_manager.get_root_hash();
    assert(root_hash != 0, 'Root hash should not be zero');

    // Check element count
    let element_count = merkle_manager.get_element_count();
    assert(element_count == 7, 'count should be 7 for 4 leaves');

    // Check leaves count
    let leaves_count = merkle_manager.get_leaves_count();
    assert(leaves_count == 4, 'Leaves count should be 4');
}


#[test]
fn test_verify_proof_one_leaf() {
    let contract_address = deploy_merkle_manager();
    let merkle_manager = IMockMerkleManagerDispatcher { contract_address };

    merkle_manager.append_withdrawal_hash(leaf_one());

    let peaks = array![leaf_one()];

    let res = merkle_manager
        .verify_proof(1, // index
        leaf_one(), // commitment_hash
        peaks, // peaks
        array![] // proof
        );

    assert(res.unwrap(), 'Proof should be valid');

    let last_peaks = merkle_manager.get_last_peaks();

    // Check peaks
    assert(last_peaks.len() == 1, 'Last peaks should not be empty');
    assert(last_peaks[0] != @0, 'First peak should not be zero');

    // Check root hash
    let root_hash = merkle_manager.get_root_hash();
    assert(root_hash != 0, 'Root hash should not be zero');

    // Check element count
    let element_count = merkle_manager.get_element_count();
    assert(element_count == 1, 'Element count should be 1');

    // Check leaves count
    let leaves_count = merkle_manager.get_leaves_count();
    assert(leaves_count == 1, 'Leaves count should be 1');

    println!("Leaf {:?}", leaf_one());
    println!("Leaf Index: 1");
    println!("Peaks {:?}", last_peaks);
    println!("Root hash: {}", root_hash);

    let peak1 = 3085182978037364507644541379307921604860861694664657935759708330416374536741;
    let peaks1 = array![peak1];

    let res = merkle_manager
        .verify_proof(
            1, // index
            3085182978037364507644541379307921604860861694664657935759708330416374536741, // commitment_hash
            peaks1, // peaks
            array![] // proof
        );

    assert(res.unwrap(), 'Proof should be valid');
}


#[test]
fn test_verify_proof_two_leaves() {
    let contract_address = deploy_merkle_manager();
    let merkle_manager = IMockMerkleManagerDispatcher { contract_address };

    merkle_manager.append_withdrawal_hash(leaf_one());
    merkle_manager.append_withdrawal_hash(leaf_two());

    let peaks = array![PoseidonHasher::hash_double(leaf_one(), leaf_two())];

    let proof = array![leaf_one()];

    let res = merkle_manager
        .verify_proof(2, // index
        leaf_two(), // commitment_hash
        peaks, // peaks
        proof // proof
        );

    assert(res.unwrap(), 'Proof should be valid');
}


#[test]
fn test_verify_proof_three_leaves() {
    let contract_address = deploy_merkle_manager();
    let merkle_manager = IMockMerkleManagerDispatcher { contract_address };

    merkle_manager.append_withdrawal_hash(leaf_one());
    merkle_manager.append_withdrawal_hash(leaf_two());
    merkle_manager.append_withdrawal_hash(leaf_three());

    let peaks = array![PoseidonHasher::hash_double(leaf_one(), leaf_two()), leaf_three()];

    let proof = array![];

    let res = merkle_manager
        .verify_proof(4, // index
        leaf_three(), // commitment_hash
        peaks, // peaks
        proof // proof
        );

    assert(res.unwrap(), 'Proof should be valid');
}
