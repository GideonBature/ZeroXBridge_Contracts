use snforge_std::{
    declare, spy_events, ContractClassTrait, DeclareResultTrait, EventSpyAssertionsTrait, CheatSpan,
    cheat_caller_address,
};

use l2::core::ZeroXBridgeL2::{
    IZeroXBridgeL2Dispatcher, IZeroXBridgeL2DispatcherTrait, IDynamicRateDispatcher,
    IDynamicRateDispatcherTrait,
};
use l2::core::ZeroXBridgeL2::ZeroXBridgeL2::{Event, BurnEvent, BurnData, MintEvent, MintData};
use l2::core::xZBERC20::{
    IMintableDispatcher, IMintableDispatcherTrait, IManagerDispatcher, IManagerDispatcherTrait,
};
use l2::core::ProofRegistry::{IProofRegistryDispatcher, IProofRegistryDispatcherTrait};
use l2::core::L2Oracle::{IL2OracleDispatcher, IL2OracleDispatcherTrait};
use l2::mocks::MockRegistry::{IMockRegistryDispatcher, IMockRegistryDispatcherTrait};
use openzeppelin_token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
use starknet::{ContractAddress, contract_address_const, get_block_timestamp};
use core::integer::u256;
use core::pedersen::PedersenTrait;
use core::hash::{HashStateTrait, HashStateExTrait};
use openzeppelin_utils::serde::SerializedAppend;

const MIN_RATE: u256 = 100_000_000_000_000_000; // 0.1 (with PRECISION)
const MAX_RATE: u256 = 5_000_000_000_000_000_000; // 5.0 (with PRECISION)
const PRECISION: u256 = 1_000_000_000_000_000_000; // 18 decimals for precision

fn alice() -> ContractAddress {
    contract_address_const::<'alice'>()
}

// Helper functions to get test addresses
fn owner() -> ContractAddress {
    contract_address_const::<'owner'>()
}


fn time_stamp() -> felt252 {
    00000000000000000000011111111111111111111122222222222222222222222222222222
}

fn merkle_root() -> felt252 {
    00000000000000000000011111111111111111111122222222222222222222222222222222
}

fn non_owner() -> ContractAddress {
    contract_address_const::<'non_owner'>()
}

fn nonce() -> felt252 {
    0
}

fn deploy_xzb() -> ContractAddress {
    let contract_class = declare("xZBERC20").unwrap().contract_class();
    let mut calldata = array![];
    calldata.append_serde(owner());
    let (contract_address, _) = contract_class.deploy(@calldata).unwrap();
    contract_address
}

fn deploy_registry() -> ContractAddress {
    let contract_class = declare("MockProofRegistry").unwrap().contract_class();
    let mut calldata = array![];
    let (contract_address, _) = contract_class.deploy(@calldata).unwrap();
    contract_address
}

fn deploy_oracle() -> ContractAddress {
    let contract_class = declare("MockL2Oracle").unwrap().contract_class();
    let mut calldata = array![];
    calldata.append_serde(owner());
    let (contract_address, _) = contract_class.deploy(@calldata).unwrap();
    contract_address
}

fn deploy_bridge(
    xzb_addr: ContractAddress, proof_registry: ContractAddress, oracle_address: ContractAddress,
) -> ContractAddress {
    let contract_class = declare("ZeroXBridgeL2").unwrap().contract_class();
    let mut calldata = array![];
    calldata.append_serde(owner());
    calldata.append_serde(xzb_addr);
    calldata.append_serde(proof_registry);
    calldata.append_serde(oracle_address);
    calldata.append_serde(MIN_RATE);
    calldata.append_serde(MAX_RATE);
    let (contract_address, _) = contract_class.deploy(@calldata).unwrap();

    // Give Bridge minter role
    cheat_caller_address(xzb_addr, owner(), CheatSpan::TargetCalls(1));
    IManagerDispatcher { contract_address: xzb_addr }.set_bridge_address(contract_address);

    contract_address
}

#[test]
fn test_burn_xzb_for_unlock_happy_path() {
    let token_addr = deploy_xzb();
    let proof_registry_addr = deploy_registry();
    let oracle_addr = deploy_oracle();
    let bridge_addr = deploy_bridge(token_addr, proof_registry_addr, oracle_addr);

    let alice_addr = alice();
    let owner_addr = owner();

    let burn_amount = 20_000_u256 * PRECISION;

    cheat_caller_address(token_addr, owner_addr, CheatSpan::TargetCalls(1));
    IMintableDispatcher { contract_address: token_addr }.mint(owner_addr, 80_000_u256 * PRECISION);

    // Mint tokens to Alice.
    cheat_caller_address(token_addr, owner_addr, CheatSpan::TargetCalls(2));
    IMintableDispatcher { contract_address: token_addr }.mint(alice_addr, burn_amount);

    let balance = IERC20Dispatcher { contract_address: token_addr }.balance_of(alice_addr);
    assert!(balance == burn_amount, "Bridge balance not updated");

    // Set total TVL in the oracle as 100,000 USD.
    cheat_caller_address(oracle_addr, owner_addr, CheatSpan::TargetCalls(1));
    IL2OracleDispatcher { contract_address: oracle_addr }.set_total_tvl(100_000_u256 * PRECISION);

    // Get the dynamic rate from the bridge
    let rate = IDynamicRateDispatcher { contract_address: bridge_addr }.get_dynamic_rate();

    // rate should be 1 usd per xZB token since TVL is 100,000 USD
    assert!(rate == 1 * PRECISION, "Dynamic rate not set correctly");

    // approve the bridget to spend Alice's tokens.
    cheat_caller_address(token_addr, alice_addr, CheatSpan::TargetCalls(1));
    IERC20Dispatcher { contract_address: token_addr }.approve(bridge_addr, burn_amount);

    // Burn tokens through bridge with alice as caller.
    let mut spy = spy_events();
    cheat_caller_address(bridge_addr, alice_addr, CheatSpan::TargetCalls(1));
    IZeroXBridgeL2Dispatcher { contract_address: bridge_addr }.burn_xzb_for_unlock(burn_amount);

    let burn_amount_usd = (burn_amount * PRECISION) / rate;

    // Compute expected commitment hash.
    let data_to_hash = BurnData {
        caller: alice_addr.try_into().unwrap(),
        amount: burn_amount_usd,
        nonce: 0,
        time_stamp: get_block_timestamp().into(),
    };

    let expected_hash = PedersenTrait::new(0).update_with(data_to_hash).finalize();

    // Build expected event value.
    let expected_event = (
        bridge_addr,
        Event::BurnEvent(
            BurnEvent {
                user: alice_addr, amount: burn_amount_usd, nonce: 0, commitment_hash: expected_hash,
            },
        ),
    );

    // Assert that the expected event was emitted.
    spy.assert_emitted(@array![expected_event]);
}


#[test]
fn test_burn_xzb_updates_balance() {
    let token_addr = deploy_xzb();
    let proof_registry_addr = deploy_registry();
    let oracle_addr = deploy_oracle();
    let bridge_addr = deploy_bridge(token_addr, proof_registry_addr, oracle_addr);

    let alice_addr = alice();
    let owner_addr = owner();

    let burn_amount = 20_000_u256 * PRECISION;

    let erc20 = IERC20Dispatcher { contract_address: token_addr };

    cheat_caller_address(token_addr, owner_addr, CheatSpan::TargetCalls(1));
    IMintableDispatcher { contract_address: token_addr }.mint(owner_addr, 80_000_u256 * PRECISION);

    // Mint tokens to Alice.
    cheat_caller_address(token_addr, owner_addr, CheatSpan::TargetCalls(2));
    IMintableDispatcher { contract_address: token_addr }.mint(alice_addr, burn_amount);

    let initial_balance = erc20.balance_of(alice_addr);
    assert!(initial_balance == burn_amount, "Bridge balance not updated");

    // Set total TVL in the oracle as 100,000 USD.
    cheat_caller_address(oracle_addr, owner_addr, CheatSpan::TargetCalls(1));
    IL2OracleDispatcher { contract_address: oracle_addr }.set_total_tvl(100_000_u256 * PRECISION);

    // Get the dynamic rate from the bridge
    let rate = IDynamicRateDispatcher { contract_address: bridge_addr }.get_dynamic_rate();

    // rate should be 1 usd per xZB token since TVL is 100,000 USD
    assert!(rate == 1 * PRECISION, "Dynamic rate not set correctly");

    // approve the bridget to spend Alice's tokens.
    cheat_caller_address(token_addr, alice_addr, CheatSpan::TargetCalls(1));
    erc20.approve(bridge_addr, burn_amount);

    // Burn tokens through bridge with alice as caller
    cheat_caller_address(bridge_addr, alice_addr, CheatSpan::TargetCalls(1));
    IZeroXBridgeL2Dispatcher { contract_address: bridge_addr }.burn_xzb_for_unlock(burn_amount);

    // Check balance after burn.
    let final_balance = erc20.balance_of(alice_addr);
    assert(initial_balance - final_balance == burn_amount, 'Token balance not reduced');
}

#[test]
#[should_panic(expected: 'ERC20: insufficient balance')]
fn test_burn_xzb_insufficient_balance() {
    // Test that burning more tokens than available triggers an error.
    let token_addr = deploy_xzb();
    let proof_registry_addr = deploy_registry();
    let oracle_addr = deploy_oracle();
    let bridge_addr = deploy_bridge(token_addr, proof_registry_addr, oracle_addr);

    let alice_addr = alice();
    let owner_addr = owner();

    // Mint fewer tokens than we attempt to burn.
    cheat_caller_address(token_addr, owner_addr, CheatSpan::TargetCalls(1));
    IMintableDispatcher { contract_address: token_addr }.mint(alice_addr, 300_u256 * PRECISION);

    // Set total TVL in the oracle as 100,000 USD.
    cheat_caller_address(oracle_addr, owner_addr, CheatSpan::TargetCalls(1));
    IL2OracleDispatcher { contract_address: oracle_addr }.set_total_tvl(300_u256 * PRECISION);

    let burn_amount = 500_u256 * PRECISION; // Attempt to burn 500 tokens

    // approve the bridget to spend Alice's tokens.
    cheat_caller_address(token_addr, alice_addr, CheatSpan::TargetCalls(1));
    IERC20Dispatcher { contract_address: token_addr }.approve(bridge_addr, burn_amount);

    // Attempt to burn 500 tokens when balance is only 300.
    cheat_caller_address(bridge_addr, alice_addr, CheatSpan::TargetCalls(1));
    IZeroXBridgeL2Dispatcher { contract_address: bridge_addr }.burn_xzb_for_unlock(burn_amount);
}
#[test]
fn test_process_mint_proof_happy_path() {
    // Setup environment
    let token_addr = deploy_xzb();
    let proof_registry_addr = deploy_registry();
    let oracle_addr = deploy_oracle();
    let bridge_addr = deploy_bridge(token_addr, proof_registry_addr, oracle_addr);

    let recipient_addr = alice();
    let owner = owner();

    // Create test data
    let amount: u256 = 10000_u256 * PRECISION; // 10,000 USD

    // Set total TVL in the oracle as 10,000 USD.
    cheat_caller_address(oracle_addr, owner, CheatSpan::TargetCalls(1));
    IL2OracleDispatcher { contract_address: oracle_addr }.set_total_tvl(amount);

    // Create mock proof array (recipient, amount, nonce, block_hash)
    let amount_felt: felt252 = amount.try_into().unwrap();

    let mut proof: Array<felt252> = array![];
    proof.append(recipient_addr.into());
    proof.append(amount_felt);
    proof.append(nonce());
    proof.append(time_stamp());

    // Create commitment hash from mint data
    let mint_data = MintData {
        recipient: recipient_addr.into(),
        amount: amount_felt,
        nonce: nonce(),
        time_stamp: time_stamp(),
    };
    let commitment_hash = PedersenTrait::new(0).update_with(mint_data).finalize();

    // Create spy to track events
    let mut spy = spy_events();

    // Mock integrity verification to return true
    // Note: In real tests, you would need to either:
    // 1. Use real integrity verification with valid proofs
    // 2. Mock the integrity dependency more thoroughly
    // For this example, we'll assume integrity verification passes
    // Process the mint proof

    IMockRegistryDispatcher { contract_address: proof_registry_addr }.set_should_succeed(true);
    IProofRegistryDispatcher { contract_address: proof_registry_addr }
        .register_deposit_proof(commitment_hash, merkle_root());

    // cheat_caller_address(token_addr, owner, CheatSpan::TargetCalls(1));
    cheat_caller_address(bridge_addr, owner, CheatSpan::TargetCalls(1));

    // Dummy values for eth_address, r, s, y_parity for test purposes
    let eth_address = 0x767410c1bb448978bd42b984d7de5970bcaf5c43_u256
    .try_into()
    .unwrap();
    let r: u256 = 0x4c8e4fbc1fbb1dece52185e532812c4f7a5f81cf3ee10044320a0d03b62d3e9a;
    let s: u256 = 0x4ac5e5c0c0e8a4871583cc131f35fb49c2b7f60e6a8b84965830658f08f7410c;
    let y_parity: bool = true;

    IZeroXBridgeL2Dispatcher { contract_address: bridge_addr }
        .mint_and_claim_xzb(proof, commitment_hash, eth_address, r, s, y_parity);

    // Build expected event
    let expected_event = (
        bridge_addr,
        Event::MintEvent(
            MintEvent { recipient: recipient_addr, amount, nonce: nonce(), commitment_hash },
        ),
    );
    // Assert event was emitted
    spy.assert_emitted(@array![expected_event]);

    // Verify tokens were minted correctly
    let erc20 = IERC20Dispatcher { contract_address: token_addr };
    let balance = erc20.balance_of(recipient_addr);

    let mint_rate = IDynamicRateDispatcher { contract_address: bridge_addr }.get_dynamic_rate();

    let mint_amount = (amount * mint_rate) / PRECISION;

    assert(balance == mint_amount, 'Tokens not minted correctly');
}

#[test]
#[should_panic(expected: 'Commitment already processed')]
fn test_duplicate_commitment_rejection() {
    // Setup environment
    let token_addr = deploy_xzb();
    let proof_registry_addr = deploy_registry();
    let oracle_addr = deploy_oracle();
    let bridge_addr = deploy_bridge(token_addr, proof_registry_addr, oracle_addr);

    let recipient_addr = alice();
    let owner = owner();

    // Create test data
    let amount: u256 = 10000_u256 * PRECISION; // 10,000 USD

    // Set total TVL in the oracle as 10,000 USD.
    cheat_caller_address(oracle_addr, owner, CheatSpan::TargetCalls(1));
    IL2OracleDispatcher { contract_address: oracle_addr }.set_total_tvl(amount);

    // Create mock proof array (recipient, amount, nonce, block_hash)
    let amount_felt: felt252 = amount.try_into().unwrap();

    let mut proof: Array<felt252> = array![];
    proof.append(recipient_addr.into());
    proof.append(amount_felt);
    proof.append(nonce());
    proof.append(time_stamp());

    // Create commitment hash from mint data
    let mint_data = MintData {
        recipient: recipient_addr.into(),
        amount: amount_felt,
        nonce: nonce(),
        time_stamp: time_stamp(),
    };
    let commitment_hash = PedersenTrait::new(0).update_with(mint_data).finalize();

    IMockRegistryDispatcher { contract_address: proof_registry_addr }.set_should_succeed(true);
    IProofRegistryDispatcher { contract_address: proof_registry_addr }
        .register_deposit_proof(commitment_hash, merkle_root());

    // cheat_caller_address(token_addr, owner, CheatSpan::TargetCalls(1));
    cheat_caller_address(bridge_addr, owner, CheatSpan::TargetCalls(1));

    let eth_address= 0x767410c1bb448978bd42b984d7de5970bcaf5c43_u256
    .try_into()
    .unwrap();
    let r: u256 = 0x4c8e4fbc1fbb1dece52185e532812c4f7a5f81cf3ee10044320a0d03b62d3e9a;
    let s: u256 = 0x4ac5e5c0c0e8a4871583cc131f35fb49c2b7f60e6a8b84965830658f08f7410c;
    let y_parity: bool = true;
    IZeroXBridgeL2Dispatcher { contract_address: bridge_addr }
        .mint_and_claim_xzb(proof.clone(), commitment_hash, eth_address, r, s, y_parity);
    let eth_address: felt252 = 0;
    let r: u256 = 0x1_u256;
    let s: u256 = 0x1_u256;
    let y_parity: bool = true;

    IZeroXBridgeL2Dispatcher { contract_address: bridge_addr }
        .mint_and_claim_xzb(proof, commitment_hash, eth_address, r, s, y_parity);
}

#[test]
#[should_panic(expected: 'Proof too short')]
fn test_insufficient_proof_data() {
    // Setup environment
    let token_addr = deploy_xzb();
    let proof_registry_addr = deploy_registry();
    let oracle_addr = deploy_oracle();
    let bridge_addr = deploy_bridge(token_addr, proof_registry_addr, oracle_addr);

    let owner = owner();
    let recipient_addr = alice();

    // Create an incomplete proof (less than 3 elements)
    let mut proof = array![];
    proof.append(123);
    proof.append(456);
    // Missing third nd 4th element

    // Create test data
    let amount: u256 = 10000_u256 * PRECISION; // 10,000 USD

    // Create mock proof array (recipient, amount, nonce, block_hash)
    let amount_felt: felt252 = amount.try_into().unwrap();

    // Create commitment hash from mint data
    let mint_data = MintData {
        recipient: recipient_addr.into(),
        amount: amount_felt,
        nonce: nonce(),
        time_stamp: time_stamp(),
    };
    let commitment_hash = PedersenTrait::new(0).update_with(mint_data).finalize();

    // cheat_caller_address(token_addr, owner, CheatSpan::TargetCalls(1));
    cheat_caller_address(bridge_addr, owner, CheatSpan::TargetCalls(1));

    // Dummy values for eth_address, r, s, y_parity for test purposes
    let eth_address = 0x767410c1bb448978bd42b984d7de5970bcaf5c43_u256
    .try_into()
    .unwrap();
    let r: u256 = 0x4c8e4fbc1fbb1dece52185e532812c4f7a5f81cf3ee10044320a0d03b62d3e9a;
    let s: u256 = 0x4ac5e5c0c0e8a4871583cc131f35fb49c2b7f60e6a8b84965830658f08f7410c;
    let y_parity: bool = true;

    IZeroXBridgeL2Dispatcher { contract_address: bridge_addr }
        .mint_and_claim_xzb(proof, commitment_hash, eth_address, r, s, y_parity);
}

