use integrity::{
    calculate_bootloaded_fact_hash, SHARP_BOOTLOADER_PROGRAM_HASH, VerifierConfiguration,
};

#[starknet::interface]
pub trait IProofRegistry<TContractState> {
    // Get the merkle root of commitment hash if it was verified.
    fn get_verified_merkle_root(self: @TContractState, commitment_hash: felt252) -> felt252;

    // Prove given commitment_hash with proof verified by Integrity.
    fn register_deposit_proof(
        ref self: TContractState, commitment_hash: felt252, merkle_root: felt252,
    );
}

// Calculate fact hash for cairo1 programs bootloaded in cairo0 by Atlantic.
fn calculate_cairo1_fact_hash(
    program_hash: felt252, input: Span<felt252>, output: Span<felt252>,
) -> felt252 {
    let CAIRO1_BOOTLOADER_PROGRAM_HASH =
        0x288ba12915c0c7e91df572cf3ed0c9f391aa673cb247c5a208beaa50b668f09;
    let OUTPUT_CONST = 0x49ee3eba8c1600700ee1b87eb599f16716b0b1022947733551fde4050ca6804;

    let mut bootloader_output = array![
        0x0, OUTPUT_CONST, 0x1, input.len().into() + output.len().into() + 5, program_hash, 0x0,
    ];
    bootloader_output.append(output.len().into());
    for x in output {
        bootloader_output.append(*x);
    };
    bootloader_output.append(input.len().into());
    for x in input {
        bootloader_output.append(*x);
    };

    // All programs sent to Sharp are bootloaded (second time in this case).
    calculate_bootloaded_fact_hash(
        SHARP_BOOTLOADER_PROGRAM_HASH, CAIRO1_BOOTLOADER_PROGRAM_HASH, bootloader_output.span(),
    )
}

const CAIRO1_LAYOUT: felt252 = 'recursive';

// Return Integrity configuration variables for Sharp proofs.
// Layout depends on what built-ins your program uses.
fn get_config(layout: felt252) -> (VerifierConfiguration, u32) {
    // This config depends on prover configuration that was used to generate the proof.
    // If you are proving using custom Stone configuration, you need to adjust those settings.
    // Configuration below is for Sharp proofs with configuration used by Atlantic.
    let config = VerifierConfiguration {
        layout, hasher: 'keccak_160_lsb', stone_version: 'stone6', memory_verification: 'relaxed',
    };
    let SECURITY_BITS = 96;
    (config, SECURITY_BITS)
}

// Calculate fact hash for specific cairo1 program - cairo1-rust-vm/src/lib.cairo
fn get_cairo1_fact_hash(commitment_hash: felt252, merkle_root: felt252) -> felt252 {
    // Cairo1 program hash is present in Atlantic query metadata at **"child_program_hash"** key.
    // IMPORTANT: In cairo1 query, program_hash refers to the program hash of the bootloader which
    //            is constant, your actual program hash is present in its output which is shown
    //            at "child_program_hash" key.
    let CAIRO1_PROGRAM_HASH = 0x1b2f325bf7c611b8cf643eed5451102df4128cb17d621dad15e2cdb9d3e3afb;

    calculate_cairo1_fact_hash(
        CAIRO1_PROGRAM_HASH, [commitment_hash.into()].span(), [merkle_root.into()].span(),
    )
}

#[starknet::contract]
mod ProofRegistry {
    use super::*;
    use starknet::storage::{
        Map, StoragePointerReadAccess, StoragePointerWriteAccess, StoragePathEntry,
    };
    use integrity::{Integrity, IntegrityWithConfig};

    #[storage]
    struct Storage {
        verified_deposit_roots: Map<felt252, Option<felt252>>,
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
    impl ProofRegistryImpl of IProofRegistry<ContractState> {
        fn get_verified_merkle_root(self: @ContractState, commitment_hash: felt252) -> felt252 {
            self.verified_deposit_roots.entry(commitment_hash).read().expect('Not found')
        }

        fn register_deposit_proof(
            ref self: ContractState, commitment_hash: felt252, merkle_root: felt252,
        ) {
            let (config, security_bits) = get_config(CAIRO1_LAYOUT);

            let fact_hash = get_cairo1_fact_hash(commitment_hash, merkle_root);

            // Integrity package provides functions for easier checking if given fact is verified.
            let integrity = Integrity::new();
            let is_valid = integrity
                .with_config(config, security_bits)
                .is_fact_hash_valid(fact_hash);

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
