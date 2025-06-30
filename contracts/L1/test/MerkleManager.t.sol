// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {MerkleMockManager} from "./mocks/MerkleManagerMock.sol";

import "@soliditymmr/src/lib/StatelessMmr.sol";

/// @title MerkleManagerTest
/// @notice Unit tests for the MerkleManager contract
contract MerkleManagerTest is Test {
    MerkleMockManager public merkleManager;
    address public owner = makeAddr("owner");

    /// @notice Sets up a fresh MerkleManager instance before each test
    function setUp() public {
        vm.startPrank(owner);
        merkleManager = new MerkleMockManager();
        vm.stopPrank();
    }

    /// @notice Tests appending elements to the Merkle tree and verifies the peaks and root hash
    function testTreeAppends() public {
        // Start with an empty peaks array
        bytes32[] memory peaks = new bytes32[](0);

        // Append the first deposit
        console.log("Adding element 1");
        merkleManager.appendDepositHashPublic(bytes32(uint256(1)));
        logPeaks();

        // Compute the expected node hash for the first element
        // hash(index, value)
        bytes32 node1 = keccak256(abi.encode(uint256(1), bytes32(uint256(1))));
        peaks = StatelessMmrHelpers.newArrWithElem(peaks, node1);

        // Verify the proof for the first element
        StatelessMmr.verifyProof(
            1, // index
            bytes32(uint256(1)), // leaf
            new bytes32[](0), // proof (empty for first element)
            merkleManager.getLastPeaks(), // current peaks
            1, // size
            merkleManager.getRootHash() // root hash
        );

        // Append the second deposit
        console.log("Adding element 2");
        merkleManager.appendDepositHashPublic(bytes32(uint256(2)));
        logPeaks();

        // Prepare proof for the second element
        bytes32[] memory proof = new bytes32[](0);
        proof = StatelessMmrHelpers.newArrWithElem(proof, node1);

        // Verify the proof for the second element
        StatelessMmr.verifyProof(
            2, // index
            bytes32(uint256(2)), // leaf
            proof, // proof (includes node1)
            merkleManager.getLastPeaks(), // current peaks
            3, // size
            merkleManager.getRootHash() // root hash
        );

        // Verify previous element with new peaks and root hash
        bytes32[] memory proof2 = new bytes32[](0);
        // hash(index, value)
        bytes32 node2 = keccak256(abi.encode(uint256(2), bytes32(uint256(2))));
        proof2 = StatelessMmrHelpers.newArrWithElem(proof2, node2);

        StatelessMmr.verifyProof(
            1, // index
            bytes32(uint256(1)), // leaf
            proof2, // proof2 (includes node2) hash of neighbouring nodes
            merkleManager.getLastPeaks(), // current peaks
            3, // size
            merkleManager.getRootHash() // root hash
        );
    }

    /// @notice Logs the current peaks of the Merkle tree
    function logPeaks() internal view {
        bytes32[] memory peaks = merkleManager.getLastPeaks();
        console.log("Current Peaks:");
        for (uint256 i = 0; i < peaks.length; i++) {
            console.logBytes32(peaks[i]);
        }
    }
}
