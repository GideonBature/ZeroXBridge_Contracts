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
    // function testTreeAppends() public {
    //     // Start with an empty peaks array
    //     bytes32[] memory peaks = new bytes32[](0);

    //     // Append the first deposit
    //     // console.log("Adding element 1");
    //     merkleManager.appendDepositHashPublic(bytes32(uint256(1)));
    //     logPeaks();

    //     // Compute the expected node hash for the first element
    //     // hash(index, value)
    //     bytes32 node1 = keccak256(abi.encode(uint256(1), bytes32(uint256(1))));
    //     peaks = StatelessMmrHelpers.newArrWithElem(peaks, node1);

    //     // Verify the proof for the first element
    //     StatelessMmr.verifyProof(
    //         1, // index
    //         bytes32(uint256(1)), // leaf
    //         new bytes32[](0), // proof (empty for first element)
    //         merkleManager.getLastPeaks(), // current peaks
    //         1, // size
    //         merkleManager.getRootHash() // root hash
    //     );

    //     // Append the second deposit
    //     // console.log("Adding element 2");
    //     merkleManager.appendDepositHashPublic(bytes32(uint256(2)));
    //     logPeaks();

    //     // Prepare proof for the second element
    //     bytes32[] memory proof = new bytes32[](0);
    //     proof = StatelessMmrHelpers.newArrWithElem(proof, node1);

    //     // Verify the proof for the second element
    //     StatelessMmr.verifyProof(
    //         2, // index
    //         bytes32(uint256(2)), // leaf
    //         proof, // proof (includes node1)
    //         merkleManager.getLastPeaks(), // current peaks
    //         3, // size
    //         merkleManager.getRootHash() // root hash
    //     );

    //     // Verify previous element with new peaks and root hash
    //     bytes32[] memory proof2 = new bytes32[](0);
    //     // hash(index, value)
    //     bytes32 node2 = keccak256(abi.encode(uint256(2), bytes32(uint256(2))));
    //     proof2 = StatelessMmrHelpers.newArrWithElem(proof2, node2);

    //     StatelessMmr.verifyProof(
    //         1, // index
    //         bytes32(uint256(1)), // leaf
    //         proof2, // proof2 (includes node2) hash of neighbouring nodes
    //         merkleManager.getLastPeaks(), // current peaks
    //         3, // size
    //         merkleManager.getRootHash() // root hash
    //     );
    // }

    function testAppendAndVerifyLeaves() public {
        uint256 last_element_idx;
        bytes32 root_hash;

        for (uint256 i = 1; i <= 10; i++) {
            bytes32 leaf = bytes32(0);
            console.log("Adding element", i);
            console.logBytes32(leaf);
            // Append to MMR
            merkleManager.appendDepositHashPublic(leaf);

            uint256 leaves = i;
            last_element_idx = merkleManager.getElementsCount();
            uint256 leaf_element_index = merkleManager.getCommitmentIndex(leaf);
            root_hash = merkleManager.getRootHash();

            console.log("leaves_count:", leaves);
            console.log("elements_count:", last_element_idx);
            console.log("element_index:", leaf_element_index);
            console.logBytes32(root_hash);
        }
        console.log("Final root");
        // Log current root
        last_element_idx = merkleManager.getElementsCount();
        root_hash = merkleManager.getRootHash();
        console.log("elements_count:", last_element_idx);
        console.logBytes32(root_hash);
    }

    /// @notice Test that verifies correct MMR indices are stored for commitments
    function testCorrectMMRIndicesStored() public {
        // Expected MMR indices for first 6 leaves according to MMR structure
        // Leaf 0 -> MMR index 1
        // Leaf 1 -> MMR index 2
        // Leaf 2 -> MMR index 4 (index 3 is internal node)
        // Leaf 3 -> MMR index 5
        // Leaf 4 -> MMR index 8 (indices 6,7 are internal nodes)
        // Leaf 5 -> MMR index 9
        uint256[] memory expectedIndices = new uint256[](10);
        expectedIndices[0] = 1;
        expectedIndices[1] = 2;
        expectedIndices[2] = 4;
        expectedIndices[3] = 5;
        expectedIndices[4] = 8;
        expectedIndices[5] = 9;
        expectedIndices[6] = 11;
        expectedIndices[7] = 12;
        expectedIndices[8] = 16;
        expectedIndices[9] = 17;

        bytes32[] memory commitments = new bytes32[](10);

        // Add leaves one by one and verify stored indices
        for (uint256 i = 0; i < 10; i++) {
            commitments[i] = keccak256(abi.encode("commitment", i));
            merkleManager.appendDepositHashPublic(commitments[i]);

            uint256 storedIndex = merkleManager.getCommitmentIndex(commitments[i]);

            assertEq(
                storedIndex, expectedIndices[i], string(abi.encodePacked("Wrong MMR index for leaf ", vm.toString(i)))
            );
        }
    }

    /// @notice Test batch append with correct MMR index assignment
    function testBatchAppendCorrectIndices() public {
        bytes32[] memory batchCommitments = new bytes32[](4);
        for (uint256 i = 0; i < 4; i++) {
            batchCommitments[i] = keccak256(abi.encode("batch", i));
        }

        // Expected indices for batch: 0, 1, 3, 4
        uint256[] memory expectedBatchIndices = new uint256[](4);
        expectedBatchIndices[0] = 1;
        expectedBatchIndices[1] = 2;
        expectedBatchIndices[2] = 4;
        expectedBatchIndices[3] = 5;

        merkleManager.multiAppendDepositHashPublic(batchCommitments);

        for (uint256 i = 0; i < 4; i++) {
            uint256 storedIndex = merkleManager.getCommitmentIndex(batchCommitments[i]);
            // console.log("Batch leaf", i, "stored at MMR index:", storedIndex);

            assertEq(storedIndex, expectedBatchIndices[i], "Wrong MMR index in batch append");
        }
    }

    /// @notice Test edge case: first leaf gets index 1
    function testFirstLeafIndexZero() public {
        bytes32 firstCommitment = keccak256("first");
        merkleManager.appendDepositHashPublic(firstCommitment);

        uint256 index = merkleManager.getCommitmentIndex(firstCommitment);
        assertEq(index, 1, "First leaf must have index 1");
    }

    /// @notice Test mixed sequential and batch appends maintain correct indices
    function testMixedAppendMaintainsCorrectIndices() public {
        // Add 2 sequential
        bytes32 seq1 = keccak256("seq1");
        bytes32 seq2 = keccak256("seq2");
        merkleManager.appendDepositHashPublic(seq1);
        merkleManager.appendDepositHashPublic(seq2);

        // Add 2 in batch
        bytes32[] memory batch = new bytes32[](2);
        batch[0] = keccak256("batch1");
        batch[1] = keccak256("batch2");
        merkleManager.multiAppendDepositHashPublic(batch);

        // Verify indices: 1, 2, 4, 5
        assertEq(merkleManager.getCommitmentIndex(seq1), 1, "seq1 wrong index");
        assertEq(merkleManager.getCommitmentIndex(seq2), 2, "seq2 wrong index");
        assertEq(merkleManager.getCommitmentIndex(batch[0]), 4, "batch1 wrong index");
        assertEq(merkleManager.getCommitmentIndex(batch[1]), 5, "batch2 wrong index");

        // console.log(" Mixed append maintains correct MMR indices");
    }

    /// @notice Test that uncommitted hashes return index 1 (default)
    function testUncommittedHashReturnsZero() public {
        bytes32 nonExistentHash = keccak256("doesnotexist");
        uint256 index = merkleManager.getCommitmentIndex(nonExistentHash);
        assertEq(index, 0, "Non-existent hash should return 0");

        // Add one commitment to make sure index 1 is now taken
        bytes32 realCommitment = keccak256("real");
        merkleManager.appendDepositHashPublic(realCommitment);

        // Non-existent should still return 0 (this is a limitation to be aware of)
        uint256 stillZero = merkleManager.getCommitmentIndex(nonExistentHash);
        assertEq(stillZero, 0, "Non-existent hash still returns 0 after commits");

        // console.log(" Note: Non-existent hashes return 0, same as first valid commitment");
    }

    /// @notice Logs the current peaks of the Merkle tree
    function logPeaks() internal view {
        bytes32[] memory peaks = merkleManager.getLastPeaks();
        // console.log("Current Peaks:");
        for (uint256 i = 0; i < peaks.length; i++) {
            // console.logBytes32(peaks[i]);
        }
    }
}
