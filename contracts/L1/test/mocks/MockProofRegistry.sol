// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IProofRegistry} from "../../src/ProofRegistry.sol";

struct VerifiedWithdrawalRoot {
    bool isVerified;
    uint256 merkleRoot;
}

contract MockProofRegistry is IProofRegistry {
    bool public shouldVerifySucceed = true;

    mapping(uint256 => VerifiedWithdrawalRoot) public verifiedWithdrawalRoots;

    event WithdrawalCommitmentVerified(uint256 withdrawalCommitmentHash, uint256 merkleRoot);

    function setShouldVerifySucceed(bool _shouldSucceed) external {
        shouldVerifySucceed = _shouldSucceed;
    }

    function getVerifiedMerkleRoot(uint256 withdrawalCommitmentHash) public view returns (uint256) {
        require(verifiedWithdrawalRoots[withdrawalCommitmentHash].isVerified, "Withdrawal proof not found");
        return verifiedWithdrawalRoots[withdrawalCommitmentHash].merkleRoot;
    }

    function checkProof(uint256 withdrawalCommitmentHash, uint256 merkleRoot) public view returns (bool) {
        withdrawalCommitmentHash;
        merkleRoot;
        return shouldVerifySucceed;
    }

    function registerWithdrawalProof(uint256 withdrawalCommitmentHash, uint256 merkleRoot) public {
        bool isValid = checkProof(withdrawalCommitmentHash, merkleRoot);
        require(isValid, "Withdrawal proof not verified");

        verifiedWithdrawalRoots[withdrawalCommitmentHash] =
            VerifiedWithdrawalRoot({isVerified: true, merkleRoot: merkleRoot});
        emit WithdrawalCommitmentVerified(withdrawalCommitmentHash, merkleRoot);
    }
}
