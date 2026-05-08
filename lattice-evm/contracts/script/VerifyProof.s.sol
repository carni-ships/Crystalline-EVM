// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Plonky3NovaVerifier} from "../verifier/Plonky3NovaVerifier.sol";

contract VerifyProofScript {
    uint256 constant FIELD_Q = 8383489;
    uint256 constant MAX_FOLDS = 1000;
    uint256 constant PROOF_MAGIC = 0x504C4F4E4B593350726F6F66000000;

    function _setUint256(bytes memory b, uint256 offset, uint256 value) internal pure {
        assembly {
            mstore(add(add(b, 0x20), offset), value)
        }
    }

    /// @notice Build a proof with the NEW hardened header layout
    /// @dev New layout:
    /// - 0-31: magic (PROOF_MAGIC)
    /// - 32-63: runningU
    /// - 64-95: runningCommW
    /// - 96-127: runningC
    /// - 128-159: runningN (= numFolds)
    /// - 160-191: finalU
    /// - 192-223: finalCommW
    /// - 224-255: numFolds
    /// - 256-287: blockNumber
    /// - 288-319: blockTimestamp
    /// - 320-351: stateRoot
    /// - 352-383: bytecodeRoot
    /// - 384-415: storageRoot
    /// - 416-447: blockHash
    /// - 448-479: txCount
    /// - 480-495: gasUsed
    /// - 496-511: proofId
    /// - 512-527: augProofLen
    /// - 528-539: reserved (0)
    /// - 540-551: numFieldElements
    /// - 552-563: proofVersion (= 1)
    /// - 564-575: reserved (0)
    /// Arrays start at 576: challenges[1000], commWOld[1000], commWcccs[1000]
    function buildHardenedProof3Folds() internal view returns (bytes memory) {
        bytes memory proof = new bytes(96512);

        // Header (total 512 bytes = 16 uint256 slots)
        _setUint256(proof, 0, PROOF_MAGIC);         // 0: magic
        _setUint256(proof, 32, 0);                   // 1: runningU
        _setUint256(proof, 64, 0);                  // 2: runningCommW
        _setUint256(proof, 96, 0);                  // 3: runningC
        _setUint256(proof, 128, 3);                 // 4: runningN = numFolds
        _setUint256(proof, 160, 0);                 // 5: finalU
        _setUint256(proof, 192, 27);                // 6: finalCommW
        _setUint256(proof, 224, 3);                 // 7: numFolds
        _setUint256(proof, 256, 1);                 // 8: blockNumber
        _setUint256(proof, 288, block.timestamp);  // 9: blockTimestamp
        _setUint256(proof, 320, 0);                 // 10: stateRoot
        _setUint256(proof, 352, 0);                 // 11: bytecodeRoot
        _setUint256(proof, 384, 0);                 // 12: storageRoot
        _setUint256(proof, 416, 0x00000000000000000000000000000000000000000000000000000000DEADBEEF); // 13: blockHash
        _setUint256(proof, 448, 1);                 // 14: txCount
        _setUint256(proof, 480, 21000);             // 15: gasUsed
        _setUint256(proof, 496, 1);                 // 16: proofId (offset 496 = 15*32+16)
        _setUint256(proof, 512, 1);                 // 17: augProofLen
        _setUint256(proof, 528, 0);                // 18: reserved
        _setUint256(proof, 540, 64);                // 19: numFieldElements
        _setUint256(proof, 552, 1);                // 20: proofVersion
        _setUint256(proof, 564, 0);                // 21: reserved

        // Arrays at offset 576 (512 + 64 reserved)
        // challenges[0..2] at 576, 608, 640
        _setUint256(proof, 576, 2);                 // r[0] = 2
        _setUint256(proof, 608, 3);                // r[1] = 3
        _setUint256(proof, 640, 4);                // r[2] = 4

        // commWOld[0..2] at 576 + 1000*32 = 32576
        // Must match runningCommW from previous fold for chain continuity
        _setUint256(proof, 32576, 0);               // commWOld[0] = 0 (initial)
        _setUint256(proof, 32608, 0);               // commWOld[1] = 0 (running from fold 0: 2*0+0=0)
        _setUint256(proof, 32640, 5);              // commWOld[2] = 5 (running from fold 1: 3*0+5=5)

        // commWcccs[0..2] at 576 + 1000*64 = 64576
        _setUint256(proof, 64576, 0);               // commWcccs[0] = 0
        _setUint256(proof, 64608, 5);             // commWcccs[1] = 5
        _setUint256(proof, 64640, 7);             // commWcccs[2] = 7

        return proof;
    }

    // Test 3-fold proof with hardened header
    function testHardenedProof() public returns (bool, string memory, uint256) {
        Plonky3NovaVerifier verifier = Plonky3NovaVerifier(0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0);
        bytes memory proof = buildHardenedProof3Folds();
        Plonky3NovaVerifier.VerifyResult memory result = verifier.verifyProof(proof);
        return (result.valid, result.reason, result.proofId);
    }

    // Test that old proof format (no magic) is rejected
    function testOldProofFormatRejected() public returns (bool, string memory, uint256) {
        Plonky3NovaVerifier verifier = Plonky3NovaVerifier(0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0);
        bytes memory proof = new bytes(512);
        _setUint256(proof, 32, 0);                   // runningU
        _setUint256(proof, 64, 0);                   // runningCommW
        _setUint256(proof, 224, 1);                   // blockNumber
        _setUint256(proof, 416, 0xDEADBEEF);         // blockHash
        _setUint256(proof, 496, 1);                   // proofId
        _setUint256(proof, 512, 1);                   // augProofLen
        // No magic at offset 0 - should fail

        Plonky3NovaVerifier.VerifyResult memory result = verifier.verifyProof(proof);
        return (result.valid, result.reason, result.proofId);
    }

    // Test that future timestamp is rejected
    function testFutureTimestampRejected() public returns (bool, string memory, uint256) {
        Plonky3NovaVerifier verifier = Plonky3NovaVerifier(0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0);
        bytes memory proof = buildHardenedProof3Folds();
        // Set timestamp too far in future
        _setUint256(proof, 288, block.timestamp + 2 hours);
        Plonky3NovaVerifier.VerifyResult memory result = verifier.verifyProof(proof);
        return (result.valid, result.reason, result.proofId);
    }

    // Test that old timestamp is rejected
    function testOldTimestampRejected() public returns (bool, string memory, uint256) {
        Plonky3NovaVerifier verifier = Plonky3NovaVerifier(0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0);
        bytes memory proof = buildHardenedProof3Folds();
        // Set timestamp more than 1 year old
        _setUint256(proof, 288, block.timestamp - 400 days);
        Plonky3NovaVerifier.VerifyResult memory result = verifier.verifyProof(proof);
        return (result.valid, result.reason, result.proofId);
    }

    // Test that invalid r (r=0) is rejected
    function testInvalidRRejected() public returns (bool, string memory, uint256) {
        Plonky3NovaVerifier verifier = Plonky3NovaVerifier(0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0);
        bytes memory proof = buildHardenedProof3Folds();
        // Set r[0] = 0 (invalid)
        _setUint256(proof, 576, 0);
        Plonky3NovaVerifier.VerifyResult memory result = verifier.verifyProof(proof);
        return (result.valid, result.reason, result.proofId);
    }

    // Test that invalid r (r=1) is rejected
    function testR1Rejected() public returns (bool, string memory, uint256) {
        Plonky3NovaVerifier verifier = Plonky3NovaVerifier(0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0);
        bytes memory proof = buildHardenedProof3Folds();
        // Set r[0] = 1 (invalid)
        _setUint256(proof, 576, 1);
        Plonky3NovaVerifier.VerifyResult memory result = verifier.verifyProof(proof);
        return (result.valid, result.reason, result.proofId);
    }
}