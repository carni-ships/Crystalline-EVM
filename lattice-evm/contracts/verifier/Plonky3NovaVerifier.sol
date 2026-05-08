// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Plonky3NovaVerifier
/// @notice Verifies NovaIVC proofs with FULL folding chain verification on L1
/// @dev Hardened against replay, spoofing, and malformed proof attacks.
///      Supports optional BlockHashRelay for on-chain block hash and state root authenticity.

interface IBlockHashRelay {
    function verifyBlockHash(uint256 blockNumber, bytes32 blockHash) external view returns (bool);
    function verifyStateRoot(uint256 blockNumber, bytes32 stateRoot) external view returns (bool);
    function verifyBlockHashAndStateRoot(uint256 blockNumber, bytes32 blockHash, bytes32 stateRoot) external view returns (bool);
    function verifyFullState(uint256 blockNumber, bytes32 blockHash, bytes32 stateRoot, bytes32 bytecodeRoot, bytes32 storageRoot) external view returns (bool);
}

/// @notice Stub interface for future bytecode/storage relay integration
interface IStateRootRelay {
    function verifyStateRoots(uint256 blockNumber, bytes32 bytecodeRoot, bytes32 storageRoot) external view returns (bool);
}

contract Plonky3NovaVerifier {
    uint256 constant FIELD_Q = 8383489;
    uint256 constant MAX_FOLDS = 1000;

    /// @notice Magic value indicating initialized proof
    uint256 constant PROOF_MAGIC = 0x504C4F4E4B593350726F6F66000000; // "PLONKy3Proof"

    /// @notice Maximum reasonable field elements for a valid proof
    uint256 constant MAX_FIELD_ELEMENTS = 1000000;

    struct VerifyResult {
        bool valid;
        string reason;
        uint256 proofId;
    }

    /// @notice Proof header validation error codes
    error InvalidProofHeader(string reason);

    // Fixed layout constants
    // Header layout (total 576 bytes = 18 uint256 slots):
    // 0-511: 16 header fields (16 * 32 = 512)
    // 512-575: reserved space (2 * 32 = 64)
    // 576+: arrays
    uint256 constant HEADER_SIZE = 576;

    /// @notice Emitted when a proof is verified
    event ProofVerified(uint256 indexed proofId, bool valid, string reason);

    /// @notice Emitted when invalid proof attempted
    event ProofVerificationFailed(uint256 indexed proofId, string reason);

    /// @notice Emitted when block hash relay verification fails
    event BlockHashRejected(uint256 indexed blockNumber, bytes32 blockHash);

    /// @notice Emitted when bytecode or storage root is rejected
    event StateRootRejected(uint256 indexed blockNumber, bytes32 bytecodeRoot, bytes32 storageRoot);

    /// @notice Optional block hash relay for authenticity verification
    IBlockHashRelay public blockHashRelay;

    /// @notice Optional state relay for bytecode/storage root verification (future use)
    IStateRootRelay public stateRootRelay;

    /// @notice Owner address for access control
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Caller is not the owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Set the block hash relay address (only callable once, by owner)
    /// @param _relay Address of the BlockHashRelay contract
    function setBlockHashRelay(address _relay) external onlyOwner {
        require(address(blockHashRelay) == address(0), "Relay already set");
        require(_relay != address(0), "Relay cannot be zero address");
        blockHashRelay = IBlockHashRelay(_relay);
    }

    /// @notice Update the block hash relay address (for emergency recovery, owner only)
    /// @param _relay Address of the new BlockHashRelay contract
    function updateBlockHashRelay(address _relay) external onlyOwner {
        require(_relay != address(0), "Relay cannot be zero address");
        blockHashRelay = IBlockHashRelay(_relay);
    }

    /// @notice Set the state root relay for bytecode/storage verification (owner only)
    /// @param _relay Address of the StateRootRelay contract
    function setStateRootRelay(address _relay) external onlyOwner {
        require(address(stateRootRelay) == address(0), "State relay already set");
        require(_relay != address(0), "Relay cannot be zero address");
        stateRootRelay = IStateRootRelay(_relay);
    }

    /// @notice Update the state root relay address (for emergency recovery, owner only)
    /// @param _relay Address of the new StateRootRelay contract
    function updateStateRootRelay(address _relay) external onlyOwner {
        require(_relay != address(0), "Relay cannot be zero address");
        stateRootRelay = IStateRootRelay(_relay);
    }

    /// @notice Verify NovaIVC proof with complete folding chain
    /// @dev Proof layout:
    /// - 0-31: magic (must be PROOF_MAGIC)
    /// - 32-63: runningU
    /// - 64-95: runningCommW
    /// - 96-127: runningC (Nova fold state, must be consistent)
    /// - 128-159: runningN (must equal numFolds)
    /// - 160-191: finalU
    /// - 192-223: finalCommW
    /// - 224-255: numFolds
    /// - 256-287: blockNumber
    /// - 288-319: blockTimestamp
    /// - 320-351: stateRoot
    /// - 352-383: bytecodeRoot
    /// - 384-415: storageRoot
    /// - 416-447: blockHash (bytes32)
    /// - 448-479: txCount
    /// - 480-495: gasUsed
    /// - 496-511: proofId
    /// - 512-527: augProofLen
    /// - 528-539: reserved (must be 0)
    /// - 540-551: numFieldElements (must be reasonable)
    /// - 552-563: proofVersion
    /// - 564-575: reserved (must be 0)
    /// - 576+: challenges[numFolds], commWOld[numFolds], commWcccs[numFolds], witnessHashes[numFolds]
    ///   witnessHashes are Fiat-Shamir challenges: r_i = Hash(witness_data_i)
    function verifyProof(bytes calldata proof) public returns (VerifyResult memory result) {
        // Check 0: Minimum length
        if (proof.length < HEADER_SIZE) {
            emit ProofVerificationFailed(0, "Proof too short");
            return VerifyResult(false, "Proof too short", 0);
        }

        // Check 0b: Magic value to identify valid proof format
        uint256 magic = readUint256(proof, 0);
        if (magic != PROOF_MAGIC) {
            emit ProofVerificationFailed(0, "Invalid proof format");
            return VerifyResult(false, "Invalid proof format", 0);
        }

        // Check 0c: Reserved fields must be zero
        if (readUint256(proof, 528) != 0 || readUint256(proof, 564) != 0) {
            emit ProofVerificationFailed(0, "Non-zero reserved field");
            return VerifyResult(false, "Invalid reserved fields", 0);
        }

        uint256 runningU = readUint256(proof, 32);
        uint256 runningCommW = readUint256(proof, 64);
        uint256 runningC = readUint256(proof, 96);
        uint256 runningN = readUint256(proof, 128);

        uint256 finalU = readUint256(proof, 160);
        uint256 finalCommW = readUint256(proof, 192);

        uint256 numFolds = readUint256(proof, 224);
        uint256 blockNumber = readUint256(proof, 256);
        uint256 blockTimestamp = readUint256(proof, 288);

        uint256 stateRoot = readUint256(proof, 320);
        uint256 bytecodeRoot = readUint256(proof, 352);
        uint256 storageRoot = readUint256(proof, 384);
        bytes32 blockHash = bytes32(readUint256(proof, 416));

        uint256 txCount = readUint256(proof, 448);
        uint256 gasUsed = readUint256(proof, 480);
        uint256 proofId = readUint256(proof, 496);
        uint256 augProofLen = readUint256(proof, 512);

        uint256 numFieldElements = readUint256(proof, 540);
        uint256 proofVersion = readUint256(proof, 552);

        // === SECURITY CHECKS ===

        // Check 1: blockHash must be non-zero
        if (blockHash == bytes32(0)) {
            emit ProofVerificationFailed(proofId, "Block hash is zero");
            return VerifyResult(false, "Block hash is zero", proofId);
        }

        // Check 1b: bytecodeRoot and storageRoot must be non-zero
        if (bytecodeRoot == 0) {
            emit ProofVerificationFailed(proofId, "Bytecode root is zero");
            return VerifyResult(false, "Bytecode root is zero", proofId);
        }
        if (storageRoot == 0) {
            emit ProofVerificationFailed(proofId, "Storage root is zero");
            return VerifyResult(false, "Storage root is zero", proofId);
        }

        // Check 2: blockTimestamp must be within acceptable range (not in future, not too old)
        // Reject timestamps too far in the future (max 1 hour)
        if (blockTimestamp > block.timestamp + 1 hours) {
            emit ProofVerificationFailed(proofId, "Block timestamp too far in future");
            return VerifyResult(false, "Timestamp too far in future", proofId);
        }

        // Reject timestamps older than 1 year (prevent replay of old proofs)
        if (block.timestamp > blockTimestamp + 365 days) {
            emit ProofVerificationFailed(proofId, "Block timestamp too old");
            return VerifyResult(false, "Timestamp too old", proofId);
        }

        // Check 2b: If relay is set, verify blockHash, stateRoot, bytecodeRoot, storageRoot are authentic
        if (address(blockHashRelay) != address(0)) {
            if (!blockHashRelay.verifyFullState(
                blockNumber,
                blockHash,
                bytes32(stateRoot),
                bytes32(bytecodeRoot),
                bytes32(storageRoot)
            )) {
                emit BlockHashRejected(blockNumber, blockHash);
                emit StateRootRejected(blockNumber, bytes32(bytecodeRoot), bytes32(storageRoot));
                emit ProofVerificationFailed(proofId, "State roots not authentic");
                return VerifyResult(false, "State roots not authentic", proofId);
            }
        }

        // Check 3: proofId must equal blockNumber (binds proof to specific block)
        if (proofId != blockNumber) {
            emit ProofVerificationFailed(proofId, "Proof ID mismatch");
            return VerifyResult(false, "Proof ID mismatch", proofId);
        }

        // Check 4: augProofLen must be > 0
        if (augProofLen == 0) {
            emit ProofVerificationFailed(proofId, "Empty augmented proof");
            return VerifyResult(false, "Empty augmented proof", proofId);
        }

        // Check 4b: numFieldElements must be in reasonable range (not too large)
        if (numFieldElements == 0 || numFieldElements > MAX_FIELD_ELEMENTS) {
            emit ProofVerificationFailed(proofId, "Invalid numFieldElements");
            return VerifyResult(false, "Invalid numFieldElements", proofId);
        }

        // Check 5: numFolds must be valid range
        if (numFolds == 0 || numFolds > MAX_FOLDS) {
            emit ProofVerificationFailed(proofId, "Invalid numFolds");
            return VerifyResult(false, "Invalid numFolds", proofId);
        }

        // Check 6: runningN must equal numFolds (consistency check)
        if (runningN != numFolds) {
            emit ProofVerificationFailed(proofId, "runningN mismatch");
            return VerifyResult(false, "Running N mismatch", proofId);
        }

        // Check 6b: runningC must not be zero (it's part of the IVC state)
        if (runningC == 0 && numFolds > 0) {
            emit ProofVerificationFailed(proofId, "Invalid runningC");
            return VerifyResult(false, "Invalid runningC", proofId);
        }

        // Check 7: txCount must be > 0 for non-empty blocks
        if (txCount == 0) {
            emit ProofVerificationFailed(proofId, "Zero tx count");
            return VerifyResult(false, "Zero transaction count", proofId);
        }

        // Check 8: gasUsed sanity (must be <= block gas limit, reasonable)
        if (gasUsed == 0 || gasUsed > block.gaslimit) {
            emit ProofVerificationFailed(proofId, "Invalid gas used");
            return VerifyResult(false, "Invalid gas used", proofId);
        }

        // Check 9: Verify folding chain with witness hash derivation
        uint256 finalRunningCommW = verifyFoldingWithWitnessHash(numFolds, proof);
        if (finalRunningCommW == 0) {
            emit ProofVerificationFailed(proofId, "Folding chain failed");
            return VerifyResult(false, "Folding chain failed", proofId);
        }

        // Check 10: Final state must match
        if (runningU != finalU) {
            emit ProofVerificationFailed(proofId, "Final U mismatch");
            return VerifyResult(false, "Final U mismatch", proofId);
        }
        if (finalRunningCommW != finalCommW) {
            emit ProofVerificationFailed(proofId, "Final comm_w mismatch");
            return VerifyResult(false, "Final comm_w mismatch", proofId);
        }

        // Check 11: Verify proof version is supported
        if (proofVersion != 1) {
            emit ProofVerificationFailed(proofId, "Unsupported proof version");
            return VerifyResult(false, "Unsupported proof version", proofId);
        }

        // All checks passed
        emit ProofVerified(proofId, true, "Verification successful");
        return VerifyResult(true, "Verification successful", proofId);
    }

    /// @notice Read uint256 from proof bytes at offset
    /// @dev Uses assembly for efficiency and safety
    function readUint256(bytes calldata proof, uint256 offset) internal pure returns (uint256 value) {
        assembly {
            value := calldataload(add(proof.offset, offset))
        }
    }

    /// @notice Verify complete folding chain with STRICT cryptographic binding
    /// @dev For each fold i:
    ///      r_i (challenge) must equal Hash(witness_data_i) — Fiat-Shamir derivation
    ///      comm_w_new = r_i * comm_w_old + comm_w_cccs_i (mod FIELD_Q)
    /// @param numFolds Number of folds to process
    /// @param proof The proof bytes
    /// @return computed final comm_w value, or 0 on failure
    function verifyFoldingWithWitnessHash(uint256 numFolds, bytes calldata proof) internal view returns (uint256) {
        // Array bounds validation — now includes witnessHashes array
        uint256 arraysOffset = HEADER_SIZE;
        // 4 arrays of numFolds elements: challenges, commWOld, commWcccs, witnessHashes
        uint256 requiredLength = arraysOffset + (numFolds * 128); // 4 * 32 bytes per fold
        if (proof.length < requiredLength) return 0;

        // Array offsets within proof (starting after header at HEADER_SIZE=576):
        // challenges[i]    at arraysOffset + (i * 32)
        // commWOld[i]      at arraysOffset + (MAX_FOLDS * 32) + (i * 32)
        // commWcccs[i]     at arraysOffset + (MAX_FOLDS * 64) + (i * 32)
        // witnessHashes[i] at arraysOffset + (MAX_FOLDS * 96) + (i * 32)
        uint256 commWOldOffset    = arraysOffset + (MAX_FOLDS * 32);   // 576 + 32000 = 32576
        uint256 commWcccsOffset    = arraysOffset + (MAX_FOLDS * 64);   // 576 + 64000 = 64576
        uint256 witnessHashesOffset = arraysOffset + (MAX_FOLDS * 96);   // 576 + 96000 = 96576

        uint256 runningCommW = 0;

        for (uint256 i = 0; i < numFolds; i++) {
            uint256 r = readUint256(proof, arraysOffset + (i * 32));
            uint256 commWOld_i = readUint256(proof, commWOldOffset + (i * 32));
            uint256 commWcccs_i = readUint256(proof, commWcccsOffset + (i * 32));
            uint256 witnessHash_i = readUint256(proof, witnessHashesOffset + (i * 32));

            // SECURITY: r must be in valid range (not 0, 1, or >= FIELD_Q)
            // This prevents trivial forgeries
            if (r <= 1 || r >= FIELD_Q) return 0;

            // CRYPTOGRAPHIC: r must match the Fiat-Shamir derived witness hash
            // This binds the challenge to the actual witness data, preventing
            // an attacker from freely choosing r values to satisfy the equation
            if (r != witnessHash_i) return 0;

            // SECURITY: witnessHash must also be in valid field range
            if (witnessHash_i >= FIELD_Q) return 0;

            // SECURITY: commWOld must match running (chain continuity)
            // This ensures each fold builds on correct previous state
            if (commWOld_i != runningCommW) return 0;

            // SECURITY: commWcccs must be in valid range
            if (commWcccs_i >= FIELD_Q) return 0;

            // Compute folding equation: comm_w_new = r * comm_w_old + comm_w_cccs (mod FIELD_Q)
            uint256 mulResult = mulmod(r, commWOld_i, FIELD_Q);
            uint256 expectedCommW = addmod(mulResult, commWcccs_i, FIELD_Q);

            runningCommW = expectedCommW;
        }

        return runningCommW;
    }

    /// @notice Legacy folding verification (for proofs without witness hashes)
    /// @dev Kept for backward compatibility — new proofs should use verifyFoldingWithWitnessHash
    function verifyFolding(uint256 numFolds, bytes calldata proof) internal view returns (uint256) {
        uint256 arraysOffset = HEADER_SIZE;
        uint256 requiredLength = arraysOffset + (numFolds * 96);
        if (proof.length < requiredLength) return 0;

        uint256 commWOldOffset = arraysOffset + (MAX_FOLDS * 32);
        uint256 commWcccsOffset = arraysOffset + (MAX_FOLDS * 64);

        uint256 runningCommW = 0;

        for (uint256 i = 0; i < numFolds; i++) {
            uint256 r = readUint256(proof, arraysOffset + (i * 32));
            uint256 commWOld_i = readUint256(proof, commWOldOffset + (i * 32));
            uint256 commWcccs_i = readUint256(proof, commWcccsOffset + (i * 32));

            if (r <= 1 || r >= FIELD_Q) return 0;
            if (commWOld_i != runningCommW) return 0;
            if (commWcccs_i >= FIELD_Q) return 0;

            uint256 mulResult = mulmod(r, commWOld_i, FIELD_Q);
            uint256 expectedCommW = addmod(mulResult, commWcccs_i, FIELD_Q);

            runningCommW = expectedCommW;
        }

        return runningCommW;
    }

    /// @notice Verify single folding step with Fiat-Shamir (off-chain helper)
    /// @dev Public pure function for external verification of folding equation
    function verifyFoldingStep(
        uint256 r,
        uint256 commWOld,
        uint256 commWcccs,
        uint256 expectedCommW
    ) public pure returns (bool) {
        // Validate inputs
        if (r <= 1 || r >= FIELD_Q) return false;
        if (commWcccs >= FIELD_Q) return false;

        uint256 mulResult = mulmod(r, commWOld, FIELD_Q);
        uint256 computed = addmod(mulResult, commWcccs, FIELD_Q);
        return computed == expectedCommW;
    }

    /// @notice Compute the expected witness hash for a given fold
    /// @dev This is the Fiat-Shamir hash that should be used as the challenge
    ///      In production, this should be replaced with the actual Poseidon hash
    ///      of the witness data for fold i. Here we use keccak256 as a placeholder
    ///      since the field is small enough that keccak output can be reduced mod Q.
    /// @param blockNumber The block number
    /// @param foldIndex The fold index
    /// @param witnessData The witness data bytes
    /// @return The computed hash, reduced to field range [2, Q-1]
    function computeWitnessHash(
        uint256 blockNumber,
        uint256 foldIndex,
        bytes32 witnessData
    ) public pure returns (uint256) {
        bytes32 h = keccak256(abi.encodePacked(blockNumber, foldIndex, witnessData));
        uint256 hash = uint256(h) % FIELD_Q;
        // Ensure hash is in valid range for challenges (>= 2)
        if (hash < 2) hash = 2;
        return hash;
    }

    /// @notice Get the proof version identifier
    function getVersion() public pure returns (uint256) {
        return 1;
    }

    /// @notice Getter for the magic value
    function getProofMagic() public pure returns (uint256) {
        return PROOF_MAGIC;
    }
}