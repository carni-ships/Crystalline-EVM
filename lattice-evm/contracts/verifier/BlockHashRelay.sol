// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BlockHashRelay
/// @notice Commits and verifies Ethereum block hashes, state roots, bytecode roots, and storage roots for authenticating proofs
/// @dev Maintains mappings of blockNumber -> blockHash, stateRoot, bytecodeRoot, storageRoot
///      Enables trustless verification that proofs are bound to canonical chain data

contract BlockHashRelay {
    // Trusted relayer address (governance or multi-sig in production)
    address public relayer;

    // Pending relayer for two-step transfer (timelock protection)
    address public pendingRelayer;

    // Timelock delay for relayer transfer (1 hour = 3600 seconds)
    uint256 public constant RELAYER_TIMELOCK = 1 hours;

    // Timestamp when pending relayer was set (0 if no pending transfer)
    uint256 public pendingRelayerSetAt;

    // Direct mapping for committed block hashes
    mapping(uint256 => bytes32) public blockHashes;

    // Direct mapping for committed state roots
    mapping(uint256 => bytes32) public stateRoots;

    // Direct mapping for committed bytecode roots
    mapping(uint256 => bytes32) public bytecodeRoots;

    // Direct mapping for committed storage roots
    mapping(uint256 => bytes32) public storageRoots;

    // Latest committed block number (for append-only enforcement)
    uint256 public latestBlockNumber;

    // Reorg safe zone - allow updates within this many blocks of latest
    uint256 public constant REORG_SAFE_ZONE = 64;

    // Event for off-chain monitoring and indexing
    event BlockHashUpdated(uint256 indexed blockNumber, bytes32 blockHash);
    event StateRootUpdated(uint256 indexed blockNumber, bytes32 stateRoot);
    event BytecodeRootUpdated(uint256 indexed blockNumber, bytes32 bytecodeRoot);
    event StorageRootUpdated(uint256 indexed blockNumber, bytes32 storageRoot);
    event FullStateUpdated(uint256 indexed blockNumber, bytes32 blockHash, bytes32 stateRoot, bytes32 bytecodeRoot, bytes32 storageRoot);
    event RelayerChanged(address indexed oldRelayer, address indexed newRelayer);
    event RelayerTransferStarted(address indexed currentRelayer, address indexed pendingRelayer, uint256 availableAfter);

    modifier onlyRelayer() {
        require(msg.sender == relayer, "Caller is not the relayer");
        _;
    }

    constructor() {
        relayer = msg.sender;
    }

    /// @notice Commit all state roots for a given block number
    /// @param blockNumber The Ethereum block number
    /// @param blockHash The canonical block hash (as returned by eth_getBlockByNumber)
    /// @param stateRoot The canonical state root (from block's stateRoot field)
    /// @param bytecodeRoot The bytecode Merkle root for this block
    /// @param storageRoot The storage Merkle root for this block
    function commitFullState(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 stateRoot,
        bytes32 bytecodeRoot,
        bytes32 storageRoot
    ) external onlyRelayer {
        require(blockHash != bytes32(0), "Block hash cannot be zero");
        require(stateRoot != bytes32(0), "State root cannot be zero");
        require(bytecodeRoot != bytes32(0), "Bytecode root cannot be zero");
        require(storageRoot != bytes32(0), "Storage root cannot be zero");
        require(blockNumber > latestBlockNumber - REORG_SAFE_ZONE, "Block number too far behind");
        require(blockNumber > latestBlockNumber || blockHashes[blockNumber] != bytes32(0),
            "Can only commit strictly forward or update within reorg zone");

        blockHashes[blockNumber] = blockHash;
        stateRoots[blockNumber] = stateRoot;
        bytecodeRoots[blockNumber] = bytecodeRoot;
        storageRoots[blockNumber] = storageRoot;
        if (blockNumber > latestBlockNumber) {
            latestBlockNumber = blockNumber;
        }

        emit FullStateUpdated(blockNumber, blockHash, stateRoot, bytecodeRoot, storageRoot);
    }

    /// @notice Commit a block hash and state root for a given block number
    /// @param blockNumber The Ethereum block number
    /// @param blockHash The canonical block hash
    /// @param stateRoot The canonical state root
    function commitBlockHashAndStateRoot(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 stateRoot
    ) external onlyRelayer {
        require(blockHash != bytes32(0), "Block hash cannot be zero");
        require(stateRoot != bytes32(0), "State root cannot be zero");
        require(blockNumber > latestBlockNumber - REORG_SAFE_ZONE, "Block number too far behind");
        require(blockNumber > latestBlockNumber || blockHashes[blockNumber] != bytes32(0),
            "Can only commit strictly forward or update within reorg zone");

        blockHashes[blockNumber] = blockHash;
        stateRoots[blockNumber] = stateRoot;
        if (blockNumber > latestBlockNumber) {
            latestBlockNumber = blockNumber;
        }

        emit BlockHashUpdated(blockNumber, blockHash);
        emit StateRootUpdated(blockNumber, stateRoot);
    }

    /// @notice Commit a block hash for a given block number (legacy single-field)
    /// @param blockNumber The Ethereum block number
    /// @param blockHash The canonical block hash
    function commitBlockHash(uint256 blockNumber, bytes32 blockHash) external onlyRelayer {
        require(blockHash != bytes32(0), "Block hash cannot be zero");
        require(blockNumber > latestBlockNumber - REORG_SAFE_ZONE, "Block number too far behind");
        require(blockNumber > latestBlockNumber || blockHashes[blockNumber] != bytes32(0),
            "Can only commit strictly forward or update within reorg zone");

        blockHashes[blockNumber] = blockHash;
        if (blockNumber > latestBlockNumber) {
            latestBlockNumber = blockNumber;
        }

        emit BlockHashUpdated(blockNumber, blockHash);
    }

    /// @notice Batch commit full state by calling single-commit repeatedly
    /// @dev This avoids stack overflow in the compiler by keeping loop variables minimal
    /// @param blockNumbers Array of block numbers (must be strictly increasing)
    /// @param blockHashes_ Array of corresponding block hashes
    /// @param stateRoots_ Array of corresponding state roots
    /// @param bytecodeRoots_ Array of corresponding bytecode roots
    /// @param storageRoots_ Array of corresponding storage roots
    function commitFullStates(
        uint256[] calldata blockNumbers,
        bytes32[] calldata blockHashes_,
        bytes32[] calldata stateRoots_,
        bytes32[] calldata bytecodeRoots_,
        bytes32[] calldata storageRoots_
    ) external onlyRelayer {
        require(blockNumbers.length == blockHashes_.length, "Array length mismatch");
        require(blockNumbers.length == stateRoots_.length, "Array length mismatch");
        require(blockNumbers.length == bytecodeRoots_.length, "Array length mismatch");
        require(blockNumbers.length == storageRoots_.length, "Array length mismatch");
        require(blockNumbers.length > 0, "Empty arrays");

        // Delegate to internal helper that handles one entry at a time
        for (uint256 i = 0; i < blockNumbers.length; i++) {
            _commitFullStateFromArrays(i, blockNumbers, blockHashes_, stateRoots_, bytecodeRoots_, storageRoots_);
        }
    }

    /// @notice Internal single-entry commit to avoid stack overflow
    function _commitFullStateFromArrays(
        uint256 i,
        uint256[] calldata blockNumbers,
        bytes32[] calldata blockHashes_,
        bytes32[] calldata stateRoots_,
        bytes32[] calldata bytecodeRoots_,
        bytes32[] calldata storageRoots_
    ) internal {
        uint256 bn = blockNumbers[i];
        bytes32 bh = blockHashes_[i];
        bytes32 sr = stateRoots_[i];
        bytes32 bcr = bytecodeRoots_[i];
        bytes32 str = storageRoots_[i];

        require(bh != bytes32(0), "Block hash cannot be zero");
        require(sr != bytes32(0), "State root cannot be zero");
        require(bcr != bytes32(0), "Bytecode root cannot be zero");
        require(str != bytes32(0), "Storage root cannot be zero");
        require(bn > latestBlockNumber - REORG_SAFE_ZONE, "Block number too far behind");
        require(bn > latestBlockNumber || blockHashes[bn] != bytes32(0),
            "Can only commit strictly forward or update within reorg zone");

        blockHashes[bn] = bh;
        stateRoots[bn] = sr;
        bytecodeRoots[bn] = bcr;
        storageRoots[bn] = str;

        if (bn > latestBlockNumber) {
            latestBlockNumber = bn;
        }

        emit FullStateUpdated(bn, bh, sr, bcr, str);
    }

    /// @notice Batch commit multiple block hashes and state roots
    /// @param blockNumbers Array of block numbers (must be strictly increasing)
    /// @param blockHashes_ Array of corresponding block hashes
    /// @param stateRoots_ Array of corresponding state roots
    function commitBlockHashesAndStateRoots(
        uint256[] calldata blockNumbers,
        bytes32[] calldata blockHashes_,
        bytes32[] calldata stateRoots_
    ) external onlyRelayer {
        require(blockNumbers.length == blockHashes_.length, "Array length mismatch");
        require(blockNumbers.length == stateRoots_.length, "Array length mismatch");
        require(blockNumbers.length > 0, "Empty arrays");

        uint256 lastBlock = latestBlockNumber;

        for (uint256 i = 0; i < blockNumbers.length; i++) {
            uint256 blockNumber = blockNumbers[i];
            bytes32 blockHash = blockHashes_[i];
            bytes32 stateRoot = stateRoots_[i];

            require(blockHash != bytes32(0), "Block hash cannot be zero");
            require(stateRoot != bytes32(0), "State root cannot be zero");
            require(blockNumber > lastBlock - REORG_SAFE_ZONE, "Block number too far behind");
            require(blockNumber > lastBlock || blockHashes[blockNumber] != bytes32(0),
                "Can only commit strictly forward or update within reorg zone");

            blockHashes[blockNumber] = blockHash;
            stateRoots[blockNumber] = stateRoot;
            lastBlock = blockNumber;

            emit BlockHashUpdated(blockNumber, blockHash);
            emit StateRootUpdated(blockNumber, stateRoot);
        }

        latestBlockNumber = lastBlock;
    }

    /// @notice Batch commit multiple block hashes (legacy single-field)
    /// @param blockNumbers Array of block numbers (must be strictly increasing)
    /// @param blockHashes_ Array of corresponding block hashes
    function commitBlockHashes(
        uint256[] calldata blockNumbers,
        bytes32[] calldata blockHashes_
    ) external onlyRelayer {
        require(blockNumbers.length == blockHashes_.length, "Array length mismatch");
        require(blockNumbers.length > 0, "Empty arrays");

        uint256 lastBlock = latestBlockNumber;

        for (uint256 i = 0; i < blockNumbers.length; i++) {
            uint256 blockNumber = blockNumbers[i];
            bytes32 blockHash = blockHashes_[i];

            require(blockHash != bytes32(0), "Block hash cannot be zero");
            require(blockNumber > lastBlock - REORG_SAFE_ZONE, "Block number too far behind");
            require(blockNumber > lastBlock || blockHashes[blockNumber] != bytes32(0),
                "Can only commit strictly forward or update within reorg zone");

            blockHashes[blockNumber] = blockHash;
            lastBlock = blockNumber;

            emit BlockHashUpdated(blockNumber, blockHash);
        }

        latestBlockNumber = lastBlock;
    }

    /// @notice Verify if a block hash is committed and authentic
    /// @param blockNumber The block number to verify
    /// @param blockHash The block hash to check against committed value
    /// @return True if blockHash matches the committed hash for blockNumber
    function verifyBlockHash(uint256 blockNumber, bytes32 blockHash)
        external
        view
        returns (bool)
    {
        return blockHashes[blockNumber] == blockHash;
    }

    /// @notice Verify if a state root is committed and authentic
    /// @param blockNumber The block number to verify
    /// @param stateRoot The state root to check against committed value
    /// @return True if stateRoot matches the committed root for blockNumber
    function verifyStateRoot(uint256 blockNumber, bytes32 stateRoot)
        external
        view
        returns (bool)
    {
        return stateRoots[blockNumber] == stateRoot;
    }

    /// @notice Verify both block hash and state root
    /// @param blockNumber The block number to verify
    /// @param blockHash The block hash to check
    /// @param stateRoot The state root to check
    /// @return True if both match committed values
    function verifyBlockHashAndStateRoot(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 stateRoot
    ) external view returns (bool) {
        return blockHashes[blockNumber] == blockHash && stateRoots[blockNumber] == stateRoot;
    }

    /// @notice Verify full state: block hash, state root, bytecode root, and storage root
    /// @param blockNumber The block number to verify
    /// @param blockHash The block hash to check
    /// @param stateRoot The state root to check
    /// @param bytecodeRoot The bytecode root to check
    /// @param storageRoot The storage root to check
    /// @return True if all match committed values
    function verifyFullState(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 stateRoot,
        bytes32 bytecodeRoot,
        bytes32 storageRoot
    ) external view returns (bool) {
        return blockHashes[blockNumber] == blockHash
            && stateRoots[blockNumber] == stateRoot
            && bytecodeRoots[blockNumber] == bytecodeRoot
            && storageRoots[blockNumber] == storageRoot;
    }

    /// @notice Get the committed block hash for a block number
    /// @param blockNumber The block number to query
    /// @return The committed block hash, or bytes32(0) if not found
    function getBlockHash(uint256 blockNumber) external view returns (bytes32) {
        return blockHashes[blockNumber];
    }

    /// @notice Get the committed state root for a block number
    /// @param blockNumber The block number to query
    /// @return The committed state root, or bytes32(0) if not found
    function getStateRoot(uint256 blockNumber) external view returns (bytes32) {
        return stateRoots[blockNumber];
    }

    /// @notice Get the committed bytecode root for a block number
    /// @param blockNumber The block number to query
    /// @return The committed bytecode root, or bytes32(0) if not found
    function getBytecodeRoot(uint256 blockNumber) external view returns (bytes32) {
        return bytecodeRoots[blockNumber];
    }

    /// @notice Get the committed storage root for a block number
    /// @param blockNumber The block number to query
    /// @return The committed storage root, or bytes32(0) if not found
    function getStorageRoot(uint256 blockNumber) external view returns (bytes32) {
        return storageRoots[blockNumber];
    }

    /// @notice Begin two-step relayer transfer with timelock
    /// @param newRelayer The address to set as the new relayer (available after timelock)
    function beginRelayerTransfer(address newRelayer) external onlyRelayer {
        require(newRelayer != address(0), "New relayer cannot be zero address");
        pendingRelayer = newRelayer;
        pendingRelayerSetAt = block.timestamp;
        emit RelayerTransferStarted(relayer, newRelayer, block.timestamp + RELAYER_TIMELOCK);
    }

    /// @notice Complete two-step relayer transfer after timelock
    /// @dev Must be called after RELAYER_TIMELOCK seconds have passed
    function completeRelayerTransfer() external {
        require(msg.sender == pendingRelayer, "Caller is not the pending relayer");
        require(pendingRelayerSetAt > 0, "No pending transfer");
        require(block.timestamp >= pendingRelayerSetAt + RELAYER_TIMELOCK, "Timelock not elapsed");

        address oldRelayer = relayer;
        relayer = pendingRelayer;
        pendingRelayer = address(0);
        pendingRelayerSetAt = 0;

        emit RelayerChanged(oldRelayer, relayer);
    }

    /// @notice Cancel pending relayer transfer
    function cancelRelayerTransfer() external onlyRelayer {
        pendingRelayer = address(0);
        pendingRelayerSetAt = 0;
    }
}